import base64
import os
import struct
import tempfile
import unittest

import sshkey_audit as ska


def s(b):
    return struct.pack(">I", len(b)) + b


def mpint(n):
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return s((b"\x00" + raw) if raw[0] & 0x80 else raw)


def rsa_blob(bits):
    n = (1 << (bits - 1)) | 1
    return s(b"ssh-rsa") + mpint(65537) + mpint(n)


def dsa_blob():
    return s(b"ssh-dss") + mpint((1 << 1023) | 1) + mpint(7) + mpint(5) + mpint(3)


def ed_blob(seed=b"a"):
    return s(b"ssh-ed25519") + s((seed * 32)[:32])


def ecdsa_blob():
    return s(b"ecdsa-sha2-nistp256") + s(b"nistp256") + s(b"\x04" + b"b" * 64)


def pub_line(blob, comment="user@host", opts=""):
    kt = ska.read_string(blob, 0)[0].decode()
    return ("%s " % opts if opts else "") + "%s %s %s" % (kt, base64.b64encode(blob).decode(), comment)


def openssh_private(pub_blob, cipher=b"none"):
    body = b"openssh-key-v1\x00" + s(cipher) + s(b"none" if cipher == b"none" else b"bcrypt") + s(b"") \
        + struct.pack(">I", 1) + s(pub_blob) + s(b"\x00" * 64)
    b64 = base64.b64encode(body).decode()
    lines = [b64[i:i + 70] for i in range(0, len(b64), 70)]
    return "\n".join(["-----BEGIN " + "OPENSSH PRIVATE KEY-----"] + lines + ["-----END " + "OPENSSH PRIVATE KEY-----", ""])


def pem(label, body="MIIBOgIBAAJB\nabc", extra=""):
    return "-----BEGIN %sPRIVATE KEY-----\n%s%s\n-----END %sPRIVATE KEY-----\n" % (label, extra, body, label)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = os.path.join(self.tmp.name, ".ssh")
        os.mkdir(self.dir, 0o700)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text, mode=0o600):
        p = os.path.join(self.dir, name)
        with open(p, "w") as fh:
            fh.write(text)
        os.chmod(p, mode)
        return p

    def rules(self, path):
        return {(f[0], f[1]) for f in ska.audit_path(path)}


class ParseTests(unittest.TestCase):
    def test_blob_parsing(self):
        self.assertEqual(ska.parse_public_blob(rsa_blob(3072)), ("ssh-rsa", 3072))
        self.assertEqual(ska.parse_public_blob(rsa_blob(1024)), ("ssh-rsa", 1024))
        self.assertEqual(ska.parse_public_blob(dsa_blob()), ("ssh-dss", 1024))
        self.assertEqual(ska.parse_public_blob(ed_blob()), ("ssh-ed25519", 256))
        self.assertEqual(ska.parse_public_blob(ecdsa_blob()), ("ecdsa-sha2-nistp256", 256))

    def test_truncated(self):
        with self.assertRaises(ska.KeyError_):
            ska.parse_public_blob(rsa_blob(2048)[:20])

    def test_fingerprint_format(self):
        self.assertTrue(ska.fingerprint(ed_blob()).startswith("SHA256:"))
        self.assertNotIn("=", ska.fingerprint(ed_blob()))


class PrivateKeyTests(Base):
    def test_unencrypted_openssh_key(self):
        p = self.write("id_ed25519", openssh_private(ed_blob()))
        self.assertIn(("HIGH", "no-passphrase"), self.rules(p))

    def test_encrypted_openssh_key_clean(self):
        p = self.write("id_ed25519", openssh_private(ed_blob(), cipher=b"aes256-ctr"))
        self.assertEqual(self.rules(p), set())

    def test_weak_keys(self):
        p = self.write("k1", openssh_private(rsa_blob(1024), b"aes256-ctr"))
        self.assertIn(("HIGH", "weak-rsa"), self.rules(p))
        p = self.write("k2", openssh_private(rsa_blob(2048), b"aes256-ctr"))
        self.assertIn(("MEDIUM", "short-rsa"), self.rules(p))
        p = self.write("k3", openssh_private(dsa_blob(), b"aes256-ctr"))
        self.assertIn(("HIGH", "dsa-key"), self.rules(p))
        p = self.write("k4", openssh_private(rsa_blob(4096), b"aes256-ctr"))
        self.assertEqual(self.rules(p), set())

    def test_permissions(self):
        p = self.write("id_x", openssh_private(ed_blob(), b"aes256-ctr"), mode=0o644)
        self.assertIn(("HIGH", "private-key-permissions"), self.rules(p))

    def test_legacy_pem(self):
        p = self.write("old", pem("RSA "))
        r = self.rules(p)
        self.assertIn(("HIGH", "no-passphrase"), r)
        self.assertIn(("LOW", "legacy-format"), r)
        enc = self.write("old2", pem("RSA ", extra="Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\n"))
        self.assertNotIn(("HIGH", "no-passphrase"), self.rules(enc))
        self.assertNotIn(("HIGH", "no-passphrase"), self.rules(self.write("p8", pem("ENCRYPTED "))))

    def test_garbage_does_not_crash(self):
        p = self.write("junk", pem("OPENSSH ", body="!!!notbase64!!!"))
        self.assertIn(("INFO", "unparsed"), self.rules(p))

    def test_key_material_never_printed(self):
        import io
        from unittest import mock
        self.write("id_a", openssh_private(ed_blob(), b"none"))
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            ska.main([self.dir])
        self.assertNotIn("AAAA", buf.getvalue())
        self.assertIn("SHA256:", buf.getvalue())


class PublicKeyTests(Base):
    def test_authorized_keys(self):
        text = "\n".join([
            "# comment",
            pub_line(ed_blob(b"a")),
            pub_line(ed_blob(b"a"), "dup@host"),
            pub_line(rsa_blob(1024), "old@host"),
            pub_line(ed_blob(b"c"), "ci", opts='from="203.0.113.5",restrict'),
            "garbage line",
            ""])
        p = self.write("authorized_keys", text)
        r = {(f[0], f[1], f[4]) for f in ska.audit_path(p)}
        self.assertIn(("LOW", "duplicate-key", 3), r)
        self.assertIn(("HIGH", "weak-rsa", 4), r)
        self.assertIn(("INFO", "unrestricted-key", 2), r)
        self.assertIn(("LOW", "unparsed-line", 6), r)
        self.assertNotIn(("INFO", "unrestricted-key", 5), r)

    def test_authorized_keys_permissions(self):
        p = self.write("authorized_keys", pub_line(ed_blob()) + "\n", mode=0o666)
        self.assertIn(("HIGH", "authorized-keys-writable"), self.rules(p))

    def test_pub_file_weak(self):
        p = self.write("id_dsa.pub", pub_line(dsa_blob()) + "\n", mode=0o644)
        self.assertIn(("HIGH", "dsa-key"), self.rules(p))

    def test_good_pub_file(self):
        p = self.write("id_ed25519.pub", pub_line(ed_blob()) + "\n", mode=0o644)
        self.assertEqual(self.rules(p), set())

    def test_config_writable(self):
        p = self.write("config", "Host *\n", mode=0o666)
        self.assertIn(("HIGH", "config-writable"), self.rules(p))


class DirAndCliTests(Base):
    def test_dir_permissions_and_exit_codes(self):
        self.write("id_ok", openssh_private(ed_blob(), b"aes256-ctr"))
        self.assertEqual(ska.main([self.dir]), 0)
        os.chmod(self.dir, 0o755)
        self.assertEqual(ska.main([self.dir]), 1)
        self.assertEqual(ska.main([os.path.join(self.dir, "missing")]), 2)

    def test_info_only_exits_zero(self):
        os.chmod(self.dir, 0o700)
        self.write("authorized_keys", pub_line(ed_blob()) + "\n")
        self.assertEqual(ska.main([self.dir]), 0)


if __name__ == "__main__":
    unittest.main()
