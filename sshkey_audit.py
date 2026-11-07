#!/usr/bin/env python3
"""sshkey-audit - audit the SSH keys in ~/.ssh (read-only).

Checks private keys for a missing passphrase (read from the key file header, the
key is never decrypted), weak key types and sizes (DSA, short RSA), loose file
permissions, and authorized_keys for weak or duplicate keys. Key material is never
printed; public fingerprints are shown to help you identify keys.
Standard library only. Exit code 0 = clean, 1 = findings, 2 = error.
"""
import argparse
import base64
import binascii
import hashlib
import os
import re
import stat
import struct
import sys

__version__ = "1.0.0"
SEV = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
PEM = re.compile(r"-----BEGIN ([A-Z ]*)PRIVATE KEY-----(.*?)-----END [A-Z ]*PRIVATE KEY-----", re.S)
KEY_TYPES = ("ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
             "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")


class KeyError_(ValueError):
    pass


def read_string(buf, off):
    if off + 4 > len(buf):
        raise KeyError_("truncated data")
    (n,) = struct.unpack(">I", buf[off:off + 4])
    if off + 4 + n > len(buf):
        raise KeyError_("truncated data")
    return buf[off + 4:off + 4 + n], off + 4 + n


def fingerprint(blob):
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def parse_public_blob(blob):
    """Return (key_type, bits_or_None) for an SSH wire-format public key blob."""
    raw, off = read_string(blob, 0)
    ktype = raw.decode("ascii", "replace")
    if ktype == "ssh-rsa":
        _, off = read_string(blob, off)           # e
        n, _ = read_string(blob, off)
        return ktype, int.from_bytes(n, "big").bit_length()
    if ktype == "ssh-dss":
        p, _ = read_string(blob, off)
        return ktype, int.from_bytes(p, "big").bit_length()
    if ktype.startswith("ecdsa-sha2-nistp") or ktype.startswith("sk-ecdsa"):
        m = re.search(r"nistp(\d+)", ktype)
        return ktype, int(m.group(1)) if m else None
    if "ed25519" in ktype:
        return ktype, 256
    return ktype, None


def parse_openssh_private(body):
    """Parse an openssh-key-v1 body; return (cipher, public_blob)."""
    try:
        data = base64.b64decode("".join(body.split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise KeyError_("invalid base64") from exc
    magic = b"openssh-key-v1\x00"
    if not data.startswith(magic):
        raise KeyError_("not an openssh-key-v1 file")
    off = len(magic)
    cipher, off = read_string(data, off)
    _kdf, off = read_string(data, off)
    _opts, off = read_string(data, off)
    if off + 4 > len(data):
        raise KeyError_("truncated data")
    (count,) = struct.unpack(">I", data[off:off + 4])
    off += 4
    if count < 1:
        raise KeyError_("no keys in file")
    pub, _ = read_string(data, off)
    return cipher.decode("ascii", "replace"), pub


def strength_findings(ktype, bits, where, add):
    if ktype == "ssh-dss":
        add("HIGH", "dsa-key", "%s: DSA keys are obsolete and unsupported by modern OpenSSH" % where,
            "generate an Ed25519 key: ssh-keygen -t ed25519")
    elif ktype == "ssh-rsa" and bits is not None:
        if bits < 2048:
            add("HIGH", "weak-rsa", "%s: RSA key is only %d bits" % (where, bits), "use Ed25519 or RSA of at least 3072 bits")
        elif bits < 3072:
            add("MEDIUM", "short-rsa", "%s: RSA key is %d bits" % (where, bits), "use Ed25519 or RSA of at least 3072 bits")


def audit_private(path, text, mode):
    out = []
    add = lambda sev, rule, msg, fix="": out.append((sev, rule, msg, fix))
    m = PEM.search(text)
    label, body = m.group(1).strip(), m.group(2)
    if mode & 0o077:
        add("HIGH", "private-key-permissions", "private key is accessible by other users (%04o)" % mode, "chmod 600 %s" % path)
    if label == "OPENSSH":
        try:
            cipher, pub = parse_openssh_private(body)
            ktype, bits = parse_public_blob(pub)
        except KeyError_ as exc:
            add("INFO", "unparsed", "could not parse OpenSSH key (%s)" % exc)
            return out
        fp = fingerprint(pub)
        desc = "%s %s" % (ktype, ("%d-bit" % bits) if bits else "")
        if cipher == "none":
            add("HIGH", "no-passphrase", "private key (%s, %s) has no passphrase" % (desc.strip(), fp),
                "add one: ssh-keygen -p -f %s" % path)
        strength_findings(ktype, bits, "%s (%s)" % (desc.strip(), fp), add)
    else:
        encrypted = "ENCRYPTED" in label or "Proc-Type: 4,ENCRYPTED" in body
        if not encrypted:
            add("HIGH", "no-passphrase", "private key (%s format) has no passphrase" % (label or "PKCS8"),
                "add one: ssh-keygen -p -f %s" % path)
        if label in ("RSA", "DSA", "EC"):
            add("LOW", "legacy-format", "key uses the legacy PEM format", "convert: ssh-keygen -p -o -f %s" % path)
    return out


def parse_key_line(line):
    """Parse an authorized_keys/.pub line. Returns (options, type, blob, comment) or None."""
    parts = line.strip().split()
    for i, tok in enumerate(parts):
        if tok in KEY_TYPES or tok.startswith(("ssh-", "ecdsa-", "sk-")):
            if i + 1 >= len(parts):
                return None
            try:
                blob = base64.b64decode(parts[i + 1], validate=True)
            except (binascii.Error, ValueError):
                return None
            return " ".join(parts[:i]), tok, blob, " ".join(parts[i + 2:])
    return None


def audit_public_lines(text, is_authorized):
    out = []
    add = lambda sev, rule, msg, fix="", no=None: out.append((sev, rule, msg, fix, no))
    seen = {}
    for no, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parsed = parse_key_line(line)
        if not parsed:
            add("LOW", "unparsed-line", "line is not a valid public key", "", no)
            continue
        opts, _t, blob, _c = parsed
        try:
            ktype, bits = parse_public_blob(blob)
        except KeyError_:
            add("LOW", "unparsed-line", "public key blob could not be parsed", "", no)
            continue
        fp = fingerprint(blob)
        tmp = []
        strength_findings(ktype, bits, fp, lambda s, r, m, f="": tmp.append((s, r, m, f)))
        for s, r, m, f in tmp:
            add(s, r, m, f, no)
        if is_authorized:
            if fp in seen:
                add("LOW", "duplicate-key", "%s duplicates line %d" % (fp, seen[fp]), "remove the duplicate", no)
            seen.setdefault(fp, no)
            if not re.search(r"(?i)\b(restrict|command=|from=)", opts):
                add("INFO", "unrestricted-key", "%s has no restrict/command=/from= options" % fp,
                    "consider `restrict` or `from=` for automation keys", no)
    return out


def audit_path(path):
    """Return list of (severity, rule, message, fix, lineno) for one file."""
    out = []
    name = os.path.basename(path)
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            return out
        mode = stat.S_IMODE(st.st_mode)
        if st.st_size > 1_000_000:
            return out
        with open(path, errors="replace") as fh:
            text = fh.read()
    except OSError:
        return out
    if PEM.search(text):
        out += [(s, r, m, f, None) for s, r, m, f in audit_private(path, text, mode)]
    elif name == "authorized_keys" or name.startswith("authorized_keys"):
        out += audit_public_lines(text, True)
        if mode & 0o022:
            out.append(("HIGH", "authorized-keys-writable", "authorized_keys is writable by others (%04o)" % mode,
                        "chmod 600 %s" % path, None))
    elif name.endswith(".pub"):
        out += audit_public_lines(text, False)
    elif name == "config" and mode & 0o022:
        out.append(("HIGH", "config-writable", "ssh config is writable by others (%04o)" % mode, "chmod 600 %s" % path, None))
    return out


def audit_dir(path):
    out = []
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return out
    if os.path.basename(os.path.abspath(path)) == ".ssh" and mode & 0o077:
        out.append((path, ("MEDIUM", "ssh-dir-permissions", ".ssh directory is accessible by others (%04o)" % mode,
                           "chmod 700 %s" % path, None)))
    for name in sorted(os.listdir(path)):
        full = os.path.join(path, name)
        if os.path.isfile(full) and not os.path.islink(full):
            out += [(full, f) for f in audit_path(full)]
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Audit SSH keys (read-only; key material never printed).")
    ap.add_argument("paths", nargs="*", help="files or directories (default: ~/.ssh)")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    paths = args.paths or [os.path.expanduser("~/.ssh")]
    results = []
    for p in paths:
        if not os.path.exists(p):
            print("sshkey-audit: no such path: %s" % p, file=sys.stderr)
            return 2
        results += audit_dir(p) if os.path.isdir(p) else [(p, f) for f in audit_path(p)]
    count = 0
    for path, (sev, rule, msg, fix, no) in sorted(results, key=lambda r: (SEV[r[1][0]], r[0])):
        print("%-6s %-24s %s%s: %s%s" % (sev, rule, path, ":%d" % no if no else "", msg, "\n         fix: " + fix if fix else ""))
        count += sev != "INFO"
    print("sshkey-audit: %d finding(s)" % count, file=sys.stderr)
    return 1 if count else 0


if __name__ == "__main__":
    sys.exit(main())
