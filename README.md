# sshkey-audit

Audit the SSH keys in `~/.ssh`, **read-only**. It spots private keys without a
passphrase (read from the key file header; the key is never decrypted or used), weak
key types and sizes, loose permissions, and risky `authorized_keys` entries.
One file, standard library only.

Key material is never printed. Public SHA256 fingerprints are shown so you can match
findings to keys (compare with `ssh-keygen -lf <key>`).

## Usage

```bash
python3 sshkey_audit.py                 # audits ~/.ssh
python3 sshkey_audit.py ~/.ssh/id_ed25519 /path/to/authorized_keys
python3 sshkey_audit.py ~/.ssh --json
# or: pip install git+https://github.com/TPOALOS/sshkey-audit && sshkey-audit
```

Suggested fix commands are shell-quoted, so a path with spaces or `$(...)` in it stays inert if you paste the command.

Example output:

```
HIGH   no-passphrase            /home/me/.ssh/id_rsa: private key (ssh-rsa 4096-bit, SHA256:abc...) has no passphrase
         fix: add one: ssh-keygen -p -f /home/me/.ssh/id_rsa
HIGH   private-key-permissions  /home/me/.ssh/id_rsa: private key is accessible by other users (0644)
         fix: chmod 600 /home/me/.ssh/id_rsa
LOW    duplicate-key            /home/me/.ssh/authorized_keys:7: SHA256:def... duplicates line 3
```

## Checks

| Rule | Severity | Meaning |
|------|----------|---------|
| `no-passphrase` | HIGH | OpenSSH keys with cipher `none`, legacy PEM / PKCS#8 keys that are not encrypted |
| `private-key-permissions` | HIGH | private key readable or writable by group/others |
| `dsa-key`, `weak-rsa` | HIGH | DSA keys, RSA under 2048 bits |
| `short-rsa` | MEDIUM | RSA under 3072 bits |
| `ssh-dir-permissions` | MEDIUM | `.ssh` accessible by others (want `700`) |
| `authorized-keys-writable`, `config-writable` | HIGH | writable by group/others |
| `duplicate-key`, `legacy-format`, `unparsed-line` | LOW | repeated keys, legacy PEM format, malformed lines |
| `few-kdf-rounds` | LOW | encrypted OpenSSH key protected with fewer than 16 bcrypt rounds (guessing the passphrase is cheap); fix with `ssh-keygen -p -a 100` |
| `dsa-key`, `weak-rsa`, `short-rsa` in `known_hosts` | HIGH / MEDIUM | the same key-strength checks applied to host keys in `known_hosts` / `ssh_known_hosts` (host names are never printed) |
| `unrestricted-key` | INFO | `authorized_keys` entry without `restrict`, `command=` or `from=` (does not affect the exit code) |

Exit codes: `0` clean (or INFO only), `1` findings, `2` path not found.

## Limits

A passphrase is detected from the file format, not tested: an encrypted key can still have
a weak passphrase. It does not read SSH agent contents, and it cannot
tell whether a key is still authorised anywhere. Unparseable files are reported as INFO.

## Tests

Tests build fake key containers at runtime (no real key material in this repository):

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS
