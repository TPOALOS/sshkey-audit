# Changelog

## 1.1.1

- Suggested fix commands no longer contain file names with newlines or other control characters (such a name could split a
  pasted command into two); a harmless placeholder is shown instead

## 1.1.0

- New `few-kdf-rounds` check for passphrase-protected OpenSSH keys
- `known_hosts` and `ssh_known_hosts` are checked for weak host keys (host names never printed)
- `--json` output; suggested fix commands are now shell-quoted
- Installable with pip (`sshkey-audit` command), CI on Linux and macOS

## 1.0.0

Initial release.
