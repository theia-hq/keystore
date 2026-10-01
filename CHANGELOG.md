# Changelog

All notable changes to keystore, newest first.

## v0.1.0

First release.

- **One ed25519 secret key in one file.** Plain, or sealed under a passphrase (Argon2id,
  XChaCha20-Poly1305), and opened as a device key (`KeyFile::device`) or a root key
  (`KeyFile::root`).
- **The passphrase changes without changing the key.** `KeyFile::add_lock` seals a plain file or
  changes the passphrase; `KeyFile::remove_lock` writes a device key plain again.
- **`PublicKey` is 32 bytes and nothing else.** `PublicKey::bytes` returns them; there is no text
  form and no curve check, so a caller that needs an identity type builds its own from the bytes.
