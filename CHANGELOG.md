# Changelog

All notable changes to keystore, newest first.

## Unreleased

### Breaking

- **The two kinds of key file are named for what they allow.** `KeyFile::device` is now
  `KeyFile::new` (plain or sealed, as its owner chooses) and `KeyFile::root` is now
  `KeyFile::strict` (always sealed, never without its passphrase lock). `Kind::Device` and
  `Kind::Root` are now `Kind::Standard` and `Kind::Strict`, and `Error::PlainRoot` and
  `Error::RootPassphrase` are now `Error::PlainStrict` and `Error::StrictPassphrase`.
- **`Method`, `Unlock`, `NewLock` and `Protection` gain `TouchId`.** An exhaustive match on them needs
  the new arm. `Unlock::TouchId`, `NewLock::TouchId` and `Protection::TouchId` carry a `wait`: how long
  the Touch ID dialog stays up.

### New

- **`touch-id`, a second lock.** A key in a Mac's Secure Enclave opens the file after a touch. It
  opens only on the Mac that made it, while the same fingers are enrolled; other builds read and keep
  it. `Protection::TouchId` writes a new standard key sealed under it, never on disk plain.
  `NewLock::TouchId` adds it beside a passphrase, or as a standard key's only lock. `Unlock::TouchId`
  opens with it. `Locked::health` says, with no dialog, whether a lock opens on this machine now:
  `Live`, `Dead`, or `Unchecked` when the enclave cannot say (a locked screen, a lockout). Format:
  lock method `2`.
- **A Touch ID dialog closes itself when its wait runs out.** The call then fails as
  `TouchIdError::TimedOut`, never `Declined`: nobody said no.
- **A strict key always keeps its passphrase lock.** A strict key file without one is refused as it
  is read (`FormatError::NoPortableLock`), and its passphrase changes only when the file is opened
  with it (`Error::StrictPassphraseNeeded`).
- **A removal keeps a lock that opens here.** Removing a lock is refused when locks are left, none
  of them opened the file, and none is known to open on this machine (`Error::NoneOpensHere`).
- **`EnclaveError::new`, public on every target.** A dependent can build, in its own tests, each
  `TouchIdError` that carries an enclave cause (`NotHere`, `Declined`, `TimedOut`, `Enclave`).
- **`keystore-enclave`**, the Secure Enclave calls behind `touch-id`, as a crate of its own.
  `Key::agree` takes the wait, closes its dialog when it runs out, and fails as `Error::TimedOut`.
  macOS only; empty on every other target.

## v0.1.0

First release.

- **One ed25519 secret key in one file.** Plain, or sealed under a passphrase (Argon2id,
  XChaCha20-Poly1305), and opened as a device key (`KeyFile::device`) or a root key
  (`KeyFile::root`).
- **The passphrase changes without changing the key.** `KeyFile::add_lock` seals a plain file or
  changes the passphrase; `KeyFile::remove_lock` writes a device key plain again.
- **`PublicKey` is 32 bytes and nothing else.** `PublicKey::bytes` returns them; there is no text
  form and no curve check, so a caller that needs an identity type builds its own from the bytes.
