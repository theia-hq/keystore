# keystore

keystore stores one ed25519 secret key (its 32-byte seed) in one file, plain or sealed. Sealed, a random
file key encrypts the seed with XChaCha20-Poly1305, and each lock on the file wraps that file key. A lock
is a passphrase, stretched with Argon2id, or `touch-id`, a key in a Mac's Secure Enclave that opens the
file with a touch. Any one lock opens the file.

- **The public key, readable while locked.** A sealed file names its public key, so you can show
  which key it holds before asking for a passphrase. Unlocking checks that name against the seed and
  refuses a file where they differ.
- **A standard key or a strict key.** A strict key is never written plain and always keeps its
  passphrase lock, the one lock that opens a copy on any machine. A sealed file records its kind,
  and you open it as one or the other (`KeyFile::new`, `KeyFile::strict`); a sealed file of the
  other kind is refused.
- **Changing a lock keeps the key.** Sealing a plain file, adding or changing a lock, and removing one
  (`KeyFile::add_lock`, `KeyFile::remove_lock`) rewrite the file around the same seed.
- **Writes land whole.** Each new file is staged beside the old one and read back as the same key
  before it takes the path, so a crash or a wrong passphrase leaves the old file as it was.

keystore stores and unlocks, nothing more. Where the file lives, how a passphrase is asked for, and
what the key signs are up to you.

## Use

```toml
[dependencies]
keystore = { git = "https://github.com/theia-hq/keystore" }
zeroize = "1"
```

```rust,no_run
use keystore::{KeyFile, NewLock, Passphrase, Protection, Secret, Stored, Unlock};
use zeroize::Zeroizing;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = KeyFile::new("secret.key");
    let passphrase = Passphrase::try_from(Zeroizing::new(String::from("correct horse")))?;

    // Write a new key, sealed under the passphrase.
    let secret = Secret::generate()?;
    file.write(&secret, Protection::Passphrase(&passphrase))?;

    // Load it. The public key is readable before the unlock.
    let Some(Stored::Locked(locked)) = file.load()? else {
        return Err("expected a sealed key file".into());
    };
    assert_eq!(locked.public_key(), secret.public_key());
    let unlocked = locked.unlock(Unlock::Passphrase(&passphrase))?;
    unlocked.with_bytes(|seed| assert_eq!(seed.len(), 32));

    // Change the passphrase: the new lock replaces the old one, and the key stays the same.
    let new = Passphrase::try_from(Zeroizing::new(String::from("battery staple")))?;
    file.add_lock(Some(Unlock::Passphrase(&passphrase)), NewLock::Passphrase(&new))?;
    Ok(())
}
```

`KeyFile::write` never writes over an existing file (`Error::Occupied`), so the example runs once
per path. `KeyFile::load` returns `None` when nothing is at the path; keystore never creates a key
on its own.

[`crates/keystore/examples/touch_id.rs`](crates/keystore/examples/touch_id.rs) puts a `touch-id` lock
on a new key file and opens it with a touch: `cargo run --example touch_id -- <path>`.

[`crates/keystore/examples/touch_id_probe.rs`](crates/keystore/examples/touch_id_probe.rs) prints what
the Secure Enclave answers, with no dialog, as the screen locks, Touch ID locks out, or a finger is
added or removed.

## Crates

| crate                                                   | what it is                                                                                  |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `keystore`                                              | one ed25519 secret key in one file, plain or sealed under a passphrase or `touch-id`        |
| [`keystore-enclave`](crates/keystore-enclave/README.md) | a P-256 key in a Mac's Secure Enclave, kept as a blob you store, that does ECDH after a touch; macOS only |

## Platforms

Tested on Linux and macOS. On Unix, a key file must be owned by you (or root) and open to no one
else, or loading it fails with `Error::Owner` or `Error::Permissive`; `chmod 600` fixes the mode.
Files keystore writes are owner-only already. Other platforms have no owner or mode check.

A `touch-id` lock opens only on the Mac that made it, and only while the same fingers are enrolled.
Anywhere else, keystore reads and keeps the lock and opens the file with another one. When two files
have `touch-id` locks made on one Mac with the same fingers, anyone who holds both can see that.

## Format

The byte layout is in `crates/keystore/src`: the file in [`envelope.rs`](crates/keystore/src/envelope.rs),
a lock in [`lock.rs`](crates/keystore/src/lock.rs), and each lock's parameters in
[`lock/passphrase.rs`](crates/keystore/src/lock/passphrase.rs) and
[`lock/enclave.rs`](crates/keystore/src/lock/enclave.rs).

## License

MIT or Apache-2.0, at your option.
