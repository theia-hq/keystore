//! Storage for one secret key: one [`Secret`], one versioned file format, and the codecs that
//! load, write, adopt, and lock a key file.
//!
//! A key file holds one ed25519 seed of one [`Kind`]. The kind says what the key is for, a device's
//! own key or a root key, and is chosen by naming the file ([`KeyFile::device`], [`KeyFile::root`]);
//! a sealed file of the other kind is refused, and a root key is never written plain. A file is plain,
//! the raw 32-byte seed, or sealed: a random file key seals the seed, and a lock wraps that file key.
//! The format holds a list of locks, at most one per [`Method`], and any one opens the file. The
//! methods are `passphrase` and `touch-id`, a key in a Mac's Secure Enclave that opens with a touch.
//! A `touch-id` lock opens only on the Mac that made it, so a root key always keeps its passphrase
//! lock, the one that opens a copy of the file anywhere. A build for another platform reads and keeps
//! a `touch-id` lock, and opens the file with another lock.
//!
//! The locks are a property of the FILE. They are read from the file's own bytes, never from
//! configuration, and they change only when [`KeyFile::add_lock`] or [`KeyFile::remove_lock`]
//! rewrites the file. [`KeyFile::load`] states which case it found (nothing there, a plain key, a
//! locked key) or why it refuses, and it never returns a key the file does not hold.
//!
//! This crate stores and unlocks; it decides nothing else. Where a key file lives, whether an absent
//! one should be created, how a passphrase is obtained from a person, and what the key signs all
//! belong to the caller. That split is enforced by what the crate depends on, and pinned by its tests.
//!
//! The secret itself never leaves a [`Secret`] by value: it is lent out through a borrow
//! ([`Secret::with_bytes`]), and every buffer that holds it here is wiped on drop. What this cannot
//! stop is a copy the caller makes on purpose: a seed is a `Copy` array, so
//! `secret.with_bytes(|seed| *seed)` compiles to a bare `[u8; 32]` that nothing wipes. Hand the borrow
//! on instead: `secret.with_bytes(f)`, where `f` takes `&[u8; 32]`, makes no copy.

mod cipher;
mod envelope;
mod error;
mod key_file;
mod kind;
mod lock;
mod method;
mod passphrase;
mod public_key;
mod secret;
mod stored;
#[cfg(unix)]
mod uid;

pub use error::{CryptoError, EnclaveError, Error, FormatError, TouchIdError};
pub use key_file::KeyFile;
pub use kind::Kind;
pub use method::{Method, NewLock, Protection, Unlock};
pub use passphrase::{Passphrase, PassphraseError};
pub use public_key::PublicKey;
pub use secret::Secret;
pub use stored::{Health, Locked, Stored};

#[cfg(test)]
mod test_dir;
