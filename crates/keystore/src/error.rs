use std::io;
use std::path::PathBuf;

use crate::kind::Kind;
use crate::method::Method;
use crate::public_key::PublicKey;

/// Why a key file could not be loaded, written, adopted, unlocked, or have its locks changed.
///
/// Every variant names the file. None carries key material, and none is ever answered by producing
/// a different key: a refusal is the whole outcome.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The file or its directory could not be opened, read, written, synced, or renamed.
    #[error("could not access the key file {}", path.display())]
    Io {
        /// The key file.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
    /// The path names something other than a regular file: a directory, a pipe, a device.
    #[error("the key file {} is not a regular file", path.display())]
    NotAFile {
        /// The key file.
        path: PathBuf,
    },
    /// Group or other holds a permission bit on the file. The seed IS the key, so loading a file
    /// others can reach would bless the leak.
    #[error(
        "the key file {} gives group or other access (mode {:04o}); run `chmod 600 {}`",
        path.display(),
        mode & 0o7777,
        path.display()
    )]
    Permissive {
        /// The key file.
        path: PathBuf,
        /// The mode that failed the owner-only check.
        mode: u32,
    },
    /// The file is owned by a user who is neither this process's user nor root. A process running
    /// as root would otherwise load a key any user could put at the path.
    #[error(
        "the key file {} is owned by uid {owner}, not by this user or root",
        path.display()
    )]
    Owner {
        /// The key file.
        path: PathBuf,
        /// The uid that owns the file.
        owner: u32,
    },
    /// The bytes are not a key file this build can read.
    #[error("the key file {} is not in a format this build reads", path.display())]
    Format {
        /// The key file.
        path: PathBuf,
        /// What the parser refused.
        #[source]
        source: FormatError,
    },
    /// A lock did not open, or the seed did not open under the key it gave. A wrong passphrase and
    /// damaged contents are deliberately this one variant: the cipher cannot tell them apart, and a
    /// refusal that guessed would be an oracle.
    ///
    /// A `touch-id` lock refuses this way only after its touch: the file's contents are checked by
    /// the cipher, and the cipher needs the key the touch gives, so no damage can be found before it.
    #[error("could not unlock the key file {}: {}", path.display(), unlock_cause(*method))]
    Unlock {
        /// The key file.
        path: PathBuf,
        /// The method of the lock that was tried.
        method: Method,
    },
    /// A sealed file unlocked, but its header names a different public key than the seed it seals.
    #[error("the key file {} seals a different key than its header names", path.display())]
    Inconsistent {
        /// The key file.
        path: PathBuf,
    },
    /// A write found a file already at the path. A write lands only where nothing is.
    #[error("a key file already exists at {}", path.display())]
    Occupied {
        /// The key file.
        path: PathBuf,
    },
    /// An adopt found a sealed file claiming the adopted key, and was given no passphrase to prove
    /// the claim with. A sealed file's header names its key before it unlocks, but only the unlock
    /// shows the file really holds that key.
    ///
    /// The message names no key: this crate has no text form for one, so the caller prints
    /// `claimed` in its own.
    #[error(
        "the key file {} is sealed and claims to hold the key; adopting over it needs its passphrase to prove that",
        path.display()
    )]
    Unconfirmed {
        /// The key file.
        path: PathBuf,
        /// The public key the file's header claims, which is also the key the adopt offered.
        claimed: PublicKey,
    },
    /// An adopt found a different key already stored at the path.
    ///
    /// The message names neither key, for the same reason as [`Error::Unconfirmed`].
    #[error("the key file {} already holds a different key", path.display())]
    Different {
        /// The key file.
        path: PathBuf,
        /// The public key the file already holds; for a sealed file, the key its header claims.
        existing: PublicKey,
        /// The public key the adopt offered.
        incoming: PublicKey,
    },
    /// A write asked to store a sealed-only key plain. A sealed-only key is only ever written
    /// sealed.
    #[error("a sealed-only key is always sealed; {} was not written plain", path.display())]
    PlainSealed {
        /// The key file.
        path: PathBuf,
    },
    /// A lock change would leave a sealed-only key with no lock that opens on another machine:
    /// removing its passphrase lock, or sealing a plain one under a lock that opens on this machine
    /// alone. A sealed-only key always keeps one, because it is how a copy of the file opens
    /// anywhere else.
    #[error("a sealed-only key always has a passphrase lock; {} was not changed", path.display())]
    SealedPassphrase {
        /// The key file.
        path: PathBuf,
    },
    /// A lock change asked to set a sealed-only key's passphrase lock while opening the file with a
    /// lock that opens on this machine alone. Whoever holds only that lock must not be able to set
    /// a passphrase that opens every copy of the key.
    #[error(
        "a sealed-only key's passphrase changes only when the file is opened with it; {} was not changed",
        path.display()
    )]
    SealedPassphraseNeeded {
        /// The key file.
        path: PathBuf,
    },
    /// A lock removal would leave no lock that opens the file on this machine: none of the others
    /// is the one that opened it, and none can open here (another Mac's `touch-id` lock, say).
    #[error(
        "removing the {method} lock would leave {} with no lock that opens on this machine; it was not changed",
        path.display()
    )]
    NoneOpensHere {
        /// The key file.
        path: PathBuf,
        /// The method whose removal was refused.
        method: Method,
    },
    /// A lock change found no file to change.
    #[error("there is no key file at {}", path.display())]
    Absent {
        /// The key file.
        path: PathBuf,
    },
    /// The file holds no lock of the method the caller named, to open or to remove. A plain file
    /// holds no lock at all.
    #[error("the key file {} has no {method} lock", path.display())]
    NoLock {
        /// The key file.
        path: PathBuf,
        /// The method the caller named.
        method: Method,
    },
    /// A lock change was given nothing to open the file with, and the file is sealed: only one of its
    /// own locks can open it to change them.
    #[error("the key file {} is sealed; changing its locks needs one of them to open it", path.display())]
    Sealed {
        /// The key file.
        path: PathBuf,
    },
    /// The rewritten file did not read back as the same key, so it was not put in place.
    #[error(
        "the rewritten key file {} did not read back as the same key; the original is unchanged",
        path.display()
    )]
    Unverified {
        /// The key file.
        path: PathBuf,
    },
    /// A lock change found the key file changed or replaced since it read it, and did not write over
    /// it: the old key put back over a new one could destroy the only copy of the new one.
    #[error(
        "the key file {} changed while it was being rewritten; it was left as it now is",
        path.display()
    )]
    Changed {
        /// The key file.
        path: PathBuf,
    },
    /// The filesystem holding the key file has no hard links, which is how a new key file is
    /// published without ever landing over another. FAT and exFAT are such filesystems.
    #[error(
        "the filesystem holding {} cannot publish a key file safely, because it has no hard links",
        path.display()
    )]
    NoHardLinks {
        /// The key file.
        path: PathBuf,
        /// What the filesystem said.
        #[source]
        source: io::Error,
    },
    /// The key file is in place, but its directory could not be synced afterwards, so a power loss
    /// could still undo the change. Not a failed write: loading the file shows the new form.
    #[error(
        "the key file {} was written, but its directory could not be synced to disk",
        path.display()
    )]
    Unsynced {
        /// The key file.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
    /// A `touch-id` lock could not be made or did not open.
    #[error("could not use the touch-id lock of the key file {}", path.display())]
    TouchId {
        /// The key file.
        path: PathBuf,
        /// Why.
        #[source]
        source: TouchIdError,
    },
    /// Sealing or unlocking could not run.
    #[error("could not seal or unlock the key file {}", path.display())]
    Crypto {
        /// The key file.
        path: PathBuf,
        /// Which primitive failed.
        #[source]
        source: CryptoError,
    },
}

/// What a failed unlock through a lock of `method` can mean. A touch that agreed has no wrong input to
/// blame, so only the passphrase names one.
const fn unlock_cause(method: Method) -> &'static str {
    match method {
        Method::Passphrase => "wrong passphrase, or the file is damaged",
        Method::TouchId => "the file is damaged",
    }
}

/// Why a key file's bytes did not parse. Raised by the one parser, before any key is derived, so
/// nothing here depends on a passphrase and nothing here reveals anything about one.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum FormatError {
    /// No sealed-file signature, and not the 32 bytes of a plain seed.
    #[error("the file is {found} bytes, neither a 32-byte plain seed nor a sealed key")]
    Size {
        /// The file's length.
        found: u64,
    },
    /// A sealed-file signature, but the bytes end before its layout does, or run on past it.
    #[error("a sealed key of {found} bytes is truncated or padded")]
    SealedSize {
        /// The file's length.
        found: u64,
    },
    /// A format version this build does not read.
    #[error("sealed key format version {found} is not one this build reads")]
    Version {
        /// The version byte.
        found: u8,
    },
    /// A file kind this build does not know.
    #[error("sealed file kind {found} is not one this build knows")]
    Kind {
        /// The kind byte.
        found: u8,
    },
    /// A sealed file of a known kind, read where the other kind belongs: a standard key presented
    /// as a sealed-only key, or a sealed-only key as a standard key.
    #[error("the sealed file is a {found}, not a {expected}")]
    WrongKind {
        /// The kind the reader expected.
        expected: Kind,
        /// The kind the file records.
        found: Kind,
    },
    /// A lock method this build does not know.
    #[error("lock method {found} is not one this build knows")]
    Method {
        /// The method byte.
        found: u8,
    },
    /// A sealed file with no locks: nothing could open it, so it is not a sealed key.
    #[error("the sealed key has no locks")]
    NoLocks,
    /// A sealed-only key with no lock that opens on another machine. A sealed-only key always keeps
    /// its passphrase lock, so a list without one was not written by this crate.
    #[error("the sealed-only key has no passphrase lock")]
    NoPortableLock,
    /// Two locks of one method. A file holds at most one of each.
    #[error("the sealed key has more than one {method} lock")]
    DuplicateLock {
        /// The method named twice.
        method: Method,
    },
    /// A lock whose body length is not one its method can have: past the method's most, refused
    /// before the body is read, or not what the body's own fields add up to.
    #[error("a {method} lock cannot be {found} bytes")]
    LockLength {
        /// The lock's method.
        method: Method,
        /// The length the record declares.
        found: u16,
    },
    /// A `touch-id` lock's access policy this build does not know.
    #[error("touch-id policy {found} is not one this build knows")]
    Policy {
        /// The policy byte.
        found: u8,
    },
    /// A `touch-id` lock whose blob length does not account for its parameters: no blob, one past
    /// the cap, or one that leaves the one-time key the wrong size.
    #[error("a touch-id lock declares a {found}-byte blob that does not fit it")]
    Blob {
        /// The blob length the lock declares.
        found: u16,
    },
    /// A `touch-id` lock's public key is not an uncompressed P-256 point.
    #[error("a touch-id lock holds a public key that is not an uncompressed P-256 point")]
    Point,
    /// A key derivation function this build does not know.
    #[error("key derivation function {found} is not one this build knows")]
    Kdf {
        /// The derivation byte.
        found: u8,
    },
    /// An Argon2id cost outside the accepted bounds, refused before any memory is committed to it.
    #[error(
        "key derivation cost of {memory_kib} KiB, {passes} passes, {lanes} lanes is outside the accepted bounds"
    )]
    Cost {
        /// Memory, in KiB.
        memory_kib: u32,
        /// Passes over memory.
        passes: u32,
        /// Parallel lanes.
        lanes: u32,
    },
}

/// Sealing or unlocking a key file could not run: the random source, the key derivation, or the
/// cipher failed.
///
/// Opaque, so the primitives this crate uses stay out of its public surface; the cause is in the
/// `source()` chain.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct CryptoError(Primitive);

#[derive(Debug, thiserror::Error)]
enum Primitive {
    #[error("the operating system's random source failed")]
    Entropy(#[source] getrandom::Error),
    #[error("argon2id could not derive a key")]
    Kdf(#[source] argon2::Error),
    #[error("could not allocate the key derivation's working memory")]
    Memory(#[source] std::collections::TryReserveError),
    // The cipher refuses only a key of the wrong length or a message longer than 2^38 bytes, and a
    // 32-byte key and seed are neither. It is a value rather than a panic because this crate does not
    // panic.
    #[error("the cipher could not seal the key")]
    Cipher,
    // A file holds at most one lock per method, so the writer is never handed more than 255 locks.
    // A value rather than a panic for the same reason as `Cipher`.
    #[error("too many locks to seal: a key file holds at most 255")]
    LockCount,
    // A scalar outside the curve's order is about one draw in 2^32; several in a row is a random
    // source that is not random.
    #[cfg(any(test, target_os = "macos"))]
    #[error("could not draw a one-time key")]
    OneTimeKey,
    // HKDF refuses only an output longer than 255 hashes, and 32 bytes is one. A value rather than a
    // panic for the same reason as `Cipher`.
    #[cfg(any(test, target_os = "macos"))]
    #[error("hkdf could not derive a key")]
    Derive,
}

impl CryptoError {
    pub(crate) const fn entropy(source: getrandom::Error) -> Self {
        Self(Primitive::Entropy(source))
    }

    pub(crate) const fn kdf(source: argon2::Error) -> Self {
        Self(Primitive::Kdf(source))
    }

    pub(crate) const fn memory(source: std::collections::TryReserveError) -> Self {
        Self(Primitive::Memory(source))
    }

    pub(crate) const fn cipher() -> Self {
        Self(Primitive::Cipher)
    }

    pub(crate) const fn lock_count() -> Self {
        Self(Primitive::LockCount)
    }

    #[cfg(any(test, target_os = "macos"))]
    pub(crate) const fn one_time_key() -> Self {
        Self(Primitive::OneTimeKey)
    }

    #[cfg(any(test, target_os = "macos"))]
    pub(crate) const fn derive() -> Self {
        Self(Primitive::Derive)
    }
}

/// Why a `touch-id` lock could not be made or opened.
///
/// The variants are the cases a caller tells a person apart: this machine cannot do it at all, the
/// lock is not this Mac's, the person said no, or the person did not answer in time. The enclave's
/// own error rides the `source()` chain.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TouchIdError {
    /// This build has no Secure Enclave to ask: it is not a macOS build.
    #[error("a touch-id lock opens only on macOS")]
    Unavailable,
    /// The lock's key does not open in this Mac's enclave with the fingers enrolled now: a lock made on
    /// another Mac, one made before a finger was added or removed (if a finger was added, the lock opens
    /// again once it is removed), or a damaged one. Told apart from a cancel even when the enclave turns the key down after the
    /// dialog.
    #[error(
        "the lock does not open on this Mac now; if a fingerprint was added after the lock was made, remove it and the lock opens again"
    )]
    NotHere(#[source] EnclaveError),
    /// The person cancelled, or the touch did not match.
    #[error("the touch was cancelled or did not match")]
    Declined(#[source] EnclaveError),
    /// No touch came within the wait the unlock carried, so the dialog was closed. Never a cancel:
    /// nobody said no, and nobody may still be there.
    #[error("no touch came in time")]
    TimedOut(#[source] EnclaveError),
    /// The enclave could not make the key or agree the secret.
    #[error("the Secure Enclave failed")]
    Enclave(#[source] EnclaveError),
}

/// What the enclave said, kept as the cause of a [`TouchIdError`]. Opaque, so the enclave's own types
/// stay out of this crate's surface and out of a build that has no enclave.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct EnclaveError(Box<dyn core::error::Error + Send + Sync>);

impl EnclaveError {
    /// Wrap `source` as what the enclave said. This crate builds one from each enclave failure; a
    /// caller builds one to make the [`TouchIdError`] it needs in its own tests, on any target, since
    /// a build without an enclave has no other way to reach most of the variants.
    ///
    /// It is only an error value: it carries no path and no key, and opens nothing.
    ///
    /// ```
    /// use keystore::{EnclaveError, TouchIdError};
    ///
    /// let timed_out = TouchIdError::TimedOut(EnclaveError::new(std::io::Error::other("no touch")));
    /// assert_eq!(timed_out.to_string(), "no touch came in time");
    /// ```
    pub fn new(source: impl core::error::Error + Send + Sync + 'static) -> Self {
        Self(Box::new(source))
    }
}

/// What the enclave handed back that a lock cannot hold. Raised on this side of the enclave, so it
/// rides an [`EnclaveError`] like the enclave's own errors do.
#[cfg(any(test, target_os = "macos"))]
#[derive(Debug, thiserror::Error)]
pub(crate) enum Unusable {
    #[error("the Secure Enclave's public key is not a P-256 point")]
    Point,
    #[cfg(target_os = "macos")]
    #[error("the Secure Enclave's key blob is {found} bytes, outside what a lock holds")]
    BlobLength { found: usize },
}

/// Why a lock's method could not make or open its key: the primitives failed, or the enclave did.
/// Crate-private: a key file attaches its path and reports each as its own [`Error`] variant.
#[derive(Debug)]
pub(crate) enum MethodError {
    Crypto(CryptoError),
    TouchId(TouchIdError),
}

impl From<CryptoError> for MethodError {
    fn from(source: CryptoError) -> Self {
        Self::Crypto(source)
    }
}

impl From<TouchIdError> for MethodError {
    fn from(source: TouchIdError) -> Self {
        Self::TouchId(source)
    }
}
