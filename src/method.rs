use core::fmt;

use crate::passphrase::Passphrase;

/// How one lock on a sealed key file opens: the method record, read from the file's own bytes.
///
/// A sealed file holds a list of locks, at most one per method, and any one of them opens it. A
/// plain file holds none, so plain is not a method: it is the absence of every lock.
///
/// Deliberately exhaustive: a method added later must be a compile error at every `match` that
/// decides something by method. Only built methods are variants; a name reserved for the future is
/// not registered here, in the file format, or anywhere a value could carry it. A method is built on
/// every target even where it cannot open: a build without an enclave still reads, names, and keeps a
/// `touch-id` lock, and opens the file with another.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Method {
    /// A passphrase: Argon2id derives a key from it, and XChaCha20-Poly1305 wraps the file key under
    /// that.
    Passphrase,
    /// A touch on this Mac: a key in its Secure Enclave, kept as a blob in the lock, agrees a secret
    /// with a one-time key after a touch of a finger enrolled when the lock was made, and the file key is wrapped under a
    /// key derived from that.
    TouchId,
}

impl Method {
    /// Whether this lock opens a copy of the file on another machine. A passphrase does; a
    /// `touch-id` lock opens only on the Mac whose enclave made it. A root key always keeps one
    /// lock that does.
    pub const fn portable(self) -> bool {
        match self {
            Self::Passphrase => true,
            Self::TouchId => false,
        }
    }
}

/// The method's name, the one word a person sees for it.
impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Passphrase => "passphrase",
            Self::TouchId => "touch-id",
        })
    }
}

/// What a caller holds to open one lock: the input to [`Locked::unlock`](crate::Locked::unlock), and
/// the proof a lock change starts from. Each variant carries what its method needs, so a passphrase
/// unlock without its passphrase cannot be expressed.
#[derive(Clone, Copy, Debug)]
pub enum Unlock<'a> {
    /// Open the passphrase lock with this passphrase.
    Passphrase(&'a Passphrase),
    /// Open the `touch-id` lock with a touch, showing `reason` in the dialog. macOS frames it as
    /// `<program> is trying to <reason>`, so it is a line a person reads.
    TouchId {
        /// Why the touch is asked for.
        reason: &'a str,
    },
}

impl Unlock<'_> {
    /// The method of the lock this opens.
    pub const fn method(&self) -> Method {
        match self {
            Self::Passphrase(_) => Method::Passphrase,
            Self::TouchId { .. } => Method::TouchId,
        }
    }
}

/// A lock to put on a key file: what [`KeyFile::add_lock`](crate::KeyFile::add_lock) wraps the file
/// key under.
#[derive(Clone, Copy, Debug)]
pub enum NewLock<'a> {
    /// A passphrase lock under this passphrase.
    Passphrase(&'a Passphrase),
    /// A `touch-id` lock on this Mac. Making it asks nothing of anyone; the rewritten file is then
    /// proven by opening it through the new lock, which asks for one touch, with `reason` in the
    /// dialog.
    TouchId {
        /// Why the touch that proves the new lock is asked for.
        reason: &'a str,
    },
}

impl<'a> NewLock<'a> {
    /// The method of the lock this makes.
    pub const fn method(&self) -> Method {
        match self {
            Self::Passphrase(_) => Method::Passphrase,
            Self::TouchId { .. } => Method::TouchId,
        }
    }

    /// What opens the lock this makes, so a rewrite is proven through the lock it just added.
    pub(crate) const fn opener(self) -> Unlock<'a> {
        match self {
            Self::Passphrase(passphrase) => Unlock::Passphrase(passphrase),
            Self::TouchId { reason } => Unlock::TouchId { reason },
        }
    }
}

/// How a new key file is written: plain, or sealed with one lock. The input to
/// [`KeyFile::write`](crate::KeyFile::write) and [`KeyFile::adopt`](crate::KeyFile::adopt), where the
/// same lock also proves a sealed file already at the path.
#[derive(Clone, Copy, Debug)]
pub enum Protection<'a> {
    /// Store the raw seed.
    Plain,
    /// Seal the seed under one passphrase lock, or unlock it with this passphrase.
    Passphrase(&'a Passphrase),
    /// Seal the seed under one `touch-id` lock, or unlock it with a touch, showing `reason` in the
    /// dialog. A new key sealed this way is never on disk plain, not even for a moment.
    TouchId {
        /// Why the touch is asked for.
        reason: &'a str,
    },
}
