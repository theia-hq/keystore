use std::path::PathBuf;

use crate::envelope::{Envelope, Opened, Refusal};
use crate::error::Error;
use crate::method::{Method, Unlock};
use crate::public_key::PublicKey;
use crate::secret::Secret;

/// A key file that is present and well-formed: either its key, or the locked form of it.
///
/// Both answer [`public_key`](Self::public_key) without unlocking, and a locked file names its locks
/// ([`Locked::methods`]), so a caller can say which key a file is for, and how it opens, before
/// deciding whether to ask for anything. For a sealed file that key is the file's claim, not yet a
/// fact; see [`Locked::public_key`].
#[derive(Debug)]
pub enum Stored {
    /// A plain file: the key, ready to use.
    Plain(Secret),
    /// A sealed file: the key is inside, and [`Locked::unlock`] is the only way to it.
    Locked(Locked),
}

impl Stored {
    /// The public key the file is for: for a plain file, computed from the seed it holds; for a
    /// sealed file, what its header claims, proven only by [`Locked::unlock`].
    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::Plain(secret) => secret.public_key(),
            Self::Locked(locked) => locked.public_key(),
        }
    }
}

/// A sealed key file, parsed and bounded but not yet unlocked.
pub struct Locked {
    path: PathBuf,
    // Boxed so a `Stored` is two pointers wide either way, rather than the size of a sealed file.
    envelope: Box<Envelope>,
}

impl Locked {
    pub(crate) fn new(path: PathBuf, envelope: Envelope) -> Self {
        Self {
            path,
            envelope: Box::new(envelope),
        }
    }

    /// The methods of this file's locks, from its header, in file order. At least one, and never one
    /// method twice. Any one of them opens the file.
    pub fn methods(&self) -> impl Iterator<Item = Method> + '_ {
        self.envelope.methods()
    }

    /// Whether this file's lock of `method` can open it on this machine, read without asking anyone
    /// for anything; `None` when the file holds no such lock.
    ///
    /// A passphrase lock is always [`Health::Live`]: whether the passphrase is right is known only by
    /// trying it. A `touch-id` lock is asked of the enclave with no dialog allowed. It is
    /// [`Health::Live`] when the enclave refuses only for want of a touch, and [`Health::Dead`] when the
    /// enclave refuses the key itself: another Mac's lock, a damaged one, or one made under other
    /// enrolled fingers than the ones enrolled now. A lock that stops opening when a finger is enrolled
    /// opens again when that finger is removed, so dead is a reading of now. Every `touch-id` lock is
    /// dead on a build with no enclave. Any other answer (a locked screen, a lockout, a busy enclave, a
    /// code not named) is [`Health::Unchecked`], never dead.
    ///
    /// A lock someone else put on the file, for a key they made in this Mac's enclave, reads as live:
    /// telling it from your own takes the touch, because only the unwrap shows whose file key it holds.
    pub fn health(&self, method: Method) -> Option<Health> {
        self.envelope.health(method)
    }

    /// The public key this file CLAIMS to seal, read from its header without unlocking.
    ///
    /// A claim, not a fact, until [`unlock`](Self::unlock) succeeds. The header is authenticated as
    /// part of the unlock, and nothing checks it before: anyone who can write the file can make it
    /// claim any key, even bytes no key could be, and the file then fails to unlock rather than open
    /// as that key. Use this to show which key a file is for or to decide what to ask for; never to
    /// conclude that the file holds a key. [`KeyFile::adopt`](crate::KeyFile::adopt) proves a claim by
    /// unlocking it.
    pub fn public_key(&self) -> PublicKey {
        self.envelope.public_key()
    }

    /// Unlock the key through the lock `with` opens. Success proves the header: the key it returns
    /// is the one [`public_key`](Self::public_key) claims.
    ///
    /// A file with no lock of `with`'s method refuses as [`Error::NoLock`]. A wrong passphrase and a
    /// damaged file both refuse as [`Error::Unlock`]. A failed unlock is a refusal and nothing more:
    /// the file is left as it was, and no key stands in for the one that did not open.
    pub fn unlock(&self, with: Unlock<'_>) -> Result<Secret, Error> {
        self.open(with).map(|opened| opened.secret)
    }

    /// [`unlock`](Self::unlock), keeping the file key a lock change re-wraps.
    pub(crate) fn open(&self, with: Unlock<'_>) -> Result<Opened, Error> {
        self.envelope
            .unlock(with)
            .map_err(|refusal| self.refused(refusal))
    }

    pub(crate) fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    /// A refusal, with this file's path attached.
    pub(crate) fn refused(&self, refusal: Refusal) -> Error {
        let path = self.path.clone();
        match refusal {
            Refusal::Unlock(method) => Error::Unlock { path, method },
            Refusal::Inconsistent => Error::Inconsistent { path },
            Refusal::NoLock(method) => Error::NoLock { path, method },
            Refusal::TouchId(source) => Error::TouchId { path, source },
            Refusal::Crypto(source) => Error::Crypto { path, source },
        }
    }
}

/// Whether a lock can open its file on this machine, as [`Locked::health`] reads it without asking
/// anyone for anything.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Health {
    /// It can open the file here, given what its method asks for.
    Live,
    /// It does not open the file here now, whatever is offered: for a `touch-id` lock, not with the
    /// fingers enrolled now, or not on this Mac.
    Dead,
    /// It could not be checked now: the enclave gave an answer that says neither, as a lockout after
    /// failed touches may. It may open later.
    Unchecked,
}

/// Names the file, the public key, and its locks, never the sealed bytes.
impl core::fmt::Debug for Locked {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Locked")
            .field("path", &self.path)
            .field("public_key", &self.public_key())
            .field("methods", &self.methods().collect::<Vec<_>>())
            .finish()
    }
}
