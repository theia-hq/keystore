//! A lock: one way into a sealed key file. Each lock wraps the file key, and any one of them opens
//! the file.
//!
//! In the file a lock is a record: its method byte, its body's length (two bytes, big-endian), and
//! its body. The body is the method's parameters, then the wrap, which is the same for every method:
//!
//! | len | field                                                                  |
//! | --- | ---------------------------------------------------------------------- |
//! | ..  | the method's parameters, one fixed length per method                   |
//! | 24  | XChaCha20-Poly1305 nonce                                               |
//! | 48  | the file key, encrypted under the method's key, then its Poly1305 tag  |
//!
//! Each method's parameters have one length, so a length is judged against the method before a byte
//! of the body is read.
//!
//! **The seam.** A method turns what the caller holds, plus its stored parameters, into a 32-byte
//! key-encryption key ([`Kek`]), and that is all it does. This module owns everything else: the file
//! key, the nonce, the cipher, and the associated data. So no method ever holds the file key or the
//! seed, and the wrap is written once for every method. Each method is reached from an exhaustive
//! `match` here, never through a trait, so nothing outside the crate can add one.
//!
//! A lock's wrap authenticates the file's first 42 bytes (the signature, version, kind, and public
//! key), its own method byte, and its own body up to the wrapped file key: the parameters and the
//! nonce. It does not cover the lock count or any other lock, so adding or removing a lock never
//! disturbs the ones that stay. What binds the list together is the seed's seal, which covers every
//! byte before it (see `envelope`).

pub(crate) mod passphrase;

use zeroize::Zeroizing;

use crate::cipher::{self, Failed, KEY_LEN, NONCE_LEN, SEALED_LEN};
use crate::envelope::{HEADER_LEN, Refusal};
use crate::error::{CryptoError, FormatError};
use crate::lock::passphrase::PassphraseParams;
use crate::method::{Method, NewLock, Unlock};

/// Method byte: a passphrase lock.
const METHOD_PASSPHRASE: u8 = 1;

/// What follows a method's parameters in every lock: the nonce, then the wrapped file key.
const WRAP_LEN: usize = NONCE_LEN + SEALED_LEN;

impl Method {
    /// The byte this method is recorded as.
    pub(crate) const fn byte(self) -> u8 {
        match self {
            Self::Passphrase => METHOD_PASSPHRASE,
        }
    }

    /// The method a byte records, or `None` for a byte no method is registered at.
    pub(crate) const fn of_byte(byte: u8) -> Option<Self> {
        match byte {
            METHOD_PASSPHRASE => Some(Self::Passphrase),
            _ => None,
        }
    }

    /// The one length this method's parameters have.
    const fn params_len(self) -> usize {
        match self {
            Self::Passphrase => passphrase::PARAMS_LEN,
        }
    }

    /// The one length this method's body has. A record declaring any other is refused before its
    /// body is read, so a hostile length costs nothing.
    pub(crate) const fn body_len(self) -> u16 {
        // In range: asserted below for every method.
        (self.params_len() + WRAP_LEN) as u16
    }
}

// A body length is two bytes on disk.
const _: () = assert!(passphrase::PARAMS_LEN + WRAP_LEN <= u16::MAX as usize);

/// The random key that seals a file's seed, and that every lock wraps.
///
/// Drawn once, when a file is first sealed, and kept for the file's life: adding or removing a lock
/// re-wraps this same key, so it needs one unlock by any lock the file already holds. Rotating it
/// would guard nothing, because whoever opened any copy of the file already holds the seed.
///
/// Boxed like [`Secret`](crate::Secret), because it opens the seed from any copy of the file: a move
/// copies the pointer, never the key, so no unwiped copy is left in a dead stack slot.
pub(crate) struct FileKey(Box<Zeroizing<[u8; KEY_LEN]>>);

impl FileKey {
    /// A fresh file key from the operating system's random source, written straight into its heap
    /// home.
    pub(crate) fn generate() -> Result<Self, CryptoError> {
        let mut key = Self::zeroed();
        getrandom::fill(&mut key.0[..]).map_err(CryptoError::entropy)?;
        Ok(key)
    }

    /// A file key holding a copy of `bytes`, for an unwrap, whose source buffer wipes itself.
    pub(crate) fn copy_of(bytes: &[u8; KEY_LEN]) -> Self {
        let mut key = Self::zeroed();
        key.0.copy_from_slice(bytes);
        key
    }

    fn zeroed() -> Self {
        Self(Box::new(Zeroizing::new([0; KEY_LEN])))
    }

    pub(crate) fn bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// A key-encryption key: what a method makes from its caller's input and its stored parameters, and
/// the only thing it hands back. It wraps one file key, and is wiped when it drops.
pub(crate) struct Kek(pub(crate) Zeroizing<[u8; Kek::LEN]>);

impl Kek {
    /// A cipher key's length: the cipher it keys is the one every seal here uses.
    pub(crate) const LEN: usize = KEY_LEN;
}

/// One lock's parameters, per method: the public inputs its method needs to make the same [`Kek`]
/// again. Exhaustive like [`Method`]: a method added later is a compile error here first.
pub(crate) enum Params {
    /// A passphrase lock's derivation.
    Passphrase(PassphraseParams),
}

impl Params {
    /// Parse a method's parameters, `bytes` of exactly its length.
    fn parse(method: Method, bytes: &[u8]) -> Result<Self, FormatError> {
        match method {
            Method::Passphrase => {
                PassphraseParams::parse(exact(method, bytes)?).map(Self::Passphrase)
            }
        }
    }

    /// Fresh parameters for `new`, and the key they make with what `new` carries.
    fn enroll(new: NewLock<'_>) -> Result<(Self, Kek), CryptoError> {
        match new {
            NewLock::Passphrase(passphrase) => {
                let (params, kek) = PassphraseParams::enroll(passphrase)?;
                Ok((Self::Passphrase(params), kek))
            }
        }
    }

    /// The key these parameters make with `with`, which the caller has matched to their method.
    fn kek(&self, with: Unlock<'_>) -> Result<Kek, Refusal> {
        match (self, with) {
            (Self::Passphrase(params), Unlock::Passphrase(passphrase)) => {
                params.kek(passphrase).map_err(Refusal::Crypto)
            }
        }
    }

    const fn method(&self) -> Method {
        match self {
            Self::Passphrase(_) => Method::Passphrase,
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::Passphrase(params) => out.extend_from_slice(&params.bytes()),
        }
    }
}

/// One parsed lock: its method's parameters, and the file key wrapped under the key they make.
pub(crate) struct Lock {
    params: Params,
    nonce: [u8; NONCE_LEN],
    wrapped: [u8; SEALED_LEN],
}

impl Lock {
    /// Parse a lock's body. The caller has already read the method and checked the body's length
    /// against it.
    pub(crate) fn parse(method: Method, body: &[u8]) -> Result<Self, FormatError> {
        let Some((params, wrap)) = body.split_at_checked(method.params_len()) else {
            return Err(length(method, body));
        };
        let Some((nonce, wrapped)) = wrap.split_at_checked(NONCE_LEN) else {
            return Err(length(method, body));
        };
        Ok(Self {
            params: Params::parse(method, params)?,
            nonce: *exact(method, nonce)?,
            wrapped: *exact(method, wrapped)?,
        })
    }

    /// Wrap `file_key` under a new lock, for a file whose first bytes are `header`, with a fresh
    /// nonce drawn for this lock alone.
    pub(crate) fn wrap(
        new: NewLock<'_>,
        file_key: &FileKey,
        header: &[u8; HEADER_LEN],
    ) -> Result<Self, CryptoError> {
        let (params, kek) = Params::enroll(new)?;
        Self::wrap_with(params, &kek, file_key, header, cipher::fresh_nonce()?)
    }

    /// Wrap with every input chosen by the caller. Only [`wrap`](Self::wrap) reaches this outside
    /// the tests; the tests use it to pin the exact bytes this build writes against the golden
    /// vector.
    pub(crate) fn wrap_with(
        params: Params,
        kek: &Kek,
        file_key: &FileKey,
        header: &[u8; HEADER_LEN],
        nonce: [u8; NONCE_LEN],
    ) -> Result<Self, CryptoError> {
        let mut lock = Self {
            params,
            nonce,
            wrapped: [0; SEALED_LEN],
        };
        lock.wrapped = cipher::seal(&kek.0, &nonce, &lock.aad(header), file_key.bytes())?;
        Ok(lock)
    }

    /// The method this lock opens with.
    pub(crate) const fn method(&self) -> Method {
        self.params.method()
    }

    /// Unwrap the file key with `with`, which the caller has matched to this lock's method. A wrong
    /// input and a damaged lock are the same refusal, because the cipher cannot tell them apart and
    /// a refusal that tried would be a guess an attacker could probe.
    pub(crate) fn open(
        &self,
        with: Unlock<'_>,
        header: &[u8; HEADER_LEN],
    ) -> Result<FileKey, Refusal> {
        let kek = self.params.kek(with)?;
        match cipher::open(&kek.0, &self.nonce, &self.aad(header), &self.wrapped) {
            Ok(file_key) => Ok(FileKey::copy_of(&file_key)),
            Err(Failed::Tag) => Err(Refusal::Unlock),
            Err(Failed::Crypto(source)) => Err(Refusal::Crypto(source)),
        }
    }

    /// Append this lock's record to `image`: method, body length, body.
    pub(crate) fn write(&self, image: &mut Vec<u8>) {
        image.push(self.method().byte());
        image.extend_from_slice(&self.method().body_len().to_be_bytes());
        self.head(image);
        image.extend_from_slice(&self.wrapped);
    }

    /// The body up to the wrapped file key: the parameters, then the nonce.
    fn head(&self, out: &mut Vec<u8>) {
        self.params.write(out);
        out.extend_from_slice(&self.nonce);
    }

    /// The associated data the wrap authenticates: the file's first bytes, the lock's method byte,
    /// and its body up to the wrapped file key. Any edit to the parameters, a cost included, fails
    /// the unwrap rather than producing a key.
    fn aad(&self, header: &[u8; HEADER_LEN]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(HEADER_LEN + 1 + self.method().params_len() + NONCE_LEN);
        aad.extend_from_slice(header);
        aad.push(self.method().byte());
        self.head(&mut aad);
        aad
    }
}

/// `bytes` as an array of its expected length, or the lock refused by its length.
///
/// Unreachable as a refusal: the caller judged the declared length before reading the body. A
/// refusal rather than a panic because this crate does not panic, and the body was read under a
/// two-byte length, so its length fits in one.
fn exact<const N: usize>(method: Method, bytes: &[u8]) -> Result<&[u8; N], FormatError> {
    bytes.try_into().map_err(|_| length(method, bytes))
}

fn length(method: Method, body: &[u8]) -> FormatError {
    FormatError::LockLength {
        method,
        found: u16::try_from(body.len()).unwrap_or(u16::MAX),
    }
}
