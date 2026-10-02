//! The `touch-id` lock: a P-256 key in this Mac's Secure Enclave agrees a secret with a one-time key,
//! and HKDF-SHA256 turns that secret into the key-encryption key. The lock's nonce and wrapped file
//! key follow these parameters, and are the core's (see `lock`).
//!
//! Its parameters, every field but the blob fixed-width, integers big-endian:
//!
//! | offset | len | field                                                                                                       |
//! | ------ | --- | ----------------------------------------------------------------------------------------------------------- |
//! | 0      | 1   | access policy, `1` = a touch of a finger enrolled when the key was made, at an unlocked screen, on this Mac |
//! | 1      | 65  | `S`, the enclave key's public key, uncompressed (X9.63)                                                     |
//! | 66     | 2   | `b`, the blob's length, 1 to 1024                                                                           |
//! | 68     | b   | the blob: the enclave key, wrapped by this Mac's enclave for itself                                         |
//! | 68 + b | 65  | `E`, the one-time key's public key, uncompressed (X9.63)                                                    |
//!
//! **Locking** asks nothing of anyone, because it needs only `S`: draw a one-time key `e`, compute
//! `KEK = HKDF-SHA256(ikm = ECDH(e, S), salt = E || S, info = "keystore enclave lock")`, and drop `e`.
//! **Opening** reloads the blob, refuses it unless its public key is `S`, and asks the enclave for
//! `ECDH(enclave key, E)`, which is the one step that asks for a touch; the same derivation follows.
//! So the enclave does one thing, an agreement, and every other byte is this crate's code, the same on
//! every platform.
//!
//! The wrap authenticates these parameters, so an edit to any of them fails the unlock. The policy
//! byte is where the lock grows: an unknown value is refused by name. Parsing needs no curve and no
//! enclave, so a build without one reads, names and keeps a `touch-id` lock it cannot open; the
//! points are checked as curve points where they are used.

#[cfg(any(test, target_os = "macos"))]
use zeroize::Zeroizing;

use crate::error::FormatError;
#[cfg(any(test, target_os = "macos"))]
use crate::error::{MethodError, TouchIdError};
#[cfg(any(test, target_os = "macos"))]
use crate::lock::Kek;
#[cfg(any(test, target_os = "macos"))]
use crate::stored::Health;

/// An uncompressed P-256 point's length: `04`, then x, then y.
pub(crate) const POINT_LEN: usize = 65;
/// An agreed secret's length: the shared point's x-coordinate.
#[cfg(any(test, target_os = "macos"))]
pub(crate) const SECRET_LEN: usize = 32;
/// The longest blob a lock holds. An enclave key under this lock's policy makes a blob of about 570
/// bytes; the cap is well above that, and well below the key file's read cap with every lock on it.
const BLOB_MAX: usize = 1024;

/// Access policy: a touch of a finger enrolled when the key was made, at an unlocked screen, on this
/// device (`privateKeyUsage | biometryCurrentSet`, `WhenUnlockedThisDeviceOnly`).
const POLICY_BIOMETRY_CURRENT_SET: u8 = 1;

/// HKDF's info string: binds the derived key to this use of it.
#[cfg(any(test, target_os = "macos"))]
const INFO: &[u8] = b"keystore enclave lock";

// The parameters' offsets, up to the blob. The blob's length decides where `E` sits.
const AT_POLICY: usize = 0;
const AT_ENCLAVE_KEY: usize = AT_POLICY + 1;
const AT_BLOB_LEN: usize = AT_ENCLAVE_KEY + POINT_LEN;
const AT_BLOB: usize = AT_BLOB_LEN + 2;
/// The shortest a `touch-id` lock's parameters can be: a blob of one byte.
pub(crate) const PARAMS_MIN: usize = AT_BLOB + 1 + POINT_LEN;
/// The longest a `touch-id` lock's parameters can be: a blob at its cap.
pub(crate) const PARAMS_MAX: usize = AT_BLOB + BLOB_MAX + POINT_LEN;

// The layout is frozen: a file written today must parse forever. Moving a field is a compile error
// here before it is a golden-vector failure in the tests.
const _: () = assert!(AT_BLOB == 68 && PARAMS_MIN == 134 && PARAMS_MAX == 1157);

/// The access control an enclave key is made under. One today, pinned: a policy that let the login
/// password or a newly enrolled finger in would open the lock for whoever learned the password.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Policy {
    BiometryCurrentSet,
}

impl Policy {
    const fn byte(self) -> u8 {
        match self {
            Self::BiometryCurrentSet => POLICY_BIOMETRY_CURRENT_SET,
        }
    }

    const fn of_byte(byte: u8) -> Option<Self> {
        match byte {
            POLICY_BIOMETRY_CURRENT_SET => Some(Self::BiometryCurrentSet),
            _ => None,
        }
    }
}

/// An uncompressed P-256 point's bytes: the form is checked here, the curve where it is used.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Point([u8; POINT_LEN]);

impl Point {
    /// The tag that opens every uncompressed point.
    const UNCOMPRESSED: u8 = 0x04;

    pub(crate) fn parse(bytes: [u8; POINT_LEN]) -> Result<Self, FormatError> {
        if bytes[0] != Self::UNCOMPRESSED {
            return Err(FormatError::Point);
        }
        Ok(Self(bytes))
    }

    pub(crate) const fn bytes(&self) -> &[u8; POINT_LEN] {
        &self.0
    }
}

/// An enclave key's blob: what the enclave hands out for a key that is not kept in the keychain, and
/// what it takes back to use it. Useless to any other Mac's enclave. Between 1 and [`BLOB_MAX`] bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Blob(Vec<u8>);

impl Blob {
    /// `bytes` as a blob, or `None` for a length no lock holds.
    pub(crate) fn new(bytes: Vec<u8>) -> Option<Self> {
        (1..=BLOB_MAX).contains(&bytes.len()).then_some(Self(bytes))
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A `touch-id` lock's parameters, parsed: a known policy, the enclave key's blob and public key, and
/// the one-time key's public key.
pub(crate) struct EnclaveParams {
    policy: Policy,
    enclave_key: Point,
    blob: Blob,
    one_time: Point,
}

impl EnclaveParams {
    /// Parse the parameters from `bytes`, all of them: the caller has bounded their length between
    /// [`PARAMS_MIN`] and [`PARAMS_MAX`], and the blob's own length must account for every byte.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        let (Some(&policy), Some(enclave_key), Some(&[high, low])) = (
            bytes.get(AT_POLICY),
            bytes.get(AT_ENCLAVE_KEY..AT_BLOB_LEN),
            bytes.get(AT_BLOB_LEN..AT_BLOB),
        ) else {
            return Err(FormatError::Blob { found: 0 });
        };
        let Some(policy) = Policy::of_byte(policy) else {
            return Err(FormatError::Policy { found: policy });
        };
        let found = u16::from_be_bytes([high, low]);
        let at_one_time = AT_BLOB + usize::from(found);
        let (Some(blob), Some(one_time)) =
            (bytes.get(AT_BLOB..at_one_time), bytes.get(at_one_time..))
        else {
            return Err(FormatError::Blob { found });
        };
        let Some(blob) = Blob::new(blob.to_vec()) else {
            return Err(FormatError::Blob { found });
        };
        // The one-time key ends the parameters, so a blob length that does not account for every
        // byte leaves it the wrong size.
        let point = |bytes: &[u8]| {
            <[u8; POINT_LEN]>::try_from(bytes)
                .map_err(|_| FormatError::Blob { found })
                .and_then(Point::parse)
        };
        Ok(Self {
            policy,
            enclave_key: point(enclave_key)?,
            blob,
            one_time: point(one_time)?,
        })
    }

    /// The parameters' length in the file.
    pub(crate) fn len(&self) -> usize {
        AT_BLOB + self.blob.bytes().len() + POINT_LEN
    }

    /// Append the parameters, byte for byte as they sit in the file.
    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        out.push(self.policy.byte());
        out.extend_from_slice(self.enclave_key.bytes());
        // In range: a blob is at most `BLOB_MAX` bytes, by construction.
        out.extend_from_slice(&(self.blob.bytes().len() as u16).to_be_bytes());
        out.extend_from_slice(self.blob.bytes());
        out.extend_from_slice(self.one_time.bytes());
    }

    #[cfg(test)]
    pub(crate) fn blob(&self) -> &Blob {
        &self.blob
    }
}

// A blob length is two bytes on disk.
const _: () = assert!(BLOB_MAX <= u16::MAX as usize);

/// Where enclave keys are made and loaded: this Mac's Secure Enclave, or the software stand-in that
/// runs the lock's every byte in the tests. Crate-private, so nothing outside the crate adds a method
/// through it.
///
/// Each answers a refusal by its shape (whose refusal, and its code), never by a verdict, so how a
/// refusal reads (a cancel, a lock that does not open here, one that cannot be checked now) is decided
/// in one place here, and tested on the stand-in.
#[cfg(any(test, target_os = "macos"))]
pub(crate) trait Enclave {
    type Key: Agree;

    /// A new key under `policy`: its blob and its public key. Asks nothing of anyone.
    fn create(&self, policy: Policy) -> Result<(Blob, Point), Refused>;

    /// The key `blob` holds, refused unless its public key is `public`. Asks nothing of anyone.
    fn load(&self, blob: &Blob, public: &Point) -> Result<Self::Key, Refused>;
}

/// An enclave key, loaded.
#[cfg(any(test, target_os = "macos"))]
pub(crate) trait Agree {
    /// ECDH with `peer`: the shared point's x-coordinate. Asks for a touch, with `reason` shown.
    fn agree(&self, peer: &Point, reason: &str) -> Result<Zeroizing<[u8; SECRET_LEN]>, Refused>;

    /// Ask for the agreement with no dialog allowed: `Ok` when the enclave refuses only for want of a
    /// person (LocalAuthentication's `-1004`), and its refusal otherwise.
    fn check(&self) -> Result<(), Refused>;
}

/// LocalAuthentication's codes for a dialog the person, or the system, closed: the touch did not
/// match, the person cancelled, the system cancelled (the screen locked with the dialog up), or the
/// program did.
#[cfg(any(test, target_os = "macos"))]
const DECLINED: [isize; 4] = [-1, -2, -4, -9];

/// How an enclave refused: by whom, and with what code. Read here, and nowhere else, into what the
/// refusal means.
#[cfg(any(test, target_os = "macos"))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Shape {
    /// The blob does not reload here, or reloads as another key than the lock names.
    NotLoaded,
    /// CryptoTokenKit, the enclave's token, refused the key itself, with this code: a damaged blob,
    /// another Mac's, or a key made under other enrolled fingers than the ones enrolled now.
    Token(isize),
    /// LocalAuthentication refused, with this code.
    LocalAuthentication(isize),
    /// Security's status domain refused, with this code.
    Status(isize),
    /// Any other refusal: one the enclave gave no code for, or this side's own.
    Other,
}

#[cfg(any(test, target_os = "macos"))]
impl Shape {
    /// What a silent check's refusal of this shape says of the lock. Only the key's own refusal reads
    /// as not opening here; a locked screen (`-4`), a lockout (`-8`), a busy enclave (`-25308`), and
    /// any code not named here read as not checkable now, never as dead.
    const fn health(self) -> Health {
        match self {
            Self::NotLoaded | Self::Token(_) => Health::Dead,
            Self::LocalAuthentication(_) | Self::Status(_) | Self::Other => Health::Unchecked,
        }
    }
}

/// An enclave's refusal: its shape, and the enclave's own error, which rides as the cause.
#[cfg(any(test, target_os = "macos"))]
pub(crate) struct Refused {
    pub(crate) shape: Shape,
    pub(crate) source: crate::error::EnclaveError,
}

#[cfg(any(test, target_os = "macos"))]
impl Refused {
    /// The refusal as a caller tells it: a key that does not open here, a person who said no, or the
    /// enclave failing. A touch the enclave turns down after the dialog (its token's refusal) is the
    /// first, never a cancel.
    fn into_error(self) -> TouchIdError {
        match self.shape {
            Shape::NotLoaded | Shape::Token(_) => TouchIdError::NotHere(self.source),
            Shape::LocalAuthentication(code) if is_declined(code) => {
                TouchIdError::Declined(self.source)
            }
            Shape::LocalAuthentication(_) | Shape::Status(_) | Shape::Other => {
                TouchIdError::Enclave(self.source)
            }
        }
    }
}

#[cfg(any(test, target_os = "macos"))]
fn is_declined(code: isize) -> bool {
    DECLINED.contains(&code)
}

/// What a silent check says of the lock: [`Health::Live`] only when the enclave refused for want of a
/// person, and the refusal's own reading otherwise.
#[cfg(any(test, target_os = "macos"))]
fn health_of(check: &Result<(), Refused>) -> Health {
    match check {
        Ok(()) => Health::Live,
        Err(refused) => refused.shape.health(),
    }
}

#[cfg(any(test, target_os = "macos"))]
impl EnclaveParams {
    /// Parameters for a new lock: a new key in `enclave`, a fresh one-time key, and the key they make.
    /// Asks nothing of anyone.
    pub(crate) fn enroll(enclave: &impl Enclave) -> Result<(Self, Kek), MethodError> {
        let policy = Policy::BiometryCurrentSet;
        let (blob, enclave_key) = enclave.create(policy).map_err(Refused::into_error)?;
        Self::enroll_with(policy, blob, enclave_key, &one_time_key()?)
    }

    /// Enroll with every input chosen by the caller. Only [`enroll`](Self::enroll) reaches this
    /// outside the tests; the tests use it to pin the exact bytes this build writes against the
    /// golden vector.
    pub(crate) fn enroll_with(
        policy: Policy,
        blob: Blob,
        enclave_key: Point,
        one_time: &p256::SecretKey,
    ) -> Result<(Self, Kek), MethodError> {
        use p256::elliptic_curve::sec1::ToEncodedPoint as _;

        let peer = p256::PublicKey::from_sec1_bytes(enclave_key.bytes())
            .map_err(|_| unusable(crate::error::Unusable::Point))?;
        let mut encoded = [0; POINT_LEN];
        encoded.copy_from_slice(one_time.public_key().to_encoded_point(false).as_bytes());
        let one_time_point = Point(encoded);
        let shared = p256::ecdh::diffie_hellman(one_time.to_nonzero_scalar(), peer.as_affine());
        let kek = derive(shared.raw_secret_bytes(), &one_time_point, &enclave_key)?;
        let params = Self {
            policy,
            enclave_key,
            blob,
            one_time: one_time_point,
        };
        Ok((params, kek))
    }

    /// The key a touch makes under these parameters, through `enclave`, with `reason` in the dialog.
    ///
    /// The key is asked first with no dialog allowed: one the enclave refuses outright (another
    /// Mac's, a damaged one, one made under other enrolled fingers) is refused here, before a dialog
    /// that could not open it. A key that cannot be checked now is still asked with the dialog.
    pub(crate) fn kek(&self, enclave: &impl Enclave, reason: &str) -> Result<Kek, MethodError> {
        let key = enclave
            .load(&self.blob, &self.enclave_key)
            .map_err(Refused::into_error)?;
        if let Err(refused) = key.check()
            && refused.shape.health() == Health::Dead
        {
            return Err(refused.into_error().into());
        }
        let shared = key
            .agree(&self.one_time, reason)
            .map_err(Refused::into_error)?;
        Ok(derive(&shared[..], &self.one_time, &self.enclave_key)?)
    }

    /// Whether this lock would open on this machine, asked of `enclave` without showing anything.
    pub(crate) fn health(&self, enclave: &impl Enclave) -> Health {
        match enclave.load(&self.blob, &self.enclave_key) {
            Ok(key) => health_of(&key.check()),
            Err(refused) => refused.shape.health(),
        }
    }
}

/// HKDF-SHA256 from the agreed secret, salted with both public keys, straight into the key's heap
/// home. HKDF's own intermediate key lives on its stack and is not wiped: it is outside this crate's
/// reach, and it makes this one lock's key, not the file key.
#[cfg(any(test, target_os = "macos"))]
fn derive(
    shared: &[u8],
    one_time: &Point,
    enclave_key: &Point,
) -> Result<Kek, crate::error::CryptoError> {
    let mut salt = [0; 2 * POINT_LEN];
    salt[..POINT_LEN].copy_from_slice(one_time.bytes());
    salt[POINT_LEN..].copy_from_slice(enclave_key.bytes());
    let mut kek = Kek::zeroed();
    hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), shared)
        .expand(INFO, &mut kek.fill()[..])
        .map_err(|_| crate::error::CryptoError::derive())?;
    Ok(kek)
}

/// A fresh one-time key from the operating system's random source. Its secret scalar is wiped when
/// it drops, which is as soon as the lock is made.
#[cfg(any(test, target_os = "macos"))]
fn one_time_key() -> Result<p256::SecretKey, crate::error::CryptoError> {
    // A draw outside the curve's order is about one in 2^32, so four in a row is a broken source.
    for _ in 0..4 {
        let mut scalar = Zeroizing::new([0; SECRET_LEN]);
        getrandom::fill(&mut scalar[..]).map_err(crate::error::CryptoError::entropy)?;
        if let Ok(key) = p256::SecretKey::from_slice(&scalar[..]) {
            return Ok(key);
        }
    }
    Err(crate::error::CryptoError::one_time_key())
}

#[cfg(any(test, target_os = "macos"))]
fn unusable(fault: crate::error::Unusable) -> TouchIdError {
    TouchIdError::Enclave(crate::error::EnclaveError::new(fault))
}

/// This Mac's Secure Enclave.
#[cfg(target_os = "macos")]
#[cfg_attr(test, allow(dead_code))]
pub(crate) struct SecureEnclave;

#[cfg(target_os = "macos")]
impl Enclave for SecureEnclave {
    type Key = keystore_enclave::Key;

    fn create(&self, policy: Policy) -> Result<(Blob, Point), Refused> {
        let policy = match policy {
            Policy::BiometryCurrentSet => keystore_enclave::Policy::BiometryCurrentSet,
        };
        let (blob, public) = keystore_enclave::create(policy).map_err(refused)?;
        let found = blob.len();
        let unusable = |fault| Refused {
            shape: Shape::Other,
            source: crate::error::EnclaveError::new(fault),
        };
        let blob = Blob::new(blob)
            .ok_or_else(|| unusable(crate::error::Unusable::BlobLength { found }))?;
        let public = Point::parse(public).map_err(|_| unusable(crate::error::Unusable::Point))?;
        Ok((blob, public))
    }

    fn load(&self, blob: &Blob, public: &Point) -> Result<Self::Key, Refused> {
        keystore_enclave::load(blob.bytes(), public.bytes()).map_err(refused)
    }
}

#[cfg(target_os = "macos")]
impl Agree for keystore_enclave::Key {
    fn agree(&self, peer: &Point, reason: &str) -> Result<Zeroizing<[u8; SECRET_LEN]>, Refused> {
        keystore_enclave::Key::agree(self, peer.bytes(), reason).map_err(refused)
    }

    fn check(&self) -> Result<(), Refused> {
        keystore_enclave::Key::check(self).map_err(refused)
    }
}

/// The enclave's error, by its shape: the system's domain and code where it gave one.
#[cfg(target_os = "macos")]
fn refused(error: keystore_enclave::Error) -> Refused {
    use keystore_enclave::Error;

    let shape = match &error {
        Error::OtherKey => Shape::NotLoaded,
        Error::Load(os) if !os.domain().contains("CryptoTokenKit") => Shape::NotLoaded,
        Error::Load(os) | Error::Declined(os) | Error::NotInteractive(os) | Error::Agree(os) => {
            match os.domain() {
                "CryptoTokenKit" => Shape::Token(os.code()),
                "com.apple.LocalAuthentication" => Shape::LocalAuthentication(os.code()),
                "NSOSStatusErrorDomain" => Shape::Status(os.code()),
                _ => Shape::Other,
            }
        }
        _ => Shape::Other,
    };
    Refused {
        shape,
        source: crate::error::EnclaveError::new(error),
    }
}

#[cfg(test)]
#[path = "enclave_tests.rs"]
pub(crate) mod enclave_tests;
