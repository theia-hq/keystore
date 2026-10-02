//! The software stand-in for the Secure Enclave, and the `touch-id` lock's parameter tests.
//!
//! The stand-in does what the enclave does, in software: it makes a P-256 key and hands out a blob,
//! takes the blob back and checks its public key, and agrees a secret when a touch matches. Its blob
//! is the byte of the Mac it was made on, then the key's scalar, in the clear: it guards nothing, it
//! only lets every byte of the lock run where there is no enclave. Each test runs on its own thread,
//! so the Mac it is on, what the next touch does, and how many touches were asked for are per test.

use core::cell::Cell;

use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use zeroize::Zeroizing;

use super::{Agree, Blob, Enclave, EnclaveParams, POINT_LEN, Point, Policy, SECRET_LEN};
use crate::error::{EnclaveError, FormatError, TouchIdError};

/// What a touch on the stand-in does.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Touch {
    /// A finger enrolled when the key was made: the key agrees.
    Matches,
    /// The person cancels the dialog.
    Cancelled,
    /// The enrolled fingers changed since the key was made: the key is gone for good, and the
    /// enclave says so without asking anyone.
    Ended,
}

thread_local! {
    static MAC: Cell<u8> = const { Cell::new(1) };
    static TOUCH: Cell<Touch> = const { Cell::new(Touch::Matches) };
    static TOUCHES: Cell<u32> = const { Cell::new(0) };
}

/// Run the rest of this test on Mac `mac`. Every test starts on Mac 1.
pub(crate) fn on_mac(mac: u8) {
    MAC.set(mac);
}

/// What every touch from here on does in this test.
pub(crate) fn touch(touch: Touch) {
    TOUCH.set(touch);
}

/// How many touches this test has asked for.
pub(crate) fn touches() -> u32 {
    TOUCHES.get()
}

/// The stand-in enclave of the Mac this test is on.
#[derive(Clone, Copy)]
pub(crate) struct StandIn;

/// A stand-in key, loaded.
pub(crate) struct StandInKey(p256::SecretKey);

#[derive(Debug, thiserror::Error)]
enum StandInError {
    #[error("the blob was made on another Mac")]
    OtherMac,
    #[error("the blob is damaged")]
    Damaged,
    #[error("the blob holds another key")]
    OtherKey,
    #[error("the touch was cancelled")]
    Cancelled,
    #[error("the enrolled fingers changed")]
    Ended,
    #[error("the peer is not a P-256 public key")]
    Peer,
}

pub(crate) fn point_of(key: &p256::SecretKey) -> Point {
    let mut bytes = [0; POINT_LEN];
    bytes.copy_from_slice(key.public_key().to_encoded_point(false).as_bytes());
    Point::parse(bytes).unwrap()
}

/// A stand-in blob for `scalar`, made on `mac`.
pub(crate) fn blob(mac: u8, scalar: &[u8; 32]) -> Blob {
    let mut bytes = vec![mac];
    bytes.extend_from_slice(scalar);
    Blob::new(bytes).unwrap()
}

impl Enclave for StandIn {
    type Key = StandInKey;

    fn create(&self, policy: Policy) -> Result<(Blob, Point), TouchIdError> {
        assert_eq!(policy, Policy::BiometryCurrentSet);
        let mut scalar = [0; 32];
        getrandom::fill(&mut scalar).unwrap();
        let key = p256::SecretKey::from_slice(&scalar).unwrap();
        let scalar: [u8; 32] = key.to_bytes().into();
        Ok((blob(MAC.get(), &scalar), point_of(&key)))
    }

    fn load(&self, blob: &Blob, public: &Point) -> Result<StandInKey, TouchIdError> {
        let not_here = |why| TouchIdError::NotHere(EnclaveError::new(why));
        let Some((&mac, scalar)) = blob.bytes().split_first() else {
            return Err(not_here(StandInError::Damaged));
        };
        if mac != MAC.get() {
            return Err(not_here(StandInError::OtherMac));
        }
        let key =
            p256::SecretKey::from_slice(scalar).map_err(|_| not_here(StandInError::Damaged))?;
        if point_of(&key) != *public {
            return Err(not_here(StandInError::OtherKey));
        }
        Ok(StandInKey(key))
    }
}

impl Agree for StandInKey {
    fn agree(
        &self,
        peer: &Point,
        reason: &str,
    ) -> Result<Zeroizing<[u8; SECRET_LEN]>, TouchIdError> {
        assert!(
            !reason.is_empty(),
            "a touch is never asked for with no reason"
        );
        TOUCHES.set(TOUCHES.get() + 1);
        match TOUCH.get() {
            Touch::Matches => {}
            Touch::Cancelled => {
                return Err(TouchIdError::Declined(EnclaveError::new(
                    StandInError::Cancelled,
                )));
            }
            Touch::Ended => {
                return Err(TouchIdError::NotHere(EnclaveError::new(
                    StandInError::Ended,
                )));
            }
        }
        // The real enclave refuses a peer off the curve the same way, as its own failure.
        let peer = p256::PublicKey::from_sec1_bytes(peer.bytes())
            .map_err(|_| TouchIdError::Enclave(EnclaveError::new(StandInError::Peer)))?;
        let shared = p256::ecdh::diffie_hellman(self.0.to_nonzero_scalar(), peer.as_affine());
        let mut secret = Zeroizing::new([0; SECRET_LEN]);
        secret.copy_from_slice(shared.raw_secret_bytes());
        Ok(secret)
    }

    fn opens_here(&self) -> bool {
        TOUCH.get() != Touch::Ended
    }
}

/// Parameters on the stand-in, and the key they make.
fn enrolled() -> (EnclaveParams, Vec<u8>) {
    let (params, _) = EnclaveParams::enroll(&StandIn).unwrap();
    let mut bytes = Vec::new();
    params.write(&mut bytes);
    (params, bytes)
}

#[test]
fn a_touch_makes_the_key_the_lock_was_made_with() {
    let (params, kek) = EnclaveParams::enroll(&StandIn).unwrap();
    // Making the lock asked for no touch; opening it asks for exactly one.
    assert_eq!(touches(), 0);
    let opened = params.kek(&StandIn, "open the test key").unwrap();
    assert_eq!(touches(), 1);
    assert_eq!(opened.bytes(), kek.bytes());
}

#[test]
fn every_lock_draws_its_own_enclave_key_and_one_time_key() {
    let (first, _) = enrolled();
    let (second, _) = enrolled();
    assert_ne!(first.enclave_key, second.enclave_key);
    assert_ne!(first.one_time, second.one_time);
    assert_ne!(first.blob(), second.blob());
}

#[test]
fn the_parameters_read_back_as_written() {
    let (params, bytes) = enrolled();
    assert_eq!(bytes.len(), params.len());
    let parsed = EnclaveParams::parse(&bytes).unwrap();
    let mut again = Vec::new();
    parsed.write(&mut again);
    assert_eq!(again, bytes);
}

#[test]
fn an_unknown_policy_refuses_by_name() {
    let (_, mut bytes) = enrolled();
    bytes[0] = 2;
    assert!(matches!(
        EnclaveParams::parse(&bytes),
        Err(FormatError::Policy { found: 2 })
    ));
}

#[test]
fn a_public_key_that_is_not_an_uncompressed_point_is_refused() {
    let (params, bytes) = enrolled();
    for at in [1, params.len() - POINT_LEN] {
        let mut edited = bytes.clone();
        edited[at] = 0x02;
        assert!(
            matches!(EnclaveParams::parse(&edited), Err(FormatError::Point)),
            "the point at {at} was taken"
        );
    }
}

#[test]
fn a_blob_length_that_does_not_account_for_every_byte_is_refused() {
    let (_, bytes) = enrolled();
    let declared = u16::from_be_bytes([bytes[66], bytes[67]]);
    for found in [0, declared - 1, declared + 1, 1025, u16::MAX] {
        let mut edited = bytes.clone();
        edited[66..68].copy_from_slice(&found.to_be_bytes());
        assert!(
            matches!(EnclaveParams::parse(&edited), Err(FormatError::Blob { found: f }) if f == found),
            "a blob length of {found} was taken"
        );
    }
    // Cut short of the blob length's own field.
    assert!(matches!(
        EnclaveParams::parse(&bytes[..67]),
        Err(FormatError::Blob { found: 0 })
    ));
}

#[test]
fn a_blob_is_one_to_1024_bytes() {
    assert!(Blob::new(Vec::new()).is_none());
    assert!(Blob::new(vec![0; 1]).is_some());
    assert!(Blob::new(vec![0; 1024]).is_some());
    assert!(Blob::new(vec![0; 1025]).is_none());
}

#[test]
fn another_macs_lock_does_not_load_here_and_asks_for_no_touch() {
    let (params, _) = enrolled();
    on_mac(2);
    assert!(!params.opens_here(&StandIn));
    assert!(matches!(
        params.kek(&StandIn, "open the test key"),
        Err(crate::error::MethodError::TouchId(TouchIdError::NotHere(_)))
    ));
    assert_eq!(touches(), 0);
}

#[test]
fn a_lock_ended_by_new_fingers_reads_as_dead_without_a_touch() {
    let (params, _) = enrolled();
    assert!(params.opens_here(&StandIn));
    touch(Touch::Ended);
    assert!(!params.opens_here(&StandIn));
    assert_eq!(touches(), 0);
}

/// The real enclave, with a finger on the sensor: make a lock, then open it twice. Each open shows
/// the dialog, and each asks again: one touch opens one key. Run on an unlocked Mac with Touch ID:
/// `cargo test -p keystore -- --ignored the_secure_enclave`.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "needs a finger on this Mac's Touch ID sensor"]
fn the_secure_enclave_opens_what_it_locked_once_per_touch() {
    use super::SecureEnclave;

    let (params, kek) = EnclaveParams::enroll(&SecureEnclave).unwrap();
    assert!(params.opens_here(&SecureEnclave));
    for time in ["first", "second"] {
        let opened = params
            .kek(&SecureEnclave, &format!("open a test key, the {time} time"))
            .unwrap();
        assert_eq!(opened.bytes(), kek.bytes());
    }
}
