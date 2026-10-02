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

use super::{
    Agree, Blob, Enclave, EnclaveParams, POINT_LEN, Point, Policy, Refused, SECRET_LEN, Shape,
};
use crate::error::{EnclaveError, FormatError, TouchIdError};
use crate::stored::Health;

/// What this Mac's stand-in enclave answers, as the founder's run on real hardware saw it. The
/// stand-in answers with a refusal's shape (whose, and its code), never a verdict, so the core's
/// reading of each code is what the tests below exercise.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Touch {
    /// At an unlocked screen: a silent check answers `-1004`, and a touch agrees.
    Matches,
    /// The person cancels the dialog: LocalAuthentication `-2`.
    Cancelled,
    /// A finger was enrolled since the key was made: CryptoTokenKit `-3`, at the silent check and
    /// after the dialog alike. Removing that finger brings the key back.
    FingersChanged,
    /// The silent check passes, and then the enclave turns the agreement down after the dialog with
    /// CryptoTokenKit `-3`, as it did on the founder's run for a key under a newly enrolled finger.
    TurnedDownAfterDialog,
    /// The screen is locked: LocalAuthentication `-4`.
    ScreenLocked,
    /// Touch ID is locked out after failed touches: LocalAuthentication `-8`.
    LockedOut,
    /// After a lockout, the enclave answers with status `-25308`.
    Busy,
    /// The key does not load, with an answer that names no code.
    Unrecognised,
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

/// What this Mac answers from here on in this test.
pub(crate) fn touch(touch: Touch) {
    TOUCH.set(touch);
}

/// How many touches this test has asked for: dialogs shown, never silent checks.
pub(crate) fn touches() -> u32 {
    TOUCHES.get()
}

/// The stand-in enclave of the Mac this test is on.
#[derive(Clone, Copy)]
pub(crate) struct StandIn;

/// A stand-in key, loaded.
pub(crate) struct StandInKey(p256::SecretKey);

/// The stand-in's refusal, carried as the cause, so a test can see the code a refusal came from.
#[derive(Debug, thiserror::Error)]
#[error("the stand-in enclave refused: {0:?}")]
pub(crate) struct StandInRefusal(pub(crate) Shape);

fn refused(shape: Shape) -> Refused {
    Refused {
        shape,
        source: EnclaveError::new(StandInRefusal(shape)),
    }
}

/// LocalAuthentication's "a person is needed, and none may be asked".
const NEEDS_A_PERSON: isize = -1004;

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

    fn create(&self, policy: Policy) -> Result<(Blob, Point), Refused> {
        assert_eq!(policy, Policy::BiometryCurrentSet);
        let mut scalar = [0; 32];
        getrandom::fill(&mut scalar).unwrap();
        let key = p256::SecretKey::from_slice(&scalar).unwrap();
        let scalar: [u8; 32] = key.to_bytes().into();
        Ok((blob(MAC.get(), &scalar), point_of(&key)))
    }

    fn load(&self, blob: &Blob, public: &Point) -> Result<StandInKey, Refused> {
        if TOUCH.get() == Touch::Unrecognised {
            return Err(refused(Shape::Other));
        }
        // Another Mac's blob, or a damaged one, does not reload here.
        let Some((&mac, scalar)) = blob.bytes().split_first() else {
            return Err(refused(Shape::NotLoaded));
        };
        if mac != MAC.get() {
            return Err(refused(Shape::NotLoaded));
        }
        let key = p256::SecretKey::from_slice(scalar).map_err(|_| refused(Shape::NotLoaded))?;
        if point_of(&key) != *public {
            return Err(refused(Shape::NotLoaded));
        }
        Ok(StandInKey(key))
    }
}

impl StandInKey {
    /// What this Mac answers a request for the agreement, with or without a dialog.
    fn answer(dialog: bool) -> Result<(), Refused> {
        let shape = match TOUCH.get() {
            Touch::Matches if dialog => return Ok(()),
            Touch::Cancelled if dialog => Shape::LocalAuthentication(-2),
            Touch::Matches | Touch::Cancelled | Touch::TurnedDownAfterDialog if !dialog => {
                Shape::LocalAuthentication(NEEDS_A_PERSON)
            }
            Touch::FingersChanged | Touch::TurnedDownAfterDialog => Shape::Token(-3),
            Touch::ScreenLocked => Shape::LocalAuthentication(-4),
            Touch::LockedOut => Shape::LocalAuthentication(-8),
            Touch::Busy => Shape::Status(-25308),
            Touch::Matches | Touch::Cancelled | Touch::Unrecognised => Shape::Other,
        };
        Err(refused(shape))
    }
}

impl Agree for StandInKey {
    fn agree(&self, peer: &Point, reason: &str) -> Result<Zeroizing<[u8; SECRET_LEN]>, Refused> {
        assert!(
            !reason.is_empty(),
            "a touch is never asked for with no reason"
        );
        TOUCHES.set(TOUCHES.get() + 1);
        Self::answer(true)?;
        // The real enclave refuses a peer off the curve the same way, as its own failure.
        let peer =
            p256::PublicKey::from_sec1_bytes(peer.bytes()).map_err(|_| refused(Shape::Other))?;
        let shared = p256::ecdh::diffie_hellman(self.0.to_nonzero_scalar(), peer.as_affine());
        let mut secret = Zeroizing::new([0; SECRET_LEN]);
        secret.copy_from_slice(shared.raw_secret_bytes());
        Ok(secret)
    }

    fn check(&self) -> Result<(), Refused> {
        // The real check is a refusal by design; `-1004` is the one that says the key is here.
        match Self::answer(false) {
            Ok(()) => Ok(()),
            Err(refusal) if refusal.shape == Shape::LocalAuthentication(NEEDS_A_PERSON) => Ok(()),
            Err(refusal) => Err(refusal),
        }
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
    assert_eq!(params.health(&StandIn), Health::Dead);
    assert!(matches!(
        params.kek(&StandIn, "open the test key"),
        Err(crate::error::MethodError::TouchId(TouchIdError::NotHere(_)))
    ));
    assert_eq!(touches(), 0);
}

#[test]
fn each_silent_answer_reads_as_its_code_says() {
    let (params, _) = enrolled();
    for (answer, health) in [
        (Touch::Matches, Health::Live),
        // The enclave's token refuses the key itself: it does not open with the fingers enrolled now.
        (Touch::FingersChanged, Health::Dead),
        // A locked screen, a lockout, a busy enclave: none says the key will not open later.
        (Touch::ScreenLocked, Health::Unchecked),
        (Touch::LockedOut, Health::Unchecked),
        (Touch::Busy, Health::Unchecked),
    ] {
        touch(answer);
        assert_eq!(params.health(&StandIn), health, "{answer:?}");
    }
    assert_eq!(touches(), 0);
}

#[test]
fn a_lock_that_stops_opening_when_a_finger_is_enrolled_opens_again_when_it_is_removed() {
    let (params, _) = enrolled();
    touch(Touch::FingersChanged);
    assert_eq!(params.health(&StandIn), Health::Dead);
    touch(Touch::Matches);
    assert_eq!(params.health(&StandIn), Health::Live);
    assert!(params.kek(&StandIn, "open the test key").is_ok());
}

#[test]
fn a_key_the_enclave_refuses_is_refused_before_a_dialog_and_never_as_a_cancel() {
    let (params, _) = enrolled();
    let refusal = |params: &EnclaveParams| match params.kek(&StandIn, "open the test key") {
        Err(crate::error::MethodError::TouchId(error)) => error,
        Err(other) => panic!("expected a touch-id refusal, found {other:?}"),
        Ok(_) => panic!("the key opened"),
    };

    // Refused at the silent check: no dialog is shown for a key that cannot open.
    touch(Touch::FingersChanged);
    assert!(matches!(refusal(&params), TouchIdError::NotHere(_)));
    assert_eq!(touches(), 0);

    // Turned down after the dialog by the enclave's token: the same refusal, not a cancel.
    touch(Touch::TurnedDownAfterDialog);
    assert!(matches!(refusal(&params), TouchIdError::NotHere(_)));
    assert_eq!(touches(), 1);

    // A person who cancels is told apart.
    touch(Touch::Cancelled);
    assert!(matches!(refusal(&params), TouchIdError::Declined(_)));
    assert_eq!(touches(), 2);

    // A locked screen that cancels the dialog is a cancel too; a lockout is the enclave's failure.
    touch(Touch::ScreenLocked);
    assert!(matches!(refusal(&params), TouchIdError::Declined(_)));
    touch(Touch::LockedOut);
    assert!(matches!(refusal(&params), TouchIdError::Enclave(_)));
}

#[test]
fn a_blob_that_reloads_as_another_key_reads_as_dead() {
    let (_, mut bytes) = enrolled();
    let (other, _) = enrolled();
    // This lock's blob, beside another lock's enclave key.
    bytes[1..1 + POINT_LEN].copy_from_slice(other.enclave_key.bytes());
    let params = EnclaveParams::parse(&bytes).unwrap();
    assert_eq!(params.health(&StandIn), Health::Dead);
    assert_eq!(touches(), 0);
}

#[test]
fn an_answer_that_says_nothing_about_the_key_reads_as_unchecked() {
    let (params, _) = enrolled();
    touch(Touch::Unrecognised);
    assert_eq!(params.health(&StandIn), Health::Unchecked);
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
    assert_eq!(params.health(&SecureEnclave), Health::Live);
    for time in ["first", "second"] {
        let opened = params
            .kek(&SecureEnclave, &format!("open a test key, the {time} time"))
            .unwrap();
        assert_eq!(opened.bytes(), kek.bytes());
    }
}
