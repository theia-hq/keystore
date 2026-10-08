//! The real Secure Enclave, on a Mac that has one. Ignored by default: CI's Macs are virtual and have
//! no enclave. Run them on an unlocked Mac with Touch ID set up:
//!
//! ```text
//! cargo test -p keystore-enclave -- --ignored
//! ```
//!
//! The first needs nobody at the sensor and shows nothing. The second shows the Touch ID dialog twice
//! and needs a finger each time. The third shows the dialog and needs nobody: it closes by itself.

#![cfg(target_os = "macos")]

use core::time::Duration;
use std::time::Instant;

use keystore_enclave::{Error, Policy, create, load};

/// Long enough for a person to touch; the tests that need a finger never reach it.
const WAIT: Duration = Duration::from_secs(60);

/// A new key refuses an agreement with nobody allowed to answer, which is the self-test `create`
/// runs before it hands a key out, and it reloads from its blob as the key it was. A blob with one
/// byte changed, or checked against another key, does not.
#[test]
#[ignore = "needs a Mac with a Secure Enclave and Touch ID set up; no finger"]
fn a_new_key_answers_no_one_without_a_touch() {
    let (blob, public) = create(Policy::BiometryCurrentSet).unwrap();
    let key = load(&blob, &public).unwrap();
    key.check().unwrap();

    let mut other = public;
    other[64] ^= 0x01;
    assert!(load(&blob, &other).is_err());
    let mut damaged = blob.clone();
    let middle = damaged.len() / 2;
    damaged[middle] ^= 0x01;
    assert!(matches!(
        load(&damaged, &public).and_then(|key| key.check()),
        Err(Error::Load(_) | Error::OtherKey)
    ));
}

/// With a finger: each agreement shows the dialog and asks again, and both give the same secret.
#[test]
#[ignore = "needs a finger on this Mac's Touch ID sensor, twice"]
fn each_agreement_asks_for_its_own_touch() {
    let (blob, public) = create(Policy::BiometryCurrentSet).unwrap();
    let key = load(&blob, &public).unwrap();
    let first = key
        .agree(&public, "agree a test secret, the first time", WAIT)
        .unwrap();
    let second = key
        .agree(&public, "agree a test secret, the second time", WAIT)
        .unwrap();
    assert_eq!(first, second);
}

/// With nobody at the sensor: the dialog shows, the wait runs out, and the call closes its own
/// dialog and fails as a timeout, never as a cancel, close to the wait. A second agreement then asks
/// again through a context of its own, and closes the same way.
#[test]
#[ignore = "needs a Mac with a Secure Enclave and Touch ID set up; shows the dialog, and no finger"]
fn deadline_dismisses_the_dialog() {
    let (blob, public) = create(Policy::BiometryCurrentSet).unwrap();
    let key = load(&blob, &public).unwrap();
    let wait = Duration::from_secs(2);
    for time in ["first", "second"] {
        let start = Instant::now();
        let agreed = key.agree(
            &public,
            &format!("test a dialog that closes by itself, the {time} time; do not touch"),
            wait,
        );
        let took = start.elapsed();
        assert!(matches!(agreed, Err(Error::TimedOut)), "{agreed:?}");
        assert!(
            took >= wait && took < wait + Duration::from_millis(500),
            "returned after {took:?}"
        );
    }
}
