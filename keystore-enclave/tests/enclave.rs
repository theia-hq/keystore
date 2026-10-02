//! The real Secure Enclave, on a Mac that has one. Ignored by default: CI's Macs are virtual and have
//! no enclave. Run them on an unlocked Mac with Touch ID set up:
//!
//! ```text
//! cargo test -p keystore-enclave -- --ignored
//! ```
//!
//! The first needs nobody at the sensor and shows nothing. The second shows the Touch ID dialog twice
//! and needs a finger each time.

#![cfg(target_os = "macos")]

use keystore_enclave::{Error, Policy, create, load};

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
        .agree(&public, "agree a test secret, the first time")
        .unwrap();
    let second = key
        .agree(&public, "agree a test secret, the second time")
        .unwrap();
    assert_eq!(first, second);
}
