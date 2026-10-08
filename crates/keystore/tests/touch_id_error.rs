//! A dependent builds every [`TouchIdError`] that carries what the enclave said, on any target, so
//! its own tests can reach each way a `touch-id` lock fails without an enclave or a touch.

use core::error::Error as _;
use std::io;

use keystore::{EnclaveError, TouchIdError};

/// What the enclave said, as a dependent's test makes it up.
fn said(text: &str) -> EnclaveError {
    EnclaveError::new(io::Error::other(text.to_owned()))
}

#[test]
fn a_dependent_builds_each_enclave_failure_with_its_cause() {
    let built = [
        TouchIdError::NotHere(said("not here")),
        TouchIdError::Declined(said("declined")),
        TouchIdError::TimedOut(said("timed out")),
        TouchIdError::Enclave(said("failed")),
    ];
    let causes: Vec<String> = built
        .iter()
        .map(|error| error.source().map(ToString::to_string).unwrap_or_default())
        .collect();
    assert_eq!(causes, ["not here", "declined", "timed out", "failed"]);
    // What a dependent shows for each: the variant's own words, never the made-up cause.
    let shown: Vec<String> = built.iter().map(ToString::to_string).collect();
    assert_eq!(
        shown,
        [
            "the lock does not open on this Mac now; if a fingerprint was added after the lock was \
             made, remove it and the lock opens again",
            "the touch was cancelled or did not match",
            "no touch came in time",
            "the Secure Enclave failed",
        ]
    );
}
