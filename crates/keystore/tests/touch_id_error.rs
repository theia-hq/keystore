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
    assert!(matches!(built[2], TouchIdError::TimedOut(_)));
}
