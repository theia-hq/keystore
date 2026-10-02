use super::OsError;

#[test]
fn a_description_carrying_a_hash_or_a_key_id_is_dropped_and_the_code_kept() {
    for description in [
        // LocalAuthentication's userInfo, should a description ever echo it.
        "User interaction is required. BiometryDatabaseHash={length = 32, bytes = 0x506ba565}",
        // A 32-byte hash as hex.
        "state 506ba565fd1e8752fd9ae867720476d6b0396e4ffa33d063506ba565fd1e8752",
        // CryptoTokenKit's key id, as round 1 saw it.
        "<sepk:p256(u) kid=2a6a915ff06fc561>: unable to compute shared secret",
    ] {
        let error = OsError::new("com.apple.LocalAuthentication", -1004, description);
        assert!(error.description_withheld(), "{description:?} was kept");
        assert_eq!(error.to_string(), "com.apple.LocalAuthentication -1004");
        assert!(!format!("{error:?}").contains(description));
    }
}

#[test]
fn a_plain_description_is_kept() {
    let error = OsError::new("com.apple.LocalAuthentication", -2, "Canceled by user.");
    assert!(!error.description_withheld());
    assert_eq!(
        error.to_string(),
        "com.apple.LocalAuthentication -2: Canceled by user."
    );
    // A short run of hex in words, like a code, stays.
    let error = OsError::new("NSOSStatusErrorDomain", -25308, "status 0xe00002e2");
    assert!(!error.description_withheld());
}
