use core::time::Duration;

use core_foundation::data::CFData;

use super::{Key, past, read};
use crate::error::{Error, OsError};

/// A key whose blob was never made by an enclave: every call below must refuse before it reaches
/// one, so this runs on any Mac, a virtual one included.
fn no_key() -> Key {
    Key {
        blob: CFData::from_buffer(&[1]),
    }
}

#[test]
fn a_touch_is_never_asked_for_with_no_reason() {
    for reason in ["", " ", "\t\n"] {
        assert!(
            matches!(
                no_key().agree(&[4; 65], reason, Duration::from_secs(1)),
                Err(Error::NoReason)
            ),
            "{reason:?} was shown as a reason"
        );
    }
}

fn local_authentication(code: isize) -> OsError {
    OsError::new("com.apple.LocalAuthentication", code, "")
}

#[test]
fn a_refusal_reads_as_what_the_system_said() {
    for code in [-1, -2, -4] {
        assert!(
            matches!(read(local_authentication(code)), Error::Declined(_)),
            "{code} is a person saying no"
        );
    }
    assert!(matches!(
        read(local_authentication(-1004)),
        Error::NotInteractive(_)
    ));
    assert!(matches!(
        read(OsError::new("CryptoTokenKit", -3, "")),
        Error::Load(_)
    ));
    // A context pulled by its own program is never a person's cancel.
    for code in [-9, -10] {
        assert!(
            matches!(read(local_authentication(code)), Error::Agree(_)),
            "{code} read as a cancel"
        );
    }
}

#[test]
fn only_a_pulled_context_after_the_deadline_reads_as_a_timeout() {
    let after = |code, fired| past(read(local_authentication(code)), fired);
    // The deadline pulled the context with the dialog up (-9), or before it showed (-10).
    assert!(matches!(after(-9, true), Error::TimedOut));
    assert!(matches!(after(-10, true), Error::TimedOut));
    // Without the deadline, the same codes are the system's failure.
    assert!(matches!(after(-9, false), Error::Agree(_)));
    assert!(matches!(after(-10, false), Error::Agree(_)));
    // A cancel or a no-match in the last instant stays what it was.
    assert!(matches!(after(-2, true), Error::Declined(_)));
    assert!(matches!(after(-1, true), Error::Declined(_)));
    assert!(matches!(
        past(read(OsError::new("CryptoTokenKit", -9, "")), true),
        Error::Load(_)
    ));
}
