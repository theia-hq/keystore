use core_foundation::data::CFData;

use super::Key;
use crate::error::Error;

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
            matches!(no_key().agree(&[4; 65], reason), Err(Error::NoReason)),
            "{reason:?} was shown as a reason"
        );
    }
}
