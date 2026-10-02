use core::fmt;

use core_foundation::base::TCFType as _;
use core_foundation::error::{CFError, CFErrorRef};

/// Why the enclave did not do what was asked.
///
/// The variants are the cases a caller decides on differently: a key this Mac does not hold, a person
/// who said no, a person who could not be asked. Everything else is the system's own error, kept whole.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The access control a new key is made under could not be built.
    #[error("the Secure Enclave's access control could not be made")]
    AccessControl(#[source] OsError),
    /// The Secure Enclave did not make a key: no enclave on this Mac, or the screen is locked.
    #[error("the Secure Enclave could not make a key")]
    Create(#[source] OsError),
    /// The new key came back without the blob that names it, so there is nothing to keep.
    #[error("the new enclave key has no blob to keep")]
    NoBlob,
    /// The blob does not load, or loads and cannot be used, in this Mac's enclave: a blob made on
    /// another Mac, or a damaged one. The two cannot be told apart: the enclave refuses both the
    /// same way.
    #[error("the key blob does not open in this Mac's Secure Enclave")]
    Load(#[source] OsError),
    /// The blob holds a different key than the public key it was loaded against.
    #[error("the key blob holds a different key than the one expected")]
    OtherKey,
    /// The peer's bytes are not a P-256 public key.
    #[error("the peer is not a P-256 public key")]
    Peer(#[source] OsError),
    /// The person cancelled, or the touch did not match.
    #[error("the touch was cancelled or did not match")]
    Declined(#[source] OsError),
    /// The key needs a person, and this operation was not allowed to ask one.
    #[error("the key needs a touch, and none could be asked for")]
    NotInteractive(#[source] OsError),
    /// A new key agreed a secret with nobody asked: it guards nothing, so it is never handed out.
    #[error("the new enclave key opened with nobody asked, so it guards nothing")]
    Unguarded,
    /// The enclave could not agree a secret for another reason.
    #[error("the Secure Enclave could not agree a secret")]
    Agree(#[source] OsError),
    /// The enclave answered with a secret of the wrong length.
    #[error("the Secure Enclave agreed a secret of {found} bytes, not 32")]
    SecretLength {
        /// The length the enclave returned.
        found: usize,
    },
    /// [`Key::agree`](crate::Key::agree) was given no reason to show in the dialog.
    #[error("the reason shown in the Touch ID dialog is empty")]
    NoReason,
    /// The system has no `LAContext` to ask a person through.
    #[error("this Mac has no local authentication context")]
    NoContext,
}

/// An error the system returned, as it said it: its domain, its code, and its description.
///
/// Copied out of the `CFError` the call returned, so it can cross threads and outlive the call.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OsError {
    domain: String,
    code: isize,
    description: String,
}

impl OsError {
    /// The error's domain: `com.apple.LocalAuthentication`, `CryptoTokenKit`, `NSOSStatusErrorDomain`.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The error's code within its domain.
    pub const fn code(&self) -> isize {
        self.code
    }

    /// Take the `CFError` a call wrote to its out-parameter, releasing it. A call that failed without
    /// writing one still fails: it reads as an unknown error rather than a success.
    pub(crate) fn take(error: CFErrorRef) -> Self {
        if error.is_null() {
            return Self {
                domain: String::from("unknown"),
                code: 0,
                description: String::from("the call failed and gave no reason"),
            };
        }
        // SAFETY: a non-null `CFErrorRef` written to a Security.framework out-parameter is a +1
        // reference this function now owns; wrapping it under the create rule releases it once.
        let error = unsafe { CFError::wrap_under_create_rule(error) };
        Self {
            domain: error.domain().to_string(),
            code: error.code(),
            description: error.description().to_string(),
        }
    }

    /// Whether this is LocalAuthentication's error `code`.
    pub(crate) fn is_local_authentication(&self, code: isize) -> bool {
        self.domain == "com.apple.LocalAuthentication" && self.code == code
    }

    /// Whether CryptoTokenKit raised this: the enclave's token refused the key itself.
    pub(crate) fn is_token(&self) -> bool {
        self.domain == "CryptoTokenKit"
    }
}

impl fmt::Display for OsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.domain, self.code, self.description)
    }
}

impl core::error::Error for OsError {}
