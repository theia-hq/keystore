use core::fmt;

use core_foundation::base::TCFType as _;
use core_foundation::error::{CFError, CFErrorRef};

/// Why the enclave did not do what was asked.
///
/// The variants are the cases a caller decides on differently: a key this Mac does not hold, a
/// person who said no, a person who did not answer in time, a person who could not be asked.
/// Everything else is the system's own error, kept whole.
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
    /// another Mac, a damaged one, or a key made before a finger was added. They cannot be told apart:
    /// the enclave refuses them all the same way.
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
    /// No touch came within the wait [`Key::agree`](crate::Key::agree) was given, so it closed its
    /// own dialog. Never a cancel: nobody said no. The source is LocalAuthentication's `-9` when
    /// the dialog was up, or `-10` when the deadline came before it.
    #[error("the Touch ID dialog closed when its wait ran out")]
    TimedOut(#[source] OsError),
    /// The thread that ends the wait could not be started, so no dialog was shown.
    #[error("the Touch ID dialog was not shown: its timer could not start")]
    Timer(#[source] std::io::Error),
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

/// An error the system returned: its domain, its code, and its localized description.
///
/// Copied out of the `CFError` the call returned, so it can cross threads and outlive the call. Only
/// those three are taken: never the error's `userInfo` and never a debug description, where
/// LocalAuthentication keeps the enrolled fingers' hash (`BiometryDatabaseHash`) and CryptoTokenKit a
/// key's id. A description that names that hash, or holds a run of 16 or more hex digits (a key id or
/// a hash), is dropped as well, so only the domain and the code are kept, and nothing printed from an
/// `OsError` can carry either.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OsError {
    domain: String,
    code: isize,
    description: Option<String>,
}

/// The shortest run of hex digits read as a hash or a key id rather than as words. CryptoTokenKit's
/// key ids are 16.
const HEX_RUN: usize = 16;

impl OsError {
    /// The error's domain: `com.apple.LocalAuthentication`, `CryptoTokenKit`, `NSOSStatusErrorDomain`.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The error's code within its domain.
    pub const fn code(&self) -> isize {
        self.code
    }

    /// Whether the system's description was dropped because it held a hash or a key id.
    pub const fn description_withheld(&self) -> bool {
        self.description.is_none()
    }

    /// Take the `CFError` a call wrote to its out-parameter, releasing it. A call that failed without
    /// writing one still fails: it reads as an unknown error rather than a success.
    pub(crate) fn take(error: CFErrorRef) -> Self {
        if error.is_null() {
            return Self::new("unknown", 0, "the call failed and gave no reason");
        }
        // SAFETY: a non-null `CFErrorRef` written to a Security.framework out-parameter is a +1
        // reference this function now owns; wrapping it under the create rule releases it once.
        let error = unsafe { CFError::wrap_under_create_rule(error) };
        // `description` is the localized description, never the `userInfo` it was built beside.
        Self::new(
            &error.domain().to_string(),
            error.code(),
            &error.description().to_string(),
        )
    }

    /// An error from its parts, the description kept only if it carries no hash or key id.
    pub fn new(domain: &str, code: isize, description: &str) -> Self {
        Self {
            domain: domain.to_owned(),
            code,
            description: (!carries_a_secret_shape(description)).then(|| description.to_owned()),
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
        write!(f, "{} {}", self.domain, self.code)?;
        match &self.description {
            Some(description) => write!(f, ": {description}"),
            None => Ok(()),
        }
    }
}

impl core::error::Error for OsError {}

/// Whether `description` names the enrolled fingers' hash or holds a run of hex long enough to be a
/// hash or a key id, spaced in groups or not.
fn carries_a_secret_shape(description: &str) -> bool {
    if description.contains("BiometryDatabaseHash") {
        return true;
    }
    // A single space inside a run continues it, so Core Foundation's printed bytes
    // (`0x506ba565 fd1e8752 ...`, in groups of eight) count as one run.
    let mut run = 0;
    let mut after_hex = false;
    for c in description.chars() {
        if c.is_ascii_hexdigit() {
            run += 1;
            after_hex = true;
        } else if c == ' ' && after_hex {
            after_hex = false;
        } else {
            run = 0;
            after_hex = false;
        }
        if run >= HEX_RUN {
            return true;
        }
    }
    false
}

#[cfg(test)]
#[path = "error_tests.rs"]
mod error_tests;
