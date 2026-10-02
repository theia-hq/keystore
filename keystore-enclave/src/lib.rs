//! A P-256 key in this Mac's Secure Enclave, kept as a blob in a file of your own, that agrees a secret
//! with a peer key only after a touch of a finger enrolled when the key was made.
//!
//! Four calls:
//!
//! - [`create`] makes a key in the enclave and returns its blob and its public key. Nothing is asked
//!   of anyone, and nothing goes in the keychain: the key is not permanent, so the blob is where it
//!   lives, and only this Mac's enclave can use it.
//! - [`load`] takes a blob back and checks it holds the public key you expect.
//! - [`Key::agree`] does ECDH between the enclave key and a peer's public key. It is the one call that
//!   asks for a touch, with your reason in the dialog, and it asks again every time.
//! - [`Key::check`] says, with no dialog, whether the key is this Mac's and still guarded.
//!
//! Wrapping a secret to the key needs only its public key, so it never touches the enclave: draw a
//! one-time P-256 key, agree with the enclave key's public half, and derive from that. Opening it
//! again is [`Key::agree`] with the one-time public key.
//!
//! The access control is pinned ([`Policy`]): a touch of a finger enrolled when the key was made, at
//! an unlocked screen, on this Mac. Adding or removing a finger ends the key. The login password
//! never stands in for the touch. Each operation asks through a context of its own, made for it and
//! invalidated after, so one touch is spent on one operation.
//!
//! Any program running as you can load a blob it can read and ask for the touch under its own reason.
//! The dialog names the program that asks; the person touching it decides.
//!
//! The crate is empty on every target but macOS.
//!
//! ```no_run
//! # fn main() -> Result<(), keystore_enclave::Error> {
//! # let peer = [4; keystore_enclave::PUBLIC_KEY_LEN];
//! use keystore_enclave::{Policy, create, load};
//!
//! let (blob, public) = create(Policy::BiometryCurrentSet)?; // keep both in your own file
//! let key = load(&blob, &public)?;
//! key.check()?; // this Mac's key, still guarded; no dialog
//! let secret = key.agree(&peer, "open your key")?; // asks for a touch
//! # drop(secret);
//! # Ok(())
//! # }
//! ```

#![cfg(target_os = "macos")]
// The workspace denies `unsafe`; this crate exists to hold the calls into Security.framework and
// LocalAuthentication, so it is allowed here and nowhere else, and every block states its case.
#![allow(unsafe_code)]

mod context;
mod error;
mod key;

pub use error::{Error, OsError};
pub use key::{Key, create, load};

/// A P-256 public key's length, uncompressed X9.63: `04`, then x, then y.
pub const PUBLIC_KEY_LEN: usize = 65;

/// An agreed secret's length: the shared point's x-coordinate.
pub const SECRET_LEN: usize = 32;

/// The access control a key is made under.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Policy {
    /// Each use needs a touch of a finger enrolled when the key was made, at an unlocked screen,
    /// on this Mac (`privateKeyUsage | biometryCurrentSet`, `WhenUnlockedThisDeviceOnly`). Adding or
    /// removing a finger ends the key; the login password never stands in.
    BiometryCurrentSet,
}
