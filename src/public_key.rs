use ed25519_dalek::VerifyingKey;
use ed25519_dalek::hazmat::ExpandedSecretKey;

/// The ed25519 public key of a stored seed, as 32 bytes.
///
/// Bytes only: no curve check, no text form, no `Display`, no `FromStr`. It exists so a public key
/// cannot be passed where a seed goes. A caller that needs an identity builds its own checked type
/// from [`bytes`](Self::bytes) at its own edge, where every key that enters is checked anyway.
///
/// A key computed from a seed ([`Secret::public_key`](crate::Secret::public_key)) is a fact. A key
/// read from a locked file's header ([`Locked::public_key`](crate::Locked::public_key)) is a claim
/// until the file unlocks, and the unlock refuses a header that does not match the seed it seals.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicKey(pub(crate) [u8; PublicKey::LEN]);

impl PublicKey {
    /// An ed25519 public key's length, which is also its length in a sealed file's header.
    pub(crate) const LEN: usize = 32;

    /// The public half of `seed`, by RFC 8032: the seed's SHA-512 expansion, clamped, times the
    /// base point. Reached through the expanded secret key rather than a signing key, because
    /// nothing here signs; the expansion wipes itself on drop.
    pub(crate) fn of_seed(seed: &[u8; Self::LEN]) -> Self {
        let expanded = ExpandedSecretKey::from(seed);
        Self(VerifyingKey::from(&expanded).to_bytes())
    }

    /// The key's 32 bytes.
    pub const fn bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

/// A [`PublicKey`] has no text form, so a caller cannot print or parse one as if it were an
/// identity: each refusal below names the error it must fail with. Only a nightly `rustdoc` checks
/// the codes; a stable one checks only that the example fails to compile.
///
/// ```compile_fail,E0277
/// # fn show(key: keystore::PublicKey) -> String {
/// format!("{key}")
/// # }
/// ```
///
/// ```compile_fail,E0277
/// # fn read(text: &str) -> Result<keystore::PublicKey, core::convert::Infallible> {
/// Ok(text.parse::<keystore::PublicKey>().unwrap())
/// # }
/// ```
///
/// The same shapes through its bytes compile, so each refusal above is the missing text form and
/// not a typo:
///
/// ```
/// # fn show(key: keystore::PublicKey) -> String {
/// format!("{:?}", key.bytes())
/// # }
/// ```
#[cfg(doctest)]
pub fn public_key_has_no_text_form() {}

#[cfg(test)]
#[path = "public_key_tests.rs"]
mod public_key_tests;
