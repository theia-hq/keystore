use core::fmt;

/// What a key file's key may be written as: plain or sealed as its owner chooses, or only ever
/// sealed.
///
/// A property of the SLOT a file is read from, chosen when the [`KeyFile`](crate::KeyFile) is named
/// ([`KeyFile::new`](crate::KeyFile::new), [`KeyFile::sealed`](crate::KeyFile::sealed)), and
/// recorded in every sealed file it writes. A sealed file of the other kind is refused where this
/// kind is expected, so a key of one kind can never stand in for a key of the other.
///
/// Deliberately exhaustive, like [`Method`](crate::Method): a kind added later must be a compile error
/// at every `match` that decides something by kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// A key written plain or sealed, as its owner chooses.
    Standard,
    /// A key only ever written sealed, that always keeps its passphrase lock.
    Sealed,
}

/// The kind's name, the words a person sees for it.
impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Standard => "standard key",
            Self::Sealed => "sealed-only key",
        })
    }
}
