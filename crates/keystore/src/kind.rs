use core::fmt;

/// How a key file's key may be kept: plain or sealed as its owner chooses, or always sealed with a
/// passphrase lock.
///
/// Chosen when the [`KeyFile`](crate::KeyFile) is named ([`KeyFile::new`](crate::KeyFile::new),
/// [`KeyFile::strict`](crate::KeyFile::strict)), and recorded in every sealed file it writes. A
/// sealed file of the other kind is refused where this kind is expected, so a key of one kind can
/// never stand in for a key of the other.
///
/// Deliberately exhaustive, like [`Method`](crate::Method): a kind added later must be a compile error
/// at every `match` that decides something by kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// A key written plain or sealed, as its owner chooses.
    Standard,
    /// A key always written sealed, that never loses its passphrase lock.
    Strict,
}

/// The kind's name, the words a person sees for it.
impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Standard => "standard key",
            Self::Strict => "strict key",
        })
    }
}
