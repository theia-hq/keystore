//! The passphrase lock: Argon2id derives the key-encryption key from the passphrase. The lock's
//! nonce and wrapped file key follow these parameters, and are the core's (see `lock`).
//!
//! Its parameters are 29 bytes, every field fixed-width, integers big-endian:
//!
//! | offset | len | field                                                   |
//! | ------ | --- | ------------------------------------------------------- |
//! | 0      | 1   | key derivation function, `1` = Argon2id, version `0x13` |
//! | 1      | 4   | Argon2id memory, KiB                                    |
//! | 5      | 4   | Argon2id passes                                         |
//! | 9      | 4   | Argon2id lanes                                          |
//! | 13     | 16  | salt                                                    |
//!
//! The wrap authenticates them, so an edit to any of them, the Argon2id cost included, fails the
//! unlock rather than producing a key. The derivation byte is where the lock grows: an unknown value
//! is refused by name, never guessed at.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroizing;

use crate::error::{CryptoError, FormatError};
use crate::lock::Kek;
use crate::passphrase::Passphrase;

/// Key derivation: Argon2id at version `0x13`.
const KDF_ARGON2ID: u8 = 1;
const SALT_LEN: usize = 16;

// The parameters' offsets, in order. Every field is fixed-width, so these ARE the grammar.
const AT_KDF: usize = 0;
const AT_MEMORY: usize = AT_KDF + 1;
const AT_PASSES: usize = AT_MEMORY + 4;
const AT_LANES: usize = AT_PASSES + 4;
const AT_SALT: usize = AT_LANES + 4;
/// The length of a passphrase lock's parameters.
pub(crate) const PARAMS_LEN: usize = AT_SALT + SALT_LEN;

// The layout is frozen: a file written today must parse forever. Moving a field is a compile error
// here before it is a golden-vector failure in the tests.
const _: () = assert!(PARAMS_LEN == 29);

/// A passphrase lock's parameters, parsed: the derivation within bounds, and its salt.
pub(crate) struct PassphraseParams {
    cost: Cost,
    salt: [u8; SALT_LEN],
}

impl PassphraseParams {
    pub(crate) fn parse(bytes: &[u8; PARAMS_LEN]) -> Result<Self, FormatError> {
        match bytes[AT_KDF] {
            KDF_ARGON2ID => {}
            found => return Err(FormatError::Kdf { found }),
        }
        let cost = Cost::parse(
            u32::from_be_bytes(field(bytes, AT_MEMORY)),
            u32::from_be_bytes(field(bytes, AT_PASSES)),
            u32::from_be_bytes(field(bytes, AT_LANES)),
        )?;
        Ok(Self {
            cost,
            salt: field(bytes, AT_SALT),
        })
    }

    /// Parameters for a new lock under `passphrase`, at the default cost with a fresh salt drawn
    /// for this lock alone, and the key they make: locking the same file under the same passphrase
    /// twice never reuses a salt.
    pub(crate) fn enroll(passphrase: &Passphrase) -> Result<(Self, Kek), CryptoError> {
        let mut salt = [0; SALT_LEN];
        getrandom::fill(&mut salt).map_err(CryptoError::entropy)?;
        Self::enroll_with(passphrase, Cost::DEFAULT, salt)
    }

    /// Enroll with every input chosen by the caller. Only [`enroll`](Self::enroll) reaches this
    /// outside the tests; the tests use it to pin the exact bytes this build writes against the
    /// golden vector.
    pub(crate) fn enroll_with(
        passphrase: &Passphrase,
        cost: Cost,
        salt: [u8; SALT_LEN],
    ) -> Result<(Self, Kek), CryptoError> {
        let params = Self { cost, salt };
        let kek = params.kek(passphrase)?;
        Ok((params, kek))
    }

    /// The key `passphrase` makes under these parameters.
    pub(crate) fn kek(&self, passphrase: &Passphrase) -> Result<Kek, CryptoError> {
        self.cost.derive(passphrase, &self.salt).map(Kek)
    }

    /// The parameters, byte for byte as they sit in the file.
    pub(crate) fn bytes(&self) -> [u8; PARAMS_LEN] {
        let mut bytes = [0; PARAMS_LEN];
        bytes[AT_KDF] = KDF_ARGON2ID;
        bytes[AT_MEMORY..AT_PASSES].copy_from_slice(&self.cost.memory_kib.to_be_bytes());
        bytes[AT_PASSES..AT_LANES].copy_from_slice(&self.cost.passes.to_be_bytes());
        bytes[AT_LANES..AT_SALT].copy_from_slice(&self.cost.lanes.to_be_bytes());
        bytes[AT_SALT..].copy_from_slice(&self.salt);
        bytes
    }
}

/// A fixed-width field of the parameters. The offsets are constants inside [`PARAMS_LEN`], asserted
/// above.
fn field<const N: usize>(bytes: &[u8; PARAMS_LEN], at: usize) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(&bytes[at..at + N]);
    out
}

/// The Argon2id cost a lock is wrapped at, bounded on read.
///
/// The ceiling exists because the cost is read from a file before anything is authenticated: a
/// hostile copy could otherwise demand gigabytes and minutes of work from the process that merely
/// tried to open it. It is 256 MiB, four times what a write uses, so a small board unlocking a
/// tampered file still stays out of the out-of-memory killer's reach, where it could take a
/// neighbouring process down with it. This is a policy of this build, not of the format, so a later
/// build can raise it, and a file this one refuses fails with the cost named. The floor exists so
/// that a file written by a careless or foreign writer at a toy cost is refused rather than reported
/// as protected; it is Argon2id's recommended minimum (19 MiB, two passes), pinned here as literals so a dependency changing its own default cannot move which
/// files this build accepts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Cost {
    memory_kib: u32,
    passes: u32,
    lanes: u32,
}

impl Cost {
    /// What every write uses: 64 MiB, three passes, one lane.
    pub(crate) const DEFAULT: Self = Self {
        memory_kib: 64 * 1024,
        passes: 3,
        lanes: 1,
    };

    /// The cheapest cost a file may carry.
    #[cfg(test)]
    pub(crate) const FLOOR: Self = Self {
        memory_kib: 19 * 1024,
        passes: 2,
        lanes: 1,
    };

    const MEMORY_KIB: (u32, u32) = (19 * 1024, 256 * 1024);
    const PASSES: (u32, u32) = (2, 10);
    const LANES: (u32, u32) = (1, 8);

    pub(crate) fn parse(memory_kib: u32, passes: u32, lanes: u32) -> Result<Self, FormatError> {
        let cost = Self {
            memory_kib,
            passes,
            lanes,
        };
        if !cost.is_bounded() {
            return Err(FormatError::Cost {
                memory_kib,
                passes,
                lanes,
            });
        }
        Ok(cost)
    }

    const fn is_bounded(self) -> bool {
        Self::MEMORY_KIB.0 <= self.memory_kib
            && self.memory_kib <= Self::MEMORY_KIB.1
            && Self::PASSES.0 <= self.passes
            && self.passes <= Self::PASSES.1
            && Self::LANES.0 <= self.lanes
            && self.lanes <= Self::LANES.1
    }

    fn derive(
        self,
        passphrase: &Passphrase,
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; Kek::LEN]>, CryptoError> {
        let params = Params::new(self.memory_kib, self.passes, self.lanes, Some(Kek::LEN))
            .map_err(CryptoError::kdf)?;
        // The work memory is ours, not argon2's, so it is wiped when it drops: argon2 frees its own
        // unwiped, and the last pass's blocks are enough to rebuild the key without the passphrase.
        // Reserved exactly and fallibly, so a machine short of memory gets an error, not an abort, and
        // filled within that reservation, so it never reallocates and leaves a copy behind.
        let count = params.block_count();
        let mut blocks = Zeroizing::new(Vec::new());
        blocks
            .try_reserve_exact(count)
            .map_err(CryptoError::memory)?;
        blocks.resize(count, Block::default());
        let mut key = Zeroizing::new([0; Kek::LEN]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into_with_memory(
                passphrase.as_bytes(),
                salt,
                &mut key[..],
                &mut blocks[..],
            )
            .map_err(CryptoError::kdf)?;
        Ok(key)
    }
}

// What this build writes, it must also read.
const _: () = assert!(Cost::DEFAULT.is_bounded());
