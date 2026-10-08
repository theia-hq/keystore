use zeroize::Zeroizing;

use super::{Envelope, HEADER_LEN, Opened, Parsed, Refusal, SIGNATURE, assemble, header, parse};
use crate::error::{FormatError, TouchIdError};
use crate::kind::Kind;
use crate::lock::enclave::enclave_tests::{self as stand_in, Touch, WAIT};
use crate::lock::enclave::{EnclaveParams, Policy};
use crate::lock::passphrase::{Cost, PassphraseParams};
use crate::lock::{FileKey, Lock, Params};
use crate::method::{Method, NewLock, Unlock};
use crate::passphrase::Passphrase;
use crate::public_key::PublicKey;
use crate::secret::Secret;

/// A version 2 sealed standard key file, byte for byte. THE format test: a file this build wrote
/// must open to the same key forever, so these bytes are literal, never computed at test time.
///
/// They were produced outside this crate, from the layout in the module docs alone: Argon2id by the
/// OpenSSL 3.6 CLI (`openssl kdf ... ARGON2ID`, version 19), XChaCha20-Poly1305 by an implementation
/// written from RFC 8439 and the XChaCha draft and checked against both documents' published vectors,
/// and the public key by `openssl pkey`. That same computation reproduces the version 1 file below
/// byte for byte. So they pin that the layout doc is the whole format, and not only that this code
/// agrees with itself.
#[rustfmt::skip]
const GOLDEN: [u8; 219] = [
    0x4b, 0x45, 0x59, 0x53, 0x54, 0x4f, 0x52, 0x45, 0x02, 0x01, 0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce,
    0x10, 0xbe, 0x1d, 0x70, 0xdd, 0x18, 0xe7, 0x4b, 0xc0, 0x99, 0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5,
    0x0d, 0x5f, 0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55, 0x31, 0xb8, 0x01, 0x01, 0x00, 0x65, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4,
    0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4,
    0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4,
    0xc5, 0xc6, 0xc7, 0xe5, 0xf7, 0xd0, 0x48, 0x86, 0x4e, 0x47, 0xed, 0xa4, 0xde, 0x19, 0x26, 0xe2,
    0xb5, 0xbd, 0x79, 0xf9, 0x35, 0x36, 0x75, 0xfe, 0xff, 0xfb, 0x76, 0x4a, 0x91, 0x33, 0x06, 0x6c,
    0xea, 0xf9, 0x09, 0x01, 0xf2, 0x7f, 0xc2, 0x64, 0xfb, 0x71, 0x89, 0x90, 0x24, 0x3c, 0x70, 0xa8,
    0xa0, 0x54, 0xaf, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c,
    0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x34, 0xd3, 0xd7, 0xcc, 0xaa,
    0x6e, 0xbe, 0x13, 0xac, 0x6d, 0x53, 0xd7, 0x8c, 0xd5, 0xe5, 0xef, 0x7d, 0x3f, 0x91, 0xac, 0xf1,
    0x4d, 0xac, 0x4f, 0xb1, 0x87, 0xfd, 0xaf, 0xf9, 0x2d, 0x82, 0xfc, 0x2c, 0x10, 0x6a, 0xba, 0x0b,
    0x67, 0x93, 0x19, 0x21, 0x7c, 0x8d, 0x08, 0xaf, 0xc2, 0xb0, 0x87,
];

/// [`GOLDEN`] sealed as a sealed-only key: the same inputs with the kind byte at 2, computed the
/// same way. The kind is in every byte the lock and the seed's seal authenticate, so the wrapped
/// file key and both tags differ.
#[rustfmt::skip]
const GOLDEN_SEALED: [u8; 219] = [
    0x4b, 0x45, 0x59, 0x53, 0x54, 0x4f, 0x52, 0x45, 0x02, 0x02, 0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce,
    0x10, 0xbe, 0x1d, 0x70, 0xdd, 0x18, 0xe7, 0x4b, 0xc0, 0x99, 0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5,
    0x0d, 0x5f, 0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55, 0x31, 0xb8, 0x01, 0x01, 0x00, 0x65, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4,
    0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4,
    0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4,
    0xc5, 0xc6, 0xc7, 0xe5, 0xf7, 0xd0, 0x48, 0x86, 0x4e, 0x47, 0xed, 0xa4, 0xde, 0x19, 0x26, 0xe2,
    0xb5, 0xbd, 0x79, 0xf9, 0x35, 0x36, 0x75, 0xfe, 0xff, 0xfb, 0x76, 0x4a, 0x91, 0x33, 0x06, 0x6c,
    0xea, 0xf9, 0x09, 0xf3, 0xda, 0xfd, 0x3d, 0x81, 0x01, 0xb8, 0x7b, 0x81, 0x53, 0x46, 0x23, 0x73,
    0x96, 0x23, 0x98, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c,
    0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x34, 0xd3, 0xd7, 0xcc, 0xaa,
    0x6e, 0xbe, 0x13, 0xac, 0x6d, 0x53, 0xd7, 0x8c, 0xd5, 0xe5, 0xef, 0x7d, 0x3f, 0x91, 0xac, 0xf1,
    0x4d, 0xac, 0x4f, 0xb1, 0x87, 0xfd, 0xaf, 0xf9, 0x2d, 0x82, 0xfc, 0x6e, 0x95, 0x41, 0xf5, 0xa3,
    0x8a, 0x2f, 0x63, 0xfd, 0x88, 0xa8, 0x6d, 0xef, 0xec, 0x4a, 0x4a,
];

/// [`GOLDEN`]'s wrapped file key (the file key and its tag), wrapped instead under the passphrase
/// `café crème` in its NFC byte form, `63 61 66 c3 a9 20 63 72 c3 a8 6d 65`. Computed the same way,
/// with the byte form taken from Python's source text, not from the normalizer this crate uses. It
/// pins the passphrase's byte form as part of the format.
#[rustfmt::skip]
const GOLDEN_NFC_WRAPPED: [u8; 48] = [
    0x38, 0x9d, 0x37, 0x73, 0x37, 0x1c, 0x88, 0x7c, 0xa6, 0xe8, 0xbf, 0x0a, 0x6a, 0xa8, 0xc9, 0x9e,
    0xd6, 0x09, 0x1a, 0xaa, 0xf6, 0x02, 0x0a, 0xad, 0x54, 0x5b, 0xb9, 0xfe, 0x97, 0x01, 0x77, 0xb2,
    0xc1, 0x74, 0xf1, 0x04, 0xfa, 0xb9, 0xf6, 0x31, 0x0b, 0x84, 0xfd, 0x13, 0x03, 0x5d, 0x7b, 0x28,
];

/// A version 1 sealed key file: the seed above sealed directly under the passphrase, the layout
/// before locks. Kept to show it is refused as what it is.
#[rustfmt::skip]
const VERSION_1: [u8; 144] = [
    0x4b, 0x45, 0x59, 0x53, 0x54, 0x4f, 0x52, 0x45, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce, 0x10, 0xbe, 0x1d, 0x70, 0xdd, 0x18, 0xe7, 0x4b, 0xc0, 0x99,
    0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5, 0x0d, 0x5f, 0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55, 0x31, 0xb8,
    0x35, 0x27, 0x00, 0x98, 0x56, 0x9e, 0x97, 0x3d, 0x74, 0x0e, 0xc9, 0xf6, 0x32, 0x65, 0x6d, 0xa9,
    0x09, 0xc5, 0xc6, 0x85, 0x0e, 0x0f, 0x0b, 0x86, 0xba, 0x61, 0xc3, 0xf6, 0x9c, 0x1a, 0x09, 0xf9,
    0xaf, 0x05, 0x64, 0x9f, 0x75, 0xa2, 0xec, 0xae, 0x8c, 0x00, 0x0d, 0xe4, 0x56, 0x14, 0xaf, 0x98,
];

/// Inputs shared by every golden vector: seed `00 01 .. 1f`; passphrase `correct horse battery
/// staple`; file key `d0 .. ef`; the lock's salt `a0 .. af` and nonce `b0 .. c7`; the seed's nonce
/// `40 .. 57`; Argon2id at 64 MiB, 3 passes, 1 lane.
fn golden_seed() -> [u8; 32] {
    core::array::from_fn(|at| at as u8)
}

fn golden_file_key() -> [u8; 32] {
    core::array::from_fn(|at| 0xd0 + at as u8)
}

fn golden_salt() -> [u8; 16] {
    core::array::from_fn(|at| 0xa0 + at as u8)
}

fn golden_lock_nonce() -> [u8; 24] {
    core::array::from_fn(|at| 0xb0 + at as u8)
}

fn golden_seed_nonce() -> [u8; 24] {
    core::array::from_fn(|at| 0x40 + at as u8)
}

fn golden_cost() -> Cost {
    Cost::parse(64 * 1024, 3, 1).unwrap()
}

/// The golden seed's ed25519 public key, as `openssl pkey` derived it.
#[rustfmt::skip]
const GOLDEN_PUBLIC: [u8; 32] = [
    0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce, 0x10, 0xbe, 0x1d, 0x70, 0xdd, 0x18, 0xe7, 0x4b, 0xc0, 0x99,
    0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5, 0x0d, 0x5f, 0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55, 0x31, 0xb8,
];

// The golden file's offsets, spelled out from the layout rather than taken from the code under test:
// the header, the count, one passphrase lock's record, then the seed's nonce and seal.
const AT_METHOD: usize = 43;
const AT_LENGTH: usize = 44;
const AT_KDF: usize = 46;
const AT_MEMORY: usize = 47;
const AT_PASSES: usize = 51;
const AT_LANES: usize = 55;
const AT_SALT: usize = 59;
const AT_LOCK_NONCE: usize = 75;
const AT_WRAPPED: usize = 99;
const AT_SEED_NONCE: usize = 147;
const AT_SEALED_SEED: usize = 171;
const AT_SEED_TAG: usize = 203;
const GOLDEN_LEN: usize = 219;

fn passphrase(text: &str) -> Passphrase {
    Passphrase::new(Zeroizing::new(text.as_bytes().to_vec())).unwrap()
}

fn golden_passphrase() -> Passphrase {
    passphrase("correct horse battery staple")
}

fn sealed(bytes: &[u8]) -> Envelope {
    sealed_as(bytes, Kind::Standard)
}

fn sealed_as(bytes: &[u8], expected: Kind) -> Envelope {
    match parse(bytes, expected) {
        Ok(Parsed::Sealed(envelope)) => envelope,
        Ok(Parsed::Plain(_)) => panic!("parsed as a plain seed"),
        Err(error) => panic!("did not parse: {error}"),
    }
}

fn refusal(bytes: &[u8]) -> FormatError {
    refusal_as(bytes, Kind::Standard)
}

fn refusal_as(bytes: &[u8], expected: Kind) -> FormatError {
    match parse(bytes, expected) {
        Err(error) => error,
        Ok(Parsed::Plain(_)) => panic!("{} bytes were read as a plain seed", bytes.len()),
        Ok(Parsed::Sealed(_)) => panic!("{} bytes were accepted as a sealed file", bytes.len()),
    }
}

/// Open with the passphrase `under`, or say why not.
fn open(envelope: &Envelope, under: &Passphrase) -> Result<Opened, Refusal> {
    envelope.unlock(Unlock::Passphrase(under))
}

/// A file built by this crate's writer from chosen inputs: `secret` under one passphrase lock, its
/// header naming `public`, at `cost`.
fn build(
    kind: Kind,
    public: PublicKey,
    secret: &Secret,
    under: &Passphrase,
    cost: Cost,
    salt: [u8; 16],
) -> Vec<u8> {
    let file_key = FileKey::copy_of(&golden_file_key());
    let header = header(kind, public);
    let lock = passphrase_lock(under, &file_key, &header, cost, salt);
    assemble(&header, &[&lock], &file_key, secret, &golden_seed_nonce()).unwrap()
}

/// A passphrase lock built by this crate's writer from chosen inputs, wrapping `file_key` for a
/// file whose first bytes are `header`, under the golden lock nonce.
fn passphrase_lock(
    under: &Passphrase,
    file_key: &FileKey,
    header: &[u8; HEADER_LEN],
    cost: Cost,
    salt: [u8; 16],
) -> Lock {
    let (params, kek) = PassphraseParams::enroll_with(under, cost, salt).unwrap();
    Lock::wrap_with(
        Params::Passphrase(params),
        &kek,
        file_key,
        header,
        golden_lock_nonce(),
    )
    .unwrap()
}

/// A standard key file at the cheapest cost a file may carry, for the tests that unlock many times.
fn floor_image(secret: &Secret, under: &Passphrase) -> Vec<u8> {
    build(
        Kind::Standard,
        secret.public_key(),
        secret,
        under,
        Cost::FLOOR,
        golden_salt(),
    )
}

#[test]
fn the_golden_vector_opens_to_its_seed() {
    let envelope = sealed(&GOLDEN);
    assert_eq!(envelope.methods().collect::<Vec<_>>(), [Method::Passphrase]);
    assert_eq!(envelope.public_key().bytes(), &GOLDEN_PUBLIC);
    let opened = open(&envelope, &golden_passphrase()).unwrap();
    opened
        .secret
        .with_bytes(|seed| assert_eq!(seed, &golden_seed()));
    assert_eq!(opened.file_key.bytes(), &golden_file_key());
    assert_eq!(opened.secret.public_key(), envelope.public_key());
}

#[test]
fn this_build_writes_the_golden_vector_byte_for_byte() {
    let secret = Secret::copy_of(&golden_seed());
    let image = build(
        Kind::Standard,
        secret.public_key(),
        &secret,
        &golden_passphrase(),
        golden_cost(),
        golden_salt(),
    );
    assert_eq!(image, GOLDEN);
}

#[test]
fn the_golden_sealed_vector_opens_to_its_seed_only_as_a_sealed_only_key() {
    let envelope = sealed_as(&GOLDEN_SEALED, Kind::Sealed);
    let opened = open(&envelope, &golden_passphrase()).unwrap();
    opened
        .secret
        .with_bytes(|seed| assert_eq!(seed, &golden_seed()));
    assert_eq!(
        refusal_as(&GOLDEN_SEALED, Kind::Standard),
        FormatError::WrongKind {
            expected: Kind::Standard,
            found: Kind::Sealed
        }
    );
}

#[test]
fn this_build_writes_the_golden_sealed_vector_byte_for_byte() {
    let secret = Secret::copy_of(&golden_seed());
    let image = build(
        Kind::Sealed,
        secret.public_key(),
        &secret,
        &golden_passphrase(),
        golden_cost(),
        golden_salt(),
    );
    assert_eq!(image, GOLDEN_SEALED);
}

#[test]
fn a_decomposed_typing_of_the_passphrase_opens_the_nfc_golden_lock() {
    // The golden lock, wrapped instead under the NFC form of `café crème`. The passphrase's byte form
    // matters only to the lock it opens, so the lock alone is pinned.
    let mut body = GOLDEN[AT_KDF..AT_SEED_NONCE].to_vec();
    body[AT_WRAPPED - AT_KDF..].copy_from_slice(&GOLDEN_NFC_WRAPPED);
    let lock = Lock::parse(Method::Passphrase, &body).unwrap();
    let mut golden_header = [0; HEADER_LEN];
    golden_header.copy_from_slice(&GOLDEN[..HEADER_LEN]);
    // `e` then a combining accent: the spelling a dead-key terminal may send, not the one sealed.
    let typed =
        Passphrase::try_from(Zeroizing::new("cafe\u{301} cre\u{300}me".to_owned())).unwrap();
    let Ok(file_key) = lock.open(Unlock::Passphrase(&typed), &golden_header) else {
        panic!("the decomposed typing did not open the NFC lock");
    };
    assert_eq!(file_key.bytes(), &golden_file_key());
}

#[test]
fn a_version_1_file_is_refused_as_version_1() {
    assert_eq!(refusal(&VERSION_1), FormatError::Version { found: 1 });
    assert_eq!(
        refusal_as(&VERSION_1, Kind::Sealed),
        FormatError::Version { found: 1 }
    );
}

#[test]
fn a_sealed_key_is_read_only_as_its_own_kind() {
    assert_eq!(
        refusal_as(&GOLDEN, Kind::Sealed),
        FormatError::WrongKind {
            expected: Kind::Sealed,
            found: Kind::Standard
        }
    );
}

#[test]
fn a_plain_seed_has_no_kind_to_refuse_it_by() {
    for expected in [Kind::Standard, Kind::Sealed] {
        assert!(matches!(
            parse(&[9; 32], expected),
            Ok(Parsed::Plain(seed)) if seed == &[9; 32]
        ));
    }
}

#[test]
fn a_standard_key_relabelled_as_a_sealed_only_key_does_not_unlock() {
    // The kind byte is authenticated by the lock and by the seed's seal: rewriting it gets past the
    // parser, which reads it before anything is verified, and then fails the unlock rather than
    // opening a standard key as a sealed-only key.
    let mut relabelled = GOLDEN;
    relabelled[9] = 2;
    let envelope = sealed_as(&relabelled, Kind::Sealed);
    assert!(matches!(
        open(&envelope, &golden_passphrase()),
        Err(Refusal::Unlock(_))
    ));
}

#[test]
fn every_seal_uses_the_golden_cost_and_draws_a_fresh_file_key_salt_and_nonces() {
    let secret = Secret::copy_of(&golden_seed());
    let under = passphrase("correct horse battery staple");
    let first = Envelope::seal(&secret, Kind::Standard, NewLock::Passphrase(&under)).unwrap();
    let second = Envelope::seal(&secret, Kind::Standard, NewLock::Passphrase(&under)).unwrap();
    for image in [&first, &second] {
        assert_eq!(image.len(), GOLDEN_LEN);
        assert_eq!(image[..AT_SALT], GOLDEN[..AT_SALT]);
    }
    for (field, range) in [
        ("salt", AT_SALT..AT_LOCK_NONCE),
        ("lock nonce", AT_LOCK_NONCE..AT_WRAPPED),
        ("seed nonce", AT_SEED_NONCE..AT_SEALED_SEED),
    ] {
        assert_ne!(
            first[range.clone()],
            second[range],
            "the {field} was reused"
        );
    }
    let (first, second) = (
        open(&sealed(&first), &under).unwrap(),
        open(&sealed(&second), &under).unwrap(),
    );
    assert_ne!(first.file_key.bytes(), second.file_key.bytes());
}

#[test]
fn a_wrong_passphrase_and_a_damaged_file_are_one_refusal() {
    let secret = Secret::copy_of(&golden_seed());
    let under = passphrase("correct horse battery staple");
    let image = floor_image(&secret, &under);

    assert!(matches!(
        open(&sealed(&image), &passphrase("Correct horse battery staple")),
        Err(Refusal::Unlock(_))
    ));
    // One flipped bit in every field the lock or the seed's seal authenticates. The Argon2id fields
    // flip to values still inside the bounds, so the damage reaches the cipher rather than the parser.
    // The public key flips its sign bit, the one flip that always names another real key, so the parse
    // passes and the cipher is what refuses it.
    for (field, at, bit) in [
        ("public key", AT_METHOD - 2, 0x80),
        ("memory", AT_MEMORY + 3, 0x01),
        ("passes", AT_PASSES + 3, 0x01),
        ("lanes", AT_LANES + 3, 0x02),
        ("salt", AT_SALT, 0x01),
        ("lock nonce", AT_LOCK_NONCE + 23, 0x80),
        ("wrapped file key", AT_WRAPPED, 0x01),
        ("wrapped file key's tag", AT_SEED_NONCE - 1, 0x01),
        ("seed nonce", AT_SEED_NONCE, 0x01),
        ("sealed seed", AT_SEALED_SEED + 31, 0x01),
        ("seed tag", AT_SEED_TAG, 0x40),
    ] {
        let mut damaged = image.clone();
        damaged[at] ^= bit;
        assert!(
            matches!(open(&sealed(&damaged), &under), Err(Refusal::Unlock(_))),
            "a damaged {field} was not refused as a failed unlock"
        );
    }
}

#[test]
fn any_edit_to_a_lock_fails_the_whole_file() {
    let secret = Secret::copy_of(&golden_seed());
    let under = passphrase("correct horse battery staple");
    let image = floor_image(&secret, &under);
    assert!(open(&sealed(&image), &under).is_ok());

    // Edited: a lock's bytes the parser cannot judge fail the unlock; the rest refuse by name.
    for at in [
        AT_MEMORY + 3,
        AT_SALT + 7,
        AT_LOCK_NONCE + 11,
        AT_WRAPPED + 40,
    ] {
        let mut edited = image.clone();
        edited[at] ^= 0x01;
        assert!(
            matches!(open(&sealed(&edited), &under), Err(Refusal::Unlock(_))),
            "an edit at byte {at} opened"
        );
    }
    let mut edited = image.clone();
    edited[AT_METHOD] = 9;
    assert_eq!(refusal(&edited), FormatError::Method { found: 9 });
    let mut edited = image.clone();
    edited[AT_KDF] = 2;
    assert_eq!(refusal(&edited), FormatError::Kdf { found: 2 });

    // Dropped: with its record gone the count must fall too, and a file of no locks is refused.
    let dropped = [&image[..HEADER_LEN], &[0][..], &image[AT_SEED_NONCE..]].concat();
    assert_eq!(refusal(&dropped), FormatError::NoLocks);

    // Swapped: a lock that opens on its own, wrapping this file's own key under this file's header,
    // put in place of the one the seed was sealed beside. The lock is good, and the file still does
    // not open, because the seed's seal covers every lock as it was.
    let file_key = FileKey::copy_of(&golden_file_key());
    let mut golden_header = [0; HEADER_LEN];
    golden_header.copy_from_slice(&image[..HEADER_LEN]);
    let other_salt = core::array::from_fn(|at| 0x10 + at as u8);
    let swapped_lock = passphrase_lock(&under, &file_key, &golden_header, Cost::FLOOR, other_salt);
    let mut record = Vec::new();
    swapped_lock.write(&mut record);
    let mut swapped = image.clone();
    swapped[AT_METHOD..AT_SEED_NONCE].copy_from_slice(&record);
    let envelope = sealed(&swapped);
    let Some(lock) = envelope.locks.first() else {
        panic!("the swapped file lost its lock");
    };
    let Ok(opened_key) = lock.open(Unlock::Passphrase(&under), &golden_header) else {
        panic!("the swapped-in lock does not open on its own");
    };
    assert_eq!(opened_key.bytes(), &golden_file_key());
    assert!(matches!(open(&envelope, &under), Err(Refusal::Unlock(_))));
}

#[test]
fn a_plain_file_is_exactly_32_bytes() {
    assert!(matches!(parse(&[9; 32], Kind::Standard), Ok(Parsed::Plain(seed)) if seed == &[9; 32]));
    for found in [0, 1, 31, 33, 218, 219, 220] {
        assert_eq!(
            refusal(&vec![9; found]),
            FormatError::Size {
                found: found as u64
            }
        );
    }
}

#[test]
fn a_cut_down_sealed_file_is_never_read_as_a_plain_seed() {
    // Cut to exactly 32 bytes it has the plain length; the signature decides first.
    for found in [8, 9, 32, 42, 43, 46, 146, 218] {
        assert_eq!(
            refusal(&GOLDEN[..found]),
            FormatError::SealedSize {
                found: found as u64
            }
        );
    }
    let mut padded = GOLDEN.to_vec();
    padded.push(0);
    assert_eq!(refusal(&padded), FormatError::SealedSize { found: 220 });
}

#[test]
fn an_unknown_version_is_named_before_its_length_is_judged() {
    assert_eq!(
        refusal(&[&SIGNATURE[..], &[3]].concat()),
        FormatError::Version { found: 3 }
    );
    for found in [0, 1, 3, 255] {
        let mut image = GOLDEN;
        image[8] = found;
        assert_eq!(refusal(&image), FormatError::Version { found });
    }
}

/// The public key the seed `[7; 32]` binds, plus the order-8 torsion point: canonical, not small-order,
/// and a second spelling of that key.
#[rustfmt::skip]
const TORSION_TWIN: [u8; 32] = [
    0x1f, 0x4f, 0x58, 0x0e, 0x73, 0xac, 0x20, 0x8f, 0x06, 0x76, 0x01, 0x90, 0xe9, 0xed, 0xc6, 0xf5,
    0x91, 0x67, 0x75, 0xda, 0xbd, 0x9c, 0x1c, 0xdc, 0xa3, 0x93, 0x17, 0x5c, 0x2d, 0x6d, 0x10, 0x83,
];

#[test]
fn a_header_that_does_not_match_the_seed_refuses_the_unlock() {
    // Each header is written by this crate's own writer under the right passphrase, so the lock and
    // the seed's seal both open, and only the compare against the seed's own key can refuse it. The
    // header is bytes, so it parses whatever it names: another real key, a second spelling of the
    // seed's own key, or bytes that are no key at all.
    let secret = Secret::copy_of(&[7; 32]);
    let under = passphrase("correct horse battery staple");
    for (named, claimed) in [
        ("another key", Secret::copy_of(&golden_seed()).public_key()),
        ("a torsion twin of the seed's key", PublicKey(TORSION_TWIN)),
        ("bytes that are no key", PublicKey([0xff; 32])),
    ] {
        let image = build(
            Kind::Standard,
            claimed,
            &secret,
            &under,
            Cost::FLOOR,
            golden_salt(),
        );
        let envelope = sealed(&image);
        assert_eq!(
            envelope.public_key(),
            claimed,
            "{named} did not parse as bytes"
        );
        assert!(
            matches!(open(&envelope, &under), Err(Refusal::Inconsistent)),
            "a header naming {named} was not refused at the unlock"
        );
    }
    // The same file with the seed's own key opens, so the refusals above are the compare's.
    let image = floor_image(&secret, &under);
    assert!(open(&sealed(&image), &under).is_ok());
}

#[test]
fn only_registered_kinds_and_derivations_parse() {
    // Kinds 1 and 2 are the standard and sealed-only keys; derivation 1 is Argon2id. No other value
    // is registered, so a value reserved for the future cannot be carried by a file this build
    // accepts.
    for found in [0, 3, 255] {
        let mut image = GOLDEN;
        image[9] = found;
        assert_eq!(refusal(&image), FormatError::Kind { found });
    }
    for found in [0, 2, 3, 255] {
        let mut image = GOLDEN;
        image[AT_KDF] = found;
        assert_eq!(refusal(&image), FormatError::Kdf { found });
    }
}

#[test]
fn each_kind_is_the_byte_it_always_was() {
    // The kind byte is format, not a name: whatever the variants are called, each reads and writes
    // the byte below, and the golden files carry it, so a file keeps the kind it was written as.
    assert_eq!(Kind::Standard.byte(), 1);
    assert_eq!(Kind::Sealed.byte(), 2);
    assert_eq!(Kind::of_byte(1), Some(Kind::Standard));
    assert_eq!(Kind::of_byte(2), Some(Kind::Sealed));
    assert_eq!(GOLDEN[9], 1);
    assert_eq!(GOLDEN_SEALED[9], 2);
}

#[test]
fn an_unknown_method_refuses_by_name() {
    // Method 1 is the passphrase, 2 is touch-id, and no other value is registered.
    for found in [0, 3, 4, 255] {
        let mut image = GOLDEN;
        image[AT_METHOD] = found;
        assert_eq!(refusal(&image), FormatError::Method { found });
    }
    // A second lock of a method this build does not know, after a good one: the list is refused at
    // that lock, by its method, not by how many locks there are.
    let mut two = GOLDEN[..AT_SEED_NONCE].to_vec();
    two[HEADER_LEN] = 2;
    two.extend_from_slice(&[3, 0, 4, 0xee, 0xee, 0xee, 0xee]);
    two.extend_from_slice(&GOLDEN[AT_SEED_NONCE..]);
    assert_eq!(refusal(&two), FormatError::Method { found: 3 });
}

#[test]
fn a_lock_length_past_the_cap_is_refused_before_reading() {
    // The file ends right after the length: had the body been read first, the refusal would be the
    // file's size. A length refusal is what shows the length was judged on its own.
    for found in [102, 0x1000, u16::MAX] {
        let mut image = GOLDEN[..AT_KDF].to_vec();
        image[AT_LENGTH..AT_KDF].copy_from_slice(&found.to_be_bytes());
        assert_eq!(
            refusal(&image),
            FormatError::LockLength {
                method: Method::Passphrase,
                found
            }
        );
    }
    // Short is refused the same way: a passphrase lock has one length.
    let mut image = GOLDEN;
    image[AT_LENGTH..AT_KDF].copy_from_slice(&100_u16.to_be_bytes());
    assert_eq!(
        refusal(&image),
        FormatError::LockLength {
            method: Method::Passphrase,
            found: 100
        }
    );
}

#[test]
fn a_file_of_no_locks_is_not_a_sealed_key() {
    let none = [&GOLDEN[..HEADER_LEN], &[0][..], &GOLDEN[AT_SEED_NONCE..]].concat();
    assert_eq!(refusal(&none), FormatError::NoLocks);
}

#[test]
fn a_file_holds_at_most_one_lock_per_method() {
    let record = &GOLDEN[AT_METHOD..AT_SEED_NONCE];
    let twice = [
        &GOLDEN[..HEADER_LEN],
        &[2][..],
        record,
        record,
        &GOLDEN[AT_SEED_NONCE..],
    ]
    .concat();
    assert_eq!(
        refusal(&twice),
        FormatError::DuplicateLock {
            method: Method::Passphrase
        }
    );
}

fn with_cost(memory_kib: u32, passes: u32, lanes: u32) -> [u8; GOLDEN_LEN] {
    let mut image = GOLDEN;
    image[AT_MEMORY..AT_PASSES].copy_from_slice(&memory_kib.to_be_bytes());
    image[AT_PASSES..AT_LANES].copy_from_slice(&passes.to_be_bytes());
    image[AT_LANES..AT_SALT].copy_from_slice(&lanes.to_be_bytes());
    image
}

#[test]
fn a_cost_outside_the_bounds_is_refused_before_any_key_is_derived() {
    // Refused by the parser, so no `Envelope` exists to derive from: a hostile file costs a read.
    for (memory_kib, passes, lanes) in [
        (u32::MAX, 3, 1),
        (256 * 1024 + 1, 3, 1),
        (19 * 1024 - 1, 3, 1),
        (64 * 1024, u32::MAX, 1),
        (64 * 1024, 11, 1),
        (64 * 1024, 1, 1),
        (64 * 1024, 3, 0),
        (64 * 1024, 3, 9),
    ] {
        assert_eq!(
            refusal(&with_cost(memory_kib, passes, lanes)),
            FormatError::Cost {
                memory_kib,
                passes,
                lanes
            }
        );
    }
}

#[test]
fn the_bounds_are_inclusive_and_hold_both_costs_this_crate_uses() {
    for (memory_kib, passes, lanes) in [(256 * 1024, 10, 8), (19 * 1024, 2, 1)] {
        assert!(matches!(
            parse(&with_cost(memory_kib, passes, lanes), Kind::Standard),
            Ok(Parsed::Sealed(_))
        ));
    }
    assert_eq!(Cost::parse(19 * 1024, 2, 1), Ok(Cost::FLOOR));
    assert_eq!(Cost::parse(64 * 1024, 3, 1), Ok(Cost::DEFAULT));
}

/// A version 2 sealed standard key file with two locks: [`GOLDEN`]'s passphrase lock, then a
/// `touch-id` lock on the software stand-in for the enclave. Every other input is [`GOLDEN`]'s, so
/// the passphrase record is byte for byte the one there; the seed's seal differs, because it covers
/// both records.
///
/// Computed outside this crate from the layout in the module docs alone: P-256 written from SEC 1
/// and checked against `openssl` for public keys and for ECDH, HKDF-SHA256 written from RFC 5869 and
/// checked against its test case and against `openssl kdf HKDF`, and the cipher, Argon2id and the
/// ed25519 key as for [`GOLDEN`]. That same computation reproduces [`GOLDEN`] byte for byte.
///
/// The `touch-id` lock's inputs: the stand-in enclave key's scalar `11 .. 30`, made on stand-in Mac 1,
/// so its blob is `01` then that scalar; the one-time key's scalar `31 .. 50`; the lock's nonce
/// `60 .. 77`; policy 1.
#[rustfmt::skip]
const GOLDEN_TOUCH_ID: [u8; 460] = [
    0x4b, 0x45, 0x59, 0x53, 0x54, 0x4f, 0x52, 0x45, 0x02, 0x01, 0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce,
    0x10, 0xbe, 0x1d, 0x70, 0xdd, 0x18, 0xe7, 0x4b, 0xc0, 0x99, 0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5,
    0x0d, 0x5f, 0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55, 0x31, 0xb8, 0x02, 0x01, 0x00, 0x65, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4,
    0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4,
    0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4,
    0xc5, 0xc6, 0xc7, 0xe5, 0xf7, 0xd0, 0x48, 0x86, 0x4e, 0x47, 0xed, 0xa4, 0xde, 0x19, 0x26, 0xe2,
    0xb5, 0xbd, 0x79, 0xf9, 0x35, 0x36, 0x75, 0xfe, 0xff, 0xfb, 0x76, 0x4a, 0x91, 0x33, 0x06, 0x6c,
    0xea, 0xf9, 0x09, 0x01, 0xf2, 0x7f, 0xc2, 0x64, 0xfb, 0x71, 0x89, 0x90, 0x24, 0x3c, 0x70, 0xa8,
    0xa0, 0x54, 0xaf, 0x02, 0x00, 0xee, 0x01, 0x04, 0x4c, 0x63, 0x36, 0xe3, 0xb8, 0xb3, 0xde, 0x77,
    0x1b, 0x61, 0x3a, 0x1c, 0x7a, 0x17, 0x34, 0x83, 0x4c, 0xd6, 0x9c, 0x1a, 0x4f, 0x5f, 0xfe, 0xcb,
    0x24, 0x0c, 0x63, 0xbc, 0x0d, 0xdb, 0x15, 0x74, 0xf6, 0x89, 0x6c, 0x5d, 0x14, 0xca, 0x44, 0xe0,
    0x03, 0x77, 0x91, 0xc2, 0x30, 0x03, 0x33, 0x25, 0x9a, 0x71, 0xb9, 0x01, 0xe5, 0x25, 0x85, 0x75,
    0xd1, 0x07, 0xe5, 0xb8, 0xac, 0x48, 0xb4, 0x24, 0x00, 0x21, 0x01, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
    0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x04, 0x0c, 0x7f, 0xcc, 0x32,
    0x1c, 0x77, 0x11, 0x92, 0x03, 0xdb, 0xe7, 0x98, 0x64, 0x90, 0x7e, 0x4f, 0x0a, 0x01, 0x91, 0x77,
    0x89, 0xde, 0xa2, 0xd4, 0x73, 0x15, 0x31, 0xa5, 0x2a, 0x22, 0xe2, 0xba, 0xc1, 0x76, 0x6d, 0x21,
    0xe4, 0x61, 0x7d, 0x72, 0xfb, 0xbe, 0xf8, 0x7d, 0x6e, 0xdf, 0x2d, 0x8f, 0x80, 0xb5, 0x26, 0x95,
    0x6e, 0x3c, 0x2c, 0x17, 0x01, 0xf1, 0x6b, 0x7f, 0x31, 0x15, 0x00, 0xc6, 0x60, 0x61, 0x62, 0x63,
    0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73,
    0x74, 0x75, 0x76, 0x77, 0x2b, 0x1c, 0x78, 0x66, 0x27, 0xd5, 0xe3, 0x9a, 0xdb, 0xea, 0x39, 0x14,
    0xfb, 0x13, 0xaf, 0x04, 0x3d, 0xd3, 0xb8, 0x75, 0xde, 0xaf, 0x69, 0x03, 0x21, 0x4b, 0xa9, 0xb3,
    0x15, 0x1c, 0x56, 0xb4, 0x03, 0x22, 0x4f, 0x27, 0x3f, 0x46, 0xb9, 0xf4, 0x4e, 0x3f, 0x82, 0xb5,
    0x8f, 0x41, 0x97, 0xa3, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
    0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x34, 0xd3, 0xd7, 0xcc,
    0xaa, 0x6e, 0xbe, 0x13, 0xac, 0x6d, 0x53, 0xd7, 0x8c, 0xd5, 0xe5, 0xef, 0x7d, 0x3f, 0x91, 0xac,
    0xf1, 0x4d, 0xac, 0x4f, 0xb1, 0x87, 0xfd, 0xaf, 0xf9, 0x2d, 0x82, 0xfc, 0xb6, 0x22, 0x1a, 0xa6,
    0x8a, 0x70, 0xc6, 0x8a, 0x85, 0x08, 0xfe, 0x7c, 0xe4, 0xec, 0x28, 0xf9,
];
/// [`GOLDEN_TOUCH_ID`] with its `touch-id` lock alone, computed the same way.
#[rustfmt::skip]
const GOLDEN_TOUCH_ID_ALONE: [u8; 356] = [
    0x4b, 0x45, 0x59, 0x53, 0x54, 0x4f, 0x52, 0x45, 0x02, 0x01, 0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce,
    0x10, 0xbe, 0x1d, 0x70, 0xdd, 0x18, 0xe7, 0x4b, 0xc0, 0x99, 0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5,
    0x0d, 0x5f, 0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55, 0x31, 0xb8, 0x01, 0x02, 0x00, 0xee, 0x01, 0x04,
    0x4c, 0x63, 0x36, 0xe3, 0xb8, 0xb3, 0xde, 0x77, 0x1b, 0x61, 0x3a, 0x1c, 0x7a, 0x17, 0x34, 0x83,
    0x4c, 0xd6, 0x9c, 0x1a, 0x4f, 0x5f, 0xfe, 0xcb, 0x24, 0x0c, 0x63, 0xbc, 0x0d, 0xdb, 0x15, 0x74,
    0xf6, 0x89, 0x6c, 0x5d, 0x14, 0xca, 0x44, 0xe0, 0x03, 0x77, 0x91, 0xc2, 0x30, 0x03, 0x33, 0x25,
    0x9a, 0x71, 0xb9, 0x01, 0xe5, 0x25, 0x85, 0x75, 0xd1, 0x07, 0xe5, 0xb8, 0xac, 0x48, 0xb4, 0x24,
    0x00, 0x21, 0x01, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
    0x2e, 0x2f, 0x30, 0x04, 0x0c, 0x7f, 0xcc, 0x32, 0x1c, 0x77, 0x11, 0x92, 0x03, 0xdb, 0xe7, 0x98,
    0x64, 0x90, 0x7e, 0x4f, 0x0a, 0x01, 0x91, 0x77, 0x89, 0xde, 0xa2, 0xd4, 0x73, 0x15, 0x31, 0xa5,
    0x2a, 0x22, 0xe2, 0xba, 0xc1, 0x76, 0x6d, 0x21, 0xe4, 0x61, 0x7d, 0x72, 0xfb, 0xbe, 0xf8, 0x7d,
    0x6e, 0xdf, 0x2d, 0x8f, 0x80, 0xb5, 0x26, 0x95, 0x6e, 0x3c, 0x2c, 0x17, 0x01, 0xf1, 0x6b, 0x7f,
    0x31, 0x15, 0x00, 0xc6, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
    0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x2b, 0x1c, 0x78, 0x66,
    0x27, 0xd5, 0xe3, 0x9a, 0xdb, 0xea, 0x39, 0x14, 0xfb, 0x13, 0xaf, 0x04, 0x3d, 0xd3, 0xb8, 0x75,
    0xde, 0xaf, 0x69, 0x03, 0x21, 0x4b, 0xa9, 0xb3, 0x15, 0x1c, 0x56, 0xb4, 0x03, 0x22, 0x4f, 0x27,
    0x3f, 0x46, 0xb9, 0xf4, 0x4e, 0x3f, 0x82, 0xb5, 0x8f, 0x41, 0x97, 0xa3, 0x40, 0x41, 0x42, 0x43,
    0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
    0x54, 0x55, 0x56, 0x57, 0x34, 0xd3, 0xd7, 0xcc, 0xaa, 0x6e, 0xbe, 0x13, 0xac, 0x6d, 0x53, 0xd7,
    0x8c, 0xd5, 0xe5, 0xef, 0x7d, 0x3f, 0x91, 0xac, 0xf1, 0x4d, 0xac, 0x4f, 0xb1, 0x87, 0xfd, 0xaf,
    0xf9, 0x2d, 0x82, 0xfc, 0xc2, 0xce, 0x1b, 0xfd, 0x9d, 0x20, 0x33, 0xcb, 0x8f, 0x73, 0x06, 0x43,
    0x2f, 0x5b, 0x29, 0x39,
];

// [`GOLDEN_TOUCH_ID`]'s offsets, from the layout: the passphrase record sits where it does in
// [`GOLDEN`], and the `touch-id` record follows it, ahead of the seed's nonce.
const AT_TOUCH_ID: usize = AT_SEED_NONCE;
const AT_TOUCH_ID_LENGTH: usize = AT_TOUCH_ID + 1;
const AT_TOUCH_ID_BLOB: usize = AT_TOUCH_ID + 3 + 68;
const AT_TOUCH_ID_ONE_TIME: usize = AT_TOUCH_ID_BLOB + 33;
const AT_TOUCH_ID_NONCE: usize = AT_TOUCH_ID_ONE_TIME + 65;
const AT_TOUCH_ID_WRAPPED: usize = AT_TOUCH_ID_NONCE + 24;
const AT_TOUCH_ID_SEED_NONCE: usize = AT_TOUCH_ID_WRAPPED + 48;

fn golden_enclave_scalar() -> [u8; 32] {
    core::array::from_fn(|at| 0x11 + at as u8)
}

fn golden_one_time_scalar() -> [u8; 32] {
    core::array::from_fn(|at| 0x31 + at as u8)
}

fn golden_touch_id_nonce() -> [u8; 24] {
    core::array::from_fn(|at| 0x60 + at as u8)
}

fn touch() -> Unlock<'static> {
    Unlock::TouchId {
        reason: "open the test key",
        wait: WAIT,
    }
}

/// The golden `touch-id` lock, built by this crate's writer from the golden inputs, wrapping
/// `file_key` for a file whose first bytes are `header`.
fn touch_id_lock(file_key: &FileKey, header: &[u8; HEADER_LEN]) -> Lock {
    let enclave_key = p256::SecretKey::from_slice(&golden_enclave_scalar()).unwrap();
    let one_time = p256::SecretKey::from_slice(&golden_one_time_scalar()).unwrap();
    let (params, kek) = EnclaveParams::enroll_with(
        Policy::BiometryCurrentSet,
        stand_in::blob(1, &golden_enclave_scalar()),
        stand_in::point_of(&enclave_key),
        &one_time,
    )
    .unwrap();
    Lock::wrap_with(
        Params::TouchId(params),
        &kek,
        file_key,
        header,
        golden_touch_id_nonce(),
    )
    .unwrap()
}

/// A file of `kind` built by this crate's writer, holding `locks` in order, each made by its
/// builder from the golden inputs.
fn build_with(kind: Kind, locks: &[fn(&FileKey, &[u8; HEADER_LEN]) -> Lock]) -> Vec<u8> {
    let secret = Secret::copy_of(&golden_seed());
    let file_key = FileKey::copy_of(&golden_file_key());
    let header = header(kind, secret.public_key());
    let locks: Vec<Lock> = locks.iter().map(|lock| lock(&file_key, &header)).collect();
    let locks: Vec<&Lock> = locks.iter().collect();
    assemble(&header, &locks, &file_key, &secret, &golden_seed_nonce()).unwrap()
}

fn golden_passphrase_lock(file_key: &FileKey, header: &[u8; HEADER_LEN]) -> Lock {
    passphrase_lock(
        &golden_passphrase(),
        file_key,
        header,
        golden_cost(),
        golden_salt(),
    )
}

fn floor_passphrase_lock(file_key: &FileKey, header: &[u8; HEADER_LEN]) -> Lock {
    passphrase_lock(
        &golden_passphrase(),
        file_key,
        header,
        Cost::FLOOR,
        golden_salt(),
    )
}

#[test]
fn the_touch_id_golden_vector_opens_to_its_seed_through_either_lock() {
    let envelope = sealed(&GOLDEN_TOUCH_ID);
    assert_eq!(
        envelope.methods().collect::<Vec<_>>(),
        [Method::Passphrase, Method::TouchId]
    );
    for opened in [
        envelope.unlock(touch()).unwrap(),
        open(&envelope, &golden_passphrase()).unwrap(),
    ] {
        opened
            .secret
            .with_bytes(|seed| assert_eq!(seed, &golden_seed()));
        assert_eq!(opened.file_key.bytes(), &golden_file_key());
    }
    assert_eq!(stand_in::touches(), 1);
}

#[test]
fn this_build_writes_the_touch_id_golden_vectors_byte_for_byte() {
    assert_eq!(
        build_with(Kind::Standard, &[golden_passphrase_lock, touch_id_lock]),
        GOLDEN_TOUCH_ID
    );
    assert_eq!(
        build_with(Kind::Standard, &[touch_id_lock]),
        GOLDEN_TOUCH_ID_ALONE
    );
    // The layout's offsets, read off the golden file.
    assert_eq!(GOLDEN_TOUCH_ID[AT_TOUCH_ID], 2);
    assert_eq!(
        GOLDEN_TOUCH_ID[AT_TOUCH_ID_LENGTH..AT_TOUCH_ID_LENGTH + 2],
        [0, 238]
    );
    assert_eq!(GOLDEN_TOUCH_ID[AT_TOUCH_ID_BLOB], 1);
    assert_eq!(GOLDEN_TOUCH_ID[AT_TOUCH_ID_ONE_TIME], 0x04);
    assert_eq!(
        GOLDEN_TOUCH_ID[AT_TOUCH_ID_NONCE..AT_TOUCH_ID_WRAPPED],
        golden_touch_id_nonce()
    );
    assert_eq!(
        GOLDEN_TOUCH_ID[AT_TOUCH_ID_SEED_NONCE..AT_TOUCH_ID_SEED_NONCE + 24],
        golden_seed_nonce()
    );
}

#[test]
fn a_touch_id_key_file_alone_opens_nothing() {
    let envelope = sealed(&GOLDEN_TOUCH_ID_ALONE);
    // No passphrase opens it: there is no lock for one.
    assert!(matches!(
        open(&envelope, &golden_passphrase()),
        Err(Refusal::NoLock(Method::Passphrase))
    ));
    // A touch that is cancelled opens nothing, and nothing stands in for it.
    stand_in::touch(Touch::Cancelled);
    assert!(matches!(
        envelope.unlock(touch()),
        Err(Refusal::TouchId(TouchIdError::Declined(_)))
    ));
    // Nor does any touch on another Mac, which is never even asked for.
    stand_in::touch(Touch::Matches);
    stand_in::on_mac(2);
    assert!(matches!(
        envelope.unlock(touch()),
        Err(Refusal::TouchId(TouchIdError::NotHere(_)))
    ));
    assert_eq!(stand_in::touches(), 1);
    // Only a matching touch on the Mac that made it opens it.
    stand_in::on_mac(1);
    assert!(envelope.unlock(touch()).is_ok());
}

#[test]
fn reordering_two_locks_fails_the_whole_file() {
    let image = build_with(Kind::Standard, &[floor_passphrase_lock, touch_id_lock]);
    let envelope = sealed(&image);
    assert!(envelope.unlock(touch()).is_ok());
    assert!(open(&envelope, &golden_passphrase()).is_ok());

    // The same two records, the other way round: each is a good lock, the list is a good list, and
    // the file opens through neither, because the seed's seal covers the locks in their order.
    let at_seed_nonce = image.len() - NONCE_LEN_AND_SEAL;
    let passphrase_end = AT_METHOD + 3 + 101;
    let reordered = [
        &image[..AT_METHOD],
        &image[passphrase_end..at_seed_nonce],
        &image[AT_METHOD..passphrase_end],
        &image[at_seed_nonce..],
    ]
    .concat();
    let envelope = sealed(&reordered);
    assert_eq!(
        envelope.methods().collect::<Vec<_>>(),
        [Method::TouchId, Method::Passphrase]
    );
    assert!(matches!(envelope.unlock(touch()), Err(Refusal::Unlock(_))));
    assert!(matches!(
        open(&envelope, &golden_passphrase()),
        Err(Refusal::Unlock(_))
    ));
}

/// The seed's nonce and its seal, which end every sealed file.
const NONCE_LEN_AND_SEAL: usize = 24 + 48;

#[test]
fn any_edit_to_a_touch_id_lock_fails_the_whole_file() {
    let image = build_with(Kind::Standard, &[floor_passphrase_lock, touch_id_lock]);
    // Every byte of the record: refused as it is read, or the touch does not open it.
    for at in AT_TOUCH_ID..image.len() - NONCE_LEN_AND_SEAL {
        let mut edited = image.clone();
        edited[at] ^= 0x01;
        let Ok(Parsed::Sealed(envelope)) = parse(&edited, Kind::Standard) else {
            continue;
        };
        assert!(
            envelope.unlock(touch()).is_err(),
            "an edit at byte {at} of the touch-id lock opened"
        );
    }
    // And the passphrase, which the edit did not touch, does not open the file either: the seed's
    // seal covers the other lock too.
    for at in [
        AT_TOUCH_ID_BLOB + 5,
        AT_TOUCH_ID_ONE_TIME + 9,
        AT_TOUCH_ID_WRAPPED + 3,
    ] {
        let mut edited = image.clone();
        edited[at] ^= 0x01;
        assert!(
            matches!(
                open(&sealed(&edited), &golden_passphrase()),
                Err(Refusal::Unlock(_))
            ),
            "an edit at byte {at} left the passphrase opening the file"
        );
    }
}

#[test]
fn a_sealed_only_key_without_a_passphrase_lock_is_refused() {
    assert_eq!(
        refusal_as(&build_with(Kind::Sealed, &[touch_id_lock]), Kind::Sealed),
        FormatError::NoPortableLock
    );
    // With its passphrase lock beside it, in either place, the same key reads.
    for locks in [
        [
            floor_passphrase_lock as fn(&FileKey, &[u8; HEADER_LEN]) -> Lock,
            touch_id_lock,
        ],
        [touch_id_lock, floor_passphrase_lock],
    ] {
        sealed_as(&build_with(Kind::Sealed, &locks), Kind::Sealed);
    }
    // A standard key keeps no such rule: this machine's key may hold the touch alone.
    sealed(&GOLDEN_TOUCH_ID_ALONE);
}

#[test]
fn a_touch_id_lock_length_past_the_cap_is_refused_before_reading() {
    // 1229 is the longest a touch-id body can be: a blob of 1024 bytes. The file ends right after the
    // length, so a refusal by length shows the length was judged before any body was read.
    for found in [1230, 0x1000, u16::MAX, 0, 205] {
        let mut image = GOLDEN_TOUCH_ID[..AT_TOUCH_ID_LENGTH + 2].to_vec();
        image[HEADER_LEN] = 2;
        image[AT_TOUCH_ID_LENGTH..].copy_from_slice(&found.to_be_bytes());
        assert_eq!(
            refusal(&image),
            FormatError::LockLength {
                method: Method::TouchId,
                found
            }
        );
    }
}
