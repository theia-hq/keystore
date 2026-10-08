use core::time::Duration;
use std::fs;

use zeroize::Zeroizing;

use super::{KeyFile, Proof, lacks_hard_links};
use crate::envelope::{AT_PUBLIC, Envelope, HEADER_LEN};
use crate::error::{Error, FormatError, TouchIdError};
use crate::kind::Kind;
use crate::lock::enclave::enclave_tests::{self as stand_in, Touch, WAIT};
use crate::method::{Method, NewLock, Protection, Unlock};
use crate::passphrase::Passphrase;
use crate::secret::Secret;
use crate::stored::{Health, Stored};
use crate::test_dir::TestDir;

/// The length of a sealed file with one passphrase lock.
const SEALED_LEN: usize = 219;

fn passphrase(text: &str) -> Passphrase {
    Passphrase::new(Zeroizing::new(text.as_bytes().to_vec())).unwrap()
}

fn with(passphrase: &Passphrase) -> Unlock<'_> {
    Unlock::Passphrase(passphrase)
}

fn lock(passphrase: &Passphrase) -> NewLock<'_> {
    NewLock::Passphrase(passphrase)
}

fn key_file(dir: &TestDir) -> KeyFile {
    KeyFile::device(dir.join("identity.key"))
}

fn plain_file(dir: &TestDir, seed: [u8; 32]) -> (KeyFile, Secret) {
    let file = key_file(dir);
    let secret = Secret::copy_of(&seed);
    file.write(&secret, Protection::Plain).unwrap();
    (file, secret)
}

fn sealed_file(dir: &TestDir, seed: [u8; 32], under: &Passphrase) -> (KeyFile, Secret) {
    let file = key_file(dir);
    let secret = Secret::copy_of(&seed);
    file.write(&secret, Protection::Passphrase(under)).unwrap();
    (file, secret)
}

/// Put `content` at the key path the way a key file sits, owner-only, so the test reaches the check
/// it is about rather than the mode guard.
fn plant(file: &KeyFile, content: &[u8]) {
    fs::write(file.path(), content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn bytes(file: &KeyFile) -> Vec<u8> {
    fs::read(file.path()).unwrap()
}

fn locked(file: &KeyFile) -> crate::stored::Locked {
    match file.load().unwrap() {
        Some(Stored::Locked(locked)) => locked,
        other => panic!("expected a locked file, found {other:?}"),
    }
}

fn plain(file: &KeyFile) -> Secret {
    match file.load().unwrap() {
        Some(Stored::Plain(secret)) => secret,
        other => panic!("expected a plain file, found {other:?}"),
    }
}

#[test]
fn nothing_at_the_path_loads_as_none() {
    let dir = TestDir::new();
    assert!(key_file(&dir).load().unwrap().is_none());
}

#[test]
fn a_plain_write_reads_back_as_the_same_key() {
    let dir = TestDir::new();
    let (file, secret) = plain_file(&dir, [1; 32]);
    assert_eq!(bytes(&file), [1; 32]);
    let stored = file.load().unwrap().unwrap();
    assert!(matches!(stored, Stored::Plain(_)));
    assert_eq!(stored.public_key(), secret.public_key());
    assert_eq!(dir.names(), ["identity.key"]);
}

#[test]
fn a_sealed_write_names_its_key_locked_and_opens_to_the_same_key() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, secret) = sealed_file(&dir, [2; 32], &under);
    assert_eq!(bytes(&file).len(), SEALED_LEN);
    let locked = locked(&file);
    assert_eq!(locked.methods().collect::<Vec<_>>(), [Method::Passphrase]);
    assert_eq!(locked.public_key(), secret.public_key());
    assert_eq!(
        locked.unlock(with(&under)).unwrap().public_key(),
        secret.public_key()
    );
    assert_eq!(dir.names(), ["identity.key"]);
}

#[test]
fn a_sealed_file_opens_with_the_keystore_signature() {
    let dir = TestDir::new();
    let (file, _) = sealed_file(&dir, [4; 32], &passphrase("correct horse"));
    assert_eq!(&bytes(&file)[..8], b"KEYSTORE");
}

#[cfg(unix)]
#[test]
fn a_written_key_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TestDir::new();
    let (file, _) = plain_file(&dir, [1; 32]);
    let mode = fs::metadata(file.path()).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn a_write_never_lands_over_an_existing_file() {
    let dir = TestDir::new();
    let (file, secret) = plain_file(&dir, [1; 32]);
    let before = bytes(&file);
    // Not even the same key, and not under another method.
    for protection in [Protection::Plain, Protection::Passphrase(&passphrase("x"))] {
        assert!(matches!(
            file.write(&secret, protection),
            Err(Error::Occupied { .. })
        ));
        assert_eq!(bytes(&file), before);
    }
    assert_eq!(dir.names(), ["identity.key"]);
}

#[test]
fn a_wrong_passphrase_and_a_damaged_file_read_the_same() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, _) = sealed_file(&dir, [2; 32], &under);
    let original = bytes(&file);

    let wrong = locked(&file)
        .unlock(with(&passphrase("wrong")))
        .unwrap_err();
    assert_eq!(bytes(&file), original);

    let mut damaged = original.clone();
    damaged[SEALED_LEN - 1] ^= 0x01;
    plant(&file, &damaged);
    let corrupt = locked(&file).unlock(with(&under)).unwrap_err();

    assert!(matches!(wrong, Error::Unlock { .. }));
    assert!(matches!(corrupt, Error::Unlock { .. }));
    assert_eq!(wrong.to_string(), corrupt.to_string());
}

#[test]
fn a_malformed_file_is_refused_by_name_and_left_alone() {
    let dir = TestDir::new();
    let file = key_file(&dir);
    for (content, expected) in [
        (vec![1; 31], FormatError::Size { found: 31 }),
        (vec![1; 33], FormatError::Size { found: 33 }),
        // A sealed file cut to the plain length: refused as sealed, never read as a seed.
        (
            [&b"KEYSTORE"[..], &[2; 24]].concat(),
            FormatError::SealedSize { found: 32 },
        ),
    ] {
        plant(&file, &content);
        match file.load() {
            Err(Error::Format { source, .. }) => assert_eq!(source, expected),
            other => panic!("expected a format refusal, got {other:?}"),
        }
        assert_eq!(bytes(&file), content);
    }
}

#[test]
fn a_file_past_the_read_cap_is_refused_on_its_size_without_being_read() {
    let dir = TestDir::new();
    let file = key_file(&dir);
    // It opens with a sealed file's signature and version, so had it been read the parser would call
    // it a damaged sealed file; a plain size refusal is what shows it was judged on its length alone.
    // Modest on purpose: if the cap regresses, this test must fail, not make the loader read
    // gigabytes.
    let content = [&b"KEYSTORE"[..], &[2], &vec![0; 64 * 1024]].concat();
    plant(&file, &content);
    match file.load() {
        Err(Error::Format { source, .. }) => {
            assert_eq!(
                source,
                FormatError::Size {
                    found: content.len() as u64
                }
            );
        }
        other => panic!("expected a size refusal, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn a_file_group_or_other_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TestDir::new();
    let (file, _) = plain_file(&dir, [1; 32]);
    for mode in [0o640, 0o604, 0o660] {
        fs::set_permissions(file.path(), fs::Permissions::from_mode(mode)).unwrap();
        assert!(matches!(
            file.load(),
            Err(Error::Permissive { mode: found, .. }) if found == mode
        ));
    }
}

#[cfg(unix)]
#[test]
fn a_file_owned_by_another_user_is_refused_and_one_owned_by_root_is_not() {
    use std::os::unix::fs::MetadataExt as _;

    let dir = TestDir::new();
    let (file, _) = plain_file(&dir, [1; 32]);
    if fs::metadata(file.path()).unwrap().uid() == 0 {
        // Run as root, every file here is root's, which the check allows: give this one to uid 1.
        std::os::unix::fs::chown(file.path(), Some(1), None).unwrap();
    }
    let metadata = fs::metadata(file.path()).unwrap();
    let owner = metadata.uid();
    // The same owner-only file, judged as if this process ran as someone else.
    let stranger = owner.wrapping_add(1).max(1);
    assert!(file.guard_access(&metadata, owner).is_ok());
    match file.guard_access(&metadata, stranger) {
        Err(Error::Owner { owner: found, .. }) => assert_eq!(found, owner),
        other => panic!("expected an owner refusal, got {other:?}"),
    }
    // A file root owns is accepted by whoever loads it; `/` is one every unix has.
    let root_owned = fs::metadata("/").unwrap();
    assert_eq!(root_owned.uid(), 0);
    assert!(!matches!(
        file.guard_access(&root_owned, stranger),
        Err(Error::Owner { .. })
    ));
}

#[test]
fn a_directory_at_the_path_is_not_a_key_file() {
    let dir = TestDir::new();
    let file = key_file(&dir);
    fs::create_dir(file.path()).unwrap();
    assert!(matches!(file.load(), Err(Error::NotAFile { .. })));
}

#[cfg(unix)]
#[test]
fn a_pipe_at_the_path_is_refused_without_blocking() {
    use core::time::Duration;
    use std::sync::mpsc;

    let dir = TestDir::new();
    let file = key_file(&dir);
    let made = std::process::Command::new("mkfifo")
        .arg(file.path())
        .status()
        .unwrap();
    assert!(made.success());
    // On a thread with a deadline: a loader that opens the pipe blocks until a writer appears, and
    // this test must fail rather than hang when that happens.
    let (done, outcome) = mpsc::channel();
    std::thread::spawn(move || {
        let refused = matches!(file.load(), Err(Error::NotAFile { .. }));
        let _ = done.send(refused);
    });
    match outcome.recv_timeout(Duration::from_secs(10)) {
        Ok(refused) => assert!(
            refused,
            "a pipe at the key path was not refused as not a file"
        ),
        Err(_) => panic!("the load blocked on a pipe at the key path instead of refusing it"),
    }
}

#[test]
fn adopting_the_key_already_held_changes_nothing() {
    let dir = TestDir::new();
    let (file, secret) = plain_file(&dir, [2; 32]);
    let under = passphrase("correct horse battery staple");
    // Offered sealed, the plain file stays plain: adopting never changes a method.
    file.adopt(&secret, Protection::Passphrase(&under)).unwrap();
    assert_eq!(bytes(&file), [2; 32]);
}

#[test]
fn adopting_over_a_sealed_file_proves_its_claim_by_unlocking_it() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, secret) = sealed_file(&dir, [2; 32], &under);
    let before = bytes(&file);
    file.adopt(&secret, Protection::Passphrase(&under)).unwrap();
    // With no passphrase, the header's claim is all there is, and a claim is not enough.
    match file.adopt(&secret, Protection::Plain) {
        Err(Error::Unconfirmed { claimed, .. }) => assert_eq!(claimed, secret.public_key()),
        other => panic!("expected the claim to go unconfirmed, got {other:?}"),
    }
    assert_eq!(bytes(&file), before);
}

#[test]
fn a_sealed_file_claiming_the_adopted_key_is_not_taken_at_its_word() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, _) = sealed_file(&dir, [2; 32], &under);
    // Rewrite the header to claim another key: the file loads as that key, and seals a key that
    // is not it.
    let claimed = Secret::copy_of(&[3; 32]);
    let mut forged = bytes(&file);
    forged[AT_PUBLIC..HEADER_LEN].copy_from_slice(claimed.public_key().bytes());
    plant(&file, &forged);
    assert_eq!(locked(&file).public_key(), claimed.public_key());

    assert!(matches!(
        file.adopt(&claimed, Protection::Passphrase(&under)),
        Err(Error::Unlock { .. })
    ));
    assert!(matches!(
        file.adopt(&claimed, Protection::Plain),
        Err(Error::Unconfirmed { .. })
    ));
    assert_eq!(bytes(&file), forged);
}

#[test]
fn adopting_over_a_different_key_is_refused_and_leaves_it() {
    let dir = TestDir::new();
    let (file, held) = plain_file(&dir, [1; 32]);
    let incoming = Secret::copy_of(&[9; 32]);
    match file.adopt(&incoming, Protection::Plain) {
        Err(Error::Different {
            existing,
            incoming: offered,
            ..
        }) => {
            assert_eq!(existing, held.public_key());
            assert_eq!(offered, incoming.public_key());
        }
        other => panic!("expected a refusal naming both keys, got {other:?}"),
    }
    assert_eq!(bytes(&file), [1; 32]);
}

#[test]
fn adopting_into_absence_writes_the_key() {
    let dir = TestDir::new();
    let file = key_file(&dir);
    let secret = Secret::copy_of(&[4; 32]);
    file.adopt(&secret, Protection::Plain).unwrap();
    assert_eq!(plain(&file).public_key(), secret.public_key());
}

#[test]
fn adopting_over_an_unreadable_file_refuses_rather_than_replacing_it() {
    let dir = TestDir::new();
    let file = key_file(&dir);
    plant(&file, &[1; 31]);
    assert!(matches!(
        file.adopt(&Secret::copy_of(&[4; 32]), Protection::Plain),
        Err(Error::Format { .. })
    ));
    assert_eq!(bytes(&file), [1; 31]);
}

#[test]
fn a_plain_key_takes_a_passphrase_lock_and_gives_it_back_as_the_same_key() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, secret) = plain_file(&dir, [6; 32]);

    file.add_lock(None, lock(&under)).unwrap();
    let locked = locked(&file);
    assert_eq!(locked.public_key(), secret.public_key());
    assert_eq!(locked.methods().collect::<Vec<_>>(), [Method::Passphrase]);
    assert_eq!(
        locked.unlock(with(&under)).unwrap().public_key(),
        secret.public_key()
    );

    file.remove_lock(with(&under), Method::Passphrase).unwrap();
    assert_eq!(bytes(&file), [6; 32]);
    assert_eq!(dir.names(), ["identity.key"]);
}

#[test]
fn a_second_lock_of_one_method_replaces_it() {
    let dir = TestDir::new();
    let (old, new) = (passphrase("old"), passphrase("new"));
    let (file, secret) = sealed_file(&dir, [6; 32], &old);
    let before = bytes(&file);
    let file_key = *locked(&file).open(with(&old)).unwrap().file_key().bytes();

    file.add_lock(Some(with(&old)), lock(&new)).unwrap();
    let after = bytes(&file);
    // Still one lock, in the same place: the list does not grow by a method it already holds.
    assert_eq!(after.len(), before.len());
    let locked = locked(&file);
    assert_eq!(locked.methods().collect::<Vec<_>>(), [Method::Passphrase]);
    assert!(matches!(
        locked.unlock(with(&old)),
        Err(Error::Unlock { .. })
    ));
    let opened = locked.open(with(&new)).unwrap();
    assert_eq!(opened.secret.public_key(), secret.public_key());
    // The file key is the file's for life: the new lock wraps the same one.
    assert_eq!(opened.file_key().bytes(), &file_key);
    // The lock's salt and nonce, and the seed's nonce, are drawn afresh: none is reused.
    for (field, range) in [
        ("salt", 59..75),
        ("lock nonce", 75..99),
        ("seed nonce", 147..171),
    ] {
        assert_ne!(
            before[range.clone()],
            after[range],
            "the {field} was reused"
        );
    }
}

#[test]
fn removing_a_device_keys_last_lock_writes_it_plain() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, secret) = sealed_file(&dir, [6; 32], &under);

    file.remove_lock(with(&under), Method::Passphrase).unwrap();
    assert_eq!(bytes(&file), [6; 32]);
    assert_eq!(plain(&file).public_key(), secret.public_key());
    assert_eq!(dir.names(), ["identity.key"]);
}

#[test]
fn a_lock_change_that_cannot_unlock_leaves_the_file_as_it_was() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let new = passphrase("a new passphrase for it");
    let (file, _) = sealed_file(&dir, [6; 32], &under);
    let before = bytes(&file);

    let wrong = passphrase("wrong");
    assert!(matches!(
        file.remove_lock(with(&wrong), Method::Passphrase),
        Err(Error::Unlock { .. })
    ));
    assert!(matches!(
        file.add_lock(Some(with(&wrong)), lock(&new)),
        Err(Error::Unlock { .. })
    ));
    // A sealed file opens only through one of its own locks.
    assert!(matches!(
        file.add_lock(None, lock(&new)),
        Err(Error::Sealed { .. })
    ));
    assert_eq!(bytes(&file), before);
    assert_eq!(dir.names(), ["identity.key"]);
}

#[test]
fn a_plain_file_has_no_lock_to_open_or_remove() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, _) = plain_file(&dir, [6; 32]);

    assert!(matches!(
        file.remove_lock(with(&under), Method::Passphrase),
        Err(Error::NoLock {
            method: Method::Passphrase,
            ..
        })
    ));
    assert!(matches!(
        file.add_lock(Some(with(&under)), lock(&under)),
        Err(Error::NoLock {
            method: Method::Passphrase,
            ..
        })
    ));
    assert_eq!(bytes(&file), [6; 32]);
    assert_eq!(dir.names(), ["identity.key"]);
}

#[test]
fn changing_the_locks_of_nothing_is_refused() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    assert!(matches!(
        key_file(&dir).add_lock(None, lock(&under)),
        Err(Error::Absent { .. })
    ));
    assert!(matches!(
        key_file(&dir).remove_lock(with(&under), Method::Passphrase),
        Err(Error::Absent { .. })
    ));
    assert!(dir.names().is_empty());
}

#[test]
fn an_interrupted_lock_change_leaves_the_original_readable() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, secret) = plain_file(&dir, [6; 32]);

    // Run the change up to the rename and stop there, as a crash would: the new form is staged and
    // proven, and the process dies before publishing it. `forget` stands in for the death, so no
    // cleanup runs either.
    let (Stored::Plain(unlocked), _) = file.load_present().unwrap() else {
        panic!("the file was not plain");
    };
    let image = file.seal(&unlocked, lock(&under)).unwrap();
    let staged = file.stage(&image).unwrap();
    staged
        .verify(Proof::Lock(with(&under)), secret.public_key())
        .unwrap();
    core::mem::forget(staged);

    assert_eq!(bytes(&file), [6; 32]);
    assert_eq!(plain(&file).public_key(), secret.public_key());
    // The orphaned stage is a sibling, and it does not stop the change from being run again.
    assert_eq!(dir.names().len(), 2);
    file.add_lock(None, lock(&under)).unwrap();
    assert_eq!(
        locked(&file).unlock(with(&under)).unwrap().public_key(),
        secret.public_key()
    );
    // And the rerun swept the orphan.
    assert_eq!(dir.names(), ["identity.key"]);
}

#[test]
fn a_write_sweeps_only_what_has_the_exact_shape_of_a_stage() {
    let dir = TestDir::new();
    let file = key_file(&dir);
    let orphan = "identity.key.tmp.4242.0123456789abcdef";
    let kept = [
        "identity.key.tmp.notes",
        "identity.key.tmp.4242.0123456789abcde",
        "identity.key.tmp..0123456789abcdef",
        "other.key.tmp.4242.0123456789abcdef",
    ];
    for name in kept.iter().chain([&orphan]) {
        fs::write(dir.join(name), [5; 32]).unwrap();
    }
    file.write(&Secret::copy_of(&[1; 32]), Protection::Plain)
        .unwrap();
    let mut expected = kept.to_vec();
    expected.push("identity.key");
    expected.sort_unstable();
    assert_eq!(dir.names(), expected);
}

#[cfg(unix)]
#[test]
fn the_sweep_leaves_a_link_under_a_stage_name_and_what_it_points_at() {
    let dir = TestDir::new();
    let file = key_file(&dir);
    let precious = dir.join("precious");
    fs::write(&precious, [5; 32]).unwrap();
    let link = dir.join("identity.key.tmp.4242.0123456789abcdef");
    std::os::unix::fs::symlink(&precious, &link).unwrap();
    file.write(&Secret::copy_of(&[1; 32]), Protection::Plain)
        .unwrap();
    assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(fs::read(&precious).unwrap(), [5; 32]);
}

#[test]
fn a_lock_change_never_writes_over_a_file_replaced_since_it_read_it() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, secret) = plain_file(&dir, [6; 32]);

    // Steps 1 and 2 of a lock change, then a restore lands a different key in the window before the
    // rename, the way a second process would.
    let (Stored::Plain(unlocked), seen) = file.load_present().unwrap() else {
        panic!("the file was not plain");
    };
    let image = file.seal(&unlocked, lock(&under)).unwrap();
    let restored = dir.join("restored");
    fs::write(&restored, [7; 32]).unwrap();
    fs::rename(&restored, file.path()).unwrap();

    assert!(matches!(
        file.replace(
            &image,
            Proof::Lock(with(&under)),
            secret.public_key(),
            &seen
        ),
        Err(Error::Changed { .. })
    ));
    assert_eq!(bytes(&file), [7; 32]);
    assert_eq!(dir.names(), ["identity.key"]);
}

#[test]
fn a_lock_change_never_writes_over_a_file_changed_in_place_since_it_read_it() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, secret) = plain_file(&dir, [6; 32]);
    let (Stored::Plain(unlocked), seen) = file.load_present().unwrap() else {
        panic!("the file was not plain");
    };
    let image = file.seal(&unlocked, lock(&under)).unwrap();
    // Same file, same length, new contents.
    fs::write(file.path(), [7; 32]).unwrap();

    assert!(matches!(
        file.replace(
            &image,
            Proof::Lock(with(&under)),
            secret.public_key(),
            &seen
        ),
        Err(Error::Changed { .. })
    ));
    assert_eq!(bytes(&file), [7; 32]);
}

#[test]
fn a_new_form_that_does_not_read_back_never_replaces_the_original() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, secret) = plain_file(&dir, [6; 32]);
    let (_, seen) = file.load_present().unwrap();

    // A well-formed sealed file, but locked under a passphrase other than the one the change is
    // adding: the stage is written, the test-unlock fails, and the rename must not happen.
    let other_passphrase = passphrase("something else");
    let wrong = Envelope::seal(&secret, Kind::Device, lock(&other_passphrase)).unwrap();
    assert!(matches!(
        file.replace(
            &wrong,
            Proof::Lock(with(&under)),
            secret.public_key(),
            &seen
        ),
        Err(Error::Unverified { .. })
    ));
    // And a form that opens, but to another key.
    let other = Secret::copy_of(&[8; 32]);
    let elsewhere = Envelope::seal(&other, Kind::Device, lock(&under)).unwrap();
    assert!(matches!(
        file.replace(
            &elsewhere,
            Proof::Lock(with(&under)),
            secret.public_key(),
            &seen
        ),
        Err(Error::Unverified { .. })
    ));

    assert_eq!(bytes(&file), [6; 32]);
    assert_eq!(dir.names(), ["identity.key"]);
}

#[cfg(unix)]
#[test]
fn a_lock_change_that_cannot_stage_leaves_the_original_readable() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, secret) = plain_file(&dir, [6; 32]);
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();

    let outcome = file.add_lock(None, lock(&under));

    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(outcome, Err(Error::Io { .. })));
    assert_eq!(plain(&file).public_key(), secret.public_key());
    assert_eq!(dir.names(), ["identity.key"]);
}

#[cfg(unix)]
#[test]
fn a_lock_change_through_a_link_rewrites_the_file_the_link_names() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    // The key is kept in a managed directory and linked into place, as a dotfile manager lays it out.
    let kept_dir = dir.join("dotfiles");
    fs::create_dir(&kept_dir).unwrap();
    let kept = KeyFile::device(kept_dir.join("identity.key"));
    let secret = Secret::copy_of(&[6; 32]);
    kept.write(&secret, Protection::Plain).unwrap();
    let file = key_file(&dir);
    std::os::unix::fs::symlink(kept.path(), file.path()).unwrap();

    file.add_lock(None, lock(&under)).unwrap();

    // The link is still a link, and the file it names is the sealed one: no plain seed is left
    // anywhere, in either directory.
    assert!(
        file.path()
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(bytes(&kept).len(), SEALED_LEN);
    assert_eq!(
        locked(&file).unlock(with(&under)).unwrap().public_key(),
        secret.public_key()
    );
    assert_eq!(dir.names(), ["dotfiles", "identity.key"]);
    assert_eq!(fs::read_dir(&kept_dir).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn a_write_never_lands_through_a_link_even_one_that_points_nowhere() {
    let dir = TestDir::new();
    let file = key_file(&dir);
    let nowhere = dir.join("nowhere.key");
    std::os::unix::fs::symlink(&nowhere, file.path()).unwrap();
    assert!(matches!(
        file.write(&Secret::copy_of(&[1; 32]), Protection::Plain),
        Err(Error::Occupied { .. })
    ));
    assert!(!nowhere.exists());
}

#[test]
fn a_new_key_that_does_not_read_back_is_never_published() {
    let dir = TestDir::new();
    let file = key_file(&dir);
    let under = passphrase("correct horse battery staple");
    let secret = Secret::copy_of(&[6; 32]);
    // Sealed under another passphrase than the one the write is for: the stage is written, its
    // test-unlock fails, and nothing may appear at the path.
    let other_passphrase = passphrase("something else");
    let wrong = Envelope::seal(&secret, Kind::Device, lock(&other_passphrase)).unwrap();
    assert!(matches!(
        file.create(&wrong, Proof::Lock(with(&under)), secret.public_key()),
        Err(Error::Unverified { .. })
    ));
    assert!(dir.names().is_empty());
}

fn root_file(dir: &TestDir) -> KeyFile {
    KeyFile::root(dir.join("root.key"))
}

/// The same path, named as the other kind.
fn as_device(file: &KeyFile) -> KeyFile {
    KeyFile::device(file.path())
}

fn wrong_kind(outcome: Result<Option<Stored>, Error>) -> (Kind, Kind) {
    match outcome {
        Err(Error::Format {
            source: FormatError::WrongKind { expected, found },
            ..
        }) => (expected, found),
        other => panic!("expected a refusal by kind, found {other:?}"),
    }
}

#[test]
fn a_root_key_is_written_sealed_as_the_root_kind() {
    let dir = TestDir::new();
    let file = root_file(&dir);
    let under = passphrase("correct horse battery staple");
    let secret = Secret::copy_of(&[4; 32]);
    file.write(&secret, Protection::Passphrase(&under)).unwrap();

    assert_eq!(file.kind(), Kind::Root);
    assert_eq!(bytes(&file).len(), SEALED_LEN);
    assert_eq!(
        locked(&file).unlock(with(&under)).unwrap().public_key(),
        secret.public_key()
    );
    assert_eq!(
        wrong_kind(as_device(&file).load()),
        (Kind::Device, Kind::Root)
    );
}

#[test]
fn a_device_key_file_in_the_root_slot_is_refused_by_kind() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (device, secret) = sealed_file(&dir, [4; 32], &under);
    let root = KeyFile::root(device.path());
    let before = bytes(&device);

    assert_eq!(wrong_kind(root.load()), (Kind::Root, Kind::Device));
    // Every other door refuses it for the same reason, and none of them changes it.
    assert!(matches!(
        root.adopt(&secret, Protection::Passphrase(&under)),
        Err(Error::Format {
            source: FormatError::WrongKind { .. },
            ..
        })
    ));
    let new = passphrase("a new passphrase for it");
    assert!(matches!(
        root.add_lock(Some(with(&under)), lock(&new)),
        Err(Error::Format {
            source: FormatError::WrongKind { .. },
            ..
        })
    ));
    assert_eq!(bytes(&device), before);
}

#[test]
fn a_plain_file_in_the_root_slot_loads_as_plain() {
    // A plain file carries no kind to refuse it by: it loads, and the caller decides what to do with
    // a root key it finds unsealed.
    let dir = TestDir::new();
    let (device, secret) = plain_file(&dir, [4; 32]);
    let root = KeyFile::root(device.path());
    assert_eq!(plain(&root).public_key(), secret.public_key());
}

#[test]
fn a_root_key_is_never_written_plain() {
    let dir = TestDir::new();
    let file = root_file(&dir);
    let secret = Secret::copy_of(&[4; 32]);

    assert!(matches!(
        file.write(&secret, Protection::Plain),
        Err(Error::PlainRoot { .. })
    ));
    assert!(matches!(
        file.adopt(&secret, Protection::Plain),
        Err(Error::PlainRoot { .. })
    ));
    assert!(dir.names().is_empty());
}

#[test]
fn a_roots_passphrase_lock_cannot_be_removed() {
    let dir = TestDir::new();
    let file = root_file(&dir);
    let under = passphrase("correct horse battery staple");
    let secret = Secret::copy_of(&[4; 32]);
    file.write(&secret, Protection::Passphrase(&under)).unwrap();
    let sealed = bytes(&file);

    assert!(matches!(
        file.remove_lock(with(&under), Method::Passphrase),
        Err(Error::RootPassphrase { .. })
    ));
    // Refused before anything is read: not even a wrong passphrase gets as far as an unlock.
    assert!(matches!(
        file.remove_lock(with(&passphrase("wrong")), Method::Passphrase),
        Err(Error::RootPassphrase { .. })
    ));
    assert_eq!(bytes(&file), sealed);
    assert_eq!(dir.names(), ["root.key"]);
}

#[test]
fn a_root_key_stays_a_root_key_through_every_lock_change() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let new = passphrase("a new passphrase for it");
    // A plain file found in the root slot, locked: it becomes a root key, not a device key.
    let (device, secret) = plain_file(&dir, [4; 32]);
    let file = KeyFile::root(device.path());
    file.add_lock(None, lock(&under)).unwrap();
    assert_eq!(wrong_kind(device.load()), (Kind::Device, Kind::Root));

    // And a new passphrase keeps it one.
    file.add_lock(Some(with(&under)), lock(&new)).unwrap();
    assert_eq!(
        locked(&file).unlock(with(&new)).unwrap().public_key(),
        secret.public_key()
    );
    assert_eq!(wrong_kind(device.load()), (Kind::Device, Kind::Root));
}

#[cfg(unix)]
#[test]
fn a_filesystem_without_hard_links_is_told_apart_from_a_denied_permission() {
    let errno = std::io::Error::from_raw_os_error;
    assert!(lacks_hard_links(&errno(libc::ENOTSUP)));
    assert!(lacks_hard_links(&errno(libc::EPERM)));
    assert!(!lacks_hard_links(&errno(libc::EACCES)));
}

fn touch() -> Unlock<'static> {
    Unlock::TouchId {
        reason: "open the test key",
        wait: WAIT,
    }
}

fn touch_lock() -> NewLock<'static> {
    NewLock::TouchId {
        reason: "check the new lock opens",
        wait: WAIT,
    }
}

/// A sealed root key under `under`, with a `touch-id` lock added through it.
fn root_with_touch_id(dir: &TestDir, under: &Passphrase) -> (KeyFile, Secret) {
    let file = root_file(dir);
    let secret = Secret::copy_of(&[4; 32]);
    file.write(&secret, Protection::Passphrase(under)).unwrap();
    file.add_lock(Some(with(under)), touch_lock()).unwrap();
    (file, secret)
}

#[test]
fn a_touch_id_lock_is_added_beside_the_passphrase_and_either_opens() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, secret) = sealed_file(&dir, [6; 32], &under);

    file.add_lock(Some(with(&under)), touch_lock()).unwrap();
    // Making the lock asked nothing; proving the rewritten file through it asked one touch.
    assert_eq!(stand_in::touches(), 1);
    let locked = locked(&file);
    assert_eq!(
        locked.methods().collect::<Vec<_>>(),
        [Method::Passphrase, Method::TouchId]
    );
    for opener in [with(&under), touch()] {
        assert_eq!(
            locked.unlock(opener).unwrap().public_key(),
            secret.public_key()
        );
    }
    assert_eq!(dir.names(), ["identity.key"]);
}

#[test]
fn a_touch_cannot_set_a_roots_passphrase() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, secret) = root_with_touch_id(&dir, &under);
    let before = bytes(&file);
    let asked = stand_in::touches();

    let new = passphrase("a passphrase set by whoever holds the touch");
    assert!(matches!(
        file.add_lock(Some(touch()), lock(&new)),
        Err(Error::RootPassphraseNeeded { .. })
    ));
    // Refused before anything is opened: no touch was even asked for.
    assert_eq!(stand_in::touches(), asked);
    assert_eq!(bytes(&file), before);

    // Through its passphrase, the root's passphrase changes, and the touch still opens it.
    file.add_lock(Some(with(&under)), lock(&new)).unwrap();
    let locked = locked(&file);
    assert_eq!(
        locked.unlock(with(&new)).unwrap().public_key(),
        secret.public_key()
    );
    assert!(locked.unlock(touch()).is_ok());
    // And the touch may still change the touch.
    file.add_lock(Some(touch()), touch_lock()).unwrap();
}

#[test]
fn a_plain_root_is_never_sealed_under_a_touch_alone() {
    let dir = TestDir::new();
    let (device, _) = plain_file(&dir, [4; 32]);
    let file = KeyFile::root(device.path());

    assert!(matches!(
        file.add_lock(None, touch_lock()),
        Err(Error::RootPassphrase { .. })
    ));
    assert_eq!(bytes(&file), [4; 32]);
    assert_eq!(stand_in::touches(), 0);
}

#[test]
fn a_roots_touch_id_lock_comes_off_and_its_passphrase_stays() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, _) = root_with_touch_id(&dir, &under);

    // The touch cannot take the passphrase off, any more than the passphrase can.
    assert!(matches!(
        file.remove_lock(touch(), Method::Passphrase),
        Err(Error::RootPassphrase { .. })
    ));
    file.remove_lock(touch(), Method::TouchId).unwrap();
    assert_eq!(
        locked(&file).methods().collect::<Vec<_>>(),
        [Method::Passphrase]
    );
}

#[test]
fn removing_the_passphrase_beside_another_macs_lock_is_refused() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, _) = sealed_file(&dir, [6; 32], &under);
    file.add_lock(Some(with(&under)), touch_lock()).unwrap();
    let before = bytes(&file);

    // A copy of this file on another Mac: its touch-id lock is this Mac's, and opens nothing there.
    stand_in::on_mac(2);
    assert!(matches!(
        file.remove_lock(with(&under), Method::Passphrase),
        Err(Error::NoneOpensHere {
            method: Method::Passphrase,
            ..
        })
    ));
    assert_eq!(bytes(&file), before);

    // On the Mac that made the lock, the same removal goes through: the touch opens the file here.
    stand_in::on_mac(1);
    file.remove_lock(with(&under), Method::Passphrase).unwrap();
    assert_eq!(
        locked(&file).methods().collect::<Vec<_>>(),
        [Method::TouchId]
    );
}

#[test]
fn removing_a_lock_new_fingers_stopped_through_the_passphrase_goes_through() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, _) = sealed_file(&dir, [6; 32], &under);
    file.add_lock(Some(with(&under)), touch_lock()).unwrap();

    // The lock that stays is the one that opened the file, so it still opens here.
    stand_in::touch(Touch::FingersChanged);
    file.remove_lock(with(&under), Method::TouchId).unwrap();
    assert_eq!(
        locked(&file).methods().collect::<Vec<_>>(),
        [Method::Passphrase]
    );
}

#[test]
fn this_machines_key_moves_to_touch_id_alone_and_either_lock_opens_between() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, secret) = sealed_file(&dir, [6; 32], &under);

    file.add_lock(Some(with(&under)), touch_lock()).unwrap();
    // Between the two steps, which is where a crash leaves it, both locks open the file.
    let between = locked(&file);
    assert!(between.unlock(with(&under)).is_ok());
    assert!(between.unlock(touch()).is_ok());

    file.remove_lock(with(&under), Method::Passphrase).unwrap();
    let locked = locked(&file);
    assert_eq!(locked.methods().collect::<Vec<_>>(), [Method::TouchId]);
    assert_eq!(
        locked.unlock(touch()).unwrap().public_key(),
        secret.public_key()
    );
    assert!(matches!(
        locked.unlock(with(&under)),
        Err(Error::NoLock {
            method: Method::Passphrase,
            ..
        })
    ));

    // And its last lock comes off through the touch, which writes it plain.
    file.remove_lock(touch(), Method::TouchId).unwrap();
    assert_eq!(bytes(&file), [6; 32]);
}

#[test]
fn a_plain_device_key_takes_a_touch_id_lock_as_its_one_lock() {
    let dir = TestDir::new();
    let (file, secret) = plain_file(&dir, [6; 32]);

    file.add_lock(None, touch_lock()).unwrap();
    let locked = locked(&file);
    assert_eq!(locked.methods().collect::<Vec<_>>(), [Method::TouchId]);
    assert_eq!(
        locked.unlock(touch()).unwrap().public_key(),
        secret.public_key()
    );
}

/// Each open asks for its own touch: the core calls the enclave once per unlock and keeps nothing
/// for the next open or the other key. The stand-in has no context, so this cannot see a reused one;
/// the context half of "one touch opens one key" is pinned by `keystore-enclave`'s
/// `a_context_is_made_for_each_operation_and_never_kept` and its touched hardware test.
#[test]
fn one_context_opens_one_key() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (device, _) = sealed_file(&dir, [6; 32], &under);
    device.add_lock(Some(with(&under)), touch_lock()).unwrap();
    let (root, _) = root_with_touch_id(&dir, &under);
    let (device, root) = (locked(&device), locked(&root));
    let asked = stand_in::touches();

    // Each open asks for its own touch: none is kept for the next open, or lent to the other key.
    device.unlock(touch()).unwrap();
    assert_eq!(stand_in::touches(), asked + 1);
    root.unlock(touch()).unwrap();
    assert_eq!(stand_in::touches(), asked + 2);
    device.unlock(touch()).unwrap();
    assert_eq!(stand_in::touches(), asked + 3);
}

#[test]
fn a_dead_touch_id_lock_is_told_without_a_touch() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, _) = sealed_file(&dir, [6; 32], &under);
    assert_eq!(locked(&file).health(Method::TouchId), None);
    file.add_lock(Some(with(&under)), touch_lock()).unwrap();
    let locked = locked(&file);
    let asked = stand_in::touches();

    assert_eq!(locked.health(Method::Passphrase), Some(Health::Live));
    assert_eq!(locked.health(Method::TouchId), Some(Health::Live));
    // Another Mac's lock, and one made under other enrolled fingers, read as dead.
    stand_in::on_mac(2);
    assert_eq!(locked.health(Method::TouchId), Some(Health::Dead));
    stand_in::on_mac(1);
    stand_in::touch(Touch::FingersChanged);
    assert_eq!(locked.health(Method::TouchId), Some(Health::Dead));
    // A passphrase lock is live wherever the passphrase is typed.
    assert_eq!(locked.health(Method::Passphrase), Some(Health::Live));
    assert_eq!(stand_in::touches(), asked);
}

#[test]
fn a_cancelled_touch_leaves_the_file_as_it_was() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, _) = sealed_file(&dir, [6; 32], &under);
    let before = bytes(&file);

    // The touch that proves the new lock is cancelled: the new form is never published.
    stand_in::touch(Touch::Cancelled);
    assert!(matches!(
        file.add_lock(Some(with(&under)), touch_lock()),
        Err(Error::TouchId {
            source: TouchIdError::Declined(_),
            ..
        })
    ));
    assert_eq!(bytes(&file), before);
    assert_eq!(dir.names(), ["identity.key"]);
}

#[test]
fn a_new_key_is_written_sealed_under_touch_id_and_never_plain() {
    let dir = TestDir::new();
    let file = key_file(&dir);
    let secret = Secret::copy_of(&[6; 32]);

    file.write(
        &secret,
        Protection::TouchId {
            reason: "write it",
            wait: WAIT,
        },
    )
    .unwrap();
    // The proof of the staged file asked one touch; the file holds the touch-id lock alone.
    assert_eq!(stand_in::touches(), 1);
    let locked = locked(&file);
    assert_eq!(locked.methods().collect::<Vec<_>>(), [Method::TouchId]);
    assert_eq!(
        locked.unlock(touch()).unwrap().public_key(),
        secret.public_key()
    );
    assert!(bytes(&file).starts_with(b"KEYSTORE"));
    assert_eq!(dir.names(), ["identity.key"]);

    // Adopting the same key proves the sealed file through a touch.
    file.adopt(
        &secret,
        Protection::TouchId {
            reason: "adopt it",
            wait: WAIT,
        },
    )
    .unwrap();
    assert_eq!(stand_in::touches(), 3);
}

/// Each touch is asked with the wait its own caller gave, on every path to the enclave: a new file's
/// proof, an adoption's, a lock added beside a passphrase, and an unlock. So each dialog is bounded
/// by its own wait, never a share of one.
#[test]
fn every_touch_is_asked_with_the_wait_its_caller_gave() {
    let dir = TestDir::new();
    let file = key_file(&dir);
    let secret = Secret::copy_of(&[9; 32]);
    let wait = Duration::from_secs;

    file.write(
        &secret,
        Protection::TouchId {
            reason: "write it",
            wait: wait(7),
        },
    )
    .unwrap();
    assert_eq!(stand_in::waited(), Some(wait(7)));
    file.adopt(
        &secret,
        Protection::TouchId {
            reason: "adopt it",
            wait: wait(8),
        },
    )
    .unwrap();
    assert_eq!(stand_in::waited(), Some(wait(8)));
    locked(&file)
        .unlock(Unlock::TouchId {
            reason: "open it",
            wait: wait(9),
        })
        .unwrap();
    assert_eq!(stand_in::waited(), Some(wait(9)));

    let under = passphrase("correct horse battery staple");
    let other = TestDir::new();
    let (sealed, _) = sealed_file(&other, [10; 32], &under);
    sealed
        .add_lock(
            Some(with(&under)),
            NewLock::TouchId {
                reason: "check the new lock opens",
                wait: wait(11),
            },
        )
        .unwrap();
    assert_eq!(stand_in::waited(), Some(wait(11)));
}

#[test]
fn a_root_key_is_never_written_under_touch_id_alone() {
    let dir = TestDir::new();
    let file = root_file(&dir);
    assert!(matches!(
        file.write(
            &Secret::copy_of(&[4; 32]),
            Protection::TouchId {
                reason: "write it",
                wait: WAIT,
            }
        ),
        Err(Error::RootPassphrase { .. })
    ));
    assert!(dir.names().is_empty());
    assert_eq!(stand_in::touches(), 0);
}

#[test]
fn removing_the_passphrase_beside_a_lock_that_cannot_be_checked_is_refused() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, _) = sealed_file(&dir, [6; 32], &under);
    file.add_lock(Some(with(&under)), touch_lock()).unwrap();

    // Locked out: the touch-id lock may open again later, but nothing says it will.
    stand_in::touch(Touch::LockedOut);
    assert_eq!(
        locked(&file).health(Method::TouchId),
        Some(Health::Unchecked)
    );
    assert!(matches!(
        file.remove_lock(with(&under), Method::Passphrase),
        Err(Error::NoneOpensHere { .. })
    ));
}

#[test]
fn a_failed_touch_id_unlock_blames_no_passphrase() {
    let dir = TestDir::new();
    let (file, _) = sealed_file(&dir, [6; 32], &passphrase("correct horse battery staple"));
    let wrong = passphrase("wrong");
    let Err(error) = locked(&file).unlock(with(&wrong)) else {
        panic!("a wrong passphrase opened the file");
    };
    assert!(
        error
            .to_string()
            .ends_with("wrong passphrase, or the file is damaged")
    );

    let file = KeyFile::device(dir.join("touch.key"));
    file.write(
        &Secret::copy_of(&[7; 32]),
        Protection::TouchId {
            reason: "write it",
            wait: WAIT,
        },
    )
    .unwrap();
    let mut damaged = bytes(&file);
    let last = damaged.len() - 1;
    damaged[last] ^= 0x01;
    fs::remove_file(file.path()).unwrap();
    plant(&file, &damaged);
    let Err(error) = locked(&file).unlock(touch()) else {
        panic!("a damaged file opened");
    };
    assert!(matches!(
        error,
        Error::Unlock {
            method: Method::TouchId,
            ..
        }
    ));
    assert!(error.to_string().ends_with(": the file is damaged"));
}

/// Prints the `touch-id` fixtures a consumer's tests read: key files whose header lists a `touch-id` lock,
/// made on the software stand-in for the enclave (stand-in Mac 1), so its blob is a plain scalar and the
/// lock opens nowhere but here. Each is printed with its seed and passphrase. Run once and copy the output:
/// `cargo test --lib -- --ignored --nocapture prints_touch_id_fixtures`.
#[test]
#[ignore = "prints fixtures for a consumer; asserts nothing"]
fn prints_touch_id_fixtures() {
    const PASS: &str = "correct horse battery staple";
    let reason = "make a fixture";
    let print = |name: &str, seed: u8, file: &KeyFile| {
        let bytes = fs::read(file.path()).unwrap();
        println!("/// seed [{seed:#04x}; 32], passphrase {PASS:?} where it holds one");
        println!("pub const {name}: [u8; {}] = [", bytes.len());
        for row in bytes.chunks(16) {
            let row: Vec<String> = row.iter().map(|byte| format!("{byte:#04x}")).collect();
            println!("    {},", row.join(", "));
        }
        println!("];");
    };
    let under = passphrase(PASS);

    let dir = TestDir::new();
    let root = KeyFile::root(dir.path().join("root.key"));
    root.write(
        &Secret::copy_of(&[0x21; 32]),
        Protection::Passphrase(&under),
    )
    .unwrap();
    root.add_lock(Some(with(&under)), NewLock::TouchId { reason, wait: WAIT })
        .unwrap();
    print("ROOT_PASSPHRASE_AND_TOUCH_ID", 0x21, &root);

    let alone = KeyFile::device(dir.path().join("alone"));
    alone
        .write(
            &Secret::copy_of(&[0x11; 32]),
            Protection::TouchId { reason, wait: WAIT },
        )
        .unwrap();
    print("DEVICE_TOUCH_ID_ALONE", 0x11, &alone);

    let both = KeyFile::device(dir.path().join("both"));
    both.write(
        &Secret::copy_of(&[0x11; 32]),
        Protection::Passphrase(&under),
    )
    .unwrap();
    both.add_lock(Some(with(&under)), NewLock::TouchId { reason, wait: WAIT })
        .unwrap();
    print("DEVICE_PASSPHRASE_AND_TOUCH_ID", 0x11, &both);
}
