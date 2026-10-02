//! The enclave crate's promises, pinned where a test can see them: the access control it makes keys
//! under, that it never writes to the keychain, that it never asks a person outside an enclave
//! operation, and that a context is made for one operation and never kept.
//!
//! These read the crate's own sources, so they run on every platform, a Mac without an enclave
//! included. They are tripwires rather than proofs: what they catch is the drift that arrives one
//! reasonable-looking line at a time.

use std::fs;
use std::path::PathBuf;

/// Every source file under `src/`, by name, with its `//` comments removed so the docs may say what
/// the code must not do.
#[allow(clippy::expect_used)]
fn sources() -> Vec<(String, String)> {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources: Vec<(String, String)> = fs::read_dir(&src)
        .expect("the source directory lists")
        .map(|entry| {
            let path = entry.expect("a source directory entry").path();
            let name = path
                .file_name()
                .expect("a source has a name")
                .to_string_lossy()
                .into_owned();
            let code = fs::read_to_string(&path)
                .expect("a source is readable")
                .lines()
                .map(|line| line.find("//").map_or(line, |at| &line[..at]))
                .collect::<Vec<_>>()
                .join("\n");
            (name, code)
        })
        .collect();
    sources.sort();
    assert!(
        sources.iter().any(|(name, _)| name == "key.rs"),
        "the scan did not reach the key code"
    );
    sources
}

fn source(name: &str) -> String {
    sources()
        .into_iter()
        .find(|(found, _)| found == name)
        .map(|(_, code)| code)
        .unwrap_or_default()
}

/// The access control is one pinned constant: a touch of a finger enrolled now, at an unlocked
/// screen, on this device. `userPresence` lets the login password in, `biometryAny` a newly
/// enrolled finger, a watch a wrist across the room; none may appear.
#[test]
fn the_access_control_is_biometry_current_set_only() {
    let key = source("key.rs");
    assert!(
        key.contains("kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet"),
        "the policy's flags must be private key usage and the current biometry set"
    );
    for (name, code) in sources() {
        for token in code.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
            if token.starts_with("kSecAccessControl") {
                assert!(
                    [
                        "kSecAccessControlPrivateKeyUsage",
                        "kSecAccessControlBiometryCurrentSet"
                    ]
                    .contains(&token),
                    "{name} names `{token}`, an access control the policy does not allow"
                );
            }
            if token.starts_with("kSecAttrAccessible") {
                assert_eq!(
                    token, "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
                    "{name} names a protection class other than this device, unlocked"
                );
            }
        }
    }
}

/// Nothing goes in the keychain: no item is added, and no key is made permanent. An unsigned
/// program could not anyway, and a signed one must not start.
#[test]
fn no_keychain_item_is_written() {
    for (name, code) in sources() {
        for call in ["SecItemAdd", "SecItemUpdate", "SecKeychain"] {
            assert!(!code.contains(call), "{name} calls `{call}`");
        }
        // Every place the attribute is set, read to the end of its statement.
        for (set, _) in code.match_indices("const kSecAttrIsPermanent") {
            let statement = code[set..].split(';').next().unwrap_or_default();
            assert!(
                statement.contains("false_value"),
                "{name} sets `kSecAttrIsPermanent` to something other than false"
            );
        }
    }
    assert!(
        source("key.rs").contains("const kSecAttrIsPermanent"),
        "the scan did not find where a key is made not permanent"
    );
}

/// The only way a person is asked is the enclave operation itself. A standalone policy evaluation
/// would be a yes in front of nothing: a dialog that guards no key.
#[test]
fn no_code_calls_evaluate_policy() {
    for (name, code) in sources() {
        assert!(
            !code.contains("valuatePolicy"),
            "{name} evaluates a policy outside an enclave operation"
        );
    }
}

/// One context opens one key: a context is made inside the operation that uses it, never stored, and
/// invalidated when it drops, so a touch given once can never answer a second operation.
#[test]
fn a_context_is_made_for_each_operation_and_never_kept() {
    let key = source("key.rs");
    let made: Vec<&str> = key
        .lines()
        .map(str::trim)
        .filter(|line| line.contains("Context::"))
        .collect();
    assert_eq!(
        made,
        [
            "let context = Context::asking(reason)?;",
            "let context = Context::silent()?;"
        ],
        "a context is made somewhere other than `agree` and `check`"
    );
    let holder = key
        .split("pub struct Key {")
        .nth(1)
        .and_then(|rest| rest.split('}').next())
        .unwrap_or_default();
    assert!(
        !holder.is_empty() && !holder.contains("Context"),
        "`Key` holds a context between operations"
    );
    let context = source("context.rs");
    let drop = context
        .split("impl Drop for Context")
        .nth(1)
        .unwrap_or_default();
    assert!(
        drop.contains("c\"invalidate\""),
        "a context must be invalidated when it drops"
    );
}
