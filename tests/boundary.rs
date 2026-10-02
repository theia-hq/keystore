//! The storage core's boundary, pinned: what it depends on, where it is not re-exported, what it
//! never names, and that nothing public hands out a bare seed.
//!
//! These read the crate's own manifest and sources. They are tripwires rather than proofs: a scan can
//! be evaded on purpose. What they catch is the drift that arrives one reasonable-looking line at a
//! time, which is how a storage crate grows a posture.

use std::fs;
use std::path::{Path, PathBuf};

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The keys of one `[section]` of a manifest.
#[allow(clippy::expect_used)]
fn manifest_keys(manifest: &Path, section: &str) -> Vec<String> {
    let text = fs::read_to_string(manifest).expect("the manifest is readable");
    let mut keys = Vec::new();
    let mut inside = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            inside = line == section;
            continue;
        }
        if !inside || line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(key) = line.split(['=', '.']).next() {
            keys.push(key.trim().to_owned());
        }
    }
    keys.sort();
    keys
}

/// The shipped source files: everything under `src/`, at any depth, except the tests and their
/// helpers. Each is named by its path under `src/`.
#[allow(clippy::expect_used)]
fn shipped_sources() -> Vec<(String, String)> {
    let src = crate_dir().join("src");
    let mut sources = Vec::new();
    let mut dirs = vec![src.clone()];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir).expect("a source directory is readable") {
            let path = entry.expect("a source directory lists").path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            let name = path
                .strip_prefix(&src)
                .expect("a source is under src/")
                .to_string_lossy()
                .into_owned();
            if name.ends_with("_tests.rs") || name == "test_dir.rs" {
                continue;
            }
            sources.push((
                name,
                fs::read_to_string(&path).expect("a source is readable"),
            ));
        }
    }
    assert!(
        sources.len() >= 10,
        "the scan found too few sources to mean anything"
    );
    assert!(
        sources.iter().any(|(name, _)| name == "lock/passphrase.rs"),
        "the scan did not reach the lock sources"
    );
    sources
}

/// Source text with every `//` comment removed, so the docs may explain what the code must not do.
fn code_only(source: &str) -> String {
    source
        .lines()
        .map(|line| line.find("//").map_or(line, |at| &line[..at]))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every line of the manifest's dependency sections, for the source checks.
#[allow(clippy::expect_used)]
fn dependency_lines(manifest: &Path) -> Vec<String> {
    let text = fs::read_to_string(manifest).expect("the manifest is readable");
    let mut lines = Vec::new();
    let mut inside = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            inside = line.ends_with("dependencies]");
            continue;
        }
        if inside && !line.is_empty() && !line.starts_with('#') {
            lines.push(line.to_owned());
        }
    }
    lines
}

/// The crate stores a key and names nobody's identity type: every dependency is a published crate
/// from the registry, so nothing of the family it serves can sit under it, and a key format change
/// never waits on another repository's release.
#[test]
fn the_storage_core_depends_on_registry_crates_only() {
    let manifest = crate_dir().join("Cargo.toml");
    assert_eq!(
        manifest_keys(&manifest, "[dependencies]"),
        [
            "argon2",
            "chacha20poly1305",
            "ed25519-dalek",
            "getrandom",
            "icu_normalizer",
            "thiserror",
            "zeroize"
        ]
    );
    // `libc` for the effective uid the owner check compares against, and nothing else.
    assert_eq!(
        manifest_keys(&manifest, "[target.'cfg(unix)'.dependencies]"),
        ["libc"]
    );
    // On a Mac, the `touch-id` lock: its derivation, and the enclave crate beside this one.
    assert_eq!(
        manifest_keys(
            &manifest,
            "[target.'cfg(target_os = \"macos\")'.dependencies]"
        ),
        ["hkdf", "keystore-enclave", "p256", "sha2"]
    );
    // A git or path source is how a crate of the family would arrive: none may. The one exception is
    // the enclave crate, which is this repository's own, beside this one, and depends on nothing of
    // this crate's.
    const OWN: &str = "keystore-enclave={path=\"keystore-enclave\"}";
    let lines = dependency_lines(&manifest);
    assert!(
        lines.len() >= 8,
        "the scan found too few dependency lines to mean anything"
    );
    for line in lines {
        let spec: String = line.split_whitespace().collect();
        assert!(
            spec == OWN
                || !["git=", "path=", "workspace="]
                    .iter()
                    .any(|source| spec.contains(source)),
            "`{line}` is a dependency from outside the registry"
        );
    }
}

#[test]
fn the_storage_code_never_names_posture_home_prompting_or_signing() {
    // The words of the concerns that belong to the caller: where a key lives and whether one is made
    // (home, posture, intent, mint, ephemeral), how a person is asked (prompt, tty, stdin, env), and
    // what the key is for (any signing surface). A storage core that needs one of these is growing a
    // concern it must not own.
    const FORBIDDEN: &[&str] = &[
        "Home",
        "home",
        "HOME",
        "home_dir",
        "Posture",
        "posture",
        "Intent",
        "intent",
        "mint",
        "Mint",
        "ephemeral",
        "Ephemeral",
        "Prompt",
        "prompt",
        "tty",
        "stdin",
        "env",
        "var_os",
        "sign",
        "sign_document",
        "Signer",
        "Signature",
        "SigningKey",
    ];
    for (name, source) in shipped_sources() {
        let code = code_only(&source);
        for token in code.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
            assert!(
                !FORBIDDEN.contains(&token),
                "{name} names `{token}`, a concern the storage core must not own"
            );
        }
    }
}

#[test]
fn no_public_function_hands_out_a_bare_seed() {
    for (name, source) in shipped_sources() {
        let code = code_only(&source);
        let mut signature = String::new();
        for line in code.lines().map(str::trim) {
            let public = line.starts_with("pub fn ") || line.starts_with("pub const fn ");
            if signature.is_empty() && !public {
                continue;
            }
            signature.push_str(line);
            signature.push(' ');
            if !(line.contains('{') || line.ends_with(';')) {
                continue;
            }
            if let Some((_, returns)) = signature.split_once("->") {
                let returns = returns.split('{').next().unwrap().trim();
                assert!(
                    !returns.contains("[u8")
                        || returns.starts_with('&')
                        || returns.contains("Zeroizing<"),
                    "{name}: `{}` returns key-sized bytes by value, outside a wiping owner",
                    signature.trim()
                );
            }
            signature.clear();
        }
    }
    // Nor may a trait do it: the only impls a `Secret` carries are the ones that cannot move bytes out.
    let secret = code_only(&fs::read_to_string(crate_dir().join("src/secret.rs")).unwrap());
    let lines: Vec<&str> = secret
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    for line in &lines {
        if line.starts_with("impl") && line.contains(" for Secret") {
            assert!(
                [
                    "impl Drop for Secret",
                    "impl ZeroizeOnDrop for Secret",
                    "impl fmt::Debug for Secret"
                ]
                .iter()
                .any(|allowed| line.starts_with(allowed)),
                "secret.rs: `{line}` is an impl that could hand the seed out"
            );
        }
    }
    let declared = lines
        .iter()
        .position(|line| line.starts_with("pub struct Secret"))
        .unwrap();
    assert!(
        !lines[declared - 1].starts_with("#[derive"),
        "secret.rs: `Secret` must derive nothing"
    );
    // A private field, so nothing outside the module reaches the box.
    assert!(
        lines[declared].starts_with("pub struct Secret(Box<"),
        "secret.rs: `Secret`'s field must stay private, found `{}`",
        lines[declared]
    );
    // And no other file may add an impl that takes a `Secret` apart: a conversion or a trait can be
    // written anywhere in the crate, not only beside the type.
    for (name, source) in shipped_sources() {
        if name == "secret.rs" {
            continue;
        }
        for line in code_only(&source).lines().map(str::trim) {
            let opens_secret = line.contains(" for Secret")
                || line.contains("Secret>")
                || line.contains("<&Secret")
                || line.contains("for &Secret");
            assert!(
                !(line.starts_with("impl") && opens_secret),
                "{name}: `{line}` is an impl on `Secret` outside secret.rs"
            );
        }
    }
}

/// argon2 frees its own work memory unwiped, and the last pass's blocks rebuild the key. The only
/// call this crate makes is the one that takes memory it owns and wipes.
#[test]
fn the_key_derivation_runs_in_memory_this_crate_wipes() {
    let lock = code_only(&fs::read_to_string(crate_dir().join("src/lock/passphrase.rs")).unwrap());
    assert!(lock.contains(".hash_password_into_with_memory("));
    assert!(lock.contains("let mut blocks = Zeroizing::new(Vec::new());"));
    // And no source anywhere calls the form that frees its memory unwiped.
    for (name, source) in shipped_sources() {
        assert!(
            !code_only(&source).contains(".hash_password_into("),
            "{name} derives a key in memory argon2 frees unwiped"
        );
    }
}

/// Wiping on drop cannot be watched from a test: reading freed memory is undefined behaviour, so
/// any test that claimed to see the wipe would be reporting nothing. What CAN be pinned is that the
/// owners are built to wipe: the seed's box has a `Drop` that zeroizes it, the passphrase lives in a
/// `Zeroizing` buffer, and the file key and the key-encryption key live in a boxed `Zeroizing`, so a
/// move copies a pointer and never the key. The key-encryption key is derived straight into its box.
#[test]
#[allow(clippy::expect_used)]
fn the_secret_owners_are_built_to_wipe() {
    let read = |name: &str| {
        code_only(&fs::read_to_string(crate_dir().join("src").join(name)).expect("readable"))
    };
    let secret = read("secret.rs");
    let drop = secret
        .split("impl Drop for Secret")
        .nth(1)
        .expect("`Secret` has a `Drop`");
    let body = drop.split("\n}").next().expect("the `Drop` has a body");
    assert!(
        body.contains("self.0.zeroize()"),
        "`Secret`'s `Drop` must zeroize the seed"
    );
    assert!(read("passphrase.rs").contains("pub struct Passphrase(Zeroizing<Vec<u8>>);"));
    let lock = read("lock.rs");
    assert!(
        lock.contains("pub(crate) struct FileKey(Box<Zeroizing<[u8; KEY_LEN]>>);"),
        "the file key must live in a boxed `Zeroizing`"
    );
    assert!(
        lock.contains("pub(crate) struct Kek(Box<Zeroizing<[u8; Kek::LEN]>>);"),
        "the key-encryption key must live in a boxed `Zeroizing`"
    );
    for name in ["lock/passphrase.rs", "lock/enclave.rs"] {
        let method = read(name);
        assert!(
            method.contains("let mut kek = Kek::zeroed();")
                && method.contains("&mut kek.fill()[..]"),
            "{name} must derive its key straight into the key's box"
        );
    }
}

/// The crate paths a method module may name: its errors, the key it makes, its caller's input, and
/// what it can say of its own health.
const METHOD_CRATE_PATHS: &[&str] = &[
    "crate::error::",
    "crate::lock::Kek",
    "crate::passphrase::",
    "crate::stored::Health",
];

/// The external crates a method module may name: its derivation and its randomness, the curve and
/// the enclave a `touch-id` lock agrees through, and the wipe.
const METHOD_CRATES: &[&str] = &[
    "argon2",
    "core",
    "getrandom",
    "hkdf",
    "keystore_enclave",
    "p256",
    "sha2",
    "zeroize",
];

/// Names any module may start a path from without importing them.
const PRELUDE: &[&str] = &[
    "Self", "Box", "Option", "Result", "Vec", "u8", "u16", "u32", "u64", "usize",
];

/// Every `use` declaration in `code`, joined onto one line.
fn uses(code: &str) -> Vec<String> {
    let mut uses = Vec::new();
    let mut open: Option<String> = None;
    for line in code.lines().map(str::trim) {
        if let Some(mut text) = open.take() {
            text.push_str(line);
            if line.ends_with(';') {
                uses.push(text);
            } else {
                open = Some(text);
            }
        } else if line.starts_with("use ") || line.starts_with("pub(crate) use ") {
            if line.ends_with(';') {
                uses.push(line.to_owned());
            } else {
                open = Some(line.to_owned());
            }
        }
    }
    uses
}

/// The names a `use` brings into scope: its last segment, each name in its braces, or an alias.
fn imported(declaration: &str) -> Vec<String> {
    let path = declaration
        .trim_end_matches(';')
        .rsplit_once(' ')
        .map_or(declaration, |(_, path)| path);
    let tail = declaration.split_once('{').map_or_else(
        || path.rsplit("::").next().unwrap_or(path),
        |(_, braced)| braced,
    );
    tail.trim_end_matches(['}', ';'])
        .split(',')
        .map(|name| name.rsplit(' ').next().unwrap_or(name).trim().to_owned())
        .filter(|name| !name.is_empty())
        .collect()
}

/// The names `code` declares itself: its types, functions, and constants.
fn declared(code: &str) -> Vec<String> {
    let words: Vec<&str> = code
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .collect();
    words
        .windows(2)
        .filter(|pair| ["struct", "enum", "fn", "const", "trait", "type"].contains(&pair[0]))
        .map(|pair| pair[1].to_owned())
        .collect()
}

/// Each path in `code` from its first segment: `(root, the whole path)`.
fn paths(code: &str) -> Vec<(String, String)> {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(offset) = code[at..].find("::") {
        let colons = at + offset;
        let start = code[..colons]
            .rfind(|c: char| !ident(c))
            .map_or(0, |before| before + 1);
        let continues = code[..start].ends_with("::");
        let root = &code[start..colons];
        if !root.is_empty() && !continues {
            let end = code[colons..]
                .find(|c: char| !(ident(c) || c == ':'))
                .map_or(code.len(), |after| colons + after);
            found.push((root.to_owned(), code[start..end].to_owned()));
        }
        at = colons + 2;
    }
    found
}

/// A method makes a key-encryption key and nothing else: the file key, the seed, and the cipher
/// that wraps one under the other belong to the core. Every method module lives under `lock/`, and
/// what it may name is an allow-list, so a method that reaches for anything else (the file key
/// through any type that holds it, the cipher's crate, a parent module through `super`) fails here,
/// not in review.
#[test]
#[allow(clippy::expect_used)]
fn no_method_sees_the_file_key() {
    let methods: Vec<(String, String)> = shipped_sources()
        .into_iter()
        .filter(|(name, _)| name.starts_with("lock/"))
        .collect();
    for method in ["lock/passphrase.rs", "lock/enclave.rs"] {
        assert!(
            methods.iter().any(|(name, _)| name == method),
            "the scan did not reach {method}"
        );
    }
    for (name, source) in &methods {
        let code = code_only(source);
        for token in code.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
            assert!(
                !["super", "extern"].contains(&token),
                "{name} names `{token}`, a way around the allow-list"
            );
        }
        assert!(
            !code.contains("self::"),
            "{name} names a path through `self::`"
        );
        let mut known: Vec<String> = declared(&code);
        for declaration in uses(&code) {
            let path = declaration
                .trim_start_matches("pub(crate) ")
                .trim_start_matches("use ");
            let allowed = METHOD_CRATE_PATHS.iter().any(|ok| path.starts_with(ok))
                || METHOD_CRATES
                    .iter()
                    .any(|ok| path.starts_with(&format!("{ok}::")));
            assert!(
                allowed,
                "{name}: `{declaration}` is outside what a method may name"
            );
            known.extend(imported(&declaration));
        }
        for (root, path) in paths(&code) {
            if root == "crate" {
                assert!(
                    METHOD_CRATE_PATHS.iter().any(|ok| path.starts_with(ok)),
                    "{name}: `{path}` is outside what a method may name"
                );
                continue;
            }
            assert!(
                known.contains(&root)
                    || PRELUDE.contains(&root.as_str())
                    || METHOD_CRATES.contains(&root.as_str()),
                "{name}: `{path}` starts from `{root}`, which a method may not name"
            );
        }
    }
    // Every method the core reaches is one this scan read: each `Params` variant's payload is a type
    // declared under `lock/`, so a method module placed anywhere else cannot be wired in unseen.
    let core = code_only(&fs::read_to_string(crate_dir().join("src/lock.rs")).expect("readable"));
    let params = core
        .split("pub(crate) enum Params {")
        .nth(1)
        .and_then(|rest| rest.split('}').next())
        .expect("the core declares `Params`");
    let payloads: Vec<&str> = params
        .split(['(', ')'])
        .skip(1)
        .step_by(2)
        .map(str::trim)
        .collect();
    assert!(!payloads.is_empty(), "the scan found no method in `Params`");
    for payload in payloads {
        assert!(
            methods
                .iter()
                .any(|(_, source)| declared(&code_only(source))
                    .iter()
                    .any(|name| name == payload)),
            "`Params` reaches `{payload}`, which no module under lock/ declares"
        );
    }
}
