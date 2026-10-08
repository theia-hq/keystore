//! A probe of what the Secure Enclave answers, with no dialog allowed, for a `touch-id` key as the
//! Mac around it changes: a locked screen, a closed lid, a lockout after failed touches, a finger
//! enrolled or removed. Rerun it on each major macOS release to check that `Locked::health` still reads
//! these states as documented.
//!
//! ```text
//! cargo run --example touch_id_probe -- sampler
//! cargo run --example touch_id_probe -- enrol
//! ```
//!
//! - `sampler` makes a key, then every 3 seconds for about 2 minutes asks it for an agreement with no
//!   dialog allowed, and tries to read the biometry domain state. While it runs: lock the screen,
//!   close the lid, and fail touches (at the lock screen) until Touch ID locks out.
//! - `enrol` makes a key and asks it, then pauses while you enrol a finger, while the screen is
//!   locked, and while you remove the finger, asking the same key after each step. After the new
//!   finger, it asks the old key once for a real agreement, which may show the dialog, and asks you
//!   whether it did.
//!
//! Every step also asks a control: the same blob with one bit flipped, which should be refused in
//! every state. At the end, the sampler prints the command to run it again over `ssh localhost`.
//!
//! It prints timestamps, the call's outcome, the system's error domain and code, whether the domain
//! state could be read, and whether it changed. Never a key, a blob, a hash or the domain state
//! itself. Its keys are not permanent, so nothing is left in the keychain. Start it at an unlocked
//! Mac with Touch ID set up. macOS only.

#![cfg_attr(target_os = "macos", allow(unsafe_code))]

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("touch_id_probe runs on macOS only");
}

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn core::error::Error>> {
    match std::env::args().nth(1).as_deref() {
        Some("sampler") => probe::sampler(),
        Some("enrol") => probe::enrol(),
        _ => Err("usage: touch_id_probe sampler | enrol".into()),
    }
}

#[cfg(target_os = "macos")]
mod probe {
    use core::error::Error as _;
    use core::ffi::{c_char, c_void};
    use core::time::Duration;
    use std::io::BufRead as _;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    use keystore_enclave::{Error, Key, OsError, Policy, create, load};

    type Id = *mut c_void;
    type Sel = *mut c_void;

    #[link(name = "LocalAuthentication", kind = "framework")]
    unsafe extern "C" {}

    #[link(name = "objc")]
    unsafe extern "C" {
        fn objc_getClass(name: *const c_char) -> Id;
        fn sel_registerName(name: *const c_char) -> Sel;
        fn objc_msgSend();
    }

    /// `LAPolicyDeviceOwnerAuthenticationWithBiometrics`.
    const POLICY_BIOMETRICS: isize = 1;

    pub(super) fn sampler() -> Result<(), Box<dyn core::error::Error>> {
        let Some((key, control)) = new_keys() else {
            return Ok(());
        };
        let start = Instant::now();
        let first = domain_state();
        println!("lock the screen, close the lid, and fail touches until lockout, while this runs");
        for _ in 0..40 {
            println!(
                "{} +{:>3}s  check: {}  control: {}  domain state: {}",
                now(),
                start.elapsed().as_secs(),
                outcome(&key.check()),
                control_outcome(&control),
                compared(&first, &domain_state()),
            );
            std::thread::sleep(Duration::from_secs(3));
        }
        if let Ok(binary) = std::env::current_exe() {
            println!("now run the same over ssh, from this Mac, and keep its output:");
            println!("  ssh localhost '{} sampler'", binary.display());
        }
        done();
        Ok(())
    }

    pub(super) fn enrol() -> Result<(), Box<dyn core::error::Error>> {
        let Some((key, control)) = new_keys() else {
            return Ok(());
        };
        let first = domain_state();
        step("start", &key, &control, &first);

        pause("enrol a new finger in System Settings, Touch ID & Password, then press Enter");
        step("after enrolling", &key, &control, &first);
        println!(
            "the old key now asks for a touch once; touch with any enrolled finger, or cancel"
        );
        let agreed = key.agree(
            &base_point(),
            "test whether this old key still opens",
            Duration::from_secs(60),
        );
        println!(
            "{} after enrolling: agree: {}",
            now(),
            outcome(&agreed.map(drop))
        );
        println!("did a Touch ID dialog show? type y or n, then press Enter");
        let shown = std::io::stdin().lock().lines().next().and_then(Result::ok);
        println!(
            "dialog shown: {}",
            shown.as_deref().map_or("no answer", str::trim)
        );

        println!(
            "lock the screen now; the key is asked in 20 seconds; unlock after, then press Enter"
        );
        std::thread::sleep(Duration::from_secs(20));
        step("screen locked", &key, &control, &first);
        pause("");

        pause("remove the finger you added, then press Enter");
        step("after removing", &key, &control, &first);
        done();
        Ok(())
    }

    /// A new key, and its control: the same blob with one bit flipped, which should be refused in
    /// every state. `None`, with the code printed, when no key can be made here.
    fn new_keys() -> Option<(Key, Result<Key, Error>)> {
        let (blob, public) = match create(Policy::BiometryCurrentSet) {
            Ok(made) => made,
            Err(error) => {
                println!("{} create: {}", now(), outcome(&Err(error)));
                return None;
            }
        };
        println!("{} made a key; its blob is {} bytes", now(), blob.len());
        let mut flipped = blob.clone();
        let middle = flipped.len() / 2;
        flipped[middle] ^= 0x01;
        let control = load(&flipped, &public);
        match load(&blob, &public) {
            Ok(key) => Some((key, control)),
            Err(error) => {
                println!("{} load: {}", now(), outcome(&Err(error)));
                None
            }
        }
    }

    /// The control's answer: refused at load, or at the check.
    fn control_outcome(control: &Result<Key, Error>) -> String {
        match control {
            Ok(key) => outcome(&key.check()),
            Err(error) => format!("at load: {}", name_and_code(error)),
        }
    }

    /// Any valid peer serves the one touched agreement: the P-256 base point, a public value.
    fn base_point() -> [u8; keystore_enclave::PUBLIC_KEY_LEN] {
        let mut peer = [0; keystore_enclave::PUBLIC_KEY_LEN];
        peer[0] = 4;
        // The P-256 base point, a fixed public value.
        peer[1..33].copy_from_slice(&[
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96,
        ]);
        peer[33..].copy_from_slice(&[
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
            0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
            0x37, 0xbf, 0x51, 0xf5,
        ]);
        peer
    }

    fn step(label: &str, key: &Key, control: &Result<Key, Error>, first: &State) {
        println!(
            "{} {label}: check: {}  control: {}  domain state: {}",
            now(),
            outcome(&key.check()),
            control_outcome(control),
            compared(first, &domain_state()),
        );
    }

    fn pause(line: &str) {
        if !line.is_empty() {
            println!("{line}");
        }
        let _ = std::io::stdin().lock().lines().next();
    }

    fn done() {
        println!("done; the keys were not permanent, so nothing was left in the keychain");
    }

    /// Seconds since the epoch, the one clock both runs share.
    fn now() -> String {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        format!("t={seconds}")
    }

    /// What a call answered, by name and by the system's own code. Never the error's description,
    /// which can carry the key's id. A `check` that is `Ok` saw `-1004`.
    fn outcome(result: &Result<(), Error>) -> String {
        match result {
            Ok(()) => String::from("ok (com.apple.LocalAuthentication -1004 for a check)"),
            Err(error) => name_and_code(error),
        }
    }

    fn name_and_code(error: &Error) -> String {
        let name = match error {
            Error::AccessControl(_) => "access control",
            Error::Create(_) => "create",
            Error::NoBlob => "no blob",
            Error::Load(_) => "load",
            Error::OtherKey => "other key",
            Error::Peer(_) => "peer",
            Error::Declined(_) => "declined",
            Error::NotInteractive(_) => "not interactive",
            Error::Unguarded => "unguarded",
            Error::Agree(_) => "agree",
            Error::NoContext => "no context",
            _ => "other",
        };
        match error
            .source()
            .and_then(|source| source.downcast_ref::<OsError>())
        {
            Some(os) => format!(
                "{name} ({} {}, description held a hash or key id: {})",
                os.domain(),
                os.code(),
                if os.description_withheld() {
                    "yes"
                } else {
                    "no"
                }
            ),
            None => name.to_owned(),
        }
    }

    /// The biometry domain state, as read now: its bytes, kept only to compare, or the code that
    /// refused the read.
    enum State {
        Read(Vec<u8>),
        Refused(isize),
        Missing,
    }

    fn compared(first: &State, now: &State) -> String {
        match (first, now) {
            (State::Read(first), State::Read(now)) => format!(
                "read, {} bytes, {}",
                now.len(),
                if first == now { "same" } else { "changed" }
            ),
            (_, State::Read(now)) => format!("read, {} bytes", now.len()),
            (_, State::Refused(code)) => format!("not read (com.apple.LocalAuthentication {code})"),
            (_, State::Missing) => String::from("not read (no error given)"),
        }
    }

    /// Read the biometry domain state through a fresh `LAContext`, with no dialog: it is filled in by
    /// asking whether biometry can be used, which asks no one.
    fn domain_state() -> State {
        // SAFETY: each call below is an Objective-C message to a live object, through
        // `objc_msgSend` cast to the method's own signature: `+new`, `-canEvaluatePolicy:error:`,
        // `-evaluatedPolicyDomainState`, `-length`, `-bytes`, `-code` and `-release`. The data's bytes
        // are copied out while the context that owns it is alive, and every null is checked.
        unsafe {
            let new: unsafe extern "C" fn(Id, Sel) -> Id = core::mem::transmute::<
                unsafe extern "C" fn(),
                unsafe extern "C" fn(Id, Sel) -> Id,
            >(objc_msgSend);
            let can: unsafe extern "C" fn(Id, Sel, isize, *mut Id) -> bool =
                core::mem::transmute::<
                    unsafe extern "C" fn(),
                    unsafe extern "C" fn(Id, Sel, isize, *mut Id) -> bool,
                >(objc_msgSend);
            let length: unsafe extern "C" fn(Id, Sel) -> usize = core::mem::transmute::<
                unsafe extern "C" fn(),
                unsafe extern "C" fn(Id, Sel) -> usize,
            >(objc_msgSend);
            let bytes: unsafe extern "C" fn(Id, Sel) -> *const u8 = core::mem::transmute::<
                unsafe extern "C" fn(),
                unsafe extern "C" fn(Id, Sel) -> *const u8,
            >(objc_msgSend);
            let code: unsafe extern "C" fn(Id, Sel) -> isize = core::mem::transmute::<
                unsafe extern "C" fn(),
                unsafe extern "C" fn(Id, Sel) -> isize,
            >(objc_msgSend);
            let release: unsafe extern "C" fn(Id, Sel) = core::mem::transmute::<
                unsafe extern "C" fn(),
                unsafe extern "C" fn(Id, Sel),
            >(objc_msgSend);

            let class = objc_getClass(c"LAContext".as_ptr());
            if class.is_null() {
                return State::Missing;
            }
            let context = new(class, sel_registerName(c"new".as_ptr()));
            if context.is_null() {
                return State::Missing;
            }
            let mut error: Id = core::ptr::null_mut();
            let usable = can(
                context,
                sel_registerName(c"canEvaluatePolicy:error:".as_ptr()),
                POLICY_BIOMETRICS,
                &raw mut error,
            );
            let data = new_state(context);
            let state = if data.is_null() {
                if !usable && !error.is_null() {
                    State::Refused(code(error, sel_registerName(c"code".as_ptr())))
                } else {
                    State::Missing
                }
            } else {
                let len = length(data, sel_registerName(c"length".as_ptr()));
                let start = bytes(data, sel_registerName(c"bytes".as_ptr()));
                if start.is_null() {
                    State::Missing
                } else {
                    State::Read(core::slice::from_raw_parts(start, len).to_vec())
                }
            };
            release(context, sel_registerName(c"release".as_ptr()));
            state
        }
    }

    /// `-evaluatedPolicyDomainState`, deprecated in macOS 15 for `-domainState` and still answered.
    ///
    /// # Safety
    ///
    /// `context` must be a live `LAContext`.
    unsafe fn new_state(context: Id) -> Id {
        // SAFETY: the caller vouches for the context; the selector takes no arguments and returns an
        // object owned by the context, or nil.
        unsafe {
            let get = core::mem::transmute::<
                unsafe extern "C" fn(),
                unsafe extern "C" fn(Id, Sel) -> Id,
            >(objc_msgSend);
            get(
                context,
                sel_registerName(c"evaluatedPolicyDomainState".as_ptr()),
            )
        }
    }
}
