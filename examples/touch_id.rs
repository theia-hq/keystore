//! A key file locked with `touch-id`, on this Mac's Secure Enclave, opened with a touch.
//!
//! ```text
//! cargo run --example touch_id -- <path>
//! ```
//!
//! With nothing at `<path>`, it writes a new device key there sealed under a `touch-id` lock, so the
//! key is never on disk plain; the new file is proven by opening it through the lock, which asks for
//! one touch. Then, and on every later run, it lists the file's locks, says which can open on this
//! Mac without asking for anything, and opens the key with a touch. Run it at an unlocked Mac with
//! Touch ID set up. Delete `<path>` to start again.

use keystore::{Health, KeyFile, Protection, Secret, Stored, Unlock};

fn main() -> Result<(), Box<dyn core::error::Error>> {
    let Some(path) = std::env::args_os().nth(1) else {
        return Err("usage: touch_id <path>".into());
    };
    let file = KeyFile::device(path);

    if file.load()?.is_none() {
        file.write(
            &Secret::generate()?,
            Protection::TouchId {
                reason: "confirm the new touch-id lock opens this test key",
            },
        )?;
        println!("wrote a new device key and locked it with touch-id");
    }

    let Some(Stored::Locked(locked)) = file.load()? else {
        return Err("the key file has no lock".into());
    };
    for method in locked.methods() {
        let here = match locked.health(method) {
            Some(Health::Live) => "can open on this Mac",
            Some(Health::Unchecked) => "could not be checked now",
            Some(Health::Dead) | None => "cannot open on this Mac",
        };
        println!("{method} lock: {here}");
    }

    let secret = locked.unlock(Unlock::TouchId {
        reason: "open this test key",
    })?;
    // The unlock already refuses a file whose header names another key; this shows it held.
    assert_eq!(secret.public_key(), locked.public_key());
    println!("opened the key with a touch");
    Ok(())
}
