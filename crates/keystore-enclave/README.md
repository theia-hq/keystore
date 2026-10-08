# keystore-enclave

A P-256 key in a Mac's Secure Enclave, kept as a blob in your own file, that does ECDH only after a
touch of an enrolled finger. The crate is empty on every target but macOS.

## Use

```toml
[target.'cfg(target_os = "macos")'.dependencies]
keystore-enclave = { git = "https://github.com/theia-hq/keystore" }
```

```rust
use core::time::Duration;

use keystore_enclave::{Error, Policy, create, load};

fn open(peer: &[u8; 65]) -> Result<(), Error> {
    let (blob, public) = create(Policy::BiometryCurrentSet)?; // keep both in your own file
    let key = load(&blob, &public)?;
    key.check()?; // opens on this Mac and still asks for a touch; no dialog
    let secret = key.agree(peer, "open your key", Duration::from_secs(60))?; // asks for a touch
    Ok(())
}
```

After a finger is added or removed, the key does not open; it opens again once a finger you added
is removed. Keep another way in to whatever it guards.

## License

MIT or Apache-2.0, at your option.
