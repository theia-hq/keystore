# keystore-enclave

A P-256 key in a Mac's Secure Enclave, kept as a blob in your own file, that does ECDH only after a
touch of an enrolled finger. The crate is empty on every target but macOS.

## Use

```toml
[target.'cfg(target_os = "macos")'.dependencies]
keystore-enclave = { git = "https://github.com/theia-hq/keystore" }
```

```rust
use keystore_enclave::{Policy, create, load};

let (blob, public) = create(Policy::BiometryCurrentSet)?; // keep both in your own file
let key = load(&blob, &public)?;
key.check()?; // this Mac's key, still guarded; no dialog
let secret = key.agree(&peer, "open your key")?; // asks for a touch
```

Adding or removing a finger stops the key opening until the fingers change back; keep another way in
to whatever it guards.

## License

MIT or Apache-2.0, at your option.
