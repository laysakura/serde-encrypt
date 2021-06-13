# serde-encrypt

[![crates.io](https://img.shields.io/crates/v/serde-encrypt.svg)](https://crates.io/crates/serde-encrypt)
[![CI](https://github.com/laysakura/serde-encrypt/workflows/CI/badge.svg?branch=main)](https://github.com/laysakura/serde-encrypt/actions)
[![Crates.io](https://img.shields.io/crates/d/serde-encrypt?label=cargo%20installs)](https://crates.io/crates/serde-encrypt)
![MSRV](https://img.shields.io/badge/rustc-1.51+-lightgray.svg)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/laysakura/serde-encrypt/blob/master/LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](https://github.com/laysakura/serde-encrypt/blob/master/LICENSE-APACHE)

:closed_lock_with_key: **Encrypts all the `Serialize`.**

```text
               Alice                                         Bob
+-----------------------------------+        +-----------------------------------+
| #[derive(Serialize, Deserialize)] |        | #[derive(Serialize, Deserialize)] |
| struct Message {}                 |        | struct Message {}                 |
+-----------------------------------+        +-----------------------------------+
                 | .encrypt()                                  ^
                 v                                             | ::decrypt()
+-----------------------------------+        +-----------------------------------+
| struct EncryptedMessage           |        | struct EncryptedMessage           |
+-----------------------------------+        +-----------------------------------+
                 | .serialize()                                ^
                 v                                             | ::deserialize()
+-----------------------------------+        +-----------------------------------+
| struct Vec<u8>                    | -----> | struct Vec<u8>                    |
+-----------------------------------+        +-----------------------------------+
```

## Overview

serde-encrypt encrypts/decrypts any `strct`s and `enum`s that implements `serde::{Serialize, Deserialize`}.

serde-encrypt supports both **shared-key encryption** (XChaCha20Poly1305) and **public-key encryption** (X25519XChaCha20Poly1305), both of which are considered to be secure enough.

serde-encrypt is optionally available in **no_std** environments.

```toml Cargo.toml
[dependencies]
serde-encrypt = "(version)"  # If you use std
serde-encrypt = {version = "(version)", default-features = false}  # If you need no_std
```

## Example

If you and your peer already have shared-key, just implement `SerdeEncryptSharedKey` trait to your `Serialize` and `Deserialize` data types.

```rust
#[derive(Debug, Serialize, Deserialize)]
struct Message {
    content: String,
    sender: String,
}

impl SerdeEncryptSharedKey for Message {}
```

Then, you can serialize the `Message` into `Vec<u8>` in encrypted form.

```rust
    let shared_key = [0u8; 32];  // or read from your filesystem?

    let msg = Message {
        content: "I ❤️ you.".to_string(),
        sender: "Alice".to_string(),
    };
    let encrypted_message = msg.encrypt(&shared_key)?;
    let serialized_encrypted_message: Vec<u8> = encrypted_message.serialize()?;
```

After your peer gets the binary, he or she can decrypt and deserialize it to `Message`.

```rust
    let shared_key = [0u8; 32];  // or your peer reads from filesystem?

    let encrypted_message = EncryptedMessage::deserialize(serialized_encrypted_message)?;
    let msg = Message::decrypt_owned(&encrypted_message, &shared_key)
```

### Further examples...

- :eyes: [Encrypts struct with reference fields](https://github.com/laysakura/serde-encrypt/blob/main/tests/example_serde_encrypt_public_key_struct_with_reference.rs)
- :key: [Generates shared-key and safely exchange it to your peer. And then, encrypt/decrypt messages using the shared-key.](https://github.com/laysakura/serde-encrypt/blob/main/tests/example_serde_encrypt_shared_key_encryption_with_key_exchange.rs)
- :books: [Encrypts/Decrypts complex serde types](https://github.com/laysakura/serde-encrypt/blob/main/tests/feat_serde_encrypt_public_key_message_types.rs)

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in serde-encrypt by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
