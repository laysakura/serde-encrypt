# serde-encrypt

[![crates.io](https://img.shields.io/crates/v/serde-encrypt.svg)](https://crates.io/crates/serde-encrypt)
[![Crates.io](https://img.shields.io/crates/d/serde-encrypt?label=cargo%20installs)](https://crates.io/crates/serde-encrypt)
[![docs.rs](https://img.shields.io/badge/API%20doc-docs.rs-blueviolet)](https://docs.rs/serde-encrypt)
![MSRV](https://img.shields.io/badge/rustc-1.49+-lightgray.svg)
[![ci](https://github.com/laysakura/serde-encrypt/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/laysakura/serde-encrypt/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/laysakura/serde-encrypt/branch/main/graph/badge.svg?token=XI0IR5QVU3)](https://codecov.io/gh/laysakura/serde-encrypt)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/laysakura/serde-encrypt/blob/master/LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](https://github.com/laysakura/serde-encrypt/blob/master/LICENSE-APACHE)

🔐 **Encrypts all the `Serialize`.**

```text
               Alice                                         Bob
+-----------------------------------+        +-----------------------------------+
| #[derive(Serialize, Deserialize)] |        | #[derive(Serialize, Deserialize)] |
| struct Message                    |        | struct Message                    |
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

serde-encrypt supports both **shared-key encryption** (XChaCha20-Poly1305) and **public-key encryption** (XChaCha20-Poly1305 with X25513 key-exchange), both of which are considered to be secure enough.

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

impl SerdeEncryptSharedKey for Message {
    type S = CborSerializer<Self>;  // you can specify serializer implementation (or implement it by yourself).
}
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

- 👀 [Encrypts struct with reference fields](https://github.com/laysakura/serde-encrypt/blob/main/tests/example_serde_encrypt_public_key_struct_with_reference.rs)
- 🔑 [Generates shared-key and safely exchange it to your peer. And then, encrypt/decrypt messages using the shared-key.](https://github.com/laysakura/serde-encrypt/blob/main/tests/example_serde_encrypt_shared_key_encryption_with_key_exchange.rs)
- 📚 [Encrypts/Decrypts complex serde types](https://github.com/laysakura/serde-encrypt/blob/main/tests/feat_serde_types.rs)

## Features and uses cases

### Feature comparison

|                       | `SerdeEncryptSharedKey` | `SerdeEncryptPublicKey` |
| --------------------- | ----------------------- | ----------------------- |
| (a)symmetric?         | symmetric               | asymmetric              |
| deterministic? _(*1)_ | no                      | no                      |
| performance           | high                    | low                     |

_(*1) Deterministic encryptions always produce the same cipher-text from a given plain-text. Usable for equal-matching in cipher-text (e.g. RDBMS's encrypted index eq-search)._

### Encryption algorithm

|                      | `SerdeEncryptSharedKey`                                                                                    | `SerdeEncryptPublicKey`                                                              |
| -------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| key exchange         | -                                                                                                          | X25519                                                                               |
| encryption           | XChaCha20                                                                                                  | XChaCha20                                                                            |
| message auth         | Poly1305                                                                                                   | Poly1305                                                                             |
| nonce _(*2)_         | XSalsa20 (random 24-byte)                                                                                  | XSalsa20 (random 24-byte)                                                            |
| Rng _(*3)_ for nonce | [ChaCha20Rng](https://docs.rs/rand_chacha/0.3.1/rand_chacha/struct.ChaCha12Rng.html)                       | [ChaCha20Rng](https://docs.rs/rand_chacha/0.3.1/rand_chacha/struct.ChaCha12Rng.html) |
| Implementation       | [XChaCha20Poly1305](https://docs.rs/chacha20poly1305/0.8.0/chacha20poly1305/struct.XChaCha20Poly1305.html) | [ChaChaBox](https://docs.rs/crypto_box/0.6.0/crypto_box/struct.ChaChaBox.html)       |

_(*2) "Number used once": to make encryption non-deterministic. Although nonce for each encryption is not secret, nonce among different encryption must be different in order for attackers to get harder to guess plain-text._

_(*3) Random number generator._

### Serialization

Crate users can choose and even implement by themselves serialize representations in design.

Currently only `CborSerializer` (ref: [CBOR](https://docs.rs/serde_cbor/)) is built-in.

### Use cases

- `SerdeEncryptedSharedKey`
  - Both message sender and receiver already hold shared key.
  - Needs shared-key exchange via any safe way but wants high-speed encryption/decryption (e.g. communicates large amounts of messages).
- `SerdeEncryptedSharedKey`
  - To exchange `SharedKey`.
  - Quickly sends/receive small amounts of messages without secret shared key.

### [RUST SGX SDK](https://github.com/apache/incubator-teaclave-sgx-sdk) support

Use [serde-encrypt-sgx](https://github.com/laysakura/serde-encrypt-sgx) crate.

### Feature flags

- `std` (`serde-encrypt` [default] ; `serde-encrypt-core` [default])
  - `std::error::Error` trait implementation to `serde_encrypt::Error`.
  - Random number generator is created via [`SeedableRng::from_entropy()`](https://rust-random.github.io/rand/rand_core/trait.SeedableRng.html#method.from_entropy), which is considered to be more secure in OS-available environments.

## Changelog

See [CHANGELOG.md](https://github.com/laysakura/serde-encrypt/blob/master/CHANGELOG.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in serde-encrypt by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
