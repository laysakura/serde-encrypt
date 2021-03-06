# serde-encrypt

[![crates.io](https://img.shields.io/crates/v/serde-encrypt.svg)](https://crates.io/crates/serde-encrypt)
[![Crates.io](https://img.shields.io/crates/d/serde-encrypt?label=cargo%20installs)](https://crates.io/crates/serde-encrypt)
[![docs.rs](https://img.shields.io/badge/API%20doc-docs.rs-blueviolet)](https://docs.rs/serde-encrypt)
![MSRV](https://img.shields.io/badge/rustc-1.49+-lightgray.svg)
[![ci](https://github.com/laysakura/serde-encrypt/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/laysakura/serde-encrypt/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/laysakura/serde-encrypt/branch/main/graph/badge.svg?token=XI0IR5QVU3)](https://codecov.io/gh/laysakura/serde-encrypt)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/laysakura/serde-encrypt/blob/master/LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](https://github.com/laysakura/serde-encrypt/blob/master/LICENSE-APACHE)

![serde-encrypt logo](https://user-images.githubusercontent.com/498788/122903416-58946580-d38a-11eb-836d-58ef02128334.png)

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

serde-encrypt encrypts/decrypts any `struct`s and `enum`s that implements `serde::{Serialize, Deserialize`}.

serde-encrypt supports both **shared-key encryption** (XChaCha20-Poly1305) and **public-key encryption** (XChaCha20-Poly1305 with X25519 key-exchange), both of which are considered to be secure enough.

serde-encrypt is optionally available in **no_std** environments.

```toml Cargo.toml
[dependencies]
serde-encrypt = "(version)"  # If you use std
serde-encrypt = {version = "(version)", default-features = false}  # If you need no_std
```

## Example

Good first example from [shared key encryption test](https://github.com/laysakura/serde-encrypt/blob/main/serde-encrypt/tests/example_serde_encrypt_shared_key_owned_data.rs).

If you and your peer already have shared-key, just implement `SerdeEncryptSharedKey` trait to your `Serialize` and `Deserialize` data types.

```rust
#[derive(Debug, Serialize, Deserialize)]
struct Message {
    content: String,
    sender: String,
}

impl SerdeEncryptSharedKey for Message {
    type S = BincodeSerializer<Self>;  // you can specify serializer implementation (or implement it by yourself).
}
```

Then, you can serialize the `Message` into `Vec<u8>` in encrypted form.

```rust
    // Alternative:
    // const SHARED_KEY: SharedKey = SharedKey::new_const([0u8; 32]); 
    let shared_key = SharedKey::new([0u8; 32]); // or your peer reads from elsewhere.

    let msg = Message {
        content: "I ❤️ you.".to_string(),
        sender: "Alice".to_string(),
    };
    let encrypted_message = msg.encrypt(&shared_key)?;
    let serialized_encrypted_message: Vec<u8> = encrypted_message.serialize();
```

After your peer gets the binary, they can decrypt and deserialize it to `Message`.

```rust
    let shared_key = SharedKey::new([0u8; 32]);

    let encrypted_message = EncryptedMessage::deserialize(serialized_encrypted_message)?;
    let msg = Message::decrypt_owned(&encrypted_message, &shared_key);
```

### Further examples...

- 👀 [Encrypts struct with reference fields](https://github.com/laysakura/serde-encrypt/blob/main/serde-encrypt/tests/example_serde_encrypt_public_key_struct_with_reference.rs)
- 🔑 [Generates shared-key and safely exchange it to your peer. And then, encrypt/decrypt messages using the shared-key.](https://github.com/laysakura/serde-encrypt/blob/main/serde-encrypt/tests/example_serde_encrypt_shared_key_encryption_with_key_exchange.rs)
- 📚 [Encrypts/Decrypts complex serde types](https://github.com/laysakura/serde-encrypt/blob/main/serde-encrypt/tests/feat_serde_types.rs)

## Features and uses cases

### Feature comparison

|                       | `SerdeEncryptSharedKey` | `SerdeEncryptSharedKeyDeterministic` | `SerdeEncryptPublicKey` |
| --------------------- | ----------------------- | ------------------------------------ | ----------------------- |
| (a)symmetric?         | symmetric               | symmetric                            | asymmetric              |
| deterministic? _(*1)_ | no                      | yes                                  | no                      |
| performance           | high                    | high                                 | low                     |

_(*1) Deterministic encryptions always produce the same cipher-text from a given plain-text. More vulnerable but useful for equal-matching in cipher-text (e.g. RDBMS's encrypted index eq-search)._

### Encryption algorithm

|                      | `SerdeEncryptSharedKey`                                                                                    | `SerdeEncryptSharedKeyDeterministic`                                                                       | `SerdeEncryptPublicKey`                                                              |
| -------------------- | ---------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| key exchange         | -                                                                                                          | -                                                                                                          | X25519                                                                               |
| encryption           | XChaCha20                                                                                                  | XChaCha20                                                                                                  | XChaCha20                                                                            |
| message auth         | Poly1305                                                                                                   | Poly1305                                                                                                   | Poly1305                                                                             |
| nonce _(*2)_         | XSalsa20 (random 24-byte)                                                                                  | Fixed 24-byte                                                                                              | XSalsa20 (random 24-byte)                                                            |
| Rng _(*3)_ for nonce | [ChaCha20Rng](https://docs.rs/rand_chacha/0.3.1/rand_chacha/struct.ChaCha12Rng.html)                       | -                                                                                                          | [ChaCha20Rng](https://docs.rs/rand_chacha/0.3.1/rand_chacha/struct.ChaCha12Rng.html) |
| Implementation       | [XChaCha20Poly1305](https://docs.rs/chacha20poly1305/0.8.0/chacha20poly1305/struct.XChaCha20Poly1305.html) | [XChaCha20Poly1305](https://docs.rs/chacha20poly1305/0.8.0/chacha20poly1305/struct.XChaCha20Poly1305.html) | [ChaChaBox](https://docs.rs/crypto_box/0.6.0/crypto_box/struct.ChaChaBox.html)       |

_(*2) "Number used once": to make encryption non-deterministic. Although nonce for each encryption is not secret, nonce among different encryption must be different in order for attackers to get harder to guess plain-text._

_(*3) Random number generator._

### Serializer

Crate users can choose and even implement by themselves serialize representations in design.

Currently, the following serializers are built-in.

- `BincodeSerializer` (only `std` feature)
  - Best choice for `std` to reduce message size in most cases.
- `PostcardSerializer`
  - Best choice for no_std to reduce message size in most cases.
- `CborSerializer`
  - Has large message size but deals with complex serde types. See [Encrypts/Decrypts complex serde types example](https://github.com/laysakura/serde-encrypt/blob/main/serde-encrypt/tests/feat_serde_types.rs) to check kind of serde types only `CborSerializer` can serialize.
  - Single available choice in `serde-encrypt-sgx`.
    - Both bincode and postcard crates cannot compile with Rust SGX SDK

### Use cases

- `SerdeEncryptSharedKey`
  - Both message sender and receiver already hold shared key.
  - Needs shared-key exchange via any safe way but wants high-speed encryption/decryption (e.g. communicates large amounts of messages).
- `SerdeEncryptSharedKeyDeterministic`
  - Only when you need deterministic encryption for equal-matching in cipher-text.
  - Note that this is more vulnerable than `SerdeEncryptSharedKey` because, for example, attackers can find repeated patterns in cipher-text and then guess repeated patterns in plain-text.
- `SerdeEncryptPublicKey`
  - To exchange `SharedKey`.
  - Quickly sends/receive small amounts of messages without secret shared key.

### [Rust SGX SDK](https://github.com/apache/incubator-teaclave-sgx-sdk) support

Use [serde-encrypt-sgx](https://github.com/laysakura/serde-encrypt-sgx) crate.

### Feature flags

- `std` (`serde-encrypt` [default] ; `serde-encrypt-core` [default])
  - `std::error::Error` trait implementation to `serde_encrypt::Error`.
  - Random number generator is created via [`SeedableRng::from_entropy()`](https://rust-random.github.io/rand/rand_core/trait.SeedableRng.html#method.from_entropy), which is considered to be more secure in OS-available environments.
  - `BincodeSerializer` available.

## Implementation

### Crates

`serde-encrypt` is a cargo workspace project and two crates are inside:

- `serde-encrypt-core`
  - Encryption / Decryption implementations.
  - Traits for serialization / deserialization.
  - Traits for RNG (Random Number Generator) singleton.
- `serde-encrypt` (depends on `serde-encrypt-core`)
  - Serialization / Deserialization impls.
  - RNG singleton impls.

[`serde-encrypt-sgx` crate](https://github.com/laysakura/serde-encrypt-sgx) is also available in separate repository.
It's in the same layer as `serde-encrypt`.

In order to use serde with Rust SGX SDK, people should use forked version [serde-sgx](https://github.com/mesalock-linux/serde-sgx/).
Also, Rust SGX SDK compiles with only old version of rustc ([nightly-2020-10-25, currently](https://github.com/apache/incubator-teaclave-sgx-sdk/blob/ed9e7cce4fd40efd7a256d5c4be1c5f00778a5bb/dockerfile/Dockerfile.1804.nightly#L34)),
even simple no_std crate cannot build sometimes (e.g. [spin crate](https://docs.rs/spin) cannot).

It is another choice to make `serde-encrypt-sgx` inside this repository using feature flags but it breaks `cargo build --all-features` in latest rustc.

### Encryption

[crypto_box crate](https://docs.rs/crypto_box) is used both for public-key encryption and shared-key encryption.

> Pure Rust implementation of the crypto_box public-key authenticated encryption scheme from NaCl-family libraries (e.g. libsodium, TweetNaCl) which combines the X25519 Diffie-Hellman function and the XSalsa20Poly1305 authenticated encryption cipher into an Elliptic Curve Integrated Encryption Scheme (ECIES).

### Serialization

`struct`s and `enum`s to encrypt are serialized before encrypted.
Built-in serializers are listed [here](#serializer).

Users can also implement [TypedSerialized trait](https://docs.rs/serde-encrypt/0.3.2/serde_encrypt/serialize/trait.TypedSerialized.html) by themselves
to get better serialization.

## Changelog

See [CHANGELOG.md](https://github.com/laysakura/serde-encrypt/blob/master/CHANGELOG.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in serde-encrypt by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
