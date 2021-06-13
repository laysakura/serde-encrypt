//! serde-encrypt encrypts/decrypts any `strct`s and `enum`s that implements `serde::{Serialize, Deserialize`}.
//!
//! # Feature comparison
//!
//! |                       | `SerdeEncryptSharedKey` | `SerdeEncryptPublicKey` |
//! | --------------------- | ----------------------- | ----------------------- |
//! | (a)symmetric?         | symmetric               | asymmetric              |
//! | deterministic? _(*1)_ | no                      | no                      |
//! | performance           | high                    | low                     |
//!
//! (*1) Deterministic encryptions always produce the same cipher-text from a given plain-text. Usable for equal-matching in cipher-text (e.g. RDBMS's encrypted index eq-search).
//!
//! # Encryption algorithm
//!
//! |                      | `SerdeEncryptSharedKey`                                                              | `SerdeEncryptPublicKey`                                                              |
//! | -------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------ |
//! | key exchange         | -                                                                                    | X25519                                                                               |
//! | encryption           | XChaCha20                                                                            | XChaCha20                                                                            |
//! | message auth         | Poly1305                                                                             | Poly1305                                                                             |
//! | nonce _(*2)_         | XSalsa20 (random 24-byte)                                                            | XSalsa20 (random 24-byte)                                                            |
//! | Rng _(*3)_ for nonce | [ChaCha20Rng](https://docs.rs/rand_chacha/0.3.1/rand_chacha/struct.ChaCha12Rng.html) | [ChaCha20Rng](https://docs.rs/rand_chacha/0.3.1/rand_chacha/struct.ChaCha12Rng.html) |
//!
//! (*2) "Number used once": to make encryption non-deterministic. Although nonce for each encryption is not secret, nonce among different encryption must be different in order for attackers to harder to guess plain-text.
//! (*3) Random number generator.
//!
//! # Serialization
//!
//! |               | `SerdeEncryptSharedKey`                               | `SerdeEncryptPublicKey`                               |
//! | ------------- | ----------------------------------------------------- | ----------------------------------------------------- |
//! | serialization | [CBOR](https://docs.rs/serde_cbor/0.11.1/serde_cbor/) | [CBOR](https://docs.rs/serde_cbor/0.11.1/serde_cbor/) |
//!
//! # Use cases
//!
//! - `SerdeEncryptedSharedKey`
//!   - Both message sender and receiver already hold shared key.
//!   - Needs shared-key exchange via any safe way but wants high-speed encryption/decryption (e.g. communicates large amounts of messages).
//! - `SerdeEncryptedSharedKey`
//!   - To exchange `SharedKey`.
//!   - Quickly sends/receive small amounts of messages without secret shared key.

#![deny(missing_debug_implementations, missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod error;
pub mod key;
pub mod msg;
pub mod traits;

pub(crate) mod random;
