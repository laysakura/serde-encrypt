//! serde-encrypt encrypts/decrypts any `strct`s and `enum`s that implements `serde::{Serialize, Deserialize`}.
//!
//! See [README.md](https://github.com/laysakura/serde-encrypt) for basic usage and implementation details.

#![deny(missing_debug_implementations, missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod shared_key;
pub mod traits;