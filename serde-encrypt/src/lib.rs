//! serde-encrypt encrypts/decrypts any `strct`s and `enum`s that implements `serde::{Serialize, Deserialize`}.
//!
//! See [README.md](https://github.com/laysakura/serde-encrypt) for basic usage and implementation details.

#![deny(missing_debug_implementations, missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod encrypt;
pub mod key;
pub mod serialize;
pub mod shared_key;
pub mod traits;

mod random;

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        use once_cell::sync::Lazy;
        use std::sync::{MutexGuard, Mutex};
    } else {
        use spin::{Lazy, MutexGuard, Mutex};
    }
}

pub use serde_encrypt_core::{
    encrypt::encrypted_message::EncryptedMessage,
    error::{Error, ErrorKind},
    key::{
        as_shared_key::AsSharedKey,
        combined_key::{ReceiverCombinedKey, SenderCombinedKey},
        key_pair::{ReceiverKeyPairCore, SenderKeyPairCore},
    },
};
