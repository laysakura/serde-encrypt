//! [Rust SGX SDK](https://github.com/apache/incubator-teaclave-sgx-sdk) compatible version of
//! `serde-encrypt` crate.
//!
//! Since [serde-sgx](https://github.com/mesalock-linux/serde-sgx) does not compile in standard environment
//! (needs Edger8r tool and require old version of nightly rustc, etc),
//! this crate is excluded from cargo workspace.
//!
//! APIs are supposed to be the same as `serde-encrypt`. Please refer to `serde-encrypt`'s API documentation.

#![deny(missing_debug_implementations)]
#![no_std]

extern crate alloc;

pub mod serialize;
pub mod shared_key;
pub mod traits;

pub use serde_encrypt_core::{
    encrypt::encrypted_message::EncryptedMessage,
    error::{Error, ErrorKind},
    key::{
        as_shared_key::AsSharedKey,
        combined_key::{ReceiverCombinedKey, SenderCombinedKey},
        key_pair::{ReceiverKeyPair, SenderKeyPair},
    },
};
