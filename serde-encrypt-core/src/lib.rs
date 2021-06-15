//! Core implementation of serde-encrypt crate.
//!
//! This crate is serde agnostic because:
//!
//! - serde cannot be easily build in some environment (e.g. rust-sgx-sdk),
//! - so it is nice to manage serde dependency in thin layer (serde-encrypt crate here) in order to build core logic easily.

#![deny(missing_debug_implementations, missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        use once_cell::sync::Lazy;
        use std::{sync::{MutexGuard, Mutex}, ops::DerefMut};
    } else if #[cfg(feature = "use-spin")] {
        use spin::{Lazy, MutexGuard, Mutex};
        use core::ops::DerefMut;
    } else {
        compile_error!("serde-encrypt-core crate cannot built without any of these feature flat: std, use-spin, sgx");
    }
}

pub mod encrypt;
pub mod error;
pub mod key;

pub(crate) mod random;
