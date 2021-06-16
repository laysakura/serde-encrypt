//! Core implementation of serde-encrypt crate.
//!
//! This crate is serde agnostic because:
//!
//! - serde cannot be easily build in some environment (e.g. rust-sgx-sdk),
//! - so it is nice to manage serde dependency in thin layer (serde-encrypt crate here) in order to build core logic easily.
//!
//! Normally, users do not depend on this crate directly.

#![deny(missing_debug_implementations, missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod encrypt;
pub mod error;
pub mod key;
pub mod random;
