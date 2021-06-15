//! Serializer trait and default implementation.

pub mod impls;

use crate::Error;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Serialization abstract with type to serialize.
///
/// Serializer implementations must implement this trait.
pub trait TypedSerialized {
    /// Type to serialize
    type T;

    /// Constructor
    fn new(serialized: Vec<u8>) -> Self
    where
        Self: Sized;

    /// Ref to serialized.
    fn as_slice(&self) -> &[u8];

    /// Into serialized.
    fn into_vec(self) -> Vec<u8>;

    /// # Failures
    ///
    /// - [SerializationError](serde_encrypt_core::error::ErrorKind::SerializationError) when failed to serialize message.
    fn serialize(v: &Self::T) -> Result<Self, Error>
    where
        Self: Sized,
        Self::T: Serialize;

    /// # Failures
    ///
    /// - [DeserializationError](serde_encrypt_core::error::ErrorKind::DeserializationError) when failed to deserialize decrypted message.
    fn deserialize<'de>(&'de self) -> Result<Self::T, Error>
    where
        Self::T: Deserialize<'de>;
}
