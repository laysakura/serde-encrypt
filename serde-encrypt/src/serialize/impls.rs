//! Serializer implementations.

use crate::Error;
use alloc::{format, vec::Vec};
use core::marker::PhantomData;
use serde::{Deserialize, Serialize};

use super::TypedSerialized;

/// CBOR serializer
#[derive(Debug)]
pub struct CborSerializer<T> {
    serialized: Vec<u8>,
    _type: PhantomData<T>,
}

impl<T> TypedSerialized for CborSerializer<T> {
    type T = T;

    fn new(serialized: Vec<u8>) -> Self
    where
        Self: Sized,
    {
        Self {
            serialized,
            _type: PhantomData::default(),
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.serialized
    }

    fn into_vec(self) -> Vec<u8> {
        self.serialized
    }

    /// # Failures
    ///
    /// - [SerializationError](serde_encrypt_core::error::ErrorKind::SerializationError) when failed to serialize message.
    fn serialize(v: &Self::T) -> Result<Self, Error>
    where
        Self: Sized,
        Self::T: Serialize,
    {
        let serialized = serde_cbor::to_vec(v).map_err(|e| {
            Error::serialization_error(&format!("failed to serialize data by serde_cbor: {:?}", e))
        })?;
        Ok(Self::new(serialized))
    }

    /// # Failures
    ///
    /// - [DeserializationError](serde_encrypt_core::error::ErrorKind::DeserializationError) when failed to deserialize decrypted message.
    fn deserialize<'de>(&'de self) -> Result<Self::T, Error>
    where
        Self::T: Deserialize<'de>,
    {
        serde_cbor::from_slice(self.as_slice()).map_err(|e| {
            Error::deserialization_error(&format!(
                "error on serde_cbor deserialization after decryption: {:?}",
                e
            ))
        })
    }
}
