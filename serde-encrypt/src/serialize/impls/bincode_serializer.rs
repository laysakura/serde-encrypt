use crate::{serialize::TypedSerialized, Error};
use alloc::{format, vec::Vec};
use core::marker::PhantomData;
use serde::{Deserialize, Serialize};

/// [bincode](https://docs.rs/bincode) serializer
#[derive(Debug)]
pub struct BincodeSerializer<T> {
    serialized: Vec<u8>,
    _type: PhantomData<T>,
}

impl<T> TypedSerialized for BincodeSerializer<T> {
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

    fn serialize(v: &Self::T) -> Result<Self, Error>
    where
        Self: Sized,
        Self::T: Serialize,
    {
        let serialized = bincode::serialize(v).map_err(|e| {
            Error::serialization_error(&format!("failed to serialize data by bincode: {:?}", e))
        })?;
        Ok(Self::new(serialized))
    }

    fn deserialize<'de>(&'de self) -> Result<Self::T, Error>
    where
        Self::T: Deserialize<'de>,
    {
        bincode::deserialize(self.as_slice()).map_err(|e| {
            Error::deserialization_error(&format!(
                "error on bincode deserialization after decryption: {:?}",
                e
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bincode_serializer() -> Result<(), Error> {
        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        struct Message(i32);

        let msg = Message(42);

        let serialized_msg = BincodeSerializer::serialize(&msg)?;
        let deserialized_msg = serialized_msg.deserialize()?;

        assert_eq!(msg, deserialized_msg);

        Ok(())
    }
}
