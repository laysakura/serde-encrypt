pub mod impls;

use crate::Error;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

pub trait TypedSerialized {
    type T;

    fn new(serialized: Vec<u8>) -> Self
    where
        Self: Sized;

    fn as_slice(&self) -> &[u8];

    fn into_vec(self) -> Vec<u8>;

    fn serialize(v: &Self::T) -> Result<Self, Error>
    where
        Self: Sized,
        Self::T: Serialize;

    fn deserialize<'de>(&'de self) -> Result<Self::T, Error>
    where
        Self::T: Deserialize<'de>;
}
