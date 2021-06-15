//! serde-serializable shared key.

use crate::AsSharedKey;
use serde::{Deserialize, Serialize};

use crate::{serialize::impls::CborSerializer, traits::SerdeEncryptPublicKey};

/// 32-byte key shared among sender and receiver secretly.
///
/// It is a good practice to use [SerdeEncryptPublicKey](crate::traits::SerdeEncryptPublicKey)
/// to exchange this shared key.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub struct SharedKey([u8; 32]);

impl AsSharedKey for SharedKey {
    fn from_array(key: [u8; 32]) -> Self {
        Self(key)
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl SerdeEncryptPublicKey for SharedKey {
    type S = CborSerializer<Self>;
}
