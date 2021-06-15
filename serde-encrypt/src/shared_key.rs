//! serde-serializable shared key.

use serde::{Deserialize, Serialize};
use serde_encrypt_core::key::shared_key_core::SharedKeyCore;

use crate::traits::SerdeEncryptPublicKey;

/// 32-byte key shared among sender and receiver secretly.
///
/// It is a good practice to use [SerdeEncryptPublicKey](crate::traits::SerdeEncryptPublicKey)
/// to exchange this shared key.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub struct SharedKey([u8; 32]);

impl SharedKey {
    /// Constructor from known secret bytes.
    pub fn from_array(key: [u8; 32]) -> Self {
        Self(key)
    }

    /// Generates secure random key.
    ///
    /// Random number generator which implements `CryptRng` is used internally.
    pub fn generate() -> Self {
        let shared_key_core = SharedKeyCore::generate();
        Self(shared_key_core.into_array())
    }

    pub(crate) fn to_shared_key_core(&self) -> SharedKeyCore {
        let key = self.0;
        SharedKeyCore::from_array(key)
    }
}

impl SerdeEncryptPublicKey for SharedKey {}
