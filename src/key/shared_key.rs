//! Keys for common key cryptosystem.

use chacha20poly1305::Key as ChaChaKey;
use serde::{Deserialize, Serialize};

/// 32-byte key shared among sender and receiver secretly.
///
/// It is a good practice to use [SerdeEncryptPublicKey](crate::traits::SerdeEncryptPublicKey)
/// to exchange this shared key.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub struct SharedKey([u8; 32]);

impl SharedKey {
    /// Constructor from known secret bytes.
    ///
    pub fn from_array(key: [u8; 32]) -> Self {
        Self(key)
    }

    pub(crate) fn to_chacha_key(&self) -> &ChaChaKey {
        ChaChaKey::from_slice(&self.0)
    }
}
