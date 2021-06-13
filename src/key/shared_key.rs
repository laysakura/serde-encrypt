//! Keys for common key cryptosystem.

use chacha20poly1305::Key as ChaChaKey;

/// 32-byte key shared among sender and receiver secretly.
///
/// It is a good practice to use [SerdeEncryptPublicKey](crate::traits::SerdeEncryptPublicKey)
/// to exchange this shared key.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct SharedKey(ChaChaKey);

impl SharedKey {
    /// Constructor from known secret bytes.
    ///
    /// # Panics
    ///
    /// - If `key_32bytes` is not 32-byte.
    pub fn from_slice(key_32bytes: &[u8]) -> Self {
        assert_eq!(key_32bytes.len(), 32);
        Self(*ChaChaKey::from_slice(key_32bytes))
    }
}
