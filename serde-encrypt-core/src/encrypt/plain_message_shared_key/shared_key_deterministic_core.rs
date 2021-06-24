//! Shared key deterministic encryption.

use crate::{
    encrypt::encrypted_message::EncryptedMessage, error::Error, key::as_shared_key::AsSharedKey,
};
use alloc::vec::Vec;
use chacha20poly1305::XNonce;

use super::{decrypt, encrypt};

const FIXED_NONCE: [u8; 24] = [255; 24];

/// Plain message structure serialized via serde.
pub trait PlainMessageSharedKeyDeterministicCore {
    /// Constructor
    fn new(plain_message: Vec<u8>) -> Self
    where
        Self: Sized;

    /// Raw representation
    fn into_vec(self) -> Vec<u8>;

    /// Ref to raw representation
    fn as_slice(&self) -> &[u8];

    /// Encrypt into EncryptedMessage
    fn encrypt<S>(&self, shared_key: &S) -> Result<EncryptedMessage, Error>
    where
        S: AsSharedKey,
    {
        let nonce = Self::generate_nonce();
        encrypt(self.as_slice(), shared_key, nonce)
    }

    /// Decrypt from EncryptedMessage
    fn decrypt<S>(encrypted_message: &EncryptedMessage, shared_key: &S) -> Result<Self, Error>
    where
        Self: Sized,
        S: AsSharedKey,
    {
        let plain = decrypt(encrypted_message, shared_key)?;
        Ok(Self::new(plain))
    }

    /// Generate fixed nonce to enable eq-match in cipher-text.
    /// Note that is more vulnerable than generating random nonce (which [PlainMessageSharedKeyCore](crate::encrypt::plain_message_shared_key::PlainMessageSharedKeyCore) does).
    fn generate_nonce() -> XNonce {
        *XNonce::from_slice(&FIXED_NONCE)
    }
}
