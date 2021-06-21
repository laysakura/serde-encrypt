//! Shared key deterministic encryption.

use super::encrypted_message::EncryptedMessage;

use crate::{error::Error, key::as_shared_key::AsSharedKey};
use alloc::{format, vec::Vec};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use crypto_box::aead::{Aead, NewAead};

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
        let chacha = XChaCha20Poly1305::new(shared_key.to_chacha_key());

        let encrypted = chacha.encrypt(&nonce, self.as_slice()).map_err(|e| {
            Error::encryption_error(&format!(
                "failed to encrypt serialized data by XChaCha20: {:?}",
                e
            ))
        })?;

        Ok(EncryptedMessage::new(encrypted, nonce.into()))
    }

    /// Decrypt from EncryptedMessage
    fn decrypt<S>(encrypted_message: &EncryptedMessage, shared_key: &S) -> Result<Self, Error>
    where
        Self: Sized,
        S: AsSharedKey,
    {
        let nonce = encrypted_message.nonce();
        let chacha = XChaCha20Poly1305::new(shared_key.to_chacha_key());

        let encrypted = encrypted_message.encrypted();

        let plain = chacha.decrypt(nonce.into(), encrypted).map_err(|e| {
            Error::decryption_error(&format!(
                "error on decryption of XChaCha20 cipher-text: {:?}",
                e
            ))
        })?;
        Ok(Self::new(plain))
    }

    /// Generate fixed nonce to enable eq-match in cipher-text.
    /// Note that is more vulnerable than generating random nonce (which [PlainMessageSharedKey](super::plain_message_shared_key::PlainMessageSharedKey) does).
    fn generate_nonce() -> XNonce {
        *XNonce::from_slice(&FIXED_NONCE)
    }
}
