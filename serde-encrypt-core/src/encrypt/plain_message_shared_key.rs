//! Shared key encryption.

use core::ops::DerefMut;

use crate::{error::Error, key::shared_key_core::SharedKeyCore, random::global_rng};
use alloc::{format, vec::Vec};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use crypto_box::aead::{Aead, NewAead};

use super::encrypted_message::EncryptedMessage;

/// Plain message structure serialized via serde.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PlainMessageSharedKey(Vec<u8>);

impl PlainMessageSharedKey {
    /// Encrypt into EncryptedMessage
    pub fn encrypt(&self, shared_key: &SharedKeyCore) -> Result<EncryptedMessage, Error> {
        let nonce = Self::generate_nonce();
        let chacha = XChaCha20Poly1305::new(shared_key.to_chacha_key());

        let encrypted = chacha.encrypt(&nonce, self.0.as_ref()).map_err(|e| {
            Error::encryption_error(&format!(
                "failed to encrypt serialized data by XChaCha20: {:?}",
                e
            ))
        })?;

        Ok(EncryptedMessage::new(encrypted, nonce.into()))
    }

    /// Decrypt from EncryptedMessage
    pub fn decrypt(
        encrypted_message: &EncryptedMessage,
        shared_key: &SharedKeyCore,
    ) -> Result<Self, Error> {
        let nonce = encrypted_message.nonce();
        let chacha = XChaCha20Poly1305::new(shared_key.to_chacha_key());

        let encrypted = encrypted_message.encrypted();

        let plain = chacha.decrypt(nonce.into(), encrypted).map_err(|e| {
            Error::decryption_error(&format!(
                "error on decryption of XChaCha20 cipher-text: {:?}",
                e
            ))
        })?;
        Ok(Self(plain))
    }

    fn generate_nonce() -> XNonce {
        let mut rng = global_rng().lock();
        crypto_box::generate_nonce(rng.deref_mut())
    }
}

impl From<Vec<u8>> for PlainMessageSharedKey {
    fn from(plain: Vec<u8>) -> Self {
        Self(plain)
    }
}

impl From<PlainMessageSharedKey> for Vec<u8> {
    fn from(p: PlainMessageSharedKey) -> Self {
        p.0
    }
}
