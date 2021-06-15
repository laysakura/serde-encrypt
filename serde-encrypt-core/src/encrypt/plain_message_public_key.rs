//! Shared key encryption.

use crate::DerefMut;
use crate::{
    error::Error,
    key::combined_key::{ReceiverCombinedKey, SenderCombinedKey},
    random::global_rng,
};
use alloc::vec::Vec;
use chacha20poly1305::{aead::Payload, XNonce};
use crypto_box::{aead::Aead, ChaChaBox};

use super::encrypted_message::EncryptedMessage;

/// Plain message structure serialized via serde.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PlainMessagePublicKey(Vec<u8>);

impl PlainMessagePublicKey {
    /// Encrypt into EncryptedMessage
    pub fn encrypt(&self, combined_key: &SenderCombinedKey) -> Result<EncryptedMessage, Error> {
        let nonce = Self::generate_nonce();
        let sender_box = ChaChaBox::new(
            combined_key.receiver_public_key().as_ref(),
            combined_key.sender_private_key().as_ref(),
        );

        // TODO https://github.com/laysakura/serde-encrypt/issues/19
        let aad = b"".as_ref();

        let encrypted = sender_box
            .encrypt(&nonce, Payload { msg: &self.0, aad })
            .map_err(|_| {
                Error::encryption_error("failed to encrypt serialized data into ChaChaBox")
            })?;

        Ok(EncryptedMessage::new(encrypted, nonce.into()))
    }

    /// Decrypt from EncryptedMessage
    pub fn decrypt(
        encrypted_message: &EncryptedMessage,
        combined_key: &ReceiverCombinedKey,
    ) -> Result<Self, Error> {
        let receiver_box = ChaChaBox::new(
            combined_key.sender_public_key().as_ref(),
            combined_key.receiver_private_key().as_ref(),
        );

        let nonce = encrypted_message.nonce();
        let encrypted = encrypted_message.encrypted();

        let serial_plain = receiver_box
            .decrypt(nonce.into(), encrypted)
            .map_err(|_| Error::decryption_error("error on decryption of ChaChaBox"))?;

        Ok(Self(serial_plain))
    }

    fn generate_nonce() -> XNonce {
        let mut rng = global_rng();
        crypto_box::generate_nonce(rng.deref_mut())
    }
}

impl From<Vec<u8>> for PlainMessagePublicKey {
    fn from(plain: Vec<u8>) -> Self {
        Self(plain)
    }
}

impl From<PlainMessagePublicKey> for Vec<u8> {
    fn from(p: PlainMessagePublicKey) -> Self {
        p.0
    }
}
