//! Shared key encryption.

use core::ops::DerefMut;

use crate::{
    error::Error,
    key::combined_key::{ReceiverCombinedKey, SenderCombinedKey},
    random::RngSingleton,
};
use alloc::vec::Vec;
use chacha20poly1305::{aead::Payload, XNonce};
use crypto_box::{aead::Aead, ChaChaBox};

use super::encrypted_message::EncryptedMessage;

/// Plain message structure serialized via serde.
pub trait PlainMessagePublicKeyCore {
    /// RNG singleton
    type R: RngSingleton;

    /// Constructor
    fn new(plain_message: Vec<u8>) -> Self
    where
        Self: Sized;

    /// Raw representation
    fn into_vec(self) -> Vec<u8>;

    /// Ref to raw representation
    fn as_slice(&self) -> &[u8];

    /// Encrypt into EncryptedMessage
    fn encrypt(&self, combined_key: &SenderCombinedKey) -> Result<EncryptedMessage, Error> {
        let nonce = Self::generate_nonce();
        let sender_box = ChaChaBox::new(
            combined_key.receiver_public_key().as_ref(),
            combined_key.sender_private_key().as_ref(),
        );

        // TODO https://github.com/laysakura/serde-encrypt/issues/19
        let aad = b"".as_ref();

        let encrypted = sender_box
            .encrypt(
                &nonce,
                Payload {
                    msg: self.as_slice(),
                    aad,
                },
            )
            .map_err(|_| {
                Error::encryption_error("failed to encrypt serialized data into ChaChaBox")
            })?;

        Ok(EncryptedMessage::new(encrypted, nonce.into()))
    }

    /// Decrypt from EncryptedMessage
    fn decrypt(
        encrypted_message: &EncryptedMessage,
        combined_key: &ReceiverCombinedKey,
    ) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let receiver_box = ChaChaBox::new(
            combined_key.sender_public_key().as_ref(),
            combined_key.receiver_private_key().as_ref(),
        );

        let nonce = encrypted_message.nonce();
        let encrypted = encrypted_message.encrypted();

        let serial_plain = receiver_box
            .decrypt(nonce.into(), encrypted)
            .map_err(|_| Error::decryption_error("error on decryption of ChaChaBox"))?;

        Ok(Self::new(serial_plain))
    }

    /// Generate random nonce which is large enough (24-byte) to rarely conflict.
    fn generate_nonce() -> XNonce {
        let mut rng = Self::R::instance();
        crypto_box::generate_nonce(rng.deref_mut())
    }
}
