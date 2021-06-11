//! Traits to enable encrypted-serialization to your struct/enum.

use crate::{
    error::Error,
    key::combined_key::{ReceiverCombinedKey, SenderCombinedKey},
    msg::EncryptedMessage,
};
use alloc::{format, vec::Vec};
use crypto_box::{
    aead::{Aead, Payload},
    ChaChaBox,
};
use rand::SeedableRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Public-key authenticated encryption for serde-serializable types.
///
/// # Features
///
/// - Safe and bidirectional public-key exchange.
/// - Message authentication.
/// - Different cipher-text for the same plain-text to avoid attacks such as statistical analysis of cipher-text.
///
/// # Anti-features
///
/// - Identity authentication of sender nor receiver.
///
/// # Popular use cases
///
/// - Shared-key exchange.
/// - Encryption for relatively small and non-frequent messages (shared-key encryption is faster than public-key).
///
/// # Examples
///
/// ```
/// use serde_encrypt::traits::SerdeEncryptPublicKey;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct Message {
///     content: String,
///     sender: String,
/// }
///
/// impl SerdeEncryptPublicKey for Message {}
///
/// // then `Message::encrypt()` to serialize message and `Message::decrypt()` to deserialize.
/// ```
///
/// # Algorithm
///
/// - Public-key exchange: X25519
/// - Encryption: XChaCha20
/// - Message authentication: Poly1305 MAC
pub trait SerdeEncryptPublicKey {
    /// Serialize and encrypt.
    ///
    /// # Failures
    ///
    /// - [SerializationError](crate::error::ErrorKind::SerializationError) when failed to serialize message.
    /// - [EncryptionError](crate::error::ErrorKind::EncryptionError) when failed to encrypt serialized message.
    fn encrypt(&self, combined_key: &SenderCombinedKey) -> Result<EncryptedMessage, Error>
    where
        Self: Serialize,
    {
        // TODO stop creating rand generator for every func call (share the same rng with key-pair generation)
        let mut rng = rand::rngs::StdRng::from_seed([0; 32]);

        let nonce = crypto_box::generate_nonce(&mut rng);

        let sender_box = ChaChaBox::new(
            combined_key.receiver_public_key().as_ref(),
            combined_key.sender_private_key().as_ref(),
        );

        // TODO cbor?
        let serial_plain = serde_cbor::to_vec(&self).map_err(|e| {
            Error::serialization_error(&format!("failed to serialize data by serde_cbor: {:?}", e))
        })?;

        // TODO https://github.com/laysakura/serde-encrypt/issues/19
        let aad = b"".as_ref();

        let encrypted = sender_box
            .encrypt(
                &nonce,
                Payload {
                    msg: &serial_plain,
                    aad,
                },
            )
            .map_err(|_| {
                Error::encryption_error("failed to encrypt serialized data into ChaChaBox")
            })?;

        Ok(EncryptedMessage::new(encrypted, nonce.into()))
    }

    /// Decrypt and deserialize.
    ///
    /// # Failures
    ///
    /// - [DecryptionError](crate::error::ErrorKind::DecryptionError) when failed to decrypt message.
    /// - [DeserializationError](crate::error::ErrorKind::DeserializationError) when failed to deserialize decrypted message.
    fn decrypt(
        encrypted_message: &EncryptedMessage,
        combined_key: &ReceiverCombinedKey,
    ) -> Result<Self, Error>
    where
        Self: Sized + DeserializeOwned,
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

        let decrypted = serde_cbor::from_slice(&serial_plain).map_err(|e| {
            Error::deserialization_error(&format!(
                "error on serde_cbor deserialization after decryption: {:?}",
                e
            ))
        })?;

        Ok(decrypted)
    }

    /// TBD
    fn decrypt_to_serialized(
        encrypted_message: &EncryptedMessage,
        combined_key: &ReceiverCombinedKey,
    ) -> Result<PlainSerialized, Error> {
        let receiver_box = ChaChaBox::new(
            combined_key.sender_public_key().as_ref(),
            combined_key.receiver_private_key().as_ref(),
        );

        let nonce = encrypted_message.nonce();
        let encrypted = encrypted_message.encrypted();

        let serial_plain = receiver_box
            .decrypt(nonce.into(), encrypted)
            .map_err(|_| Error::decryption_error("error on decryption of ChaChaBox"))?;

        Ok(PlainSerialized(serial_plain))
    }
}

/// a
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct PlainSerialized(Vec<u8>);

impl PlainSerialized {
    ///
    pub fn finalize<'de, T>(&'de self) -> Result<T, Error>
    where
        T: Sized + Deserialize<'de>,
    {
        serde_cbor::from_slice(&self.0).map_err(|e| {
            Error::deserialization_error(&format!(
                "error on serde_cbor deserialization after decryption: {:?}",
                e
            ))
        })
    }
}
