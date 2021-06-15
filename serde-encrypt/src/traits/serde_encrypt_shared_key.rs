use crate::{error::Error, key::shared_key::SharedKey, msg::EncryptedMessage};
use alloc::format;
use chacha20poly1305::XChaCha20Poly1305;
use crypto_box::aead::{Aead, NewAead};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::{
    impl_detail::{self, nonce::generate_nonce},
    SerializedPlain,
};

/// Shared-key authenticated encryption for serde-serializable types.
///
/// # Features
///
/// - Message authentication.
/// - Different cipher-text for the same plain-text to avoid attacks such as statistical analysis of cipher-text.
/// - Uses small (32-byte) key.
///
/// # Anti-features
///
/// - Identity authentication of sender nor receiver.
///
/// # Popular use cases
///
/// Good for both large and small message encryption / decryption.
///
/// ## when sender and receiver does not hold shared key yet:
///
/// First, message sender or receiver should generate [SharedKey](crate::key::shared_key::SharedKey).
///
/// And then sender or receiver who generated the key should give it to another using safe communication.
/// [SerdeEncryptPublicKey](crate::traits::SerdeEncryptPublicKey) is recommended for it.
///
/// # Examples
///
/// ## Encrypting owned data with already-shared key
///
/// See [this example](https://github.com/laysakura/serde-encrypt/blob/main/tests/example_serde_encrypt_shared_key_owned_data.rs).
///
/// ## Generate and exchange shared key and encrypt struct with reference fields
///
/// See [this example](https://github.com/laysakura/serde-encrypt/blob/main/tests/example_serde_encrypt_shared_key_encryption_with_key_exchange.rs).
///
/// # Algorithm
///
/// - Encryption: XChaCha20
/// - Message authentication: Poly1305 MAC
pub trait SerdeEncryptSharedKey {
    /// Serialize and encrypt.
    ///
    /// # Failures
    ///
    /// - [SerializationError](crate::error::ErrorKind::SerializationError) when failed to serialize message.
    /// - [EncryptionError](crate::error::ErrorKind::EncryptionError) when failed to encrypt serialized message.
    fn encrypt(&self, shared_key: &SharedKey) -> Result<EncryptedMessage, Error>
    where
        Self: Serialize,
    {
        let nonce = generate_nonce();
        let chacha = XChaCha20Poly1305::new(shared_key.to_chacha_key());

        let serial_plain = impl_detail::serialize(&self)?;

        let encrypted = chacha.encrypt(&nonce, serial_plain.as_ref()).map_err(|e| {
            Error::encryption_error(&format!(
                "failed to encrypt serialized data by XChaCha20: {:?}",
                e
            ))
        })?;

        Ok(EncryptedMessage::new(encrypted, nonce.into()))
    }

    /// Decrypt and deserialize into DeserializeOwned type.
    ///
    /// # Failures
    ///
    /// - [DecryptionError](crate::error::ErrorKind::DecryptionError) when failed to decrypt message.
    /// - [DeserializationError](crate::error::ErrorKind::DeserializationError) when failed to deserialize decrypted message.
    fn decrypt_owned(
        encrypted_message: &EncryptedMessage,
        shared_key: &SharedKey,
    ) -> Result<Self, Error>
    where
        Self: Sized + DeserializeOwned,
    {
        let serial_plain = Self::decrypt_ref(encrypted_message, shared_key)?;
        serial_plain.deserialize()
    }

    /// Just decrypts cipher-text. Returned data must be deserialized later.
    /// Types implementing `serde::Deserialize<'de>` (not `serde::de::DeserializeOwned`) should use
    /// this function to resolve lifetime.
    ///
    /// # Failures
    ///
    /// - [DecryptionError](crate::error::ErrorKind::DecryptionError) when failed to decrypt message.
    fn decrypt_ref<'de>(
        encrypted_message: &EncryptedMessage,
        shared_key: &SharedKey,
    ) -> Result<SerializedPlain<Self>, Error>
    where
        Self: Sized + Deserialize<'de>,
    {
        let chacha = XChaCha20Poly1305::new(shared_key.to_chacha_key());

        let nonce = encrypted_message.nonce();
        let encrypted = encrypted_message.encrypted();

        let serial_plain = chacha.decrypt(nonce.into(), encrypted).map_err(|e| {
            Error::decryption_error(&format!(
                "error on decryption of XChaCha20 cipher-text: {:?}",
                e
            ))
        })?;

        Ok(SerializedPlain::new(serial_plain))
    }
}
