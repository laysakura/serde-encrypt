use crate::{serialize::TypedSerialized, shared_key::SharedKey, EncryptedMessage, Error};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_encrypt_core::encrypt::plain_message_shared_key::PlainMessageSharedKeyCore;

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
/// First, message sender or receiver should generate [SharedKey](crate::shared_key::SharedKey).
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
    /// Serializer implementation
    type S: TypedSerialized<T = Self>;

    /// Serialize and encrypt.
    ///
    /// # Failures
    ///
    /// - [SerializationError](serde_encrypt_core::error::ErrorKind::SerializationError) when failed to serialize message.
    /// - [EncryptionError](serde_encrypt_core::error::ErrorKind::EncryptionError) when failed to encrypt serialized message.
    fn encrypt(&self, shared_key: &SharedKey) -> Result<EncryptedMessage, Error>
    where
        Self: Serialize,
    {
        let serialized = Self::S::serialize(&self)?;
        let plain_msg = PlainMessageSharedKeyCore::from(serialized.into_vec());
        plain_msg.encrypt(shared_key)
    }

    /// Decrypt and deserialize into DeserializeOwned type.
    ///
    /// # Failures
    ///
    /// - [DecryptionError](serde_encrypt_core::error::ErrorKind::DecryptionError) when failed to decrypt message.
    /// - [DeserializationError](serde_encrypt_core::error::ErrorKind::DeserializationError) when failed to deserialize decrypted message.
    fn decrypt_owned(
        encrypted_message: &EncryptedMessage,
        shared_key: &SharedKey,
    ) -> Result<Self, Error>
    where
        Self: DeserializeOwned,
    {
        let serialized = Self::decrypt_ref(encrypted_message, shared_key)?;
        serialized.deserialize()
    }

    /// Just decrypts cipher-text. Returned data must be deserialized later.
    /// Types implementing `serde::Deserialize<'de>` (not `serde::de::DeserializeOwned`) should use
    /// this function to resolve lifetime.
    ///
    /// # Failures
    ///
    /// - [DecryptionError](serde_encrypt_core::error::ErrorKind::DecryptionError) when failed to decrypt message.
    fn decrypt_ref<'de>(
        encrypted_message: &EncryptedMessage,
        shared_key: &SharedKey,
    ) -> Result<Self::S, Error>
    where
        Self: Deserialize<'de>,
    {
        let plain_msg = PlainMessageSharedKeyCore::decrypt(encrypted_message, shared_key)?;
        Ok(Self::S::new(plain_msg.into()))
    }
}
