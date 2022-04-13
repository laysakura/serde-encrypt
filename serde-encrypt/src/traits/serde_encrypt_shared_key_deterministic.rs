use crate::{
    encrypt::plain_message_shared_key_deterministic::PlainMessageSharedKeyDeterministic,
    serialize::TypedSerialized, shared_key::SharedKey, EncryptedMessage, Error,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_encrypt_core::encrypt::plain_message_shared_key::PlainMessageSharedKeyDeterministicCore;

/// Shared-key authenticated **deterministic** encryption for serde-serializable types.
///
/// # Features
///
/// - Message authentication.
/// - Same cipher-text for the same plain-text for eq-match in cipher-text.
///   Note that this is more vulnerable than [SerdeEncryptSharedKey](crate::traits::SerdeEncryptSharedKey)
///   because, for example, attackers can find repeated patterns in cipher-text and then guess
///   repeated patterns in plain-text.
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
/// Eq-match feature is used in encrypted indexes in RDBMS, for example.
///
/// # Examples
///
/// See: [SerdeEncryptSharedKey](crate::traits::SerdeEncryptSharedKey), who has nearly the same usage.
///
/// # Algorithm
///
/// - Encryption: XChaCha20
/// - Message authentication: Poly1305 MAC
/// - Fixed nonce.
pub trait SerdeEncryptSharedKeyDeterministic {
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
        let serialized = Self::S::serialize(self)?;
        let plain_msg = PlainMessageSharedKeyDeterministic::new(serialized.into_vec());
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
        let plain_msg = PlainMessageSharedKeyDeterministic::decrypt(encrypted_message, shared_key)?;
        Ok(Self::S::new(plain_msg.into_vec()))
    }
}
