use crate::serialize::TypedSerialized;
use crate::{EncryptedMessage, Error, ReceiverCombinedKey, SenderCombinedKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_encrypt_core::encrypt::plain_message_public_key::PlainMessagePublicKey;

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
/// ## Encrypting owned data
///
/// See [this example](https://github.com/laysakura/serde-encrypt/blob/main/tests/example_serde_encrypt_public_key_owned_data.rs).
///
/// ## Encrypting struct with reference fields
///
/// See [this example](https://github.com/laysakura/serde-encrypt/blob/main/tests/example_serde_encrypt_public_key_struct_with_reference.rs).
///
/// # Algorithm
///
/// - Public-key exchange: X25519
/// - Encryption: XChaCha20
/// - Message authentication: Poly1305 MAC
pub trait SerdeEncryptPublicKey {
    /// Serializer implementation
    type S: TypedSerialized<T = Self>;

    /// Serialize and encrypt.
    ///
    /// # Failures
    ///
    /// - [SerializationError](serde_encrypt_core::error::ErrorKind::SerializationError) when failed to serialize message.
    /// - [EncryptionError](serde_encrypt_core::error::ErrorKind::EncryptionError) when failed to encrypt serialized message.
    fn encrypt(&self, combined_key: &SenderCombinedKey) -> Result<EncryptedMessage, Error>
    where
        Self: Serialize,
    {
        let serialized = Self::S::serialize(&self)?;
        let plain_msg = PlainMessagePublicKey::from(serialized.into_vec());
        plain_msg.encrypt(combined_key)
    }

    /// Decrypt and deserialize into DeserializeOwned type.
    ///
    /// # Failures
    ///
    /// - [DecryptionError](serde_encrypt_core::error::ErrorKind::DecryptionError) when failed to decrypt message.
    /// - [DeserializationError](serde_encrypt_core::error::ErrorKind::DeserializationError) when failed to deserialize decrypted message.
    fn decrypt_owned(
        encrypted_message: &EncryptedMessage,
        combined_key: &ReceiverCombinedKey,
    ) -> Result<Self, Error>
    where
        Self: DeserializeOwned,
    {
        let serialized = Self::decrypt_ref(encrypted_message, combined_key)?;
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
        combined_key: &ReceiverCombinedKey,
    ) -> Result<Self::S, Error>
    where
        Self: Deserialize<'de>,
    {
        let plain_msg = PlainMessagePublicKey::decrypt(encrypted_message, combined_key)?;
        Ok(Self::S::new(plain_msg.into()))
    }
}
