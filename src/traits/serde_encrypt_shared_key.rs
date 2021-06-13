use core::{marker::PhantomData, ops::DerefMut};

use crate::{error::Error, key::shared_key::SharedKey, msg::EncryptedMessage, random::global_rng};
use alloc::{format, vec::Vec};
use chacha20poly1305::XChaCha20Poly1305;
use crypto_box::aead::{Aead, NewAead};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

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
/// See [this example](https://github.com/laysakura/serde-encrypt/blob/main/tests/example_shared_key_excryption_with_key_exchange.rs).
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
        let mut rng = global_rng().lock();

        let nonce = crypto_box::generate_nonce(rng.deref_mut());
        let chacha = XChaCha20Poly1305::new(shared_key.to_chacha_key());

        let serial_plain = self.inner_serialize()?;

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
    ) -> Result<ToDeserialize<Self>, Error>
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

        Ok(ToDeserialize::new(serial_plain))
    }

    /// # Failures
    ///
    /// - [SerializationError](crate::error::ErrorKind::SerializationError) when failed to serialize message.
    fn inner_serialize(&self) -> Result<Vec<u8>, Error>
    where
        Self: Serialize,
    {
        serde_cbor::to_vec(&self).map_err(|e| {
            Error::serialization_error(&format!("failed to serialize data by serde_cbor: {:?}", e))
        })
    }
}

/// TODO use in common with *_public_key.rs
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct ToDeserialize<T> {
    serialized_plain: Vec<u8>,
    _type: PhantomData<T>,
}

impl<T> ToDeserialize<T> {
    fn new(serialized_plain: Vec<u8>) -> Self {
        Self {
            serialized_plain,
            _type: PhantomData::default(),
        }
    }

    /// Deserialize to get plain message.
    ///
    /// # Failures
    ///
    /// - [DeserializationError](crate::error::ErrorKind::DeserializationError) when failed to deserialize decrypted message.
    pub fn deserialize<'de>(&'de self) -> Result<T, Error>
    where
        T: Sized + Deserialize<'de>,
    {
        serde_cbor::from_slice(&self.serialized_plain).map_err(|e| {
            Error::deserialization_error(&format!(
                "error on serde_cbor deserialization after decryption: {:?}",
                e
            ))
        })
    }
}
