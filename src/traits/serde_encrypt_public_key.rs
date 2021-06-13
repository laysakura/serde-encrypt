use core::{marker::PhantomData, ops::DerefMut};

use crate::{
    error::Error,
    key::combined_key::{ReceiverCombinedKey, SenderCombinedKey},
    msg::EncryptedMessage,
    random::global_rng,
};
use alloc::{format, vec::Vec};
use crypto_box::{
    aead::{Aead, Payload},
    ChaChaBox,
};
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
        let mut rng = global_rng().lock();

        let nonce = crypto_box::generate_nonce(rng.deref_mut());
        let sender_box = ChaChaBox::new(
            combined_key.receiver_public_key().as_ref(),
            combined_key.sender_private_key().as_ref(),
        );

        let serial_plain = self.inner_serialize()?;

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

    /// Decrypt and deserialize into DeserializeOwned type.
    ///
    /// # Failures
    ///
    /// - [DecryptionError](crate::error::ErrorKind::DecryptionError) when failed to decrypt message.
    /// - [DeserializationError](crate::error::ErrorKind::DeserializationError) when failed to deserialize decrypted message.
    fn decrypt_owned(
        encrypted_message: &EncryptedMessage,
        combined_key: &ReceiverCombinedKey,
    ) -> Result<Self, Error>
    where
        Self: Sized + DeserializeOwned,
    {
        let serial_plain = Self::decrypt_ref(encrypted_message, combined_key)?;
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
        combined_key: &ReceiverCombinedKey,
    ) -> Result<ToDeserialize<Self>, Error>
    where
        Self: Sized + Deserialize<'de>,
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

/// Serialized plain-text.
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
