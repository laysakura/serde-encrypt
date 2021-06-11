//! Traits to enable encrypted-serialization to your struct/enum.

use alloc::format;
use crypto_box::{
    aead::{Aead, Payload},
    ChaChaBox,
};
use rand::SeedableRng;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    error::Error,
    key::combined_key::{ReceiverCombinedKey, SenderCombinedKey},
    msg::EncryptedMessage,
};

/// Enable encrypted-serialization to your struct/enum.
///
/// # Examples
///
/// ```
/// use serde_encrypt::traits::SerdeEncrypt;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct Message {
///     content: String,
///     sender: String,
/// }
///
/// impl SerdeEncrypt for Message {}
///
/// // then `Message::encrypt()` to serialize message and `Message::decrypt()` to deserialize.
/// ```
pub trait SerdeEncrypt: Sized + Serialize + DeserializeOwned // TODO `Owned` required?
{
    /// Serialize and encrypt.
    fn encrypt(&self, combined_key: &SenderCombinedKey) -> EncryptedMessage {
        // TODO stop creating rand generator for every func call (share the same rng with key-pair generation)
        let mut rng = rand::rngs::StdRng::from_seed([0; 32]);

        let nonce = crypto_box::generate_nonce(&mut rng);

        let sender_box = ChaChaBox::new(
            combined_key.receiver_public_key().as_ref(),
            combined_key.sender_private_key().as_ref(),
        );

        // TODO cbor?
        let serial_plain = serde_cbor::to_vec(&self).unwrap();

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
            .expect("TODO");

        EncryptedMessage::new(encrypted, nonce.into())
    }

    /// Deserialize and decrypt.
    fn decrypt(
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

        let decrypted = serde_cbor::from_slice(&serial_plain).map_err(|e| {
            Error::deserialization_error(&format!(
                "error on serde_cbor deserialization after decryption: {:?}",
                e
            ))
        })?;

        Ok(decrypted)
    }
}
