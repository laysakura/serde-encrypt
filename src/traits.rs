//! Traits to enable encrypted-serialization to your struct/enum.

use serde::{de::DeserializeOwned, Serialize};

use crate::{key::combined_key::{ReceiverCombinedKey, SenderCombinedKey}, msg::EncryptedMessage};

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
        todo!()
    }

    /// Deserialize and decrypt.
    fn decrypt(
        encrypted_serialized: &EncryptedMessage,
        combined_key: &ReceiverCombinedKey,
    ) -> Self {
        todo!()
    }
}
