use crate::encrypt::plain_message_public_key::PlainMessagePublicKey;
use crate::serialize::TypedSerialized;
use crate::{EncryptedMessage, Error, ReceiverCombinedKey, SenderCombinedKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_encrypt_core::encrypt::plain_message_public_key::PlainMessagePublicKeyCore;

pub trait SerdeEncryptPublicKey {
    type S: TypedSerialized<T = Self>;

    fn encrypt(&self, combined_key: &SenderCombinedKey) -> Result<EncryptedMessage, Error>
    where
        Self: Serialize,
    {
        let serialized = Self::S::serialize(&self)?;
        let plain_msg = PlainMessagePublicKey::new(serialized.into_vec());
        plain_msg.encrypt(combined_key)
    }

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

    fn decrypt_ref<'de>(
        encrypted_message: &EncryptedMessage,
        combined_key: &ReceiverCombinedKey,
    ) -> Result<Self::S, Error>
    where
        Self: Deserialize<'de>,
    {
        let plain_msg = PlainMessagePublicKey::decrypt(encrypted_message, combined_key)?;
        Ok(Self::S::new(plain_msg.into_vec()))
    }
}
