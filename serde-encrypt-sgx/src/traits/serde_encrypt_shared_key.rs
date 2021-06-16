use crate::{
    encrypt::plain_message_shared_key::PlainMessageSharedKey, serialize::TypedSerialized,
    shared_key::SharedKey, EncryptedMessage, Error,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_encrypt_core::encrypt::plain_message_shared_key::PlainMessageSharedKeyCore;

pub trait SerdeEncryptSharedKey {
    type S: TypedSerialized<T = Self>;

    fn encrypt(&self, shared_key: &SharedKey) -> Result<EncryptedMessage, Error>
    where
        Self: Serialize,
    {
        let serialized = Self::S::serialize(&self)?;
        let plain_msg = PlainMessageSharedKey::new(serialized.into_vec());
        plain_msg.encrypt(shared_key)
    }

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

    fn decrypt_ref<'de>(
        encrypted_message: &EncryptedMessage,
        shared_key: &SharedKey,
    ) -> Result<Self::S, Error>
    where
        Self: Deserialize<'de>,
    {
        let plain_msg = PlainMessageSharedKey::decrypt(encrypted_message, shared_key)?;
        Ok(Self::S::new(plain_msg.into_vec()))
    }
}
