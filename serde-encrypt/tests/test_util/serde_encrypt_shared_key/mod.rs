#![allow(dead_code)]

use core::fmt;

use serde::{de::DeserializeOwned, Serialize};
use serde_encrypt::{shared_key::SharedKey, traits::SerdeEncryptSharedKey};
use serde_encrypt_core::error::Error;

pub fn shared_key_enc_dec<T>(sender_msg: &T, shared_key: &SharedKey) -> Result<T, Error>
where
    T: SerdeEncryptSharedKey + Sized + Serialize + DeserializeOwned,
{
    let enc = sender_msg.encrypt(shared_key)?;
    T::decrypt_owned(&enc, shared_key)
}

pub fn shared_key_enc_dec_assert_eq<T>(sender_msg: &T, shared_key: &SharedKey) -> Result<(), Error>
where
    T: SerdeEncryptSharedKey + Sized + Serialize + DeserializeOwned + PartialEq + fmt::Debug,
{
    let receiver_msg = shared_key_enc_dec(sender_msg, shared_key)?;
    assert_eq!(sender_msg, &receiver_msg);
    Ok(())
}
