#![allow(dead_code)]

use core::fmt;

use serde::{de::DeserializeOwned, Serialize};
use serde_encrypt::{traits::SerdeEncryptPublicKey, Error};
use serde_encrypt_core::key::{
    combined_key::{ReceiverCombinedKey, SenderCombinedKey},
    key_pair::{ReceiverKeyPair, SenderKeyPair},
};

#[macro_export]
macro_rules! combined_keys_gen {
    ($sender_combined_key:ident, $receiver_combined_key:ident) => {
        let (sender_key_pair, receiver_key_pair) = gen_key_pairs();
        let ($sender_combined_key, $receiver_combined_key) =
            mk_combined_keys(&sender_key_pair, &receiver_key_pair);
    };
}

pub fn gen_key_pairs() -> (SenderKeyPair, ReceiverKeyPair) {
    let sender_key_pair = SenderKeyPair::generate();
    let receiver_key_pair = ReceiverKeyPair::generate();
    (sender_key_pair, receiver_key_pair)
}

pub fn mk_combined_keys<'s, 'r>(
    sender_key_pair: &'s SenderKeyPair,
    receiver_key_pair: &'r ReceiverKeyPair,
) -> (SenderCombinedKey<'s, 'r>, ReceiverCombinedKey<'s, 'r>) {
    let sender_combined_key = SenderCombinedKey::new(
        sender_key_pair.private_key(),
        receiver_key_pair.public_key(),
    );
    let receiver_combined_key = ReceiverCombinedKey::new(
        sender_key_pair.public_key(),
        receiver_key_pair.private_key(),
    );

    (sender_combined_key, receiver_combined_key)
}

pub fn public_key_enc_dec<T>(
    sender_msg: &T,
    sender_combined_key: &SenderCombinedKey,
    receiver_combined_key: &ReceiverCombinedKey,
) -> Result<T, Error>
where
    T: SerdeEncryptPublicKey + Sized + Serialize + DeserializeOwned,
{
    let enc = sender_msg.encrypt(sender_combined_key)?;
    T::decrypt_owned(&enc, receiver_combined_key)
}

pub fn public_key_enc_dec_assert_eq<T>(
    sender_msg: &T,
    sender_combined_key: &SenderCombinedKey,
    receiver_combined_key: &ReceiverCombinedKey,
) -> Result<(), Error>
where
    T: SerdeEncryptPublicKey + Sized + Serialize + DeserializeOwned + PartialEq + fmt::Debug,
{
    let receiver_msg = public_key_enc_dec(sender_msg, sender_combined_key, receiver_combined_key)?;
    assert_eq!(sender_msg, &receiver_msg);
    Ok(())
}
