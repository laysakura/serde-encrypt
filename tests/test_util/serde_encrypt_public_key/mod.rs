use core::fmt;

use serde_encrypt::{
    error::Error,
    key::{
        combined_key::{ReceiverCombinedKey, SenderCombinedKey},
        key_pair::{ReceiverKeyPair, SenderKeyPair},
    },
    traits::SerdeEncryptPublicKey,
};

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

pub fn enc_dec<T>(
    sender_msg: &T,
    sender_combined_key: &SenderCombinedKey,
    receiver_combined_key: &ReceiverCombinedKey,
) -> Result<T, Error>
where
    T: SerdeEncryptPublicKey,
{
    let enc = sender_msg.encrypt(sender_combined_key)?;
    T::decrypt(&enc, receiver_combined_key)
}

pub fn enc_dec_assert_eq<T>(
    sender_msg: &T,
    sender_combined_key: &SenderCombinedKey,
    receiver_combined_key: &ReceiverCombinedKey,
) -> Result<(), Error>
where
    T: SerdeEncryptPublicKey + PartialEq + fmt::Debug,
{
    let receiver_msg = enc_dec(sender_msg, sender_combined_key, receiver_combined_key)?;
    pretty_assertions::assert_eq!(sender_msg, &receiver_msg);
    Ok(())
}