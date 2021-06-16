//! Unit test to PlainMessagePublicKey and PlainMessageSharedKey

mod test_util;

use serde_encrypt::{
    encrypt::{
        plain_message_public_key::PlainMessagePublicKey,
        plain_message_shared_key::PlainMessageSharedKey,
    },
    shared_key::SharedKey,
    AsSharedKey, Error, ErrorKind,
};
use serde_encrypt_core::encrypt::{
    plain_message_public_key::PlainMessagePublicKeyCore,
    plain_message_shared_key::PlainMessageSharedKeyCore,
};
use test_util::*;

#[test]
fn test_decrypt_with_wrong_public_key() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key1, _r);
    combined_keys_gen!(_s, receiver_combined_key2);

    let plain_msg = PlainMessagePublicKey::new(b"abc".to_vec());
    let enc_msg = plain_msg.encrypt(&sender_combined_key1)?;
    let e = PlainMessagePublicKey::decrypt(&enc_msg, &receiver_combined_key2).unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::DecryptionError);

    Ok(())
}

#[test]
fn test_decrypt_with_wrong_shared_key() -> Result<(), Error> {
    let shared_key1 = SharedKey::generate();
    let shared_key2 = SharedKey::generate();

    let plain_msg = PlainMessageSharedKey::new(b"abc".to_vec());
    let enc_msg = plain_msg.encrypt(&shared_key1)?;
    let e = PlainMessageSharedKey::decrypt(&enc_msg, &shared_key2).unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::DecryptionError);

    Ok(())
}
