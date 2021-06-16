//! Unit test to PlainMessagePublicKey

mod test_util;

use serde_encrypt::{encrypt::plain_message_public_key::PlainMessagePublicKey, Error, ErrorKind};
use serde_encrypt_core::encrypt::plain_message_public_key::PlainMessagePublicKeyCore;
use test_util::*;

#[test]
fn test_decrypt_with_wrong_key() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key1, _r);
    combined_keys_gen!(_s, receiver_combined_key2);

    let plain_msg = PlainMessagePublicKey::new(b"abc".to_vec());
    let enc_msg = plain_msg.encrypt(&sender_combined_key1)?;
    let e = PlainMessagePublicKey::decrypt(&enc_msg, &receiver_combined_key2).unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::DecryptionError);

    Ok(())
}
