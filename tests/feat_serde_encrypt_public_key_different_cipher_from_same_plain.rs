//! Test if SerdeEncryptPublicKey emits different cipher-text for the same plain-text to avoid attacks such as statistical analysis of cipher-text.

mod test_util;

use serde::{Deserialize, Serialize};
use serde_encrypt::{error::Error, traits::SerdeEncryptPublicKey};
use test_util::serde_encrypt_public_key::*;

#[test]
fn test_serde_encrypt_public_key_in_a_process() -> Result<(), Error> {
    keygen!(sender_combined_key, _x);

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Message(String);
    impl SerdeEncryptPublicKey for Message {}

    type EncMessage = Vec<u8>;

    let mut enc_msgs = Vec::<EncMessage>::new();
    for _ in 0..100 {
        let msg = Message("same message".into());
        let encrypted = msg.encrypt(&sender_combined_key)?;
        let enc_msg = encrypted.serialize();
        enc_msgs.push(enc_msg);
    }

    for i in 0..100 {
        let enc_msg_i = enc_msgs.get(i).unwrap();
        for j in (i + 1)..100 {
            let enc_msg_j = enc_msgs.get(j).unwrap();
            assert_ne!(enc_msg_i, enc_msg_j);
        }
    }

    Ok(())
}

// TODO Test "separate processes produce different cipher-text".
