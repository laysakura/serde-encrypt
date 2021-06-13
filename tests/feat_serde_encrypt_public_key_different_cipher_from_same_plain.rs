//! Test if SerdeEncryptPublicKey emits different cipher-text for the same plain-text to avoid attacks such as statistical analysis of cipher-text.

mod test_util;

use serde::{Deserialize, Serialize};
use serde_encrypt::traits::SerdeEncryptPublicKey;
use test_util::serde_encrypt_public_key::*;
use test_util::*;

#[test]
fn test_serde_encrypt_public_key_in_a_process() {
    keygen!(sender_combined_key, _x);

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Message(String);
    impl SerdeEncryptPublicKey for Message {}

    assert_no_duplicate(
        || {
            let msg = Message("same message".into());
            let encrypted = msg.encrypt(&sender_combined_key).unwrap();
            encrypted.serialize()
        },
        100,
    );
}

// TODO Test "separate processes produce different cipher-text".
