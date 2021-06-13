//! Test if:
//!
//! - SerdeEncryptPublicKey
//! - SerdeEncryptSharedKey
//!
//!  emit different cipher-text for the same plain-text to avoid attacks such as statistical analysis of cipher-text.

mod test_util;

use serde::{Deserialize, Serialize};
use serde_encrypt::key::shared_key::SharedKey;
use serde_encrypt::traits::SerdeEncryptPublicKey;
use serde_encrypt::traits::SerdeEncryptSharedKey;
use test_util::serde_encrypt_public_key::*;
use test_util::*;

#[derive(PartialEq, Debug, Serialize, Deserialize)]
struct Message(String);

#[test]
fn test_serde_encrypt_public_key_in_a_process() {
    combined_keys_gen!(sender_combined_key, _x);

    impl SerdeEncryptPublicKey for Message {}
    assert_no_duplicate(
        || {
            let msg = Message("same message".into());
            let encrypted = SerdeEncryptPublicKey::encrypt(&msg, &sender_combined_key).unwrap();
            encrypted.serialize()
        },
        100,
    );
}

#[test]
fn test_serde_encrypt_shared_key_in_a_process() {
    let shared_key = SharedKey::generate();

    impl SerdeEncryptSharedKey for Message {}
    assert_no_duplicate(
        || {
            let msg = Message("same message".into());
            let encrypted = SerdeEncryptSharedKey::encrypt(&msg, &shared_key).unwrap();
            encrypted.serialize()
        },
        100,
    );
}

// TODO Test "separate processes produce different cipher-text".
