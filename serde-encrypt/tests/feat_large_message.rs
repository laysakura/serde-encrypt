//! Test if:
//!
//! - SerdeEncryptPublicKey
//! - SerdeEncryptSharedKey
//!
//!  can encrypt/decrypt large message.

mod test_util;

use serde::{Deserialize, Serialize};
use serde_encrypt::serialize::impls::BincodeSerializer;
use serde_encrypt::shared_key::SharedKey;
use serde_encrypt::traits::{SerdeEncryptPublicKey, SerdeEncryptSharedKey};
use serde_encrypt::AsSharedKey;
use test_util::*;

const SIZE: usize = 1_000_000;

#[derive(PartialEq, Debug, Serialize, Deserialize)]
struct Message(Vec<u8>);

#[test]
fn test_serde_encrypt_public_key_large_message() {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);

    impl SerdeEncryptPublicKey for Message {
        type S = BincodeSerializer<Self>;
    }

    let msg = Message(vec![42u8; SIZE]);
    public_key_enc_dec_assert_eq(&msg, &sender_combined_key, &receiver_combined_key).unwrap();
}

#[test]
fn test_serde_encrypt_shared_key_large_message() {
    let shared_key = SharedKey::generate();

    impl SerdeEncryptSharedKey for Message {
        type S = BincodeSerializer<Self>;
    }

    let msg = Message(vec![42u8; SIZE]);
    shared_key_enc_dec_assert_eq(&msg, &shared_key).unwrap();
}
