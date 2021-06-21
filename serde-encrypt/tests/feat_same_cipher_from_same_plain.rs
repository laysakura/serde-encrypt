//! Test if:
//!
//! - SerdeEncryptSharedKeyDeterministic
//!
//!  emit the same cipher-text for the same plain-text for eq-match in cipher-text.

mod test_util;

use serde::{Deserialize, Serialize};
use serde_encrypt::serialize::impls::BincodeSerializer;
use serde_encrypt::shared_key::SharedKey;
use serde_encrypt::traits::SerdeEncryptSharedKeyDeterministic;
use serde_encrypt::AsSharedKey;

#[derive(PartialEq, Debug, Serialize, Deserialize)]
struct Message(String);

#[test]
fn test_serde_encrypt_shared_key_deterministic() {
    let shared_key = SharedKey::generate();

    impl SerdeEncryptSharedKeyDeterministic for Message {
        type S = BincodeSerializer<Self>;
    }

    let msg1 = Message("same message".into());
    let msg2 = Message("same message".into());
    let msg3 = Message("same? message".into());

    let encrypted1 = Message::encrypt(&msg1, &shared_key).unwrap();
    let encrypted2 = Message::encrypt(&msg2, &shared_key).unwrap();
    let encrypted3 = Message::encrypt(&msg3, &shared_key).unwrap();

    assert_eq!(encrypted1, encrypted2);
    assert_ne!(encrypted2, encrypted3);
}
