//! Shows how to use SerdeEncryptPublicKey.

use serde::{Deserialize, Serialize};
use serde_encrypt::{
    key::{
        combined_key::{ReceiverCombinedKey, SenderCombinedKey},
        key_pair::{ReceiverKeyPair, SenderKeyPair},
    },
    msg::EncryptedMessage,
    traits::SerdeEncryptPublicKey,
};

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    content: String,
    sender: String,
}

impl SerdeEncryptPublicKey for Message {}

fn alice_sends_secret_message(combined_key: &SenderCombinedKey) -> Vec<u8> {
    let msg = Message {
        content: "I ❤️ you.".to_string(),
        sender: "Alice".to_string(),
    };
    let encrypted_message = msg.encrypt(combined_key).unwrap();
    encrypted_message.serialize()
}

fn bob_receives_secret_message(
    encrypted_serialized: Vec<u8>,
    combined_key: &ReceiverCombinedKey,
) -> Message {
    let encrypted_message = EncryptedMessage::deserialize(encrypted_serialized).unwrap();
    Message::decrypt(&encrypted_message, combined_key).unwrap()
}

#[test]
fn test_serde_encrypt_public_key() {
    let alice_key_pair = SenderKeyPair::generate();
    let bob_key_pair = ReceiverKeyPair::generate();

    let alice_combined_key =
        SenderCombinedKey::new(alice_key_pair.private_key(), bob_key_pair.public_key());
    let bob_combined_key =
        ReceiverCombinedKey::new(alice_key_pair.public_key(), bob_key_pair.private_key());

    let secret_message = alice_sends_secret_message(&alice_combined_key);
    let revealed_message = bob_receives_secret_message(secret_message, &bob_combined_key);

    // Congrats 🎉👏
    assert_eq!(revealed_message.content, "I ❤️ you.");
    assert_eq!(revealed_message.sender, "Alice");
}
