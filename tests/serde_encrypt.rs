use serde::{Deserialize, Serialize};
use serde_encrypt::{
    key::{
        combined_key::{ReceiverCombinedKey, SenderCombinedKey},
        key_pair::{ReceiverKeyPair, SenderKeyPair},
    },
    msg::EncryptedMessage,
    traits::SerdeEncrypt,
};

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    content: String,
    sender: String,
}

impl SerdeEncrypt for Message {}

fn alice_sends_secret_message(combined_key: &SenderCombinedKey) -> EncryptedMessage {
    let msg = Message {
        content: "I ❤️ you.".to_string(),
        sender: "Alice".to_string(),
    };
    msg.encrypt(combined_key)
}

fn bob_receives_secret_message(
    enc_ser: &EncryptedMessage,
    combined_key: &ReceiverCombinedKey,
) -> Message {
    Message::decrypt(enc_ser, combined_key).unwrap()
}

#[test]
fn test_serde_encrypt() {
    let alice_key_pair = SenderKeyPair::generate();
    let bob_key_pair = ReceiverKeyPair::generate();

    let alice_combined_key =
        SenderCombinedKey::new(alice_key_pair.private_key(), bob_key_pair.public_key());
    let bob_combined_key =
        ReceiverCombinedKey::new(alice_key_pair.public_key(), bob_key_pair.private_key());

    let secret_message = alice_sends_secret_message(&alice_combined_key);
    let revealed_message = bob_receives_secret_message(&secret_message, &bob_combined_key);

    // Congrats 🎉👏
    assert_eq!(revealed_message.content, "I ❤️ you.");
    assert_eq!(revealed_message.sender, "Alice");
}
