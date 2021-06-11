use serde::{Deserialize, Serialize};
use serde_encrypt::{
    key::{ReceiverCombinedKey, ReceiverKeyPair, SenderCombinedKey, SenderKeyPair},
    msg::EncryptedSerialized,
    traits::SerdeEncrypt,
};

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    content: String,
    sender: String,
}

impl SerdeEncrypt for Message {}

fn alice_sends_secret_message(combined_key: &SenderCombinedKey) -> EncryptedSerialized {
    let msg = Message {
        content: "I ❤️ you.",
        sender: "Alice",
    };
    msg.encrypt(combined_key)
}

fn bob_receives_secret_message(
    enc_ser: &EncryptedSerialized,
    combined_key: &ReceiverCombinedKey,
) -> Message {
    Message::decrypt(enc_ser, combined_key)
}

#[test]
fn test_serde_encrypt() {
    let alice_key_pair = SenderKeyPair::new();
    let bob_key_pair = ReceiverKeyPair::new();

    let alice_combined_key =
        SenderCombinedKey::new(alice_key_pair.private_key(), bob_key_pair.public_key());
    let bob_combined_key =
        ReceiverCombinedKey::new(bob_key_pair.private_key(), alice_key_pair.public_key());

    let secret_message = alice_sends_secret_message(&alice_combined_key);
    let revealed_message = bob_receives_secret_message(&secret_message, bob_combined_key);

    // Congrats 🎉👏
    assert_eq!(revealed_message.content, "I ❤️ you.");
    assert_eq!(revealed_message.sender, "Alice");
}
