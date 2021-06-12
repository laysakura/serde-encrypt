//! Shows how to use SerdeEncryptPublicKey for struct with reference fields.

use serde::{Deserialize, Serialize};
use serde_encrypt::{
    error::Error,
    key::{
        combined_key::{ReceiverCombinedKey, SenderCombinedKey},
        key_pair::{ReceiverKeyPair, SenderKeyPair},
    },
    msg::EncryptedMessage,
    traits::SerdeEncryptPublicKey,
};

#[derive(Debug, Serialize, Deserialize)]
struct Content<'a> {
    title: &'a str,
    sentence: &'a str,
}

#[derive(Debug, Serialize, Deserialize)]
struct Message<'a> {
    content: Content<'a>,
    sender: &'a str,
}

impl<'a> SerdeEncryptPublicKey for Message<'a> {}

fn alice_sends_secret_message(combined_key: &SenderCombinedKey) -> Vec<u8> {
    let msg = Message {
        content: Content {
            title: "my heart",
            sentence: "I ❤️ you.",
        },
        sender: "Alice",
    };
    let encrypted_message = msg.encrypt(combined_key).unwrap();
    encrypted_message.serialize()
}

fn bob_reads_secret_message(
    encrypted_serialized: Vec<u8>,
    combined_key: &ReceiverCombinedKey,
) -> Result<(), Error> {
    let encrypted_message = EncryptedMessage::deserialize(encrypted_serialized)?;

    let x = Message::decrypt_to_serialized(&encrypted_message, &combined_key)?;
    let revealed_message: Message = x.finalize()?;

    // Note that you cannot return `revealed_message` from this function
    // because it has the same lifetime as local-scoped `x`.

    // Congrats 🎉👏
    assert_eq!(revealed_message.content.title, "my heart");
    assert_eq!(revealed_message.content.sentence, "I ❤️ you.");
    assert_eq!(revealed_message.sender, "Alice");

    Ok(())
}

#[test]
fn test_serde_encrypt_public_key() -> Result<(), Error> {
    let alice_key_pair = SenderKeyPair::generate();
    let bob_key_pair = ReceiverKeyPair::generate();

    let alice_combined_key =
        SenderCombinedKey::new(alice_key_pair.private_key(), bob_key_pair.public_key());
    let bob_combined_key =
        ReceiverCombinedKey::new(alice_key_pair.public_key(), bob_key_pair.private_key());

    let secret_message = alice_sends_secret_message(&alice_combined_key);
    bob_reads_secret_message(secret_message, &bob_combined_key)
}
