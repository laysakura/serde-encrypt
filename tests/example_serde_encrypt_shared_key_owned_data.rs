//! Shows how to use SerdeEncryptSharedKey.

use serde::{Deserialize, Serialize};
use serde_encrypt::{
    error::Error, key::shared_key::SharedKey, msg::EncryptedMessage, traits::SerdeEncryptSharedKey,
};

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    content: String,
    sender: String,
}

impl SerdeEncryptSharedKey for Message {}

fn alice_sends_secret_message(shared_key: &SharedKey) -> Result<Vec<u8>, Error> {
    let msg = Message {
        content: "I ❤️ you.".to_string(),
        sender: "Alice".to_string(),
    };
    let encrypted_message = msg.encrypt(shared_key)?;
    Ok(encrypted_message.serialize())
}

fn bob_receives_secret_message(
    encrypted_serialized: Vec<u8>,
    shared_key: &SharedKey,
) -> Result<Message, Error> {
    let encrypted_message = EncryptedMessage::deserialize(encrypted_serialized)?;
    Message::decrypt_owned(&encrypted_message, shared_key)
}

#[test]
fn test_serde_encrypt_shared_key() -> Result<(), Error> {
    // Both Alice and Bob have this key secretly.
    const SHARED_KEY: [u8; 32] = [42; 32];
    let shared_key = SharedKey::from_slice(&SHARED_KEY);

    let secret_message = alice_sends_secret_message(&shared_key)?;
    let revealed_message = bob_receives_secret_message(secret_message, &shared_key)?;

    // Congrats 🎉👏
    assert_eq!(revealed_message.content, "I ❤️ you.");
    assert_eq!(revealed_message.sender, "Alice");

    Ok(())
}
