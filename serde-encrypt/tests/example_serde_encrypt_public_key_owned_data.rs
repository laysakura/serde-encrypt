//! Shows how to use SerdeEncryptPublicKey.

use serde::{Deserialize, Serialize};
use serde_encrypt::{
    key::key_pair::{ReceiverKeyPair, SenderKeyPair},
    serialize::impls::BincodeSerializer,
    traits::SerdeEncryptPublicKey,
    EncryptedMessage, Error, ReceiverCombinedKey, ReceiverKeyPairCore, SenderCombinedKey,
    SenderKeyPairCore,
};

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    content: String,
    sender: String,
}

impl SerdeEncryptPublicKey for Message {
    type S = BincodeSerializer<Self>;
}

fn alice_sends_secret_message(combined_key: &SenderCombinedKey) -> Result<Vec<u8>, Error> {
    let msg = Message {
        content: "I ❤️ you.".to_string(),
        sender: "Alice".to_string(),
    };
    let encrypted_message = msg.encrypt(combined_key)?;
    Ok(encrypted_message.serialize())
}

fn bob_receives_secret_message(
    encrypted_serialized: Vec<u8>,
    combined_key: &ReceiverCombinedKey,
) -> Result<Message, Error> {
    let encrypted_message = EncryptedMessage::deserialize(encrypted_serialized)?;
    Message::decrypt_owned(&encrypted_message, combined_key)
}

#[test]
fn test_serde_encrypt_public_key() -> Result<(), Error> {
    let alice_key_pair = SenderKeyPair::generate();
    let bob_key_pair = ReceiverKeyPair::generate();

    let alice_combined_key =
        SenderCombinedKey::new(alice_key_pair.private_key(), bob_key_pair.public_key());
    let bob_combined_key =
        ReceiverCombinedKey::new(alice_key_pair.public_key(), bob_key_pair.private_key());

    let secret_message = alice_sends_secret_message(&alice_combined_key)?;
    let revealed_message = bob_receives_secret_message(secret_message, &bob_combined_key)?;

    // Congrats 🎉👏
    assert_eq!(revealed_message.content, "I ❤️ you.");
    assert_eq!(revealed_message.sender, "Alice");

    Ok(())
}
