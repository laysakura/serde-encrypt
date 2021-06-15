//! Shows how to use SerdeEncryptPublicKey for struct with reference fields.

use serde::{Deserialize, Serialize};
use serde_encrypt::{
    serialize::{impls::CborSerializer, TypedSerialized},
    traits::SerdeEncryptPublicKey,
    EncryptedMessage, Error, ReceiverCombinedKey, ReceiverKeyPair, SenderCombinedKey,
    SenderKeyPair,
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

impl<'a> SerdeEncryptPublicKey for Message<'a> {
    type S = CborSerializer<Self>;
}

fn alice_sends_secret_message(combined_key: &SenderCombinedKey) -> Result<Vec<u8>, Error> {
    let msg = Message {
        content: Content {
            title: "my heart",
            sentence: "I ❤️ you.",
        },
        sender: "Alice",
    };
    let encrypted_message = msg.encrypt(combined_key)?;
    Ok(encrypted_message.serialize())
}

fn bob_reads_secret_message(
    encrypted_serialized: Vec<u8>,
    combined_key: &ReceiverCombinedKey,
) -> Result<(), Error> {
    let encrypted_message = EncryptedMessage::deserialize(encrypted_serialized)?;

    let decrypted = Message::decrypt_ref(&encrypted_message, &combined_key)?;
    let revealed_message = decrypted.deserialize()?;

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

    let secret_message = alice_sends_secret_message(&alice_combined_key)?;
    bob_reads_secret_message(secret_message, &bob_combined_key)
}
