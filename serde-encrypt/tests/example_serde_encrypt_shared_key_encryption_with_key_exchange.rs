//! Shows typical use case of "Shared-key exchange by public-key encryption":
//!
//! 1. Bob (message receiver) generates shared key.
//! 2. Bob encrypts the shared key using one-time public-key encryption.
//! 3. Bob serializes the encrypted key into binary and gives it to Bob (message sender).
//! 4. Alice decrypts the binary into the shared key.
//! 5. Then Alice encrypts her secret message using the shared key and sends it to Bob.
//! 6. Bob gets the secret and decrypts it using the shared key.
//!
//! Bob generates the shared key in this example, however, it is also OK for Alice to generate the key.
//! (Both sides can start key exchange.)
//!
//! Also, note that Alice (or Bob) can continue to send secret messages to the other using the secret key.
//! In other words, public-key encryption is used only at the start of communication.
//! This achieves good performance compared to repeated public-key encryption.

use serde::{Deserialize, Serialize};
use serde_encrypt::{
    key::key_pair::{ReceiverKeyPair, SenderKeyPair},
    serialize::{impls::BincodeSerializer, TypedSerialized},
    shared_key::SharedKey,
    traits::{SerdeEncryptPublicKey, SerdeEncryptSharedKey},
    AsSharedKey, EncryptedMessage, Error, ReceiverCombinedKey, ReceiverKeyPairCore,
    SenderCombinedKey, SenderKeyPairCore,
};

impl<'a> SerdeEncryptSharedKey for Message<'a> {
    type S = BincodeSerializer<Self>;
}

fn bob_generates_shared_key() -> SharedKey {
    SharedKey::generate()
}

fn bob_sends_shared_key(
    shared_key: &SharedKey,
    combined_key: &SenderCombinedKey,
) -> Result<Vec<u8>, Error> {
    let encrypted_shared_key = shared_key.encrypt(combined_key)?;
    Ok(encrypted_shared_key.serialize())
}

fn alice_receives_shared_key(
    encrypted_serialized_shared_key: Vec<u8>,
    combined_key: &ReceiverCombinedKey,
) -> Result<SharedKey, Error> {
    let encrypted_shared_key = EncryptedMessage::deserialize(encrypted_serialized_shared_key)?;
    SharedKey::decrypt_owned(&encrypted_shared_key, combined_key)
}

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

fn alice_sends_secret_message(shared_key: &SharedKey) -> Result<Vec<u8>, Error> {
    let msg = Message {
        content: Content {
            title: "my heart",
            sentence: "I ❤️ you.",
        },
        sender: "Alice",
    };
    let encrypted_message = msg.encrypt(shared_key)?;
    Ok(encrypted_message.serialize())
}

fn bob_reads_secret_message(
    encrypted_serialized: Vec<u8>,
    shared_key: &SharedKey,
) -> Result<(), Error> {
    let encrypted_message = EncryptedMessage::deserialize(encrypted_serialized)?;

    let decrypted = Message::decrypt_ref(&encrypted_message, shared_key)?;
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
    // public/private key generation to start key exchange
    let alice_key_pair = ReceiverKeyPair::generate();
    let bob_key_pair = SenderKeyPair::generate();

    let alice_combined_key =
        ReceiverCombinedKey::new(bob_key_pair.public_key(), alice_key_pair.private_key());
    let bob_combined_key =
        SenderCombinedKey::new(bob_key_pair.private_key(), alice_key_pair.public_key());

    // key exchange
    let bob_shared_key = bob_generates_shared_key();
    let encrypted_shared_key = bob_sends_shared_key(&bob_shared_key, &bob_combined_key)?;
    let alice_shared_key = alice_receives_shared_key(encrypted_shared_key, &alice_combined_key)?;
    assert_eq!(alice_shared_key, bob_shared_key);

    // message exchange using shared key
    let secret_message = alice_sends_secret_message(&alice_shared_key)?;
    bob_reads_secret_message(secret_message, &bob_shared_key)
}
