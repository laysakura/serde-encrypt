//! Encrypted message structure.

use alloc::vec::Vec;

/// Encrypted message structure.
///
/// This struct is serialized into `Vec<u8>` (and deserialized from `Vec<u8>`).
/// In order to send an EncryptedMessage to a remote receiver, use `let bin = encrypted_message.serialize();`.
/// Then, the receiver should deserialize it by `let encrypted_message = EncryptedMessage::deserialize(bin);`.
///
/// This struct includes Nonce, which is internally used when a receiver decrypt the encrypted message.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct EncryptedMessage {
    encrypted: Vec<u8>,

    /// XChaCha20 nonce (192-bit / 24-byte)
    nonce: [u8; 24],
}

impl EncryptedMessage {
    /// Serialize this encrypted message into binary in order to send it to a remote receiver.
    pub fn serialize(self) -> Vec<u8> {
        todo!()
    }

    /// Deserializer function for a receiver.
    /// TODO return Result when nonce not found
    pub fn deserialize(serialized_encrypted_message: Vec<u8>) -> Self {
        todo!()
    }

    pub(crate) fn new(encrypted: Vec<u8>, nonce: [u8; 24]) -> Self {
        Self { encrypted, nonce }
    }

    pub(crate) fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub(crate) fn encrypted(&self) -> &[u8] {
        &self.encrypted
    }
}
