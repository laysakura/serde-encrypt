//! Encrypted message structure.

use core::convert::TryInto;

use alloc::vec::Vec;

use crate::error::Error;

/// 192-bit / 24-byte nonce used in XChaCha20 / XSalsa20
const NONCE_SIZE: usize = 24;

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
    nonce: [u8; NONCE_SIZE],
}

impl EncryptedMessage {
    /// Serialize this encrypted message into binary in order to send it to a remote receiver.
    pub fn serialize(mut self) -> Vec<u8> {
        let mut serialized: Vec<u8> = self.nonce.to_vec();
        serialized.append(&mut self.encrypted);
        serialized
    }

    /// Deserializer function for a receiver.
    ///
    /// # Failures
    ///
    /// - [DeserializationError](crate::error::ErrorKind::DeserializationError) when:
    ///   - binary data does not have nonce.
    pub fn deserialize(mut serialized_encrypted_message: Vec<u8>) -> Result<Self, Error> {
        (serialized_encrypted_message.len() >= NONCE_SIZE).then(|| {
            let encrypted = serialized_encrypted_message.split_off(NONCE_SIZE);
            Self {
                encrypted,
                nonce: serialized_encrypted_message.try_into().expect("length already checked"),
            }
        }).ok_or_else(||
            Error::decryption_error("binary data to decrypt (and then deserialize) does not seem to have nonce data"))
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

#[cfg(test)]
mod tests {
    use alloc::vec;

    use crate::error::ErrorKind;

    use super::*;

    #[test]
    fn test_serialization() -> Result<(), Error> {
        let encrypted_message = EncryptedMessage::new(b"*ENCRYPTED*".to_vec(), [42u8; 24]);
        let bin = encrypted_message.clone().serialize();
        assert_eq!(EncryptedMessage::deserialize(bin)?, encrypted_message);
        Ok(())
    }

    #[test]
    fn test_decryption_error_on_no_nonce() {
        let bin = vec![42u8; NONCE_SIZE - 1];
        let e = EncryptedMessage::deserialize(bin).unwrap_err();
        assert_eq!(e.kind(), &ErrorKind::DecryptionError);
    }
}
