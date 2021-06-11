//! Encrypted message structure.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Encrypted message structure.
///
/// This struct itself is serde-serializable and -deserializable.
/// Use any serde-serializer to send this to a receiver over the Internet.
///
/// This includes Nonce, which is internally used when a receiver decrypt the encrypted message.
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    encrypted: Vec<u8>,

    /// XChaCha20 nonce (192-bit / 24-byte)
    nonce: [u8; 24],
}
