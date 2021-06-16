//! X25519 public-key.

use crypto_box::PublicKey;

/// Message sender's public key
#[derive(Clone, Debug)]
pub struct SenderPublicKey(PublicKey);

impl AsRef<PublicKey> for SenderPublicKey {
    fn as_ref(&self) -> &PublicKey {
        &self.0
    }
}

impl From<PublicKey> for SenderPublicKey {
    fn from(p: PublicKey) -> Self {
        Self(p)
    }
}

/// Message receiver's public key
#[derive(Clone, Debug)]
pub struct ReceiverPublicKey(PublicKey);

impl AsRef<PublicKey> for ReceiverPublicKey {
    fn as_ref(&self) -> &PublicKey {
        &self.0
    }
}

impl From<PublicKey> for ReceiverPublicKey {
    fn from(p: PublicKey) -> Self {
        Self(p)
    }
}
