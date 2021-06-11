//! X25519 public-key.

use crypto_box::PublicKey;

#[derive(Clone, Debug)]
pub struct SenderPublicKey(PublicKey);

impl AsRef<PublicKey> for SenderPublicKey {
    fn as_ref(&self) -> &PublicKey {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct ReceiverPublicKey(PublicKey);

impl AsRef<PublicKey> for ReceiverPublicKey {
    fn as_ref(&self) -> &PublicKey {
        &self.0
    }
}
