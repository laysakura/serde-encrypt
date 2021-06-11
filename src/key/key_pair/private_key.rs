//! X25519 private-key.

use crypto_box::SecretKey;

#[derive(Clone, Debug)]
pub struct SenderPrivateKey(SecretKey);

impl AsRef<SecretKey> for SenderPrivateKey {
    fn as_ref(&self) -> &SecretKey {
        &self.0
    }
}

impl From<SecretKey> for SenderPrivateKey {
    fn from(s: SecretKey) -> Self {
        Self(s)
    }
}

#[derive(Clone, Debug)]
pub struct ReceiverPrivateKey(SecretKey);

impl AsRef<SecretKey> for ReceiverPrivateKey {
    fn as_ref(&self) -> &SecretKey {
        &self.0
    }
}

impl From<SecretKey> for ReceiverPrivateKey {
    fn from(s: SecretKey) -> Self {
        Self(s)
    }
}
