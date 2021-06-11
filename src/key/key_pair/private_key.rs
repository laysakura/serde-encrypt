//! X25519 private-key.

use crypto_box::SecretKey;

#[derive(Clone, Debug)]
pub struct SenderPrivateKey(SecretKey);

#[derive(Clone, Debug)]
pub struct ReceiverPrivateKey(SecretKey);
