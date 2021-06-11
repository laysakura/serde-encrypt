//! X25519 public-key.

use crypto_box::PublicKey;

#[derive(Clone, Debug)]
pub struct SenderPublicKey(PublicKey);

#[derive(Clone, Debug)]
pub struct ReceiverPublicKey(PublicKey);
