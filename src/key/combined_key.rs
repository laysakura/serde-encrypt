//! "Combined key" for Diffie-Hellman key exchange.
//! A combined key consists of either:
//!
//! - (`Alice's private key`, `Bob's public key`) pair
//! - (`Alice's public key`, `Bob's private key`) pair

use super::key_pair::{
    private_key::{ReceiverPrivateKey, SenderPrivateKey},
    public_key::{ReceiverPublicKey, SenderPublicKey},
};

/// (`Alice's private key`, `Bob's public key`) pair.
///
/// (Alice is a sender and Bob a receiver.)
#[derive(Clone, Debug)]
pub struct SenderCombinedKey<'s, 'r> {
    sender_private_key: &'s SenderPrivateKey,
    receiver_public_key: &'r ReceiverPublicKey,
}

impl<'s, 'r> SenderCombinedKey<'s, 'r> {
    /// Constructor.
    pub fn new(
        sender_private_key: &'s SenderPrivateKey,
        receiver_public_key: &'r ReceiverPublicKey,
    ) -> Self {
        Self {
            sender_private_key,
            receiver_public_key,
        }
    }

    pub(crate) fn sender_private_key(&self) -> &SenderPrivateKey {
        &self.sender_private_key
    }

    pub(crate) fn receiver_public_key(&self) -> &ReceiverPublicKey {
        &self.receiver_public_key
    }
}

/// (`Alice's public key`, `Bob's private key`) pair.
///
/// (Alice is a sender and Bob a receiver.)
#[derive(Clone, Debug)]
pub struct ReceiverCombinedKey<'s, 'r> {
    sender_public_key: &'s SenderPublicKey,
    receiver_private_key: &'r ReceiverPrivateKey,
}

impl<'s, 'r> ReceiverCombinedKey<'s, 'r> {
    /// Constructor.
    pub fn new(
        sender_public_key: &'s SenderPublicKey,
        receiver_private_key: &'r ReceiverPrivateKey,
    ) -> Self {
        Self {
            sender_public_key,
            receiver_private_key,
        }
    }
}
