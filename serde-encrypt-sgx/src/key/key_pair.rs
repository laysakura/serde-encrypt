use serde_encrypt_core::key::key_pair::{
    private_key::{ReceiverPrivateKey, SenderPrivateKey},
    public_key::{ReceiverPublicKey, SenderPublicKey},
    ReceiverKeyPairCore, SenderKeyPairCore,
};

use crate::random::RngSingletonImpl;

#[derive(Clone, Debug)]
pub struct SenderKeyPair {
    sender_private_key: SenderPrivateKey,
    sender_public_key: SenderPublicKey,
}

impl SenderKeyPairCore for SenderKeyPair {
    type R = RngSingletonImpl;

    fn new(sender_private_key: SenderPrivateKey, sender_public_key: SenderPublicKey) -> Self
    where
        Self: Sized,
    {
        Self {
            sender_private_key,
            sender_public_key,
        }
    }

    fn private_key(&self) -> &SenderPrivateKey {
        &self.sender_private_key
    }

    fn public_key(&self) -> &SenderPublicKey {
        &self.sender_public_key
    }
}

#[derive(Clone, Debug)]
pub struct ReceiverKeyPair {
    receiver_private_key: ReceiverPrivateKey,
    receiver_public_key: ReceiverPublicKey,
}

impl ReceiverKeyPairCore for ReceiverKeyPair {
    type R = RngSingletonImpl;

    fn new(receiver_private_key: ReceiverPrivateKey, receiver_public_key: ReceiverPublicKey) -> Self
    where
        Self: Sized,
    {
        Self {
            receiver_private_key,
            receiver_public_key,
        }
    }

    fn private_key(&self) -> &ReceiverPrivateKey {
        &self.receiver_private_key
    }

    fn public_key(&self) -> &ReceiverPublicKey {
        &self.receiver_public_key
    }
}
