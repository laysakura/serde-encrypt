use alloc::vec::Vec;
use serde_encrypt_core::encrypt::plain_message_public_key::PlainMessagePublicKeyCore;

use crate::random::RngSingletonImpl;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PlainMessagePublicKey(Vec<u8>);

impl PlainMessagePublicKeyCore for PlainMessagePublicKey {
    type R = RngSingletonImpl;

    fn new(plain_message: Vec<u8>) -> Self
    where
        Self: Sized,
    {
        Self(plain_message)
    }

    fn into_vec(self) -> Vec<u8> {
        self.0
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}
