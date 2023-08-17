//! Shared key encryption.

use crate::encrypt::encrypted_message::EncryptedMessage;
use crate::random::RngSingleton;
use crate::{error::Error, key::as_shared_key::AsSharedKey};
use alloc::vec::Vec;
use chacha20poly1305::XNonce;
use core::ops::DerefMut;
use rand_chacha::rand_core::RngCore;

use super::{decrypt, encrypt};

/// Plain message structure serialized via serde.
pub trait PlainMessageSharedKeyCore {
    /// RNG singleton
    type R: RngSingleton;

    /// Constructor
    fn new(plain_message: Vec<u8>) -> Self
    where
        Self: Sized;

    /// Raw representation
    fn into_vec(self) -> Vec<u8>;

    /// Ref to raw representation
    fn as_slice(&self) -> &[u8];

    /// Encrypt into EncryptedMessage
    fn encrypt<S>(&self, shared_key: &S) -> Result<EncryptedMessage, Error>
    where
        S: AsSharedKey,
    {
        let nonce = Self::generate_nonce();
        encrypt(self.as_slice(), shared_key, nonce)
    }

    /// Decrypt from EncryptedMessage
    fn decrypt<S>(encrypted_message: &EncryptedMessage, shared_key: &S) -> Result<Self, Error>
    where
        Self: Sized,
        S: AsSharedKey,
    {
        let plain = decrypt(encrypted_message, shared_key)?;
        Ok(Self::new(plain))
    }

    /// Generate random nonce which is large enough (24-byte) to rarely conflict.
    fn generate_nonce() -> XNonce {
        let mut rng = Self::R::instance();
        let mut nonce = XNonce::default();
        rng.deref_mut().fill_bytes(&mut nonce);
        nonce
    }
}
