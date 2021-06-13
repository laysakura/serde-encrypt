//! Keys for common key cryptosystem.

use chacha20poly1305::Key as ChaChaKey;
use core::{convert::TryInto, ops::DerefMut};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::random::global_rng;

/// 32-byte key shared among sender and receiver secretly.
///
/// It is a good practice to use [SerdeEncryptPublicKey](crate::traits::SerdeEncryptPublicKey)
/// to exchange this shared key.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub struct SharedKey([u8; 32]);

impl SharedKey {
    /// Constructor from known secret bytes.
    pub fn from_array(key: [u8; 32]) -> Self {
        Self(key)
    }

    /// Generates secure random key.
    ///
    /// Random number generator which implements `CryptRng` is used internally.
    pub fn generate() -> Self {
        let mut rng = global_rng().lock();

        let r0: u64 = rng.deref_mut().gen();
        let r1: u64 = rng.deref_mut().gen();
        let r2: u64 = rng.deref_mut().gen();
        let r3: u64 = rng.deref_mut().gen();

        let key = [
            r0.to_le_bytes(),
            r1.to_le_bytes(),
            r2.to_le_bytes(),
            r3.to_le_bytes(),
        ]
        .concat()
        .try_into()
        .expect("must be 32 bytes");

        Self(key)
    }

    pub(crate) fn to_chacha_key(&self) -> &ChaChaKey {
        ChaChaKey::from_slice(&self.0)
    }
}
