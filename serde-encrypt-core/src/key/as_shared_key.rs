//! Keys for common key cryptosystem.

use crate::random::RngSingleton;
use chacha20poly1305::Key as ChaChaKey;
use core::{convert::TryInto, ops::DerefMut};
use rand::RngCore;

/// 32-byte key shared among sender and receiver secretly.
///
/// The reason why this is not a struct but a trait is:
///
/// - shared key should be serialized and encrypted in order to be shared among peers
/// - but this -core trait is serialization agnostic.
///
/// So, implementators of this trait is expected to have `serde::{Serialize, Deserialize}` and `SerdeSerializePublicKey` trait bounds.
pub trait AsSharedKey {
    /// RNG singleton
    type R: RngSingleton;

    /// Constructor from secret bytes.
    fn from_array(key: [u8; 32]) -> Self
    where
        Self: Sized;

    /// Ref to 32-byte slice
    fn as_slice(&self) -> &[u8];

    /// Generates secure random key.
    ///
    /// Random number generator which implements `CryptRng` is used internally.
    fn generate() -> Self
    where
        Self: Sized,
    {
        let mut rng = Self::R::instance();

        let r0 = rng.deref_mut().next_u64();
        let r1 = rng.deref_mut().next_u64();
        let r2 = rng.deref_mut().next_u64();
        let r3 = rng.deref_mut().next_u64();

        let key = [
            r0.to_le_bytes(),
            r1.to_le_bytes(),
            r2.to_le_bytes(),
            r3.to_le_bytes(),
        ]
        .concat()
        .try_into()
        .expect("must be 32 bytes");

        Self::from_array(key)
    }

    /// Makes `chacha20poly1305::Key`
    fn to_chacha_key(&self) -> &ChaChaKey {
        ChaChaKey::from_slice(self.as_slice())
    }
}
