//! Keys for common key cryptosystem.

use crate::random::global_rng;
use crate::DerefMut;
use chacha20poly1305::Key as ChaChaKey;
use core::convert::TryInto;
use rand::Rng;

/// 32-byte key shared among sender and receiver secretly.
///
/// The reason why this is not a struct but a trait is:
///
/// - shared key should be serialized and encrypted in order to be shared among peers
/// - but this -core trait is serialization agnostic.
///
/// So, implementators of this trait is expected to have `serde::{Serialize, Deserialize}` and `SerdeSerializePublicKey` trait bounds.
pub trait AsSharedKey {
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
        let mut rng = global_rng();

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

        Self::from_array(key)
    }

    /// Makes `chacha20poly1305::Key`
    fn to_chacha_key(&self) -> &ChaChaKey {
        ChaChaKey::from_slice(self.as_slice())
    }
}
