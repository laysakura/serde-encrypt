//! serde-serializable shared key.

use serde::{Deserialize, Serialize};

use crate::traits::SerdeEncryptPublicKey;
use crate::{random::RngSingletonImpl, AsSharedKey};

/// 32-byte key shared among sender and receiver secretly.
///
/// It is a good practice to use [SerdeEncryptPublicKey](crate::traits::SerdeEncryptPublicKey)
/// to exchange this shared key.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub struct SharedKey([u8; 32]);

impl SharedKey {
    /// Build SharedKey from static `[u8; 32]` data at compile time.
    pub const fn new_const(data: [u8; 32]) -> Self {
        Self(data)
    }

    /// Build SharedKey from `[u8; 32]` data.
    pub fn new(data: [u8; 32]) -> Self {
        Self(data)
    }
}

impl AsSharedKey for SharedKey {
    type R = RngSingletonImpl;

    fn from_array(key: [u8; 32]) -> Self {
        Self(key)
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        use crate::serialize::impls::BincodeSerializer;
        impl SerdeEncryptPublicKey for SharedKey {
            type S = BincodeSerializer<Self>;
        }
    } else {
        use crate::serialize::impls::PostcardSerializer;
        impl SerdeEncryptPublicKey for SharedKey {
            type S = PostcardSerializer<Self>;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::convert::TryInto;

    #[test]
    fn build_sharedkey_from_array() {
        const STATIC_ARRAY: [u8; 32] = [
            1, 1, 4, 5, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];

        let runtime_array: [u8; 32] = Vec::from(STATIC_ARRAY).try_into().unwrap();

        // Building SharedKey directly from static_array only works in the same mod.
        const SHAREDKEY_CONST_INTERNAL: SharedKey = SharedKey(STATIC_ARRAY);

        // Test `const fn new`, which build SharedKey in compile time
        const SHARED_KEY_CONST: SharedKey = SharedKey::new_const(STATIC_ARRAY);

        // Test `fn new`, which build SharedKey in runtime.
        let shared_key = SharedKey::new(runtime_array);

        assert_eq!(shared_key, SHAREDKEY_CONST_INTERNAL);
        assert_eq!(SHARED_KEY_CONST, SHAREDKEY_CONST_INTERNAL);
    }
}
