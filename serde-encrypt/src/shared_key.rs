//! serde-serializable shared key.

use serde::{Deserialize, Serialize};

use crate::{AsSharedKey, random::RngSingletonImpl};
use crate::traits::SerdeEncryptPublicKey;

/// 32-byte key shared among sender and receiver secretly.
///
/// It is a good practice to use [SerdeEncryptPublicKey](crate::traits::SerdeEncryptPublicKey)
/// to exchange this shared key.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub struct SharedKey(pub [u8; 32]);

impl From<[u8; 32]> for SharedKey {
    fn from(data: [u8; 32]) -> Self {
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

    #[test]
    fn build_sharedkey_from_array() {
        const STATIC_ARRAY: [u8; 32] = [1, 1, 4, 5, 1, 4,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        const SHAREDKEY_CONST: SharedKey = SharedKey(STATIC_ARRAY);

        let shared_key = SharedKey::from(STATIC_ARRAY);

        assert_eq!(shared_key, SHAREDKEY_CONST);
    }
}