//! serde-serializable shared key.

use crate::{random::RngSingletonImpl, AsSharedKey};
use serde::{Deserialize, Serialize};

use crate::traits::SerdeEncryptPublicKey;

/// 32-byte key shared among sender and receiver secretly.
///
/// It is a good practice to use [SerdeEncryptPublicKey](crate::traits::SerdeEncryptPublicKey)
/// to exchange this shared key.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub struct SharedKey([u8; 32]);

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
