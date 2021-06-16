use crate::{random::RngSingletonImpl, AsSharedKey};
use serde::{Deserialize, Serialize};

use crate::{serialize::impls::CborSerializer, traits::SerdeEncryptPublicKey};

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

impl SerdeEncryptPublicKey for SharedKey {
    type S = CborSerializer<Self>;
}
