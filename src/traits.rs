//! Traits to enable encrypted-serialization to your struct/enum.

mod impl_detail;
mod serde_encrypt_public_key;
mod serde_encrypt_shared_key;

pub use impl_detail::SerializedPlain;
pub use serde_encrypt_public_key::SerdeEncryptPublicKey;
pub use serde_encrypt_shared_key::SerdeEncryptSharedKey;
