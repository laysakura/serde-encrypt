//! Shared key encryption.

mod shared_key_core;
mod shared_key_deterministic_core;

pub use shared_key_core::PlainMessageSharedKeyCore;
pub use shared_key_deterministic_core::PlainMessageSharedKeyDeterministicCore;

use super::encrypted_message::EncryptedMessage;
use crate::{error::Error, key::as_shared_key::AsSharedKey};
use alloc::{format, vec::Vec};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use crypto_box::aead::{Aead, NewAead};

/// Encrypt into EncryptedMessage
fn encrypt<S>(
    plain_message: &[u8],
    shared_key: &S,
    nonce: XNonce,
) -> Result<EncryptedMessage, Error>
where
    S: AsSharedKey,
{
    let chacha = XChaCha20Poly1305::new(shared_key.to_chacha_key());

    let encrypted = chacha.encrypt(&nonce, plain_message).map_err(|e| {
        Error::encryption_error(&format!(
            "failed to encrypt serialized data by XChaCha20: {:?}",
            e
        ))
    })?;

    Ok(EncryptedMessage::new(encrypted, nonce.into()))
}

/// Decrypt from EncryptedMessage
fn decrypt<S>(encrypted_message: &EncryptedMessage, shared_key: &S) -> Result<Vec<u8>, Error>
where
    S: AsSharedKey,
{
    let nonce = encrypted_message.nonce();
    let chacha = XChaCha20Poly1305::new(shared_key.to_chacha_key());

    let encrypted = encrypted_message.encrypted();

    chacha.decrypt(nonce.into(), encrypted).map_err(|e| {
        Error::decryption_error(&format!(
            "error on decryption of XChaCha20 cipher-text: {:?}",
            e
        ))
    })
}
