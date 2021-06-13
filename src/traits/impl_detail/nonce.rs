use crate::random::global_rng;
use chacha20poly1305::XNonce;
use core::ops::DerefMut;

pub(in crate::traits) fn generate_nonce() -> XNonce {
    let mut rng = global_rng().lock();
    crypto_box::generate_nonce(rng.deref_mut())
}
