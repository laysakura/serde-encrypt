//! RNG abstract

use core::ops::DerefMut;
use chacha20poly1305::XNonce;

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{CryptoRng, RngCore};

/// RNG singleton
pub trait RngSingleton {
    /// &mut ChaCha20Rng
    type D: DerefMut<Target = ChaCha20Rng>;

    /// Singleton instance
    fn instance() -> Self::D;
}

pub(crate) fn generate_nonce<R: RngCore + CryptoRng>(rng: &mut R) -> XNonce {
    let mut nonce = XNonce::default();
    rng.fill_bytes(&mut nonce);
    nonce
}