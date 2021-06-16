//! RNG abstract

use core::ops::DerefMut;

use rand_chacha::ChaCha12Rng;

/// RNG singleton
pub trait RngSingleton {
    /// &mut ChaCha12Rng
    type D: DerefMut<Target = ChaCha12Rng>;

    /// Singleton instance
    fn instance() -> Self::D;
}
