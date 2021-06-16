//! RNG

#[cfg(not(feature = "std"))]
use alloc::format;
#[cfg(not(feature = "std"))]
use core::convert::TryInto;

use crate::{Lazy, Mutex, MutexGuard};
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
use serde_encrypt_core::random::RngSingleton;

static GLOBAL_RNG: Lazy<Mutex<ChaCha12Rng>> =
    Lazy::new(|| Mutex::new(RngSingletonImpl::chacha12_rng()));

/// RNG singleton implementation
#[derive(Clone, Debug)]
pub struct RngSingletonImpl;
impl RngSingleton for RngSingletonImpl {
    type D = MutexGuard<'static, ChaCha12Rng>;

    #[cfg(feature = "std")]
    fn instance() -> Self::D {
        GLOBAL_RNG
            .lock()
            .expect("Panic occurred in another MutexGuard scope")
    }
    #[cfg(not(feature = "std"))]
    fn instance() -> Self::D {
        GLOBAL_RNG.lock()
    }
}
impl RngSingletonImpl {
    #[cfg(feature = "std")]
    fn chacha12_rng() -> ChaCha12Rng {
        ChaCha12Rng::from_entropy()
    }

    #[cfg(not(feature = "std"))]
    fn chacha12_rng() -> ChaCha12Rng {
        ChaCha12Rng::from_seed(Self::gen_seed())
    }

    #[cfg(not(feature = "std"))]
    /// Generate random seed from memory address.
    ///
    /// Note that this is for no_std env.
    /// If you use `SeedableRng::from_entropy` would more secure.
    /// E.g. Single process environments may have deterministic memory address.
    fn gen_seed() -> [u8; 32] {
        let a0 = Self::gen_rand_u64_mem_addr();
        let a1 = a0 ^ a0.rotate_right(13);
        let a2 = a1 ^ a1.rotate_right(17);
        let a3 = a2 ^ a2.rotate_right(5);

        let a0 = a0.to_le_bytes();
        let a1 = a1.to_le_bytes();
        let a2 = a2.to_le_bytes();
        let a3 = a3.to_le_bytes();

        [a0, a1, a2, a3]
            .concat()
            .try_into()
            .expect("must be 32 bytes")
    }

    /// Poorly distributed numbers to use themselves as rand.
    /// Just use as seed.
    #[cfg(not(feature = "std"))]
    fn gen_rand_u64_mem_addr() -> u64 {
        let x = 123;
        let x_addr = &x as *const i32;
        let x_addr_s = format!("{:p}", x_addr);
        let x_addr_s = x_addr_s.trim_start_matches("0x");
        u64::from_str_radix(x_addr_s, 16).expect("must be a hex string")
    }
}
