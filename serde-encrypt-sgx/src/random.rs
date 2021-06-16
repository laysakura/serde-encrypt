use crate::{Lazy, Mutex, MutexGuard};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha12Rng;
use serde_encrypt_core::random::RngSingleton;

static GLOBAL_RNG: Lazy<Mutex<ChaCha12Rng>> =
    Lazy::new(|| Mutex::new(RngSingletonImpl::chacha12_rng()));

#[derive(Clone, Debug)]
pub struct RngSingletonImpl;

impl RngSingleton for RngSingletonImpl {
    type D = MutexGuard<'static, ChaCha12Rng>;

    fn instance() -> Self::D {
        GLOBAL_RNG
            .lock()
            .expect("Panic occurred in another MutexGuard scope")
    }
}

impl RngSingletonImpl {
    fn chacha12_rng() -> ChaCha12Rng {
        ChaCha12Rng::from_entropy()
    }
}
