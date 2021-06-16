use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use serde_encrypt_core::random::RngSingleton;
use spin::{Lazy, Mutex, MutexGuard};

static GLOBAL_RNG: Lazy<Mutex<ChaCha12Rng>> =
    Lazy::new(|| Mutex::new(ChaCha12Rng::from_seed([0u8; 32])));

#[derive(Clone, Debug)]
pub struct TestRngSingleton;
impl RngSingleton for TestRngSingleton {
    type D = MutexGuard<'static, ChaCha12Rng>;

    fn instance() -> Self::D {
        GLOBAL_RNG.lock()
    }
}
