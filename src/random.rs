use rand_chacha::{rand_core::SeedableRng, ChaCha12Rng};
use spin::{Lazy, Mutex};

static GLOBAL_RNG: Lazy<Mutex<ChaCha12Rng>> =
    Lazy::new(|| Mutex::new(ChaCha12Rng::from_seed(gen_seed())));

pub(crate) fn global_rng() -> &'static Mutex<ChaCha12Rng> {
    &*GLOBAL_RNG
}

fn gen_seed() -> [u8; 32] {
    // FIXME generate different seeds for each process
    [0; 32]
}
