//! no_std random number generator

use core::convert::TryInto;

use alloc::format;
use rand_chacha::{rand_core::SeedableRng, ChaCha12Rng};
use spin::{Lazy, Mutex};

static GLOBAL_RNG: Lazy<Mutex<ChaCha12Rng>> =
    Lazy::new(|| Mutex::new(ChaCha12Rng::from_seed(gen_seed())));

pub(crate) fn global_rng() -> &'static Mutex<ChaCha12Rng> {
    &*GLOBAL_RNG
}

fn gen_seed() -> [u8; 32] {
    let a0 = gen_rand_u64_mem_addr();
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
fn gen_rand_u64_mem_addr() -> u64 {
    let x = 123;
    let x_addr = &x as *const i32;
    let x_addr_s = format!("{:p}", x_addr);
    let x_addr_s = x_addr_s.trim_start_matches("0x");
    u64::from_str_radix(x_addr_s, 16).expect("must be a hex string")
}
