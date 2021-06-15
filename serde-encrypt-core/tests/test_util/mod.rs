#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::Debug;

pub fn assert_no_duplicate<T>(generator: impl Fn() -> T, n_generate: usize)
where
    T: PartialEq + Debug,
{
    let mut vs = Vec::<T>::new();
    for _ in 0..n_generate {
        let v = generator();
        vs.push(v);
    }

    for i in 0..n_generate {
        let v_i = vs.get(i).unwrap();
        for j in (i + 1)..n_generate {
            let v_j = vs.get(j).unwrap();
            assert_ne!(v_i, v_j);
        }
    }
}
