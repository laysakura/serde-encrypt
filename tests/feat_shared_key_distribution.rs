//! Test if SharedKey::generates() emits different key every time.

mod test_util;

use serde_encrypt::{error::Error, key::shared_key::SharedKey};

#[test]
fn test_shared_key_distribution() -> Result<(), Error> {
    let mut keys = Vec::<SharedKey>::new();
    for _ in 0..100 {
        let key = SharedKey::generate();
        keys.push(key);
    }

    for i in 0..100 {
        let key_i = keys.get(i).unwrap();
        for j in (i + 1)..100 {
            let key_j = keys.get(j).unwrap();
            assert_ne!(key_i, key_j);
        }
    }

    Ok(())
}
