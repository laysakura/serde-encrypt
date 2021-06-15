//! Test if SharedKey::generates() emits different key every time.

mod test_util;

use serde_encrypt_core::key::as_shared_key::AsSharedKey;
use test_util::*;

#[test]
fn test_shared_key_distribution() {
    #[derive(PartialEq, Debug)]
    struct MySharedKey([u8; 32]);

    impl AsSharedKey for MySharedKey {
        fn from_array(key: [u8; 32]) -> Self
        where
            Self: Sized,
        {
            Self(key)
        }

        fn as_slice(&self) -> &[u8] {
            &self.0
        }
    }

    assert_no_duplicate(MySharedKey::generate, 100);
}
