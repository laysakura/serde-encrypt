//! Test if SharedKey::generates() emits different key every time.

mod test_util;

use serde_encrypt_core::key::shared_key_core::SharedKeyCore;
use test_util::*;

#[test]
fn test_shared_key_distribution() {
    assert_no_duplicate(SharedKeyCore::generate, 100);
}
