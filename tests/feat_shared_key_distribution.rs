//! Test if SharedKey::generates() emits different key every time.

mod test_util;

use serde_encrypt::key::shared_key::SharedKey;
use test_util::*;

#[test]
fn test_shared_key_distribution() {
    assert_no_duplicate(|| SharedKey::generate(), 100);
}
