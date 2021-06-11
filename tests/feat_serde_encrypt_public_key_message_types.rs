//! SerdeEncryptPublicKey to various types.

mod test_util;

use serde::{Deserialize, Serialize};
use serde_encrypt::{error::Error, traits::SerdeEncryptPublicKey};
use test_util::serde_encrypt_public_key::*;

#[test]
fn test_serde_encrypt_public_key_message_types() -> Result<(), Error> {
    let (sender_key_pair, receiver_key_pair) = gen_key_pairs();
    let (sender_combined_key, receiver_combined_key) =
        mk_combined_keys(&sender_key_pair, &receiver_key_pair);

    {
        // primitive type (fixed len)
        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        struct I32(i32);
        impl SerdeEncryptPublicKey for I32 {}

        let msg: I32 = I32(42);
        enc_dec_assert_eq(&msg, &sender_combined_key, &receiver_combined_key)?;
    }

    Ok(())
}
