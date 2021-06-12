//! SerdeEncryptPublicKey in no_std mode.

#![no_std]

extern crate alloc;

mod test_util;

use alloc::{string::String, vec, vec::Vec};
use serde::{Deserialize, Serialize};
use serde_encrypt::{error::Error, traits::SerdeEncryptPublicKey};
use test_util::serde_encrypt_public_key::*;

#[test]
fn test_serde_encrypt_public_key_nostd() -> Result<(), Error> {
    keygen!(sender_combined_key, receiver_combined_key);

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Pagination {
        limit: u64,
        offset: u64,
        total: u64,
    }

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct User {
        id: String,
        username: String,
    }

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Users {
        users: Vec<User>,

        #[serde(flatten)]
        pagination: Pagination,
    }
    impl SerdeEncryptPublicKey for Users {}

    let msg = Users {
        users: vec![
            User {
                id: "1".into(),
                username: "John".into(),
            },
            User {
                id: "2".into(),
                username: "Jane".into(),
            },
        ],
        pagination: Pagination {
            limit: 100,
            offset: 200,
            total: 256,
        },
    };
    enc_dec_assert_eq(&msg, &sender_combined_key, &receiver_combined_key)?;
    Ok(())
}
