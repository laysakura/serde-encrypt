//! Runtime check for no_std mode.

#![no_std]

extern crate alloc;

mod test_util;

use alloc::{string::String, vec, vec::Vec};
use serde::{Deserialize, Serialize};
use serde_encrypt::{
    serialize::impls::PostcardSerializer,
    shared_key::SharedKey,
    traits::{SerdeEncryptPublicKey, SerdeEncryptSharedKey},
    AsSharedKey, Error,
};
use test_util::{serde_encrypt_public_key::*, serde_encrypt_shared_key::*};

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

    // #[serde(flatten)]: https://github.com/jamesmunns/postcard/issues/29
    pagination: Pagination,
}

#[test]
fn test_serde_encrypt_public_key_nostd() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);

    impl SerdeEncryptPublicKey for Users {
        type S = PostcardSerializer<Self>;
    }

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
    public_key_enc_dec_assert_eq(&msg, &sender_combined_key, &receiver_combined_key)?;
    Ok(())
}

#[test]
fn test_serde_encrypt_shared_key_nostd() -> Result<(), Error> {
    let shared_key = SharedKey::generate();

    impl SerdeEncryptSharedKey for Users {
        type S = PostcardSerializer<Self>;
    }

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
    shared_key_enc_dec_assert_eq(&msg, &shared_key)?;
    Ok(())
}
