//! SerdeEncryptPublicKey to various types.
//!
//! Some types are from [Examples in Serde document](https://serde.rs/examples.html).

mod test_util;

use pretty_assertions::assert_eq;
use serde::{Deserialize, Serialize};
use serde_encrypt::{error::Error, traits::SerdeEncryptPublicKey};
use test_util::serde_encrypt_public_key::*;

#[test]
fn test_serde_encrypt_public_key_message_types() -> Result<(), Error> {
    keygen!(sender_combined_key, receiver_combined_key);

    {
        // unit struct
        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        struct Unit;
        impl SerdeEncryptPublicKey for Unit {}

        let msg = Unit;
        enc_dec_assert_eq(&msg, &sender_combined_key, &receiver_combined_key)?;
    }
    {
        // primitive type (fixed len)
        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        struct I32(i32);
        impl SerdeEncryptPublicKey for I32 {}

        let msg = I32(42);
        enc_dec_assert_eq(&msg, &sender_combined_key, &receiver_combined_key)?;
    }
    {
        // primitive type (unbound len)
        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        struct MyString(String);
        impl SerdeEncryptPublicKey for MyString {}

        let msg = MyString("MyString".to_string());
        enc_dec_assert_eq(&msg, &sender_combined_key, &receiver_combined_key)?;
    }
    {
        // tuple struct
        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        struct Tuple(i16, i32, i64);
        impl SerdeEncryptPublicKey for Tuple {}

        let msg = Tuple(42, 4242, 424242);
        enc_dec_assert_eq(&msg, &sender_combined_key, &receiver_combined_key)?;
    }
    {
        // enum
        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        struct Params;

        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        struct Value;

        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        enum Message {
            Request {
                id: String,
                method: String,
                params: Params,
            },
            Response {
                id: String,
                result: Value,
            },
        }
        impl SerdeEncryptPublicKey for Message {}

        let msg_request = Message::Request {
            id: "1".into(),
            method: "get_foo".into(),
            params: Params,
        };
        enc_dec_assert_eq(&msg_request, &sender_combined_key, &receiver_combined_key)?;

        let msg_response = Message::Response {
            id: "1".into(),
            result: Value,
        };
        enc_dec_assert_eq(&msg_response, &sender_combined_key, &receiver_combined_key)?;
    }
    {
        // enum tagged as "type"
        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        struct Params;

        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        struct Value;

        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        #[serde(tag = "type")]
        enum Message {
            Request {
                id: String,
                method: String,
                params: Params,
            },
            Response {
                id: String,
                result: Value,
            },
        }
        impl SerdeEncryptPublicKey for Message {}

        let msg_request = Message::Request {
            id: "1".into(),
            method: "get_foo".into(),
            params: Params,
        };
        enc_dec_assert_eq(&msg_request, &sender_combined_key, &receiver_combined_key)?;

        let msg_response = Message::Response {
            id: "1".into(),
            result: Value,
        };
        enc_dec_assert_eq(&msg_response, &sender_combined_key, &receiver_combined_key)?;
    }
    {
        // enum adjacently tagged
        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        struct Params;

        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        struct Value;

        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        #[serde(tag = "t", content = "c")]
        enum Message {
            Request {
                id: String,
                method: String,
                params: Params,
            },
            Response {
                id: String,
                result: Value,
            },
        }
        impl SerdeEncryptPublicKey for Message {}

        let msg_request = Message::Request {
            id: "1".into(),
            method: "get_foo".into(),
            params: Params,
        };
        enc_dec_assert_eq(&msg_request, &sender_combined_key, &receiver_combined_key)?;

        let msg_response = Message::Response {
            id: "1".into(),
            result: Value,
        };
        enc_dec_assert_eq(&msg_response, &sender_combined_key, &receiver_combined_key)?;
    }
    {
        // enum untagged
        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        struct Params;

        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        struct Value;

        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        #[serde(untagged)]
        enum Message {
            Request {
                id: String,
                method: String,
                params: Params,
            },
            Response {
                id: String,
                result: Value,
            },
        }
        impl SerdeEncryptPublicKey for Message {}

        let msg_request = Message::Request {
            id: "1".into(),
            method: "get_foo".into(),
            params: Params,
        };
        enc_dec_assert_eq(&msg_request, &sender_combined_key, &receiver_combined_key)?;

        let msg_response = Message::Response {
            id: "1".into(),
            result: Value,
        };
        enc_dec_assert_eq(&msg_response, &sender_combined_key, &receiver_combined_key)?;
    }
    {
        // skip_deserializing
        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        struct Struct {
            a: i32,
            b: i32,
            #[serde(skip_deserializing)]
            c: i32,
        }
        impl SerdeEncryptPublicKey for Struct {}

        let msg = Struct {
            a: 42,
            b: 42,
            c: 42,
        };
        let receive_msg = enc_dec(&msg, &sender_combined_key, &receiver_combined_key)?;

        assert_eq!(msg.a, receive_msg.a);
        assert_eq!(msg.b, receive_msg.b);
        assert_eq!(
            receive_msg.c, 0,
            "deserialization skipped and got default value"
        );
    }
    {
        // skip_deserializing and custom default

        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        struct Request {
            #[serde(skip_deserializing)]
            #[serde(default = "default_resource")]
            resource: String,

            #[serde(skip_deserializing)]
            #[serde(default)]
            timeout: Timeout,

            #[serde(skip_deserializing)]
            #[serde(default = "Priority::lowest")]
            priority: Priority,
        }

        fn default_resource() -> String {
            "/".to_string()
        }
        impl SerdeEncryptPublicKey for Request {}

        /// Timeout in seconds.
        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        struct Timeout(u32);
        impl Default for Timeout {
            fn default() -> Self {
                Timeout(30)
            }
        }

        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        enum Priority {
            ExtraHigh,
            High,
            Normal,
            Low,
            ExtraLow,
        }
        impl Priority {
            fn lowest() -> Self {
                Priority::ExtraLow
            }
        }

        let msg = Request {
            resource: "ignored".into(),
            timeout: Timeout(12345),
            priority: Priority::ExtraHigh,
        };
        let receive_msg = enc_dec(&msg, &sender_combined_key, &receiver_combined_key)?;

        // all fields from sender are skipped deserialization
        assert_eq!(receive_msg.resource, default_resource());
        assert_eq!(receive_msg.timeout, Timeout::default());
        assert_eq!(receive_msg.priority, Priority::lowest());
    }
    {
        // flatten

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
    }
    {
        // struct with reference
        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        struct Str<'a>(&'a str);
        impl<'a> SerdeEncryptPublicKey for Str<'a> {}

        let msg = Str("Str");
        let encrypted_msg = msg.encrypt(&sender_combined_key)?;

        let x = Str::decrypt_to_serialized(&encrypted_msg, &receiver_combined_key)?;
        let r_msg = x.finalize()?;

        pretty_assertions::assert_eq!(msg, r_msg);
    }
    {
        // serialize enum as number
        use serde_repr::*;

        #[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug)]
        #[repr(u8)]
        enum SmallPrime {
            Two = 2,
            Three = 3,
            Five = 5,
            Seven = 7,
        }
        impl SerdeEncryptPublicKey for SmallPrime {}

        let msg_two = SmallPrime::Two;
        enc_dec_assert_eq(&msg_two, &sender_combined_key, &receiver_combined_key)?;

        let msg_seven = SmallPrime::Seven;
        enc_dec_assert_eq(&msg_seven, &sender_combined_key, &receiver_combined_key)?;
    }
    {
        // serialize fields as camelCase

        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Person {
            first_name: String,
            last_name: String,
        }
        impl SerdeEncryptPublicKey for Person {}

        let msg = Person {
            first_name: "John".into(),
            last_name: "Doe".into(),
        };
        enc_dec_assert_eq(&msg, &sender_combined_key, &receiver_combined_key)?;
    }
    {
        // skip_serializing
        use std::collections::BTreeMap as Map;

        #[derive(PartialEq, Debug, Serialize, Deserialize)]
        struct Resource {
            // Always serialized.
            name: String,

            // Never serialized.
            #[serde(skip_serializing)]
            hash: String,

            // Use a method to decide whether the field should be skipped.
            #[serde(skip_serializing_if = "Map::is_empty")]
            metadata: Map<String, String>,
        }
        impl SerdeEncryptPublicKey for Resource {}

        let msg_with_metadata = Resource {
            name: "a.txt".into(),
            hash: "deadc0de".into(),
            metadata: vec![("size".into(), "123".into())].into_iter().collect(),
        };
        let r_msg_with_metadata = enc_dec(
            &msg_with_metadata,
            &sender_combined_key,
            &receiver_combined_key,
        )?;

        assert_eq!(r_msg_with_metadata.name, msg_with_metadata.name);
        assert_eq!(r_msg_with_metadata.hash, String::default());
        assert_eq!(r_msg_with_metadata.metadata, msg_with_metadata.metadata);
    }
    Ok(())
}
