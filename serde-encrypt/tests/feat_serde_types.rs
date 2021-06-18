//! Encrypt/Decrypt various serde types.
//!
//! Some types are from [Examples in Serde document](https://serde.rs/examples.html).

mod test_util;

use std::{fmt, marker::PhantomData, str::FromStr};

use pretty_assertions::assert_eq;
use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_encrypt::{
    serialize::{impls::BincodeSerializer, TypedSerialized},
    shared_key::SharedKey,
    traits::{SerdeEncryptPublicKey, SerdeEncryptSharedKey},
    AsSharedKey, Error, ErrorKind,
};
use test_util::*;
use void::Void;

#[test]
fn test_unit_struct() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);
    let shared_key = SharedKey::generate();

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Unit;
    impl SerdeEncryptPublicKey for Unit {
        type S = BincodeSerializer<Self>;
    }
    impl SerdeEncryptSharedKey for Unit {
        type S = BincodeSerializer<Self>;
    }

    let msg = Unit;
    public_key_enc_dec_assert_eq(&msg, &sender_combined_key, &receiver_combined_key)?;
    shared_key_enc_dec_assert_eq(&msg, &shared_key)?;
    Ok(())
}

#[test]
fn test_primitive_type_fixed_len() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);
    let shared_key = SharedKey::generate();

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct I32(i32);
    impl SerdeEncryptPublicKey for I32 {
        type S = BincodeSerializer<Self>;
    }
    impl SerdeEncryptSharedKey for I32 {
        type S = BincodeSerializer<Self>;
    }

    let msg = I32(42);
    public_key_enc_dec_assert_eq(&msg, &sender_combined_key, &receiver_combined_key)?;
    shared_key_enc_dec_assert_eq(&msg, &shared_key)?;
    Ok(())
}

#[test]
fn test_primitive_type_unbound_len() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);
    let shared_key = SharedKey::generate();

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct MyString(String);
    impl SerdeEncryptPublicKey for MyString {
        type S = BincodeSerializer<Self>;
    }
    impl SerdeEncryptSharedKey for MyString {
        type S = BincodeSerializer<Self>;
    }

    let msg = MyString("MyString".to_string());
    public_key_enc_dec_assert_eq(&msg, &sender_combined_key, &receiver_combined_key)?;
    shared_key_enc_dec_assert_eq(&msg, &shared_key)?;
    Ok(())
}

#[test]
fn test_tuple_struct() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);
    let shared_key = SharedKey::generate();

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Tuple(i16, i32, i64);
    impl SerdeEncryptPublicKey for Tuple {
        type S = BincodeSerializer<Self>;
    }
    impl SerdeEncryptSharedKey for Tuple {
        type S = BincodeSerializer<Self>;
    }

    let msg = Tuple(42, 4242, 424242);
    public_key_enc_dec_assert_eq(&msg, &sender_combined_key, &receiver_combined_key)?;
    shared_key_enc_dec_assert_eq(&msg, &shared_key)?;
    Ok(())
}

#[test]
fn test_enum() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);
    let shared_key = SharedKey::generate();

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
    impl SerdeEncryptPublicKey for Message {
        type S = BincodeSerializer<Self>;
    }
    impl SerdeEncryptSharedKey for Message {
        type S = BincodeSerializer<Self>;
    }

    let msg_request = Message::Request {
        id: "1".into(),
        method: "get_foo".into(),
        params: Params,
    };
    public_key_enc_dec_assert_eq(&msg_request, &sender_combined_key, &receiver_combined_key)?;
    shared_key_enc_dec_assert_eq(&msg_request, &shared_key)?;

    let msg_response = Message::Response {
        id: "1".into(),
        result: Value,
    };
    public_key_enc_dec_assert_eq(&msg_response, &sender_combined_key, &receiver_combined_key)?;
    shared_key_enc_dec_assert_eq(&msg_response, &shared_key)?;
    Ok(())
}

#[test]
fn test_enum_tagged() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);
    let shared_key = SharedKey::generate();

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
    impl SerdeEncryptPublicKey for Message {
        type S = BincodeSerializer<Self>;
    }
    impl SerdeEncryptSharedKey for Message {
        type S = BincodeSerializer<Self>;
    }

    let msg_request = Message::Request {
        id: "1".into(),
        method: "get_foo".into(),
        params: Params,
    };
    public_key_enc_dec_assert_eq(&msg_request, &sender_combined_key, &receiver_combined_key)?;
    shared_key_enc_dec_assert_eq(&msg_request, &shared_key)?;

    let msg_response = Message::Response {
        id: "1".into(),
        result: Value,
    };
    public_key_enc_dec_assert_eq(&msg_response, &sender_combined_key, &receiver_combined_key)?;
    shared_key_enc_dec_assert_eq(&msg_response, &shared_key)?;
    Ok(())
}

#[test]
fn test_enum_adjacently_tagged() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);
    let shared_key = SharedKey::generate();

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
    impl SerdeEncryptPublicKey for Message {
        type S = BincodeSerializer<Self>;
    }
    impl SerdeEncryptSharedKey for Message {
        type S = BincodeSerializer<Self>;
    }

    let msg_request = Message::Request {
        id: "1".into(),
        method: "get_foo".into(),
        params: Params,
    };
    public_key_enc_dec_assert_eq(&msg_request, &sender_combined_key, &receiver_combined_key)?;
    shared_key_enc_dec_assert_eq(&msg_request, &shared_key)?;

    let msg_response = Message::Response {
        id: "1".into(),
        result: Value,
    };
    public_key_enc_dec_assert_eq(&msg_response, &sender_combined_key, &receiver_combined_key)?;
    shared_key_enc_dec_assert_eq(&msg_response, &shared_key)?;
    Ok(())
}

#[test]
fn test_enum_untagged() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);
    let shared_key = SharedKey::generate();

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
    impl SerdeEncryptPublicKey for Message {
        type S = BincodeSerializer<Self>;
    }
    impl SerdeEncryptSharedKey for Message {
        type S = BincodeSerializer<Self>;
    }

    let msg_request = Message::Request {
        id: "1".into(),
        method: "get_foo".into(),
        params: Params,
    };
    public_key_enc_dec_assert_eq(&msg_request, &sender_combined_key, &receiver_combined_key)?;
    shared_key_enc_dec_assert_eq(&msg_request, &shared_key)?;

    let msg_response = Message::Response {
        id: "1".into(),
        result: Value,
    };
    public_key_enc_dec_assert_eq(&msg_response, &sender_combined_key, &receiver_combined_key)?;
    shared_key_enc_dec_assert_eq(&msg_response, &shared_key)?;
    Ok(())
}

#[test]
fn test_skip_deserializing() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);
    let shared_key = SharedKey::generate();

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Struct {
        a: i32,
        b: i32,
        #[serde(skip_deserializing)]
        c: i32,
    }
    impl SerdeEncryptPublicKey for Struct {
        type S = BincodeSerializer<Self>;
    }
    impl SerdeEncryptSharedKey for Struct {
        type S = BincodeSerializer<Self>;
    }

    let msg = Struct {
        a: 42,
        b: 42,
        c: 42,
    };

    let receive_msg = public_key_enc_dec(&msg, &sender_combined_key, &receiver_combined_key)?;
    assert_eq!(msg.a, receive_msg.a);
    assert_eq!(msg.b, receive_msg.b);
    assert_eq!(
        receive_msg.c, 0,
        "deserialization skipped and got default value"
    );

    let receive_msg = shared_key_enc_dec(&msg, &shared_key)?;
    assert_eq!(msg.a, receive_msg.a);
    assert_eq!(msg.b, receive_msg.b);
    assert_eq!(
        receive_msg.c, 0,
        "deserialization skipped and got default value"
    );

    Ok(())
}

#[test]
fn test_skip_deserializing_and_custom_default() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);
    let shared_key = SharedKey::generate();

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
    impl SerdeEncryptPublicKey for Request {
        type S = BincodeSerializer<Self>;
    }
    impl SerdeEncryptSharedKey for Request {
        type S = BincodeSerializer<Self>;
    }

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

    let receive_msg = public_key_enc_dec(&msg, &sender_combined_key, &receiver_combined_key)?;
    // all fields from sender are skipped deserialization
    assert_eq!(receive_msg.resource, default_resource());
    assert_eq!(receive_msg.timeout, Timeout::default());
    assert_eq!(receive_msg.priority, Priority::lowest());

    let receive_msg = shared_key_enc_dec(&msg, &shared_key)?;
    // all fields from sender are skipped deserialization
    assert_eq!(receive_msg.resource, default_resource());
    assert_eq!(receive_msg.timeout, Timeout::default());
    assert_eq!(receive_msg.priority, Priority::lowest());

    Ok(())
}

#[test]
fn test_flatten() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);
    let shared_key = SharedKey::generate();

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
    impl SerdeEncryptPublicKey for Users {
        type S = BincodeSerializer<Self>;
    }
    impl SerdeEncryptSharedKey for Users {
        type S = BincodeSerializer<Self>;
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
    shared_key_enc_dec_assert_eq(&msg, &shared_key)?;
    Ok(())
}

#[test]
fn test_struct_with_reference_shared_key() -> Result<(), Error> {
    let shared_key = SharedKey::generate();

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Str<'a>(&'a str);
    impl<'a> SerdeEncryptSharedKey for Str<'a> {
        type S = BincodeSerializer<Self>;
    }

    let msg = Str("Str");

    let encrypted_msg = msg.encrypt(&shared_key)?;
    let decrypted = Str::decrypt_ref(&encrypted_msg, &shared_key)?;
    let r_msg = decrypted.deserialize()?;
    pretty_assertions::assert_eq!(msg, r_msg);

    Ok(())
}

#[test]
fn test_struct_with_reference_public_key() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Str<'a>(&'a str);
    impl<'a> SerdeEncryptPublicKey for Str<'a> {
        type S = BincodeSerializer<Self>;
    }

    let msg = Str("Str");

    let encrypted_msg = msg.encrypt(&sender_combined_key)?;
    let decrypted = Str::decrypt_ref(&encrypted_msg, &receiver_combined_key)?;
    let r_msg = decrypted.deserialize()?;
    pretty_assertions::assert_eq!(msg, r_msg);

    Ok(())
}

#[test]
fn test_serialize_enum_as_number() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);
    let shared_key = SharedKey::generate();

    use serde_repr::*;

    #[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug)]
    #[repr(u8)]
    enum SmallPrime {
        Two = 2,
        Three = 3,
        Five = 5,
        Seven = 7,
    }
    impl SerdeEncryptPublicKey for SmallPrime {
        type S = BincodeSerializer<Self>;
    }
    impl SerdeEncryptSharedKey for SmallPrime {
        type S = BincodeSerializer<Self>;
    }

    let msg_two = SmallPrime::Two;
    public_key_enc_dec_assert_eq(&msg_two, &sender_combined_key, &receiver_combined_key)?;
    shared_key_enc_dec_assert_eq(&msg_two, &shared_key)?;

    let msg_seven = SmallPrime::Seven;
    public_key_enc_dec_assert_eq(&msg_seven, &sender_combined_key, &receiver_combined_key)?;
    shared_key_enc_dec_assert_eq(&msg_seven, &shared_key)?;

    Ok(())
}

#[test]
fn test_serialize_field_as_camel_case() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);
    let shared_key = SharedKey::generate();

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Person {
        first_name: String,
        last_name: String,
    }
    impl SerdeEncryptPublicKey for Person {
        type S = BincodeSerializer<Self>;
    }
    impl SerdeEncryptSharedKey for Person {
        type S = BincodeSerializer<Self>;
    }

    let msg = Person {
        first_name: "John".into(),
        last_name: "Doe".into(),
    };
    public_key_enc_dec_assert_eq(&msg, &sender_combined_key, &receiver_combined_key)?;
    shared_key_enc_dec_assert_eq(&msg, &shared_key)?;
    Ok(())
}

#[test]
fn test_skip_serializing_without_default() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);
    let shared_key = SharedKey::generate();

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Resource {
        #[serde(skip_serializing)]
        // #[serde(default)] here prevents DeserializationError
        hash: String,
    }
    impl SerdeEncryptPublicKey for Resource {
        type S = BincodeSerializer<Self>;
    }
    impl SerdeEncryptSharedKey for Resource {
        type S = BincodeSerializer<Self>;
    }

    let msg_with_metadata = Resource {
        hash: "deadc0de".into(),
    };

    let e = public_key_enc_dec(
        &msg_with_metadata,
        &sender_combined_key,
        &receiver_combined_key,
    )
    .unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::DeserializationError);

    let e = shared_key_enc_dec(&msg_with_metadata, &shared_key).unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::DeserializationError);

    Ok(())
}

#[test]
fn test_skip_serializing_if() -> Result<(), Error> {
    use std::collections::BTreeMap as Map;

    combined_keys_gen!(sender_combined_key, receiver_combined_key);
    let shared_key = SharedKey::generate();

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Resource {
        name: String,

        #[serde(skip_serializing_if = "Map::is_empty")]
        metadata: Map<String, String>,
    }
    impl SerdeEncryptPublicKey for Resource {
        type S = BincodeSerializer<Self>;
    }
    impl SerdeEncryptSharedKey for Resource {
        type S = BincodeSerializer<Self>;
    }

    let msg_with_metadata = Resource {
        name: "a.txt".into(),
        metadata: vec![("size".into(), "123".into())].into_iter().collect(),
    };
    public_key_enc_dec_assert_eq(
        &msg_with_metadata,
        &sender_combined_key,
        &receiver_combined_key,
    )?;

    let msg_without_metadata = Resource {
        name: "a.txt".into(),
        metadata: Map::new(),
    };

    let e = public_key_enc_dec(
        &msg_without_metadata,
        &sender_combined_key,
        &receiver_combined_key,
    )
    .unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::DeserializationError);

    let e = shared_key_enc_dec(&msg_without_metadata, &shared_key).unwrap_err();
    assert_eq!(e.kind(), &ErrorKind::DeserializationError);

    Ok(())
}

#[test]
fn test_remote_crate() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);
    let shared_key = SharedKey::generate();

    // Pretend that this is somebody else's crate, not a module.
    mod other_crate {
        // Neither Serde nor the other crate provides Serialize and Deserialize
        // impls for this struct.
        #[derive(PartialEq, Debug)]
        pub struct Duration {
            pub secs: i64,
            pub nanos: i32,
        }
    }

    use other_crate::Duration;

    // Serde calls this the definition of the remote type. It is just a copy of the
    // remote data structure. The `remote` attribute gives the path to the actual
    // type we intend to derive code for.
    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    #[serde(remote = "Duration")]
    struct DurationDef {
        secs: i64,
        nanos: i32,
    }

    // Now the remote type can be used almost like it had its own Serialize and
    // Deserialize impls all along. The `with` attribute gives the path to the
    // definition for the remote type. Note that the real type of the field is the
    // remote type, not the definition type.
    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Process {
        command_line: String,

        #[serde(with = "DurationDef")]
        wall_time: Duration,
    }

    impl SerdeEncryptPublicKey for Process {
        type S = BincodeSerializer<Self>;
    }
    impl SerdeEncryptSharedKey for Process {
        type S = BincodeSerializer<Self>;
    }

    let msg = Process {
        command_line: "sl".into(),
        wall_time: Duration { secs: 33, nanos: 4 },
    };
    public_key_enc_dec_assert_eq(&msg, &sender_combined_key, &receiver_combined_key)?;
    shared_key_enc_dec_assert_eq(&msg, &shared_key)?;
    Ok(())
}

#[test]
fn test_remote_crate_with_priv_fields() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);
    let shared_key = SharedKey::generate();

    // Pretend that this is somebody else's crate, not a module.
    mod other_crate {
        // Neither Serde nor the other crate provides Serialize and Deserialize
        // impls for this struct. Oh, and the fields are private.
        #[derive(PartialEq, Debug)]
        pub struct Duration {
            secs: i64,
            nanos: i32,
        }

        impl Duration {
            pub fn new(secs: i64, nanos: i32) -> Self {
                Duration { secs, nanos }
            }

            pub fn seconds(&self) -> i64 {
                self.secs
            }

            pub fn subsec_nanos(&self) -> i32 {
                self.nanos
            }
        }
    }

    use other_crate::Duration;

    // Provide getters for every private field of the remote struct. The getter must
    // return either `T` or `&T` where `T` is the type of the field.
    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    #[serde(remote = "Duration")]
    struct DurationDef {
        #[serde(getter = "Duration::seconds")]
        secs: i64,
        #[serde(getter = "Duration::subsec_nanos")]
        nanos: i32,
    }

    // Provide a conversion to construct the remote type.
    impl From<DurationDef> for Duration {
        fn from(def: DurationDef) -> Duration {
            Duration::new(def.secs, def.nanos)
        }
    }

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Process {
        command_line: String,

        #[serde(with = "DurationDef")]
        wall_time: Duration,
    }
    impl SerdeEncryptPublicKey for Process {
        type S = BincodeSerializer<Self>;
    }
    impl SerdeEncryptSharedKey for Process {
        type S = BincodeSerializer<Self>;
    }

    let msg = Process {
        command_line: "sl".into(),
        wall_time: Duration::new(33, 4),
    };
    public_key_enc_dec_assert_eq(&msg, &sender_combined_key, &receiver_combined_key)?;
    shared_key_enc_dec_assert_eq(&msg, &shared_key)?;
    Ok(())
}

#[test]
fn test_remote_crate_with_helper() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);
    let shared_key = SharedKey::generate();

    // Pretend that this is somebody else's crate, not a module.
    mod other_crate {
        // Neither Serde nor the other crate provides Serialize and Deserialize
        // impls for this struct. Oh, and the fields are private.
        #[derive(PartialEq, Debug)]
        pub struct Duration {
            secs: i64,
            nanos: i32,
        }

        impl Duration {
            pub fn new(secs: i64, nanos: i32) -> Self {
                Duration { secs, nanos }
            }

            pub fn seconds(&self) -> i64 {
                self.secs
            }

            pub fn subsec_nanos(&self) -> i32 {
                self.nanos
            }
        }
    }

    use other_crate::Duration;

    // Provide getters for every private field of the remote struct. The getter must
    // return either `T` or `&T` where `T` is the type of the field.
    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    #[serde(remote = "Duration")]
    struct DurationDef {
        #[serde(getter = "Duration::seconds")]
        secs: i64,
        #[serde(getter = "Duration::subsec_nanos")]
        nanos: i32,
    }

    // Provide a conversion to construct the remote type.
    impl From<DurationDef> for Duration {
        fn from(def: DurationDef) -> Duration {
            Duration::new(def.secs, def.nanos)
        }
    }

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Helper(#[serde(with = "DurationDef")] Duration);

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Process {
        command_line: String,
        wall_time: Helper,
    }
    impl SerdeEncryptPublicKey for Process {
        type S = BincodeSerializer<Self>;
    }
    impl SerdeEncryptSharedKey for Process {
        type S = BincodeSerializer<Self>;
    }

    let msg = Process {
        command_line: "sl".into(),
        wall_time: Helper(Duration::new(33, 4)),
    };
    public_key_enc_dec_assert_eq(&msg, &sender_combined_key, &receiver_combined_key)?;
    shared_key_enc_dec_assert_eq(&msg, &shared_key)?;
    Ok(())
}

#[test]
fn test_string_or_struct() -> Result<(), Error> {
    use std::collections::BTreeMap as Map;

    combined_keys_gen!(sender_combined_key, receiver_combined_key);
    let shared_key = SharedKey::generate();

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Service {
        // The `string_or_struct` function delegates deserialization to a type's
        // `FromStr` impl if given a string, and to the type's `Deserialize` impl if
        // given a struct. The function is generic over the field type T (here T is
        // `Build`) so it can be reused for any field that implements both `FromStr`
        // and `Deserialize`.
        #[serde(deserialize_with = "string_or_struct")]
        build: Build,
    }
    impl SerdeEncryptPublicKey for Service {
        type S = BincodeSerializer<Self>;
    }
    impl SerdeEncryptSharedKey for Service {
        type S = BincodeSerializer<Self>;
    }

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Build {
        // This is the only required field.
        context: String,

        dockerfile: Option<String>,

        // When `args` is not present in the input, this attribute tells Serde to
        // use `Default::default()` which in this case is an empty map. See the
        // "default value for a field" example for more about `#[serde(default)]`.
        #[serde(default)]
        args: Map<String, String>,
    }

    // The `string_or_struct` function uses this impl to instantiate a `Build` if
    // the input file contains a string and not a struct. According to the
    // docker-compose.yml documentation, a string by itself represents a `Build`
    // with just the `context` field set.
    //
    // > `build` can be specified either as a string containing a path to the build
    // > context, or an object with the path specified under context and optionally
    // > dockerfile and args.
    impl FromStr for Build {
        // This implementation of `from_str` can never fail, so use the impossible
        // `Void` type as the error type.
        type Err = Void;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Ok(Build {
                context: s.to_string(),
                dockerfile: None,
                args: Map::new(),
            })
        }
    }

    fn string_or_struct<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: Deserialize<'de> + FromStr<Err = Void>,
        D: Deserializer<'de>,
    {
        // This is a Visitor that forwards string types to T's `FromStr` impl and
        // forwards map types to T's `Deserialize` impl. The `PhantomData` is to
        // keep the compiler from complaining about T being an unused generic type
        // parameter. We need T in order to know the Value type for the Visitor
        // impl.
        struct StringOrStruct<T>(PhantomData<fn() -> T>);

        impl<'de, T> Visitor<'de> for StringOrStruct<T>
        where
            T: Deserialize<'de> + FromStr<Err = Void>,
        {
            type Value = T;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("string or map")
            }

            fn visit_str<E>(self, value: &str) -> Result<T, E>
            where
                E: de::Error,
            {
                Ok(FromStr::from_str(value).unwrap())
            }

            fn visit_map<M>(self, map: M) -> Result<T, M::Error>
            where
                M: MapAccess<'de>,
            {
                // `MapAccessDeserializer` is a wrapper that turns a `MapAccess`
                // into a `Deserializer`, allowing it to be used as the input to T's
                // `Deserialize` implementation. T then deserializes itself using
                // the entries from the map visitor.
                Deserialize::deserialize(de::value::MapAccessDeserializer::new(map))
            }
        }

        deserializer.deserialize_any(StringOrStruct(PhantomData))
    }

    let msg = Service {
        build: Build {
            context: "./dir".into(),
            dockerfile: Some("Dockerfile".into()),
            args: vec![("buildno".into(), "1".into())].into_iter().collect(),
        },
    };
    public_key_enc_dec_assert_eq(&msg, &sender_combined_key, &receiver_combined_key)?;
    shared_key_enc_dec_assert_eq(&msg, &shared_key)?;
    Ok(())
}

#[test]
fn test_convert_error_types() -> Result<(), Error> {
    combined_keys_gen!(sender_combined_key, receiver_combined_key);
    let shared_key = SharedKey::generate();

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Resource {
        name: String,

        #[serde(with = "as_json_string")]
        policy: Policy,
    }

    impl SerdeEncryptPublicKey for Resource {
        type S = BincodeSerializer<Self>;
    }
    impl SerdeEncryptSharedKey for Resource {
        type S = BincodeSerializer<Self>;
    }

    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Policy {
        effect: String,
        action: String,
        resource: String,
    }

    // Serialize and deserialize logic for dealing with nested values represented as
    // JSON strings.
    mod as_json_string {
        use serde::de::{Deserialize, DeserializeOwned, Deserializer};
        use serde::ser::{Serialize, Serializer};

        // Serialize to a JSON string, then serialize the string to the output
        // format.
        pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
        where
            T: Serialize,
            S: Serializer,
        {
            use serde::ser::Error;
            let j = serde_json::to_string(value).map_err(Error::custom)?;
            j.serialize(serializer)
        }

        // Deserialize a string from the input format, then deserialize the content
        // of that string as JSON.
        pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
        where
            T: DeserializeOwned,
            D: Deserializer<'de>,
        {
            use serde::de::Error;
            let j = String::deserialize(deserializer)?;
            serde_json::from_str(&j).map_err(Error::custom)
        }
    }

    let msg = Resource {
        name: "a.txt".into(),
        policy: Policy {
            effect: "Allow".to_owned(),
            action: "s3:ListBucket".to_owned(),
            resource: "arn:aws:s3:::example_bucket".to_owned(),
        },
    };
    public_key_enc_dec_assert_eq(&msg, &sender_combined_key, &receiver_combined_key)?;
    shared_key_enc_dec_assert_eq(&msg, &shared_key)?;
    Ok(())
}
