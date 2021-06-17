//! Serializers available in `feature = "std"`.

use serde::{Deserialize, Serialize};
use serde_encrypt::{
    serialize::impls::CborSerializer, shared_key::SharedKey, traits::SerdeEncryptSharedKey,
    AsSharedKey, Error,
};

const RAW_MSG: [u8; 1000] = [42; 1000];

#[test]
fn test_cbor_serializer() -> Result<(), Error> {
    #[derive(PartialEq, Debug, Serialize, Deserialize)]
    struct Message(Vec<u8>);

    impl SerdeEncryptSharedKey for Message {
        type S = CborSerializer<Self>;
    }

    let shared_key = SharedKey::generate();

    let msg = Message(RAW_MSG.to_vec());

    let enc_msg = msg.encrypt(&shared_key)?;
    let dec_msg = Message::decrypt_owned(&enc_msg, &shared_key)?;

    eprintln!(
        "[CborSerializer] {} bytes in plain-text ; {} bytes in cipher-text.",
        msg.0.len(),
        enc_msg.len()
    );

    assert_eq!(dec_msg, msg);

    Ok(())
}

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        use serde_encrypt::serialize::impls::BincodeSerializer;

        #[test]
        fn test_bincode_serializer() -> Result<(), Error> {
            #[derive(PartialEq, Debug, Serialize, Deserialize)]
            struct Message(Vec<u8>);

            impl SerdeEncryptSharedKey for Message {
                type S = BincodeSerializer<Self>;
            }

            let shared_key = SharedKey::generate();

            let msg = Message(RAW_MSG.to_vec());

            let enc_msg = msg.encrypt(&shared_key)?;
            let dec_msg = Message::decrypt_owned(&enc_msg, &shared_key)?;

            eprintln!(
                "[BincodeSerializer] {} bytes in plain-text ; {} bytes in cipher-text.",
                msg.0.len(),
                enc_msg.len()
            );

            assert_eq!(dec_msg, msg);

            Ok(())
        }
    }
}
