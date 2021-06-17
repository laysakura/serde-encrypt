//! Serializer implementations.

mod cbor_serializer;
pub use cbor_serializer::CborSerializer;

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        mod bincode_serializer;
        pub use bincode_serializer::BincodeSerializer;
    }
}
