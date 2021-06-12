//! Error type.

mod error_kind;

pub use self::error_kind::ErrorKind;

use alloc::string::{String, ToString};
use core::fmt::Display;

/// Error type.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Error {
    /// Machine-readable error type.
    kind: ErrorKind,

    /// Human-readable error reason.
    reason: String,
}

impl Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.kind, self.reason)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl Error {
    /// Ref to error kind.
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    fn new(kind: ErrorKind, reason: &str) -> Self {
        Self {
            kind,
            reason: reason.to_string(),
        }
    }

    pub(crate) fn serialization_error(reason: &str) -> Self {
        Self::new(ErrorKind::SerializationError, reason)
    }

    pub(crate) fn deserialization_error(reason: &str) -> Self {
        Self::new(ErrorKind::DeserializationError, reason)
    }

    pub(crate) fn encryption_error(reason: &str) -> Self {
        Self::new(ErrorKind::EncryptionError, reason)
    }

    pub(crate) fn decryption_error(reason: &str) -> Self {
        Self::new(ErrorKind::DecryptionError, reason)
    }
}
