//! Error type.

mod error_kind;

use core::fmt::Display;

use alloc::string::{String, ToString};

use self::error_kind::ErrorKind;

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

impl Error {
    fn new(kind: ErrorKind, reason: &str) -> Self {
        Self {
            kind,
            reason: reason.to_string(),
        }
    }

    pub(crate) fn deserialization_error(reason: &str) -> Self {
        Self::new(ErrorKind::DeserializationError, reason)
    }

    pub(crate) fn decryption_error(reason: &str) -> Self {
        Self::new(ErrorKind::DecryptionError, reason)
    }
}
