//! Kinds of errors.

use core::fmt::Display;

/// Kinds of errors.
#[allow(missing_docs)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ErrorKind {
    DeserializationError,
    DecryptionError,
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            ErrorKind::DeserializationError => {
                "DeserializationError: Failed to deserialize data received."
            }
            ErrorKind::DecryptionError => "DecryptionError: Failed to decrypt data received",
        };
        write!(f, "{}", s)
    }
}
