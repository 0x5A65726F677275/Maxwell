//! Error types shared across Maxwell crates.

use thiserror::Error;

/// Convenient alias used by all Maxwell crates.
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level error enum for Maxwell modules.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("internal error: {0}")]
    Internal(String),
}
