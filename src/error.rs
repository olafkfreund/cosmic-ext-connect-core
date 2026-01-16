//! Error types for cosmic-connect-core

use std::io;
use thiserror::Error;

/// Result type alias using ProtocolError
pub type Result<T> = std::result::Result<T, ProtocolError>;

/// Protocol error types
///
/// All errors that can occur in the COSMIC Connect protocol implementation.
/// These are designed to be FFI-compatible when using uniffi.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// I/O error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid packet format or content
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// TLS/SSL error
    #[error("TLS error: {0}")]
    Tls(String),

    /// Certificate error
    #[error("Certificate error: {0}")]
    Certificate(String),

    /// Discovery error
    #[error("Discovery error: {0}")]
    Discovery(String),

    /// Device not found
    #[error("Device not found: {0}")]
    DeviceNotFound(String),

    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// Pairing error
    #[error("Pairing error: {0}")]
    Pairing(String),

    /// Plugin error
    #[error("Plugin error: {0}")]
    Plugin(String),

    /// Timeout error
    #[error("Operation timed out")]
    Timeout,

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Already exists
    #[error("Already exists: {0}")]
    AlreadyExists(String),

    /// Not paired
    #[error("Device not paired: {0}")]
    NotPaired(String),

    /// Generic error
    #[error("{0}")]
    Other(String),
}

impl ProtocolError {
    /// Create a Network error
    pub fn network(msg: impl Into<String>) -> Self {
        Self::Network(msg.into())
    }

    /// Create a TLS error
    pub fn tls(msg: impl Into<String>) -> Self {
        Self::Tls(msg.into())
    }

    /// Create a Certificate error
    pub fn certificate(msg: impl Into<String>) -> Self {
        Self::Certificate(msg.into())
    }

    /// Create a Discovery error
    pub fn discovery(msg: impl Into<String>) -> Self {
        Self::Discovery(msg.into())
    }

    /// Create a Connection error
    pub fn connection(msg: impl Into<String>) -> Self {
        Self::Connection(msg.into())
    }

    /// Create a Plugin error
    pub fn plugin(msg: impl Into<String>) -> Self {
        Self::Plugin(msg.into())
    }

    /// Create an Other error
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
}

// Implement From for common error types
impl From<rustls::Error> for ProtocolError {
    fn from(err: rustls::Error) -> Self {
        Self::Tls(err.to_string())
    }
}

impl From<rcgen::Error> for ProtocolError {
    fn from(err: rcgen::Error) -> Self {
        Self::Certificate(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = ProtocolError::network("test");
        assert!(matches!(err, ProtocolError::Network(_)));
    }

    #[test]
    fn test_error_display() {
        let err = ProtocolError::InvalidPacket("bad format".to_string());
        assert_eq!(err.to_string(), "Invalid packet: bad format");
    }
}
