//! cosmic-connect-core
//!
//! KDE Connect protocol implementation in Rust.
//! Shared library for COSMIC Connect Android and COSMIC Desktop.
//!
//! ## Architecture
//!
//! This library provides a complete implementation of the KDE Connect protocol v7,
//! designed for cross-platform use via FFI (Foreign Function Interface).
//!
//! ### Modules
//!
//! - `protocol`: Core protocol types (NetworkPacket, Device, Identity)
//! - `network`: Network layer (Discovery, TCP transport)
//! - `crypto`: Cryptography (TLS, Certificate management)
//! - `plugins`: Plugin system and implementations
//! - `ffi`: Foreign Function Interface for Kotlin/Swift
//!
//! ## Example
//!
//! ```rust
//! use cosmic_connect_core::Packet;
//! use serde_json::json;
//!
//! // Create a packet
//! let packet = Packet::new("kdeconnect.ping", json!({}));
//!
//! // Serialize with newline terminator (KDE Connect protocol requirement)
//! let bytes = packet.to_bytes().unwrap();
//! assert_eq!(bytes.last(), Some(&b'\n'));
//! ```

// Re-export commonly used types
pub use error::{ProtocolError, Result};
pub use protocol::Packet;

// Public modules
pub mod protocol;
pub mod network;
pub mod crypto;
pub mod plugins;
pub mod error;

// FFI module (for Android/iOS bindings)
#[cfg(feature = "ffi")]
pub mod ffi;

// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROTOCOL_VERSION: i32 = 7;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_protocol_version() {
        assert_eq!(PROTOCOL_VERSION, 7);
    }
}
