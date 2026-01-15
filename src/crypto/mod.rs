//! Cryptography module
//!
//! Cryptographic operations for KDE Connect protocol.
//!
//! This module contains:
//! - `certificate`: Certificate generation and management
//! - `tls`: Secure TLS connections (rustls-based)
//! - `pairing`: Device pairing and verification

// Module exports
pub mod certificate;   // ✅ Extracted (Issue #47)
pub mod tls;           // ✅ Extracted (Issue #47)
// pub mod pairing;    // TODO: Extract from applet

// Re-exports for convenience
pub use certificate::CertificateInfo;
pub use tls::{DeviceInfo, TlsConfig, TlsConnection, TlsServer, should_initiate_connection};
