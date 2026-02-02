//! Cryptography module
//!
//! Cryptographic operations for KDE Connect protocol.
//!
//! This module contains:
//! - `certificate`: Certificate generation and management
//! - `tls`: Secure TLS connections (rustls-based)
//!
//! ## Pairing Implementation Status
//!
//! Device pairing has been fully implemented in `cosmic-connect-protocol::pairing`.
//! The pairing module was extracted from the applet and now provides:
//! - `PairingService`: Manages pairing lifecycle and state
//! - `PairingHandler`: Handles pairing request/response packets
//! - `PairingEvent`: Event notifications for UI integration
//!
//! The pairing implementation uses the crypto primitives from this module
//! (certificate generation and TLS) but lives in the protocol crate to avoid
//! circular dependencies between core crypto and protocol packet handling.
//!
//! For pairing functionality, use: `cosmic_connect_protocol::pairing`

// Module exports
pub mod certificate;   // ✅ Extracted (Issue #47)
pub mod tls;           // ✅ Extracted (Issue #47)
// Pairing now lives in cosmic-connect-protocol::pairing (Issue #47 complete)

// Re-exports for convenience
pub use certificate::CertificateInfo;
pub use tls::{DeviceInfo, TlsConfig, TlsConnection, TlsServer, should_initiate_connection};
