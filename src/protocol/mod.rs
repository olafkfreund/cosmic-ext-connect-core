//! Protocol module
//!
//! Core KDE Connect protocol types and implementations.
//!
//! This module contains:
//! - `Packet`: NetworkPacket serialization/deserialization
//! - `Device`: Device information and identity (TODO: Issue #46)
//! - `Identity`: Device identity packets (TODO)
//! - `Payload`: Payload transfer handling (TODO)

// Module exports
pub mod packet;       // ✅ Extracted from applet (Issue #45)
// pub mod device;    // TODO: Extract from applet
// pub mod identity;  // TODO: Create
// pub mod payload;   // TODO: Extract from applet

// Re-exports for convenience
pub use packet::Packet;
// pub use device::{Device, DeviceInfo, DeviceType};
// pub use identity::Identity;

/// KDE Connect protocol version implemented by this library
/// Updated to version 8 to match latest KDE Connect Android app
pub const PROTOCOL_VERSION: i32 = 8;
