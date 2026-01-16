//! KDE Connect Transport Layer
//!
//! This module provides transport abstraction for KDE Connect protocol.
//! The transport layer supports multiple transport types (TCP, Bluetooth)
//! through a common trait interface.
//!
//! ## Architecture
//!
//! The transport layer is designed to be:
//! - **Pluggable**: Easy to add new transports (USB, NFC, etc.)
//! - **Cross-platform**: Works on Linux, Android, and other platforms
//! - **FFI-friendly**: Can be exposed via UniFFI for Kotlin/Swift
//!
//! ## Transport Types
//!
//! Currently supported:
//! - **TCP**: Traditional TCP/IP connections (WiFi, Ethernet)
//! - **Bluetooth**: BLE-based connections for when WiFi unavailable
//!
//! ## Usage
//!
//! ```rust,no_run
//! use cosmic_connect_core::network::transport::{Transport, TransportAddress};
//!
//! async fn send_packet(transport: &mut Box<dyn Transport>) {
//!     // Get capabilities
//!     let caps = transport.capabilities();
//!     println!("MTU: {} bytes", caps.max_packet_size);
//!
//!     // Send packet
//!     // let packet = Packet::new("cconnect.ping", json!({}));
//!     // transport.send_packet(&packet).await?;
//! }
//! ```

mod r#trait;

pub use r#trait::{
    LatencyCategory, Transport, TransportAddress, TransportCapabilities, TransportFactory,
    TransportPreference, TransportType,
};

/// KDE Connect Bluetooth service UUID
///
/// This UUID identifies the KDE Connect service when advertising or discovering
/// devices over Bluetooth. All KDE Connect implementations must use this UUID
/// for compatibility.
pub const KDECONNECT_SERVICE_UUID: &str = "185f3df4-3268-4e3f-9fca-d4d5059915bd";

/// Bluetooth RFCOMM characteristic UUID for reading packets
pub const RFCOMM_READ_CHAR_UUID: &str = "8667556c-9a37-4c91-84ed-54ee27d90049";

/// Bluetooth RFCOMM characteristic UUID for writing packets
pub const RFCOMM_WRITE_CHAR_UUID: &str = "d0e8434d-cd29-0996-af41-6c90f4e0eb2a";

/// Maximum packet size for Bluetooth transport (512 bytes)
///
/// Bluetooth RFCOMM typically has a smaller MTU than TCP.
/// This conservative value ensures compatibility across devices.
pub const MAX_BT_PACKET_SIZE: usize = 512;

/// Maximum packet size for TCP transport (1 MB)
pub const MAX_TCP_PACKET_SIZE: usize = 1024 * 1024;
