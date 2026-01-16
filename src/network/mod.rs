//! Network module
//!
//! Network communication layer for KDE Connect protocol.
//!
//! This module contains:
//! - `Discovery`: UDP device discovery on port 1816
//! - `Transport`: Transport abstraction (TCP, Bluetooth)
//! - `TcpTransport`: TCP connection management (TODO: Extract from applet)
//! - `TlsTransport`: Secure TLS connections (TODO: Rewrite with rustls)

// Module exports
pub mod discovery;  // ✅ Extracted (Issue #46)
pub mod transport;  // ✅ Transport abstraction layer
// pub mod tcp;     // TODO: Extract from applet
// pub mod tls;     // TODO: Rewrite with rustls (Issue #47)

// Re-exports for convenience
pub use discovery::{
    DeviceInfo, DeviceType, Discovery, DiscoveryConfig, DiscoveryEvent, DiscoveryService,
    BROADCAST_ADDR, DEFAULT_BROADCAST_INTERVAL, DEFAULT_DEVICE_TIMEOUT, DISCOVERY_PORT,
    PORT_RANGE_END, PORT_RANGE_START,
};

pub use transport::{
    LatencyCategory, Transport, TransportAddress, TransportCapabilities, TransportFactory,
    TransportPreference, TransportType, KDECONNECT_SERVICE_UUID, MAX_BT_PACKET_SIZE,
    MAX_TCP_PACKET_SIZE, RFCOMM_READ_CHAR_UUID, RFCOMM_WRITE_CHAR_UUID,
};

// pub use tcp::TcpTransport;
// pub use tls::TlsTransport;
