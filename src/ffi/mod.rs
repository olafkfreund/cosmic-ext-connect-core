//! Foreign Function Interface (FFI) module
//!
//! UniFFI bindings for Kotlin (Android) and Swift (iOS).
//!
//! This module provides the FFI layer between Rust core and platform-specific code.
//! All types and functions defined here correspond to the `cosmic_connect_core.udl`
//! interface definition.
//!
//! ## Architecture
//!
//! ```
//! Platform (Kotlin/Swift)
//!         ↓
//!     FFI Layer (this module)
//!         ↓
//!    Rust Core (protocol, crypto, plugins, etc.)
//! ```
//!
//! ## Type Conversions
//!
//! - `FfiPacket` ↔ `protocol::Packet`
//! - `FfiCertificate` ↔ `crypto::CertificateInfo`
//! - `FfiBatteryState` ↔ `plugins::battery::BatteryState`
//!
//! ## Error Handling
//!
//! All Rust `Result<T, ProtocolError>` types are automatically converted to
//! exceptions in Kotlin/Swift by UniFFI.

use crate::crypto::CertificateInfo;
use crate::error::{ProtocolError, Result};
use crate::network::discovery;
use crate::plugins::{battery::BatteryState, battery::BatteryPlugin, ping::PingPlugin, Plugin, PluginManager as CorePluginManager};
use crate::protocol::Packet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

// ==========================================================================
// FFI Data Types
// ==========================================================================

/// FFI-compatible network packet
#[derive(Debug, Clone)]
pub struct FfiPacket {
    pub id: i64,
    pub packet_type: String,
    pub body: String,
    pub payload_size: Option<i64>,
}

impl From<Packet> for FfiPacket {
    fn from(packet: Packet) -> Self {
        Self {
            id: packet.id,
            packet_type: packet.packet_type,
            body: packet.body.to_string(),
            payload_size: packet.payload_size,
        }
    }
}

impl TryFrom<FfiPacket> for Packet {
    type Error = ProtocolError;

    fn try_from(ffi: FfiPacket) -> Result<Self> {
        let body: serde_json::Value = serde_json::from_str(&ffi.body)?;
        let mut packet = Packet::with_id(ffi.id, ffi.packet_type, body);
        if let Some(size) = ffi.payload_size {
            packet.payload_size = Some(size);
        }
        Ok(packet)
    }
}

/// FFI-compatible device information
#[derive(Debug, Clone)]
pub struct FfiDeviceInfo {
    pub device_id: String,
    pub device_name: String,
    pub device_type: String,
    pub protocol_version: i32,
    pub incoming_capabilities: Vec<String>,
    pub outgoing_capabilities: Vec<String>,
    pub tcp_port: u16,
}

/// FFI-compatible certificate
#[derive(Debug, Clone)]
pub struct FfiCertificate {
    pub device_id: String,
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
    pub fingerprint: String,
}

impl From<CertificateInfo> for FfiCertificate {
    fn from(cert: CertificateInfo) -> Self {
        Self {
            device_id: cert.device_id,
            certificate: cert.certificate,
            private_key: cert.private_key,
            fingerprint: cert.fingerprint,
        }
    }
}

impl From<FfiCertificate> for CertificateInfo {
    fn from(ffi: FfiCertificate) -> Self {
        Self {
            device_id: ffi.device_id,
            certificate: ffi.certificate,
            private_key: ffi.private_key,
            fingerprint: ffi.fingerprint,
        }
    }
}

/// FFI-compatible battery state
#[derive(Debug, Clone)]
pub struct FfiBatteryState {
    pub is_charging: bool,
    pub current_charge: i32,
    pub threshold_event: i32,
}

impl From<BatteryState> for FfiBatteryState {
    fn from(state: BatteryState) -> Self {
        Self {
            is_charging: state.is_charging,
            current_charge: state.current_charge,
            threshold_event: state.threshold_event,
        }
    }
}

impl From<FfiBatteryState> for BatteryState {
    fn from(ffi: FfiBatteryState) -> Self {
        Self {
            is_charging: ffi.is_charging,
            current_charge: ffi.current_charge,
            threshold_event: ffi.threshold_event,
        }
    }
}

/// Plugin capabilities
#[derive(Debug, Clone)]
pub struct FfiCapabilities {
    pub incoming: Vec<String>,
    pub outgoing: Vec<String>,
}

/// Ping statistics
#[derive(Debug, Clone)]
pub struct FfiPingStats {
    pub pings_received: u64,
    pub pings_sent: u64,
}

/// Discovery events
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    DeviceFound { device: FfiDeviceInfo },
    DeviceLost { device_id: String },
    IdentityReceived { device_id: String, packet: FfiPacket },
}

// ==========================================================================
// Callbacks
// ==========================================================================
//
// NOTE: Callback interfaces are defined in the UDL file (cosmic_connect_core.udl)
// and implemented here as Rust traits. The uniffi scaffolding will generate the
// necessary glue code to connect Kotlin/Swift implementations to these traits.

/// Discovery callback trait
pub trait DiscoveryCallback: Send + Sync {
    fn on_device_found(&self, device: FfiDeviceInfo);
    fn on_device_lost(&self, device_id: String);
    fn on_identity_received(&self, device_id: String, packet: FfiPacket);
}

/// Plugin callback trait
pub trait PluginCallback: Send + Sync {
    fn on_battery_update(&self, device_id: String, state: FfiBatteryState);
    fn on_ping_received(&self, device_id: String, message: Option<String>);
    fn on_packet_received(&self, device_id: String, packet: FfiPacket);
}

// ==========================================================================
// Namespace Functions
// ==========================================================================

/// Initialize the library with logging
pub fn initialize(log_level: String) -> Result<()> {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_new(&log_level)
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()
        .map_err(|e| ProtocolError::Other(format!("Failed to initialize logging: {}", e)))?;

    info!("cosmic-connect-core initialized with log level: {}", log_level);
    Ok(())
}

/// Get library version
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Get protocol version
pub fn get_protocol_version() -> i32 {
    crate::PROTOCOL_VERSION
}

/// Create a new network packet
pub fn create_packet(packet_type: String, body: String) -> Result<FfiPacket> {
    let body_value: serde_json::Value = serde_json::from_str(&body)?;
    let packet = Packet::new(packet_type, body_value);
    Ok(packet.into())
}

/// Create a packet with explicit ID
pub fn create_packet_with_id(id: i64, packet_type: String, body: String) -> Result<FfiPacket> {
    let body_value: serde_json::Value = serde_json::from_str(&body)?;
    let packet = Packet::with_id(id, packet_type, body_value);
    Ok(packet.into())
}

/// Serialize packet to bytes
pub fn serialize_packet(packet: FfiPacket) -> Result<Vec<u8>> {
    let core_packet: Packet = packet.try_into()?;
    core_packet.to_bytes()
}

/// Deserialize packet from bytes
pub fn deserialize_packet(data: Vec<u8>) -> Result<FfiPacket> {
    let packet = Packet::from_bytes(&data)?;
    Ok(packet.into())
}

/// Generate a new self-signed certificate
pub fn generate_certificate(device_id: String) -> Result<FfiCertificate> {
    let cert = CertificateInfo::generate(device_id)?;
    Ok(cert.into())
}

/// Load certificate from PEM files
pub fn load_certificate(cert_path: String, key_path: String) -> Result<FfiCertificate> {
    let cert = CertificateInfo::load_from_files(cert_path, key_path)?;
    Ok(cert.into())
}

/// Save certificate to PEM files
pub fn save_certificate(cert: FfiCertificate, cert_path: String, key_path: String) -> Result<()> {
    let cert_info: CertificateInfo = cert.into();
    cert_info.save_to_files(cert_path, key_path)
}

/// Get certificate fingerprint
pub fn get_certificate_fingerprint(cert: FfiCertificate) -> String {
    cert.fingerprint
}

/// Start device discovery
pub fn start_discovery(
    local_device: FfiDeviceInfo,
    callback: Box<dyn DiscoveryCallback>,
) -> Result<Arc<DiscoveryService>> {
    use crate::network::DeviceType;

    // Convert device_type string to enum
    let device_type = match local_device.device_type.to_lowercase().as_str() {
        "desktop" => DeviceType::Desktop,
        "laptop" => DeviceType::Laptop,
        "phone" => DeviceType::Phone,
        "tablet" => DeviceType::Tablet,
        "tv" => DeviceType::Tv,
        _ => return Err(ProtocolError::InvalidPacket(
            format!("Invalid device type: {}", local_device.device_type)
        )),
    };

    // Convert FfiDeviceInfo to discovery::DeviceInfo
    let device_info = discovery::DeviceInfo {
        device_id: local_device.device_id,
        device_name: local_device.device_name,
        device_type,
        protocol_version: local_device.protocol_version as u32,
        incoming_capabilities: local_device.incoming_capabilities,
        outgoing_capabilities: local_device.outgoing_capabilities,
        tcp_port: local_device.tcp_port,
    };

    Ok(Arc::new(DiscoveryService::new(device_info, callback)))
}

/// Create a new plugin manager
pub fn create_plugin_manager() -> Arc<PluginManager> {
    Arc::new(PluginManager::new())
}

// ==========================================================================
// Interfaces (Objects)
// ==========================================================================

/// Discovery service
pub struct DiscoveryService {
    device_info: discovery::DeviceInfo,
    callback: Box<dyn DiscoveryCallback>,
    running: Arc<RwLock<bool>>,
}

impl DiscoveryService {
    fn new(device_info: discovery::DeviceInfo, callback: Box<dyn DiscoveryCallback>) -> Self {
        Self {
            device_info,
            callback,
            running: Arc::new(RwLock::new(false)),
        }
    }
}

impl DiscoveryService {
    /// Stop discovery
    pub fn stop(&self) -> Result<()> {
        info!("Stopping discovery service");
        // Implementation would stop the discovery process
        Ok(())
    }

    /// Get discovered devices
    pub fn get_devices(&self) -> Vec<FfiDeviceInfo> {
        // Placeholder - actual implementation would return discovered devices
        Vec::new()
    }

    /// Check if discovery is running
    pub fn is_running(&self) -> bool {
        // Placeholder
        false
    }
}

/// Plugin manager
pub struct PluginManager {
    core: Arc<RwLock<CorePluginManager>>,
    runtime: tokio::runtime::Runtime,
}

impl PluginManager {
    fn new() -> Self {
        let runtime = tokio::runtime::Runtime::new()
            .expect("Failed to create Tokio runtime");

        Self {
            core: Arc::new(RwLock::new(CorePluginManager::new())),
            runtime,
        }
    }
}

impl PluginManager {
    /// Register a plugin by name
    pub fn register_plugin(&self, plugin_name: String) -> Result<()> {
        let core = Arc::clone(&self.core);

        self.runtime.block_on(async move {
            let mut manager = core.write().await;

            match plugin_name.as_str() {
                "ping" => {
                    manager.register_plugin(Box::new(PingPlugin::new())).await?;
                    info!("Registered ping plugin");
                }
                "battery" => {
                    manager.register_plugin(Box::new(BatteryPlugin::new())).await?;
                    info!("Registered battery plugin");
                }
                _ => {
                    return Err(ProtocolError::Plugin(format!(
                        "Unknown plugin: {}",
                        plugin_name
                    )));
                }
            }

            Ok(())
        })
    }

    /// Unregister a plugin
    pub fn unregister_plugin(&self, plugin_name: String) -> Result<()> {
        let core = Arc::clone(&self.core);

        self.runtime.block_on(async move {
            let mut manager = core.write().await;
            manager.unregister_plugin(&plugin_name).await
        })
    }

    /// Route a packet to the appropriate plugin
    pub fn route_packet(&self, packet: FfiPacket) -> Result<()> {
        let core = Arc::clone(&self.core);

        self.runtime.block_on(async move {
            let core_packet: Packet = packet.try_into()?;
            let manager = core.read().await;
            manager.route_packet(&core_packet).await
        })
    }

    /// Get all capabilities
    pub fn get_capabilities(&self) -> FfiCapabilities {
        let core = Arc::clone(&self.core);

        self.runtime.block_on(async move {
            let manager = core.read().await;
            let (incoming, outgoing) = manager.get_capabilities().await;
            FfiCapabilities { incoming, outgoing }
        })
    }

    /// Check if a plugin is registered
    pub fn has_plugin(&self, plugin_name: String) -> bool {
        let core = Arc::clone(&self.core);

        self.runtime.block_on(async move {
            let manager = core.read().await;
            manager.has_plugin(&plugin_name)
        })
    }

    /// Get list of registered plugin names
    pub fn plugin_names(&self) -> Vec<String> {
        let core = Arc::clone(&self.core);

        self.runtime.block_on(async move {
            let manager = core.read().await;
            manager.plugin_names()
        })
    }

    /// Shutdown all plugins
    pub fn shutdown_all(&self) -> Result<()> {
        let core = Arc::clone(&self.core);

        self.runtime.block_on(async move {
            let mut manager = core.write().await;
            manager.shutdown_all().await
        })
    }

    // Plugin-specific operations

    /// Update local battery state
    pub fn update_battery(&self, state: FfiBatteryState) -> Result<()> {
        let core = Arc::clone(&self.core);
        let battery_state: BatteryState = state.into();

        self.runtime.block_on(async move {
            let manager = core.read().await;
            let plugin = manager.get_plugin("battery")
                .ok_or_else(|| ProtocolError::Plugin("Battery plugin not registered".to_string()))?;

            let mut plugin_guard = plugin.write().await;

            // Downcast to BatteryPlugin
            // Note: This is a workaround since we can't easily downcast trait objects
            // In practice, we'd use a different approach or expose this through the plugin trait
            error!("update_battery: Direct plugin access not yet implemented");
            Err(ProtocolError::Plugin("Direct plugin access not yet implemented".to_string()))
        })
    }

    /// Get remote battery state
    pub fn get_remote_battery(&self) -> Option<FfiBatteryState> {
        // Placeholder - would access battery plugin state
        None
    }

    /// Create a ping packet
    pub fn create_ping(&self, message: Option<String>) -> Result<FfiPacket> {
        let core = Arc::clone(&self.core);

        self.runtime.block_on(async move {
            let manager = core.read().await;
            let plugin = manager.get_plugin("ping")
                .ok_or_else(|| ProtocolError::Plugin("Ping plugin not registered".to_string()))?;

            let mut plugin_guard = plugin.write().await;

            // Same limitation as above - would need plugin trait extension
            error!("create_ping: Direct plugin access not yet implemented");
            Err(ProtocolError::Plugin("Direct plugin access not yet implemented".to_string()))
        })
    }

    /// Get ping statistics
    pub fn get_ping_stats(&self) -> FfiPingStats {
        // Placeholder - would access ping plugin stats
        FfiPingStats {
            pings_received: 0,
            pings_sent: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_ffi_packet_conversion() {
        let packet = Packet::new("kdeconnect.ping", json!({"message": "hello"}));
        let ffi_packet: FfiPacket = packet.clone().into();

        assert_eq!(ffi_packet.packet_type, "kdeconnect.ping");
        assert!(ffi_packet.body.contains("hello"));

        let core_packet: Packet = ffi_packet.try_into().unwrap();
        assert_eq!(core_packet.packet_type, packet.packet_type);
    }

    #[test]
    fn test_get_version() {
        let version = get_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn test_get_protocol_version() {
        let version = get_protocol_version();
        assert_eq!(version, 7);
    }

    #[test]
    fn test_create_packet() {
        let packet = create_packet(
            "kdeconnect.ping".to_string(),
            "{}".to_string(),
        ).unwrap();

        assert_eq!(packet.packet_type, "kdeconnect.ping");
    }

    #[test]
    fn test_serialize_deserialize() {
        let packet = create_packet(
            "kdeconnect.ping".to_string(),
            r#"{"message":"test"}"#.to_string(),
        ).unwrap();

        let bytes = serialize_packet(packet.clone()).unwrap();
        let deserialized = deserialize_packet(bytes).unwrap();

        assert_eq!(packet.packet_type, deserialized.packet_type);
    }

    #[test]
    fn test_generate_certificate() {
        let cert = generate_certificate("test_device".to_string()).unwrap();

        assert_eq!(cert.device_id, "test_device");
        assert!(!cert.certificate.is_empty());
        assert!(!cert.private_key.is_empty());
        assert!(!cert.fingerprint.is_empty());
    }

    #[test]
    fn test_plugin_manager_creation() {
        let manager = create_plugin_manager();
        assert_eq!(manager.plugin_names().len(), 0);
    }

    #[test]
    fn test_plugin_registration() {
        let manager = create_plugin_manager();

        manager.register_plugin("ping".to_string()).unwrap();
        assert!(manager.has_plugin("ping".to_string()));

        manager.register_plugin("battery".to_string()).unwrap();
        assert!(manager.has_plugin("battery".to_string()));

        let names = manager.plugin_names();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn test_plugin_capabilities() {
        let manager = create_plugin_manager();

        manager.register_plugin("ping".to_string()).unwrap();
        manager.register_plugin("battery".to_string()).unwrap();

        let caps = manager.get_capabilities();

        assert!(caps.incoming.contains(&"kdeconnect.ping".to_string()));
        assert!(caps.incoming.contains(&"kdeconnect.battery".to_string()));
    }
}
