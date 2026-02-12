//! Plugin system module
//!
//! KDE Connect plugin trait and implementations.
//!
//! ## Architecture
//!
//! The plugin system in `cosmic-ext-connect-core` provides a clean separation between:
//! - **Protocol logic** (in Rust core) - Packet parsing, state management
//! - **Platform integration** (Android/Desktop) - UI, system APIs, permissions
//!
//! ## Components
//!
//! - [`Plugin`](trait@Plugin) - Trait that all plugins must implement
//! - [`PluginManager`](struct@PluginManager) - Manages plugin lifecycle and routing
//! - [`PluginMetadata`](struct@PluginMetadata) - Plugin information for display
//!
//! ## Built-in Plugins
//!
//! ### Core Plugins
//! - [`ping`](ping) - Simple connectivity testing
//! - [`battery`](battery) - Battery status monitoring
//!
//! ### Communication Plugins
//! - [`notification`](notification) - Notification forwarding
//! - [`telephony`](telephony) - Call/SMS notifications
//! - [`contacts`](contacts) - Contact sync
//!
//! ### Content Sharing Plugins
//! - [`clipboard`](clipboard) - Clipboard sync
//! - [`share`](share) - File/text/URL sharing
//!
//! ### Remote Control Plugins
//! - [`remoteinput`](remoteinput) - Mouse/keyboard control
//! - [`mpris`](mpris) - Media player control
//! - [`runcommand`](runcommand) - Remote command execution
//! - [`presenter`](presenter) - Presentation control
//!
//! ### Utility Plugins
//! - [`findmyphone`](findmyphone) - Find my phone
//! - [`lock`](lock) - Lock/unlock device screen
//!
//! ## Example Usage
//!
//! ```rust
//! use cosmic_ext_connect_core::plugins::{PluginManager, ping::PingPlugin, battery::BatteryPlugin};
//! use cosmic_ext_connect_core::protocol::Packet;
//! use serde_json::json;
//!
//! # async fn example() -> cosmic_ext_connect_core::error::Result<()> {
//! let mut manager = PluginManager::new();
//!
//! // Register plugins
//! manager.register_plugin(Box::new(PingPlugin::new())).await?;
//! manager.register_plugin(Box::new(BatteryPlugin::new())).await?;
//!
//! // Get capabilities for identity packet
//! let (incoming, outgoing) = manager.get_capabilities().await;
//! println!("Incoming capabilities: {:?}", incoming);
//! println!("Outgoing capabilities: {:?}", outgoing);
//!
//! // Route incoming packet
//! let packet = Packet::new("cconnect.ping", json!({}));
//! manager.route_packet(&packet).await?;
//!
//! // Shutdown
//! manager.shutdown_all().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Creating Custom Plugins
//!
//! To create a custom plugin, implement the [`Plugin`](trait@Plugin) trait:
//!
//! ```rust
//! use cosmic_ext_connect_core::plugins::Plugin;
//! use cosmic_ext_connect_core::protocol::Packet;
//! use cosmic_ext_connect_core::error::Result;
//! use async_trait::async_trait;
//!
//! struct MyPlugin {
//!     name: String,
//! }
//!
//! #[async_trait]
//! impl Plugin for MyPlugin {
//!     fn name(&self) -> &str {
//!         &self.name
//!     }
//!
//!     fn incoming_capabilities(&self) -> Vec<String> {
//!         vec!["cconnect.myplugin".to_string()]
//!     }
//!
//!     fn outgoing_capabilities(&self) -> Vec<String> {
//!         vec!["cconnect.myplugin.response".to_string()]
//!     }
//!
//!     async fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
//!         // Handle incoming packets
//!         Ok(())
//!     }
//!
//!     async fn initialize(&mut self) -> Result<()> {
//!         // Set up resources
//!         Ok(())
//!     }
//!
//!     async fn shutdown(&mut self) -> Result<()> {
//!         // Clean up resources
//!         Ok(())
//!     }
//! }
//! ```

// Module exports
pub mod r#trait;       // ✅ Plugin trait
pub mod manager;       // ✅ PluginManager

// Core plugins
pub mod ping;          // ✅ Ping plugin
pub mod battery;       // ✅ Battery status monitoring

// Communication plugins
pub mod notification;   // ✅ Device architecture refactored for FFI
pub mod notification_image; // ✅ Rich notification image support (Issue #126)

// ## Planned Communication Plugins
//
// The following communication plugins are planned but blocked on architecture work:
//
// ### telephony
// - **Status**: Blocked
// - **Requirements**: Device FFI refactoring (Issue #46)
// - **Description**: Call and SMS notifications
// - **Capabilities**: `kdeconnect.telephony`, `kdeconnect.telephony.request_mute`
//
// ### contacts
// - **Status**: Blocked
// - **Requirements**: Device FFI refactoring (Issue #46)
// - **Description**: Contact synchronization
// - **Capabilities**: `kdeconnect.contacts.request_all_uids_timestamps`, `kdeconnect.contacts.request_vcards_by_uid`

// Content sharing plugins

// ## Planned Content Sharing Plugins
//
// ### clipboard
// - **Status**: Blocked
// - **Requirements**: Device FFI refactoring (Issue #46)
// - **Description**: Clipboard synchronization across devices
// - **Capabilities**: `kdeconnect.clipboard`, `kdeconnect.clipboard.connect`

pub mod share;            // ✅  Phase 1 complete: Device dependencies removed (Issue #53)

// Streaming plugins
pub mod camera;           // ✅  Camera webcam streaming (Issue #99-#100)
pub mod webcam;           // ✅  Webcam streaming (desktop → phone)
pub mod audiostream;      // ✅  Audio streaming (Issue #153)

// App continuity plugins
pub mod open;             // ✅  Open content on remote devices (Issue #113)

// Remote control plugins

// ## Planned Remote Control Plugins
//
// The following remote control plugins require platform-specific dependencies:
//
// ### remoteinput
// - **Status**: Blocked
// - **Requirements**: `mouse_keyboard_input` crate (Linux-only, needs cross-platform alternative)
// - **Description**: Remote mouse and keyboard control
// - **Capabilities**: `kdeconnect.mousepad.request`, `kdeconnect.mousepad.keyboardstate`
// - **Notes**: Needs abstraction layer for Android/Desktop platform differences
//
// ### mpris
// - **Status**: Blocked
// - **Requirements**: Device FFI refactoring (Issue #46)
// - **Description**: Media player control via MPRIS2 protocol
// - **Capabilities**: `kdeconnect.mpris`, `kdeconnect.mpris.request`
//
// ### runcommand
// - **Status**: Blocked
// - **Requirements**: Device FFI refactoring (Issue #46)
// - **Description**: Remote command execution with command registry
// - **Capabilities**: `kdeconnect.runcommand`, `kdeconnect.runcommand.request`
// - **Security**: Requires command whitelist and permissions system
//
// ### presenter
// - **Status**: Blocked
// - **Requirements**: Device FFI refactoring (Issue #46)
// - **Description**: Presentation remote control (pointer, slides)
// - **Capabilities**: `kdeconnect.presenter`

// Utility plugins

// ## Planned Utility Plugins
//
// ### findmyphone
// - **Status**: Blocked
// - **Requirements**: Device FFI refactoring (Issue #46)
// - **Description**: Trigger phone ringtone for locating device
// - **Capabilities**: `kdeconnect.findmyphone.request`
// - **Notes**: Requires platform audio APIs

pub mod lock;             // ✅ Lock/unlock device screen
pub mod filesync;         // ✅ File synchronization
pub mod screenshare;      // ✅ Screen sharing with configurable resolution and codec
pub mod virtualmonitor;   // ✅ Virtual monitor plugin

// Re-exports for convenience
pub use r#trait::{Plugin, PluginMetadata};
pub use manager::PluginManager;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Packet;
    use serde_json::json;

    #[tokio::test]
    async fn test_plugin_system_integration() {
        let mut manager = PluginManager::new();

        // Register multiple plugins
        manager
            .register_plugin(Box::new(ping::PingPlugin::new()))
            .await
            .unwrap();

        manager
            .register_plugin(Box::new(battery::BatteryPlugin::new()))
            .await
            .unwrap();

        // Verify plugins are registered
        assert!(manager.has_plugin("ping"));
        assert!(manager.has_plugin("battery"));
        assert_eq!(manager.plugin_count(), 2);

        // Get capabilities
        let (incoming, outgoing) = manager.get_capabilities().await;

        // Ping capabilities
        assert!(incoming.contains(&"cconnect.ping".to_string()));
        assert!(outgoing.contains(&"cconnect.ping".to_string()));

        // Battery capabilities
        assert!(incoming.contains(&"cconnect.battery".to_string()));
        assert!(incoming.contains(&"cconnect.battery.request".to_string()));
        assert!(outgoing.contains(&"cconnect.battery".to_string()));

        // Route ping packet
        let ping_packet = Packet::new("cconnect.ping", json!({}));
        manager.route_packet(&ping_packet).await.unwrap();

        // Route battery packet
        let battery_packet = Packet::new(
            "cconnect.battery",
            json!({
                "isCharging": true,
                "currentCharge": 75,
                "thresholdEvent": 0,
            }),
        );
        manager.route_packet(&battery_packet).await.unwrap();

        // Shutdown all
        manager.shutdown_all().await.unwrap();
        assert_eq!(manager.plugin_count(), 0);
    }

    #[tokio::test]
    async fn test_plugin_metadata() {
        let metadata = PluginMetadata::new("battery", "Battery Monitor", "Monitor battery status")
            .with_version("1.0.0")
            .with_author("COSMIC Connect")
            .with_enabled(true);

        assert_eq!(metadata.name, "battery");
        assert_eq!(metadata.display_name, "Battery Monitor");
        assert!(metadata.enabled);
    }
}
