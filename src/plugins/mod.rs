//! Plugin system module
//!
//! KDE Connect plugin trait and implementations.
//!
//! ## Architecture
//!
//! The plugin system in `cosmic-connect-core` provides a clean separation between:
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
//!
//! ## Example Usage
//!
//! ```rust
//! use cosmic_connect_core::plugins::{PluginManager, ping::PingPlugin, battery::BatteryPlugin};
//! use cosmic_connect_core::protocol::Packet;
//! use serde_json::json;
//!
//! # async fn example() -> cosmic_connect_core::error::Result<()> {
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
//! let packet = Packet::new("kdeconnect.ping", json!({}));
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
//! use cosmic_connect_core::plugins::Plugin;
//! use cosmic_connect_core::protocol::Packet;
//! use cosmic_connect_core::error::Result;
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
//!         vec!["kdeconnect.myplugin".to_string()]
//!     }
//!
//!     fn outgoing_capabilities(&self) -> Vec<String> {
//!         vec!["kdeconnect.myplugin.response".to_string()]
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
pub mod notification;  // ✅ Notification forwarding
pub mod telephony;     // ✅ Call/SMS notifications
pub mod contacts;      // ✅ Contact sync

// Content sharing plugins
pub mod clipboard;     // ✅ Clipboard sync
pub mod share;         // ✅ File/text/URL sharing

// Remote control plugins
pub mod remoteinput;   // ✅ Mouse/keyboard control
pub mod mpris;         // ✅ Media player control
pub mod runcommand;    // ✅ Remote command execution
pub mod presenter;     // ✅ Presentation control

// Utility plugins
pub mod findmyphone;   // ✅ Find my phone

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
        assert!(incoming.contains(&"kdeconnect.ping".to_string()));
        assert!(outgoing.contains(&"kdeconnect.ping".to_string()));

        // Battery capabilities
        assert!(incoming.contains(&"kdeconnect.battery".to_string()));
        assert!(incoming.contains(&"kdeconnect.battery.request".to_string()));
        assert!(outgoing.contains(&"kdeconnect.battery".to_string()));

        // Route ping packet
        let ping_packet = Packet::new("kdeconnect.ping", json!({}));
        manager.route_packet(&ping_packet).await.unwrap();

        // Route battery packet
        let battery_packet = Packet::new(
            "kdeconnect.battery",
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
