//! Plugin trait definition
//!
//! Defines the interface that all KDE Connect plugins must implement.
//!
//! ## Plugin Architecture
//!
//! Plugins in `cosmic-connect-core` handle:
//! - Protocol logic (packet parsing/generation)
//! - State management
//! - Business logic
//!
//! Platform-specific code (Android/Desktop) handles:
//! - UI rendering
//! - System API integration (permissions, notifications, etc.)
//! - Platform-specific features
//!
//! ## Example
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
//!         vec!["kdeconnect.myplugin".to_string()]
//!     }
//!
//!     async fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
//!         // Process packet
//!         Ok(())
//!     }
//!
//!     async fn initialize(&mut self) -> Result<()> {
//!         Ok(())
//!     }
//!
//!     async fn shutdown(&mut self) -> Result<()> {
//!         Ok(())
//!     }
//! }
//! ```

use crate::error::Result;
use crate::protocol::Packet;
use async_trait::async_trait;

/// Plugin trait for KDE Connect plugins
///
/// All plugins must implement this trait to participate in the plugin system.
/// Plugins are responsible for handling specific packet types and managing
/// their own state.
///
/// ## Lifecycle
///
/// 1. **Construction**: Plugin is created (constructor)
/// 2. **Registration**: Plugin is registered with PluginManager
/// 3. **Initialization**: `initialize()` is called to set up resources
/// 4. **Operation**: `handle_packet()` is called for incoming packets
/// 5. **Shutdown**: `shutdown()` is called to clean up resources
///
/// ## Thread Safety
///
/// Plugins must be `Send + Sync` to allow use in async contexts and across threads.
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Get the plugin name
    ///
    /// This should be a unique identifier for the plugin, typically matching
    /// the plugin name in packet types (e.g., "battery" for "kdeconnect.battery").
    ///
    /// # Examples
    ///
    /// ```ignore
    /// fn name(&self) -> &str {
    ///     "battery"
    /// }
    /// ```
    fn name(&self) -> &str;

    /// Get incoming packet capabilities
    ///
    /// Returns a list of packet types this plugin can receive and handle.
    /// These are advertised to remote devices in the identity packet.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// fn incoming_capabilities(&self) -> Vec<String> {
    ///     vec![
    ///         "kdeconnect.battery".to_string(),
    ///         "kdeconnect.battery.request".to_string(),
    ///     ]
    /// }
    /// ```
    fn incoming_capabilities(&self) -> Vec<String>;

    /// Get outgoing packet capabilities
    ///
    /// Returns a list of packet types this plugin can send.
    /// These are advertised to remote devices in the identity packet.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// fn outgoing_capabilities(&self) -> Vec<String> {
    ///     vec!["kdeconnect.battery".to_string()]
    /// }
    /// ```
    fn outgoing_capabilities(&self) -> Vec<String>;

    /// Handle an incoming packet
    ///
    /// Called by the PluginManager when a packet matching this plugin's
    /// incoming capabilities is received.
    ///
    /// # Arguments
    ///
    /// * `packet` - The incoming packet to process
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Packet was handled successfully
    /// - `Err(ProtocolError)` - An error occurred while handling the packet
    ///
    /// # Examples
    ///
    /// ```ignore
    /// async fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
    ///     match packet.packet_type.as_str() {
    ///         "kdeconnect.battery.request" => self.send_battery_state().await,
    ///         "kdeconnect.battery" => self.update_battery_state(packet).await,
    ///         _ => Ok(()),
    ///     }
    /// }
    /// ```
    async fn handle_packet(&mut self, packet: &Packet) -> Result<()>;

    /// Initialize the plugin
    ///
    /// Called once after the plugin is registered with the PluginManager.
    /// Use this to set up resources, establish connections, or load state.
    ///
    /// # Errors
    ///
    /// Return an error if initialization fails. The plugin will not be usable.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// async fn initialize(&mut self) -> Result<()> {
    ///     // Load plugin state from storage
    ///     self.load_state().await?;
    ///     Ok(())
    /// }
    /// ```
    async fn initialize(&mut self) -> Result<()>;

    /// Shutdown the plugin
    ///
    /// Called when the plugin is being removed or the application is shutting down.
    /// Use this to clean up resources, save state, or close connections.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// async fn shutdown(&mut self) -> Result<()> {
    ///     // Save plugin state
    ///     self.save_state().await?;
    ///     Ok(())
    /// }
    /// ```
    async fn shutdown(&mut self) -> Result<()>;

    /// Check if this plugin handles a specific packet type
    ///
    /// Default implementation checks if the packet type is in incoming_capabilities.
    ///
    /// # Arguments
    ///
    /// * `packet_type` - The packet type to check
    ///
    /// # Returns
    ///
    /// `true` if this plugin can handle the packet type, `false` otherwise
    fn handles_packet_type(&self, packet_type: &str) -> bool {
        self.incoming_capabilities()
            .iter()
            .any(|cap| cap == packet_type)
    }

    /// Get all capabilities (incoming + outgoing)
    ///
    /// Helper method to get both incoming and outgoing capabilities.
    ///
    /// # Returns
    ///
    /// A tuple of (incoming_capabilities, outgoing_capabilities)
    fn get_capabilities(&self) -> (Vec<String>, Vec<String>) {
        (self.incoming_capabilities(), self.outgoing_capabilities())
    }
}

/// Plugin metadata
///
/// Additional information about a plugin for display and management purposes.
#[derive(Debug, Clone)]
pub struct PluginMetadata {
    /// Plugin name
    pub name: String,

    /// Human-readable display name
    pub display_name: String,

    /// Plugin description
    pub description: String,

    /// Plugin version
    pub version: String,

    /// Plugin author
    pub author: String,

    /// Whether the plugin is enabled
    pub enabled: bool,
}

impl PluginMetadata {
    /// Create new plugin metadata
    pub fn new(
        name: impl Into<String>,
        display_name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            display_name: display_name.into(),
            description: description.into(),
            version: "1.0.0".to_string(),
            author: "COSMIC Connect".to_string(),
            enabled: true,
        }
    }

    /// Builder: Set version
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Builder: Set author
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = author.into();
        self
    }

    /// Builder: Set enabled state
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestPlugin {
        name: String,
        initialized: bool,
        shutdown: bool,
    }

    #[async_trait]
    impl Plugin for TestPlugin {
        fn name(&self) -> &str {
            &self.name
        }

        fn incoming_capabilities(&self) -> Vec<String> {
            vec!["kdeconnect.test".to_string()]
        }

        fn outgoing_capabilities(&self) -> Vec<String> {
            vec!["kdeconnect.test.response".to_string()]
        }

        async fn handle_packet(&mut self, _packet: &Packet) -> Result<()> {
            Ok(())
        }

        async fn initialize(&mut self) -> Result<()> {
            self.initialized = true;
            Ok(())
        }

        async fn shutdown(&mut self) -> Result<()> {
            self.shutdown = true;
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_plugin_trait() {
        let mut plugin = TestPlugin {
            name: "test".to_string(),
            initialized: false,
            shutdown: false,
        };

        assert_eq!(plugin.name(), "test");
        assert!(!plugin.initialized);

        plugin.initialize().await.unwrap();
        assert!(plugin.initialized);

        plugin.shutdown().await.unwrap();
        assert!(plugin.shutdown);
    }

    #[test]
    fn test_handles_packet_type() {
        let plugin = TestPlugin {
            name: "test".to_string(),
            initialized: false,
            shutdown: false,
        };

        assert!(plugin.handles_packet_type("kdeconnect.test"));
        assert!(!plugin.handles_packet_type("kdeconnect.other"));
    }

    #[test]
    fn test_get_capabilities() {
        let plugin = TestPlugin {
            name: "test".to_string(),
            initialized: false,
            shutdown: false,
        };

        let (incoming, outgoing) = plugin.get_capabilities();
        assert_eq!(incoming, vec!["kdeconnect.test"]);
        assert_eq!(outgoing, vec!["kdeconnect.test.response"]);
    }

    #[test]
    fn test_plugin_metadata() {
        let metadata = PluginMetadata::new("battery", "Battery Monitor", "Monitor battery status")
            .with_version("2.0.0")
            .with_author("Test Author");

        assert_eq!(metadata.name, "battery");
        assert_eq!(metadata.display_name, "Battery Monitor");
        assert_eq!(metadata.version, "2.0.0");
        assert_eq!(metadata.author, "Test Author");
        assert!(metadata.enabled);
    }
}
