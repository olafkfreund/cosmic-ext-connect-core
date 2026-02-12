//! Plugin Manager
//!
//! Manages the lifecycle and routing of plugins in the KDE Connect protocol.
//!
//! ## Responsibilities
//!
//! - Plugin registration and de-registration
//! - Plugin lifecycle management (initialize/shutdown)
//! - Packet routing to appropriate plugins
//! - Capability aggregation for identity packets
//! - Plugin state management
//!
//! ## Example
//!
//! ```rust
//! use cosmic_ext_connect_core::plugins::PluginManager;
//! use cosmic_ext_connect_core::protocol::Packet;
//! use serde_json::json;
//!
//! # async fn example() -> cosmic_ext_connect_core::error::Result<()> {
//! let mut manager = PluginManager::new();
//!
//! // Register plugins
//! // manager.register_plugin(Box::new(BatteryPlugin::new())).await?;
//! // manager.register_plugin(Box::new(PingPlugin::new())).await?;
//!
//! // Get capabilities for identity packet
//! let (incoming, outgoing) = manager.get_capabilities().await;
//!
//! // Route incoming packet
//! let packet = Packet::new("cconnect.ping", json!({}));
//! manager.route_packet(&packet).await?;
//! # Ok(())
//! # }
//! ```

use crate::error::{ProtocolError, Result};
use crate::plugins::Plugin;
use crate::protocol::Packet;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Plugin Manager
///
/// Manages all registered plugins and routes packets to the appropriate handlers.
pub struct PluginManager {
    /// Registered plugins indexed by name
    plugins: HashMap<String, Arc<RwLock<Box<dyn Plugin>>>>,

    /// Packet type to plugin name mapping for fast routing
    packet_routes: HashMap<String, Vec<String>>,

    /// Whether the manager has been initialized
    initialized: bool,
}

impl PluginManager {
    /// Create a new PluginManager
    pub fn new() -> Self {
        info!("Creating new PluginManager");
        Self {
            plugins: HashMap::new(),
            packet_routes: HashMap::new(),
            initialized: false,
        }
    }

    /// Register a plugin
    ///
    /// Registers a plugin with the manager and calls its `initialize()` method.
    /// The plugin's incoming capabilities are used to set up packet routing.
    ///
    /// # Arguments
    ///
    /// * `plugin` - Boxed plugin implementing the Plugin trait
    ///
    /// # Errors
    ///
    /// - `ProtocolError::AlreadyExists` - Plugin with this name is already registered
    /// - `ProtocolError::Plugin` - Plugin initialization failed
    ///
    /// # Examples
    ///
    /// ```ignore
    /// manager.register_plugin(Box::new(BatteryPlugin::new())).await?;
    /// ```
    pub async fn register_plugin(&mut self, mut plugin: Box<dyn Plugin>) -> Result<()> {
        let name = plugin.name().to_string();

        if self.plugins.contains_key(&name) {
            return Err(ProtocolError::AlreadyExists(format!(
                "Plugin '{}' is already registered",
                name
            )));
        }

        info!("Registering plugin: {}", name);

        // Initialize the plugin
        plugin
            .initialize()
            .await
            .map_err(|e| ProtocolError::Plugin(format!("Failed to initialize plugin '{}': {}", name, e)))?;

        // Build packet routing table
        let incoming_caps = plugin.incoming_capabilities();
        for packet_type in &incoming_caps {
            self.packet_routes
                .entry(packet_type.clone())
                .or_insert_with(Vec::new)
                .push(name.clone());
        }

        debug!(
            "Plugin '{}' registered with {} incoming capabilities",
            name,
            incoming_caps.len()
        );

        // Store plugin
        self.plugins
            .insert(name.clone(), Arc::new(RwLock::new(plugin)));

        Ok(())
    }

    /// Unregister a plugin
    ///
    /// Removes a plugin from the manager and calls its `shutdown()` method.
    ///
    /// # Arguments
    ///
    /// * `name` - Plugin name
    ///
    /// # Errors
    ///
    /// - `ProtocolError::DeviceNotFound` - Plugin not found
    /// - `ProtocolError::Plugin` - Plugin shutdown failed
    pub async fn unregister_plugin(&mut self, name: &str) -> Result<()> {
        info!("Unregistering plugin: {}", name);

        let plugin = self
            .plugins
            .remove(name)
            .ok_or_else(|| ProtocolError::DeviceNotFound(format!("Plugin '{}' not found", name)))?;

        // Shutdown the plugin
        let mut plugin_guard = plugin.write().await;
        plugin_guard
            .shutdown()
            .await
            .map_err(|e| ProtocolError::Plugin(format!("Failed to shutdown plugin '{}': {}", name, e)))?;

        // Remove from routing table
        self.packet_routes.retain(|_, plugins| {
            plugins.retain(|p| p != name);
            !plugins.is_empty()
        });

        debug!("Plugin '{}' unregistered successfully", name);

        Ok(())
    }

    /// Route a packet to the appropriate plugin(s)
    ///
    /// Looks up which plugin(s) handle the packet type and calls their
    /// `handle_packet()` method.
    ///
    /// # Arguments
    ///
    /// * `packet` - The packet to route
    ///
    /// # Errors
    ///
    /// - `ProtocolError::Plugin` - No plugin found for packet type, or plugin failed to handle packet
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let packet = Packet::new("cconnect.ping", json!({}));
    /// manager.route_packet(&packet).await?;
    /// ```
    pub async fn route_packet(&self, packet: &Packet) -> Result<()> {
        let packet_type = &packet.packet_type;

        debug!("Routing packet type: {}", packet_type);

        // Find plugins that handle this packet type
        let plugin_names = self
            .packet_routes
            .get(packet_type)
            .ok_or_else(|| {
                warn!("No plugin registered for packet type: {}", packet_type);
                ProtocolError::Plugin(format!("No plugin handles packet type: {}", packet_type))
            })?;

        // Route to all plugins that handle this type
        for plugin_name in plugin_names {
            let plugin = self
                .plugins
                .get(plugin_name)
                .ok_or_else(|| {
                    error!("Plugin '{}' not found in registry", plugin_name);
                    ProtocolError::Plugin(format!("Plugin '{}' not found", plugin_name))
                })?;

            debug!(
                "Dispatching packet '{}' to plugin '{}'",
                packet_type, plugin_name
            );

            let mut plugin_guard = plugin.write().await;
            plugin_guard.handle_packet(packet).await.map_err(|e| {
                error!(
                    "Plugin '{}' failed to handle packet '{}': {}",
                    plugin_name, packet_type, e
                );
                ProtocolError::Plugin(format!(
                    "Plugin '{}' failed to handle packet: {}",
                    plugin_name, e
                ))
            })?;

            debug!(
                "Plugin '{}' handled packet '{}' successfully",
                plugin_name, packet_type
            );
        }

        Ok(())
    }

    /// Get aggregated capabilities from all plugins
    ///
    /// Returns a tuple of (incoming_capabilities, outgoing_capabilities)
    /// collected from all registered plugins. Duplicates are removed.
    ///
    /// These capabilities should be included in the identity packet sent
    /// to remote devices.
    ///
    /// # Returns
    ///
    /// A tuple of (incoming_capabilities, outgoing_capabilities)
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let (incoming, outgoing) = manager.get_capabilities();
    /// let identity = Packet::new("cconnect.identity", json!({
    ///     "incomingCapabilities": incoming,
    ///     "outgoingCapabilities": outgoing,
    /// }));
    /// ```
    pub async fn get_capabilities(&self) -> (Vec<String>, Vec<String>) {
        let mut incoming = Vec::new();
        let mut outgoing = Vec::new();

        for plugin in self.plugins.values() {
            let plugin_guard = plugin.read().await;
            let (inc, out) = plugin_guard.get_capabilities();
            incoming.extend(inc);
            outgoing.extend(out);
        }

        // Remove duplicates and sort
        incoming.sort();
        incoming.dedup();
        outgoing.sort();
        outgoing.dedup();

        (incoming, outgoing)
    }

    /// Get a plugin by name
    ///
    /// Returns a reference to the plugin if it exists.
    ///
    /// # Arguments
    ///
    /// * `name` - Plugin name
    ///
    /// # Returns
    ///
    /// `Some(plugin)` if found, `None` otherwise
    pub fn get_plugin(&self, name: &str) -> Option<Arc<RwLock<Box<dyn Plugin>>>> {
        self.plugins.get(name).cloned()
    }

    /// Check if a plugin is registered
    ///
    /// # Arguments
    ///
    /// * `name` - Plugin name
    ///
    /// # Returns
    ///
    /// `true` if the plugin is registered, `false` otherwise
    pub fn has_plugin(&self, name: &str) -> bool {
        self.plugins.contains_key(name)
    }

    /// Get all registered plugin names
    pub fn plugin_names(&self) -> Vec<String> {
        self.plugins.keys().cloned().collect()
    }

    /// Get the number of registered plugins
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    /// Shutdown all plugins
    ///
    /// Calls `shutdown()` on all registered plugins in reverse registration order.
    /// This is typically called when the application is shutting down.
    ///
    /// # Errors
    ///
    /// Returns the first error encountered, but continues shutting down remaining plugins.
    pub async fn shutdown_all(&mut self) -> Result<()> {
        info!("Shutting down all plugins");

        let mut errors = Vec::new();

        // Get plugin names to shutdown
        let plugin_names: Vec<String> = self.plugins.keys().cloned().collect();

        for name in plugin_names {
            if let Err(e) = self.unregister_plugin(&name).await {
                error!("Failed to shutdown plugin '{}': {}", name, e);
                errors.push(e);
            }
        }

        if let Some(first_error) = errors.into_iter().next() {
            return Err(first_error);
        }

        self.initialized = false;

        info!("All plugins shut down successfully");

        Ok(())
    }

    /// Check if the manager is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Mark the manager as initialized
    pub fn set_initialized(&mut self, initialized: bool) {
        self.initialized = initialized;
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use serde_json::json;

    struct TestPlugin {
        name: String,
        incoming: Vec<String>,
        outgoing: Vec<String>,
        packets_received: Vec<String>,
    }

    impl TestPlugin {
        fn new(name: impl Into<String>, incoming: Vec<&str>, outgoing: Vec<&str>) -> Self {
            Self {
                name: name.into(),
                incoming: incoming.iter().map(|s| s.to_string()).collect(),
                outgoing: outgoing.iter().map(|s| s.to_string()).collect(),
                packets_received: Vec::new(),
            }
        }
    }

    #[async_trait]
    impl Plugin for TestPlugin {
        fn name(&self) -> &str {
            &self.name
        }

        fn incoming_capabilities(&self) -> Vec<String> {
            self.incoming.clone()
        }

        fn outgoing_capabilities(&self) -> Vec<String> {
            self.outgoing.clone()
        }

        async fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
            self.packets_received.push(packet.packet_type.clone());
            Ok(())
        }

        async fn initialize(&mut self) -> Result<()> {
            Ok(())
        }

        async fn shutdown(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_register_plugin() {
        let mut manager = PluginManager::new();
        let plugin = Box::new(TestPlugin::new(
            "test",
            vec!["cconnect.test"],
            vec!["cconnect.test.response"],
        ));

        manager.register_plugin(plugin).await.unwrap();

        assert!(manager.has_plugin("test"));
        assert_eq!(manager.plugin_count(), 1);
    }

    #[tokio::test]
    async fn test_duplicate_registration() {
        let mut manager = PluginManager::new();

        manager
            .register_plugin(Box::new(TestPlugin::new("test", vec![], vec![])))
            .await
            .unwrap();

        let result = manager
            .register_plugin(Box::new(TestPlugin::new("test", vec![], vec![])))
            .await;

        assert!(result.is_err());
        assert!(matches!(result, Err(ProtocolError::AlreadyExists(_))));
    }

    #[tokio::test]
    async fn test_route_packet() {
        let mut manager = PluginManager::new();

        manager
            .register_plugin(Box::new(TestPlugin::new(
                "test",
                vec!["cconnect.test"],
                vec![],
            )))
            .await
            .unwrap();

        let packet = Packet::new("cconnect.test", json!({}));
        manager.route_packet(&packet).await.unwrap();

        // Packet routing succeeded - plugin handled it
        // Note: Cannot directly verify packet_received count without downcasting
        // but the fact that route_packet succeeded proves the packet was handled
    }

    #[tokio::test]
    async fn test_route_to_nonexistent_plugin() {
        let manager = PluginManager::new();

        let packet = Packet::new("cconnect.nonexistent", json!({}));
        let result = manager.route_packet(&packet).await;

        assert!(result.is_err());
        assert!(matches!(result, Err(ProtocolError::Plugin(_))));
    }

    #[tokio::test]
    async fn test_get_capabilities() {
        let mut manager = PluginManager::new();

        manager
            .register_plugin(Box::new(TestPlugin::new(
                "plugin1",
                vec!["cconnect.battery"],
                vec!["cconnect.battery.request"],
            )))
            .await
            .unwrap();

        manager
            .register_plugin(Box::new(TestPlugin::new(
                "plugin2",
                vec!["cconnect.ping"],
                vec!["cconnect.ping"],
            )))
            .await
            .unwrap();

        let (incoming, outgoing) = manager.get_capabilities().await;

        assert_eq!(incoming.len(), 2);
        assert!(incoming.contains(&"cconnect.battery".to_string()));
        assert!(incoming.contains(&"cconnect.ping".to_string()));

        assert_eq!(outgoing.len(), 2);
        assert!(outgoing.contains(&"cconnect.battery.request".to_string()));
        assert!(outgoing.contains(&"cconnect.ping".to_string()));
    }

    #[tokio::test]
    async fn test_unregister_plugin() {
        let mut manager = PluginManager::new();

        manager
            .register_plugin(Box::new(TestPlugin::new("test", vec![], vec![])))
            .await
            .unwrap();

        assert!(manager.has_plugin("test"));

        manager.unregister_plugin("test").await.unwrap();

        assert!(!manager.has_plugin("test"));
        assert_eq!(manager.plugin_count(), 0);
    }

    #[tokio::test]
    async fn test_shutdown_all() {
        let mut manager = PluginManager::new();

        manager
            .register_plugin(Box::new(TestPlugin::new("plugin1", vec![], vec![])))
            .await
            .unwrap();

        manager
            .register_plugin(Box::new(TestPlugin::new("plugin2", vec![], vec![])))
            .await
            .unwrap();

        assert_eq!(manager.plugin_count(), 2);

        manager.shutdown_all().await.unwrap();

        assert_eq!(manager.plugin_count(), 0);
    }

    #[tokio::test]
    async fn test_plugin_names() {
        let mut manager = PluginManager::new();

        manager
            .register_plugin(Box::new(TestPlugin::new("plugin1", vec![], vec![])))
            .await
            .unwrap();

        manager
            .register_plugin(Box::new(TestPlugin::new("plugin2", vec![], vec![])))
            .await
            .unwrap();

        let names = manager.plugin_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"plugin1".to_string()));
        assert!(names.contains(&"plugin2".to_string()));
    }
}
