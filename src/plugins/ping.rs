//! Ping Plugin
//!
//! Simple plugin for testing connectivity between devices.
//! Responds to ping packets and can send pings to remote devices.
//!
//! ## Packet Types
//!
//! - **Incoming**: `cconnect.ping` - Respond to ping requests
//! - **Outgoing**: `cconnect.ping` - Send ping requests
//!
//! ## Example
//!
//! ```rust
//! use cosmic_connect_core::plugins::ping::PingPlugin;
//! use cosmic_connect_core::plugins::Plugin;
//!
//! # async fn example() {
//! let mut plugin = PingPlugin::new();
//! plugin.initialize().await.unwrap();
//! # }
//! ```

use crate::error::Result;
use crate::plugins::Plugin;
use crate::protocol::Packet;
use async_trait::async_trait;
use serde_json::json;
use tracing::{debug, info};

/// Ping plugin for testing connectivity
///
/// This plugin responds to ping requests and can send pings to test
/// the connection with remote devices.
pub struct PingPlugin {
    /// Plugin name
    name: String,

    /// Number of pings received
    pings_received: u64,

    /// Number of pings sent
    pings_sent: u64,
}

impl PingPlugin {
    /// Create a new ping plugin
    pub fn new() -> Self {
        Self {
            name: "ping".to_string(),
            pings_received: 0,
            pings_sent: 0,
        }
    }

    /// Get the number of pings received
    pub fn pings_received(&self) -> u64 {
        self.pings_received
    }

    /// Get the number of pings sent
    pub fn pings_sent(&self) -> u64 {
        self.pings_sent
    }

    /// Create a ping packet
    ///
    /// # Arguments
    ///
    /// * `message` - Optional message to include in the ping
    ///
    /// # Returns
    ///
    /// A ping packet ready to be sent
    pub fn create_ping(&mut self, message: Option<String>) -> Packet {
        self.pings_sent += 1;

        let body = if let Some(msg) = message {
            json!({ "message": msg })
        } else {
            json!({})
        };

        Packet::new("cconnect.ping", body)
    }
}

impl Default for PingPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for PingPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn incoming_capabilities(&self) -> Vec<String> {
        vec!["cconnect.ping".to_string()]
    }

    fn outgoing_capabilities(&self) -> Vec<String> {
        vec!["cconnect.ping".to_string()]
    }

    async fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
        if packet.is_type("cconnect.ping") {
            self.pings_received += 1;

            let message = packet
                .body
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if message.is_empty() {
                info!("Received ping (total: {})", self.pings_received);
            } else {
                info!(
                    "Received ping with message '{}' (total: {})",
                    message, self.pings_received
                );
            }

            debug!("Ping packet body: {:?}", packet.body);
        }

        Ok(())
    }

    async fn initialize(&mut self) -> Result<()> {
        info!("Ping plugin initialized");
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!(
            "Ping plugin shutting down (received: {}, sent: {})",
            self.pings_received, self.pings_sent
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_ping_plugin_creation() {
        let plugin = PingPlugin::new();
        assert_eq!(plugin.name(), "ping");
        assert_eq!(plugin.pings_received(), 0);
        assert_eq!(plugin.pings_sent(), 0);
    }

    #[tokio::test]
    async fn test_ping_capabilities() {
        let plugin = PingPlugin::new();
        let incoming = plugin.incoming_capabilities();
        let outgoing = plugin.outgoing_capabilities();

        assert_eq!(incoming, vec!["cconnect.ping"]);
        assert_eq!(outgoing, vec!["cconnect.ping"]);
    }

    #[tokio::test]
    async fn test_handle_ping_packet() {
        let mut plugin = PingPlugin::new();

        let packet = Packet::new("cconnect.ping", json!({}));
        plugin.handle_packet(&packet).await.unwrap();

        assert_eq!(plugin.pings_received(), 1);
    }

    #[tokio::test]
    async fn test_handle_ping_with_message() {
        let mut plugin = PingPlugin::new();

        let packet = Packet::new("cconnect.ping", json!({"message": "test ping"}));
        plugin.handle_packet(&packet).await.unwrap();

        assert_eq!(plugin.pings_received(), 1);
    }

    #[tokio::test]
    async fn test_create_ping() {
        let mut plugin = PingPlugin::new();

        let packet = plugin.create_ping(None);
        assert_eq!(packet.packet_type, "cconnect.ping");
        assert_eq!(plugin.pings_sent(), 1);

        let packet_with_msg = plugin.create_ping(Some("hello".to_string()));
        assert_eq!(packet_with_msg.packet_type, "cconnect.ping");
        assert_eq!(
            packet_with_msg
                .body
                .get("message")
                .and_then(|v| v.as_str()),
            Some("hello")
        );
        assert_eq!(plugin.pings_sent(), 2);
    }

    #[tokio::test]
    async fn test_lifecycle() {
        let mut plugin = PingPlugin::new();

        plugin.initialize().await.unwrap();
        plugin.shutdown().await.unwrap();
    }
}
