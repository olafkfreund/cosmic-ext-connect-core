//! Battery Plugin
//!
//! Monitors and shares battery status between devices.
//! Can send battery updates and respond to battery status requests.
//!
//! ## Packet Types
//!
//! - **Incoming**:
//!   - `kdeconnect.battery` - Receive battery status from remote device
//!   - `kdeconnect.battery.request` - Request for our battery status
//! - **Outgoing**:
//!   - `kdeconnect.battery` - Send battery status to remote device
//!
//! ## Example
//!
//! ```rust
//! use cosmic_connect_core::plugins::battery::{BatteryPlugin, BatteryState};
//!
//! # async fn example() {
//! let mut plugin = BatteryPlugin::new();
//! plugin.update_local_battery(BatteryState {
//!     is_charging: true,
//!     current_charge: 85,
//!     threshold_event: 0,
//! });
//! # }
//! ```

use crate::error::Result;
use crate::plugins::Plugin;
use crate::protocol::Packet;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, info, warn};

/// Battery state information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BatteryState {
    /// Whether the device is charging
    #[serde(rename = "isCharging")]
    pub is_charging: bool,

    /// Current charge level (0-100)
    #[serde(rename = "currentCharge")]
    pub current_charge: i32,

    /// Threshold event:
    /// - 0: No event
    /// - 1: Battery is low (typically < 15%)
    #[serde(rename = "thresholdEvent")]
    pub threshold_event: i32,
}

impl BatteryState {
    /// Create a new battery state
    pub fn new(is_charging: bool, current_charge: i32) -> Self {
        // Determine threshold event
        let threshold_event = if !is_charging && current_charge < 15 { 1 } else { 0 };

        Self {
            is_charging,
            current_charge: current_charge.clamp(0, 100),
            threshold_event,
        }
    }

    /// Check if battery is low (< 15%)
    pub fn is_low(&self) -> bool {
        self.current_charge < 15 && !self.is_charging
    }

    /// Check if battery is critical (< 5%)
    pub fn is_critical(&self) -> bool {
        self.current_charge < 5 && !self.is_charging
    }
}

/// Battery plugin for monitoring battery status
///
/// This plugin tracks both local and remote device battery states.
/// Platform-specific code is responsible for:
/// - Reading actual battery level from system
/// - Displaying battery status in UI
/// - Triggering low battery notifications
pub struct BatteryPlugin {
    /// Plugin name
    name: String,

    /// Local device battery state (set by platform code)
    local_battery: Option<BatteryState>,

    /// Remote device battery state (received via packets)
    remote_battery: Option<BatteryState>,
}

impl BatteryPlugin {
    /// Create a new battery plugin
    pub fn new() -> Self {
        Self {
            name: "battery".to_string(),
            local_battery: None,
            remote_battery: None,
        }
    }

    /// Update local battery state
    ///
    /// Platform code should call this when the local battery state changes.
    ///
    /// # Arguments
    ///
    /// * `state` - New battery state
    pub fn update_local_battery(&mut self, state: BatteryState) {
        debug!(
            "Local battery updated: {}%, charging: {}",
            state.current_charge, state.is_charging
        );

        self.local_battery = Some(state);
    }

    /// Get local battery state
    pub fn local_battery(&self) -> Option<&BatteryState> {
        self.local_battery.as_ref()
    }

    /// Get remote battery state
    pub fn remote_battery(&self) -> Option<&BatteryState> {
        self.remote_battery.as_ref()
    }

    /// Create a battery status packet
    ///
    /// Creates a packet containing the current local battery state.
    ///
    /// # Returns
    ///
    /// A packet with battery information, or None if local battery is unknown
    pub fn create_battery_packet(&self) -> Option<Packet> {
        self.local_battery.as_ref().map(|state| {
            Packet::new(
                "kdeconnect.battery",
                json!({
                    "isCharging": state.is_charging,
                    "currentCharge": state.current_charge,
                    "thresholdEvent": state.threshold_event,
                }),
            )
        })
    }
}

impl Default for BatteryPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for BatteryPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn incoming_capabilities(&self) -> Vec<String> {
        vec![
            "kdeconnect.battery".to_string(),
            "kdeconnect.battery.request".to_string(),
        ]
    }

    fn outgoing_capabilities(&self) -> Vec<String> {
        vec!["kdeconnect.battery".to_string()]
    }

    async fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
        match packet.packet_type.as_str() {
            "kdeconnect.battery" => {
                // Receive remote battery status
                let state: BatteryState = serde_json::from_value(packet.body.clone())
                    .map_err(|e| {
                        warn!("Failed to parse battery packet: {}", e);
                        crate::error::ProtocolError::InvalidPacket(format!(
                            "Invalid battery packet: {}",
                            e
                        ))
                    })?;

                info!(
                    "Remote battery: {}%, charging: {}",
                    state.current_charge, state.is_charging
                );

                if state.is_low() {
                    warn!(
                        "Remote device battery is low: {}%",
                        state.current_charge
                    );
                }

                self.remote_battery = Some(state);
            }

            "kdeconnect.battery.request" => {
                // Remote device is requesting our battery status
                info!("Received battery status request");

                // Platform code should handle sending the response packet
                // by calling create_battery_packet() and sending it
                debug!("Battery request received (platform should send response)");
            }

            _ => {
                warn!("Unexpected packet type: {}", packet.packet_type);
            }
        }

        Ok(())
    }

    async fn initialize(&mut self) -> Result<()> {
        info!("Battery plugin initialized");
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("Battery plugin shutting down");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_battery_state_creation() {
        let state = BatteryState::new(true, 85);
        assert_eq!(state.current_charge, 85);
        assert!(state.is_charging);
        assert_eq!(state.threshold_event, 0);
        assert!(!state.is_low());
    }

    #[test]
    fn test_battery_state_low() {
        let state = BatteryState::new(false, 10);
        assert!(state.is_low());
        assert_eq!(state.threshold_event, 1);
    }

    #[test]
    fn test_battery_state_critical() {
        let state = BatteryState::new(false, 3);
        assert!(state.is_critical());
        assert!(state.is_low());
    }

    #[test]
    fn test_battery_state_charging_not_low() {
        let state = BatteryState::new(true, 10);
        assert!(!state.is_low()); // Charging, so not low
        assert_eq!(state.threshold_event, 0);
    }

    #[tokio::test]
    async fn test_battery_plugin_creation() {
        let plugin = BatteryPlugin::new();
        assert_eq!(plugin.name(), "battery");
        assert!(plugin.local_battery().is_none());
        assert!(plugin.remote_battery().is_none());
    }

    #[tokio::test]
    async fn test_battery_capabilities() {
        let plugin = BatteryPlugin::new();
        let incoming = plugin.incoming_capabilities();
        let outgoing = plugin.outgoing_capabilities();

        assert_eq!(incoming.len(), 2);
        assert!(incoming.contains(&"kdeconnect.battery".to_string()));
        assert!(incoming.contains(&"kdeconnect.battery.request".to_string()));

        assert_eq!(outgoing, vec!["kdeconnect.battery"]);
    }

    #[tokio::test]
    async fn test_update_local_battery() {
        let mut plugin = BatteryPlugin::new();

        let state = BatteryState::new(true, 75);
        plugin.update_local_battery(state.clone());

        let local = plugin.local_battery().unwrap();
        assert_eq!(local.current_charge, 75);
        assert!(local.is_charging);
    }

    #[tokio::test]
    async fn test_handle_battery_packet() {
        let mut plugin = BatteryPlugin::new();

        let packet = Packet::new(
            "kdeconnect.battery",
            json!({
                "isCharging": false,
                "currentCharge": 50,
                "thresholdEvent": 0,
            }),
        );

        plugin.handle_packet(&packet).await.unwrap();

        let remote = plugin.remote_battery().unwrap();
        assert_eq!(remote.current_charge, 50);
        assert!(!remote.is_charging);
    }

    #[tokio::test]
    async fn test_handle_battery_request() {
        let mut plugin = BatteryPlugin::new();

        let packet = Packet::new("kdeconnect.battery.request", json!({}));

        // Should not error
        plugin.handle_packet(&packet).await.unwrap();
    }

    #[tokio::test]
    async fn test_create_battery_packet() {
        let mut plugin = BatteryPlugin::new();

        // No packet if battery unknown
        assert!(plugin.create_battery_packet().is_none());

        // Set battery state
        let state = BatteryState::new(true, 80);
        plugin.update_local_battery(state);

        // Now we can create packet
        let packet = plugin.create_battery_packet().unwrap();
        assert_eq!(packet.packet_type, "kdeconnect.battery");

        let charge = packet
            .body
            .get("currentCharge")
            .and_then(|v| v.as_i64())
            .unwrap();
        assert_eq!(charge, 80);

        let is_charging = packet
            .body
            .get("isCharging")
            .and_then(|v| v.as_bool())
            .unwrap();
        assert!(is_charging);
    }

    #[tokio::test]
    async fn test_lifecycle() {
        let mut plugin = BatteryPlugin::new();

        plugin.initialize().await.unwrap();
        plugin.shutdown().await.unwrap();
    }
}
