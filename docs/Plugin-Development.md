# Plugin Development Guide

## Overview

Plugins extend the functionality of `cosmic-connect-core` by handling specific packet types and implementing custom features. This guide covers creating, registering, and testing plugins.

## Plugin Architecture

### Responsibilities

**Rust Plugin (Core):**
- Protocol logic and packet handling
- State management and business rules
- Data validation and transformation
- Cross-platform functionality

**Platform Code (Kotlin/Swift):**
- User interface rendering
- System API integration
- Permissions and notifications
- Platform-specific features

### Plugin Trait

All plugins implement the `Plugin` trait:

```rust
#[async_trait]
pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;
    fn incoming_capabilities(&self) -> Vec<String>;
    fn outgoing_capabilities(&self) -> Vec<String>;
    async fn handle_packet(&mut self, packet: &Packet) -> Result<()>;
    async fn initialize(&mut self) -> Result<()>;
    async fn shutdown(&mut self) -> Result<()>;
}
```

## Creating a Plugin

### Step 1: Define Plugin Structure

Create a new file: `src/plugins/your_plugin.rs`

```rust
use async_trait::async_trait;
use crate::error::Result;
use crate::plugins::Plugin;
use crate::protocol::Packet;
use serde_json::json;

pub struct YourPlugin {
    name: String,
    // Add state fields
    counter: u64,
    last_message: Option<String>,
}

impl YourPlugin {
    pub fn new() -> Self {
        Self {
            name: "your_plugin".to_string(),
            counter: 0,
            last_message: None,
        }
    }
}
```

### Step 2: Implement Plugin Trait

```rust
#[async_trait]
impl Plugin for YourPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn incoming_capabilities(&self) -> Vec<String> {
        vec![
            "kdeconnect.yourplugin".to_string(),
            "kdeconnect.yourplugin.request".to_string(),
        ]
    }

    fn outgoing_capabilities(&self) -> Vec<String> {
        vec![
            "kdeconnect.yourplugin".to_string(),
            "kdeconnect.yourplugin.response".to_string(),
        ]
    }

    async fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
        match packet.packet_type.as_str() {
            "kdeconnect.yourplugin.request" => {
                self.handle_request(packet).await
            }
            "kdeconnect.yourplugin" => {
                self.handle_data(packet).await
            }
            _ => Ok(()), // Ignore unknown packet types
        }
    }

    async fn initialize(&mut self) -> Result<()> {
        // Setup resources, load state, etc.
        tracing::info!("YourPlugin initialized");
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        // Cleanup resources, save state, etc.
        tracing::info!("YourPlugin shutting down");
        Ok(())
    }
}
```

### Step 3: Implement Packet Handlers

```rust
impl YourPlugin {
    async fn handle_request(&mut self, packet: &Packet) -> Result<()> {
        // Parse request
        let request_type = packet
            .get_body_field::<String>("requestType")
            .unwrap_or_default();

        tracing::debug!("Received request: {}", request_type);

        // Process request
        self.counter += 1;

        // Create response packet
        let response = Packet::new(
            "kdeconnect.yourplugin.response",
            json!({
                "requestType": request_type,
                "counter": self.counter,
            }),
        );

        // Emit response via callback or return
        // (Implementation depends on architecture)

        Ok(())
    }

    async fn handle_data(&mut self, packet: &Packet) -> Result<()> {
        // Extract data from packet
        let message = packet
            .get_body_field::<String>("message")
            .unwrap_or_default();

        // Update state
        self.last_message = Some(message.clone());
        self.counter += 1;

        tracing::info!("Received message: {}", message);

        Ok(())
    }

    // Public methods for platform code
    pub fn get_counter(&self) -> u64 {
        self.counter
    }

    pub fn get_last_message(&self) -> Option<String> {
        self.last_message.clone()
    }

    pub fn create_data_packet(&self, message: &str) -> Packet {
        Packet::new(
            "kdeconnect.yourplugin",
            json!({
                "message": message,
                "timestamp": chrono::Utc::now().timestamp_millis(),
            }),
        )
    }
}
```

### Step 4: Register Plugin

Add to `src/plugins/mod.rs`:

```rust
pub mod your_plugin;

pub use your_plugin::YourPlugin;
```

### Step 5: Add to Plugin Manager

In `src/plugins/manager.rs`:

```rust
impl PluginManager {
    pub fn register_your_plugin(&mut self) -> Result<()> {
        let plugin = Box::new(YourPlugin::new());
        self.register_plugin(plugin)
    }
}
```

## Plugin Patterns

### State Management

```rust
pub struct StatefulPlugin {
    // Immutable configuration
    device_id: String,

    // Mutable state
    is_active: bool,
    message_count: u64,
    last_update: i64,

    // Cached data
    cache: HashMap<String, String>,
}

impl StatefulPlugin {
    // State query methods
    pub fn is_active(&self) -> bool {
        self.is_active
    }

    pub fn get_message_count(&self) -> u64 {
        self.message_count
    }

    // State mutation methods
    fn update_state(&mut self, active: bool) {
        self.is_active = active;
        self.last_update = chrono::Utc::now().timestamp_millis();
    }
}
```

### Capability-Based Routing

```rust
fn incoming_capabilities(&self) -> Vec<String> {
    vec![
        // Base capability
        "kdeconnect.myplugin".to_string(),

        // Action-specific capabilities
        "kdeconnect.myplugin.request".to_string(),
        "kdeconnect.myplugin.update".to_string(),
        "kdeconnect.myplugin.delete".to_string(),
    ]
}

async fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
    match packet.packet_type.as_str() {
        "kdeconnect.myplugin.request" => self.handle_request(packet).await,
        "kdeconnect.myplugin.update" => self.handle_update(packet).await,
        "kdeconnect.myplugin.delete" => self.handle_delete(packet).await,
        _ => self.handle_default(packet).await,
    }
}
```

### Builder Pattern for Packets

```rust
impl MyPlugin {
    pub fn build_status_packet(&self) -> Packet {
        Packet::new("kdeconnect.myplugin", json!({}))
            .with_body_field("status", "active")
            .with_body_field("count", self.counter)
            .with_body_field("timestamp", current_timestamp())
    }

    pub fn build_request_packet(&self, request_type: &str) -> Packet {
        Packet::new("kdeconnect.myplugin.request", json!({}))
            .with_body_field("requestType", request_type)
            .with_body_field("deviceId", &self.device_id)
    }
}
```

### Error Handling

```rust
async fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
    // Validate packet structure
    let message = packet
        .get_body_field::<String>("message")
        .ok_or_else(|| {
            ProtocolError::InvalidPacket("Missing 'message' field".to_string())
        })?;

    // Validate data
    if message.is_empty() {
        return Err(ProtocolError::InvalidPacket(
            "Empty message not allowed".to_string()
        ));
    }

    // Process with error handling
    match self.process_message(&message).await {
        Ok(()) => {
            tracing::debug!("Message processed successfully");
            Ok(())
        }
        Err(e) => {
            tracing::error!("Failed to process message: {}", e);
            Err(ProtocolError::plugin(format!("Processing failed: {}", e)))
        }
    }
}
```

## Built-in Plugin Examples

### Ping Plugin

Simple plugin for connectivity testing:

```rust
pub struct PingPlugin {
    name: String,
    pings_received: u64,
    pings_sent: u64,
    last_ping_time: Option<i64>,
}

#[async_trait]
impl Plugin for PingPlugin {
    fn name(&self) -> &str {
        "ping"
    }

    fn incoming_capabilities(&self) -> Vec<String> {
        vec!["kdeconnect.ping".to_string()]
    }

    fn outgoing_capabilities(&self) -> Vec<String> {
        vec!["kdeconnect.ping".to_string()]
    }

    async fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
        if packet.is_type("kdeconnect.ping") {
            self.pings_received += 1;
            self.last_ping_time = Some(packet.id);

            let message = packet.get_body_field::<String>("message");
            tracing::info!("Ping received: {:?}", message);
        }
        Ok(())
    }

    async fn initialize(&mut self) -> Result<()> {
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }
}

impl PingPlugin {
    pub fn create_ping(&mut self, message: Option<String>) -> Packet {
        self.pings_sent += 1;

        let mut body = json!({});
        if let Some(msg) = message {
            body["message"] = json!(msg);
        }

        Packet::new("kdeconnect.ping", body)
    }

    pub fn get_stats(&self) -> (u64, u64) {
        (self.pings_received, self.pings_sent)
    }
}
```

### Battery Plugin

Plugin with bidirectional state sync:

```rust
#[derive(Debug, Clone)]
pub struct BatteryState {
    pub is_charging: bool,
    pub current_charge: i32,
    pub threshold_event: i32,
}

pub struct BatteryPlugin {
    name: String,
    local_battery: Option<BatteryState>,
    remote_battery: Option<BatteryState>,
}

#[async_trait]
impl Plugin for BatteryPlugin {
    fn name(&self) -> &str {
        "battery"
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
                self.handle_battery_update(packet).await
            }
            "kdeconnect.battery.request" => {
                self.handle_battery_request(packet).await
            }
            _ => Ok(()),
        }
    }

    async fn initialize(&mut self) -> Result<()> {
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }
}

impl BatteryPlugin {
    async fn handle_battery_update(&mut self, packet: &Packet) -> Result<()> {
        let state = BatteryState {
            is_charging: packet.get_body_field("isCharging").unwrap_or(false),
            current_charge: packet.get_body_field("currentCharge").unwrap_or(0),
            threshold_event: packet.get_body_field("thresholdEvent").unwrap_or(0),
        };

        self.remote_battery = Some(state);
        tracing::info!("Remote battery updated: {}%", self.remote_battery.as_ref().unwrap().current_charge);

        Ok(())
    }

    async fn handle_battery_request(&mut self, _packet: &Packet) -> Result<()> {
        // Send local battery state if available
        if let Some(state) = &self.local_battery {
            tracing::debug!("Battery state requested, would send: {}%", state.current_charge);
            // In real implementation, send packet via connection
        }
        Ok(())
    }

    pub fn update_local_battery(&mut self, state: BatteryState) {
        self.local_battery = Some(state);
    }

    pub fn get_remote_battery(&self) -> Option<BatteryState> {
        self.remote_battery.clone()
    }

    pub fn create_battery_packet(&self, state: &BatteryState) -> Packet {
        Packet::new(
            "kdeconnect.battery",
            json!({
                "isCharging": state.is_charging,
                "currentCharge": state.current_charge,
                "thresholdEvent": state.threshold_event,
            }),
        )
    }
}
```

## Testing Plugins

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_plugin_initialization() {
        let mut plugin = YourPlugin::new();
        let result = plugin.initialize().await;
        assert!(result.is_ok());
        assert_eq!(plugin.counter, 0);
    }

    #[tokio::test]
    async fn test_handle_request() {
        let mut plugin = YourPlugin::new();
        plugin.initialize().await.unwrap();

        let packet = Packet::new(
            "kdeconnect.yourplugin.request",
            json!({ "requestType": "test" }),
        );

        let result = plugin.handle_packet(&packet).await;
        assert!(result.is_ok());
        assert_eq!(plugin.counter, 1);
    }

    #[test]
    fn test_capabilities() {
        let plugin = YourPlugin::new();

        let incoming = plugin.incoming_capabilities();
        assert!(incoming.contains(&"kdeconnect.yourplugin".to_string()));

        let outgoing = plugin.outgoing_capabilities();
        assert!(outgoing.contains(&"kdeconnect.yourplugin.response".to_string()));
    }

    #[test]
    fn test_packet_creation() {
        let plugin = YourPlugin::new();
        let packet = plugin.create_data_packet("test message");

        assert_eq!(packet.packet_type, "kdeconnect.yourplugin");
        assert_eq!(
            packet.get_body_field::<String>("message"),
            Some("test message".to_string())
        );
    }
}
```

### Integration Tests

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_plugin_in_manager() {
        let mut manager = PluginManager::new();
        manager.register_your_plugin().unwrap();

        assert!(manager.has_plugin("your_plugin"));

        let capabilities = manager.get_capabilities();
        assert!(capabilities.incoming.contains(&"kdeconnect.yourplugin".to_string()));
    }

    #[tokio::test]
    async fn test_packet_routing() {
        let mut manager = PluginManager::new();
        manager.register_your_plugin().unwrap();

        let packet = Packet::new(
            "kdeconnect.yourplugin",
            json!({ "message": "test" }),
        );

        let result = manager.route_packet(packet).await;
        assert!(result.is_ok());
    }
}
```

## FFI Integration

### Exposing Plugin Functions

Add to `src/ffi/mod.rs`:

```rust
impl PluginManager {
    pub fn your_plugin_get_counter(&self) -> u64 {
        if let Some(plugin) = self.get_plugin("your_plugin") {
            if let Some(your_plugin) = plugin.downcast_ref::<YourPlugin>() {
                return your_plugin.get_counter();
            }
        }
        0
    }

    pub fn your_plugin_send_message(&mut self, message: String) -> Result<FfiPacket> {
        if let Some(plugin) = self.get_plugin_mut("your_plugin") {
            if let Some(your_plugin) = plugin.downcast_mut::<YourPlugin>() {
                let packet = your_plugin.create_data_packet(&message);
                return Ok(packet.into());
            }
        }
        Err(ProtocolError::plugin("YourPlugin not found"))
    }
}
```

### UDL Definitions

Add to `src/cosmic_connect_core.udl`:

```
interface PluginManager {
    // ... existing methods ...

    /// Get counter from YourPlugin
    u64 your_plugin_get_counter();

    /// Send message via YourPlugin
    [Throws=ProtocolError]
    FfiPacket your_plugin_send_message(string message);
}
```

## Best Practices

### 1. State Management

- Keep plugin state minimal
- Use immutable data where possible
- Document state transitions
- Provide query methods for state

### 2. Error Handling

- Validate all packet fields
- Return descriptive errors
- Log errors with context
- Don't panic in packet handlers

### 3. Capabilities

- List all packet types handled
- Keep capabilities specific
- Document capability purpose
- Update identity packet

### 4. Testing

- Test initialization and shutdown
- Test packet handling
- Test error conditions
- Test state transitions

### 5. Documentation

- Document packet formats
- Explain state management
- Provide usage examples
- Note platform requirements

## Common Pitfalls

### 1. Blocking Operations

**Wrong:**
```rust
async fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
    std::thread::sleep(Duration::from_secs(5)); // Blocks entire runtime!
    Ok(())
}
```

**Right:**
```rust
async fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
    tokio::time::sleep(Duration::from_secs(5)).await; // Async sleep
    Ok(())
}
```

### 2. Shared Mutable State

**Wrong:**
```rust
static mut COUNTER: u64 = 0; // Unsafe!

async fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
    unsafe { COUNTER += 1; }
    Ok(())
}
```

**Right:**
```rust
struct MyPlugin {
    counter: u64, // Plugin owns its state
}

async fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
    self.counter += 1;
    Ok(())
}
```

### 3. Missing Error Handling

**Wrong:**
```rust
async fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
    let value = packet.get_body_field::<i32>("value").unwrap(); // May panic!
    self.process(value);
    Ok(())
}
```

**Right:**
```rust
async fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
    let value = packet
        .get_body_field::<i32>("value")
        .ok_or_else(|| ProtocolError::InvalidPacket("Missing value".to_string()))?;
    self.process(value)?;
    Ok(())
}
```

## References

- Plugin Trait: `src/plugins/trait.rs`
- Plugin Manager: `src/plugins/manager.rs`
- Example Plugins: `src/plugins/ping.rs`, `src/plugins/battery.rs`
- Protocol Documentation: `docs/Protocol.md`
