# Testing Guide

## Overview

This guide covers testing strategies, practices, and tools for `cosmic-ext-connect-core`. Comprehensive testing ensures protocol compliance, reliability, and cross-platform compatibility.

## Testing Philosophy

### Test Pyramid

```
        ┌─────────────┐
        │   Manual    │  Compatibility testing with real devices
        │   Testing   │
        └─────────────┘
       ┌───────────────┐
       │  Integration  │  Full packet flow, plugin system
       │    Tests      │
       └───────────────┘
    ┌────────────────────┐
    │    Unit Tests      │  Individual functions, packet parsing
    └────────────────────┘
```

### Testing Principles

1. **Test Behavior, Not Implementation**
   - Focus on public API contracts
   - Avoid testing internal details
   - Test observable outcomes

2. **Isolation**
   - Each test should be independent
   - No shared mutable state
   - Clean setup and teardown

3. **Coverage**
   - Aim for high coverage of critical paths
   - Test error conditions
   - Test edge cases

4. **Fast Feedback**
   - Unit tests run in milliseconds
   - Integration tests under 1 second each
   - Full suite under 30 seconds

## Test Organization

### Directory Structure

```
src/
├── protocol/
│   ├── mod.rs
│   ├── packet.rs
│   └── tests/           # Protocol unit tests
│       └── packet_tests.rs
├── network/
│   ├── mod.rs
│   ├── discovery/
│   │   ├── mod.rs
│   │   └── tests/       # Network unit tests
│   └── transport.rs
└── plugins/
    ├── mod.rs
    ├── ping.rs
    └── tests/           # Plugin unit tests
        └── ping_tests.rs

tests/
├── integration/
│   ├── discovery_test.rs
│   ├── plugin_routing_test.rs
│   └── packet_flow_test.rs
└── compatibility/
    └── kdeconnect_test.rs
```

### Test Location

**In-Module Tests (`#[cfg(test)]`):**
- Located in same file as code
- Test private functions
- Test implementation details

**Separate Test Modules:**
- Located in `tests/` directory
- Test public API only
- Integration tests
- Compatibility tests

## Unit Testing

### Basic Structure

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_functionality() {
        // Arrange
        let input = create_test_input();

        // Act
        let result = function_under_test(input);

        // Assert
        assert_eq!(result, expected_value);
    }
}
```

### Testing Packet Serialization

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_packet_serialization() {
        let packet = Packet::new(
            "kdeconnect.ping",
            json!({ "message": "test" }),
        );

        let bytes = packet.to_bytes().unwrap();

        // Verify newline terminator
        assert_eq!(bytes.last(), Some(&b'\n'));

        // Verify valid JSON
        let json_str = String::from_utf8(bytes).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed.is_object());
    }

    #[test]
    fn test_packet_deserialization() {
        let json_data = r#"{"id":123,"type":"kdeconnect.ping","body":{}}"#;
        let packet = Packet::from_bytes(json_data.as_bytes()).unwrap();

        assert_eq!(packet.id, 123);
        assert_eq!(packet.packet_type, "kdeconnect.ping");
    }

    #[test]
    fn test_packet_roundtrip() {
        let original = Packet::new(
            "kdeconnect.battery",
            json!({
                "isCharging": true,
                "currentCharge": 85,
            }),
        );

        let bytes = original.to_bytes().unwrap();
        let parsed = Packet::from_bytes(&bytes).unwrap();

        assert_eq!(original.packet_type, parsed.packet_type);
        assert_eq!(original.body, parsed.body);
    }
}
```

### Testing Error Conditions

```rust
#[test]
fn test_invalid_packet() {
    let invalid_json = b"not json data";
    let result = Packet::from_bytes(invalid_json);

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ProtocolError::InvalidPacket(_)));
}

#[test]
fn test_missing_required_field() {
    let packet_missing_type = r#"{"id":123,"body":{}}"#;
    let result = Packet::from_bytes(packet_missing_type.as_bytes());

    assert!(result.is_err());
}

#[test]
#[should_panic(expected = "Device name cannot be empty")]
fn test_invalid_device_name() {
    DeviceInfo::new("", DeviceType::Desktop, 1716);
}
```

### Testing Async Code

```rust
#[tokio::test]
async fn test_async_function() {
    let service = DiscoveryService::new(device_info).await.unwrap();

    let result = service.start().await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_async_plugin_lifecycle() {
    let mut plugin = PingPlugin::new();

    // Initialize
    plugin.initialize().await.unwrap();

    // Handle packet
    let packet = Packet::new("kdeconnect.ping", json!({}));
    let result = plugin.handle_packet(&packet).await;
    assert!(result.is_ok());

    // Shutdown
    plugin.shutdown().await.unwrap();
}
```

### Property-Based Testing

Using `proptest` for property-based testing:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_packet_id_always_positive(id in 0i64..i64::MAX) {
        let packet = Packet::with_id(id, "kdeconnect.ping", json!({}));
        assert!(packet.id > 0);
    }

    #[test]
    fn test_packet_roundtrip_any_string(
        packet_type in "[a-z.]+",
        message in ".*"
    ) {
        let original = Packet::new(
            packet_type,
            json!({ "message": message }),
        );

        let bytes = original.to_bytes().unwrap();
        let parsed = Packet::from_bytes(&bytes).unwrap();

        prop_assert_eq!(original.packet_type, parsed.packet_type);
    }
}
```

## Integration Testing

### Discovery Integration Test

```rust
// tests/integration/discovery_test.rs

use cosmic_ext_connect_core::discovery::{DeviceInfo, DeviceType, Discovery};
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_discovery_bidirectional() {
    // Create two devices
    let device1 = DeviceInfo::new("Device1", DeviceType::Desktop, 1716);
    let device2 = DeviceInfo::new("Device2", DeviceType::Phone, 1717);

    let discovery1 = Discovery::new(device1.clone()).unwrap();
    let discovery2 = Discovery::new(device2.clone()).unwrap();

    // Device 1 broadcasts
    discovery1.broadcast_identity().unwrap();

    // Device 2 should discover Device 1
    let result = timeout(
        Duration::from_secs(5),
        discovery2.listen_for_devices()
    ).await;

    assert!(result.is_ok());
    let (discovered_device, _addr) = result.unwrap().unwrap();
    assert_eq!(discovered_device.device_id, device1.device_id);
}
```

### Plugin Manager Integration Test

```rust
// tests/integration/plugin_routing_test.rs

use cosmic_ext_connect_core::plugins::{PluginManager, PingPlugin};
use cosmic_ext_connect_core::protocol::Packet;
use serde_json::json;

#[tokio::test]
async fn test_plugin_routing() {
    let mut manager = PluginManager::new();

    // Register ping plugin
    let ping_plugin = Box::new(PingPlugin::new());
    manager.register_plugin(ping_plugin).unwrap();

    // Create ping packet
    let packet = Packet::new("kdeconnect.ping", json!({}));

    // Route packet
    let result = manager.route_packet(packet).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_multiple_plugins() {
    let mut manager = PluginManager::new();

    // Register multiple plugins
    manager.register_plugin(Box::new(PingPlugin::new())).unwrap();
    manager.register_plugin(Box::new(BatteryPlugin::new())).unwrap();

    // Verify capabilities
    let capabilities = manager.get_capabilities();
    assert!(capabilities.incoming.contains(&"kdeconnect.ping".to_string()));
    assert!(capabilities.incoming.contains(&"kdeconnect.battery".to_string()));
}
```

### Full Packet Flow Test

```rust
// tests/integration/packet_flow_test.rs

#[tokio::test]
async fn test_end_to_end_packet_flow() {
    // Setup
    let device1 = create_test_device("Device1");
    let device2 = create_test_device("Device2");

    let mut service1 = setup_service(device1).await;
    let mut service2 = setup_service(device2).await;

    // Start discovery
    service1.start().await.unwrap();
    service2.start().await.unwrap();

    // Wait for discovery
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Create and send packet
    let packet = Packet::new("kdeconnect.ping", json!({}));
    service1.send_packet(packet).await.unwrap();

    // Verify receipt
    let received = timeout(
        Duration::from_secs(2),
        service2.receive_packet()
    ).await;

    assert!(received.is_ok());
    let packet = received.unwrap().unwrap();
    assert_eq!(packet.packet_type, "kdeconnect.ping");

    // Cleanup
    service1.stop().await.unwrap();
    service2.stop().await.unwrap();
}
```

## Mocking

### Mock Network Socket

```rust
use std::sync::mpsc::{channel, Sender, Receiver};

struct MockSocket {
    send_buffer: Sender<Vec<u8>>,
    recv_buffer: Receiver<Vec<u8>>,
}

impl MockSocket {
    fn new() -> (Self, Receiver<Vec<u8>>, Sender<Vec<u8>>) {
        let (tx_send, rx_send) = channel();
        let (tx_recv, rx_recv) = channel();

        (
            Self {
                send_buffer: tx_send,
                recv_buffer: rx_recv,
            },
            rx_send,
            tx_recv,
        )
    }

    fn send(&self, data: Vec<u8>) -> Result<()> {
        self.send_buffer.send(data).unwrap();
        Ok(())
    }

    fn recv(&self) -> Result<Vec<u8>> {
        self.recv_buffer.recv()
            .map_err(|_| ProtocolError::network("Receive failed"))
    }
}

#[test]
fn test_with_mock_socket() {
    let (socket, sent_data, inject_data) = MockSocket::new();

    // Send data through mock
    socket.send(vec![1, 2, 3]).unwrap();

    // Verify it was sent
    let received = sent_data.recv().unwrap();
    assert_eq!(received, vec![1, 2, 3]);
}
```

### Mock Plugin

```rust
struct MockPlugin {
    name: String,
    packets_received: Vec<Packet>,
}

impl MockPlugin {
    fn new() -> Self {
        Self {
            name: "mock".to_string(),
            packets_received: Vec::new(),
        }
    }

    fn received_count(&self) -> usize {
        self.packets_received.len()
    }
}

#[async_trait]
impl Plugin for MockPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn incoming_capabilities(&self) -> Vec<String> {
        vec!["kdeconnect.test".to_string()]
    }

    fn outgoing_capabilities(&self) -> Vec<String> {
        vec![]
    }

    async fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
        self.packets_received.push(packet.clone());
        Ok(())
    }

    async fn initialize(&mut self) -> Result<()> { Ok(()) }
    async fn shutdown(&mut self) -> Result<()> { Ok(()) }
}

#[tokio::test]
async fn test_with_mock_plugin() {
    let mut manager = PluginManager::new();
    let mock = Box::new(MockPlugin::new());
    manager.register_plugin(mock).unwrap();

    // Send test packet
    let packet = Packet::new("kdeconnect.test", json!({}));
    manager.route_packet(packet).await.unwrap();

    // Verify mock received it
    let mock = manager.get_plugin("mock").unwrap();
    assert_eq!(mock.downcast_ref::<MockPlugin>().unwrap().received_count(), 1);
}
```

## Benchmarking

### Criterion Benchmarks

```rust
// benches/packet_benchmark.rs

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cosmic_ext_connect_core::protocol::Packet;
use serde_json::json;

fn benchmark_packet_serialization(c: &mut Criterion) {
    let packet = Packet::new(
        "kdeconnect.ping",
        json!({ "message": "benchmark" }),
    );

    c.bench_function("packet_serialization", |b| {
        b.iter(|| {
            black_box(packet.to_bytes()).unwrap()
        })
    });
}

fn benchmark_packet_deserialization(c: &mut Criterion) {
    let data = r#"{"id":123,"type":"kdeconnect.ping","body":{}}"#;

    c.bench_function("packet_deserialization", |b| {
        b.iter(|| {
            black_box(Packet::from_bytes(data.as_bytes())).unwrap()
        })
    });
}

criterion_group!(benches, benchmark_packet_serialization, benchmark_packet_deserialization);
criterion_main!(benches);
```

Run benchmarks:
```bash
cargo bench
```

## Compatibility Testing

### Testing Against Real KDE Connect

```rust
// tests/compatibility/kdeconnect_test.rs

#[tokio::test]
#[ignore] // Only run with --ignored flag
async fn test_discover_real_kdeconnect() {
    let device_info = DeviceInfo::new("Test Device", DeviceType::Desktop, 1716);
    let mut service = DiscoveryService::with_defaults(device_info).unwrap();

    let mut events = service.subscribe().await;
    service.start().await.unwrap();

    // Wait for discovery (30 seconds)
    let timeout_future = tokio::time::timeout(
        Duration::from_secs(30),
        events.recv()
    );

    match timeout_future.await {
        Ok(Some(event)) => {
            println!("Discovered: {:?}", event);
        }
        Ok(None) => panic!("Discovery service closed"),
        Err(_) => panic!("Timeout: No KDE Connect device found"),
    }
}
```

Run compatibility tests:
```bash
cargo test --ignored
```

## Test Utilities

### Test Fixtures

```rust
// tests/common/mod.rs

pub fn create_test_device(name: &str) -> DeviceInfo {
    DeviceInfo::new(name, DeviceType::Desktop, 1716)
        .with_incoming_capability("kdeconnect.ping")
        .with_outgoing_capability("kdeconnect.ping")
}

pub fn create_test_packet(packet_type: &str) -> Packet {
    Packet::new(packet_type, json!({}))
}

pub fn create_identity_packet(device: &DeviceInfo) -> Packet {
    device.to_identity_packet()
}
```

### Test Helpers

```rust
pub async fn wait_for_condition<F>(condition: F, timeout_secs: u64) -> bool
where
    F: Fn() -> bool,
{
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    loop {
        if condition() {
            return true;
        }

        if start.elapsed() > timeout {
            return false;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn test_with_helper() {
    let mut counter = 0;

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        counter = 10;
    });

    let success = wait_for_condition(|| counter == 10, 5).await;
    assert!(success);
}
```

## CI/CD Integration

### GitHub Actions Workflow

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - name: Run tests
        run: cargo test --all-features
      - name: Run clippy
        run: cargo clippy -- -D warnings
      - name: Check formatting
        run: cargo fmt -- --check

  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install tarpaulin
        run: cargo install cargo-tarpaulin
      - name: Generate coverage
        run: cargo tarpaulin --out Xml
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

## Best Practices

### 1. Test Naming

Use descriptive names that explain what is tested:

```rust
#[test]
fn test_packet_serialization_includes_newline_terminator() { }

#[test]
fn test_discovery_filters_own_broadcasts() { }

#[test]
fn test_plugin_manager_routes_to_correct_plugin() { }
```

### 2. Arrange-Act-Assert Pattern

```rust
#[test]
fn test_example() {
    // Arrange: Setup test data
    let input = create_test_input();

    // Act: Execute function under test
    let result = function_under_test(input);

    // Assert: Verify expected outcome
    assert_eq!(result, expected);
}
```

### 3. One Assertion Per Test

Each test should verify one specific behavior:

```rust
// Good
#[test]
fn test_packet_has_correct_type() {
    let packet = Packet::new("kdeconnect.ping", json!({}));
    assert_eq!(packet.packet_type, "kdeconnect.ping");
}

#[test]
fn test_packet_has_positive_id() {
    let packet = Packet::new("kdeconnect.ping", json!({}));
    assert!(packet.id > 0);
}

// Avoid
#[test]
fn test_packet_properties() {
    let packet = Packet::new("kdeconnect.ping", json!({}));
    assert_eq!(packet.packet_type, "kdeconnect.ping");
    assert!(packet.id > 0);
    assert!(packet.body.is_object());
}
```

### 4. Test Independence

Tests should not depend on each other:

```rust
// Bad: Tests depend on execution order
static mut COUNTER: i32 = 0;

#[test]
fn test_first() {
    unsafe { COUNTER = 1; }
}

#[test]
fn test_second() {
    unsafe { assert_eq!(COUNTER, 1); } // Fails if run alone
}

// Good: Each test is independent
#[test]
fn test_first() {
    let counter = 1;
    assert_eq!(counter, 1);
}

#[test]
fn test_second() {
    let counter = 2;
    assert_eq!(counter, 2);
}
```

### 5. Fast Tests

Keep tests fast by avoiding:
- Real network I/O (use mocks)
- Long timeouts (use short test timeouts)
- Expensive computations (test with small data)

## Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_packet_serialization

# Run tests in specific module
cargo test --package cosmic-ext-connect-core --lib protocol::tests

# Run with output
cargo test -- --nocapture

# Run with logging
RUST_LOG=debug cargo test

# Run integration tests only
cargo test --test '*'

# Run benchmarks
cargo bench

# Run ignored tests (compatibility)
cargo test -- --ignored

# Run tests with coverage
cargo tarpaulin --out Html
```

## References

- Rust Testing Guide: https://doc.rust-lang.org/book/ch11-00-testing.html
- Tokio Testing: https://tokio.rs/tokio/topics/testing
- Criterion Benchmarking: https://github.com/bheisler/criterion.rs
- Property Testing: https://github.com/proptest-rs/proptest
