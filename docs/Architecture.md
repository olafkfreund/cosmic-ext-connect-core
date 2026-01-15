# Architecture Documentation

## Overview

`cosmic-connect-core` is a layered Rust library implementing the KDE Connect protocol v7. The architecture is designed for cross-platform use via Foreign Function Interface (FFI), with clear separation between protocol logic (Rust core) and platform-specific implementation (Kotlin/Swift).

## Design Principles

### 1. Separation of Concerns

**Rust Core Responsibilities:**
- Protocol packet handling and serialization
- Network discovery and communication
- Cryptographic operations (TLS, certificates)
- Business logic and state management
- Plugin system and routing

**Platform Code Responsibilities:**
- User interface rendering
- System API integration (notifications, permissions, file access)
- Platform-specific features (Android intents, iOS extensions)
- Native UI components

### 2. FFI-First Design

The library is designed with FFI as a first-class concern:
- All public APIs are FFI-compatible
- Types are defined in `.udl` for cross-language use
- Error handling uses FFI-safe enums
- Callbacks for platform-to-Rust communication

### 3. Async-First Architecture

Built on `tokio` runtime:
- Non-blocking I/O for network operations
- Async plugin lifecycle
- Event-driven discovery service
- Concurrent packet handling

## Layer Architecture

```
┌─────────────────────────────────────────────────┐
│          Platform Layer (Kotlin/Swift)          │
│  UI, System APIs, Platform-Specific Features    │
└─────────────────────────────────────────────────┘
                       ↕ FFI
┌─────────────────────────────────────────────────┐
│              FFI Layer (UniFFI)                  │
│  Type Conversions, Callbacks, Scaffolding       │
└─────────────────────────────────────────────────┘
                       ↕
┌─────────────────────────────────────────────────┐
│            Plugin Layer (plugins/)               │
│  Plugin Trait, Manager, Implementations         │
└─────────────────────────────────────────────────┘
                       ↕
┌─────────────────────────────────────────────────┐
│           Network Layer (network/)               │
│  Discovery Service, TCP Transport, TLS          │
└─────────────────────────────────────────────────┘
                       ↕
┌─────────────────────────────────────────────────┐
│          Crypto Layer (crypto/)                  │
│  Certificate Management, TLS Configuration      │
└─────────────────────────────────────────────────┘
                       ↕
┌─────────────────────────────────────────────────┐
│         Protocol Layer (protocol/)               │
│  Packet Structure, Serialization, Device Info   │
└─────────────────────────────────────────────────┘
```

## Module Details

### Protocol Layer (`src/protocol/`)

**Purpose:** Core protocol types and serialization

**Key Components:**
- `Packet`: Network packet structure with JSON body
- `DeviceInfo`: Identity information for discovery
- Serialization/deserialization with newline terminators
- Timestamp generation for packet IDs

**Design Decisions:**
- Packets use UNIX millisecond timestamps as IDs
- JSON serialization with mandatory `\n` terminator
- Flexible ID parsing (string or number) for compatibility
- Builder pattern for packet construction

### Network Layer (`src/network/`)

**Purpose:** Network communication and device discovery

**Key Components:**
- `Discovery`: Synchronous UDP broadcast (for testing)
- `DiscoveryService`: Async UDP discovery with event system
- `TcpTransport`: TCP connection handling (future)
- `TlsTransport`: TLS-secured communication (future)

**Discovery Protocol:**
1. Bind to UDP port 1716 (with fallback to 1717-1764)
2. Broadcast identity packet to 255.255.255.255:1716
3. Listen for identity packets from other devices
4. Track device presence with timeout mechanism
5. Emit events: DeviceFound, DeviceLost, IdentityReceived

**Design Decisions:**
- Port fallback range to handle conflicts
- Event-based async architecture
- Separate broadcast and listen loops
- Self-packet filtering by device ID

### Crypto Layer (`src/crypto/`)

**Purpose:** TLS and certificate management

**Key Components:**
- `Certificate`: Self-signed X.509 certificate generation
- `TlsConfig`: rustls configuration builder
- Fingerprint calculation (SHA-256)
- PEM encoding/decoding

**Why rustls:**
- No C dependencies (pure Rust)
- Better Android cross-compilation
- Modern TLS implementation
- No OpenSSL version conflicts

**Certificate Requirements:**
- Self-signed X.509 certificates
- Subject name matches device ID
- SHA-256 fingerprints for verification
- Generated via `rcgen` crate

### Plugin Layer (`src/plugins/`)

**Purpose:** Extensible plugin architecture

**Key Components:**
- `Plugin` trait: Lifecycle and packet handling
- `PluginManager`: Registration and routing
- Built-in plugins: `ping`, `battery`, `share`
- `PluginMetadata`: Display information

**Plugin Lifecycle:**
```
Constructor → Registration → Initialize → [Handle Packets] → Shutdown
```

**Design Decisions:**
- Trait-based for extensibility
- Async methods for I/O operations
- Capability-based routing
- Platform-agnostic business logic

### FFI Layer (`src/ffi/`)

**Purpose:** Cross-language interface

**Key Components:**
- UDL definitions in `cosmic_connect_core.udl`
- Type conversions (Rust ↔ Kotlin/Swift)
- Callback interfaces for platform events
- Top-level functions for library operations

**Type Mapping:**
```
Rust              UniFFI UDL       Kotlin           Swift
---------------------------------------------------------------
String            string           String           String
i64               i64              Long             Int64
Vec<T>            sequence<T>      List<T>          [T]
Vec<u8>           bytes            ByteArray        Data
HashMap           dictionary       data class       struct
Result<T, E>      [Throws=E]       throws           throws
```

**Build Process:**
1. `build.rs` runs during compilation
2. Reads `cosmic_connect_core.udl`
3. Generates Rust scaffolding code
4. Includes scaffolding via macro
5. Platform bindings generated separately

## Data Flow

### Packet Reception Flow

```
UDP Socket
    ↓
Network Layer (recv_from)
    ↓
Packet::from_bytes()
    ↓
DeviceInfo::from_identity_packet()
    ↓
DiscoveryService (event emission)
    ↓
Platform Callback (on_device_found)
    ↓
Platform UI Update
```

### Packet Sending Flow

```
Platform Code
    ↓
FFI Function (create_packet)
    ↓
Packet::new()
    ↓
Packet::to_bytes()
    ↓
Network Layer (send_to)
    ↓
UDP Socket
```

### Plugin Packet Routing

```
Received Packet
    ↓
PluginManager::route_packet()
    ↓
Check packet type against capabilities
    ↓
Plugin::handle_packet()
    ↓
Plugin updates state
    ↓
Emit callback to platform
    ↓
Platform updates UI
```

## Concurrency Model

### Async Runtime

- Uses `tokio` for async I/O
- Single runtime instance
- Async plugin trait methods
- Non-blocking network operations

### Thread Safety

- All types are `Send + Sync`
- Mutex-protected shared state
- Channel-based event passing
- No global mutable state

### Event System

```rust
// Discovery events via channels
let (tx, rx) = tokio::sync::mpsc::channel();

// Broadcast loop
tokio::spawn(async move {
    loop {
        broadcast_identity().await;
        sleep(INTERVAL).await;
    }
});

// Listen loop
tokio::spawn(async move {
    loop {
        let device = listen_for_devices().await;
        tx.send(DiscoveryEvent::DeviceFound(device)).await;
    }
});
```

## Error Handling Strategy

### Error Types

```rust
pub enum ProtocolError {
    Io(io::Error),           // System I/O errors
    Json(serde_json::Error), // Serialization errors
    InvalidPacket(String),   // Protocol violations
    Network(String),         // Network failures
    Tls(String),            // TLS handshake errors
    Certificate(String),     // Certificate issues
    Discovery(String),       // Discovery failures
    Plugin(String),         // Plugin errors
    Timeout,                // Operation timeouts
    // ... more variants
}
```

### Error Propagation

- `Result<T>` return types everywhere
- `?` operator for propagation
- FFI-safe error conversion
- Platform receives exceptions

### Error Recovery

- Automatic port fallback in discovery
- Timeout-based device cleanup
- Plugin initialization failures logged
- Graceful degradation of features

## State Management

### Discovery State

- Tracked in `DiscoveryService`
- Map of `device_id → DeviceInfo`
- Last-seen timestamps
- Automatic timeout cleanup

### Plugin State

- Each plugin manages own state
- Encapsulated in plugin struct
- No shared mutable state between plugins
- State updates via `&mut self` methods

### Connection State

- TLS sessions (future implementation)
- Paired device list
- Certificate trust store
- Connection pool

## Performance Considerations

### Memory Management

- Zero-copy packet parsing where possible
- Buffer pooling for network I/O
- Lazy initialization of plugins
- Efficient JSON serialization

### Network Optimization

- UDP broadcast with rate limiting
- TCP connection pooling (future)
- TLS session resumption (future)
- Packet batching for bulk transfers

### FFI Overhead

- Minimal type conversions
- Callback batching where appropriate
- Avoid frequent FFI boundary crossings
- Cache frequently accessed data

## Security Architecture

### TLS Security

- rustls with modern cipher suites
- Certificate pinning via fingerprints
- Self-signed certificates for device trust
- No weak protocols (SSLv3, TLS 1.0/1.1)

### Input Validation

- Packet size limits
- JSON structure validation
- Device ID format checking
- Capability whitelist enforcement

### Access Control

- Pairing required before data transfer
- Per-plugin permission model
- Device trust database
- Certificate verification

## Testing Strategy

### Unit Tests

- In-module tests via `#[cfg(test)]`
- Mock network operations
- Test each layer independently
- Property-based testing for serialization

### Integration Tests

- Full packet flow end-to-end
- Real UDP socket communication
- Plugin manager with multiple plugins
- FFI boundary testing

### Compatibility Tests

- Test against real KDE Connect devices
- Verify interoperability with other implementations
- Protocol version compatibility
- Edge case packet formats

## Future Architecture Enhancements

### Planned Additions

1. **TCP Transport Layer**
   - Connection pooling
   - Automatic reconnection
   - Heartbeat mechanism

2. **TLS Integration**
   - Complete handshake flow
   - Certificate exchange
   - Session management

3. **Plugin Discovery**
   - Dynamic plugin loading
   - Plugin versioning
   - Dependency resolution

4. **State Persistence**
   - Device pairing database
   - Plugin configuration storage
   - Certificate trust store

5. **Advanced Features**
   - File transfer support
   - Payload streaming
   - Multicast optimization
   - IPv6 support

## References

- KDE Connect Protocol: https://invent.kde.org/network/kdeconnect-kde
- Valent Protocol Reference: https://valent.andyholmes.ca/documentation/protocol.html
- UniFFI Documentation: https://mozilla.github.io/uniffi-rs/
- rustls Documentation: https://docs.rs/rustls/
