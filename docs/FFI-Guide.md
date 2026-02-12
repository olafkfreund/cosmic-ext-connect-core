# FFI Development Guide

## Overview

`cosmic-ext-connect-core` uses [UniFFI](https://mozilla.github.io/uniffi-rs/) to generate Foreign Function Interface (FFI) bindings for Kotlin (Android) and Swift (iOS). This guide covers FFI architecture, type mappings, and cross-platform development.

## UniFFI Architecture

### Build Process

```
┌─────────────────────────────────────┐
│   cosmic_ext_connect_core.udl           │
│   (Interface Definition)            │
└─────────────────┬───────────────────┘
                  │
                  ↓
┌─────────────────────────────────────┐
│   build.rs                          │
│   uniffi::generate_scaffolding()    │
└─────────────────┬───────────────────┘
                  │
                  ↓
┌─────────────────────────────────────┐
│   Generated Rust Scaffolding        │
│   (Included via macro)              │
└─────────────────┬───────────────────┘
                  │
                  ↓
┌─────────────────────────────────────┐
│   Compiled Rust Library             │
│   libcosmic_ext_connect_core.so/.dylib  │
└─────────────────┬───────────────────┘
                  │
                  ↓
┌─────────────────────────────────────┐
│   uniffi-bindgen CLI Tool           │
│   Generate Platform Bindings        │
└─────────────────┬───────────────────┘
           ┌──────┴──────┐
           ↓             ↓
┌──────────────┐  ┌──────────────┐
│   Kotlin     │  │   Swift      │
│   Bindings   │  │   Bindings   │
└──────────────┘  └──────────────┘
```

### Key Files

- **`src/cosmic_ext_connect_core.udl`**: Interface definition (hand-written)
- **`build.rs`**: Build script that generates scaffolding
- **`src/lib.rs`**: Includes generated scaffolding via macro
- **`src/ffi/mod.rs`**: FFI-specific Rust implementations

## UDL Syntax

### Namespace Declaration

```
namespace cosmic_ext_connect_core {
    // Top-level functions go here
    void initialize(string log_level);
    string get_version();
}
```

### Functions

```
// Simple function
string get_version();

// Function with error handling
[Throws=ProtocolError]
void initialize(string log_level);

// Function with multiple parameters
[Throws=ProtocolError]
FfiPacket create_packet(string packet_type, string body);
```

### Data Types

#### Dictionaries (Structs)

```
dictionary FfiPacket {
    i64 id;
    string packet_type;
    string body;
    i64? payload_size;  // Optional field
}
```

#### Enums (Error Types)

```
[Error]
enum ProtocolError {
    "Io",
    "Json",
    "InvalidPacket",
    "Network",
    // ... more variants
}
```

#### Interfaces (Objects with Methods)

```
interface DiscoveryService {
    [Throws=ProtocolError]
    void stop();

    sequence<FfiDeviceInfo> get_devices();

    boolean is_running();
}
```

#### Callbacks (Platform → Rust)

```
callback interface DiscoveryCallback {
    void on_device_found(FfiDeviceInfo device);
    void on_device_lost(string device_id);
}
```

#### Enums (Tagged Unions)

```
[Enum]
interface DiscoveryEvent {
    DeviceFound(FfiDeviceInfo device);
    DeviceLost(string device_id);
    IdentityReceived(string device_id, FfiPacket packet);
}
```

## Type Mappings

### Primitive Types

| UDL Type | Rust Type | Kotlin Type | Swift Type |
|----------|-----------|-------------|------------|
| boolean  | bool      | Boolean     | Bool       |
| i8       | i8        | Byte        | Int8       |
| i16      | i16       | Short       | Int16      |
| i32      | i32       | Int         | Int32      |
| i64      | i64       | Long        | Int64      |
| u8       | u8        | UByte       | UInt8      |
| u16      | u16       | UShort      | UInt16     |
| u32      | u32       | UInt        | UInt32     |
| u64      | u64       | ULong       | UInt64     |
| f32      | f32       | Float       | Float      |
| f64      | f64       | Double      | Double     |
| string   | String    | String      | String     |

### Collection Types

| UDL Type       | Rust Type      | Kotlin Type  | Swift Type |
|----------------|----------------|--------------|------------|
| sequence<T>    | Vec<T>         | List<T>      | [T]        |
| bytes          | Vec<u8>        | ByteArray    | Data       |

### Optional Types

| UDL Type | Rust Type   | Kotlin Type | Swift Type |
|----------|-------------|-------------|------------|
| T?       | Option<T>   | T?          | T?         |

### Custom Types

UDL dictionaries and interfaces map to:
- **Kotlin**: Data classes and interfaces
- **Swift**: Structs and protocols

## Implementing FFI Types

### Rust Side

#### Converting Internal Types to FFI Types

```rust
// Internal Rust type
pub struct Packet {
    pub id: i64,
    pub packet_type: String,
    pub body: Value,
    pub payload_size: Option<i64>,
}

// FFI type (simplified)
pub struct FfiPacket {
    pub id: i64,
    pub packet_type: String,
    pub body: String, // JSON string instead of Value
    pub payload_size: Option<i64>,
}

// Conversion
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
        Ok(Self {
            id: ffi.id,
            packet_type: ffi.packet_type,
            body: serde_json::from_str(&ffi.body)?,
            payload_size: ffi.payload_size,
        })
    }
}
```

#### Implementing Top-Level Functions

```rust
// In src/ffi/mod.rs or src/lib.rs

pub fn initialize(log_level: String) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .init();
    Ok(())
}

pub fn get_version() -> String {
    VERSION.to_string()
}

pub fn create_packet(packet_type: String, body: String) -> Result<FfiPacket> {
    let body_value: Value = serde_json::from_str(&body)?;
    let packet = Packet::new(packet_type, body_value);
    Ok(packet.into())
}
```

#### Implementing Interfaces

```rust
pub struct DiscoveryService {
    inner: Arc<Mutex<InternalDiscoveryService>>,
}

impl DiscoveryService {
    pub fn new(device_info: FfiDeviceInfo, callback: Box<dyn DiscoveryCallback>) -> Result<Self> {
        let inner = InternalDiscoveryService::new(device_info.into(), callback)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    pub fn stop(&self) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.stop()
    }

    pub fn get_devices(&self) -> Vec<FfiDeviceInfo> {
        let inner = self.inner.lock().unwrap();
        inner.get_devices()
            .into_iter()
            .map(|d| d.into())
            .collect()
    }

    pub fn is_running(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.is_running()
    }
}
```

#### Implementing Callbacks

```rust
// Define callback trait
pub trait DiscoveryCallback: Send + Sync {
    fn on_device_found(&self, device: FfiDeviceInfo);
    fn on_device_lost(&self, device_id: String);
}

// Use in Rust code
fn notify_device_found(callback: &dyn DiscoveryCallback, device: DeviceInfo) {
    callback.on_device_found(device.into());
}
```

### Kotlin Side (Android)

#### Using Top-Level Functions

```kotlin
import uniffi.cosmic_ext_connect_core.*

// Initialize library
CosmicConnectCore.initialize("info")

// Get version
val version = CosmicConnectCore.getVersion()
println("Library version: $version")

// Create packet
val packet = CosmicConnectCore.createPacket(
    packetType = "kdeconnect.ping",
    body = """{"message": "Hello"}"""
)
```

#### Using Interfaces

```kotlin
class MyDiscoveryCallback : DiscoveryCallback {
    override fun onDeviceFound(device: FfiDeviceInfo) {
        println("Found device: ${device.deviceName}")
        // Update UI on main thread
        runOnUiThread {
            adapter.addDevice(device)
        }
    }

    override fun onDeviceLost(deviceId: String) {
        println("Lost device: $deviceId")
        runOnUiThread {
            adapter.removeDevice(deviceId)
        }
    }
}

// Create discovery service
val deviceInfo = FfiDeviceInfo(
    deviceId = "android_device_123",
    deviceName = "My Android Phone",
    deviceType = "phone",
    protocolVersion = 7,
    incomingCapabilities = listOf("kdeconnect.ping"),
    outgoingCapabilities = listOf("kdeconnect.ping"),
    tcpPort = 1716u
)

val callback = MyDiscoveryCallback()
val discovery = CosmicConnectCore.startDiscovery(deviceInfo, callback)

// Use discovery service
val devices = discovery.getDevices()
val isRunning = discovery.isRunning()

// Cleanup
discovery.stop()
```

#### Error Handling

```kotlin
try {
    val packet = CosmicConnectCore.createPacket(
        packetType = "kdeconnect.ping",
        body = "invalid json"
    )
} catch (e: ProtocolException.Json) {
    Log.e(TAG, "JSON error: ${e.message}")
} catch (e: ProtocolException.InvalidPacket) {
    Log.e(TAG, "Invalid packet: ${e.message}")
} catch (e: ProtocolException) {
    Log.e(TAG, "Protocol error: ${e.message}")
}
```

### Swift Side (iOS)

#### Using Top-Level Functions

```swift
import cosmic_ext_connect_core

// Initialize library
try? initialize(logLevel: "info")

// Get version
let version = getVersion()
print("Library version: \(version)")

// Create packet
let packet = try createPacket(
    packetType: "kdeconnect.ping",
    body: #"{"message": "Hello"}"#
)
```

#### Using Interfaces

```swift
class MyDiscoveryCallback: DiscoveryCallback {
    func onDeviceFound(device: FfiDeviceInfo) {
        print("Found device: \(device.deviceName)")
        DispatchQueue.main.async {
            // Update UI
        }
    }

    func onDeviceLost(deviceId: String) {
        print("Lost device: \(deviceId)")
        DispatchQueue.main.async {
            // Update UI
        }
    }
}

// Create discovery service
let deviceInfo = FfiDeviceInfo(
    deviceId: "ios_device_123",
    deviceName: "My iPhone",
    deviceType: "phone",
    protocolVersion: 7,
    incomingCapabilities: ["kdeconnect.ping"],
    outgoingCapabilities: ["kdeconnect.ping"],
    tcpPort: 1716
)

let callback = MyDiscoveryCallback()
let discovery = try startDiscovery(localDevice: deviceInfo, callback: callback)

// Use discovery service
let devices = discovery.getDevices()
let isRunning = discovery.isRunning()

// Cleanup
try discovery.stop()
```

#### Error Handling

```swift
do {
    let packet = try createPacket(
        packetType: "kdeconnect.ping",
        body: "invalid json"
    )
} catch ProtocolError.Json(let message) {
    print("JSON error: \(message)")
} catch ProtocolError.InvalidPacket(let message) {
    print("Invalid packet: \(message)")
} catch {
    print("Protocol error: \(error)")
}
```

## Generating Bindings

### For Kotlin (Android)

```bash
# Generate Kotlin bindings
cargo run --bin uniffi-bindgen generate \
    src/cosmic_ext_connect_core.udl \
    --language kotlin \
    --out-dir ./bindings/kotlin

# Output files:
# - bindings/kotlin/uniffi/cosmic_ext_connect_core/cosmic_ext_connect_core.kt
```

### For Swift (iOS)

```bash
# Generate Swift bindings
cargo run --bin uniffi-bindgen generate \
    src/cosmic_ext_connect_core.udl \
    --language swift \
    --out-dir ./bindings/swift

# Output files:
# - bindings/swift/cosmic_ext_connect_core.swift
# - bindings/swift/cosmic_ext_connect_coreFFI.h
# - bindings/swift/cosmic_ext_connect_coreFFI.modulemap
```

### Integrating into Projects

#### Android (Kotlin)

1. Build Rust library for Android targets:
```bash
cargo build --target aarch64-linux-android --release
cargo build --target armv7-linux-androideabi --release
cargo build --target i686-linux-android --release
cargo build --target x86_64-linux-android --release
```

2. Copy native libraries to Android project:
```
android/app/src/main/jniLibs/
├── arm64-v8a/
│   └── libcosmic_ext_connect_core.so
├── armeabi-v7a/
│   └── libcosmic_ext_connect_core.so
├── x86/
│   └── libcosmic_ext_connect_core.so
└── x86_64/
    └── libcosmic_ext_connect_core.so
```

3. Copy Kotlin bindings:
```
android/app/src/main/kotlin/uniffi/cosmic_ext_connect_core/
└── cosmic_ext_connect_core.kt
```

4. Load library in Kotlin:
```kotlin
init {
    System.loadLibrary("cosmic_ext_connect_core")
}
```

#### iOS (Swift)

1. Build Rust library for iOS targets:
```bash
cargo build --target aarch64-apple-ios --release
cargo build --target x86_64-apple-ios --release
```

2. Create XCFramework:
```bash
xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libcosmic_ext_connect_core.a \
    -library target/x86_64-apple-ios/release/libcosmic_ext_connect_core.a \
    -output CosmicConnectCore.xcframework
```

3. Add to Xcode project and import Swift bindings

## Best Practices

### 1. Keep FFI Types Simple

**Good:**
```
dictionary FfiPacket {
    i64 id;
    string packet_type;
    string body;  // JSON string
}
```

**Avoid:**
```
dictionary FfiPacket {
    i64 id;
    string packet_type;
    ComplexNestedType body;  // Complex nested structures
}
```

### 2. Use JSON for Complex Data

Instead of defining many nested UDL types, serialize complex data as JSON strings:

```rust
pub fn get_device_info() -> String {
    let info = ComplexDeviceInfo { /* ... */ };
    serde_json::to_string(&info).unwrap()
}
```

### 3. Handle Errors Properly

Define FFI-friendly error types:

```
[Error]
enum ProtocolError {
    "Io",
    "Network",
    "InvalidPacket",
}
```

Convert internal errors to FFI errors:

```rust
impl From<std::io::Error> for ProtocolError {
    fn from(e: std::io::Error) -> Self {
        ProtocolError::Io(e.to_string())
    }
}
```

### 4. Use Callbacks for Events

For asynchronous events, use callback interfaces:

```
callback interface EventCallback {
    void on_event(string event_type, string data);
}
```

### 5. Thread Safety

UniFFI objects are not automatically thread-safe. Use `Arc<Mutex<T>>` for shared state:

```rust
pub struct MyService {
    inner: Arc<Mutex<InternalService>>,
}
```

### 6. Memory Management

UniFFI handles memory management automatically:
- Rust objects are freed when platform references are dropped
- Don't manually manage memory
- Trust UniFFI's reference counting

## Testing FFI

### Unit Tests

Test FFI conversions:

```rust
#[test]
fn test_packet_conversion() {
    let packet = Packet::new("kdeconnect.ping", json!({}));
    let ffi: FfiPacket = packet.clone().into();
    let converted: Packet = ffi.try_into().unwrap();
    assert_eq!(packet.packet_type, converted.packet_type);
}
```

### Integration Tests

Test from platform code:

**Kotlin:**
```kotlin
@Test
fun testPacketCreation() {
    val packet = CosmicConnectCore.createPacket(
        "kdeconnect.ping",
        "{}"
    )
    assertEquals("kdeconnect.ping", packet.packetType)
}
```

**Swift:**
```swift
func testPacketCreation() throws {
    let packet = try createPacket(
        packetType: "kdeconnect.ping",
        body: "{}"
    )
    XCTAssertEqual(packet.packetType, "kdeconnect.ping")
}
```

## Common Issues

### Issue: Type Not Exposed

**Problem:** Rust type not available in platform code

**Solution:** Add to UDL file:
```
dictionary MyType {
    string field;
}
```

### Issue: Callback Not Working

**Problem:** Callback not receiving events

**Solution:** Ensure callback is kept alive and not dropped:

```kotlin
class MyActivity : AppCompatActivity() {
    private val callback = MyCallback() // Keep reference

    override fun onCreate(savedInstanceState: Bundle?) {
        service.setCallback(callback)
    }
}
```

### Issue: Thread Panic

**Problem:** Rust panics on wrong thread

**Solution:** Use `Arc<Mutex<T>>` for thread-safe access:

```rust
pub struct MyService {
    inner: Arc<Mutex<InternalService>>,
}
```

### Issue: Build Failures

**Problem:** UniFFI scaffolding generation fails

**Solution:**
1. Check UDL syntax
2. Ensure all types are defined
3. Verify build.rs is correct
4. Clean and rebuild: `cargo clean && cargo build`

## References

- UniFFI Documentation: https://mozilla.github.io/uniffi-rs/
- UniFFI Examples: https://github.com/mozilla/uniffi-rs/tree/main/examples
- Android JNI Guide: https://developer.android.com/training/articles/perf-jni
- iOS Swift Interop: https://developer.apple.com/documentation/swift/imported_c_and_objective-c_apis
