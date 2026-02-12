# cosmic-ext-connect-core

KDE Connect protocol implementation in Rust - shared library for COSMIC Connect Android and COSMIC Desktop.

## Overview

`cosmic-ext-connect-core` is a pure Rust implementation of the KDE Connect protocol v7, designed for cross-platform use via Foreign Function Interface (FFI). This library powers both the COSMIC Connect Android app (Kotlin) and COSMIC Desktop applet (Rust).

### Key Features

- **KDE Connect Protocol v7**: Complete implementation with JSON packets
- **Cross-Platform**: Works on Android, Linux, and COSMIC Desktop
- **FFI Ready**: uniffi-rs bindings for Kotlin and Swift
- **Modern Rust**: async/await with tokio, rustls for TLS
- **Zero OpenSSL**: Uses rustls for better Android cross-compilation
- **Plugin System**: Extensible plugin architecture

## Architecture

```
cosmic-ext-connect-core/
├── src/
│   ├── protocol/     # NetworkPacket, Device, Identity
│   ├── network/      # Discovery (UDP), TCP/TLS transport
│   ├── crypto/       # Certificate management, TLS config
│   ├── plugins/      # Plugin trait and implementations
│   ├── ffi/          # uniffi-rs bindings
│   ├── error.rs      # Error types
│   └── lib.rs        # Library entry point
├── Cargo.toml
└── build.rs          # uniffi code generation
```

### Modules

- **protocol**: Core protocol types (NetworkPacket, Device, Identity)
- **network**: Network layer (UDP Discovery, TCP transport, TLS)
- **crypto**: Cryptography (rustls TLS, certificate management)
- **plugins**: Plugin system and implementations (ping, battery, share, etc.)
- **ffi**: Foreign Function Interface for Kotlin/Swift

## Usage

### Rust

```rust
use cosmic_ext_connect_core::protocol::Packet;
use serde_json::json;

// Create a packet
let packet = Packet::new("kdeconnect.ping", json!({}));

// Serialize with newline terminator (KDE Connect protocol requirement)
let bytes = packet.to_bytes()?;
assert_eq!(bytes.last(), Some(&b'\n'));
```

### Kotlin (Android)

```kotlin
import uniffi.cosmic_ext_connect_core.*

// Discover devices
val discovery = DiscoveryService.start()
discovery.onDeviceFound { device ->
    println("Found: ${device.name}")
}

// Send packet
val packet = Packet("kdeconnect.ping", "{}")
device.send(packet)
```

## Development Status

**Phase 0: Rust Core Extraction** (Current)

This project is actively being developed as part of the COSMIC Connect hybrid architecture initiative. We're extracting the protocol implementation from the COSMIC Desktop applet into this shared library.

### Completed

- [x] Project structure and module organization
- [x] Cargo configuration with rustls and uniffi
- [x] Error type system (ProtocolError)
- [x] Module stub files

### In Progress

- [ ] Extract NetworkPacket from applet (Issue #45)
- [ ] Extract Discovery service (Issue #46)
- [ ] Rewrite TLS transport with rustls (Issue #47)
- [ ] Create certificate generation with rcgen (Issue #48)
- [ ] Design unified Plugin trait (Issue #49)
- [ ] Create uniffi FFI bindings (Issue #50)

## Building

### Prerequisites

- Rust 1.70 or later
- cargo

### Build Commands

```bash
# Build the library
cargo build

# Run tests
cargo test

# Build release version
cargo build --release

# Generate uniffi bindings (Kotlin)
cargo run --bin uniffi-bindgen generate src/cosmic_ext_connect_core.udl --language kotlin --out-dir ./bindings/kotlin

# Generate uniffi bindings (Swift)
cargo run --bin uniffi-bindgen generate src/cosmic_ext_connect_core.udl --language swift --out-dir ./bindings/swift
```

## Cross-Compilation for Android

```bash
# Install Android NDK targets
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add i686-linux-android
rustup target add x86_64-linux-android

# Build for Android
cargo build --target aarch64-linux-android --release
```

## Testing

```bash
# Run all tests
cargo test

# Run specific module tests
cargo test --package cosmic-ext-connect-core --lib protocol::tests

# Run with logging
RUST_LOG=debug cargo test
```

## Contributing

This project is part of the COSMIC Connect initiative. Contributions are welcome!

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is dual-licensed under:

- GNU General Public License v2.0 or later (GPL-2.0-or-later)
- GNU General Public License v3.0 or later (GPL-3.0-or-later)

See [LICENSE](LICENSE) for details.

## Related Projects

- **cosmic-connect-android**: Android app (Kotlin + this library)
- **cosmic-applet-kdeconnect**: COSMIC Desktop applet (Rust + this library)
- **kdeconnect-kde**: Original KDE Connect implementation

## Protocol Compatibility

This library implements KDE Connect protocol version 7, ensuring compatibility with:

- KDE Connect on Linux, Windows, macOS
- GSConnect on GNOME
- Other KDE Connect implementations

## Documentation

Comprehensive documentation is available in the `/docs` directory:

- **[Architecture](docs/Architecture.md)** - System design and architecture
- **[Protocol](docs/Protocol.md)** - KDE Connect protocol specification
- **[Plugin Development](docs/Plugin-Development.md)** - Creating custom plugins
- **[FFI Guide](docs/FFI-Guide.md)** - Cross-platform FFI development
- **[Testing](docs/Testing.md)** - Testing strategies and tools
- **[Contributing](docs/Contributing.md)** - How to contribute

See [docs/README.md](docs/README.md) for the complete documentation index.

## Resources

- [KDE Connect Protocol Documentation](https://invent.kde.org/network/kdeconnect-kde)
- [COSMIC Desktop](https://github.com/pop-os/cosmic-epoch)
- [uniffi-rs Documentation](https://mozilla.github.io/uniffi-rs/)
- [rustls Documentation](https://docs.rs/rustls/)

## Support

For issues and questions:

- File an issue on GitHub
- Check existing documentation in `/docs`
- Review the COSMIC Connect architecture document

---

**Status**: Alpha - Active Development

**Version**: 0.1.0-alpha

**Maintainer**: Olaf Kfreund <olafkfreund@gmail.com>
