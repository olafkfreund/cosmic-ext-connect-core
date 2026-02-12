# Documentation

Welcome to the `cosmic-ext-connect-core` documentation. This directory contains comprehensive guides covering all aspects of the project.

## Documentation Index

### Core Documentation

- **[Architecture.md](Architecture.md)** - System architecture and design
  - Layer structure and responsibilities
  - Module organization
  - Concurrency model
  - Data flow diagrams
  - Performance considerations
  - Security architecture

- **[Protocol.md](Protocol.md)** - KDE Connect protocol specification
  - Protocol version 7 details
  - Packet format and structure
  - Discovery protocol
  - Pairing workflow
  - Plugin packet formats
  - Compatibility notes

### Development Guides

- **[Plugin-Development.md](Plugin-Development.md)** - Creating custom plugins
  - Plugin trait implementation
  - State management patterns
  - Packet handling
  - Built-in plugin examples
  - FFI integration
  - Best practices

- **[FFI-Guide.md](FFI-Guide.md)** - Cross-platform FFI development
  - UniFFI architecture
  - Type mappings (Rust ↔ Kotlin/Swift)
  - UDL syntax reference
  - Platform integration
  - Callback interfaces
  - Troubleshooting

- **[Testing.md](Testing.md)** - Testing strategies and tools
  - Unit testing patterns
  - Integration testing
  - Mocking and fixtures
  - Benchmarking
  - Compatibility testing
  - CI/CD integration

- **[Contributing.md](Contributing.md)** - How to contribute
  - Development workflow
  - Coding standards
  - Pull request process
  - Testing requirements
  - Documentation standards

## Quick Start

### For New Contributors

1. Read [Contributing.md](Contributing.md) for development setup
2. Review [Architecture.md](Architecture.md) to understand the system
3. Check [Protocol.md](Protocol.md) for protocol details
4. Follow [Testing.md](Testing.md) for testing guidelines

### For Plugin Developers

1. Start with [Plugin-Development.md](Plugin-Development.md)
2. Review [Protocol.md](Protocol.md) for packet formats
3. Check [FFI-Guide.md](FFI-Guide.md) if exposing via FFI
4. Add tests following [Testing.md](Testing.md)

### For Platform Developers (Android/iOS)

1. Read [FFI-Guide.md](FFI-Guide.md) for platform integration
2. Review [Protocol.md](Protocol.md) for protocol understanding
3. Check [Architecture.md](Architecture.md) for system design
4. See [Plugin-Development.md](Plugin-Development.md) for available plugins

## Documentation Standards

All documentation follows these principles:

- **Clear and Concise**: Easy to understand for developers of all levels
- **Practical Examples**: Code examples for every concept
- **Up-to-Date**: Updated with code changes
- **Complete**: Covers both happy path and edge cases
- **Searchable**: Well-organized with clear headings

## Updating Documentation

When making code changes, please update relevant documentation:

- Protocol changes → Update `Protocol.md`
- Architecture changes → Update `Architecture.md`
- New plugins → Update `Plugin-Development.md`
- FFI changes → Update `FFI-Guide.md`
- New testing patterns → Update `Testing.md`

## Additional Resources

### External Documentation

- [KDE Connect Protocol](https://invent.kde.org/network/kdeconnect-kde)
- [Valent Protocol Reference](https://valent.andyholmes.ca/documentation/protocol.html)
- [UniFFI Documentation](https://mozilla.github.io/uniffi-rs/)
- [rustls Documentation](https://docs.rs/rustls/)
- [COSMIC Desktop](https://github.com/pop-os/cosmic-epoch)

### Project Files

- `../CLAUDE.md` - AI assistant guidance for development
- `../README.md` - Project overview and quick start
- `../Cargo.toml` - Dependencies and project metadata

## Getting Help

If you can't find what you're looking for:

1. Check if your question is answered in existing docs
2. Search GitHub issues for similar questions
3. Open a new issue with the "question" label
4. Reference the relevant documentation in your issue

## Contributing to Documentation

Documentation improvements are always welcome:

1. Fix typos or unclear explanations
2. Add missing examples
3. Improve diagrams or visualizations
4. Update outdated information
5. Add new guides for common tasks

See [Contributing.md](Contributing.md) for the contribution process.

## Documentation Maintenance

Documentation is maintained by:
- Core maintainers
- Community contributors
- Automated checks for broken links
- Regular reviews for accuracy

Last major update: 2026-01-15

---

Thank you for reading the documentation. Happy coding!
