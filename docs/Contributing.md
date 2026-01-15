# Contributing Guide

## Welcome

Thank you for your interest in contributing to `cosmic-connect-core`! This project is part of the COSMIC Connect initiative and welcomes contributions from the community.

## Getting Started

### Prerequisites

- Rust 1.70 or later
- cargo
- Git
- Basic understanding of the KDE Connect protocol
- (Optional) Android NDK for cross-compilation

### Setting Up Development Environment

1. **Clone the repository**
```bash
git clone https://github.com/olafkfreund/cosmic-connect-core.git
cd cosmic-connect-core
```

2. **Build the project**
```bash
cargo build
```

3. **Run tests**
```bash
cargo test
```

4. **Install development tools**
```bash
# Clippy for linting
rustup component add clippy

# Rustfmt for formatting
rustup component add rustfmt

# Cargo-watch for auto-rebuild
cargo install cargo-watch
```

### Project Structure

```
cosmic-connect-core/
├── src/
│   ├── protocol/        # Core protocol types
│   ├── network/         # Network and discovery
│   ├── crypto/          # TLS and certificates
│   ├── plugins/         # Plugin system
│   ├── ffi/            # Foreign function interface
│   ├── error.rs        # Error types
│   └── lib.rs          # Library entry point
├── tests/              # Integration tests
├── docs/               # Documentation
├── build.rs            # Build script
├── Cargo.toml          # Dependencies
└── CLAUDE.md           # AI assistant guide
```

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

Branch naming conventions:
- `feature/` - New features
- `fix/` - Bug fixes
- `refactor/` - Code refactoring
- `docs/` - Documentation updates
- `test/` - Test additions or fixes

### 2. Make Your Changes

Follow the coding standards (see below) and ensure:
- Code compiles without warnings
- All tests pass
- New functionality has tests
- Documentation is updated

### 3. Test Your Changes

```bash
# Run all tests
cargo test

# Run clippy
cargo clippy -- -D warnings

# Check formatting
cargo fmt -- --check

# Run specific tests
cargo test test_your_feature
```

### 4. Commit Your Changes

Write clear, descriptive commit messages:

```bash
git add .
git commit -m "Add support for XYZ feature

- Implement XYZ functionality in module ABC
- Add tests for XYZ
- Update documentation

Closes #123"
```

Commit message format:
- First line: Brief summary (50 chars or less)
- Blank line
- Detailed description (wrap at 72 chars)
- Reference related issues

### 5. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Create a pull request on GitHub with:
- Clear description of changes
- Reference to related issues
- Screenshots/examples if applicable
- Checklist of completed items

## Coding Standards

### Rust Style Guide

Follow the [Rust Style Guide](https://doc.rust-lang.org/stable/style-guide/) and project conventions:

#### Naming Conventions

```rust
// Modules: snake_case
mod network_discovery;

// Types: PascalCase
struct NetworkPacket;
enum DeviceType;
trait Plugin;

// Functions/methods: snake_case
fn parse_packet() { }
fn get_device_info() { }

// Constants: SCREAMING_SNAKE_CASE
const MAX_PACKET_SIZE: usize = 4096;
const DISCOVERY_PORT: u16 = 1716;

// Lifetimes: short lowercase
fn process<'a>(data: &'a str) { }
```

#### Code Organization

```rust
// Order of items in a file:
// 1. Module documentation
// 2. Imports
// 3. Constants
// 4. Type definitions
// 5. Implementations
// 6. Private helpers
// 7. Tests

//! Module documentation

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

const DEFAULT_PORT: u16 = 1716;

#[derive(Debug, Clone)]
pub struct MyType {
    field: String,
}

impl MyType {
    pub fn new(field: String) -> Self {
        Self { field }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_my_type() { }
}
```

#### Error Handling

```rust
// Use Result types
fn parse_data(input: &str) -> Result<Data> {
    // Validate input
    if input.is_empty() {
        return Err(ProtocolError::InvalidPacket(
            "Empty input".to_string()
        ));
    }

    // Use ? operator for propagation
    let parsed = serde_json::from_str(input)?;

    Ok(parsed)
}

// Avoid unwrap() in library code
// Good
let value = optional.ok_or_else(|| {
    ProtocolError::InvalidPacket("Missing value".to_string())
})?;

// Bad
let value = optional.unwrap();
```

#### Documentation

All public items must have documentation:

```rust
/// Creates a new network packet.
///
/// # Arguments
///
/// * `packet_type` - The packet type identifier
/// * `body` - JSON body of the packet
///
/// # Examples
///
/// ```
/// use cosmic_connect_core::protocol::Packet;
/// use serde_json::json;
///
/// let packet = Packet::new("kdeconnect.ping", json!({}));
/// ```
pub fn new(packet_type: impl Into<String>, body: Value) -> Self {
    // Implementation
}
```

#### Testing

Write tests for all new functionality:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_case() {
        let result = function_under_test();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_error_case() {
        let result = function_that_fails();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_async_function() {
        let result = async_function().await;
        assert!(result.is_ok());
    }
}
```

### Code Formatting

Use `rustfmt` for consistent formatting:

```bash
# Format all code
cargo fmt

# Check formatting
cargo fmt -- --check
```

Configuration in `rustfmt.toml` (if present) or use defaults.

### Linting

Use `clippy` to catch common mistakes:

```bash
# Run clippy
cargo clippy

# Deny warnings
cargo clippy -- -D warnings
```

Common clippy lints to follow:
- Avoid unnecessary clones
- Use `if let` for single pattern matching
- Prefer `?` over `try!`
- Avoid excessive nesting

## Pull Request Process

### Before Submitting

Checklist:
- [ ] Code compiles without warnings
- [ ] All tests pass
- [ ] New tests added for new functionality
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (if applicable)
- [ ] Code formatted with `rustfmt`
- [ ] Clippy checks pass
- [ ] Commit messages are clear

### PR Description Template

```markdown
## Description
Brief description of the changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Related Issues
Closes #123

## Changes Made
- Change 1
- Change 2
- Change 3

## Testing
Describe the tests you ran to verify your changes.

## Checklist
- [ ] Tests pass
- [ ] Documentation updated
- [ ] Code formatted
- [ ] Clippy checks pass
```

### Review Process

1. **Automated Checks**
   - CI/CD pipeline runs tests
   - Code coverage is checked
   - Linting is verified

2. **Code Review**
   - Maintainers review the code
   - Feedback is provided
   - Discussions happen in PR comments

3. **Approval and Merge**
   - PR must be approved by maintainer
   - All discussions resolved
   - CI checks must pass
   - Squash or merge commits

## Types of Contributions

### Bug Fixes

1. Check if the bug is already reported
2. Create an issue if not exists
3. Reference the issue in your PR
4. Add regression tests

Example:
```rust
// Before: Bug in packet parsing
let id = packet.id.parse::<i64>().unwrap(); // Panics on invalid

// After: Proper error handling
let id = packet.id.parse::<i64>()
    .map_err(|_| ProtocolError::InvalidPacket("Invalid ID".to_string()))?;
```

### New Features

1. Discuss the feature in an issue first
2. Get approval from maintainers
3. Follow the plugin development guide
4. Add comprehensive tests
5. Update documentation

Example: Adding a new plugin
```bash
# Create plugin file
touch src/plugins/my_plugin.rs

# Implement Plugin trait
# Add tests
# Update mod.rs
# Add FFI bindings if needed
# Update documentation
```

### Documentation

Documentation improvements are always welcome:
- Fix typos
- Clarify explanations
- Add examples
- Improve diagrams
- Update outdated information

### Refactoring

1. Ensure behavior doesn't change
2. Keep PRs focused and small
3. Maintain or improve test coverage
4. Update documentation if needed

## Architecture Guidelines

### Adding a New Module

1. Create module directory: `src/new_module/`
2. Add `mod.rs` with public interface
3. Implement functionality in separate files
4. Add tests in `tests/` subdirectory
5. Update `src/lib.rs` to expose module
6. Document in `docs/Architecture.md`

### Adding a New Plugin

Follow the Plugin Development Guide:

1. Create `src/plugins/my_plugin.rs`
2. Implement `Plugin` trait
3. Add to `src/plugins/mod.rs`
4. Register in `PluginManager`
5. Add FFI bindings if needed
6. Write tests
7. Update documentation

### Modifying the Protocol

Protocol changes must:
- Maintain backward compatibility
- Follow KDE Connect protocol spec
- Update protocol documentation
- Add compatibility tests
- Get approval from maintainers

## Testing Requirements

All contributions must include appropriate tests:

### Unit Tests
```rust
#[test]
fn test_new_feature() {
    // Test implementation
}
```

### Integration Tests
```rust
#[tokio::test]
async fn test_feature_integration() {
    // Test end-to-end flow
}
```

### Documentation Tests
```rust
/// # Examples
///
/// ```
/// use cosmic_connect_core::MyType;
///
/// let instance = MyType::new();
/// assert_eq!(instance.value(), 42);
/// ```
```

## Documentation Standards

### Code Documentation

Use rustdoc format:
```rust
/// Short description (one line).
///
/// Longer description with details about the function,
/// its behavior, and any important notes.
///
/// # Arguments
///
/// * `param1` - Description of param1
/// * `param2` - Description of param2
///
/// # Returns
///
/// Description of return value
///
/// # Errors
///
/// This function will return an error if:
/// - Condition 1
/// - Condition 2
///
/// # Examples
///
/// ```
/// use cosmic_connect_core::example;
///
/// let result = example(42, "test");
/// assert_eq!(result, expected);
/// ```
pub fn example(param1: i32, param2: &str) -> Result<Type> {
    // Implementation
}
```

### Documentation Files

Update relevant documentation:
- `README.md` - Project overview
- `CLAUDE.md` - AI assistant guidance
- `docs/Architecture.md` - Architecture changes
- `docs/Protocol.md` - Protocol details
- `docs/Plugin-Development.md` - Plugin guides
- `docs/FFI-Guide.md` - FFI information
- `docs/Testing.md` - Testing strategies

## Communication

### Issues

- Use issue templates if available
- Provide clear reproduction steps for bugs
- Include system information
- Search for duplicates before creating

### Discussions

- Be respectful and constructive
- Stay on topic
- Provide context and examples
- Reference relevant documentation

### Code Reviews

- Be respectful and professional
- Explain reasoning behind suggestions
- Focus on code, not people
- Acknowledge good work

## License

By contributing, you agree that your contributions will be licensed under the project's dual license (GPL-2.0-or-later OR GPL-3.0-or-later).

## Questions?

- Open a GitHub issue for questions
- Check existing documentation
- Review CLAUDE.md for development guidance
- Ask in pull request discussions

## Recognition

Contributors are recognized in:
- Git history
- Release notes
- Project acknowledgments

Thank you for contributing to cosmic-connect-core!
