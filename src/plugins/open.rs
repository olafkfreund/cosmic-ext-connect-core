//! Open Plugin (App Continuity)
//!
//! Enables app continuity by opening content (URLs, files, text) on remote devices.
//! Allows sharing links, triggering file opens, and cross-device content handoff.
//!
//! ## Protocol
//!
//! **Packet Types**:
//! - Incoming: `cconnect.open.request`, `cconnect.open.capability`
//! - Outgoing: `cconnect.open.request`, `cconnect.open.response`, `cconnect.open.capability`
//!
//! **Capabilities**: `cconnect.open`
//!
//! ## Open Request
//!
//! Request to open content on a remote device:
//!
//! ```json
//! {
//!     "id": 1234567890,
//!     "type": "cconnect.open.request",
//!     "body": {
//!         "requestId": "uuid-string",
//!         "contentType": "url",
//!         "url": "https://example.com",
//!         "mimeType": "text/html",
//!         "title": "Example Page"
//!     }
//! }
//! ```
//!
//! ## Open Response
//!
//! Response after attempting to open content:
//!
//! ```json
//! {
//!     "id": 1234567890,
//!     "type": "cconnect.open.response",
//!     "body": {
//!         "requestId": "uuid-string",
//!         "success": true,
//!         "openedWith": "Firefox"
//!     }
//! }
//! ```
//!
//! ## Capability Announcement
//!
//! Advertise what content types this device can open:
//!
//! ```json
//! {
//!     "id": 1234567890,
//!     "type": "cconnect.open.capability",
//!     "body": {
//!         "supportedSchemes": ["http", "https", "mailto", "tel"],
//!         "maxFileSize": 104857600,
//!         "supportedMimeTypes": ["text/*", "image/*", "application/pdf"]
//!     }
//! }
//! ```
//!
//! ## Workflow
//!
//! ### Sending Open Request
//! 1. User triggers "Open on device" action
//! 2. Create `OpenRequest` with content details
//! 3. Send `cconnect.open.request` packet
//! 4. Wait for `cconnect.open.response`
//!
//! ### Receiving Open Request
//! 1. Receive `cconnect.open.request` packet
//! 2. Validate content type and size
//! 3. Open content with appropriate app
//! 4. Send `cconnect.open.response` with result
//!
//! ## Example
//!
//! ```rust,ignore
//! use cosmic_connect_core::plugins::open::*;
//!
//! // Request to open a URL on remote device
//! let request = OpenRequest {
//!     request_id: "req-123".to_string(),
//!     content_type: OpenContentType::Url,
//!     url: Some("https://example.com".to_string()),
//!     mime_type: Some("text/html".to_string()),
//!     filename: None,
//!     file_size: None,
//!     title: Some("Example Website".to_string()),
//! };
//!
//! // After opening, send response
//! let response = OpenResponse {
//!     request_id: "req-123".to_string(),
//!     success: true,
//!     error_message: None,
//!     opened_with: Some("Firefox".to_string()),
//! };
//! ```
//!
//! ## References
//!
//! - [KDE Connect Protocol](https://invent.kde.org/network/kdeconnect-kde)

use serde::{Deserialize, Serialize};

/// Content type for open requests
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OpenContentType {
    /// URL to open in browser or appropriate app
    Url,
    /// File path to open (requires file transfer)
    File,
    /// Plain text content
    Text,
}

impl Default for OpenContentType {
    fn default() -> Self {
        Self::Url
    }
}

/// Device capabilities for opening content
///
/// Advertises what types of content a device can handle.
///
/// ## Example
///
/// ```rust
/// use cosmic_connect_core::plugins::open::OpenCapability;
///
/// let capability = OpenCapability {
///     supported_schemes: vec!["http".to_string(), "https".to_string()],
///     max_file_size: 100 * 1024 * 1024, // 100 MB
///     supported_mime_types: vec!["text/*".to_string(), "image/*".to_string()],
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenCapability {
    /// URL schemes this device supports (e.g., "http", "https", "mailto", "tel", "geo")
    #[serde(rename = "supportedSchemes")]
    pub supported_schemes: Vec<String>,

    /// Maximum file size in bytes this device can handle
    #[serde(rename = "maxFileSize")]
    pub max_file_size: u64,

    /// MIME type patterns supported (e.g., "text/*", "image/png", "application/pdf")
    #[serde(rename = "supportedMimeTypes")]
    pub supported_mime_types: Vec<String>,
}

impl Default for OpenCapability {
    fn default() -> Self {
        Self {
            supported_schemes: vec![
                "http".to_string(),
                "https".to_string(),
                "mailto".to_string(),
                "tel".to_string(),
            ],
            max_file_size: 100 * 1024 * 1024, // 100 MB default
            supported_mime_types: vec![
                "text/*".to_string(),
                "image/*".to_string(),
                "application/pdf".to_string(),
            ],
        }
    }
}

/// Request to open content on a remote device
///
/// ## Example
///
/// ```rust
/// use cosmic_connect_core::plugins::open::{OpenRequest, OpenContentType};
///
/// let request = OpenRequest {
///     request_id: "req-001".to_string(),
///     content_type: OpenContentType::Url,
///     url: Some("https://example.com".to_string()),
///     mime_type: Some("text/html".to_string()),
///     filename: None,
///     file_size: None,
///     title: Some("Example Page".to_string()),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenRequest {
    /// Unique request ID for tracking responses
    #[serde(rename = "requestId")]
    pub request_id: String,

    /// Type of content to open
    #[serde(rename = "contentType")]
    pub content_type: OpenContentType,

    /// URL to open (for URL content type)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// MIME type of the content
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,

    /// Filename (for file content type)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,

    /// File size in bytes (for file content type)
    #[serde(rename = "fileSize", skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,

    /// Optional display title
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

impl OpenRequest {
    /// Create a new open request for a URL
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_connect_core::plugins::open::OpenRequest;
    ///
    /// let request = OpenRequest::new_url(
    ///     "req-001".to_string(),
    ///     "https://example.com".to_string(),
    ///     Some("Example".to_string()),
    /// );
    /// ```
    pub fn new_url(request_id: String, url: String, title: Option<String>) -> Self {
        Self {
            request_id,
            content_type: OpenContentType::Url,
            url: Some(url),
            mime_type: Some("text/html".to_string()),
            filename: None,
            file_size: None,
            title,
        }
    }

    /// Create a new open request for a file
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_connect_core::plugins::open::OpenRequest;
    ///
    /// let request = OpenRequest::new_file(
    ///     "req-002".to_string(),
    ///     "document.pdf".to_string(),
    ///     "application/pdf".to_string(),
    ///     1024000,
    /// );
    /// ```
    pub fn new_file(
        request_id: String,
        filename: String,
        mime_type: String,
        file_size: u64,
    ) -> Self {
        Self {
            request_id,
            content_type: OpenContentType::File,
            url: None,
            mime_type: Some(mime_type),
            filename: Some(filename),
            file_size: Some(file_size),
            title: None,
        }
    }

    /// Create a new open request for text content
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_connect_core::plugins::open::OpenRequest;
    ///
    /// let request = OpenRequest::new_text(
    ///     "req-003".to_string(),
    ///     "Hello World".to_string(),
    /// );
    /// ```
    pub fn new_text(request_id: String, text: String) -> Self {
        Self {
            request_id,
            content_type: OpenContentType::Text,
            url: Some(text), // Store text in url field
            mime_type: Some("text/plain".to_string()),
            filename: None,
            file_size: None,
            title: None,
        }
    }
}

/// Response after attempting to open content
///
/// ## Example
///
/// ```rust
/// use cosmic_connect_core::plugins::open::OpenResponse;
///
/// let response = OpenResponse {
///     request_id: "req-001".to_string(),
///     success: true,
///     error_message: None,
///     opened_with: Some("Firefox".to_string()),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenResponse {
    /// Request ID this response corresponds to
    #[serde(rename = "requestId")]
    pub request_id: String,

    /// Whether the content was successfully opened
    pub success: bool,

    /// Error message if unsuccessful
    #[serde(rename = "errorMessage", skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,

    /// Name of application that opened the content
    #[serde(rename = "openedWith", skip_serializing_if = "Option::is_none")]
    pub opened_with: Option<String>,
}

impl OpenResponse {
    /// Create a successful response
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_connect_core::plugins::open::OpenResponse;
    ///
    /// let response = OpenResponse::success(
    ///     "req-001".to_string(),
    ///     Some("Firefox".to_string()),
    /// );
    /// assert!(response.success);
    /// ```
    pub fn success(request_id: String, opened_with: Option<String>) -> Self {
        Self {
            request_id,
            success: true,
            error_message: None,
            opened_with,
        }
    }

    /// Create a failure response
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_connect_core::plugins::open::OpenResponse;
    ///
    /// let response = OpenResponse::failure(
    ///     "req-001".to_string(),
    ///     "Unsupported content type".to_string(),
    /// );
    /// assert!(!response.success);
    /// ```
    pub fn failure(request_id: String, error_message: String) -> Self {
        Self {
            request_id,
            success: false,
            error_message: Some(error_message),
            opened_with: None,
        }
    }
}

// ============================================================================
// Desktop Plugin Implementation (Issue #118)
// ============================================================================

use crate::error::Result;
use crate::protocol::Packet;
use async_trait::async_trait;
use std::collections::HashSet;
use std::net::IpAddr;
use std::process::Command;
use tracing::{debug, error, info, warn};
use url::Url;

use super::Plugin;

/// Configuration for OpenPlugin security and behavior
#[derive(Debug, Clone)]
pub struct OpenPluginConfig {
    /// Allowed URL schemes (default: http, https, mailto, tel, geo)
    pub allowed_schemes: HashSet<String>,

    /// Auto-open URLs from trusted devices without confirmation
    pub auto_open_trusted: bool,

    /// Timeout for confirmation requests in seconds
    pub confirmation_timeout_secs: u64,

    /// Block localhost and internal IPs
    pub block_internal_hosts: bool,
}

impl Default for OpenPluginConfig {
    fn default() -> Self {
        let mut allowed_schemes = HashSet::new();
        allowed_schemes.insert("http".to_string());
        allowed_schemes.insert("https".to_string());
        allowed_schemes.insert("mailto".to_string());
        allowed_schemes.insert("tel".to_string());
        allowed_schemes.insert("geo".to_string());

        Self {
            allowed_schemes,
            auto_open_trusted: false,
            confirmation_timeout_secs: 30,
            block_internal_hosts: true,
        }
    }
}

/// Errors specific to URL opening operations
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("URL scheme not allowed: {0}")]
    SchemeNotAllowed(String),

    #[error("URL host is blocked: {0}")]
    HostBlocked(String),

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("User declined to open URL")]
    UserDeclined,

    #[error("Failed to open URL: {0}")]
    OpenFailed(String),

    #[error("Confirmation timeout")]
    ConfirmationTimeout,

    #[error("Unsupported content type: {0:?}")]
    UnsupportedContentType(OpenContentType),
}

/// Desktop plugin for receiving and securely opening content from Android
///
/// Implements URL validation, security checks, and integration with xdg-open.
pub struct OpenPlugin {
    /// Device ID this plugin is associated with
    device_id: String,

    /// Plugin configuration
    config: OpenPluginConfig,
}

impl OpenPlugin {
    /// Create a new OpenPlugin with default configuration
    pub fn new(device_id: impl Into<String>) -> Self {
        Self {
            device_id: device_id.into(),
            config: OpenPluginConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(device_id: impl Into<String>, config: OpenPluginConfig) -> Self {
        Self {
            device_id: device_id.into(),
            config,
        }
    }

    /// Handle incoming open request from Android
    ///
    /// Validates the URL, requests user confirmation (if needed), and opens the content.
    pub async fn handle_open_request(&self, request: OpenRequest) -> OpenResponse {
        info!(
            "Received open request: type={:?}, title={:?}, id={}",
            request.content_type, request.title, request.request_id
        );

        // Handle different content types
        match request.content_type {
            OpenContentType::Url => {
                if let Some(ref url) = request.url {
                    self.handle_url_open(&request.request_id, url).await
                } else {
                    OpenResponse::failure(
                        request.request_id,
                        "URL content type requires url field".to_string(),
                    )
                }
            }
            OpenContentType::File => {
                // TODO: Implement file opening (requires payload transfer)
                warn!("File opening not implemented yet");
                OpenResponse::failure(
                    request.request_id,
                    "File opening not yet implemented".to_string(),
                )
            }
            OpenContentType::Text => {
                // TODO: Implement text opening (show in notification or clipboard)
                warn!("Text opening not implemented yet");
                OpenResponse::failure(
                    request.request_id,
                    "Text opening not yet implemented".to_string(),
                )
            }
        }
    }

    /// Handle URL opening with validation
    async fn handle_url_open(&self, request_id: &str, url: &str) -> OpenResponse {
        // Validate URL
        if let Err(e) = self.validate_url(url) {
            warn!("URL validation failed: {}", e);
            return OpenResponse::failure(request_id.to_string(), e.to_string());
        }

        // TODO: Request user confirmation via notification system
        // For now, we'll use the config setting
        let confirmed = self.config.auto_open_trusted;

        if !confirmed {
            warn!("User confirmation required but not implemented yet");
            return OpenResponse::failure(
                request_id.to_string(),
                "User confirmation not implemented - set auto_open_trusted to test".to_string(),
            );
        }

        // Open URL
        match self.open_url(url) {
            Ok(app_name) => {
                info!("Successfully opened URL: {}", url);
                OpenResponse::success(request_id.to_string(), Some(app_name))
            }
            Err(e) => {
                error!("Failed to open URL: {}", e);
                OpenResponse::failure(request_id.to_string(), e.to_string())
            }
        }
    }

    /// Validate URL for security
    ///
    /// Checks:
    /// - URL is well-formed
    /// - Scheme is in allowlist
    /// - Host is not blocked (localhost, internal IPs)
    fn validate_url(&self, url_str: &str) -> std::result::Result<(), OpenError> {
        // Parse URL
        let url = Url::parse(url_str)
            .map_err(|e| OpenError::InvalidUrl(format!("Parse error: {}", e)))?;

        // Check scheme
        let scheme = url.scheme();
        if !self.config.allowed_schemes.contains(scheme) {
            return Err(OpenError::SchemeNotAllowed(scheme.to_string()));
        }

        // For HTTP/HTTPS, validate host if blocking is enabled
        if self.config.block_internal_hosts && (scheme == "http" || scheme == "https") {
            self.validate_host(&url)?;
        }

        Ok(())
    }

    /// Validate URL host is not localhost or internal IP
    fn validate_host(&self, url: &Url) -> std::result::Result<(), OpenError> {
        let host = url
            .host_str()
            .ok_or_else(|| OpenError::InvalidUrl("Missing host".to_string()))?;

        // Check for localhost string
        if host == "localhost" || host == "127.0.0.1" {
            return Err(OpenError::HostBlocked(format!("Localhost: {}", host)));
        }

        // Use url::Host which handles IPv6 properly
        if let Some(url_host) = url.host() {
            use url::Host;
            match url_host {
                Host::Ipv4(ip) => {
                    if self.is_blocked_ip(&IpAddr::V4(ip)) {
                        return Err(OpenError::HostBlocked(format!("Internal IP: {}", ip)));
                    }
                }
                Host::Ipv6(ip) => {
                    if self.is_blocked_ip(&IpAddr::V6(ip)) {
                        return Err(OpenError::HostBlocked(format!("Internal IP: {}", ip)));
                    }
                }
                Host::Domain(_) => {
                    // Domain names are OK (unless they're "localhost" which we check above)
                }
            }
        }

        Ok(())
    }

    /// Check if IP address is in blocked ranges
    ///
    /// Blocks:
    /// - Private IPv4 ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
    /// - Link-local addresses (169.254.x.x, fe80::/10)
    /// - Loopback addresses
    fn is_blocked_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Private networks
                octets[0] == 10 // 10.0.0.0/8
                    || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) // 172.16.0.0/12
                    || (octets[0] == 192 && octets[1] == 168) // 192.168.0.0/16
                    // Link-local
                    || (octets[0] == 169 && octets[1] == 254) // 169.254.0.0/16
                    // Loopback
                    || octets[0] == 127 // 127.0.0.0/8
            }
            IpAddr::V6(ipv6) => {
                // Link-local (fe80::/10)
                ipv6.segments()[0] & 0xffc0 == 0xfe80
                    // Loopback (::1)
                    || ipv6.is_loopback()
            }
        }
    }

    /// Open URL using xdg-open
    ///
    /// Spawns xdg-open as a detached process to open the URL
    /// with the system's default handler.
    ///
    /// Returns the name of the application (currently "xdg-open")
    fn open_url(&self, url: &str) -> std::result::Result<String, OpenError> {
        debug!("Opening URL with xdg-open: {}", url);

        Command::new("xdg-open")
            .arg(url)
            .spawn()
            .map_err(|e| OpenError::OpenFailed(format!("xdg-open failed: {}", e)))?;

        Ok("xdg-open".to_string())
    }

    /// Create an open response packet for sending back to Android
    pub fn create_response_packet(&self, response: OpenResponse) -> Packet {
        Packet::new("cconnect.open.response", serde_json::to_value(response).unwrap())
    }

    /// Create capability announcement packet
    pub fn create_capability_packet(&self) -> Packet {
        let capability = OpenCapability::default();
        Packet::new("cconnect.open.capability", serde_json::to_value(capability).unwrap())
    }
}

#[async_trait]
impl Plugin for OpenPlugin {
    fn name(&self) -> &str {
        "open"
    }

    fn incoming_capabilities(&self) -> Vec<String> {
        vec!["cconnect.open.request".to_string()]
    }

    fn outgoing_capabilities(&self) -> Vec<String> {
        vec![
            "cconnect.open.response".to_string(),
            "cconnect.open.capability".to_string(),
        ]
    }

    async fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
        match packet.packet_type.as_str() {
            "cconnect.open.request" => {
                // Parse request
                let request: OpenRequest = serde_json::from_value(packet.body.clone())
                    .map_err(|e| {
                        crate::error::ProtocolError::InvalidPacket(format!(
                            "Invalid open request: {}",
                            e
                        ))
                    })?;

                // Handle request
                let response = self.handle_open_request(request).await;

                // TODO: Send response packet back to device via PluginManager callback
                // For now, just log it
                debug!("Open response: {:?}", response);

                Ok(())
            }
            _ => {
                warn!("Unknown packet type: {}", packet.packet_type);
                Ok(())
            }
        }
    }

    async fn initialize(&mut self) -> Result<()> {
        info!("OpenPlugin initialized for device: {}", self.device_id);
        // TODO: Send capability packet to advertise what we can open
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("OpenPlugin shutdown for device: {}", self.device_id);
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_open_content_type_serialization() {
        let url_type = OpenContentType::Url;
        assert_eq!(
            serde_json::to_string(&url_type).unwrap(),
            r#""url""#
        );

        let file_type = OpenContentType::File;
        assert_eq!(
            serde_json::to_string(&file_type).unwrap(),
            r#""file""#
        );

        let text_type = OpenContentType::Text;
        assert_eq!(
            serde_json::to_string(&text_type).unwrap(),
            r#""text""#
        );
    }

    #[test]
    fn test_open_capability_default() {
        let capability = OpenCapability::default();
        assert!(capability.supported_schemes.contains(&"http".to_string()));
        assert!(capability.supported_schemes.contains(&"https".to_string()));
        assert_eq!(capability.max_file_size, 100 * 1024 * 1024);
        assert!(!capability.supported_mime_types.is_empty());
    }

    #[test]
    fn test_open_capability_serialization() {
        let capability = OpenCapability {
            supported_schemes: vec!["http".to_string(), "https".to_string()],
            max_file_size: 104857600,
            supported_mime_types: vec!["text/*".to_string()],
        };

        let json = serde_json::to_value(&capability).unwrap();
        assert_eq!(json["supportedSchemes"][0], "http");
        assert_eq!(json["maxFileSize"], 104857600);
        assert_eq!(json["supportedMimeTypes"][0], "text/*");
    }

    #[test]
    fn test_open_request_new_url() {
        let request = OpenRequest::new_url(
            "req-001".to_string(),
            "https://example.com".to_string(),
            Some("Example".to_string()),
        );

        assert_eq!(request.request_id, "req-001");
        assert_eq!(request.content_type, OpenContentType::Url);
        assert_eq!(request.url.as_deref(), Some("https://example.com"));
        assert_eq!(request.title.as_deref(), Some("Example"));
    }

    #[test]
    fn test_open_request_new_file() {
        let request = OpenRequest::new_file(
            "req-002".to_string(),
            "document.pdf".to_string(),
            "application/pdf".to_string(),
            1024000,
        );

        assert_eq!(request.request_id, "req-002");
        assert_eq!(request.content_type, OpenContentType::File);
        assert_eq!(request.filename.as_deref(), Some("document.pdf"));
        assert_eq!(request.mime_type.as_deref(), Some("application/pdf"));
        assert_eq!(request.file_size, Some(1024000));
    }

    #[test]
    fn test_open_request_new_text() {
        let request = OpenRequest::new_text(
            "req-003".to_string(),
            "Hello World".to_string(),
        );

        assert_eq!(request.request_id, "req-003");
        assert_eq!(request.content_type, OpenContentType::Text);
        assert_eq!(request.url.as_deref(), Some("Hello World"));
        assert_eq!(request.mime_type.as_deref(), Some("text/plain"));
    }

    #[test]
    fn test_open_request_serialization() {
        let request = OpenRequest::new_url(
            "req-001".to_string(),
            "https://example.com".to_string(),
            Some("Example".to_string()),
        );

        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["requestId"], "req-001");
        assert_eq!(json["contentType"], "url");
        assert_eq!(json["url"], "https://example.com");
        assert_eq!(json["title"], "Example");
    }

    #[test]
    fn test_open_request_deserialization() {
        let json = r#"{
            "requestId": "req-001",
            "contentType": "url",
            "url": "https://example.com",
            "mimeType": "text/html",
            "title": "Example"
        }"#;

        let request: OpenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.request_id, "req-001");
        assert_eq!(request.content_type, OpenContentType::Url);
        assert_eq!(request.url.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn test_open_response_success() {
        let response = OpenResponse::success(
            "req-001".to_string(),
            Some("Firefox".to_string()),
        );

        assert!(response.success);
        assert_eq!(response.request_id, "req-001");
        assert_eq!(response.opened_with.as_deref(), Some("Firefox"));
        assert!(response.error_message.is_none());
    }

    #[test]
    fn test_open_response_failure() {
        let response = OpenResponse::failure(
            "req-001".to_string(),
            "Unsupported content".to_string(),
        );

        assert!(!response.success);
        assert_eq!(response.request_id, "req-001");
        assert_eq!(response.error_message.as_deref(), Some("Unsupported content"));
        assert!(response.opened_with.is_none());
    }

    #[test]
    fn test_open_response_serialization() {
        let response = OpenResponse::success(
            "req-001".to_string(),
            Some("Firefox".to_string()),
        );

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["requestId"], "req-001");
        assert_eq!(json["success"], true);
        assert_eq!(json["openedWith"], "Firefox");
    }

    #[test]
    fn test_open_response_deserialization() {
        let json = r#"{
            "requestId": "req-001",
            "success": false,
            "errorMessage": "File not found"
        }"#;

        let response: OpenResponse = serde_json::from_str(json).unwrap();
        assert!(!response.success);
        assert_eq!(response.request_id, "req-001");
        assert_eq!(response.error_message.as_deref(), Some("File not found"));
    }

    #[test]
    fn test_round_trip_serialization() {
        let original = OpenRequest::new_file(
            "req-123".to_string(),
            "test.pdf".to_string(),
            "application/pdf".to_string(),
            5000,
        );

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: OpenRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(original, deserialized);
    }

    // ========================================================================
    // OpenPlugin Security Tests (Issue #118)
    // ========================================================================

    #[test]
    fn test_validate_url_allowed_schemes() {
        let plugin = OpenPlugin::new("test-device");

        // Valid schemes
        assert!(plugin.validate_url("https://example.com").is_ok());
        assert!(plugin.validate_url("http://example.com").is_ok());
        assert!(plugin.validate_url("mailto:test@example.com").is_ok());
        assert!(plugin.validate_url("tel:+1234567890").is_ok());
        assert!(plugin.validate_url("geo:37.7749,-122.4194").is_ok());
    }

    #[test]
    fn test_validate_url_blocked_schemes() {
        let plugin = OpenPlugin::new("test-device");

        // Blocked schemes
        assert!(matches!(
            plugin.validate_url("file:///etc/passwd"),
            Err(OpenError::SchemeNotAllowed(_))
        ));
        assert!(matches!(
            plugin.validate_url("javascript:alert(1)"),
            Err(OpenError::SchemeNotAllowed(_))
        ));
        assert!(matches!(
            plugin.validate_url("data:text/html,<script>alert(1)</script>"),
            Err(OpenError::SchemeNotAllowed(_))
        ));
        assert!(matches!(
            plugin.validate_url("ftp://example.com"),
            Err(OpenError::SchemeNotAllowed(_))
        ));
    }

    #[test]
    fn test_validate_url_localhost() {
        let plugin = OpenPlugin::new("test-device");

        // Localhost variations
        assert!(matches!(
            plugin.validate_url("http://localhost/admin"),
            Err(OpenError::HostBlocked(_))
        ));
        assert!(matches!(
            plugin.validate_url("http://127.0.0.1/admin"),
            Err(OpenError::HostBlocked(_))
        ));
        assert!(matches!(
            plugin.validate_url("http://[::1]/admin"),
            Err(OpenError::HostBlocked(_))
        ));
    }

    #[test]
    fn test_validate_url_internal_ips() {
        let plugin = OpenPlugin::new("test-device");

        // Private IPv4 ranges
        assert!(matches!(
            plugin.validate_url("http://10.0.0.1"),
            Err(OpenError::HostBlocked(_))
        ));
        assert!(matches!(
            plugin.validate_url("http://172.16.0.1"),
            Err(OpenError::HostBlocked(_))
        ));
        assert!(matches!(
            plugin.validate_url("http://172.31.255.255"),
            Err(OpenError::HostBlocked(_))
        ));
        assert!(matches!(
            plugin.validate_url("http://192.168.1.1"),
            Err(OpenError::HostBlocked(_))
        ));

        // Link-local
        assert!(matches!(
            plugin.validate_url("http://169.254.1.1"),
            Err(OpenError::HostBlocked(_))
        ));
    }

    #[test]
    fn test_validate_url_public_ips() {
        let plugin = OpenPlugin::new("test-device");

        // Public IPs should be allowed
        assert!(plugin.validate_url("http://8.8.8.8").is_ok());
        assert!(plugin.validate_url("http://1.1.1.1").is_ok());
        assert!(plugin.validate_url("https://93.184.216.34").is_ok()); // example.com
    }

    #[test]
    fn test_is_blocked_ip_ipv4() {
        let plugin = OpenPlugin::new("test-device");

        // Private ranges
        assert!(plugin.is_blocked_ip(&"10.0.0.1".parse().unwrap()));
        assert!(plugin.is_blocked_ip(&"10.255.255.255".parse().unwrap()));
        assert!(plugin.is_blocked_ip(&"172.16.0.1".parse().unwrap()));
        assert!(plugin.is_blocked_ip(&"172.31.255.255".parse().unwrap()));
        assert!(plugin.is_blocked_ip(&"192.168.0.1".parse().unwrap()));
        assert!(plugin.is_blocked_ip(&"192.168.255.255".parse().unwrap()));

        // Link-local
        assert!(plugin.is_blocked_ip(&"169.254.1.1".parse().unwrap()));

        // Loopback
        assert!(plugin.is_blocked_ip(&"127.0.0.1".parse().unwrap()));
        assert!(plugin.is_blocked_ip(&"127.255.255.255".parse().unwrap()));

        // Public IPs should not be blocked
        assert!(!plugin.is_blocked_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!plugin.is_blocked_ip(&"1.1.1.1".parse().unwrap()));
        assert!(!plugin.is_blocked_ip(&"93.184.216.34".parse().unwrap()));
    }

    #[test]
    fn test_is_blocked_ip_ipv6() {
        let plugin = OpenPlugin::new("test-device");

        // Loopback
        assert!(plugin.is_blocked_ip(&"::1".parse().unwrap()));

        // Link-local (fe80::/10)
        assert!(plugin.is_blocked_ip(&"fe80::1".parse().unwrap()));
        assert!(plugin.is_blocked_ip(&"fe80::dead:beef".parse().unwrap()));

        // Public IPv6 should not be blocked
        assert!(!plugin.is_blocked_ip(&"2001:4860:4860::8888".parse().unwrap())); // Google DNS
    }

    #[test]
    fn test_validate_url_malformed() {
        let plugin = OpenPlugin::new("test-device");

        // Malformed URLs
        assert!(matches!(
            plugin.validate_url("not a url"),
            Err(OpenError::InvalidUrl(_))
        ));
        assert!(matches!(
            plugin.validate_url("http://"),
            Err(OpenError::InvalidUrl(_))
        ));
    }

    #[test]
    fn test_config_disable_host_blocking() {
        let mut config = OpenPluginConfig::default();
        config.block_internal_hosts = false;

        let plugin = OpenPlugin::with_config("test-device", config);

        // Internal IPs should be allowed when blocking is disabled
        assert!(plugin.validate_url("http://192.168.1.1").is_ok());
        assert!(plugin.validate_url("http://10.0.0.1").is_ok());
        assert!(plugin.validate_url("http://localhost").is_ok());
    }

    #[test]
    fn test_config_custom_schemes() {
        let mut config = OpenPluginConfig::default();
        config.allowed_schemes.insert("ftp".to_string());

        let plugin = OpenPlugin::with_config("test-device", config);

        // FTP should now be allowed
        assert!(plugin.validate_url("ftp://example.com").is_ok());
    }

    #[tokio::test]
    async fn test_plugin_trait_impl() {
        let mut plugin = OpenPlugin::new("test-device");

        assert_eq!(plugin.name(), "open");

        let incoming = plugin.incoming_capabilities();
        assert_eq!(incoming, vec!["cconnect.open.request"]);

        let outgoing = plugin.outgoing_capabilities();
        assert!(outgoing.contains(&"cconnect.open.response".to_string()));
        assert!(outgoing.contains(&"cconnect.open.capability".to_string()));

        // Initialize and shutdown
        plugin.initialize().await.unwrap();
        plugin.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_packet_url_request() {
        let mut plugin = OpenPlugin::new("test-device");

        let packet = Packet::new(
            "cconnect.open.request",
            serde_json::to_value(OpenRequest::new_url(
                "req-001".to_string(),
                "https://rust-lang.org".to_string(),
                Some("Rust".to_string()),
            ))
            .unwrap(),
        );

        // Should not error (but won't actually open URL in tests)
        let result = plugin.handle_packet(&packet).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_packet_invalid_json() {
        let mut plugin = OpenPlugin::new("test-device");

        let packet = Packet::new(
            "cconnect.open.request",
            serde_json::json!({
                "invalid": "data"
            }),
        );

        // Should return error for invalid packet
        let result = plugin.handle_packet(&packet).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_open_request_url() {
        let mut config = OpenPluginConfig::default();
        config.auto_open_trusted = false; // User confirmation required

        let plugin = OpenPlugin::with_config("test-device", config);

        let request = OpenRequest::new_url(
            "req-001".to_string(),
            "https://example.com".to_string(),
            Some("Test".to_string()),
        );

        let response = plugin.handle_open_request(request).await;

        // Should fail because confirmation not implemented
        assert!(!response.success);
        assert!(response.error_message.is_some());
    }

    #[tokio::test]
    async fn test_handle_open_request_file_not_implemented() {
        let plugin = OpenPlugin::new("test-device");

        let request = OpenRequest::new_file(
            "req-002".to_string(),
            "test.pdf".to_string(),
            "application/pdf".to_string(),
            1024,
        );

        let response = plugin.handle_open_request(request).await;

        // Should fail because file opening not implemented
        assert!(!response.success);
        assert!(response.error_message.is_some());
    }

    #[test]
    fn test_create_response_packet() {
        let plugin = OpenPlugin::new("test-device");

        let response = OpenResponse::success("req-001".to_string(), Some("Firefox".to_string()));
        let packet = plugin.create_response_packet(response);

        assert_eq!(packet.packet_type, "cconnect.open.response");
        assert_eq!(packet.body["requestId"], "req-001");
        assert_eq!(packet.body["success"], true);
    }

    #[test]
    fn test_create_capability_packet() {
        let plugin = OpenPlugin::new("test-device");

        let packet = plugin.create_capability_packet();

        assert_eq!(packet.packet_type, "cconnect.open.capability");
        assert!(packet.body["supportedSchemes"].is_array());
        assert!(packet.body["maxFileSize"].is_number());
    }
}
