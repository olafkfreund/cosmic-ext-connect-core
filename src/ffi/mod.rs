//! Foreign Function Interface (FFI) module
//!
//! UniFFI bindings for Kotlin (Android) and Swift (iOS).
//!
//! This module provides the FFI layer between Rust core and platform-specific code.
//! All types and functions defined here correspond to the `cosmic_connect_core.udl`
//! interface definition.
//!
//! ## Architecture
//!
//! ```
//! Platform (Kotlin/Swift)
//!         ↓
//!     FFI Layer (this module)
//!         ↓
//!    Rust Core (protocol, crypto, plugins, etc.)
//! ```
//!
//! ## Type Conversions
//!
//! - `FfiPacket` ↔ `protocol::Packet`
//! - `FfiCertificate` ↔ `crypto::CertificateInfo`
//! - `FfiBatteryState` ↔ `plugins::battery::BatteryState`
//!
//! ## Error Handling
//!
//! All Rust `Result<T, ProtocolError>` types are automatically converted to
//! exceptions in Kotlin/Swift by UniFFI.

use crate::crypto::CertificateInfo;
use crate::error::{ProtocolError, Result};
use crate::network::discovery;
use crate::plugins::{battery::BatteryState, battery::BatteryPlugin, ping::PingPlugin, Plugin, PluginManager as CorePluginManager};
use crate::protocol::Packet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

// ==========================================================================
// FFI Data Types
// ==========================================================================

/// FFI-compatible network packet
#[derive(Debug, Clone)]
pub struct FfiPacket {
    pub id: i64,
    pub packet_type: String,
    pub body: String,
    pub payload_size: Option<i64>,
}

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
        let body: serde_json::Value = serde_json::from_str(&ffi.body)?;
        let mut packet = Packet::with_id(ffi.id, ffi.packet_type, body);
        if let Some(size) = ffi.payload_size {
            packet.payload_size = Some(size);
        }
        Ok(packet)
    }
}

/// FFI-compatible device information
#[derive(Debug, Clone)]
pub struct FfiDeviceInfo {
    pub device_id: String,
    pub device_name: String,
    pub device_type: String,
    pub protocol_version: i32,
    pub incoming_capabilities: Vec<String>,
    pub outgoing_capabilities: Vec<String>,
    pub tcp_port: u16,
}

/// FFI-compatible certificate
#[derive(Debug, Clone)]
pub struct FfiCertificate {
    pub device_id: String,
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
    pub fingerprint: String,
}

impl From<CertificateInfo> for FfiCertificate {
    fn from(cert: CertificateInfo) -> Self {
        Self {
            device_id: cert.device_id,
            certificate: cert.certificate,
            private_key: cert.private_key,
            fingerprint: cert.fingerprint,
        }
    }
}

impl From<FfiCertificate> for CertificateInfo {
    fn from(ffi: FfiCertificate) -> Self {
        Self {
            device_id: ffi.device_id,
            certificate: ffi.certificate,
            private_key: ffi.private_key,
            fingerprint: ffi.fingerprint,
        }
    }
}

/// FFI-compatible battery state
#[derive(Debug, Clone)]
pub struct FfiBatteryState {
    pub is_charging: bool,
    pub current_charge: i32,
    pub threshold_event: i32,
}

impl From<BatteryState> for FfiBatteryState {
    fn from(state: BatteryState) -> Self {
        Self {
            is_charging: state.is_charging,
            current_charge: state.current_charge,
            threshold_event: state.threshold_event,
        }
    }
}

impl From<FfiBatteryState> for BatteryState {
    fn from(ffi: FfiBatteryState) -> Self {
        Self {
            is_charging: ffi.is_charging,
            current_charge: ffi.current_charge,
            threshold_event: ffi.threshold_event,
        }
    }
}

/// Plugin capabilities
#[derive(Debug, Clone)]
pub struct FfiCapabilities {
    pub incoming: Vec<String>,
    pub outgoing: Vec<String>,
}

/// Ping statistics
#[derive(Debug, Clone)]
pub struct FfiPingStats {
    pub pings_received: u64,
    pub pings_sent: u64,
}

/// Discovery events
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    DeviceFound { device: FfiDeviceInfo },
    DeviceLost { device_id: String },
    IdentityReceived { device_id: String, packet: FfiPacket },
}

// ==========================================================================
// Callbacks
// ==========================================================================
//
// NOTE: Callback interfaces are defined in the UDL file (cosmic_connect_core.udl)
// and implemented here as Rust traits. The uniffi scaffolding will generate the
// necessary glue code to connect Kotlin/Swift implementations to these traits.

/// Discovery callback trait
pub trait DiscoveryCallback: Send + Sync {
    fn on_device_found(&self, device: FfiDeviceInfo);
    fn on_device_lost(&self, device_id: String);
    fn on_identity_received(&self, device_id: String, packet: FfiPacket);
}

/// Plugin callback trait
pub trait PluginCallback: Send + Sync {
    fn on_battery_update(&self, device_id: String, state: FfiBatteryState);
    fn on_ping_received(&self, device_id: String, message: Option<String>);
    fn on_packet_received(&self, device_id: String, packet: FfiPacket);
}

/// Payload transfer callback trait
pub trait PayloadCallback: Send + Sync {
    fn on_progress(&self, bytes_transferred: u64, total_bytes: u64);
    fn on_complete(&self);
    fn on_error(&self, error: String);
}

// ==========================================================================
// Namespace Functions
// ==========================================================================

/// Initialize the library with logging
pub fn initialize(log_level: String) -> Result<()> {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_new(&log_level)
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()
        .map_err(|e| ProtocolError::Other(format!("Failed to initialize logging: {}", e)))?;

    info!("cosmic-connect-core initialized with log level: {}", log_level);
    Ok(())
}

/// Get library version
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Get protocol version
pub fn get_protocol_version() -> i32 {
    crate::PROTOCOL_VERSION
}

/// Create a new network packet
pub fn create_packet(packet_type: String, body: String) -> Result<FfiPacket> {
    let body_value: serde_json::Value = serde_json::from_str(&body)?;
    let packet = Packet::new(packet_type, body_value);
    Ok(packet.into())
}

/// Create a packet with explicit ID
pub fn create_packet_with_id(id: i64, packet_type: String, body: String) -> Result<FfiPacket> {
    let body_value: serde_json::Value = serde_json::from_str(&body)?;
    let packet = Packet::with_id(id, packet_type, body_value);
    Ok(packet.into())
}

/// Serialize packet to bytes
pub fn serialize_packet(packet: FfiPacket) -> Result<Vec<u8>> {
    let core_packet: Packet = packet.try_into()?;
    core_packet.to_bytes()
}

/// Deserialize packet from bytes
pub fn deserialize_packet(data: Vec<u8>) -> Result<FfiPacket> {
    let packet = Packet::from_bytes(&data)?;
    Ok(packet.into())
}

// ==========================================================================
// Share Plugin Functions
// ==========================================================================

/// Create a file share packet
///
/// Creates a packet for sharing a file with optional metadata.
/// The file payload must be sent separately via payload transfer.
///
/// # Arguments
/// * `filename` - Name of the file being shared
/// * `size` - Size of the file in bytes
/// * `creation_time` - Optional creation timestamp (milliseconds since epoch)
/// * `last_modified` - Optional last modified timestamp (milliseconds since epoch)
pub fn create_file_share_packet(
    filename: String,
    size: i64,
    creation_time: Option<i64>,
    last_modified: Option<i64>,
) -> Result<FfiPacket> {
    use serde_json::json;

    let mut body = json!({
        "filename": filename,
    });

    if let Some(time) = creation_time {
        body["creationTime"] = json!(time);
    }

    if let Some(time) = last_modified {
        body["lastModified"] = json!(time);
    }

    let mut packet = Packet::new("cconnect.share.request".to_string(), body);
    packet.payload_size = Some(size);

    Ok(packet.into())
}

/// Create a text share packet
///
/// Creates a packet for sharing plain text content.
///
/// # Arguments
/// * `text` - Text content to share
pub fn create_text_share_packet(text: String) -> Result<FfiPacket> {
    use serde_json::json;

    let body = json!({
        "text": text,
    });

    let packet = Packet::new("cconnect.share.request".to_string(), body);
    Ok(packet.into())
}

/// Create a URL share packet
///
/// Creates a packet for sharing a URL.
///
/// # Arguments
/// * `url` - URL to share
pub fn create_url_share_packet(url: String) -> Result<FfiPacket> {
    use serde_json::json;

    let body = json!({
        "url": url,
    });

    let packet = Packet::new("cconnect.share.request".to_string(), body);
    Ok(packet.into())
}

/// Create a multi-file update packet
///
/// Creates a packet indicating multiple files will be transferred.
/// This packet is sent before transferring multiple files.
///
/// # Arguments
/// * `number_of_files` - Total number of files to be transferred
/// * `total_payload_size` - Combined size of all files in bytes
pub fn create_multifile_update_packet(
    number_of_files: i32,
    total_payload_size: i64,
) -> Result<FfiPacket> {
    use serde_json::json;

    let body = json!({
        "numberOfFiles": number_of_files,
        "totalPayloadSize": total_payload_size,
    });

    let packet = Packet::new("cconnect.share.request.update".to_string(), body);
    Ok(packet.into())
}

// ==========================================================================
// Clipboard Plugin Functions
// ==========================================================================

/// Create a standard clipboard update packet
///
/// Creates a packet for syncing clipboard changes between devices.
/// This packet does not include a timestamp and represents a standard clipboard update.
///
/// # Arguments
/// * `content` - Text content to sync to clipboard
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_clipboard_packet;
///
/// let packet = create_clipboard_packet("Hello World".to_string())?;
/// // Send packet to peer device...
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_clipboard_packet(content: String) -> Result<FfiPacket> {
    use serde_json::json;

    let body = json!({
        "content": content,
    });

    let packet = Packet::new("cconnect.clipboard".to_string(), body);
    Ok(packet.into())
}

/// Create a clipboard connect packet with timestamp
///
/// Creates a packet for syncing clipboard state when devices connect.
/// Includes timestamp for sync loop prevention.
///
/// # Arguments
/// * `content` - Text content to sync to clipboard
/// * `timestamp` - UNIX epoch timestamp in milliseconds when content was last modified
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_clipboard_connect_packet;
/// use chrono::Utc;
///
/// let content = "Hello World".to_string();
/// let timestamp = Utc::now().timestamp_millis();
/// let packet = create_clipboard_connect_packet(content, timestamp)?;
/// // Send packet to newly connected peer device...
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_clipboard_connect_packet(content: String, timestamp: i64) -> Result<FfiPacket> {
    use serde_json::json;

    let body = json!({
        "content": content,
        "timestamp": timestamp,
    });

    let packet = Packet::new("cconnect.clipboard.connect".to_string(), body);
    Ok(packet.into())
}

// ==========================================================================
// FindMyPhone Plugin FFI Functions
// ==========================================================================

/// Create a find my phone request packet
///
/// Creates a packet to make a remote device (usually a phone) ring
/// at maximum volume to help locate it. The packet has an empty body.
///
/// Sending this packet makes the phone ring. Sending it again should
/// cancel the ringing (implementation dependent on receiving side).
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_findmyphone_request;
///
/// let packet = create_findmyphone_request()?;
/// // Send packet to Android device...
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_findmyphone_request() -> Result<FfiPacket> {
    use serde_json::json;

    let packet = Packet::new("cconnect.findmyphone.request".to_string(), json!({}));
    Ok(packet.into())
}

// ==========================================================================
// RunCommand Plugin FFI Functions
// ==========================================================================

/// Create a run command request list packet
///
/// Creates a packet requesting the list of available commands from the remote device.
/// Used when the Android app wants to refresh its command list from the desktop.
///
/// # Packet Format
/// ```json
/// {
///     "id": 1234567890,
///     "type": "cconnect.runcommand.request",
///     "body": {
///         "requestCommandList": true
///     }
/// }
/// ```
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_runcommand_request_list;
///
/// let packet = create_runcommand_request_list()?;
/// // Send packet to desktop...
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_runcommand_request_list() -> Result<FfiPacket> {
    use serde_json::json;

    let packet = Packet::new(
        "cconnect.runcommand.request".to_string(),
        json!({
            "requestCommandList": true
        }),
    );
    Ok(packet.into())
}

/// Create a run command execute packet
///
/// Creates a packet requesting execution of a specific pre-configured command
/// on the remote device. The command key must correspond to a command ID
/// configured on the desktop.
///
/// # Arguments
/// * `command_key` - The unique key/ID of the command to execute
///
/// # Packet Format
/// ```json
/// {
///     "id": 1234567890,
///     "type": "cconnect.runcommand.request",
///     "body": {
///         "key": "cmd1"
///     }
/// }
/// ```
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_runcommand_execute;
///
/// let packet = create_runcommand_execute("backup".to_string())?;
/// // Send packet to desktop to execute "backup" command...
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_runcommand_execute(command_key: String) -> Result<FfiPacket> {
    use serde_json::json;

    let packet = Packet::new(
        "cconnect.runcommand.request".to_string(),
        json!({
            "key": command_key
        }),
    );
    Ok(packet.into())
}

/// Create a run command setup packet
///
/// Creates a packet requesting the remote device to open its command configuration
/// interface. This allows the user to add/edit/remove available commands.
///
/// # Packet Format
/// ```json
/// {
///     "id": 1234567890,
///     "type": "cconnect.runcommand.request",
///     "body": {
///         "setup": true
///     }
/// }
/// ```
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_runcommand_setup;
///
/// let packet = create_runcommand_setup()?;
/// // Send packet to desktop to open command setup UI...
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_runcommand_setup() -> Result<FfiPacket> {
    use serde_json::json;

    let packet = Packet::new(
        "cconnect.runcommand.request".to_string(),
        json!({
            "setup": true
        }),
    );
    Ok(packet.into())
}

// ==========================================================================
// Telephony Plugin FFI Functions
// ==========================================================================

/// Create a telephony event packet (call notification)
///
/// Creates a packet for notifying about phone call events (ringing, talking, missed call).
/// This packet is sent from Android to desktop when call state changes.
///
/// # Arguments
/// * `event` - Event type: "ringing", "talking", "missedCall", or "sms" (deprecated)
/// * `phone_number` - Caller's phone number (optional)
/// * `contact_name` - Contact name from address book (optional)
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_telephony_event;
///
/// let packet = create_telephony_event(
///     "ringing".to_string(),
///     Some("+1234567890".to_string()),
///     Some("John Doe".to_string())
/// )?;
/// // Send packet to desktop...
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_telephony_event(
    event: String,
    phone_number: Option<String>,
    contact_name: Option<String>,
) -> Result<FfiPacket> {
    use serde_json::json;

    let mut body = json!({
        "event": event,
    });

    if let Some(number) = phone_number {
        body["phoneNumber"] = json!(number);
    }

    if let Some(name) = contact_name {
        body["contactName"] = json!(name);
    }

    let packet = Packet::new("cconnect.telephony".to_string(), body);
    Ok(packet.into())
}

/// Create a mute ringer request packet
///
/// Creates a packet requesting the phone to mute its ringer.
/// Sent from desktop to Android when user wants to silence an incoming call.
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_mute_request;
///
/// let packet = create_mute_request()?;
/// // Send packet to Android device...
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_mute_request() -> Result<FfiPacket> {
    use serde_json::json;

    let packet = Packet::new("cconnect.telephony.request_mute".to_string(), json!({}));
    Ok(packet.into())
}

/// Create an SMS messages packet
///
/// Creates a packet containing SMS conversations with messages.
/// Sent from Android to desktop in response to conversation requests.
///
/// # Arguments
/// * `conversations_json` - JSON string containing array of conversations with messages
///
/// # JSON Format
/// ```json
/// {
///   "conversations": [
///     {
///       "thread_id": 123,
///       "messages": [
///         {
///           "_id": 456,
///           "thread_id": 123,
///           "address": "+1234567890",
///           "body": "Hello!",
///           "date": 1705507200000,
///           "type": 1,
///           "read": 1
///         }
///       ]
///     }
///   ]
/// }
/// ```
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_sms_messages;
///
/// let conversations_json = r#"{"conversations":[{"thread_id":123,"messages":[]}]}"#;
/// let packet = create_sms_messages(conversations_json.to_string())?;
/// // Send packet to desktop...
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_sms_messages(conversations_json: String) -> Result<FfiPacket> {
    use serde_json::Value;

    // Parse JSON to validate format
    let body: Value = serde_json::from_str(&conversations_json)
        .map_err(|e| ProtocolError::InvalidPacket(format!("Invalid SMS JSON: {}", e)))?;

    let packet = Packet::new("cconnect.sms.messages".to_string(), body);
    Ok(packet.into())
}

/// Create a request for SMS conversations list
///
/// Creates a packet requesting the list of SMS conversations (latest message in each thread).
/// Sent from desktop to Android to get overview of SMS threads.
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_conversations_request;
///
/// let packet = create_conversations_request()?;
/// // Send packet to Android device...
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_conversations_request() -> Result<FfiPacket> {
    use serde_json::json;

    let packet = Packet::new(
        "cconnect.sms.request_conversations".to_string(),
        json!({}),
    );
    Ok(packet.into())
}

/// Create a request for messages in a specific conversation
///
/// Creates a packet requesting messages from a specific SMS thread.
/// Sent from desktop to Android to view conversation history.
///
/// # Arguments
/// * `thread_id` - The conversation thread ID
/// * `start_timestamp` - Optional earliest message timestamp (ms since epoch, for pagination)
/// * `count` - Optional maximum number of messages to return
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_conversation_request;
///
/// // Request latest 50 messages from thread 123
/// let packet = create_conversation_request(123, None, Some(50))?;
/// // Send packet to Android device...
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_conversation_request(
    thread_id: i64,
    start_timestamp: Option<i64>,
    count: Option<i32>,
) -> Result<FfiPacket> {
    use serde_json::json;

    let mut body = json!({
        "threadID": thread_id,
    });

    if let Some(ts) = start_timestamp {
        body["rangeStartTimestamp"] = json!(ts);
    }

    if let Some(n) = count {
        body["numberToRequest"] = json!(n);
    }

    let packet = Packet::new("cconnect.sms.request_conversation".to_string(), body);
    Ok(packet.into())
}

/// Create a request for a message attachment
///
/// Creates a packet requesting a message attachment (MMS image, video, etc.).
/// Sent from desktop to Android to download attachment.
///
/// # Arguments
/// * `part_id` - The attachment part ID from the message
/// * `unique_identifier` - Unique file identifier for the attachment
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_attachment_request;
///
/// let packet = create_attachment_request(789, "abc123".to_string())?;
/// // Send packet to Android device...
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_attachment_request(part_id: i64, unique_identifier: String) -> Result<FfiPacket> {
    use serde_json::json;

    let body = json!({
        "part_id": part_id,
        "unique_identifier": unique_identifier,
    });

    let packet = Packet::new("cconnect.sms.request_attachment".to_string(), body);
    Ok(packet.into())
}

/// Create a request to send an SMS message
///
/// Creates a packet requesting to send an SMS from the Android device.
/// Sent from desktop to Android when user composes a message.
///
/// # Arguments
/// * `phone_number` - Recipient phone number
/// * `message_body` - Message text to send
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_send_sms_request;
///
/// let packet = create_send_sms_request(
///     "+1234567890".to_string(),
///     "Hello from desktop!".to_string()
/// )?;
/// // Send packet to Android device...
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_send_sms_request(phone_number: String, message_body: String) -> Result<FfiPacket> {
    use serde_json::json;

    let body = json!({
        "phoneNumber": phone_number,
        "messageBody": message_body,
    });

    let packet = Packet::new("cconnect.sms.request".to_string(), body);
    Ok(packet.into())
}

// ==========================================================================
// Battery Plugin FFI Functions
// ==========================================================================

/// Create a battery status packet
///
/// Creates a packet containing current battery state information.
/// This packet is sent bi-directionally between devices to share battery status.
///
/// # Arguments
/// * `is_charging` - Whether the device is currently charging
/// * `current_charge` - Battery percentage (0-100, will be clamped)
/// * `threshold_event` - Threshold event indicator (0=none, 1=battery low)
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_battery_packet;
///
/// // Device is charging at 85%
/// let packet = create_battery_packet(true, 85, 0)?;
/// // Send packet to remote device...
///
/// // Device not charging, low battery (12%)
/// let low_battery = create_battery_packet(false, 12, 1)?;
/// // Send packet to remote device...
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_battery_packet(
    is_charging: bool,
    current_charge: i32,
    threshold_event: i32,
) -> Result<FfiPacket> {
    use serde_json::json;

    // Clamp current_charge to valid range (0-100)
    let clamped_charge = current_charge.clamp(0, 100);

    let body = json!({
        "isCharging": is_charging,
        "currentCharge": clamped_charge,
        "thresholdEvent": threshold_event,
    });

    let packet = Packet::new("cconnect.battery".to_string(), body);
    Ok(packet.into())
}

/// Create a battery status request packet
///
/// Creates a packet requesting the remote device's current battery status.
/// When received, the remote device should respond with a battery status packet.
/// Sent from desktop to Android to get current battery information.
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_battery_request;
///
/// let packet = create_battery_request()?;
/// // Send packet to Android device...
/// // Android will respond with battery status
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_battery_request() -> Result<FfiPacket> {
    use serde_json::json;

    let packet = Packet::new("cconnect.battery.request".to_string(), json!({}));
    Ok(packet.into())
}

// ==========================================================================
// Notifications Plugin Functions
// ==========================================================================

/// Create a full notification packet.
///
/// Creates a `cconnect.notification` packet for sending notification data
/// from Android to desktop. The notification data is passed as a JSON string
/// to avoid a massive parameter list (12+ fields).
///
/// # Arguments
///
/// * `notification_json` - JSON string containing notification fields:
///   - `id` (string, required) - Unique notification identifier
///   - `appName` (string, required) - Source application name
///   - `title` (string, optional) - Notification title
///   - `text` (string, optional) - Notification body text
///   - `ticker` (string, optional) - Combined title and text
///   - `isClearable` (boolean, required) - Whether user can dismiss
///   - `time` (string, required) - UNIX epoch timestamp in milliseconds
///   - `silent` (string, required) - "true" for preexisting, "false" for new
///   - `requestReplyId` (string, optional) - UUID for inline reply support
///   - `actions` (array, optional) - Available action button names
///   - `payloadHash` (string, optional) - MD5 hash of icon payload
///
/// # Errors
///
/// Returns `ProtocolError::Json` if the JSON string is invalid or missing required fields.
///
/// # Example JSON
/// ```json
/// {
///   "id": "notification-123",
///   "appName": "Messages",
///   "title": "New Message",
///   "text": "Hello from your phone!",
///   "isClearable": true,
///   "time": "1704067200000",
///   "silent": "false"
/// }
/// ```
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_notification_packet;
/// use serde_json::json;
///
/// let notification_json = json!({
///     "id": "notif-123",
///     "appName": "Messages",
///     "title": "New Message",
///     "text": "Hello!",
///     "isClearable": true,
///     "time": "1704067200000",
///     "silent": "false"
/// }).to_string();
///
/// let packet = create_notification_packet(notification_json)?;
/// // Send packet to desktop...
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_notification_packet(notification_json: String) -> Result<FfiPacket> {
    use crate::plugins::notification::{Notification, NotificationPlugin};

    // Parse JSON string into Notification struct
    let notification: Notification = serde_json::from_str(&notification_json)?;

    // Create packet using plugin method
    let plugin = NotificationPlugin::new();
    let packet = plugin.create_notification_packet(&notification);

    Ok(packet.into())
}

/// Create a cancel notification packet.
///
/// Creates a `cconnect.notification` packet with `isCancel: true` to
/// inform the desktop that a notification has been dismissed on Android.
///
/// # Arguments
///
/// * `notification_id` - ID of the notification to cancel
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_cancel_notification_packet;
///
/// let packet = create_cancel_notification_packet("notif-123".to_string())?;
/// // Send packet to desktop...
/// // Desktop will remove the notification from its list
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_cancel_notification_packet(notification_id: String) -> Result<FfiPacket> {
    use crate::plugins::notification::NotificationPlugin;

    let plugin = NotificationPlugin::new();
    let packet = plugin.create_cancel_packet(&notification_id);

    Ok(packet.into())
}

/// Create a notification request packet.
///
/// Creates a `cconnect.notification.request` packet with `request: true`
/// to ask the remote device to send all its current notifications.
///
/// This is typically sent when devices connect to sync existing notifications.
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_notification_request_packet;
///
/// let packet = create_notification_request_packet()?;
/// // Send packet to Android...
/// // Android will respond with all current notifications
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_notification_request_packet() -> Result<FfiPacket> {
    use crate::plugins::notification::NotificationPlugin;

    let plugin = NotificationPlugin::new();
    let packet = plugin.create_request_packet();

    Ok(packet.into())
}

/// Create a dismiss notification packet.
///
/// Creates a `cconnect.notification.request` packet with a `cancel` field
/// to request the remote device to dismiss a specific notification.
///
/// # Arguments
///
/// * `notification_id` - ID of the notification to dismiss
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_dismiss_notification_packet;
///
/// let packet = create_dismiss_notification_packet("notif-123".to_string())?;
/// // Send packet to Android...
/// // Android will dismiss the notification
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_dismiss_notification_packet(notification_id: String) -> Result<FfiPacket> {
    use crate::plugins::notification::NotificationPlugin;

    let plugin = NotificationPlugin::new();
    let packet = plugin.create_dismiss_packet(&notification_id);

    Ok(packet.into())
}

/// Create a notification action packet.
///
/// Creates a `cconnect.notification.action` packet to trigger an
/// action button on a remote notification.
///
/// # Arguments
///
/// * `notification_key` - ID of the notification
/// * `action_name` - Name of the action button to trigger
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_notification_action_packet;
///
/// let packet = create_notification_action_packet(
///     "notif-123".to_string(),
///     "Reply".to_string()
/// )?;
/// // Send packet to Android...
/// // Android will trigger the "Reply" action
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_notification_action_packet(
    notification_key: String,
    action_name: String,
) -> Result<FfiPacket> {
    use serde_json::json;

    let body = json!({
        "key": notification_key,
        "action": action_name,
    });

    let packet = Packet::new("cconnect.notification.action".to_string(), body);
    Ok(packet.into())
}

/// Create a notification reply packet.
///
/// Creates a `cconnect.notification.reply` packet to send an inline
/// reply to a notification that supports replies (typically messaging apps).
///
/// # Arguments
///
/// * `reply_id` - UUID from the notification's `requestReplyId` field
/// * `message` - Reply message text
///
/// # Example
/// ```rust,no_run
/// use cosmic_connect_core::create_notification_reply_packet;
///
/// let packet = create_notification_reply_packet(
///     "uuid-reply-123".to_string(),
///     "Thanks, I'll be there soon!".to_string()
/// )?;
/// // Send packet to Android...
/// // Android will send the reply via RemoteInput
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_notification_reply_packet(
    reply_id: String,
    message: String,
) -> Result<FfiPacket> {
    use serde_json::json;

    let body = json!({
        "requestReplyId": reply_id,
        "message": message,
    });

    let packet = Packet::new("cconnect.notification.reply".to_string(), body);
    Ok(packet.into())
}

// ==========================================================================
// Certificate Functions
// ==========================================================================

/// Generate a new self-signed certificate
pub fn generate_certificate(device_id: String) -> Result<FfiCertificate> {
    let cert = CertificateInfo::generate(device_id)?;
    Ok(cert.into())
}

/// Load certificate from PEM files
pub fn load_certificate(cert_path: String, key_path: String) -> Result<FfiCertificate> {
    let cert = CertificateInfo::load_from_files(cert_path, key_path)?;
    Ok(cert.into())
}

/// Save certificate to PEM files
// ==========================================================================
// Presenter Plugin
// ==========================================================================

/// Create a presenter pointer movement packet
///
/// This function creates a packet for sending pointer movement events for presentation
/// control. The pointer movement can be used to simulate a laser pointer on the receiving
/// device's screen.
///
/// # Arguments
///
/// * `dx` - Horizontal movement delta
/// * `dy` - Vertical movement delta
///
/// # Returns
///
/// A packet containing the pointer movement data
///
/// # Example
///
/// ```ignore
/// let packet = create_presenter_pointer(10.5, -5.2)?;
/// // Send packet to desktop...
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_presenter_pointer(dx: f64, dy: f64) -> Result<FfiPacket> {
    use serde_json::json;

    let body = json!({
        "dx": dx,
        "dy": dy,
    });

    let packet = Packet::new("cconnect.presenter", body);
    Ok(packet.into())
}

/// Create a presenter stop packet
///
/// This function creates a packet to stop presentation mode on the receiving device.
///
/// # Returns
///
/// A packet to stop presentation mode
///
/// # Example
///
/// ```ignore
/// let packet = create_presenter_stop()?;
/// // Send packet to desktop...
/// # Ok::<(), cosmic_connect_core::error::ProtocolError>(())
/// ```
pub fn create_presenter_stop() -> Result<FfiPacket> {
    use serde_json::json;

    let body = json!({
        "stop": true
    });

    let packet = Packet::new("cconnect.presenter", body);
    Ok(packet.into())
}

// ==========================================================================
// Certificate Management
// ==========================================================================

pub fn save_certificate(cert: FfiCertificate, cert_path: String, key_path: String) -> Result<()> {
    let cert_info: CertificateInfo = cert.into();
    cert_info.save_to_files(cert_path, key_path)
}

/// Get certificate fingerprint
pub fn get_certificate_fingerprint(cert: FfiCertificate) -> String {
    cert.fingerprint
}

/// Start device discovery
pub fn start_discovery(
    local_device: FfiDeviceInfo,
    callback: Box<dyn DiscoveryCallback>,
) -> Result<Arc<DiscoveryService>> {
    use crate::network::DeviceType;

    // Convert device_type string to enum
    let device_type = match local_device.device_type.to_lowercase().as_str() {
        "desktop" => DeviceType::Desktop,
        "laptop" => DeviceType::Laptop,
        "phone" => DeviceType::Phone,
        "tablet" => DeviceType::Tablet,
        "tv" => DeviceType::Tv,
        _ => return Err(ProtocolError::InvalidPacket(
            format!("Invalid device type: {}", local_device.device_type)
        )),
    };

    // Convert FfiDeviceInfo to discovery::DeviceInfo
    let device_info = discovery::DeviceInfo {
        device_id: local_device.device_id,
        device_name: local_device.device_name,
        device_type,
        protocol_version: local_device.protocol_version as u32,
        incoming_capabilities: local_device.incoming_capabilities,
        outgoing_capabilities: local_device.outgoing_capabilities,
        tcp_port: local_device.tcp_port,
    };

    Ok(Arc::new(DiscoveryService::new(device_info, callback)))
}

/// Create a new plugin manager
pub fn create_plugin_manager() -> Arc<PluginManager> {
    Arc::new(PluginManager::new())
}

// ==========================================================================
// Interfaces (Objects)
// ==========================================================================

/// Discovery service
pub struct DiscoveryService {
    device_info: discovery::DeviceInfo,
    callback: Box<dyn DiscoveryCallback>,
    running: Arc<RwLock<bool>>,
}

impl DiscoveryService {
    fn new(device_info: discovery::DeviceInfo, callback: Box<dyn DiscoveryCallback>) -> Self {
        Self {
            device_info,
            callback,
            running: Arc::new(RwLock::new(false)),
        }
    }
}

impl DiscoveryService {
    /// Stop discovery
    pub fn stop(&self) -> Result<()> {
        info!("Stopping discovery service");
        // Implementation would stop the discovery process
        Ok(())
    }

    /// Get discovered devices
    pub fn get_devices(&self) -> Vec<FfiDeviceInfo> {
        // Placeholder - actual implementation would return discovered devices
        Vec::new()
    }

    /// Check if discovery is running
    pub fn is_running(&self) -> bool {
        // Placeholder
        false
    }
}

/// Plugin manager
pub struct PluginManager {
    core: Arc<RwLock<CorePluginManager>>,
    runtime: Arc<tokio::runtime::Runtime>,
    // Plugin-specific instances for direct access
    ping_plugin: Arc<RwLock<PingPlugin>>,
    battery_plugin: Arc<RwLock<BatteryPlugin>>,
}

impl PluginManager {
    fn new() -> Self {
        let runtime = Arc::new(tokio::runtime::Runtime::new()
            .expect("Failed to create Tokio runtime"));

        Self {
            core: Arc::new(RwLock::new(CorePluginManager::new())),
            runtime,
            ping_plugin: Arc::new(RwLock::new(PingPlugin::new())),
            battery_plugin: Arc::new(RwLock::new(BatteryPlugin::new())),
        }
    }
}

impl PluginManager {
    /// Register a plugin by name
    pub fn register_plugin(&self, plugin_name: String) -> Result<()> {
        let core = Arc::clone(&self.core);

        self.runtime.block_on(async move {
            let mut manager = core.write().await;

            match plugin_name.as_str() {
                "ping" => {
                    manager.register_plugin(Box::new(PingPlugin::new())).await?;
                    info!("Registered ping plugin");
                }
                "battery" => {
                    manager.register_plugin(Box::new(BatteryPlugin::new())).await?;
                    info!("Registered battery plugin");
                }
                _ => {
                    return Err(ProtocolError::Plugin(format!(
                        "Unknown plugin: {}",
                        plugin_name
                    )));
                }
            }

            Ok(())
        })
    }

    /// Unregister a plugin
    pub fn unregister_plugin(&self, plugin_name: String) -> Result<()> {
        let core = Arc::clone(&self.core);

        self.runtime.block_on(async move {
            let mut manager = core.write().await;
            manager.unregister_plugin(&plugin_name).await
        })
    }

    /// Route a packet to the appropriate plugin
    pub fn route_packet(&self, packet: FfiPacket) -> Result<()> {
        let core = Arc::clone(&self.core);

        self.runtime.block_on(async move {
            let core_packet: Packet = packet.try_into()?;
            let manager = core.read().await;
            manager.route_packet(&core_packet).await
        })
    }

    /// Get all capabilities
    pub fn get_capabilities(&self) -> FfiCapabilities {
        let core = Arc::clone(&self.core);

        self.runtime.block_on(async move {
            let manager = core.read().await;
            let (incoming, outgoing) = manager.get_capabilities().await;
            FfiCapabilities { incoming, outgoing }
        })
    }

    /// Check if a plugin is registered
    pub fn has_plugin(&self, plugin_name: String) -> bool {
        let core = Arc::clone(&self.core);

        self.runtime.block_on(async move {
            let manager = core.read().await;
            manager.has_plugin(&plugin_name)
        })
    }

    /// Get list of registered plugin names
    pub fn plugin_names(&self) -> Vec<String> {
        let core = Arc::clone(&self.core);

        self.runtime.block_on(async move {
            let manager = core.read().await;
            manager.plugin_names()
        })
    }

    /// Shutdown all plugins
    pub fn shutdown_all(&self) -> Result<()> {
        let core = Arc::clone(&self.core);

        self.runtime.block_on(async move {
            let mut manager = core.write().await;
            manager.shutdown_all().await
        })
    }

    // Plugin-specific operations

    /// Update local battery state
    pub fn update_battery(&self, state: FfiBatteryState) -> Result<()> {
        let battery_plugin = Arc::clone(&self.battery_plugin);
        let battery_state: BatteryState = state.into();

        self.runtime.block_on(async move {
            let mut plugin = battery_plugin.write().await;
            plugin.update_local_battery(battery_state);
            Ok(())
        })
    }

    /// Get remote battery state
    pub fn get_remote_battery(&self) -> Option<FfiBatteryState> {
        let battery_plugin = Arc::clone(&self.battery_plugin);

        self.runtime.block_on(async move {
            let plugin = battery_plugin.read().await;
            plugin.remote_battery().map(|state| FfiBatteryState::from(state.clone()))
        })
    }

    /// Create a ping packet
    pub fn create_ping(&self, message: Option<String>) -> Result<FfiPacket> {
        let ping_plugin = Arc::clone(&self.ping_plugin);

        self.runtime.block_on(async move {
            let mut plugin = ping_plugin.write().await;
            let packet = plugin.create_ping(message);
            Ok(FfiPacket::from(packet))
        })
    }

    /// Get ping statistics
    pub fn get_ping_stats(&self) -> FfiPingStats {
        let ping_plugin = Arc::clone(&self.ping_plugin);

        self.runtime.block_on(async move {
            let plugin = ping_plugin.read().await;
            FfiPingStats {
                pings_received: plugin.pings_received(),
                pings_sent: plugin.pings_sent(),
            }
        })
    }
}

/// Payload transfer handle
pub struct PayloadTransferHandle {
    transfer_id: u64,
    callback: Arc<Box<dyn PayloadCallback>>,
    cancel_token: Arc<RwLock<bool>>,
    runtime: Arc<tokio::runtime::Runtime>,
}

impl PayloadTransferHandle {
    fn new(
        transfer_id: u64,
        callback: Box<dyn PayloadCallback>,
        runtime: Arc<tokio::runtime::Runtime>,
    ) -> Self {
        Self {
            transfer_id,
            callback: Arc::new(callback),
            cancel_token: Arc::new(RwLock::new(false)),
            runtime,
        }
    }

    /// Get the transfer ID
    pub fn get_id(&self) -> u64 {
        self.transfer_id
    }

    /// Cancel the payload transfer
    pub fn cancel(&self) -> Result<()> {
        let cancel_token = Arc::clone(&self.cancel_token);
        self.runtime.block_on(async move {
            let mut token = cancel_token.write().await;
            *token = true;
            Ok(())
        })
    }

    /// Check if transfer is cancelled
    pub fn is_cancelled(&self) -> bool {
        self.runtime.block_on(async {
            let token = self.cancel_token.read().await;
            *token
        })
    }
}

/// Start a payload download
///
/// Downloads a file payload from a remote device via TCP connection.
/// Progress, completion, and errors are reported via the callback.
///
/// # Arguments
/// * `device_host` - IP address of the remote device
/// * `port` - TCP port for payload transfer
/// * `expected_size` - Expected size of the payload in bytes
/// * `callback` - Callback for progress updates and completion
///
/// # Returns
/// A PayloadTransferHandle that can be used to cancel the transfer
pub fn start_payload_download(
    device_host: String,
    port: u16,
    expected_size: i64,
    callback: Box<dyn PayloadCallback>,
) -> Result<Arc<PayloadTransferHandle>> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    static TRANSFER_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

    let runtime = Arc::new(
        tokio::runtime::Runtime::new()
            .map_err(|e| ProtocolError::Other(format!("Failed to create runtime: {}", e)))?,
    );

    let transfer_id = TRANSFER_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    let handle = Arc::new(PayloadTransferHandle::new(transfer_id, callback, Arc::clone(&runtime)));

    let handle_clone = Arc::clone(&handle);
    let runtime_clone = Arc::clone(&runtime);

    // Spawn the download task
    runtime_clone.spawn(async move {
        let callback = Arc::clone(&handle_clone.callback);
        let cancel_token = Arc::clone(&handle_clone.cancel_token);

        // Attempt to connect
        let addr = format!("{}:{}", device_host, port);
        let mut stream = match TcpStream::connect(&addr).await {
            Ok(s) => s,
            Err(e) => {
                callback.on_error(format!("Failed to connect to {}: {}", addr, e));
                return;
            }
        };

        info!("Connected to {} for payload transfer", addr);

        // Download the payload
        let mut total_bytes = 0u64;
        let mut buffer = vec![0u8; 8192];

        loop {
            // Check for cancellation
            {
                let token = cancel_token.read().await;
                if *token {
                    info!("Payload transfer {} cancelled", transfer_id);
                    callback.on_error("Transfer cancelled".to_string());
                    return;
                }
            }

            // Read chunk
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    // Connection closed
                    if total_bytes >= expected_size as u64 {
                        info!("Payload transfer {} complete: {} bytes", transfer_id, total_bytes);
                        callback.on_complete();
                    } else {
                        error!(
                            "Payload transfer {} incomplete: {} of {} bytes",
                            transfer_id, total_bytes, expected_size
                        );
                        callback.on_error(format!(
                            "Transfer incomplete: {} of {} bytes",
                            total_bytes, expected_size
                        ));
                    }
                    break;
                }
                Ok(n) => {
                    total_bytes += n as u64;

                    // Report progress
                    callback.on_progress(total_bytes, expected_size as u64);

                    // Check if we've received all expected bytes
                    if total_bytes >= expected_size as u64 {
                        info!("Payload transfer {} complete: {} bytes", transfer_id, total_bytes);
                        callback.on_complete();
                        break;
                    }
                }
                Err(e) => {
                    error!("Payload transfer {} error: {}", transfer_id, e);
                    callback.on_error(format!("Transfer error: {}", e));
                    break;
                }
            }
        }
    });

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_ffi_packet_conversion() {
        let packet = Packet::new("cconnect.ping", json!({"message": "hello"}));
        let ffi_packet: FfiPacket = packet.clone().into();

        assert_eq!(ffi_packet.packet_type, "cconnect.ping");
        assert!(ffi_packet.body.contains("hello"));

        let core_packet: Packet = ffi_packet.try_into().unwrap();
        assert_eq!(core_packet.packet_type, packet.packet_type);
    }

    #[test]
    fn test_get_version() {
        let version = get_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn test_get_protocol_version() {
        let version = get_protocol_version();
        assert_eq!(version, 7);
    }

    #[test]
    fn test_create_packet() {
        let packet = create_packet(
            "cconnect.ping".to_string(),
            "{}".to_string(),
        ).unwrap();

        assert_eq!(packet.packet_type, "cconnect.ping");
    }

    #[test]
    fn test_serialize_deserialize() {
        let packet = create_packet(
            "cconnect.ping".to_string(),
            r#"{"message":"test"}"#.to_string(),
        ).unwrap();

        let bytes = serialize_packet(packet.clone()).unwrap();
        let deserialized = deserialize_packet(bytes).unwrap();

        assert_eq!(packet.packet_type, deserialized.packet_type);
    }

    #[test]
    fn test_generate_certificate() {
        let cert = generate_certificate("test_device".to_string()).unwrap();

        assert_eq!(cert.device_id, "test_device");
        assert!(!cert.certificate.is_empty());
        assert!(!cert.private_key.is_empty());
        assert!(!cert.fingerprint.is_empty());
    }

    #[test]
    fn test_plugin_manager_creation() {
        let manager = create_plugin_manager();
        assert_eq!(manager.plugin_names().len(), 0);
    }

    #[test]
    fn test_plugin_registration() {
        let manager = create_plugin_manager();

        manager.register_plugin("ping".to_string()).unwrap();
        assert!(manager.has_plugin("ping".to_string()));

        manager.register_plugin("battery".to_string()).unwrap();
        assert!(manager.has_plugin("battery".to_string()));

        let names = manager.plugin_names();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn test_plugin_capabilities() {
        let manager = create_plugin_manager();

        manager.register_plugin("ping".to_string()).unwrap();
        manager.register_plugin("battery".to_string()).unwrap();

        let caps = manager.get_capabilities();

        assert!(caps.incoming.contains(&"cconnect.ping".to_string()));
        assert!(caps.incoming.contains(&"cconnect.battery".to_string()));
    }
}
