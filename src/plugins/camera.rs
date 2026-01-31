//! Camera Plugin
//!
//! Enables using Android device camera as a virtual webcam on COSMIC Desktop.
//! Streams H.264 encoded video frames from phone to desktop for V4L2 injection.
//!
//! ## Packet Types
//!
//! - **Desktop → Android**:
//!   - `cconnect.camera.start` - Start camera streaming
//!   - `cconnect.camera.stop` - Stop camera streaming
//!   - `cconnect.camera.settings` - Change camera settings
//!
//! - **Android → Desktop**:
//!   - `cconnect.camera.capability` - Camera capabilities advertisement
//!   - `cconnect.camera.frame` - Encoded video frame data
//!   - `cconnect.camera.status` - Streaming status update
//!
//! ## Example
//!
//! ```rust
//! use cosmic_connect_core::plugins::camera::{CameraPlugin, CameraStart, Resolution};
//!
//! # fn example() {
//! let plugin = CameraPlugin::new();
//!
//! // Request camera streaming at 720p, 30fps
//! let start_packet = plugin.create_start_packet(CameraStart {
//!     camera_id: 0,
//!     resolution: Resolution { width: 1280, height: 720 },
//!     fps: 30,
//!     bitrate: 2000,
//!     codec: "h264".to_string(),
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

// ============================================================================
// Packet Type Constants
// ============================================================================

/// Packet type for camera capability advertisement
pub const PACKET_TYPE_CAMERA_CAPABILITY: &str = "cconnect.camera.capability";

/// Packet type for starting camera streaming
pub const PACKET_TYPE_CAMERA_START: &str = "cconnect.camera.start";

/// Packet type for stopping camera streaming
pub const PACKET_TYPE_CAMERA_STOP: &str = "cconnect.camera.stop";

/// Packet type for changing camera settings
pub const PACKET_TYPE_CAMERA_SETTINGS: &str = "cconnect.camera.settings";

/// Packet type for camera frame data
pub const PACKET_TYPE_CAMERA_FRAME: &str = "cconnect.camera.frame";

/// Packet type for camera status update
pub const PACKET_TYPE_CAMERA_STATUS: &str = "cconnect.camera.status";

// ============================================================================
// Common Types
// ============================================================================

/// Video resolution
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Resolution {
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
}

impl Resolution {
    /// Create a new resolution
    pub fn new(width: u32, height: u32) -> Self {
        Self { width, height }
    }

    /// 480p resolution (854x480)
    pub fn p480() -> Self {
        Self::new(854, 480)
    }

    /// 720p resolution (1280x720)
    pub fn p720() -> Self {
        Self::new(1280, 720)
    }

    /// 1080p resolution (1920x1080)
    pub fn p1080() -> Self {
        Self::new(1920, 1080)
    }

    /// Total pixel count
    pub fn pixels(&self) -> u64 {
        self.width as u64 * self.height as u64
    }
}

/// Camera facing direction
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CameraFacing {
    /// Front-facing camera (selfie)
    Front,
    /// Back-facing camera (main)
    Back,
    /// External USB camera
    External,
}

impl Default for CameraFacing {
    fn default() -> Self {
        Self::Back
    }
}

/// Video frame type for H.264 streams
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// SPS/PPS decoder configuration data
    #[serde(rename = "sps_pps")]
    SpsPps = 0x01,
    /// I-Frame (keyframe, independently decodable)
    #[serde(rename = "iframe")]
    IFrame = 0x02,
    /// P-Frame (delta frame, depends on previous frames)
    #[serde(rename = "pframe")]
    PFrame = 0x03,
}

impl FrameType {
    /// Convert from byte value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::SpsPps),
            0x02 => Some(Self::IFrame),
            0x03 => Some(Self::PFrame),
            _ => None,
        }
    }

    /// Check if this is a keyframe
    pub fn is_keyframe(&self) -> bool {
        matches!(self, Self::IFrame | Self::SpsPps)
    }
}

/// Streaming status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StreamingStatus {
    /// Streaming is starting
    Starting,
    /// Streaming is active
    Streaming,
    /// Streaming is stopping
    Stopping,
    /// Streaming has stopped
    Stopped,
    /// Error occurred
    Error,
}

// ============================================================================
// Packet Structures
// ============================================================================

/// Information about a single camera on the device
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CameraInfo {
    /// Camera ID (0 = back, 1 = front typically)
    pub id: u32,
    /// Human-readable camera name
    pub name: String,
    /// Camera facing direction
    pub facing: CameraFacing,
    /// Maximum supported resolution
    #[serde(rename = "maxResolution")]
    pub max_resolution: Resolution,
    /// Supported resolutions
    pub resolutions: Vec<Resolution>,
}

/// Camera capability advertisement (Android → Desktop)
///
/// Sent when device connects to advertise available cameras and capabilities.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CameraCapability {
    /// List of available cameras
    pub cameras: Vec<CameraInfo>,
    /// Supported video codecs (e.g., ["h264", "vp9"])
    #[serde(rename = "supportedCodecs")]
    pub supported_codecs: Vec<String>,
    /// Whether audio streaming is supported
    #[serde(rename = "audioSupported")]
    pub audio_supported: bool,
    /// Maximum total resolution supported
    #[serde(rename = "maxResolution")]
    pub max_resolution: Resolution,
    /// Maximum supported bitrate in kbps
    #[serde(rename = "maxBitrate")]
    pub max_bitrate: u32,
    /// Maximum supported frame rate
    #[serde(rename = "maxFps")]
    pub max_fps: u32,
}

impl CameraCapability {
    /// Parse from packet body
    pub fn from_packet(packet: &Packet) -> Result<Self> {
        serde_json::from_value(packet.body.clone())
            .map_err(|e| crate::error::ProtocolError::InvalidPacket(e.to_string()))
    }

    /// Create a packet containing this capability info
    pub fn to_packet(&self) -> Packet {
        Packet::new(PACKET_TYPE_CAMERA_CAPABILITY, serde_json::to_value(self).unwrap())
    }
}

/// Request to start camera streaming (Desktop → Android)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CameraStart {
    /// ID of camera to use
    #[serde(rename = "cameraId")]
    pub camera_id: u32,
    /// Requested resolution
    pub resolution: Resolution,
    /// Requested frame rate
    pub fps: u32,
    /// Requested bitrate in kbps
    pub bitrate: u32,
    /// Video codec to use
    pub codec: String,
}

impl CameraStart {
    /// Create with default settings for 720p streaming
    pub fn default_720p(camera_id: u32) -> Self {
        Self {
            camera_id,
            resolution: Resolution::p720(),
            fps: 30,
            bitrate: 2000,
            codec: "h264".to_string(),
        }
    }

    /// Parse from packet body
    pub fn from_packet(packet: &Packet) -> Result<Self> {
        serde_json::from_value(packet.body.clone())
            .map_err(|e| crate::error::ProtocolError::InvalidPacket(e.to_string()))
    }

    /// Create a packet containing this start request
    pub fn to_packet(&self) -> Packet {
        Packet::new(PACKET_TYPE_CAMERA_START, serde_json::to_value(self).unwrap())
    }
}

/// Request to stop camera streaming (Desktop → Android)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CameraStop;

impl CameraStop {
    /// Create a stop packet
    pub fn to_packet() -> Packet {
        Packet::new(PACKET_TYPE_CAMERA_STOP, json!({}))
    }
}

/// Request to change camera settings while streaming (Desktop → Android)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CameraSettings {
    /// Switch to different camera
    #[serde(rename = "cameraId", skip_serializing_if = "Option::is_none")]
    pub camera_id: Option<u32>,
    /// Change resolution
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution: Option<Resolution>,
    /// Change frame rate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fps: Option<u32>,
    /// Change bitrate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitrate: Option<u32>,
    /// Enable/disable flash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flash: Option<bool>,
    /// Enable/disable autofocus
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autofocus: Option<bool>,
}

impl CameraSettings {
    /// Create settings to switch camera
    pub fn switch_camera(camera_id: u32) -> Self {
        Self {
            camera_id: Some(camera_id),
            ..Default::default()
        }
    }

    /// Create settings to change resolution
    pub fn change_resolution(resolution: Resolution) -> Self {
        Self {
            resolution: Some(resolution),
            ..Default::default()
        }
    }

    /// Parse from packet body
    pub fn from_packet(packet: &Packet) -> Result<Self> {
        serde_json::from_value(packet.body.clone())
            .map_err(|e| crate::error::ProtocolError::InvalidPacket(e.to_string()))
    }

    /// Create a packet containing these settings
    pub fn to_packet(&self) -> Packet {
        Packet::new(PACKET_TYPE_CAMERA_SETTINGS, serde_json::to_value(self).unwrap())
    }
}

/// Camera frame header (Android → Desktop)
///
/// The actual frame data is sent as payload after the packet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CameraFrame {
    /// Type of frame (SPS/PPS, I-frame, P-frame)
    #[serde(rename = "frameType")]
    pub frame_type: FrameType,
    /// Presentation timestamp in microseconds
    #[serde(rename = "timestampUs")]
    pub timestamp_us: u64,
    /// Frame sequence number
    #[serde(rename = "sequenceNumber")]
    pub sequence_number: u64,
    /// Size of frame data in bytes
    pub size: u64,
}

impl CameraFrame {
    /// Parse from packet body
    pub fn from_packet(packet: &Packet) -> Result<Self> {
        serde_json::from_value(packet.body.clone())
            .map_err(|e| crate::error::ProtocolError::InvalidPacket(e.to_string()))
    }

    /// Create a packet containing this frame header
    ///
    /// Note: The actual frame data is sent as payload
    pub fn to_packet(&self) -> Packet {
        Packet::new(PACKET_TYPE_CAMERA_FRAME, serde_json::to_value(self).unwrap())
            .with_payload_size(self.size as i64)
    }
}

/// Camera status update (Android → Desktop)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CameraStatus {
    /// Current streaming status
    pub status: StreamingStatus,
    /// Current camera ID
    #[serde(rename = "cameraId")]
    pub camera_id: u32,
    /// Current resolution
    pub resolution: Resolution,
    /// Current frame rate
    pub fps: u32,
    /// Current bitrate in kbps
    pub bitrate: u32,
    /// Error message if status is Error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl CameraStatus {
    /// Create a streaming status
    pub fn streaming(camera_id: u32, resolution: Resolution, fps: u32, bitrate: u32) -> Self {
        Self {
            status: StreamingStatus::Streaming,
            camera_id,
            resolution,
            fps,
            bitrate,
            error: None,
        }
    }

    /// Create a stopped status
    pub fn stopped() -> Self {
        Self {
            status: StreamingStatus::Stopped,
            camera_id: 0,
            resolution: Resolution::new(0, 0),
            fps: 0,
            bitrate: 0,
            error: None,
        }
    }

    /// Create an error status
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: StreamingStatus::Error,
            camera_id: 0,
            resolution: Resolution::new(0, 0),
            fps: 0,
            bitrate: 0,
            error: Some(message.into()),
        }
    }

    /// Parse from packet body
    pub fn from_packet(packet: &Packet) -> Result<Self> {
        serde_json::from_value(packet.body.clone())
            .map_err(|e| crate::error::ProtocolError::InvalidPacket(e.to_string()))
    }

    /// Create a packet containing this status
    pub fn to_packet(&self) -> Packet {
        Packet::new(PACKET_TYPE_CAMERA_STATUS, serde_json::to_value(self).unwrap())
    }
}

// ============================================================================
// Camera Plugin
// ============================================================================

/// Camera plugin for virtual webcam streaming
///
/// Manages camera capability exchange and streaming state between
/// Android device and COSMIC Desktop.
pub struct CameraPlugin {
    /// Plugin name
    name: String,
    /// Remote device camera capabilities
    remote_capabilities: Option<CameraCapability>,
    /// Current streaming status
    streaming_status: Option<CameraStatus>,
    /// Whether we're actively streaming
    is_streaming: bool,
    /// Current camera settings
    current_settings: Option<CameraStart>,
}

impl Default for CameraPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl CameraPlugin {
    /// Create a new camera plugin
    pub fn new() -> Self {
        Self {
            name: "camera".to_string(),
            remote_capabilities: None,
            streaming_status: None,
            is_streaming: false,
            current_settings: None,
        }
    }

    /// Get remote camera capabilities
    pub fn capabilities(&self) -> Option<&CameraCapability> {
        self.remote_capabilities.as_ref()
    }

    /// Check if remote device has camera capability
    pub fn has_camera(&self) -> bool {
        self.remote_capabilities
            .as_ref()
            .map(|c| !c.cameras.is_empty())
            .unwrap_or(false)
    }

    /// Get available cameras
    pub fn cameras(&self) -> Option<&[CameraInfo]> {
        self.remote_capabilities.as_ref().map(|c| c.cameras.as_slice())
    }

    /// Check if currently streaming
    pub fn is_streaming(&self) -> bool {
        self.is_streaming
    }

    /// Get current streaming status
    pub fn streaming_status(&self) -> Option<&CameraStatus> {
        self.streaming_status.as_ref()
    }

    /// Get current camera settings
    pub fn current_settings(&self) -> Option<&CameraStart> {
        self.current_settings.as_ref()
    }

    /// Create a packet to start camera streaming
    pub fn create_start_packet(&self, settings: CameraStart) -> Packet {
        settings.to_packet()
    }

    /// Create a packet to stop camera streaming
    pub fn create_stop_packet(&self) -> Packet {
        CameraStop::to_packet()
    }

    /// Create a packet to change camera settings
    pub fn create_settings_packet(&self, settings: CameraSettings) -> Packet {
        settings.to_packet()
    }

    /// Handle incoming camera capability packet
    fn handle_capability(&mut self, packet: &Packet) -> Result<()> {
        let capability = CameraCapability::from_packet(packet)?;
        info!(
            "Received camera capabilities: {} cameras, codecs: {:?}",
            capability.cameras.len(),
            capability.supported_codecs
        );
        self.remote_capabilities = Some(capability);
        Ok(())
    }

    /// Handle incoming camera status packet
    fn handle_status(&mut self, packet: &Packet) -> Result<()> {
        let status = CameraStatus::from_packet(packet)?;
        debug!(
            "Camera status: {:?}, {}x{} @ {}fps",
            status.status, status.resolution.width, status.resolution.height, status.fps
        );

        self.is_streaming = matches!(status.status, StreamingStatus::Streaming);
        self.streaming_status = Some(status);
        Ok(())
    }

    /// Handle incoming camera frame packet
    fn handle_frame(&mut self, packet: &Packet) -> Result<CameraFrame> {
        let frame = CameraFrame::from_packet(packet)?;
        debug!(
            "Camera frame: {:?}, seq={}, size={}",
            frame.frame_type, frame.sequence_number, frame.size
        );
        Ok(frame)
    }
}

#[async_trait]
impl Plugin for CameraPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn incoming_capabilities(&self) -> Vec<String> {
        vec![
            PACKET_TYPE_CAMERA_CAPABILITY.to_string(),
            PACKET_TYPE_CAMERA_FRAME.to_string(),
            PACKET_TYPE_CAMERA_STATUS.to_string(),
        ]
    }

    fn outgoing_capabilities(&self) -> Vec<String> {
        vec![
            PACKET_TYPE_CAMERA_START.to_string(),
            PACKET_TYPE_CAMERA_STOP.to_string(),
            PACKET_TYPE_CAMERA_SETTINGS.to_string(),
        ]
    }

    async fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
        match packet.packet_type.as_str() {
            PACKET_TYPE_CAMERA_CAPABILITY => {
                self.handle_capability(packet)?;
            }
            PACKET_TYPE_CAMERA_STATUS => {
                self.handle_status(packet)?;
            }
            PACKET_TYPE_CAMERA_FRAME => {
                // Frame handling is done separately as it has payload data
                self.handle_frame(packet)?;
            }
            _ => {
                warn!("Unknown camera packet type: {}", packet.packet_type);
            }
        }
        Ok(())
    }

    async fn initialize(&mut self) -> Result<()> {
        info!("Camera plugin initialized");
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("Camera plugin shutdown");
        self.is_streaming = false;
        self.streaming_status = None;
        Ok(())
    }
}

// ============================================================================
// Frame Receiver (Desktop-side frame processing)
// ============================================================================

/// Stream statistics for monitoring
#[derive(Debug, Clone, Default)]
pub struct StreamStats {
    /// Total frames received
    pub frames_received: u64,
    /// Total frames decoded
    pub frames_decoded: u64,
    /// Total frames written to V4L2
    pub frames_written: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Decode errors
    pub decode_errors: u64,
    /// Write errors
    pub write_errors: u64,
    /// Frames dropped (queue full)
    pub frames_dropped: u64,
    /// Last frame timestamp
    pub last_timestamp_us: u64,
    /// Start time (Unix timestamp ms)
    pub start_time_ms: u64,
}

impl StreamStats {
    /// Create new stats with current time
    pub fn new() -> Self {
        Self {
            start_time_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            ..Default::default()
        }
    }

    /// Calculate average FPS
    pub fn fps(&self) -> f64 {
        let elapsed_secs = self.elapsed_secs();
        if elapsed_secs > 0.0 {
            self.frames_decoded as f64 / elapsed_secs
        } else {
            0.0
        }
    }

    /// Calculate average bitrate in kbps
    pub fn bitrate_kbps(&self) -> f64 {
        let elapsed_secs = self.elapsed_secs();
        if elapsed_secs > 0.0 {
            (self.bytes_received as f64 * 8.0) / (elapsed_secs * 1000.0)
        } else {
            0.0
        }
    }

    /// Get elapsed time in seconds
    pub fn elapsed_secs(&self) -> f64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        (now.saturating_sub(self.start_time_ms)) as f64 / 1000.0
    }

    /// Get frame drop rate (0.0 - 1.0)
    pub fn drop_rate(&self) -> f64 {
        let total = self.frames_received + self.frames_dropped;
        if total > 0 {
            self.frames_dropped as f64 / total as f64
        } else {
            0.0
        }
    }

    /// Get average latency in milliseconds (if tracking enabled)
    pub fn avg_latency_ms(&self) -> Option<f64> {
        // Latency is tracked via NetworkStats
        None
    }
}

// ============================================================================
// Performance Optimization: Network Statistics
// ============================================================================

/// Network statistics for adaptive streaming
#[derive(Debug, Clone, Default)]
pub struct NetworkStats {
    /// Round-trip time in milliseconds
    pub rtt_ms: u32,
    /// Packet loss rate (0.0 - 1.0)
    pub packet_loss: f64,
    /// Jitter in milliseconds
    pub jitter_ms: u32,
    /// Available bandwidth estimate in kbps
    pub bandwidth_kbps: u32,
    /// Last update timestamp (Unix ms)
    pub last_update_ms: u64,
}

impl NetworkStats {
    /// Create new network stats
    pub fn new() -> Self {
        Self {
            bandwidth_kbps: 10000, // Assume good network initially
            ..Default::default()
        }
    }

    /// Update RTT measurement
    pub fn update_rtt(&mut self, rtt_ms: u32) {
        // Exponential moving average
        self.rtt_ms = if self.rtt_ms == 0 {
            rtt_ms
        } else {
            (self.rtt_ms * 7 + rtt_ms * 3) / 10
        };
        self.update_timestamp();
    }

    /// Update packet loss rate
    pub fn update_packet_loss(&mut self, packets_sent: u64, packets_received: u64) {
        if packets_sent > 0 {
            self.packet_loss = (packets_sent - packets_received) as f64 / packets_sent as f64;
        }
        self.update_timestamp();
    }

    fn update_timestamp(&mut self) {
        self.last_update_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
    }

    /// Check if network conditions are good
    pub fn is_good(&self) -> bool {
        self.rtt_ms < 50 && self.packet_loss < 0.01
    }

    /// Check if network conditions are degraded
    pub fn is_degraded(&self) -> bool {
        self.rtt_ms > 100 || self.packet_loss > 0.05
    }
}

// ============================================================================
// Performance Optimization: Adaptive Bitrate Controller
// ============================================================================

/// Adaptive bitrate controller for dynamic quality adjustment
#[derive(Debug, Clone)]
pub struct AdaptiveBitrateController {
    /// Current bitrate in kbps
    current_bitrate: u32,
    /// Minimum bitrate in kbps
    min_bitrate: u32,
    /// Maximum bitrate in kbps
    max_bitrate: u32,
    /// Target latency in milliseconds (reserved for future latency-based adjustment)
    #[allow(dead_code)]
    target_latency_ms: u32,
    /// Last adjustment timestamp
    last_adjustment_ms: u64,
    /// Adjustment cooldown in milliseconds
    cooldown_ms: u64,
}

impl Default for AdaptiveBitrateController {
    fn default() -> Self {
        Self {
            current_bitrate: 2000,
            min_bitrate: 500,
            max_bitrate: 8000,
            target_latency_ms: 100,
            last_adjustment_ms: 0,
            cooldown_ms: 2000, // 2 second cooldown between adjustments
        }
    }
}

impl AdaptiveBitrateController {
    /// Create a new adaptive bitrate controller
    pub fn new(initial_bitrate: u32, min_bitrate: u32, max_bitrate: u32) -> Self {
        Self {
            current_bitrate: initial_bitrate.clamp(min_bitrate, max_bitrate),
            min_bitrate,
            max_bitrate,
            ..Default::default()
        }
    }

    /// Get current bitrate
    pub fn current_bitrate(&self) -> u32 {
        self.current_bitrate
    }

    /// Adjust bitrate based on network conditions
    ///
    /// Returns Some(new_bitrate) if adjustment is needed, None otherwise
    pub fn adjust(&mut self, network_stats: &NetworkStats) -> Option<u32> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Check cooldown
        if now - self.last_adjustment_ms < self.cooldown_ms {
            return None;
        }

        let new_bitrate = if network_stats.is_degraded() {
            // Network degraded: reduce bitrate by 20%
            let reduced = (self.current_bitrate as f64 * 0.8) as u32;
            reduced.max(self.min_bitrate)
        } else if network_stats.is_good() && self.current_bitrate < self.max_bitrate {
            // Network good: increase bitrate by 10%
            let increased = (self.current_bitrate as f64 * 1.1) as u32;
            increased.min(self.max_bitrate)
        } else {
            self.current_bitrate
        };

        if new_bitrate != self.current_bitrate {
            self.current_bitrate = new_bitrate;
            self.last_adjustment_ms = now;
            Some(new_bitrate)
        } else {
            None
        }
    }

    /// Force a bitrate change (e.g., user request)
    pub fn set_bitrate(&mut self, bitrate: u32) {
        self.current_bitrate = bitrate.clamp(self.min_bitrate, self.max_bitrate);
    }
}

// ============================================================================
// Performance Optimization: Smart Frame Dropping
// ============================================================================

/// Frame priority for smart dropping
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FramePriority {
    /// Lowest priority - can be dropped freely
    Low = 0,
    /// Medium priority - drop if queue is full
    Medium = 1,
    /// High priority - only drop in extreme cases
    High = 2,
    /// Critical priority - never drop (I-frames, SPS/PPS)
    Critical = 3,
}

impl FrameType {
    /// Get the drop priority for this frame type
    pub fn priority(&self) -> FramePriority {
        match self {
            FrameType::SpsPps => FramePriority::Critical,
            FrameType::IFrame => FramePriority::Critical,
            FrameType::PFrame => FramePriority::Low,
        }
    }

    /// Check if this frame can be dropped when queue is full
    pub fn can_drop(&self) -> bool {
        self.priority() < FramePriority::High
    }
}

/// Smart frame dropper for maintaining low latency
#[derive(Debug, Clone)]
pub struct SmartFrameDropper {
    /// Maximum queue size before dropping
    max_queue_size: usize,
    /// Target queue size
    target_queue_size: usize,
    /// Consecutive drops counter
    consecutive_drops: u32,
    /// Maximum consecutive P-frame drops before requesting I-frame
    max_consecutive_drops: u32,
}

impl Default for SmartFrameDropper {
    fn default() -> Self {
        Self {
            max_queue_size: 10,
            target_queue_size: 3,
            consecutive_drops: 0,
            max_consecutive_drops: 30, // About 1 second at 30fps
        }
    }
}

impl SmartFrameDropper {
    /// Create a new smart frame dropper
    pub fn new(max_queue_size: usize, target_queue_size: usize) -> Self {
        Self {
            max_queue_size,
            target_queue_size,
            ..Default::default()
        }
    }

    /// Decide whether to drop a frame based on queue state
    ///
    /// Returns (should_drop, request_keyframe)
    pub fn should_drop(&mut self, frame_type: FrameType, current_queue_size: usize) -> (bool, bool) {
        // Never drop critical frames
        if !frame_type.can_drop() {
            self.consecutive_drops = 0;
            return (false, false);
        }

        // Drop if queue is too large
        if current_queue_size >= self.max_queue_size {
            self.consecutive_drops += 1;

            // Request keyframe if too many consecutive drops
            let request_keyframe = self.consecutive_drops >= self.max_consecutive_drops;
            if request_keyframe {
                self.consecutive_drops = 0;
            }

            return (true, request_keyframe);
        }

        // Keep frame if queue is at target or below
        if current_queue_size <= self.target_queue_size {
            self.consecutive_drops = 0;
            return (false, false);
        }

        // Queue is between target and max - probabilistic drop
        let drop_probability = (current_queue_size - self.target_queue_size) as f64
            / (self.max_queue_size - self.target_queue_size) as f64;

        // Use simple deterministic approach for now
        if drop_probability > 0.5 {
            self.consecutive_drops += 1;
            (true, self.consecutive_drops >= self.max_consecutive_drops)
        } else {
            self.consecutive_drops = 0;
            (false, false)
        }
    }

    /// Reset the dropper state
    pub fn reset(&mut self) {
        self.consecutive_drops = 0;
    }
}

// ============================================================================
// Performance Optimization: Latency Tracker
// ============================================================================

/// Latency tracker for end-to-end latency measurement
#[derive(Debug, Clone)]
pub struct LatencyTracker {
    /// Recent latency samples (circular buffer)
    samples: Vec<u32>,
    /// Current sample index
    sample_index: usize,
    /// Maximum samples to keep
    max_samples: usize,
    /// Minimum observed latency
    min_latency_ms: u32,
    /// Maximum observed latency
    max_latency_ms: u32,
}

impl Default for LatencyTracker {
    fn default() -> Self {
        Self {
            samples: Vec::with_capacity(100),
            sample_index: 0,
            max_samples: 100,
            min_latency_ms: u32::MAX,
            max_latency_ms: 0,
        }
    }
}

impl LatencyTracker {
    /// Record a latency sample
    pub fn record(&mut self, latency_ms: u32) {
        if self.samples.len() < self.max_samples {
            self.samples.push(latency_ms);
        } else {
            self.samples[self.sample_index] = latency_ms;
        }
        self.sample_index = (self.sample_index + 1) % self.max_samples;

        self.min_latency_ms = self.min_latency_ms.min(latency_ms);
        self.max_latency_ms = self.max_latency_ms.max(latency_ms);
    }

    /// Get average latency in milliseconds
    pub fn average_ms(&self) -> f64 {
        if self.samples.is_empty() {
            0.0
        } else {
            self.samples.iter().map(|&x| x as f64).sum::<f64>() / self.samples.len() as f64
        }
    }

    /// Get P95 latency in milliseconds
    pub fn p95_ms(&self) -> u32 {
        if self.samples.is_empty() {
            return 0;
        }
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();
        let idx = (sorted.len() as f64 * 0.95) as usize;
        sorted.get(idx.min(sorted.len() - 1)).copied().unwrap_or(0)
    }

    /// Get minimum observed latency
    pub fn min_ms(&self) -> u32 {
        if self.min_latency_ms == u32::MAX {
            0
        } else {
            self.min_latency_ms
        }
    }

    /// Get maximum observed latency
    pub fn max_ms(&self) -> u32 {
        self.max_latency_ms
    }

    /// Check if latency is within acceptable range
    pub fn is_acceptable(&self, target_ms: u32) -> bool {
        self.average_ms() <= target_ms as f64
    }

    /// Reset the tracker
    pub fn reset(&mut self) {
        self.samples.clear();
        self.sample_index = 0;
        self.min_latency_ms = u32::MAX;
        self.max_latency_ms = 0;
    }
}

/// Encoded frame ready for decoding
#[derive(Debug, Clone)]
pub struct EncodedFrame {
    /// Frame type (SPS/PPS, I-frame, P-frame)
    pub frame_type: FrameType,
    /// Presentation timestamp in microseconds
    pub timestamp_us: u64,
    /// Sequence number
    pub sequence_number: u64,
    /// Raw H.264 NAL unit data
    pub data: Vec<u8>,
}

impl EncodedFrame {
    /// Create from CameraFrame header and payload data
    pub fn from_frame_and_payload(frame: &CameraFrame, data: Vec<u8>) -> Self {
        Self {
            frame_type: frame.frame_type,
            timestamp_us: frame.timestamp_us,
            sequence_number: frame.sequence_number,
            data,
        }
    }
}

/// Frame receiver callback interface
///
/// Implement this trait to receive decoded frames and status updates.
pub trait FrameReceiverCallback: Send + Sync {
    /// Called when a frame is successfully decoded and written
    fn on_frame_written(&self, timestamp_us: u64);

    /// Called when statistics are updated
    fn on_stats_update(&self, stats: &StreamStats);

    /// Called when an error occurs
    fn on_error(&self, error: &str);

    /// Called when the stream starts
    fn on_stream_started(&self);

    /// Called when the stream stops
    fn on_stream_stopped(&self);
}

/// Frame receiver for processing camera frames from Android
///
/// Receives encoded H.264 frames, decodes them, and writes to V4L2 device.
/// This is the desktop-side counterpart to Android's CameraStreamClient.
///
/// ## Usage
///
/// ```rust,ignore
/// use cosmic_connect_core::plugins::camera::{FrameReceiver, FrameReceiverConfig};
///
/// let config = FrameReceiverConfig::default();
/// let receiver = FrameReceiver::new(config, callback);
///
/// // Start receiving frames
/// receiver.start().await?;
///
/// // Queue frames as they arrive from network
/// receiver.queue_frame(encoded_frame).await?;
///
/// // Stop when done
/// receiver.stop().await?;
/// ```
#[cfg(feature = "video")]
pub struct FrameReceiver {
    /// Configuration
    config: FrameReceiverConfig,
    /// Camera daemon for V4L2 output
    daemon: crate::video::camera_daemon::CameraDaemon,
    /// Statistics
    stats: std::sync::Arc<std::sync::RwLock<StreamStats>>,
    /// Whether receiver is running
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Callback for events
    callback: Option<Box<dyn FrameReceiverCallback>>,
}

/// Configuration for frame receiver
#[cfg(feature = "video")]
#[derive(Debug, Clone)]
pub struct FrameReceiverConfig {
    /// V4L2 device path
    pub device_path: std::path::PathBuf,
    /// Video width
    pub width: u32,
    /// Video height
    pub height: u32,
    /// Target FPS (for statistics)
    pub fps: u32,
    /// Stats update interval in frames
    pub stats_interval: u64,
}

#[cfg(feature = "video")]
impl Default for FrameReceiverConfig {
    fn default() -> Self {
        Self {
            device_path: std::path::PathBuf::from("/dev/video10"),
            width: 1280,
            height: 720,
            fps: 30,
            stats_interval: 30,
        }
    }
}

#[cfg(feature = "video")]
impl FrameReceiver {
    /// Create a new frame receiver
    pub fn new(config: FrameReceiverConfig, callback: Option<Box<dyn FrameReceiverCallback>>) -> Self {
        use crate::video::camera_daemon::{CameraDaemon, CameraDaemonConfig};
        use crate::video::frame::PixelFormat;

        let daemon_config = CameraDaemonConfig {
            device_path: config.device_path.clone(),
            width: config.width,
            height: config.height,
            fps: config.fps,
            output_format: PixelFormat::YUYV,
        };

        Self {
            config,
            daemon: CameraDaemon::new(daemon_config),
            stats: std::sync::Arc::new(std::sync::RwLock::new(StreamStats::new())),
            running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            callback,
        }
    }

    /// Check if receiver is running
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get current statistics
    pub fn stats(&self) -> StreamStats {
        self.stats.read().unwrap().clone()
    }

    /// Start the frame receiver
    pub async fn start(&mut self) -> crate::error::Result<()> {
        if self.is_running() {
            return Err(crate::error::ProtocolError::Other(
                "Frame receiver already running".to_string(),
            ));
        }

        info!("Starting frame receiver: {}x{} @ {}fps",
            self.config.width, self.config.height, self.config.fps);

        // Start the daemon
        self.daemon.start().await.map_err(|e| {
            crate::error::ProtocolError::Other(format!("Failed to start daemon: {}", e))
        })?;

        self.running.store(true, std::sync::atomic::Ordering::Relaxed);

        // Reset stats
        *self.stats.write().unwrap() = StreamStats::new();

        if let Some(ref cb) = self.callback {
            cb.on_stream_started();
        }

        Ok(())
    }

    /// Stop the frame receiver
    pub async fn stop(&mut self) -> crate::error::Result<()> {
        if !self.is_running() {
            return Ok(());
        }

        info!("Stopping frame receiver");

        self.running.store(false, std::sync::atomic::Ordering::Relaxed);

        // Stop the daemon
        self.daemon.stop().await.map_err(|e| {
            crate::error::ProtocolError::Other(format!("Failed to stop daemon: {}", e))
        })?;

        // Log final stats
        let stats = self.stats();
        info!(
            "Frame receiver stopped: {} frames, {:.1} fps, {:.1} kbps, {:.1}% dropped",
            stats.frames_decoded,
            stats.fps(),
            stats.bitrate_kbps(),
            stats.drop_rate() * 100.0
        );

        if let Some(ref cb) = self.callback {
            cb.on_stream_stopped();
        }

        Ok(())
    }

    /// Queue an encoded frame for processing
    pub async fn queue_frame(&self, frame: EncodedFrame) -> crate::error::Result<()> {
        if !self.is_running() {
            return Err(crate::error::ProtocolError::Other(
                "Frame receiver not running".to_string(),
            ));
        }

        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.frames_received += 1;
            stats.bytes_received += frame.data.len() as u64;
            stats.last_timestamp_us = frame.timestamp_us;
        }

        // Send to daemon for processing
        self.daemon
            .process_frame(frame.data, frame.frame_type, frame.timestamp_us)
            .await
            .map_err(|e| {
                // Update error stats
                {
                    let mut stats = self.stats.write().unwrap();
                    stats.decode_errors += 1;
                }
                crate::error::ProtocolError::Other(format!("Failed to process frame: {}", e))
            })?;

        // Update decoded count
        {
            let mut stats = self.stats.write().unwrap();
            stats.frames_decoded += 1;
            stats.frames_written += 1;

            // Periodic stats callback
            if stats.frames_decoded % self.config.stats_interval == 0 {
                if let Some(ref cb) = self.callback {
                    cb.on_stats_update(&stats);
                }
            }
        }

        if let Some(ref cb) = self.callback {
            cb.on_frame_written(frame.timestamp_us);
        }

        Ok(())
    }

    /// Queue SPS/PPS configuration data
    pub async fn queue_sps_pps(&self, data: Vec<u8>) -> crate::error::Result<()> {
        let frame = EncodedFrame {
            frame_type: FrameType::SpsPps,
            timestamp_us: 0,
            sequence_number: 0,
            data,
        };
        self.queue_frame(frame).await
    }

    /// Create from camera capability negotiation
    pub fn from_capability(
        capability: &CameraCapability,
        settings: &CameraStart,
        callback: Option<Box<dyn FrameReceiverCallback>>,
    ) -> Self {
        let config = FrameReceiverConfig {
            width: settings.resolution.width,
            height: settings.resolution.height,
            fps: settings.fps,
            ..Default::default()
        };
        Self::new(config, callback)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolution_presets() {
        assert_eq!(Resolution::p480(), Resolution::new(854, 480));
        assert_eq!(Resolution::p720(), Resolution::new(1280, 720));
        assert_eq!(Resolution::p1080(), Resolution::new(1920, 1080));
    }

    #[test]
    fn test_resolution_pixels() {
        let res = Resolution::p720();
        assert_eq!(res.pixels(), 1280 * 720);
    }

    #[test]
    fn test_frame_type_from_u8() {
        assert_eq!(FrameType::from_u8(0x01), Some(FrameType::SpsPps));
        assert_eq!(FrameType::from_u8(0x02), Some(FrameType::IFrame));
        assert_eq!(FrameType::from_u8(0x03), Some(FrameType::PFrame));
        assert_eq!(FrameType::from_u8(0xFF), None);
    }

    #[test]
    fn test_frame_type_is_keyframe() {
        assert!(FrameType::SpsPps.is_keyframe());
        assert!(FrameType::IFrame.is_keyframe());
        assert!(!FrameType::PFrame.is_keyframe());
    }

    #[test]
    fn test_camera_capability_serialization() {
        let capability = CameraCapability {
            cameras: vec![CameraInfo {
                id: 0,
                name: "Back Camera".to_string(),
                facing: CameraFacing::Back,
                max_resolution: Resolution::p1080(),
                resolutions: vec![Resolution::p1080(), Resolution::p720(), Resolution::p480()],
            }],
            supported_codecs: vec!["h264".to_string()],
            audio_supported: false,
            max_resolution: Resolution::p1080(),
            max_bitrate: 8000,
            max_fps: 60,
        };

        let packet = capability.to_packet();
        assert_eq!(packet.packet_type, PACKET_TYPE_CAMERA_CAPABILITY);

        let parsed = CameraCapability::from_packet(&packet).unwrap();
        assert_eq!(parsed.cameras.len(), 1);
        assert_eq!(parsed.cameras[0].name, "Back Camera");
        assert_eq!(parsed.supported_codecs, vec!["h264"]);
    }

    #[test]
    fn test_camera_start_serialization() {
        let start = CameraStart::default_720p(0);
        let packet = start.to_packet();
        assert_eq!(packet.packet_type, PACKET_TYPE_CAMERA_START);

        let parsed = CameraStart::from_packet(&packet).unwrap();
        assert_eq!(parsed.camera_id, 0);
        assert_eq!(parsed.resolution, Resolution::p720());
        assert_eq!(parsed.fps, 30);
        assert_eq!(parsed.bitrate, 2000);
        assert_eq!(parsed.codec, "h264");
    }

    #[test]
    fn test_camera_stop_serialization() {
        let packet = CameraStop::to_packet();
        assert_eq!(packet.packet_type, PACKET_TYPE_CAMERA_STOP);
    }

    #[test]
    fn test_camera_settings_serialization() {
        let settings = CameraSettings {
            camera_id: Some(1),
            resolution: Some(Resolution::p720()),
            fps: None,
            bitrate: None,
            flash: Some(true),
            autofocus: None,
        };

        let packet = settings.to_packet();
        assert_eq!(packet.packet_type, PACKET_TYPE_CAMERA_SETTINGS);

        let json = serde_json::to_string(&packet.body).unwrap();
        // Optional None fields should be omitted
        assert!(!json.contains("fps"));
        assert!(!json.contains("autofocus"));
        // Present fields should be included
        assert!(json.contains("cameraId"));
        assert!(json.contains("flash"));
    }

    #[test]
    fn test_camera_frame_serialization() {
        let frame = CameraFrame {
            frame_type: FrameType::IFrame,
            timestamp_us: 1234567890,
            sequence_number: 42,
            size: 65536,
        };

        let packet = frame.to_packet();
        assert_eq!(packet.packet_type, PACKET_TYPE_CAMERA_FRAME);
        assert_eq!(packet.payload_size, Some(65536));

        let parsed = CameraFrame::from_packet(&packet).unwrap();
        assert_eq!(parsed.frame_type, FrameType::IFrame);
        assert_eq!(parsed.timestamp_us, 1234567890);
        assert_eq!(parsed.sequence_number, 42);
    }

    #[test]
    fn test_camera_status_serialization() {
        let status = CameraStatus::streaming(0, Resolution::p720(), 30, 2000);
        let packet = status.to_packet();
        assert_eq!(packet.packet_type, PACKET_TYPE_CAMERA_STATUS);

        let parsed = CameraStatus::from_packet(&packet).unwrap();
        assert_eq!(parsed.status, StreamingStatus::Streaming);
        assert_eq!(parsed.resolution, Resolution::p720());
    }

    #[test]
    fn test_camera_status_error() {
        let status = CameraStatus::error("Camera access denied");
        assert_eq!(status.status, StreamingStatus::Error);
        assert_eq!(status.error, Some("Camera access denied".to_string()));
    }

    #[test]
    fn test_camera_plugin_new() {
        let plugin = CameraPlugin::new();
        assert_eq!(plugin.name(), "camera");
        assert!(!plugin.has_camera());
        assert!(!plugin.is_streaming());
    }

    #[test]
    fn test_camera_plugin_capabilities() {
        let plugin = CameraPlugin::new();
        let incoming = plugin.incoming_capabilities();
        let outgoing = plugin.outgoing_capabilities();

        assert!(incoming.contains(&PACKET_TYPE_CAMERA_CAPABILITY.to_string()));
        assert!(incoming.contains(&PACKET_TYPE_CAMERA_FRAME.to_string()));
        assert!(incoming.contains(&PACKET_TYPE_CAMERA_STATUS.to_string()));

        assert!(outgoing.contains(&PACKET_TYPE_CAMERA_START.to_string()));
        assert!(outgoing.contains(&PACKET_TYPE_CAMERA_STOP.to_string()));
        assert!(outgoing.contains(&PACKET_TYPE_CAMERA_SETTINGS.to_string()));
    }

    #[tokio::test]
    async fn test_camera_plugin_handle_capability() {
        let mut plugin = CameraPlugin::new();

        let capability = CameraCapability {
            cameras: vec![
                CameraInfo {
                    id: 0,
                    name: "Back Camera".to_string(),
                    facing: CameraFacing::Back,
                    max_resolution: Resolution::p1080(),
                    resolutions: vec![Resolution::p1080(), Resolution::p720()],
                },
                CameraInfo {
                    id: 1,
                    name: "Front Camera".to_string(),
                    facing: CameraFacing::Front,
                    max_resolution: Resolution::p720(),
                    resolutions: vec![Resolution::p720()],
                },
            ],
            supported_codecs: vec!["h264".to_string()],
            audio_supported: false,
            max_resolution: Resolution::p1080(),
            max_bitrate: 8000,
            max_fps: 60,
        };

        let packet = capability.to_packet();
        plugin.handle_packet(&packet).await.unwrap();

        assert!(plugin.has_camera());
        assert_eq!(plugin.cameras().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_camera_plugin_handle_status() {
        let mut plugin = CameraPlugin::new();

        let status = CameraStatus::streaming(0, Resolution::p720(), 30, 2000);
        let packet = status.to_packet();
        plugin.handle_packet(&packet).await.unwrap();

        assert!(plugin.is_streaming());
        assert_eq!(
            plugin.streaming_status().unwrap().status,
            StreamingStatus::Streaming
        );
    }

    #[test]
    fn test_stream_stats_new() {
        let stats = StreamStats::new();
        assert_eq!(stats.frames_received, 0);
        assert_eq!(stats.frames_decoded, 0);
        assert!(stats.start_time_ms > 0);
    }

    #[test]
    fn test_stream_stats_fps() {
        let mut stats = StreamStats::new();
        stats.frames_decoded = 30;
        // Simulate 1 second elapsed by adjusting start time
        stats.start_time_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
            - 1000;

        let fps = stats.fps();
        assert!(fps > 25.0 && fps < 35.0); // Allow some variance
    }

    #[test]
    fn test_stream_stats_drop_rate() {
        let mut stats = StreamStats::new();
        stats.frames_received = 90;
        stats.frames_dropped = 10;

        let drop_rate = stats.drop_rate();
        assert!((drop_rate - 0.1).abs() < 0.01); // 10% drop rate
    }

    #[test]
    fn test_encoded_frame_from_camera_frame() {
        let camera_frame = CameraFrame {
            frame_type: FrameType::IFrame,
            timestamp_us: 1234567890,
            sequence_number: 42,
            size: 1024,
        };

        let payload = vec![0u8; 1024];
        let encoded = EncodedFrame::from_frame_and_payload(&camera_frame, payload.clone());

        assert_eq!(encoded.frame_type, FrameType::IFrame);
        assert_eq!(encoded.timestamp_us, 1234567890);
        assert_eq!(encoded.sequence_number, 42);
        assert_eq!(encoded.data.len(), 1024);
    }

    // ========================================================================
    // Performance Optimization Tests
    // ========================================================================

    #[test]
    fn test_network_stats_rtt_smoothing() {
        let mut stats = NetworkStats::new();

        // Initial RTT
        stats.update_rtt(100);
        assert_eq!(stats.rtt_ms, 100);

        // Smoothed RTT (EMA: 70% old + 30% new)
        stats.update_rtt(50);
        let expected = (100 * 7 + 50 * 3) / 10;
        assert_eq!(stats.rtt_ms, expected); // 85ms
    }

    #[test]
    fn test_network_stats_conditions() {
        let mut stats = NetworkStats::new();

        // Good conditions
        stats.rtt_ms = 30;
        stats.packet_loss = 0.0;
        assert!(stats.is_good());
        assert!(!stats.is_degraded());

        // Degraded conditions
        stats.rtt_ms = 150;
        assert!(!stats.is_good());
        assert!(stats.is_degraded());

        // High packet loss
        stats.rtt_ms = 30;
        stats.packet_loss = 0.1;
        assert!(stats.is_degraded());
    }

    #[test]
    fn test_adaptive_bitrate_controller_default() {
        let controller = AdaptiveBitrateController::default();
        assert_eq!(controller.current_bitrate(), 2000);
    }

    #[test]
    fn test_adaptive_bitrate_reduce_on_degraded() {
        let mut controller = AdaptiveBitrateController::new(2000, 500, 8000);
        controller.last_adjustment_ms = 0; // Reset cooldown

        let mut stats = NetworkStats::new();
        stats.rtt_ms = 150; // Degraded network

        let new_bitrate = controller.adjust(&stats);
        assert!(new_bitrate.is_some());
        assert_eq!(new_bitrate.unwrap(), 1600); // 20% reduction
    }

    #[test]
    fn test_adaptive_bitrate_increase_on_good() {
        let mut controller = AdaptiveBitrateController::new(2000, 500, 8000);
        controller.last_adjustment_ms = 0; // Reset cooldown

        let mut stats = NetworkStats::new();
        stats.rtt_ms = 30; // Good network
        stats.packet_loss = 0.0;

        let new_bitrate = controller.adjust(&stats);
        assert!(new_bitrate.is_some());
        assert_eq!(new_bitrate.unwrap(), 2200); // 10% increase
    }

    #[test]
    fn test_adaptive_bitrate_respects_bounds() {
        let mut controller = AdaptiveBitrateController::new(600, 500, 8000);
        controller.last_adjustment_ms = 0;

        let mut stats = NetworkStats::new();
        stats.rtt_ms = 200; // Very degraded

        let new_bitrate = controller.adjust(&stats);
        assert!(new_bitrate.is_some());
        assert_eq!(new_bitrate.unwrap(), 500); // Clamped to min
    }

    #[test]
    fn test_frame_type_priority() {
        assert_eq!(FrameType::SpsPps.priority(), FramePriority::Critical);
        assert_eq!(FrameType::IFrame.priority(), FramePriority::Critical);
        assert_eq!(FrameType::PFrame.priority(), FramePriority::Low);
    }

    #[test]
    fn test_frame_type_can_drop() {
        assert!(!FrameType::SpsPps.can_drop());
        assert!(!FrameType::IFrame.can_drop());
        assert!(FrameType::PFrame.can_drop());
    }

    #[test]
    fn test_smart_frame_dropper_never_drops_critical() {
        let mut dropper = SmartFrameDropper::new(5, 2);

        // Even with full queue, never drop I-frames
        let (should_drop, _) = dropper.should_drop(FrameType::IFrame, 10);
        assert!(!should_drop);

        // Never drop SPS/PPS
        let (should_drop, _) = dropper.should_drop(FrameType::SpsPps, 10);
        assert!(!should_drop);
    }

    #[test]
    fn test_smart_frame_dropper_drops_p_frames() {
        let mut dropper = SmartFrameDropper::new(5, 2);

        // P-frames should be dropped when queue is full
        let (should_drop, _) = dropper.should_drop(FrameType::PFrame, 10);
        assert!(should_drop);
    }

    #[test]
    fn test_smart_frame_dropper_keeps_frames_at_target() {
        let mut dropper = SmartFrameDropper::new(10, 3);

        // Keep frames when queue is at or below target
        let (should_drop, _) = dropper.should_drop(FrameType::PFrame, 2);
        assert!(!should_drop);
    }

    #[test]
    fn test_smart_frame_dropper_requests_keyframe() {
        let mut dropper = SmartFrameDropper::new(5, 2);
        dropper.max_consecutive_drops = 3;

        // Simulate consecutive drops
        for _ in 0..2 {
            let (_, request_keyframe) = dropper.should_drop(FrameType::PFrame, 10);
            assert!(!request_keyframe);
        }

        // Third consecutive drop should request keyframe
        let (should_drop, request_keyframe) = dropper.should_drop(FrameType::PFrame, 10);
        assert!(should_drop);
        assert!(request_keyframe);
    }

    #[test]
    fn test_latency_tracker_average() {
        let mut tracker = LatencyTracker::default();

        tracker.record(50);
        tracker.record(60);
        tracker.record(70);

        let avg = tracker.average_ms();
        assert!((avg - 60.0).abs() < 0.1);
    }

    #[test]
    fn test_latency_tracker_p95() {
        let mut tracker = LatencyTracker::default();

        // Record 100 samples: 1, 2, 3, ..., 100
        for i in 1..=100 {
            tracker.record(i);
        }

        let p95 = tracker.p95_ms();
        assert!(p95 >= 95 && p95 <= 96);
    }

    #[test]
    fn test_latency_tracker_min_max() {
        let mut tracker = LatencyTracker::default();

        tracker.record(50);
        tracker.record(100);
        tracker.record(25);

        assert_eq!(tracker.min_ms(), 25);
        assert_eq!(tracker.max_ms(), 100);
    }

    #[test]
    fn test_latency_tracker_acceptable() {
        let mut tracker = LatencyTracker::default();

        tracker.record(50);
        tracker.record(60);
        tracker.record(70);

        assert!(tracker.is_acceptable(100)); // 60ms avg < 100ms target
        assert!(!tracker.is_acceptable(50)); // 60ms avg > 50ms target
    }

    #[test]
    fn test_latency_tracker_reset() {
        let mut tracker = LatencyTracker::default();

        tracker.record(100);
        tracker.record(200);

        tracker.reset();

        assert_eq!(tracker.average_ms(), 0.0);
        assert_eq!(tracker.min_ms(), 0);
        assert_eq!(tracker.max_ms(), 0);
    }
}
