//! Camera Daemon
//!
//! Main daemon that receives H.264 frames from Android, decodes them,
//! and writes to V4L2 loopback device for virtual webcam support.

use crate::plugins::camera::{CameraFrame, FrameType};
use crate::video::frame::{PixelFormat, VideoFrame};
use crate::video::h264_decoder::{DecoderError, H264Decoder};
use crate::video::performance::PerformanceMonitor;
use crate::video::v4l2_device::{V4l2Error, V4l2LoopbackDevice};
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Error types for camera daemon
#[derive(Debug)]
pub enum DaemonError {
    /// V4L2 device error
    V4l2Error(V4l2Error),
    /// Decoder error
    DecoderError(DecoderError),
    /// Daemon not running
    NotRunning,
    /// Already running
    AlreadyRunning,
    /// Channel error
    ChannelError(String),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaemonError::V4l2Error(e) => write!(f, "V4L2 error: {}", e),
            DaemonError::DecoderError(e) => write!(f, "Decoder error: {}", e),
            DaemonError::NotRunning => write!(f, "Camera daemon is not running"),
            DaemonError::AlreadyRunning => write!(f, "Camera daemon is already running"),
            DaemonError::ChannelError(msg) => write!(f, "Channel error: {}", msg),
        }
    }
}

impl std::error::Error for DaemonError {}

impl From<V4l2Error> for DaemonError {
    fn from(e: V4l2Error) -> Self {
        DaemonError::V4l2Error(e)
    }
}

impl From<DecoderError> for DaemonError {
    fn from(e: DecoderError) -> Self {
        DaemonError::DecoderError(e)
    }
}

/// Configuration for the camera daemon
#[derive(Debug, Clone)]
pub struct CameraDaemonConfig {
    /// V4L2 loopback device path
    pub device_path: PathBuf,
    /// Output video width
    pub width: u32,
    /// Output video height
    pub height: u32,
    /// Target frame rate (for statistics)
    pub fps: u32,
    /// Output pixel format (YUYV is most compatible)
    pub output_format: PixelFormat,
    /// Frame queue size (larger = more latency, smaller = more drops)
    pub queue_size: usize,
    /// Enable performance monitoring
    pub enable_perf_monitoring: bool,
}

impl Default for CameraDaemonConfig {
    fn default() -> Self {
        Self {
            device_path: PathBuf::from("/dev/video10"),
            width: 1280,
            height: 720,
            fps: 30,
            output_format: PixelFormat::YUYV,
            queue_size: 5, // Reduced from 10 for lower latency (Issue #110)
            enable_perf_monitoring: true,
        }
    }
}

impl CameraDaemonConfig {
    /// Create config for 720p @ 30fps
    pub fn hd_720p() -> Self {
        Self {
            width: 1280,
            height: 720,
            fps: 30,
            ..Default::default()
        }
    }

    /// Create config for 1080p @ 30fps
    pub fn fhd_1080p() -> Self {
        Self {
            width: 1920,
            height: 1080,
            fps: 30,
            ..Default::default()
        }
    }
}

/// Frame data for the processing queue
struct FrameData {
    /// Raw H.264 NAL unit data
    data: Vec<u8>,
    /// Frame type
    frame_type: FrameType,
    /// Timestamp in microseconds
    timestamp_us: u64,
}

/// Camera daemon statistics
#[derive(Debug, Clone, Default)]
pub struct DaemonStats {
    /// Total frames received
    pub frames_received: u64,
    /// Frames successfully decoded
    pub frames_decoded: u64,
    /// Frames written to V4L2
    pub frames_written: u64,
    /// Decode errors
    pub decode_errors: u64,
    /// Write errors
    pub write_errors: u64,
    /// Frames dropped (queue full)
    pub frames_dropped: u64,
}

/// Camera daemon for receiving and processing Android camera streams
///
/// Manages the full pipeline:
/// 1. Receive H.264 frames from Android via COSMIC Connect
/// 2. Decode frames using OpenH264
/// 3. Convert to V4L2-compatible format
/// 4. Write to V4L2 loopback device
///
/// ## Performance Optimizations (Issue #110)
///
/// - Reduced queue size for lower latency
/// - Performance monitoring integration
/// - Optimized frame conversion
/// - Pre-allocated decode buffers
pub struct CameraDaemon {
    /// Configuration
    config: CameraDaemonConfig,
    /// Running state
    running: Arc<AtomicBool>,
    /// Frame sender (to processing task)
    frame_tx: Option<mpsc::Sender<FrameData>>,
    /// Statistics
    stats: Arc<DaemonStatsInner>,
    /// Performance monitor
    perf_monitor: Option<Arc<PerformanceMonitor>>,
}

/// Inner statistics with atomic counters
struct DaemonStatsInner {
    frames_received: AtomicU64,
    frames_decoded: AtomicU64,
    frames_written: AtomicU64,
    decode_errors: AtomicU64,
    write_errors: AtomicU64,
    frames_dropped: AtomicU64,
}

impl Default for DaemonStatsInner {
    fn default() -> Self {
        Self {
            frames_received: AtomicU64::new(0),
            frames_decoded: AtomicU64::new(0),
            frames_written: AtomicU64::new(0),
            decode_errors: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
            frames_dropped: AtomicU64::new(0),
        }
    }
}

impl DaemonStatsInner {
    fn to_stats(&self) -> DaemonStats {
        DaemonStats {
            frames_received: self.frames_received.load(Ordering::Relaxed),
            frames_decoded: self.frames_decoded.load(Ordering::Relaxed),
            frames_written: self.frames_written.load(Ordering::Relaxed),
            decode_errors: self.decode_errors.load(Ordering::Relaxed),
            write_errors: self.write_errors.load(Ordering::Relaxed),
            frames_dropped: self.frames_dropped.load(Ordering::Relaxed),
        }
    }
}

impl CameraDaemon {
    /// Create a new camera daemon with the given configuration
    pub fn new(config: CameraDaemonConfig) -> Self {
        let perf_monitor = if config.enable_perf_monitoring {
            Some(Arc::new(PerformanceMonitor::new()))
        } else {
            None
        };

        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            frame_tx: None,
            stats: Arc::new(DaemonStatsInner::default()),
            perf_monitor,
        }
    }

    /// Get the performance monitor
    pub fn perf_monitor(&self) -> Option<&Arc<PerformanceMonitor>> {
        self.perf_monitor.as_ref()
    }

    /// Check if daemon is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Get current statistics
    pub fn stats(&self) -> DaemonStats {
        self.stats.to_stats()
    }

    /// Start the camera daemon
    ///
    /// Opens the V4L2 device and starts the processing task.
    pub async fn start(&mut self) -> Result<(), DaemonError> {
        if self.is_running() {
            return Err(DaemonError::AlreadyRunning);
        }

        info!(
            "Starting camera daemon: {}x{} @ {}fps -> {} (queue_size={})",
            self.config.width,
            self.config.height,
            self.config.fps,
            self.config.device_path.display(),
            self.config.queue_size
        );

        // Start performance monitoring
        if let Some(ref monitor) = self.perf_monitor {
            monitor.start();
        }

        // Create frame channel with configurable size (Issue #110: reduced for lower latency)
        let (tx, rx) = mpsc::channel::<FrameData>(self.config.queue_size);
        self.frame_tx = Some(tx);

        // Clone handles for processing task
        let config = self.config.clone();
        let running = Arc::clone(&self.running);
        let stats = Arc::clone(&self.stats);
        let perf_monitor = self.perf_monitor.clone();

        // Start processing task
        self.running.store(true, Ordering::Relaxed);
        tokio::spawn(async move {
            if let Err(e) = Self::processing_task(config, running, rx, stats, perf_monitor).await {
                error!("Camera daemon processing error: {}", e);
            }
        });

        Ok(())
    }

    /// Stop the camera daemon
    pub async fn stop(&mut self) -> Result<(), DaemonError> {
        if !self.is_running() {
            return Err(DaemonError::NotRunning);
        }

        info!("Stopping camera daemon");

        self.running.store(false, Ordering::Relaxed);
        self.frame_tx = None;

        // Stop performance monitoring
        if let Some(ref monitor) = self.perf_monitor {
            monitor.stop();
        }

        // Log final statistics
        let stats = self.stats();
        info!(
            "Daemon stats: received={}, decoded={}, written={}, dropped={}",
            stats.frames_received,
            stats.frames_decoded,
            stats.frames_written,
            stats.frames_dropped
        );

        Ok(())
    }

    /// Process incoming frame from Android
    ///
    /// Called by the camera plugin when a frame packet is received.
    pub async fn process_frame(
        &self,
        data: Vec<u8>,
        frame_type: FrameType,
        timestamp_us: u64,
    ) -> Result<(), DaemonError> {
        if !self.is_running() {
            return Err(DaemonError::NotRunning);
        }

        self.stats.frames_received.fetch_add(1, Ordering::Relaxed);

        let frame_data = FrameData {
            data,
            frame_type,
            timestamp_us,
        };

        if let Some(ref tx) = self.frame_tx {
            if tx.try_send(frame_data).is_err() {
                self.stats.frames_dropped.fetch_add(1, Ordering::Relaxed);
                warn!("Frame dropped due to full queue");
            }
        }

        Ok(())
    }

    /// Process SPS/PPS configuration data
    ///
    /// Called when Android sends decoder configuration.
    pub async fn process_sps_pps(&self, data: Vec<u8>) -> Result<(), DaemonError> {
        // SPS/PPS is handled as a special frame type
        self.process_frame(data, FrameType::SpsPps, 0).await
    }

    /// Main processing task
    ///
    /// Optimized for low latency (Issue #110):
    /// - Shorter timeout for faster response
    /// - Performance metrics tracking
    /// - Timed decode and write operations
    async fn processing_task(
        config: CameraDaemonConfig,
        running: Arc<AtomicBool>,
        mut rx: mpsc::Receiver<FrameData>,
        stats: Arc<DaemonStatsInner>,
        perf_monitor: Option<Arc<PerformanceMonitor>>,
    ) -> Result<(), DaemonError> {
        // Initialize V4L2 device
        let mut v4l2_device = V4l2LoopbackDevice::new(&config.device_path);
        v4l2_device.open(config.width, config.height, config.output_format)?;

        // Initialize H.264 decoder
        let mut decoder = H264Decoder::new()?;

        info!("Camera daemon processing started");

        // Reduced timeout for lower latency (Issue #110)
        let frame_timeout = std::time::Duration::from_millis(50);

        // Process frames
        while running.load(Ordering::Relaxed) {
            // Wait for next frame with short timeout
            let frame_data = tokio::select! {
                data = rx.recv() => {
                    match data {
                        Some(d) => d,
                        None => break, // Channel closed
                    }
                }
                _ = tokio::time::sleep(frame_timeout) => {
                    continue; // Timeout, check running state
                }
            };

            // Track frame received
            if let Some(ref monitor) = perf_monitor {
                monitor.on_frame_received(frame_data.data.len());
            }

            // Handle SPS/PPS
            if frame_data.frame_type == FrameType::SpsPps {
                match decoder.decode_sps_pps(&frame_data.data) {
                    Ok(()) => debug!("Decoder initialized with SPS/PPS"),
                    Err(e) => {
                        stats.decode_errors.fetch_add(1, Ordering::Relaxed);
                        if let Some(ref monitor) = perf_monitor {
                            monitor.on_decode_error();
                        }
                        warn!("Failed to set SPS/PPS: {}", e);
                    }
                }
                continue;
            }

            // Decode frame with timing
            let decode_start = Instant::now();
            match decoder.decode(&frame_data.data, frame_data.timestamp_us) {
                Ok(Some(frame)) => {
                    let decode_time_ns = decode_start.elapsed().as_nanos() as u64;
                    stats.frames_decoded.fetch_add(1, Ordering::Relaxed);

                    if let Some(ref monitor) = perf_monitor {
                        monitor.on_frame_decoded(decode_time_ns);
                    }

                    // Write to V4L2 device with timing
                    let write_start = Instant::now();
                    if let Err(e) = v4l2_device.write_frame(&frame) {
                        stats.write_errors.fetch_add(1, Ordering::Relaxed);
                        if let Some(ref monitor) = perf_monitor {
                            monitor.on_write_error();
                        }
                        warn!("Failed to write frame: {}", e);
                    } else {
                        let write_time_ns = write_start.elapsed().as_nanos() as u64;
                        stats.frames_written.fetch_add(1, Ordering::Relaxed);

                        if let Some(ref monitor) = perf_monitor {
                            monitor.on_frame_written(write_time_ns);
                        }
                    }
                }
                Ok(None) => {
                    // Need more data (normal for P-frames)
                    debug!("Decoder needs more data");
                }
                Err(DecoderError::NeedMoreData) => {
                    // Decoder not initialized yet
                    debug!("Waiting for SPS/PPS");
                }
                Err(e) => {
                    stats.decode_errors.fetch_add(1, Ordering::Relaxed);
                    if let Some(ref monitor) = perf_monitor {
                        monitor.on_decode_error();
                    }
                    warn!("Decode error: {}", e);

                    // Reset decoder on error
                    if let Err(reset_err) = decoder.reset() {
                        error!("Failed to reset decoder: {}", reset_err);
                    }
                }
            }

            // Periodic performance check
            if let Some(ref monitor) = perf_monitor {
                monitor.check_performance();
            }
        }

        // Cleanup
        v4l2_device.close();
        info!("Camera daemon processing stopped");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_config_default() {
        let config = CameraDaemonConfig::default();
        assert_eq!(config.width, 1280);
        assert_eq!(config.height, 720);
        assert_eq!(config.fps, 30);
    }

    #[test]
    fn test_daemon_new() {
        let config = CameraDaemonConfig::default();
        let daemon = CameraDaemon::new(config);
        assert!(!daemon.is_running());
    }

    #[test]
    fn test_daemon_stats_default() {
        let stats = DaemonStats::default();
        assert_eq!(stats.frames_received, 0);
        assert_eq!(stats.frames_decoded, 0);
        assert_eq!(stats.frames_written, 0);
    }
}
