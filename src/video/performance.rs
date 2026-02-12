//! Camera Performance Monitor
//!
//! Real-time performance metrics for camera streaming pipeline.
//! Tracks latency, frame rate, decode time, and V4L2 write efficiency.
//!
//! ## Performance Targets (Issue #110)
//!
//! | Metric | Target | Acceptable |
//! |--------|--------|------------|
//! | End-to-end latency | <100ms | <150ms |
//! | Frame rate | 30 fps stable | 25+ fps |
//! | CPU usage | <5% | <10% |
//! | Memory usage | <100MB | <150MB |
//!
//! ## Usage
//!
//! ```rust,ignore
//! use cosmic_ext_connect_core::video::performance::PerformanceMonitor;
//!
//! let monitor = PerformanceMonitor::new();
//! monitor.start();
//!
//! // Track frame events
//! monitor.on_frame_received(frame_size);
//! monitor.on_frame_decoded(decode_time_ns);
//! monitor.on_frame_written(write_time_ns);
//!
//! // Get metrics
//! let metrics = monitor.get_metrics();
//! println!("FPS: {}, Latency: {}ms", metrics.current_fps, metrics.avg_latency_ms);
//!
//! monitor.stop();
//! ```

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Target FPS for performance comparison
pub const TARGET_FPS: f64 = 30.0;

/// Target end-to-end latency in milliseconds
pub const TARGET_LATENCY_MS: u64 = 100;

/// Acceptable latency threshold in milliseconds
pub const ACCEPTABLE_LATENCY_MS: u64 = 150;

/// Metrics update interval
pub const METRICS_UPDATE_INTERVAL: Duration = Duration::from_secs(1);

/// Rolling window size for averages
const ROLLING_WINDOW_SIZE: usize = 30;

/// Performance metrics snapshot
#[derive(Debug, Clone, Default)]
pub struct PerformanceMetrics {
    /// Session duration in milliseconds
    pub session_duration_ms: u64,

    /// Current frame rate
    pub current_fps: f64,

    /// Average decode time in milliseconds
    pub avg_decode_time_ms: f64,

    /// Maximum decode time in milliseconds
    pub max_decode_time_ms: f64,

    /// Average V4L2 write time in milliseconds
    pub avg_write_time_ms: f64,

    /// Average end-to-end latency in milliseconds (if available)
    pub avg_latency_ms: f64,

    /// Minimum latency observed
    pub min_latency_ms: f64,

    /// Maximum latency observed
    pub max_latency_ms: f64,

    /// Current bitrate in kbps
    pub bitrate_kbps: u64,

    /// Total frames received
    pub total_frames_received: u64,

    /// Total frames decoded
    pub total_frames_decoded: u64,

    /// Total frames written to V4L2
    pub total_frames_written: u64,

    /// Frames dropped due to queue full
    pub frames_dropped: u64,

    /// Decode errors
    pub decode_errors: u64,

    /// V4L2 write errors
    pub write_errors: u64,

    /// Drop rate as percentage
    pub drop_rate_percent: f64,

    /// Whether current FPS meets target
    pub meets_target_fps: bool,

    /// Whether latency meets target (<100ms)
    pub meets_target_latency: bool,

    /// Whether latency meets acceptable threshold (<150ms)
    pub meets_acceptable_latency: bool,
}

impl PerformanceMetrics {
    /// Get overall performance status
    pub fn get_status(&self) -> PerformanceStatus {
        if self.meets_target_fps && self.meets_target_latency {
            PerformanceStatus::Excellent
        } else if self.meets_target_fps && self.meets_acceptable_latency {
            PerformanceStatus::Good
        } else if self.meets_acceptable_latency {
            PerformanceStatus::Acceptable
        } else {
            PerformanceStatus::Degraded
        }
    }
}

/// Performance status levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerformanceStatus {
    /// Meets all targets
    Excellent,
    /// Meets FPS, acceptable latency
    Good,
    /// Acceptable performance
    Acceptable,
    /// Performance is degraded
    Degraded,
}

/// Rolling window for time-series data
struct RollingWindow {
    values: Vec<f64>,
    index: usize,
    count: usize,
}

impl RollingWindow {
    fn new(size: usize) -> Self {
        Self {
            values: vec![0.0; size],
            index: 0,
            count: 0,
        }
    }

    fn add(&mut self, value: f64) {
        self.values[self.index] = value;
        self.index = (self.index + 1) % self.values.len();
        if self.count < self.values.len() {
            self.count += 1;
        }
    }

    fn clear(&mut self) {
        self.index = 0;
        self.count = 0;
    }

    fn average(&self) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        self.values[..self.count].iter().sum::<f64>() / self.count as f64
    }

    fn max(&self) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        self.values[..self.count]
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max)
    }

    fn min(&self) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        self.values[..self.count]
            .iter()
            .cloned()
            .fold(f64::INFINITY, f64::min)
    }
}

/// Inner state protected by RwLock
struct MonitorState {
    /// Session start time
    session_start: Instant,

    /// Frame receive times for FPS calculation
    receive_times: RollingWindow,

    /// Decode times
    decode_times: RollingWindow,

    /// Write times
    write_times: RollingWindow,

    /// Latency samples
    latency_samples: RollingWindow,

    /// Last FPS calculation time
    last_fps_time: Instant,

    /// Frames since last FPS calculation
    frames_since_fps: u64,
}

impl MonitorState {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            session_start: now,
            receive_times: RollingWindow::new(ROLLING_WINDOW_SIZE),
            decode_times: RollingWindow::new(ROLLING_WINDOW_SIZE),
            write_times: RollingWindow::new(ROLLING_WINDOW_SIZE),
            latency_samples: RollingWindow::new(ROLLING_WINDOW_SIZE),
            last_fps_time: now,
            frames_since_fps: 0,
        }
    }

    fn reset(&mut self) {
        let now = Instant::now();
        self.session_start = now;
        self.receive_times.clear();
        self.decode_times.clear();
        self.write_times.clear();
        self.latency_samples.clear();
        self.last_fps_time = now;
        self.frames_since_fps = 0;
    }
}

/// Performance monitor for camera streaming pipeline
pub struct PerformanceMonitor {
    /// Whether monitoring is active
    running: Arc<AtomicBool>,

    /// Mutable state
    state: Arc<RwLock<MonitorState>>,

    /// Total frames received
    frames_received: AtomicU64,

    /// Total frames decoded
    frames_decoded: AtomicU64,

    /// Total frames written
    frames_written: AtomicU64,

    /// Frames dropped
    frames_dropped: AtomicU64,

    /// Decode errors
    decode_errors: AtomicU64,

    /// Write errors
    write_errors: AtomicU64,

    /// Total bytes received
    bytes_received: AtomicU64,

    /// Current FPS (atomic for fast access)
    current_fps: AtomicU64,

    /// Current metrics snapshot
    current_metrics: Arc<RwLock<PerformanceMetrics>>,
}

impl Default for PerformanceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl PerformanceMonitor {
    /// Create a new performance monitor
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            state: Arc::new(RwLock::new(MonitorState::new())),
            frames_received: AtomicU64::new(0),
            frames_decoded: AtomicU64::new(0),
            frames_written: AtomicU64::new(0),
            frames_dropped: AtomicU64::new(0),
            decode_errors: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            current_fps: AtomicU64::new(0),
            current_metrics: Arc::new(RwLock::new(PerformanceMetrics::default())),
        }
    }

    /// Start performance monitoring
    pub fn start(&self) {
        if self.running.load(Ordering::Relaxed) {
            return;
        }

        info!("Starting performance monitoring");
        self.running.store(true, Ordering::Relaxed);

        // Reset counters
        self.frames_received.store(0, Ordering::Relaxed);
        self.frames_decoded.store(0, Ordering::Relaxed);
        self.frames_written.store(0, Ordering::Relaxed);
        self.frames_dropped.store(0, Ordering::Relaxed);
        self.decode_errors.store(0, Ordering::Relaxed);
        self.write_errors.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);

        // Reset state
        if let Ok(mut state) = self.state.write() {
            state.reset();
        }
    }

    /// Stop performance monitoring
    pub fn stop(&self) {
        if !self.running.load(Ordering::Relaxed) {
            return;
        }

        info!("Stopping performance monitoring");
        self.running.store(false, Ordering::Relaxed);

        // Log final metrics
        let metrics = self.get_metrics();
        info!(
            "Final metrics: fps={:.1}, decoded={}, written={}, dropped={}, status={:?}",
            metrics.current_fps,
            metrics.total_frames_decoded,
            metrics.total_frames_written,
            metrics.frames_dropped,
            metrics.get_status()
        );
    }

    /// Check if monitoring is active
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Record frame received event
    pub fn on_frame_received(&self, frame_size: usize) {
        if !self.is_running() {
            return;
        }

        self.frames_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received
            .fetch_add(frame_size as u64, Ordering::Relaxed);

        // Update FPS calculation
        if let Ok(mut state) = self.state.write() {
            state.frames_since_fps += 1;

            let now = Instant::now();
            let elapsed = now.duration_since(state.last_fps_time);

            if elapsed >= Duration::from_secs(1) {
                let fps = state.frames_since_fps as f64 / elapsed.as_secs_f64();
                self.current_fps.store(fps.to_bits(), Ordering::Relaxed);
                state.last_fps_time = now;
                state.frames_since_fps = 0;
            }
        }
    }

    /// Record frame decoded event
    pub fn on_frame_decoded(&self, decode_time_ns: u64) {
        if !self.is_running() {
            return;
        }

        self.frames_decoded.fetch_add(1, Ordering::Relaxed);

        let decode_time_ms = decode_time_ns as f64 / 1_000_000.0;
        if let Ok(mut state) = self.state.write() {
            state.decode_times.add(decode_time_ms);
        }
    }

    /// Record frame written to V4L2
    pub fn on_frame_written(&self, write_time_ns: u64) {
        if !self.is_running() {
            return;
        }

        self.frames_written.fetch_add(1, Ordering::Relaxed);

        let write_time_ms = write_time_ns as f64 / 1_000_000.0;
        if let Ok(mut state) = self.state.write() {
            state.write_times.add(write_time_ms);
        }
    }

    /// Record frame dropped
    pub fn on_frame_dropped(&self) {
        if !self.is_running() {
            return;
        }

        self.frames_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Record decode error
    pub fn on_decode_error(&self) {
        if !self.is_running() {
            return;
        }

        self.decode_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record write error
    pub fn on_write_error(&self) {
        if !self.is_running() {
            return;
        }

        self.write_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record end-to-end latency sample
    pub fn on_latency_sample(&self, latency_ms: f64) {
        if !self.is_running() {
            return;
        }

        if let Ok(mut state) = self.state.write() {
            state.latency_samples.add(latency_ms);
        }
    }

    /// Get current performance metrics
    pub fn get_metrics(&self) -> PerformanceMetrics {
        let state = self.state.read().unwrap();

        let session_duration_ms = state.session_start.elapsed().as_millis() as u64;
        let current_fps = f64::from_bits(self.current_fps.load(Ordering::Relaxed));

        let avg_decode_time_ms = state.decode_times.average();
        let max_decode_time_ms = state.decode_times.max();
        let avg_write_time_ms = state.write_times.average();

        let avg_latency_ms = state.latency_samples.average();
        let min_latency_ms = state.latency_samples.min();
        let max_latency_ms = state.latency_samples.max();

        let frames_received = self.frames_received.load(Ordering::Relaxed);
        let frames_dropped = self.frames_dropped.load(Ordering::Relaxed);

        let total_frames = frames_received + frames_dropped;
        let drop_rate_percent = if total_frames > 0 {
            (frames_dropped as f64 / total_frames as f64) * 100.0
        } else {
            0.0
        };

        let bytes = self.bytes_received.load(Ordering::Relaxed);
        let elapsed_secs = session_duration_ms as f64 / 1000.0;
        let bitrate_kbps = if elapsed_secs > 0.0 {
            ((bytes * 8) as f64 / (elapsed_secs * 1000.0)) as u64
        } else {
            0
        };

        let meets_target_fps = current_fps >= TARGET_FPS - 2.0;
        let meets_target_latency =
            avg_latency_ms <= TARGET_LATENCY_MS as f64 || avg_latency_ms == 0.0;
        let meets_acceptable_latency =
            avg_latency_ms <= ACCEPTABLE_LATENCY_MS as f64 || avg_latency_ms == 0.0;

        PerformanceMetrics {
            session_duration_ms,
            current_fps,
            avg_decode_time_ms,
            max_decode_time_ms,
            avg_write_time_ms,
            avg_latency_ms,
            min_latency_ms,
            max_latency_ms,
            bitrate_kbps,
            total_frames_received: frames_received,
            total_frames_decoded: self.frames_decoded.load(Ordering::Relaxed),
            total_frames_written: self.frames_written.load(Ordering::Relaxed),
            frames_dropped,
            decode_errors: self.decode_errors.load(Ordering::Relaxed),
            write_errors: self.write_errors.load(Ordering::Relaxed),
            drop_rate_percent,
            meets_target_fps,
            meets_target_latency,
            meets_acceptable_latency,
        }
    }

    /// Log performance warning if degraded
    pub fn check_performance(&self) {
        if !self.is_running() {
            return;
        }

        let metrics = self.get_metrics();

        if !metrics.meets_acceptable_latency && metrics.avg_latency_ms > 0.0 {
            warn!(
                "Performance degraded: latency={:.1}ms > {}ms",
                metrics.avg_latency_ms, ACCEPTABLE_LATENCY_MS
            );
        }

        if metrics.current_fps < TARGET_FPS - 5.0 && metrics.current_fps > 0.0 {
            warn!(
                "Performance degraded: fps={:.1} < target {}",
                metrics.current_fps, TARGET_FPS
            );
        }

        if metrics.drop_rate_percent > 5.0 {
            warn!("High drop rate: {:.1}%", metrics.drop_rate_percent);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_performance_monitor_new() {
        let monitor = PerformanceMonitor::new();
        assert!(!monitor.is_running());
    }

    #[test]
    fn test_performance_monitor_lifecycle() {
        let monitor = PerformanceMonitor::new();

        monitor.start();
        assert!(monitor.is_running());

        monitor.stop();
        assert!(!monitor.is_running());
    }

    #[test]
    fn test_rolling_window() {
        let mut window = RollingWindow::new(3);

        window.add(10.0);
        window.add(20.0);
        window.add(30.0);

        assert_eq!(window.average(), 20.0);
        assert_eq!(window.min(), 10.0);
        assert_eq!(window.max(), 30.0);

        // Test rollover
        window.add(40.0);
        assert_eq!(window.average(), 30.0); // (20 + 30 + 40) / 3
    }

    #[test]
    fn test_metrics_status() {
        let metrics = PerformanceMetrics {
            current_fps: 30.0,
            avg_latency_ms: 50.0,
            meets_target_fps: true,
            meets_target_latency: true,
            meets_acceptable_latency: true,
            ..Default::default()
        };

        assert_eq!(metrics.get_status(), PerformanceStatus::Excellent);
    }
}
