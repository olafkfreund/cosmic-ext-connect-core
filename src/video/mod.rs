//! Video Processing Module
//!
//! Provides V4L2 loopback support for camera streaming from Android devices
//! to COSMIC Desktop virtual webcam.
//!
//! ## Architecture
//!
//! ```text
//! Android Camera → H.264 Frames → cosmic-connect-core → H.264 Decoder → V4L2 Loopback
//!                                                                              ↓
//!                                                           Any V4L2 application
//!                                                           (Zoom, OBS, etc.)
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! use cosmic_connect_core::video::{CameraDaemon, CameraDaemonConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create and start the camera daemon
//! let config = CameraDaemonConfig {
//!     device_path: "/dev/video10".into(),
//!     width: 1280,
//!     height: 720,
//!     fps: 30,
//! };
//!
//! let daemon = CameraDaemon::new(config)?;
//! daemon.start().await?;
//!
//! // Feed frames from Android
//! daemon.process_frame(h264_data, frame_type).await?;
//!
//! // Stop when done
//! daemon.stop().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Requirements
//!
//! - Linux kernel with V4L2 support
//! - `v4l2loopback` kernel module loaded:
//!   ```bash
//!   sudo modprobe v4l2loopback devices=1 video_nr=10 card_label="COSMIC Camera"
//!   ```
//!
//! ## Feature Flag
//!
//! This module requires the `video` feature:
//! ```toml
//! cosmic-connect-core = { version = "0.1", features = ["video"] }
//! ```

mod frame;
mod h264_decoder;
mod v4l2_device;
mod camera_daemon;
mod performance;

pub use frame::{VideoFrame, PixelFormat};
pub use h264_decoder::{H264Decoder, DecoderError};
pub use v4l2_device::{V4l2LoopbackDevice, V4l2Error};
pub use camera_daemon::{CameraDaemon, CameraDaemonConfig, DaemonError};
pub use performance::{PerformanceMonitor, PerformanceMetrics, PerformanceStatus};
