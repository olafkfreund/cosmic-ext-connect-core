//! V4L2 Loopback Device Management
//!
//! Provides interface to V4L2 loopback devices for virtual webcam output.
//!
//! ## Prerequisites
//!
//! The `v4l2loopback` kernel module must be loaded:
//!
//! ```bash
//! # Install the module (Debian/Ubuntu)
//! sudo apt install v4l2loopback-dkms
//!
//! # Load with a specific device number
//! sudo modprobe v4l2loopback devices=1 video_nr=10 card_label="COSMIC Camera"
//!
//! # Make persistent across reboots
//! echo "v4l2loopback" | sudo tee /etc/modules-load.d/v4l2loopback.conf
//! echo "options v4l2loopback devices=1 video_nr=10 card_label=\"COSMIC Camera\"" | \
//!     sudo tee /etc/modprobe.d/v4l2loopback.conf
//! ```

use crate::video::frame::{PixelFormat, VideoFrame};
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use tracing::{debug, info, warn};
use v4l::prelude::*;
use v4l::video::Output;
use v4l::FourCC;

/// Error types for V4L2 operations
#[derive(Debug)]
pub enum V4l2Error {
    /// Device not found
    DeviceNotFound(String),
    /// Failed to open device
    OpenError(String),
    /// Device configuration error
    ConfigError(String),
    /// Write error
    WriteError(String),
    /// Format not supported
    UnsupportedFormat(String),
    /// Permission denied
    PermissionDenied(String),
}

impl fmt::Display for V4l2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            V4l2Error::DeviceNotFound(path) => write!(f, "V4L2 device not found: {}", path),
            V4l2Error::OpenError(msg) => write!(f, "Failed to open V4L2 device: {}", msg),
            V4l2Error::ConfigError(msg) => write!(f, "V4L2 configuration error: {}", msg),
            V4l2Error::WriteError(msg) => write!(f, "V4L2 write error: {}", msg),
            V4l2Error::UnsupportedFormat(msg) => write!(f, "Unsupported format: {}", msg),
            V4l2Error::PermissionDenied(path) => {
                write!(f, "Permission denied for {}, try adding user to 'video' group", path)
            }
        }
    }
}

impl std::error::Error for V4l2Error {}

/// V4L2 loopback device for virtual webcam output
///
/// Writes decoded video frames to a V4L2 loopback device,
/// making them available as a virtual webcam to applications.
pub struct V4l2LoopbackDevice {
    /// Device path (e.g., /dev/video10)
    path: PathBuf,
    /// Device file for raw writes
    device: Option<std::fs::File>,
    /// Configured width
    width: u32,
    /// Configured height
    height: u32,
    /// Configured pixel format
    format: PixelFormat,
    /// Frames written counter
    frames_written: u64,
    /// Whether device is opened and configured
    is_open: bool,
}

impl V4l2LoopbackDevice {
    /// Create a new V4L2 loopback device handle
    ///
    /// Does not open the device yet - call `open()` to configure and open.
    pub fn new(device_path: impl Into<PathBuf>) -> Self {
        Self {
            path: device_path.into(),
            device: None,
            width: 0,
            height: 0,
            format: PixelFormat::YUYV,
            frames_written: 0,
            is_open: false,
        }
    }

    /// Open and configure the V4L2 loopback device
    pub fn open(&mut self, width: u32, height: u32, format: PixelFormat) -> Result<(), V4l2Error> {
        info!(
            "Opening V4L2 loopback device {} ({}x{}, {:?})",
            self.path.display(),
            width,
            height,
            format
        );

        // Check if device exists
        if !self.path.exists() {
            return Err(V4l2Error::DeviceNotFound(self.path.display().to_string()));
        }

        // Open device for writing
        let file = OpenOptions::new()
            .write(true)
            .open(&self.path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    V4l2Error::PermissionDenied(self.path.display().to_string())
                } else {
                    V4l2Error::OpenError(e.to_string())
                }
            })?;

        // Set format using v4l2 ioctls
        self.set_format(&file, width, height, format)?;

        self.device = Some(file);
        self.width = width;
        self.height = height;
        self.format = format;
        self.is_open = true;

        info!("V4L2 loopback device opened successfully");
        Ok(())
    }

    /// Set the video format on the device
    ///
    /// Note: For v4l2loopback devices, the format is often auto-negotiated.
    /// This function attempts to configure the format but may silently succeed
    /// even if the device doesn't fully support the requested parameters.
    fn set_format(
        &self,
        _file: &std::fs::File,
        width: u32,
        height: u32,
        format: PixelFormat,
    ) -> Result<(), V4l2Error> {
        // For v4l2loopback, we use a simpler approach:
        // The device accepts writes in the configured format.
        // We'll validate format support when opening with v4l Device.

        // Try to open device with v4l to set format
        let device = Device::with_path(&self.path)
            .map_err(|e| V4l2Error::OpenError(e.to_string()))?;

        // Build format description
        let fourcc = FourCC::new(&self.fourcc_bytes(&format));
        let mut fmt = v4l::Format::new(width, height, fourcc);

        // Try to set the format (may not work for all loopback configurations)
        if let Err(e) = device.set_format(&fmt) {
            // Log warning but don't fail - v4l2loopback often works without explicit format set
            warn!("Could not set V4L2 format (may still work): {}", e);
        }

        debug!(
            "Set V4L2 format: {}x{}, fourcc={:?}",
            width,
            height,
            fourcc
        );

        Ok(())
    }

    /// Convert PixelFormat to fourcc bytes
    fn fourcc_bytes(&self, format: &PixelFormat) -> [u8; 4] {
        match format {
            PixelFormat::I420 => *b"I420",
            PixelFormat::NV12 => *b"NV12",
            PixelFormat::YUYV => *b"YUYV",
            PixelFormat::RGB24 => *b"RGB3",
            PixelFormat::RGBA32 => *b"AB24",
        }
    }

    /// Calculate bytes per line for a format
    fn bytes_per_line(&self, width: u32, format: &PixelFormat) -> u32 {
        match format {
            PixelFormat::YUYV => width * 2,
            PixelFormat::RGB24 => width * 3,
            PixelFormat::RGBA32 => width * 4,
            PixelFormat::I420 | PixelFormat::NV12 => width, // Stride of Y plane
        }
    }

    /// Write a frame to the V4L2 device
    pub fn write_frame(&mut self, frame: &VideoFrame) -> Result<(), V4l2Error> {
        if !self.is_open {
            return Err(V4l2Error::OpenError("Device not opened".into()));
        }

        // Convert frame format if necessary
        let frame_to_write = if frame.format != self.format {
            frame
                .convert(self.format)
                .ok_or_else(|| V4l2Error::UnsupportedFormat(format!(
                    "Cannot convert {:?} to {:?}",
                    frame.format, self.format
                )))?
        } else {
            frame.clone()
        };

        // Validate dimensions
        if frame_to_write.width != self.width || frame_to_write.height != self.height {
            return Err(V4l2Error::ConfigError(format!(
                "Frame dimensions {}x{} don't match device {}x{}",
                frame_to_write.width, frame_to_write.height, self.width, self.height
            )));
        }

        // Write to device
        if let Some(ref mut device) = self.device {
            device
                .write_all(&frame_to_write.data)
                .map_err(|e| V4l2Error::WriteError(e.to_string()))?;

            self.frames_written += 1;
        }

        Ok(())
    }

    /// Close the device
    pub fn close(&mut self) {
        if self.is_open {
            info!("Closing V4L2 loopback device (wrote {} frames)", self.frames_written);
            self.device = None;
            self.is_open = false;
        }
    }

    /// Check if device is open
    pub fn is_open(&self) -> bool {
        self.is_open
    }

    /// Get device path
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Get configured dimensions
    pub fn dimensions(&self) -> Option<(u32, u32)> {
        if self.is_open {
            Some((self.width, self.height))
        } else {
            None
        }
    }

    /// Get number of frames written
    pub fn frames_written(&self) -> u64 {
        self.frames_written
    }
}

impl Drop for V4l2LoopbackDevice {
    fn drop(&mut self) {
        self.close();
    }
}

/// Find available V4L2 loopback devices on the system
pub fn find_loopback_devices() -> Vec<PathBuf> {
    let mut devices = Vec::new();

    for entry in std::fs::read_dir("/dev").into_iter().flatten() {
        if let Ok(entry) = entry {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with("video") {
                    // Check if it's a loopback device by reading capabilities
                    if is_loopback_device(&path) {
                        devices.push(path);
                    }
                }
            }
        }
    }

    devices.sort();
    devices
}

/// Check if a V4L2 device is a loopback device
fn is_loopback_device(path: &PathBuf) -> bool {
    // Try to open and query capabilities
    if let Ok(device) = Device::with_path(path) {
        if let Ok(caps) = device.query_caps() {
            // v4l2loopback shows up as output-capable
            let has_output = caps.capabilities.contains(v4l::capability::Flags::VIDEO_OUTPUT);
            let driver = caps.driver.to_string();

            return has_output && driver.contains("v4l2 loopback");
        }
    }

    false
}

/// Get the recommended loopback device path
///
/// Returns the first available loopback device, or a default path.
pub fn default_loopback_device() -> PathBuf {
    find_loopback_devices()
        .into_iter()
        .next()
        .unwrap_or_else(|| PathBuf::from("/dev/video10"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v4l2_device_new() {
        let device = V4l2LoopbackDevice::new("/dev/video10");
        assert!(!device.is_open());
        assert_eq!(device.frames_written(), 0);
    }

    #[test]
    fn test_bytes_per_line() {
        let device = V4l2LoopbackDevice::new("/dev/video10");
        assert_eq!(device.bytes_per_line(1280, &PixelFormat::YUYV), 2560);
        assert_eq!(device.bytes_per_line(1280, &PixelFormat::RGB24), 3840);
    }
}
