//! Video Frame Types
//!
//! Defines frame buffers and pixel format types for video processing.

use std::fmt;

/// Pixel format for video frames
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// I420 (YUV 4:2:0 planar) - Common encoder output
    I420,
    /// NV12 (YUV 4:2:0 semi-planar) - Common hardware format
    NV12,
    /// YUYV (YUV 4:2:2 packed) - Common V4L2 format
    YUYV,
    /// RGB24 (8 bits per channel, packed)
    RGB24,
    /// RGBA32 (8 bits per channel with alpha, packed)
    RGBA32,
}

impl PixelFormat {
    /// Get the V4L2 fourcc code for this format
    pub fn fourcc(&self) -> u32 {
        match self {
            // FourCC codes as little-endian u32
            PixelFormat::I420 => u32::from_le_bytes(*b"I420"),
            PixelFormat::NV12 => u32::from_le_bytes(*b"NV12"),
            PixelFormat::YUYV => u32::from_le_bytes(*b"YUYV"),
            PixelFormat::RGB24 => u32::from_le_bytes(*b"RGB3"),
            PixelFormat::RGBA32 => u32::from_le_bytes(*b"AB24"),
        }
    }

    /// Calculate the buffer size needed for a frame
    pub fn buffer_size(&self, width: u32, height: u32) -> usize {
        let pixels = width as usize * height as usize;
        match self {
            PixelFormat::I420 => pixels * 3 / 2,  // Y + U/4 + V/4
            PixelFormat::NV12 => pixels * 3 / 2,  // Y + UV/2
            PixelFormat::YUYV => pixels * 2,      // 2 bytes per pixel
            PixelFormat::RGB24 => pixels * 3,     // 3 bytes per pixel
            PixelFormat::RGBA32 => pixels * 4,    // 4 bytes per pixel
        }
    }

    /// Get bytes per pixel (for packed formats) or average (for planar)
    pub fn bytes_per_pixel(&self) -> f32 {
        match self {
            PixelFormat::I420 => 1.5,
            PixelFormat::NV12 => 1.5,
            PixelFormat::YUYV => 2.0,
            PixelFormat::RGB24 => 3.0,
            PixelFormat::RGBA32 => 4.0,
        }
    }
}

impl fmt::Display for PixelFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PixelFormat::I420 => write!(f, "I420 (YUV 4:2:0 planar)"),
            PixelFormat::NV12 => write!(f, "NV12 (YUV 4:2:0 semi-planar)"),
            PixelFormat::YUYV => write!(f, "YUYV (YUV 4:2:2 packed)"),
            PixelFormat::RGB24 => write!(f, "RGB24"),
            PixelFormat::RGBA32 => write!(f, "RGBA32"),
        }
    }
}

/// A decoded video frame
#[derive(Debug, Clone)]
pub struct VideoFrame {
    /// Frame width in pixels
    pub width: u32,
    /// Frame height in pixels
    pub height: u32,
    /// Pixel format
    pub format: PixelFormat,
    /// Presentation timestamp in microseconds
    pub timestamp_us: u64,
    /// Frame data buffer
    pub data: Vec<u8>,
    /// Stride for each plane (if planar format)
    pub strides: Vec<u32>,
}

impl VideoFrame {
    /// Create a new frame with allocated buffer
    pub fn new(width: u32, height: u32, format: PixelFormat, timestamp_us: u64) -> Self {
        let size = format.buffer_size(width, height);
        let strides = Self::compute_strides(width, &format);

        Self {
            width,
            height,
            format,
            timestamp_us,
            data: vec![0u8; size],
            strides,
        }
    }

    /// Create a frame from existing data
    pub fn from_data(
        width: u32,
        height: u32,
        format: PixelFormat,
        timestamp_us: u64,
        data: Vec<u8>,
    ) -> Self {
        let strides = Self::compute_strides(width, &format);
        Self {
            width,
            height,
            format,
            timestamp_us,
            data,
            strides,
        }
    }

    /// Compute strides for each plane
    fn compute_strides(width: u32, format: &PixelFormat) -> Vec<u32> {
        match format {
            PixelFormat::I420 => vec![width, width / 2, width / 2],
            PixelFormat::NV12 => vec![width, width],
            PixelFormat::YUYV => vec![width * 2],
            PixelFormat::RGB24 => vec![width * 3],
            PixelFormat::RGBA32 => vec![width * 4],
        }
    }

    /// Get the Y plane (for YUV formats)
    pub fn y_plane(&self) -> Option<&[u8]> {
        match self.format {
            PixelFormat::I420 | PixelFormat::NV12 => {
                let y_size = self.width as usize * self.height as usize;
                Some(&self.data[..y_size])
            }
            _ => None,
        }
    }

    /// Get the U plane (for I420)
    pub fn u_plane(&self) -> Option<&[u8]> {
        if self.format != PixelFormat::I420 {
            return None;
        }
        let y_size = self.width as usize * self.height as usize;
        let uv_size = y_size / 4;
        Some(&self.data[y_size..y_size + uv_size])
    }

    /// Get the V plane (for I420)
    pub fn v_plane(&self) -> Option<&[u8]> {
        if self.format != PixelFormat::I420 {
            return None;
        }
        let y_size = self.width as usize * self.height as usize;
        let uv_size = y_size / 4;
        Some(&self.data[y_size + uv_size..])
    }

    /// Get the UV plane (for NV12)
    pub fn uv_plane(&self) -> Option<&[u8]> {
        if self.format != PixelFormat::NV12 {
            return None;
        }
        let y_size = self.width as usize * self.height as usize;
        Some(&self.data[y_size..])
    }

    /// Convert frame to a different pixel format
    ///
    /// Currently supports:
    /// - I420 → YUYV
    /// - NV12 → YUYV
    pub fn convert(&self, target_format: PixelFormat) -> Option<VideoFrame> {
        match (self.format, target_format) {
            (PixelFormat::I420, PixelFormat::YUYV) => Some(self.i420_to_yuyv()),
            (PixelFormat::NV12, PixelFormat::YUYV) => Some(self.nv12_to_yuyv()),
            (a, b) if a == b => Some(self.clone()),
            _ => None,
        }
    }

    /// Convert I420 to YUYV
    ///
    /// Optimized for performance (Issue #110):
    /// - Uses direct indexing with bounds checking eliminated
    /// - Processes two pixels per iteration
    /// - Cache-friendly memory access pattern
    fn i420_to_yuyv(&self) -> VideoFrame {
        let y_plane = self.y_plane().unwrap();
        let u_plane = self.u_plane().unwrap();
        let v_plane = self.v_plane().unwrap();

        let width = self.width as usize;
        let height = self.height as usize;
        let yuyv_size = width * height * 2;

        // Pre-allocate with exact size
        let mut yuyv_data = Vec::with_capacity(yuyv_size);
        unsafe { yuyv_data.set_len(yuyv_size); }

        // Process row by row for cache efficiency
        let y_stride = width;
        let uv_stride = width / 2;
        let yuyv_stride = width * 2;

        for row in 0..height {
            let y_row_start = row * y_stride;
            let uv_row_start = (row / 2) * uv_stride;
            let yuyv_row_start = row * yuyv_stride;

            // Process pairs of pixels
            for col_pair in 0..(width / 2) {
                let y_idx = y_row_start + col_pair * 2;
                let uv_idx = uv_row_start + col_pair;
                let yuyv_idx = yuyv_row_start + col_pair * 4;

                // YUYV format: Y0 U Y1 V
                unsafe {
                    *yuyv_data.get_unchecked_mut(yuyv_idx) = *y_plane.get_unchecked(y_idx);
                    *yuyv_data.get_unchecked_mut(yuyv_idx + 1) = *u_plane.get_unchecked(uv_idx);
                    *yuyv_data.get_unchecked_mut(yuyv_idx + 2) = *y_plane.get_unchecked(y_idx + 1);
                    *yuyv_data.get_unchecked_mut(yuyv_idx + 3) = *v_plane.get_unchecked(uv_idx);
                }
            }
        }

        VideoFrame::from_data(
            self.width,
            self.height,
            PixelFormat::YUYV,
            self.timestamp_us,
            yuyv_data,
        )
    }

    /// Convert NV12 to YUYV
    ///
    /// Optimized for performance (Issue #110):
    /// - Uses direct indexing with bounds checking eliminated
    /// - Processes two pixels per iteration
    /// - Cache-friendly memory access pattern
    fn nv12_to_yuyv(&self) -> VideoFrame {
        let y_plane = self.y_plane().unwrap();
        let uv_plane = self.uv_plane().unwrap();

        let width = self.width as usize;
        let height = self.height as usize;
        let yuyv_size = width * height * 2;

        // Pre-allocate with exact size
        let mut yuyv_data = Vec::with_capacity(yuyv_size);
        unsafe { yuyv_data.set_len(yuyv_size); }

        // Process row by row for cache efficiency
        let y_stride = width;
        let uv_stride = width; // NV12 UV plane has same width as Y
        let yuyv_stride = width * 2;

        for row in 0..height {
            let y_row_start = row * y_stride;
            let uv_row_start = (row / 2) * uv_stride;
            let yuyv_row_start = row * yuyv_stride;

            // Process pairs of pixels
            for col_pair in 0..(width / 2) {
                let y_idx = y_row_start + col_pair * 2;
                let uv_idx = uv_row_start + col_pair * 2;
                let yuyv_idx = yuyv_row_start + col_pair * 4;

                // YUYV format: Y0 U Y1 V
                // NV12 UV plane is interleaved: U V U V ...
                unsafe {
                    *yuyv_data.get_unchecked_mut(yuyv_idx) = *y_plane.get_unchecked(y_idx);
                    *yuyv_data.get_unchecked_mut(yuyv_idx + 1) = *uv_plane.get_unchecked(uv_idx);
                    *yuyv_data.get_unchecked_mut(yuyv_idx + 2) = *y_plane.get_unchecked(y_idx + 1);
                    *yuyv_data.get_unchecked_mut(yuyv_idx + 3) = *uv_plane.get_unchecked(uv_idx + 1);
                }
            }
        }

        VideoFrame::from_data(
            self.width,
            self.height,
            PixelFormat::YUYV,
            self.timestamp_us,
            yuyv_data,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pixel_format_buffer_size() {
        // 1280x720 frame sizes
        assert_eq!(PixelFormat::I420.buffer_size(1280, 720), 1280 * 720 * 3 / 2);
        assert_eq!(PixelFormat::NV12.buffer_size(1280, 720), 1280 * 720 * 3 / 2);
        assert_eq!(PixelFormat::YUYV.buffer_size(1280, 720), 1280 * 720 * 2);
        assert_eq!(PixelFormat::RGB24.buffer_size(1280, 720), 1280 * 720 * 3);
    }

    #[test]
    fn test_video_frame_new() {
        let frame = VideoFrame::new(1280, 720, PixelFormat::I420, 0);
        assert_eq!(frame.width, 1280);
        assert_eq!(frame.height, 720);
        assert_eq!(frame.format, PixelFormat::I420);
        assert_eq!(frame.data.len(), 1280 * 720 * 3 / 2);
    }

    #[test]
    fn test_video_frame_planes() {
        let frame = VideoFrame::new(1280, 720, PixelFormat::I420, 0);

        let y = frame.y_plane().unwrap();
        let u = frame.u_plane().unwrap();
        let v = frame.v_plane().unwrap();

        assert_eq!(y.len(), 1280 * 720);
        assert_eq!(u.len(), 1280 * 720 / 4);
        assert_eq!(v.len(), 1280 * 720 / 4);
    }
}
