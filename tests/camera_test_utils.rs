//! Camera Testing Utilities
//!
//! Provides utilities for testing the camera streaming pipeline on the desktop side.
//! Includes mock H.264 frame generation, NAL unit validation, and network simulation.

use cosmic_ext_connect_core::plugins::camera::{CameraFrame, FrameType};
use cosmic_ext_connect_core::video::frame::{PixelFormat, VideoFrame};
use std::time::Duration;

/// Mock H.264 SPS (Sequence Parameter Set) NAL unit for testing
///
/// Creates a realistic-looking SPS NAL unit for 720p H.264 video.
/// Note: This is not a real decodable stream, just for protocol testing.
pub fn mock_sps_nal() -> Vec<u8> {
    vec![
        0x00, 0x00, 0x00, 0x01, // NAL unit start code
        0x67, // NAL unit type: SPS (7)
        0x42, 0xC0, 0x1E, // Profile, constraints, level
        0xFF, 0xE1, // More SPS data
        0x00, 0x18, // SPS size
        // Mock SPS payload (720p compatible)
        0x67, 0x42, 0xC0, 0x1E, 0x8C, 0x68, 0x02, 0x80, 0x2D, 0xD8, 0x0F, 0x00, 0x44, 0xFC, 0xB8,
        0x08, 0x84, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xF0, 0x3C,
    ]
}

/// Mock H.264 PPS (Picture Parameter Set) NAL unit for testing
pub fn mock_pps_nal() -> Vec<u8> {
    vec![
        0x00, 0x00, 0x00, 0x01, // NAL unit start code
        0x68, // NAL unit type: PPS (8)
        0xCE, 0x3C, 0x80, // PPS payload
    ]
}

/// Generate a mock I-frame (IDR) NAL unit
///
/// # Arguments
/// * `size` - Size of the frame payload (excluding NAL header)
/// * `seed` - Random seed for reproducible data
pub fn mock_iframe_nal(size: usize, seed: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(size + 5);

    // NAL unit start code
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

    // NAL unit type: IDR slice (5)
    data.push(0x65);

    // Fill with pseudo-random data based on seed
    let mut rng = SimpleRng::new(seed);
    for _ in 0..size {
        data.push(rng.next_u8());
    }

    data
}

/// Generate a mock P-frame NAL unit
///
/// # Arguments
/// * `size` - Size of the frame payload (excluding NAL header)
/// * `seed` - Random seed for reproducible data
pub fn mock_pframe_nal(size: usize, seed: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(size + 5);

    // NAL unit start code
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

    // NAL unit type: Non-IDR slice (1)
    data.push(0x41);

    // Fill with pseudo-random data based on seed
    let mut rng = SimpleRng::new(seed);
    for _ in 0..size {
        data.push(rng.next_u8());
    }

    data
}

/// Mock camera frame for testing
#[derive(Debug, Clone)]
pub struct MockCameraFrame {
    pub data: Vec<u8>,
    pub frame_type: FrameType,
    pub timestamp_us: u64,
    pub sequence_number: u64,
}

impl MockCameraFrame {
    /// Create a new mock SPS/PPS frame
    pub fn sps_pps(sequence: u64) -> Self {
        let mut data = mock_sps_nal();
        data.extend_from_slice(&mock_pps_nal());

        Self {
            data,
            frame_type: FrameType::SpsPps,
            timestamp_us: 0,
            sequence_number: sequence,
        }
    }

    /// Create a new mock I-frame
    pub fn iframe(sequence: u64, timestamp_us: u64, size: usize) -> Self {
        Self {
            data: mock_iframe_nal(size, sequence),
            frame_type: FrameType::IFrame,
            timestamp_us,
            sequence_number: sequence,
        }
    }

    /// Create a new mock P-frame
    pub fn pframe(sequence: u64, timestamp_us: u64, size: usize) -> Self {
        Self {
            data: mock_pframe_nal(size, sequence),
            frame_type: FrameType::PFrame,
            timestamp_us,
            sequence_number: sequence,
        }
    }

    /// Convert to CameraFrame for transmission
    pub fn to_camera_frame(&self) -> CameraFrame {
        CameraFrame {
            frame_type: self.frame_type.clone(),
            timestamp_us: self.timestamp_us,
            sequence_number: self.sequence_number,
            data: self.data.clone(),
        }
    }
}

/// Generate a sequence of mock frames simulating a video stream
///
/// # Arguments
/// * `duration_ms` - Duration of the stream in milliseconds
/// * `fps` - Frames per second
/// * `iframe_interval` - Number of P-frames between I-frames
///
/// # Returns
/// Vector of mock frames with proper timing and sequence numbers
pub fn mock_frame_sequence(duration_ms: u64, fps: u32, iframe_interval: u32) -> Vec<MockCameraFrame> {
    let mut frames = Vec::new();
    let frame_interval_us = 1_000_000 / fps as u64;
    let total_frames = (duration_ms * fps as u64 / 1000) as usize;

    // Add SPS/PPS at start
    frames.push(MockCameraFrame::sps_pps(0));

    // Generate I-frames and P-frames
    for i in 0..total_frames {
        let is_iframe = (i as u32 % iframe_interval) == 0;
        let timestamp = i as u64 * frame_interval_us;
        let sequence = (i + 1) as u64;

        let frame = if is_iframe {
            MockCameraFrame::iframe(sequence, timestamp, 2048)
        } else {
            MockCameraFrame::pframe(sequence, timestamp, 512)
        };

        frames.push(frame);
    }

    frames
}

/// Mock raw YUV frame for V4L2 testing
#[derive(Debug, Clone)]
pub struct MockYuvFrame {
    pub width: u32,
    pub height: u32,
    pub format: PixelFormat,
    pub data: Vec<u8>,
}

impl MockYuvFrame {
    /// Create a new mock YUV frame with a solid color
    pub fn solid_color(width: u32, height: u32, format: PixelFormat, y: u8, u: u8, v: u8) -> Self {
        let data_size = match format {
            PixelFormat::YUYV => (width * height * 2) as usize,
            PixelFormat::I420 => ((width * height * 3) / 2) as usize,
            PixelFormat::NV12 => ((width * height * 3) / 2) as usize,
            PixelFormat::RGB24 => (width * height * 3) as usize,
        };

        let data = match format {
            PixelFormat::YUYV => {
                // YUYV: Y0 U0 Y1 V0 repeating
                let mut d = Vec::with_capacity(data_size);
                for _ in 0..(width * height / 2) {
                    d.extend_from_slice(&[y, u, y, v]);
                }
                d
            }
            PixelFormat::I420 => {
                // I420: Y plane, U plane, V plane
                let mut d = vec![y; (width * height) as usize];
                d.extend(vec![u; (width * height / 4) as usize]);
                d.extend(vec![v; (width * height / 4) as usize]);
                d
            }
            PixelFormat::NV12 => {
                // NV12: Y plane, interleaved UV plane
                let mut d = vec![y; (width * height) as usize];
                for _ in 0..(width * height / 4) {
                    d.extend_from_slice(&[u, v]);
                }
                d
            }
            PixelFormat::RGB24 => {
                // Simple RGB conversion (not accurate, just for testing)
                let r = y.saturating_add(((1.370 * (v as f32 - 128.0)) as i16) as u8);
                let g = y.saturating_sub(((0.698 * (v as f32 - 128.0)) as i16) as u8)
                    .saturating_sub(((0.336 * (u as f32 - 128.0)) as i16) as u8);
                let b = y.saturating_add(((1.732 * (u as f32 - 128.0)) as i16) as u8);
                vec![r, g, b].repeat((width * height) as usize)
            }
        };

        Self {
            width,
            height,
            format,
            data,
        }
    }

    /// Create a test pattern (gradient)
    pub fn gradient(width: u32, height: u32, format: PixelFormat) -> Self {
        let data_size = match format {
            PixelFormat::YUYV => (width * height * 2) as usize,
            PixelFormat::I420 => ((width * height * 3) / 2) as usize,
            PixelFormat::NV12 => ((width * height * 3) / 2) as usize,
            PixelFormat::RGB24 => (width * height * 3) as usize,
        };

        let mut data = Vec::with_capacity(data_size);

        match format {
            PixelFormat::YUYV => {
                for y in 0..height {
                    for x in 0..width / 2 {
                        let luma = ((x * 255) / (width / 2)) as u8;
                        data.extend_from_slice(&[luma, 128, luma, 128]);
                    }
                }
            }
            _ => {
                // Simple gradient for other formats
                data.extend(vec![128; data_size]);
            }
        }

        Self {
            width,
            height,
            format,
            data,
        }
    }

    /// Convert to VideoFrame
    pub fn to_video_frame(&self) -> VideoFrame {
        VideoFrame {
            width: self.width,
            height: self.height,
            format: self.format,
            data: self.data.clone(),
            timestamp: Duration::from_secs(0),
        }
    }
}

/// Validate NAL unit structure
pub fn is_valid_nal_unit(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }

    // Check for NAL unit start code (0x00 0x00 0x00 0x01)
    data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x00 && data[3] == 0x01
}

/// Extract NAL unit type from frame data
pub fn get_nal_unit_type(data: &[u8]) -> Option<u8> {
    if !is_valid_nal_unit(data) {
        return None;
    }
    Some(data[4] & 0x1F)
}

/// Simple pseudo-random number generator for reproducible tests
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self {
            state: seed.wrapping_add(1),
        }
    }

    fn next(&mut self) -> u64 {
        // Simple LCG (Linear Congruential Generator)
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        self.state
    }

    fn next_u8(&mut self) -> u8 {
        (self.next() >> 32) as u8
    }
}

/// Calculate expected frame size for a given resolution and format
pub fn calculate_frame_size(width: u32, height: u32, format: PixelFormat) -> usize {
    match format {
        PixelFormat::YUYV => (width * height * 2) as usize,
        PixelFormat::I420 | PixelFormat::NV12 => ((width * height * 3) / 2) as usize,
        PixelFormat::RGB24 => (width * height * 3) as usize,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_sps_pps_structure() {
        let sps = mock_sps_nal();
        assert!(is_valid_nal_unit(&sps));
        assert_eq!(get_nal_unit_type(&sps), Some(7)); // SPS

        let pps = mock_pps_nal();
        assert!(is_valid_nal_unit(&pps));
        assert_eq!(get_nal_unit_type(&pps), Some(8)); // PPS
    }

    #[test]
    fn test_mock_iframe_structure() {
        let iframe = mock_iframe_nal(2048, 42);
        assert!(is_valid_nal_unit(&iframe));
        assert_eq!(get_nal_unit_type(&iframe), Some(5)); // IDR
        assert_eq!(iframe.len(), 2048 + 5);
    }

    #[test]
    fn test_mock_pframe_structure() {
        let pframe = mock_pframe_nal(512, 43);
        assert!(is_valid_nal_unit(&pframe));
        assert_eq!(get_nal_unit_type(&pframe), Some(1)); // Non-IDR
        assert_eq!(pframe.len(), 512 + 5);
    }

    #[test]
    fn test_frame_sequence_generation() {
        let frames = mock_frame_sequence(1000, 30, 30);

        // Should have SPS/PPS + ~30 frames
        assert!(frames.len() >= 30);
        assert_eq!(frames[0].frame_type, FrameType::SpsPps);
        assert_eq!(frames[1].frame_type, FrameType::IFrame);

        // Check timestamp progression
        for i in 1..frames.len() {
            if frames[i].frame_type != FrameType::SpsPps {
                assert!(frames[i].timestamp_us > frames[i - 1].timestamp_us);
            }
        }
    }

    #[test]
    fn test_mock_yuv_frame_sizes() {
        let yuyv_frame = MockYuvFrame::solid_color(1280, 720, PixelFormat::YUYV, 128, 128, 128);
        assert_eq!(yuyv_frame.data.len(), 1280 * 720 * 2);

        let i420_frame = MockYuvFrame::solid_color(1280, 720, PixelFormat::I420, 128, 128, 128);
        assert_eq!(i420_frame.data.len(), (1280 * 720 * 3) / 2);
    }

    #[test]
    fn test_reproducible_random_generation() {
        let frame1 = mock_iframe_nal(1024, 100);
        let frame2 = mock_iframe_nal(1024, 100);
        assert_eq!(frame1, frame2);

        let frame3 = mock_iframe_nal(1024, 101);
        assert_ne!(frame1, frame3);
    }
}
