//! H.264 Video Decoder
//!
//! Wrapper around OpenH264 for decoding H.264 NAL units from Android camera.

use crate::video::frame::{PixelFormat, VideoFrame};
use openh264::decoder::{Decoder, DecodedYUV};
use openh264::Error as OpenH264Error;
use std::fmt;
use tracing::{debug, trace, warn};

/// Error types for H.264 decoding
#[derive(Debug)]
pub enum DecoderError {
    /// Failed to create decoder
    InitError(String),
    /// Failed to decode frame
    DecodeError(String),
    /// Invalid NAL unit
    InvalidNalUnit(String),
    /// No frame available yet (need more data)
    NeedMoreData,
}

impl fmt::Display for DecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecoderError::InitError(msg) => write!(f, "Decoder initialization error: {}", msg),
            DecoderError::DecodeError(msg) => write!(f, "Decode error: {}", msg),
            DecoderError::InvalidNalUnit(msg) => write!(f, "Invalid NAL unit: {}", msg),
            DecoderError::NeedMoreData => write!(f, "Need more data to decode frame"),
        }
    }
}

impl std::error::Error for DecoderError {}

impl From<OpenH264Error> for DecoderError {
    fn from(e: OpenH264Error) -> Self {
        DecoderError::DecodeError(format!("{:?}", e))
    }
}

/// H.264 decoder for Android camera streams
///
/// Decodes Annex B formatted H.264 NAL units to YUV frames.
pub struct H264Decoder {
    /// OpenH264 decoder instance
    decoder: Decoder,
    /// Expected width (from SPS)
    width: Option<u32>,
    /// Expected height (from SPS)
    height: Option<u32>,
    /// Frame counter for statistics
    frames_decoded: u64,
    /// Cached SPS data
    sps: Option<Vec<u8>>,
    /// Cached PPS data
    pps: Option<Vec<u8>>,
    /// Whether decoder is initialized with SPS/PPS
    initialized: bool,
}

impl H264Decoder {
    /// Create a new H.264 decoder
    pub fn new() -> Result<Self, DecoderError> {
        let decoder = Decoder::new()
            .map_err(|e| DecoderError::InitError(format!("{:?}", e)))?;

        Ok(Self {
            decoder,
            width: None,
            height: None,
            frames_decoded: 0,
            sps: None,
            pps: None,
            initialized: false,
        })
    }

    /// Set SPS and PPS for decoder initialization
    ///
    /// Must be called before decoding frames. The SPS/PPS are sent
    /// periodically from Android as `sps_pps` frame type.
    pub fn set_sps_pps(&mut self, sps: &[u8], pps: &[u8]) -> Result<(), DecoderError> {
        debug!("Setting SPS ({} bytes) and PPS ({} bytes)", sps.len(), pps.len());

        // Validate start codes
        if !Self::has_start_code(sps) {
            return Err(DecoderError::InvalidNalUnit("SPS missing start code".into()));
        }
        if !Self::has_start_code(pps) {
            return Err(DecoderError::InvalidNalUnit("PPS missing start code".into()));
        }

        self.sps = Some(sps.to_vec());
        self.pps = Some(pps.to_vec());

        // Decode SPS to initialize decoder
        self.decoder.decode(sps)?;
        self.decoder.decode(pps)?;

        self.initialized = true;
        Ok(())
    }

    /// Check if decoder is initialized with SPS/PPS
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get expected frame dimensions (from SPS)
    pub fn dimensions(&self) -> Option<(u32, u32)> {
        match (self.width, self.height) {
            (Some(w), Some(h)) => Some((w, h)),
            _ => None,
        }
    }

    /// Get number of frames decoded
    pub fn frames_decoded(&self) -> u64 {
        self.frames_decoded
    }

    /// Decode an H.264 NAL unit
    ///
    /// The input should be in Annex B format (with 00 00 00 01 start codes).
    /// Returns a decoded frame if one is available.
    pub fn decode(&mut self, nal_unit: &[u8], timestamp_us: u64) -> Result<Option<VideoFrame>, DecoderError> {
        if !self.initialized {
            warn!("Decoder not initialized, need SPS/PPS first");
            return Err(DecoderError::NeedMoreData);
        }

        // Validate start code
        if !Self::has_start_code(nal_unit) {
            return Err(DecoderError::InvalidNalUnit("Missing start code".into()));
        }

        trace!("Decoding NAL unit: {} bytes", nal_unit.len());

        // Decode the NAL unit
        let maybe_yuv = self.decoder.decode(nal_unit)?;

        if let Some(yuv) = maybe_yuv {
            self.frames_decoded += 1;

            // Extract dimensions from decoded frame
            let (width, height) = yuv.dimension_rgb();
            self.width = Some(width as u32);
            self.height = Some(height as u32);

            // Convert to VideoFrame
            let frame = self.yuv_to_frame(yuv, timestamp_us)?;
            Ok(Some(frame))
        } else {
            // Need more data
            Ok(None)
        }
    }

    /// Decode combined SPS+PPS data (Android format)
    ///
    /// Android sends SPS and PPS concatenated with start codes.
    pub fn decode_sps_pps(&mut self, combined: &[u8]) -> Result<(), DecoderError> {
        // Find the split point between SPS and PPS
        // Both have start codes, so we look for the second one
        let (sps, pps) = Self::split_sps_pps(combined)?;
        self.set_sps_pps(sps, pps)
    }

    /// Split combined SPS+PPS into individual units
    fn split_sps_pps(data: &[u8]) -> Result<(&[u8], &[u8]), DecoderError> {
        // Find all start codes in the data
        let mut positions = Vec::new();
        let mut i = 0;

        while i < data.len() - 3 {
            if data[i] == 0 && data[i + 1] == 0 {
                if data[i + 2] == 1 {
                    positions.push(i);
                    i += 3;
                } else if i < data.len() - 4 && data[i + 2] == 0 && data[i + 3] == 1 {
                    positions.push(i);
                    i += 4;
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }

        if positions.len() < 2 {
            return Err(DecoderError::InvalidNalUnit(
                "Combined SPS+PPS must have at least 2 NAL units".into(),
            ));
        }

        let sps = &data[positions[0]..positions[1]];
        let pps = &data[positions[1]..];

        Ok((sps, pps))
    }

    /// Check if data has H.264 start code
    fn has_start_code(data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }

        // Check for 3-byte start code (00 00 01)
        if data[0] == 0 && data[1] == 0 && data[2] == 1 {
            return true;
        }

        // Check for 4-byte start code (00 00 00 01)
        if data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 1 {
            return true;
        }

        false
    }

    /// Convert OpenH264 YUV output to VideoFrame
    fn yuv_to_frame(&self, yuv: DecodedYUV, timestamp_us: u64) -> Result<VideoFrame, DecoderError> {
        let (width, height) = yuv.dimension_rgb();

        // OpenH264 outputs I420 format
        let y_stride = yuv.strides_yuv().0;
        let u_stride = yuv.strides_yuv().1;
        let v_stride = yuv.strides_yuv().2;

        let y_plane = yuv.y();
        let u_plane = yuv.u();
        let v_plane = yuv.v();

        // Calculate sizes
        let y_size = width * height;
        let uv_size = (width / 2) * (height / 2);

        // Allocate output buffer
        let mut data = Vec::with_capacity(y_size + uv_size * 2);

        // Copy Y plane (with stride handling)
        for row in 0..height {
            let src_offset = row * y_stride;
            let src_end = src_offset + width;
            if src_end <= y_plane.len() {
                data.extend_from_slice(&y_plane[src_offset..src_end]);
            }
        }

        // Copy U plane
        for row in 0..(height / 2) {
            let src_offset = row * u_stride;
            let src_end = src_offset + (width / 2);
            if src_end <= u_plane.len() {
                data.extend_from_slice(&u_plane[src_offset..src_end]);
            }
        }

        // Copy V plane
        for row in 0..(height / 2) {
            let src_offset = row * v_stride;
            let src_end = src_offset + (width / 2);
            if src_end <= v_plane.len() {
                data.extend_from_slice(&v_plane[src_offset..src_end]);
            }
        }

        Ok(VideoFrame::from_data(
            width as u32,
            height as u32,
            PixelFormat::I420,
            timestamp_us,
            data,
        ))
    }

    /// Reset decoder state
    ///
    /// Called when stream restarts or after errors.
    pub fn reset(&mut self) -> Result<(), DecoderError> {
        debug!("Resetting H.264 decoder");

        // Create new decoder instance
        self.decoder = Decoder::new()
            .map_err(|e| DecoderError::InitError(format!("{:?}", e)))?;

        // Re-initialize with cached SPS/PPS if available
        if let (Some(sps), Some(pps)) = (self.sps.as_ref(), self.pps.as_ref()) {
            self.decoder.decode(sps)?;
            self.decoder.decode(pps)?;
        } else {
            self.initialized = false;
        }

        Ok(())
    }
}

impl Default for H264Decoder {
    fn default() -> Self {
        Self::new().expect("Failed to create H264 decoder")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_start_code() {
        // 3-byte start code
        assert!(H264Decoder::has_start_code(&[0, 0, 1, 0x67]));

        // 4-byte start code
        assert!(H264Decoder::has_start_code(&[0, 0, 0, 1, 0x67]));

        // No start code
        assert!(!H264Decoder::has_start_code(&[1, 2, 3, 4]));

        // Too short
        assert!(!H264Decoder::has_start_code(&[0, 0]));
    }

    #[test]
    fn test_decoder_new() {
        let decoder = H264Decoder::new();
        assert!(decoder.is_ok());

        let decoder = decoder.unwrap();
        assert!(!decoder.is_initialized());
        assert_eq!(decoder.frames_decoded(), 0);
    }
}
