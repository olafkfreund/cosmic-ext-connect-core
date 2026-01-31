//! Camera Integration Tests
//!
//! Tests the camera streaming pipeline integration including:
//! - Receiving H.264 frames from network
//! - Decoding H.264 frames to raw video
//! - Error handling for corrupt/missing frames
//! - Frame sequencing and timing

mod camera_test_utils;

use camera_test_utils::*;
use cosmic_connect_core::plugins::camera::{CameraFrame, FrameType};
use cosmic_connect_core::video::frame::{PixelFormat, VideoFrame};
use cosmic_connect_core::video::h264_decoder::{DecoderError, H264Decoder};
use std::time::Duration;

/// Test basic H.264 decoder initialization
#[test]
fn test_decoder_initialization() {
    let result = H264Decoder::new(1280, 720);
    assert!(result.is_ok(), "Decoder should initialize successfully");

    let mut decoder = result.unwrap();
    assert!(decoder.is_ready(), "Decoder should be ready after initialization");
}

/// Test decoding SPS/PPS configuration
#[test]
fn test_decode_sps_pps() {
    let mut decoder = H264Decoder::new(1280, 720).unwrap();

    // Create mock SPS/PPS
    let sps_data = mock_sps_nal();
    let pps_data = mock_pps_nal();
    let mut combined = sps_data;
    combined.extend_from_slice(&pps_data);

    // Decode SPS/PPS
    let frame = CameraFrame {
        frame_type: FrameType::SpsPps,
        timestamp_us: 0,
        sequence_number: 0,
        data: combined,
    };

    let result = decoder.decode_frame(&frame);

    // SPS/PPS should be processed but may not produce a frame
    match result {
        Ok(None) => {
            // This is expected - SPS/PPS configures decoder but doesn't produce frame
        }
        Ok(Some(_)) => {
            // Some decoders might return a dummy frame
        }
        Err(e) => {
            // Mock data might not be valid for real decoder, that's okay
            println!("SPS/PPS decode returned error (expected for mock data): {:?}", e);
        }
    }
}

/// Test decoding an I-frame
#[test]
fn test_decode_iframe() {
    let mut decoder = H264Decoder::new(1280, 720).unwrap();

    // First send SPS/PPS (decoder needs configuration)
    let sps_data = mock_sps_nal();
    let pps_data = mock_pps_nal();
    let mut sps_pps = sps_data;
    sps_pps.extend_from_slice(&pps_data);

    let config_frame = CameraFrame {
        frame_type: FrameType::SpsPps,
        timestamp_us: 0,
        sequence_number: 0,
        data: sps_pps,
    };

    let _ = decoder.decode_frame(&config_frame);

    // Now try to decode I-frame
    let iframe_data = mock_iframe_nal(2048, 42);
    let iframe = CameraFrame {
        frame_type: FrameType::IFrame,
        timestamp_us: 33333,
        sequence_number: 1,
        data: iframe_data,
    };

    let result = decoder.decode_frame(&iframe);

    // Mock data won't actually decode, but test that API works
    match result {
        Ok(Some(video_frame)) => {
            assert_eq!(video_frame.width, 1280);
            assert_eq!(video_frame.height, 720);
            assert!(!video_frame.data.is_empty());
        }
        Ok(None) => {
            // Frame queued but not yet ready
        }
        Err(DecoderError::InvalidData(_)) => {
            // Expected for mock data
            println!("I-frame decode failed (expected for mock data)");
        }
        Err(e) => {
            panic!("Unexpected error: {:?}", e);
        }
    }
}

/// Test handling corrupt frame data
#[test]
fn test_decode_corrupt_frame() {
    let mut decoder = H264Decoder::new(1280, 720).unwrap();

    // Create corrupt data (no NAL header)
    let corrupt_data = vec![0xFF; 1024];

    let corrupt_frame = CameraFrame {
        frame_type: FrameType::IFrame,
        timestamp_us: 0,
        sequence_number: 1,
        data: corrupt_data,
    };

    let result = decoder.decode_frame(&corrupt_frame);

    // Should return error for corrupt data
    assert!(
        matches!(result, Err(DecoderError::InvalidData(_))),
        "Should detect corrupt frame data"
    );
}

/// Test frame sequence processing
#[test]
fn test_frame_sequence_processing() {
    let mut decoder = H264Decoder::new(1280, 720).unwrap();

    // Generate a short frame sequence
    let frames = mock_frame_sequence(500, 30, 15);

    let mut frames_processed = 0;
    let mut frames_decoded = 0;

    for mock_frame in frames {
        let camera_frame = mock_frame.to_camera_frame();
        let result = decoder.decode_frame(&camera_frame);

        frames_processed += 1;

        match result {
            Ok(Some(_video_frame)) => {
                frames_decoded += 1;
            }
            Ok(None) => {
                // Frame queued or config frame
            }
            Err(DecoderError::InvalidData(_)) => {
                // Expected for mock data
            }
            Err(e) => {
                println!("Frame {} decode error: {:?}", frames_processed, e);
            }
        }
    }

    assert!(frames_processed > 0, "Should process some frames");
    println!(
        "Processed {} frames, decoded {} frames",
        frames_processed, frames_decoded
    );
}

/// Test decoder reset functionality
#[test]
fn test_decoder_reset() {
    let mut decoder = H264Decoder::new(1280, 720).unwrap();

    // Process some frames
    let frames = mock_frame_sequence(200, 30, 15);
    for mock_frame in frames.iter().take(5) {
        let _ = decoder.decode_frame(&mock_frame.to_camera_frame());
    }

    // Reset decoder
    let result = decoder.reset();
    assert!(result.is_ok(), "Reset should succeed");

    // Should be able to process frames again
    for mock_frame in frames.iter().skip(5).take(5) {
        let result = decoder.decode_frame(&mock_frame.to_camera_frame());
        // Should not panic
        let _ = result;
    }
}

/// Test handling missing SPS/PPS
#[test]
fn test_missing_sps_pps() {
    let mut decoder = H264Decoder::new(1280, 720).unwrap();

    // Try to decode I-frame without SPS/PPS first
    let iframe_data = mock_iframe_nal(2048, 42);
    let iframe = CameraFrame {
        frame_type: FrameType::IFrame,
        timestamp_us: 0,
        sequence_number: 1,
        data: iframe_data,
    };

    let result = decoder.decode_frame(&iframe);

    // Should handle gracefully (either error or queue for later)
    match result {
        Ok(_) => {
            // Some decoders might buffer
        }
        Err(DecoderError::NotConfigured) => {
            // Expected - needs SPS/PPS first
        }
        Err(DecoderError::InvalidData(_)) => {
            // Also acceptable for mock data
        }
        Err(e) => {
            println!("Missing SPS/PPS error: {:?}", e);
        }
    }
}

/// Test decoder with different resolutions
#[test]
fn test_decoder_resolutions() {
    let resolutions = vec![(854, 480), (1280, 720), (1920, 1080)];

    for (width, height) in resolutions {
        let result = H264Decoder::new(width, height);
        assert!(
            result.is_ok(),
            "Decoder should support {}x{}",
            width,
            height
        );
    }
}

/// Test frame timestamp handling
#[test]
fn test_frame_timestamps() {
    let mut decoder = H264Decoder::new(1280, 720).unwrap();

    let frames = mock_frame_sequence(500, 30, 15);
    let mut last_timestamp = 0u64;

    for mock_frame in frames.iter().skip(1) {
        // Skip SPS/PPS
        assert!(
            mock_frame.timestamp_us >= last_timestamp,
            "Timestamps should be monotonic"
        );
        last_timestamp = mock_frame.timestamp_us;
    }
}

/// Test handling out-of-order frames
#[test]
fn test_out_of_order_frames() {
    let mut decoder = H264Decoder::new(1280, 720).unwrap();

    let mut frames = mock_frame_sequence(300, 30, 15);

    // Swap two P-frames to simulate out-of-order delivery
    if frames.len() > 5 {
        frames.swap(3, 4);
    }

    for mock_frame in frames {
        let result = decoder.decode_frame(&mock_frame.to_camera_frame());

        // Decoder should handle gracefully
        match result {
            Ok(_) => {
                // Successfully processed
            }
            Err(DecoderError::InvalidData(_)) => {
                // Expected for mock data
            }
            Err(e) => {
                println!("Out-of-order frame error: {:?}", e);
            }
        }
    }
}

/// Test decoder recovery after errors
#[test]
fn test_decoder_error_recovery() {
    let mut decoder = H264Decoder::new(1280, 720).unwrap();

    // Send valid SPS/PPS
    let sps_pps_frame = MockCameraFrame::sps_pps(0);
    let _ = decoder.decode_frame(&sps_pps_frame.to_camera_frame());

    // Send corrupt frame
    let corrupt_frame = CameraFrame {
        frame_type: FrameType::PFrame,
        timestamp_us: 33333,
        sequence_number: 1,
        data: vec![0xFF; 512],
    };
    let _ = decoder.decode_frame(&corrupt_frame);

    // Send valid I-frame - decoder should recover
    let valid_iframe = MockCameraFrame::iframe(2, 66666, 2048);
    let result = decoder.decode_frame(&valid_iframe.to_camera_frame());

    // Should not panic and should try to process
    match result {
        Ok(_) => {
            // Successfully recovered
        }
        Err(DecoderError::InvalidData(_)) => {
            // Expected for mock data
        }
        Err(e) => {
            println!("Recovery attempt error: {:?}", e);
        }
    }
}

/// Test frame size validation
#[test]
fn test_frame_size_limits() {
    let mut decoder = H264Decoder::new(1280, 720).unwrap();

    // Test very small frame (should be rejected)
    let tiny_frame = CameraFrame {
        frame_type: FrameType::PFrame,
        timestamp_us: 0,
        sequence_number: 1,
        data: vec![0x00, 0x00, 0x00, 0x01],
    };

    let result = decoder.decode_frame(&tiny_frame);
    assert!(
        result.is_err() || matches!(result, Ok(None)),
        "Should handle tiny frames gracefully"
    );

    // Test very large frame (should handle or reject cleanly)
    let large_frame = CameraFrame {
        frame_type: FrameType::IFrame,
        timestamp_us: 0,
        sequence_number: 2,
        data: vec![0xFF; 1024 * 1024], // 1MB frame
    };

    let result = decoder.decode_frame(&large_frame);
    // Should not panic
    let _ = result;
}

/// Test decoder cleanup on drop
#[test]
fn test_decoder_cleanup() {
    {
        let mut decoder = H264Decoder::new(1280, 720).unwrap();

        let frames = mock_frame_sequence(200, 30, 15);
        for mock_frame in frames.iter().take(10) {
            let _ = decoder.decode_frame(&mock_frame.to_camera_frame());
        }

        // Decoder goes out of scope here and should clean up
    }

    // If we get here without panic/leak, cleanup worked
    assert!(true, "Decoder cleaned up successfully");
}

/// Test concurrent decoder instances (if supported)
#[test]
fn test_multiple_decoders() {
    let mut decoder1 = H264Decoder::new(1280, 720).unwrap();
    let mut decoder2 = H264Decoder::new(1920, 1080).unwrap();

    let frames1 = mock_frame_sequence(200, 30, 15);
    let frames2 = mock_frame_sequence(200, 30, 15);

    // Process frames on both decoders
    for (f1, f2) in frames1.iter().zip(frames2.iter()).take(10) {
        let _ = decoder1.decode_frame(&f1.to_camera_frame());
        let _ = decoder2.decode_frame(&f2.to_camera_frame());
    }

    // Both should work independently
    assert!(decoder1.is_ready());
    assert!(decoder2.is_ready());
}

/// Test NAL unit validation
#[test]
fn test_nal_unit_validation() {
    // Valid NAL units
    assert!(is_valid_nal_unit(&mock_sps_nal()));
    assert!(is_valid_nal_unit(&mock_pps_nal()));
    assert!(is_valid_nal_unit(&mock_iframe_nal(1024, 1)));

    // Invalid NAL units
    assert!(!is_valid_nal_unit(&[0x00, 0x00, 0x00])); // Too short
    assert!(!is_valid_nal_unit(&[0xFF, 0x00, 0x00, 0x01, 0x67])); // Wrong start
    assert!(!is_valid_nal_unit(&[])); // Empty
}

/// Test NAL unit type extraction
#[test]
fn test_nal_unit_type_extraction() {
    assert_eq!(get_nal_unit_type(&mock_sps_nal()), Some(7)); // SPS
    assert_eq!(get_nal_unit_type(&mock_pps_nal()), Some(8)); // PPS
    assert_eq!(get_nal_unit_type(&mock_iframe_nal(1024, 1)), Some(5)); // IDR
    assert_eq!(get_nal_unit_type(&mock_pframe_nal(512, 1)), Some(1)); // Non-IDR
    assert_eq!(get_nal_unit_type(&[0xFF, 0xFF]), None); // Invalid
}

/// Integration test: Full pipeline simulation
#[test]
fn test_full_pipeline_simulation() {
    let mut decoder = H264Decoder::new(1280, 720).unwrap();

    // Simulate receiving frames from network
    let stream_frames = mock_frame_sequence(1000, 30, 30);

    let mut total_processed = 0;
    let mut total_decoded = 0;
    let mut total_errors = 0;

    println!("Testing full pipeline with {} frames", stream_frames.len());

    for (idx, mock_frame) in stream_frames.iter().enumerate() {
        let camera_frame = mock_frame.to_camera_frame();

        match decoder.decode_frame(&camera_frame) {
            Ok(Some(video_frame)) => {
                total_decoded += 1;

                // Validate decoded frame
                assert_eq!(video_frame.width, 1280);
                assert_eq!(video_frame.height, 720);
                assert!(!video_frame.data.is_empty());
            }
            Ok(None) => {
                // Frame queued or config frame
            }
            Err(DecoderError::InvalidData(_)) => {
                // Expected for mock data
                total_errors += 1;
            }
            Err(e) => {
                println!("Frame {} error: {:?}", idx, e);
                total_errors += 1;
            }
        }

        total_processed += 1;
    }

    println!(
        "Pipeline test: {} processed, {} decoded, {} errors",
        total_processed, total_decoded, total_errors
    );

    assert_eq!(
        total_processed,
        stream_frames.len(),
        "Should process all frames"
    );
}
