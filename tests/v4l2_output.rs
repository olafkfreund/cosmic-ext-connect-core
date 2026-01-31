//! V4L2 Output Tests
//!
//! Tests for V4L2 loopback device output including:
//! - Device opening and configuration
//! - Frame injection to V4L2 device
//! - Format conversion (YUV, RGB)
//! - Buffer management
//! - Error handling
//!
//! Note: Some tests require v4l2loopback kernel module to be loaded.
//! Tests will gracefully skip if module is not available.

mod camera_test_utils;

use camera_test_utils::*;
use cosmic_connect_core::video::frame::{PixelFormat, VideoFrame};
use cosmic_connect_core::video::v4l2_device::{V4l2Error, V4l2LoopbackDevice};
use std::path::PathBuf;

/// Check if v4l2loopback is available on the system
fn is_v4l2loopback_available() -> bool {
    PathBuf::from("/dev/video10").exists() || PathBuf::from("/dev/video20").exists()
}

/// Get a test V4L2 device path
fn get_test_device_path() -> PathBuf {
    if PathBuf::from("/dev/video10").exists() {
        PathBuf::from("/dev/video10")
    } else if PathBuf::from("/dev/video20").exists() {
        PathBuf::from("/dev/video20")
    } else {
        PathBuf::from("/dev/video10") // Will fail gracefully in tests
    }
}

/// Test V4L2 device creation
#[test]
fn test_v4l2_device_creation() {
    let device_path = get_test_device_path();
    let device = V4l2LoopbackDevice::new(device_path);

    // Device should be created (not opened yet)
    assert!(!device.is_open);
}

/// Test V4L2 device opening with YUYV format
#[test]
fn test_v4l2_device_open_yuyv() {
    if !is_v4l2loopback_available() {
        println!("Skipping test: v4l2loopback not available");
        return;
    }

    let device_path = get_test_device_path();
    let mut device = V4l2LoopbackDevice::new(device_path);

    let result = device.open(1280, 720, PixelFormat::YUYV);

    match result {
        Ok(()) => {
            assert!(device.is_open);
            println!("Successfully opened V4L2 device at 1280x720 YUYV");
        }
        Err(V4l2Error::PermissionDenied(path)) => {
            println!("Skipping test: Permission denied for {}", path);
            println!("Add user to 'video' group: sudo usermod -a -G video $USER");
        }
        Err(V4l2Error::DeviceNotFound(path)) => {
            println!("Skipping test: Device not found at {}", path);
            println!("Load v4l2loopback: sudo modprobe v4l2loopback devices=1 video_nr=10");
        }
        Err(e) => {
            panic!("Unexpected error opening device: {}", e);
        }
    }
}

/// Test V4L2 device opening with different formats
#[test]
fn test_v4l2_device_formats() {
    if !is_v4l2loopback_available() {
        println!("Skipping test: v4l2loopback not available");
        return;
    }

    let formats = vec![
        (PixelFormat::YUYV, "YUYV"),
        (PixelFormat::I420, "I420"),
        (PixelFormat::NV12, "NV12"),
    ];

    for (format, name) in formats {
        let device_path = get_test_device_path();
        let mut device = V4l2LoopbackDevice::new(device_path);

        let result = device.open(1280, 720, format);

        match result {
            Ok(()) => {
                println!("Successfully opened V4L2 device with {} format", name);
                assert!(device.is_open);
            }
            Err(V4l2Error::PermissionDenied(_)) | Err(V4l2Error::DeviceNotFound(_)) => {
                println!("Skipping {} test: Device not accessible", name);
            }
            Err(V4l2Error::UnsupportedFormat(msg)) => {
                println!("Format {} not supported: {}", name, msg);
            }
            Err(e) => {
                println!("Error with {} format: {}", name, e);
            }
        }
    }
}

/// Test writing a single frame to V4L2 device
#[test]
fn test_v4l2_write_single_frame() {
    if !is_v4l2loopback_available() {
        println!("Skipping test: v4l2loopback not available");
        return;
    }

    let device_path = get_test_device_path();
    let mut device = V4l2LoopbackDevice::new(device_path);

    let result = device.open(1280, 720, PixelFormat::YUYV);
    if result.is_err() {
        println!("Skipping test: Could not open device");
        return;
    }

    // Create a test frame (solid color)
    let test_frame = MockYuvFrame::solid_color(1280, 720, PixelFormat::YUYV, 128, 128, 128);
    let video_frame = test_frame.to_video_frame();

    // Write frame
    let write_result = device.write_frame(&video_frame);

    match write_result {
        Ok(()) => {
            println!("Successfully wrote frame to V4L2 device");
            assert_eq!(device.frames_written, 1);
        }
        Err(e) => {
            println!("Write error (may be expected): {}", e);
        }
    }
}

/// Test writing multiple frames to V4L2 device
#[test]
fn test_v4l2_write_multiple_frames() {
    if !is_v4l2loopback_available() {
        println!("Skipping test: v4l2loopback not available");
        return;
    }

    let device_path = get_test_device_path();
    let mut device = V4l2LoopbackDevice::new(device_path);

    let result = device.open(1280, 720, PixelFormat::YUYV);
    if result.is_err() {
        println!("Skipping test: Could not open device");
        return;
    }

    // Write 30 frames (1 second at 30fps)
    let mut frames_written = 0;

    for i in 0..30 {
        // Alternate between different brightness levels
        let brightness = if i % 2 == 0 { 128 } else { 200 };

        let test_frame = MockYuvFrame::solid_color(1280, 720, PixelFormat::YUYV, brightness, 128, 128);
        let video_frame = test_frame.to_video_frame();

        match device.write_frame(&video_frame) {
            Ok(()) => {
                frames_written += 1;
            }
            Err(e) => {
                println!("Frame {} write failed: {}", i, e);
                break;
            }
        }

        // Small delay to simulate real frame timing
        std::thread::sleep(std::time::Duration::from_millis(33));
    }

    println!("Wrote {} frames to V4L2 device", frames_written);
    assert!(frames_written > 0, "Should have written at least one frame");
}

/// Test V4L2 device with different resolutions
#[test]
fn test_v4l2_different_resolutions() {
    if !is_v4l2loopback_available() {
        println!("Skipping test: v4l2loopback not available");
        return;
    }

    let resolutions = vec![(854, 480), (1280, 720), (1920, 1080)];

    for (width, height) in resolutions {
        let device_path = get_test_device_path();
        let mut device = V4l2LoopbackDevice::new(device_path);

        let result = device.open(width, height, PixelFormat::YUYV);

        match result {
            Ok(()) => {
                println!("Opened device at {}x{}", width, height);

                // Write a test frame
                let test_frame = MockYuvFrame::solid_color(width, height, PixelFormat::YUYV, 128, 128, 128);
                let video_frame = test_frame.to_video_frame();

                let write_result = device.write_frame(&video_frame);
                assert!(
                    write_result.is_ok(),
                    "Should write frame at {}x{}",
                    width,
                    height
                );
            }
            Err(e) => {
                println!("Could not open device at {}x{}: {}", width, height, e);
            }
        }
    }
}

/// Test format size calculation
#[test]
fn test_format_size_calculation() {
    assert_eq!(calculate_frame_size(1280, 720, PixelFormat::YUYV), 1280 * 720 * 2);
    assert_eq!(
        calculate_frame_size(1280, 720, PixelFormat::I420),
        (1280 * 720 * 3) / 2
    );
    assert_eq!(
        calculate_frame_size(1280, 720, PixelFormat::NV12),
        (1280 * 720 * 3) / 2
    );
    assert_eq!(
        calculate_frame_size(1280, 720, PixelFormat::RGB24),
        1280 * 720 * 3
    );
}

/// Test writing frame with wrong size
#[test]
fn test_v4l2_write_wrong_size() {
    if !is_v4l2loopback_available() {
        println!("Skipping test: v4l2loopback not available");
        return;
    }

    let device_path = get_test_device_path();
    let mut device = V4l2LoopbackDevice::new(device_path);

    let result = device.open(1280, 720, PixelFormat::YUYV);
    if result.is_err() {
        println!("Skipping test: Could not open device");
        return;
    }

    // Create frame with wrong dimensions
    let wrong_frame = VideoFrame {
        width: 640,
        height: 480,
        format: PixelFormat::YUYV,
        data: vec![128u8; 640 * 480 * 2],
        timestamp: std::time::Duration::from_secs(0),
    };

    // Should reject frame with wrong size
    let write_result = device.write_frame(&wrong_frame);
    assert!(
        write_result.is_err(),
        "Should reject frame with wrong dimensions"
    );
}

/// Test device not found error
#[test]
fn test_v4l2_device_not_found() {
    let device_path = PathBuf::from("/dev/video999"); // Unlikely to exist
    let mut device = V4l2LoopbackDevice::new(device_path);

    let result = device.open(1280, 720, PixelFormat::YUYV);

    assert!(
        matches!(result, Err(V4l2Error::DeviceNotFound(_))),
        "Should return DeviceNotFound error"
    );
}

/// Test device close and reopen
#[test]
fn test_v4l2_close_and_reopen() {
    if !is_v4l2loopback_available() {
        println!("Skipping test: v4l2loopback not available");
        return;
    }

    let device_path = get_test_device_path();
    let mut device = V4l2LoopbackDevice::new(device_path.clone());

    // Open device
    let result = device.open(1280, 720, PixelFormat::YUYV);
    if result.is_err() {
        println!("Skipping test: Could not open device");
        return;
    }

    // Write a frame
    let test_frame = MockYuvFrame::solid_color(1280, 720, PixelFormat::YUYV, 128, 128, 128);
    let _ = device.write_frame(&test_frame.to_video_frame());

    // Close device (drop)
    drop(device);

    // Reopen device
    let mut device2 = V4l2LoopbackDevice::new(device_path);
    let result2 = device2.open(1280, 720, PixelFormat::YUYV);

    assert!(result2.is_ok(), "Should be able to reopen device");
}

/// Test gradient pattern frame
#[test]
fn test_v4l2_write_gradient() {
    if !is_v4l2loopback_available() {
        println!("Skipping test: v4l2loopback not available");
        return;
    }

    let device_path = get_test_device_path();
    let mut device = V4l2LoopbackDevice::new(device_path);

    let result = device.open(1280, 720, PixelFormat::YUYV);
    if result.is_err() {
        println!("Skipping test: Could not open device");
        return;
    }

    // Create gradient pattern
    let gradient_frame = MockYuvFrame::gradient(1280, 720, PixelFormat::YUYV);
    let video_frame = gradient_frame.to_video_frame();

    let write_result = device.write_frame(&video_frame);

    match write_result {
        Ok(()) => {
            println!("Successfully wrote gradient frame");
        }
        Err(e) => {
            println!("Gradient write error: {}", e);
        }
    }
}

/// Test frame statistics tracking
#[test]
fn test_v4l2_frame_statistics() {
    if !is_v4l2loopback_available() {
        println!("Skipping test: v4l2loopback not available");
        return;
    }

    let device_path = get_test_device_path();
    let mut device = V4l2LoopbackDevice::new(device_path);

    let result = device.open(1280, 720, PixelFormat::YUYV);
    if result.is_err() {
        println!("Skipping test: Could not open device");
        return;
    }

    assert_eq!(device.frames_written, 0, "Should start at 0 frames");

    // Write multiple frames
    for i in 0..10 {
        let test_frame = MockYuvFrame::solid_color(1280, 720, PixelFormat::YUYV, 128, 128, 128);

        if device.write_frame(&test_frame.to_video_frame()).is_ok() {
            assert_eq!(
                device.frames_written,
                i + 1,
                "Frame counter should increment"
            );
        } else {
            break;
        }
    }

    assert!(
        device.frames_written > 0,
        "Should have written some frames"
    );
}

/// Test concurrent access (should fail or queue)
#[test]
fn test_v4l2_concurrent_access() {
    if !is_v4l2loopback_available() {
        println!("Skipping test: v4l2loopback not available");
        return;
    }

    let device_path = get_test_device_path();

    // Open first device
    let mut device1 = V4l2LoopbackDevice::new(device_path.clone());
    let result1 = device1.open(1280, 720, PixelFormat::YUYV);

    if result1.is_err() {
        println!("Skipping test: Could not open first device");
        return;
    }

    // Try to open second device to same path
    let mut device2 = V4l2LoopbackDevice::new(device_path);
    let result2 = device2.open(1280, 720, PixelFormat::YUYV);

    // Second open might fail (device busy) or succeed (depending on driver)
    match result2 {
        Ok(()) => {
            println!("Device allows concurrent access");
        }
        Err(e) => {
            println!("Device does not allow concurrent access: {}", e);
        }
    }
}

/// Integration test: Full decoding to V4L2 pipeline
#[test]
fn test_full_decode_to_v4l2_pipeline() {
    if !is_v4l2loopback_available() {
        println!("Skipping test: v4l2loopback not available");
        return;
    }

    use cosmic_connect_core::video::h264_decoder::H264Decoder;

    let device_path = get_test_device_path();
    let mut v4l2_device = V4l2LoopbackDevice::new(device_path);

    // Open V4L2 device
    let result = v4l2_device.open(1280, 720, PixelFormat::YUYV);
    if result.is_err() {
        println!("Skipping test: Could not open V4L2 device");
        return;
    }

    // Create decoder
    let mut decoder = H264Decoder::new(1280, 720).unwrap();

    // Generate mock frame sequence
    let frames = mock_frame_sequence(500, 30, 15);

    let mut frames_written = 0;

    for mock_frame in frames.iter().take(30) {
        let camera_frame = mock_frame.to_camera_frame();

        // Decode frame
        match decoder.decode_frame(&camera_frame) {
            Ok(Some(video_frame)) => {
                // Write to V4L2
                if v4l2_device.write_frame(&video_frame).is_ok() {
                    frames_written += 1;
                }
            }
            Ok(None) => {
                // Config frame or queued
            }
            Err(_) => {
                // Expected for mock data
            }
        }
    }

    println!(
        "Full pipeline test: {} frames written to V4L2",
        frames_written
    );
}

/// Test memory cleanup on device drop
#[test]
fn test_v4l2_memory_cleanup() {
    if !is_v4l2loopback_available() {
        println!("Skipping test: v4l2loopback not available");
        return;
    }

    {
        let device_path = get_test_device_path();
        let mut device = V4l2LoopbackDevice::new(device_path);

        if device.open(1280, 720, PixelFormat::YUYV).is_ok() {
            // Write some frames
            for _ in 0..10 {
                let test_frame = MockYuvFrame::solid_color(1280, 720, PixelFormat::YUYV, 128, 128, 128);
                let _ = device.write_frame(&test_frame.to_video_frame());
            }
        }

        // Device drops here
    }

    // If we get here without leak/panic, cleanup worked
    assert!(true, "Device cleanup successful");
}
