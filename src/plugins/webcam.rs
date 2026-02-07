//! Webcam plugin
//!
//! Receives webcam video stream from the paired desktop device.
//! This is the reverse direction of the Camera plugin — desktop webcam → phone display.

use crate::protocol::Packet;
use crate::error::Result;
use serde_json::json;

/// Webcam data packet type (desktop → phone)
pub const PACKET_TYPE_WEBCAM: &str = "cconnect.webcam";
/// Webcam request packet type (phone → desktop)
pub const PACKET_TYPE_WEBCAM_REQUEST: &str = "cconnect.webcam.request";
/// Webcam capability packet type
pub const PACKET_TYPE_WEBCAM_CAPABILITY: &str = "cconnect.webcam.capability";

/// Create a webcam start request packet
///
/// Requests the desktop to start streaming its webcam.
pub fn create_webcam_start_request(
    camera_id: Option<String>,
    width: Option<i32>,
    height: Option<i32>,
) -> Result<Packet> {
    let mut body = json!({"action": "start"});
    if let Some(id) = camera_id {
        body["cameraId"] = json!(id);
    }
    if let Some(w) = width {
        body["width"] = json!(w);
    }
    if let Some(h) = height {
        body["height"] = json!(h);
    }
    Ok(Packet::new(PACKET_TYPE_WEBCAM_REQUEST, body))
}

/// Create a webcam stop request packet
///
/// Requests the desktop to stop streaming its webcam.
pub fn create_webcam_stop_request() -> Result<Packet> {
    Ok(Packet::new(PACKET_TYPE_WEBCAM_REQUEST, json!({"action": "stop"})))
}

/// Create a webcam capability request packet
///
/// Requests the desktop to report its webcam capabilities.
pub fn create_webcam_capability_request() -> Result<Packet> {
    Ok(Packet::new(PACKET_TYPE_WEBCAM_REQUEST, json!({"action": "capabilities"})))
}

/// Create a webcam status packet
///
/// Reports webcam streaming state.
pub fn create_webcam_status(streaming: bool, camera_id: Option<String>) -> Result<Packet> {
    let mut body = json!({"streaming": streaming});
    if let Some(id) = camera_id {
        body["cameraId"] = json!(id);
    }
    Ok(Packet::new(PACKET_TYPE_WEBCAM, body))
}

/// Create a webcam capability announcement packet
///
/// Announces available webcams and supported resolutions.
pub fn create_webcam_capability(cameras_json: String) -> Result<Packet> {
    let body: serde_json::Value = serde_json::from_str(&cameras_json)?;
    Ok(Packet::new(PACKET_TYPE_WEBCAM_CAPABILITY, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_webcam_start_request_minimal() {
        let packet = create_webcam_start_request(None, None, None).unwrap();
        assert_eq!(packet.packet_type, PACKET_TYPE_WEBCAM_REQUEST);
        assert_eq!(packet.body["action"], "start");
    }

    #[test]
    fn test_create_webcam_start_request_with_params() {
        let packet = create_webcam_start_request(
            Some("webcam0".to_string()),
            Some(1920),
            Some(1080),
        ).unwrap();
        assert_eq!(packet.body["action"], "start");
        assert_eq!(packet.body["cameraId"], "webcam0");
        assert_eq!(packet.body["width"], 1920);
        assert_eq!(packet.body["height"], 1080);
    }

    #[test]
    fn test_create_webcam_stop_request() {
        let packet = create_webcam_stop_request().unwrap();
        assert_eq!(packet.packet_type, PACKET_TYPE_WEBCAM_REQUEST);
        assert_eq!(packet.body["action"], "stop");
    }

    #[test]
    fn test_create_webcam_capability_request() {
        let packet = create_webcam_capability_request().unwrap();
        assert_eq!(packet.packet_type, PACKET_TYPE_WEBCAM_REQUEST);
        assert_eq!(packet.body["action"], "capabilities");
    }

    #[test]
    fn test_create_webcam_status_streaming() {
        let packet = create_webcam_status(true, Some("webcam0".to_string())).unwrap();
        assert_eq!(packet.packet_type, PACKET_TYPE_WEBCAM);
        assert_eq!(packet.body["streaming"], true);
        assert_eq!(packet.body["cameraId"], "webcam0");
    }

    #[test]
    fn test_create_webcam_status_not_streaming() {
        let packet = create_webcam_status(false, None).unwrap();
        assert_eq!(packet.body["streaming"], false);
    }

    #[test]
    fn test_create_webcam_capability() {
        let json = r#"{"cameras": [{"id": "webcam0", "name": "Built-in Webcam"}]}"#;
        let packet = create_webcam_capability(json.to_string()).unwrap();
        assert_eq!(packet.packet_type, PACKET_TYPE_WEBCAM_CAPABILITY);
    }
}
