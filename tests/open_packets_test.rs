//! Integration tests for Open Plugin packets (App Continuity)
//!
//! Tests packet serialization, deserialization, and FFI bindings for the
//! Open plugin which enables opening URLs, files, and text on remote devices.

use cosmic_connect_core::plugins::open::{
    OpenCapability, OpenContentType, OpenRequest, OpenResponse,
};
use cosmic_connect_core::{
    create_open_capability_packet, create_open_file_packet, create_open_response_packet,
    create_open_text_packet, create_open_url_packet,
};

// =============================================================================
// Packet Type Constants Tests
// =============================================================================

#[test]
fn test_packet_type_constants() {
    // Verify packet type strings match protocol specification
    let url_packet = create_open_url_packet(
        "req-001".to_string(),
        "https://example.com".to_string(),
        None,
    )
    .unwrap();
    assert_eq!(url_packet.packet_type, "cconnect.open.request");

    let response_packet = create_open_response_packet(
        "req-001".to_string(),
        true,
        None,
        Some("Firefox".to_string()),
    )
    .unwrap();
    assert_eq!(response_packet.packet_type, "cconnect.open.response");

    let capability_packet = create_open_capability_packet(
        vec!["http".to_string()],
        1048576,
        vec!["text/*".to_string()],
    )
    .unwrap();
    assert_eq!(capability_packet.packet_type, "cconnect.open.capability");
}

// =============================================================================
// OpenContentType Tests
// =============================================================================

#[test]
fn test_open_content_type_serialization() {
    assert_eq!(
        serde_json::to_string(&OpenContentType::Url).unwrap(),
        r#""url""#
    );
    assert_eq!(
        serde_json::to_string(&OpenContentType::File).unwrap(),
        r#""file""#
    );
    assert_eq!(
        serde_json::to_string(&OpenContentType::Text).unwrap(),
        r#""text""#
    );
}

#[test]
fn test_open_content_type_deserialization() {
    let url_type: OpenContentType = serde_json::from_str(r#""url""#).unwrap();
    assert_eq!(url_type, OpenContentType::Url);

    let file_type: OpenContentType = serde_json::from_str(r#""file""#).unwrap();
    assert_eq!(file_type, OpenContentType::File);

    let text_type: OpenContentType = serde_json::from_str(r#""text""#).unwrap();
    assert_eq!(text_type, OpenContentType::Text);
}

#[test]
fn test_open_content_type_default() {
    assert_eq!(OpenContentType::default(), OpenContentType::Url);
}

// =============================================================================
// OpenCapability Tests
// =============================================================================

#[test]
fn test_open_capability_default() {
    let capability = OpenCapability::default();

    assert!(capability.supported_schemes.contains(&"http".to_string()));
    assert!(capability.supported_schemes.contains(&"https".to_string()));
    assert!(capability.supported_schemes.contains(&"mailto".to_string()));
    assert!(capability.supported_schemes.contains(&"tel".to_string()));

    assert_eq!(capability.max_file_size, 100 * 1024 * 1024); // 100 MB

    assert!(capability
        .supported_mime_types
        .contains(&"text/*".to_string()));
    assert!(capability
        .supported_mime_types
        .contains(&"image/*".to_string()));
    assert!(capability
        .supported_mime_types
        .contains(&"application/pdf".to_string()));
}

#[test]
fn test_open_capability_serialization() {
    let capability = OpenCapability {
        supported_schemes: vec!["http".to_string(), "https".to_string()],
        max_file_size: 104857600,
        supported_mime_types: vec!["text/*".to_string(), "image/*".to_string()],
    };

    let json = serde_json::to_value(&capability).unwrap();
    assert_eq!(json["supportedSchemes"][0], "http");
    assert_eq!(json["supportedSchemes"][1], "https");
    assert_eq!(json["maxFileSize"], 104857600);
    assert_eq!(json["supportedMimeTypes"][0], "text/*");
    assert_eq!(json["supportedMimeTypes"][1], "image/*");
}

#[test]
fn test_open_capability_deserialization() {
    let json = r#"{
        "supportedSchemes": ["http", "https", "mailto"],
        "maxFileSize": 52428800,
        "supportedMimeTypes": ["text/*", "application/pdf"]
    }"#;

    let capability: OpenCapability = serde_json::from_str(json).unwrap();
    assert_eq!(capability.supported_schemes.len(), 3);
    assert_eq!(capability.max_file_size, 52428800);
    assert_eq!(capability.supported_mime_types.len(), 2);
}

// =============================================================================
// OpenRequest Tests
// =============================================================================

#[test]
fn test_open_request_new_url() {
    let request = OpenRequest::new_url(
        "req-001".to_string(),
        "https://example.com".to_string(),
        Some("Example Site".to_string()),
    );

    assert_eq!(request.request_id, "req-001");
    assert_eq!(request.content_type, OpenContentType::Url);
    assert_eq!(request.url.as_deref(), Some("https://example.com"));
    assert_eq!(request.mime_type.as_deref(), Some("text/html"));
    assert_eq!(request.title.as_deref(), Some("Example Site"));
    assert!(request.filename.is_none());
    assert!(request.file_size.is_none());
}

#[test]
fn test_open_request_new_file() {
    let request = OpenRequest::new_file(
        "req-002".to_string(),
        "document.pdf".to_string(),
        "application/pdf".to_string(),
        1048576,
    );

    assert_eq!(request.request_id, "req-002");
    assert_eq!(request.content_type, OpenContentType::File);
    assert_eq!(request.filename.as_deref(), Some("document.pdf"));
    assert_eq!(request.mime_type.as_deref(), Some("application/pdf"));
    assert_eq!(request.file_size, Some(1048576));
    assert!(request.url.is_none());
    assert!(request.title.is_none());
}

#[test]
fn test_open_request_new_text() {
    let request = OpenRequest::new_text("req-003".to_string(), "Hello World".to_string());

    assert_eq!(request.request_id, "req-003");
    assert_eq!(request.content_type, OpenContentType::Text);
    assert_eq!(request.url.as_deref(), Some("Hello World"));
    assert_eq!(request.mime_type.as_deref(), Some("text/plain"));
    assert!(request.filename.is_none());
    assert!(request.file_size.is_none());
}

#[test]
fn test_open_request_serialization() {
    let request = OpenRequest::new_url(
        "req-001".to_string(),
        "https://example.com".to_string(),
        Some("Example".to_string()),
    );

    let json = serde_json::to_value(&request).unwrap();
    assert_eq!(json["requestId"], "req-001");
    assert_eq!(json["contentType"], "url");
    assert_eq!(json["url"], "https://example.com");
    assert_eq!(json["mimeType"], "text/html");
    assert_eq!(json["title"], "Example");

    // Optional fields should not be present
    assert!(json.get("filename").is_none());
    assert!(json.get("fileSize").is_none());
}

#[test]
fn test_open_request_deserialization() {
    let json = r#"{
        "requestId": "req-001",
        "contentType": "url",
        "url": "https://example.com",
        "mimeType": "text/html",
        "title": "Example"
    }"#;

    let request: OpenRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.request_id, "req-001");
    assert_eq!(request.content_type, OpenContentType::Url);
    assert_eq!(request.url.as_deref(), Some("https://example.com"));
    assert_eq!(request.title.as_deref(), Some("Example"));
}

#[test]
fn test_open_request_round_trip() {
    let original = OpenRequest::new_file(
        "req-123".to_string(),
        "test.pdf".to_string(),
        "application/pdf".to_string(),
        5000,
    );

    let json = serde_json::to_string(&original).unwrap();
    let deserialized: OpenRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(original, deserialized);
}

// =============================================================================
// OpenResponse Tests
// =============================================================================

#[test]
fn test_open_response_success() {
    let response = OpenResponse::success("req-001".to_string(), Some("Firefox".to_string()));

    assert!(response.success);
    assert_eq!(response.request_id, "req-001");
    assert_eq!(response.opened_with.as_deref(), Some("Firefox"));
    assert!(response.error_message.is_none());
}

#[test]
fn test_open_response_failure() {
    let response =
        OpenResponse::failure("req-001".to_string(), "File not found".to_string());

    assert!(!response.success);
    assert_eq!(response.request_id, "req-001");
    assert_eq!(response.error_message.as_deref(), Some("File not found"));
    assert!(response.opened_with.is_none());
}

#[test]
fn test_open_response_serialization() {
    let response = OpenResponse::success("req-001".to_string(), Some("Chrome".to_string()));

    let json = serde_json::to_value(&response).unwrap();
    assert_eq!(json["requestId"], "req-001");
    assert_eq!(json["success"], true);
    assert_eq!(json["openedWith"], "Chrome");

    // Error message should not be present on success
    assert!(json.get("errorMessage").is_none());
}

#[test]
fn test_open_response_deserialization() {
    let json = r#"{
        "requestId": "req-001",
        "success": false,
        "errorMessage": "Unsupported file type"
    }"#;

    let response: OpenResponse = serde_json::from_str(json).unwrap();
    assert!(!response.success);
    assert_eq!(response.request_id, "req-001");
    assert_eq!(
        response.error_message.as_deref(),
        Some("Unsupported file type")
    );
}

// =============================================================================
// FFI Function Tests
// =============================================================================

#[test]
fn test_ffi_create_open_url_packet() {
    let packet = create_open_url_packet(
        "req-001".to_string(),
        "https://example.com".to_string(),
        Some("Example".to_string()),
    )
    .unwrap();

    assert_eq!(packet.packet_type, "cconnect.open.request");

    let body: serde_json::Value = serde_json::from_str(&packet.body).unwrap();
    assert_eq!(body["requestId"], "req-001");
    assert_eq!(body["contentType"], "url");
    assert_eq!(body["url"], "https://example.com");
    assert_eq!(body["title"], "Example");
}

#[test]
fn test_ffi_create_open_url_packet_no_title() {
    let packet =
        create_open_url_packet("req-002".to_string(), "https://test.com".to_string(), None)
            .unwrap();

    let body: serde_json::Value = serde_json::from_str(&packet.body).unwrap();
    assert!(body.get("title").is_none());
}

#[test]
fn test_ffi_create_open_file_packet() {
    let packet = create_open_file_packet(
        "req-003".to_string(),
        "document.pdf".to_string(),
        "application/pdf".to_string(),
        1048576,
    )
    .unwrap();

    assert_eq!(packet.packet_type, "cconnect.open.request");

    let body: serde_json::Value = serde_json::from_str(&packet.body).unwrap();
    assert_eq!(body["requestId"], "req-003");
    assert_eq!(body["contentType"], "file");
    assert_eq!(body["filename"], "document.pdf");
    assert_eq!(body["mimeType"], "application/pdf");
    assert_eq!(body["fileSize"], 1048576);
}

#[test]
fn test_ffi_create_open_text_packet() {
    let packet =
        create_open_text_packet("req-004".to_string(), "Hello World".to_string()).unwrap();

    assert_eq!(packet.packet_type, "cconnect.open.request");

    let body: serde_json::Value = serde_json::from_str(&packet.body).unwrap();
    assert_eq!(body["requestId"], "req-004");
    assert_eq!(body["contentType"], "text");
    assert_eq!(body["url"], "Hello World");
    assert_eq!(body["mimeType"], "text/plain");
}

#[test]
fn test_ffi_create_open_response_success() {
    let packet = create_open_response_packet(
        "req-001".to_string(),
        true,
        None,
        Some("Firefox".to_string()),
    )
    .unwrap();

    assert_eq!(packet.packet_type, "cconnect.open.response");

    let body: serde_json::Value = serde_json::from_str(&packet.body).unwrap();
    assert_eq!(body["requestId"], "req-001");
    assert_eq!(body["success"], true);
    assert_eq!(body["openedWith"], "Firefox");
    assert!(body.get("errorMessage").is_none());
}

#[test]
fn test_ffi_create_open_response_failure() {
    let packet = create_open_response_packet(
        "req-002".to_string(),
        false,
        Some("File not found".to_string()),
        None,
    )
    .unwrap();

    let body: serde_json::Value = serde_json::from_str(&packet.body).unwrap();
    assert_eq!(body["success"], false);
    assert_eq!(body["errorMessage"], "File not found");
    assert!(body.get("openedWith").is_none());
}

#[test]
fn test_ffi_create_open_capability_packet() {
    let packet = create_open_capability_packet(
        vec![
            "http".to_string(),
            "https".to_string(),
            "mailto".to_string(),
        ],
        104857600,
        vec!["text/*".to_string(), "image/*".to_string()],
    )
    .unwrap();

    assert_eq!(packet.packet_type, "cconnect.open.capability");

    let body: serde_json::Value = serde_json::from_str(&packet.body).unwrap();
    assert_eq!(body["supportedSchemes"][0], "http");
    assert_eq!(body["supportedSchemes"][1], "https");
    assert_eq!(body["supportedSchemes"][2], "mailto");
    assert_eq!(body["maxFileSize"], 104857600);
    assert_eq!(body["supportedMimeTypes"][0], "text/*");
    assert_eq!(body["supportedMimeTypes"][1], "image/*");
}

// =============================================================================
// Packet Deserialization Tests
// =============================================================================

#[test]
fn test_deserialize_open_request_packet() {
    let packet = create_open_url_packet(
        "req-001".to_string(),
        "https://example.com".to_string(),
        Some("Example".to_string()),
    )
    .unwrap();

    // Parse JSON body
    let body: serde_json::Value = serde_json::from_str(&packet.body).unwrap();
    assert_eq!(body["requestId"], "req-001");
    assert_eq!(body["contentType"], "url");
    assert_eq!(body["url"], "https://example.com");
}

#[test]
fn test_deserialize_open_response_packet() {
    let packet = create_open_response_packet(
        "req-001".to_string(),
        true,
        None,
        Some("Firefox".to_string()),
    )
    .unwrap();

    // Parse JSON body
    let body: serde_json::Value = serde_json::from_str(&packet.body).unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["openedWith"], "Firefox");
}

// =============================================================================
// Protocol Compatibility Tests
// =============================================================================

#[test]
fn test_protocol_field_naming() {
    // Verify camelCase naming matches KDE Connect protocol
    let request = OpenRequest::new_url(
        "req-001".to_string(),
        "https://example.com".to_string(),
        None,
    );

    let json = serde_json::to_value(&request).unwrap();

    // Check field names use camelCase
    assert!(json.get("requestId").is_some());
    assert!(json.get("contentType").is_some());
    assert!(json.get("mimeType").is_some());

    // Should not have snake_case
    assert!(json.get("request_id").is_none());
    assert!(json.get("content_type").is_none());
}

#[test]
fn test_optional_fields_omitted() {
    // Verify optional fields are omitted when None
    let request = OpenRequest::new_url("req-001".to_string(), "https://test.com".to_string(), None);

    let json = serde_json::to_value(&request).unwrap();

    // title is None, should be omitted
    assert!(json.get("title").is_none());

    // filename and fileSize not applicable for URL, should be omitted
    assert!(json.get("filename").is_none());
    assert!(json.get("fileSize").is_none());
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_empty_request_id() {
    // Edge case: empty request ID (should still serialize)
    let request = OpenRequest::new_url("".to_string(), "https://test.com".to_string(), None);

    assert_eq!(request.request_id, "");

    let json = serde_json::to_value(&request).unwrap();
    assert_eq!(json["requestId"], "");
}

#[test]
fn test_large_file_size() {
    // Edge case: very large file size
    let large_size = u64::MAX;
    let request = OpenRequest::new_file(
        "req-001".to_string(),
        "huge.bin".to_string(),
        "application/octet-stream".to_string(),
        large_size,
    );

    assert_eq!(request.file_size, Some(u64::MAX));

    let json = serde_json::to_value(&request).unwrap();
    assert_eq!(json["fileSize"], large_size);
}

#[test]
fn test_special_characters_in_url() {
    // Edge case: URL with special characters
    let url = "https://example.com/path?query=value&foo=bar#fragment";
    let request = OpenRequest::new_url("req-001".to_string(), url.to_string(), None);

    assert_eq!(request.url.as_deref(), Some(url));

    let json = serde_json::to_value(&request).unwrap();
    assert_eq!(json["url"], url);
}

#[test]
fn test_unicode_in_text() {
    // Edge case: Unicode content in text
    let text = "Hello 世界 🌍";
    let request = OpenRequest::new_text("req-001".to_string(), text.to_string());

    assert_eq!(request.url.as_deref(), Some(text));

    let json_str = serde_json::to_string(&request).unwrap();
    let deserialized: OpenRequest = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.url.as_deref(), Some(text));
}
