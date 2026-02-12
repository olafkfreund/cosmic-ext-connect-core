//! Notification Sync Plugin
//!
//! Mirrors notifications between devices, enabling users to see and interact with
//! notifications from their phone on their desktop and vice versa.
//!
//! ## Protocol
//!
//! **Packet Types**:
//! - `cconnect.notification` - Send or cancel notification
//! - `cconnect.notification.request` - Request all notifications or dismiss one
//! - `cconnect.notification.action` - Trigger notification action button
//! - `cconnect.notification.reply` - Reply to notification (chat apps)
//!
//! **Capabilities**:
//! - Incoming: All four packet types
//! - Outgoing: All four packet types
//!
//! ## Packet Formats
//!
//! ### Notification (`cconnect.notification`)
//!
//! ```json
//! {
//!     "id": 1234567890,
//!     "type": "cconnect.notification",
//!     "body": {
//!         "id": "notification-id-123",
//!         "appName": "Messages",
//!         "title": "New Message",
//!         "text": "Hello from your phone!",
//!         "ticker": "Messages: New Message - Hello from your phone!",
//!         "isClearable": true,
//!         "time": "1704067200000",
//!         "silent": "false"
//!     }
//! }
//! ```
//!
//! ### Cancel Notification
//!
//! ```json
//! {
//!     "id": 1234567890,
//!     "type": "cconnect.notification",
//!     "body": {
//!         "id": "notification-id-123",
//!         "isCancel": true
//!     }
//! }
//! ```
//!
//! ### Request All Notifications
//!
//! ```json
//! {
//!     "id": 1234567890,
//!     "type": "cconnect.notification.request",
//!     "body": {
//!         "request": true
//!     }
//! }
//! ```
//!
//! ### Dismiss Notification
//!
//! ```json
//! {
//!     "id": 1234567890,
//!     "type": "cconnect.notification.request",
//!     "body": {
//!         "cancel": "notification-id-123"
//!     }
//! }
//! ```
//!
//! ## Features
//!
//! - **Notification Mirroring**: Display remote notifications locally
//! - **Dismissal Sync**: Dismiss notification on one device, gone on all
//! - **Action Buttons**: Trigger notification actions (future)
//! - **Inline Replies**: Reply to messages directly (future)
//! - **Icon Transfer**: Download notification icons (future)
//!
//! ## Use Cases
//!
//! - See phone notifications on desktop
//! - Dismiss notifications from any device
//! - Reply to messages without touching phone
//! - Monitor app notifications
//!
//! ## Example
//!
//! ```rust,ignore
//! use cosmic_ext_connect_core::plugins::notification::{
//!     NotificationPlugin, Notification
//! };
//!
//! // Create plugin
//! let mut plugin = NotificationPlugin::new();
//!
//! // Get active notifications
//! let notifications = plugin.get_all_notifications();
//! for notif in notifications {
//!     println!("{}: {}", notif.title, notif.text);
//! }
//!
//! // Dismiss a notification
//! let packet = plugin.create_dismiss_packet("notif-123");
//! ```
//!
//! ## References
//!
//! - [Valent Protocol - Notification](https://valent.andyholmes.ca/documentation/protocol.html)

use crate::error::Result;
use crate::protocol::Packet;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

use crate::plugins::Plugin;

/// Type of link embedded in notification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LinkType {
    /// Web URL (http/https)
    Web,
    /// Email address (mailto:)
    Email,
    /// Phone number (tel:)
    Phone,
    /// Map coordinates (geo:)
    Map,
    /// App deep link
    DeepLink,
}

/// Link embedded in rich notification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NotificationLink {
    /// URL of the link
    pub url: String,

    /// Display label for the link
    pub label: String,

    /// Type of link
    #[serde(rename = "linkType")]
    pub link_type: LinkType,
}

impl NotificationLink {
    /// Create a new notification link
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_ext_connect_core::plugins::notification::{NotificationLink, LinkType};
    ///
    /// let link = NotificationLink::new(
    ///     "https://example.com",
    ///     "View Details",
    ///     LinkType::Web
    /// );
    ///
    /// assert_eq!(link.url, "https://example.com");
    /// assert_eq!(link.label, "View Details");
    /// ```
    pub fn new(url: impl Into<String>, label: impl Into<String>, link_type: LinkType) -> Self {
        Self {
            url: url.into(),
            label: label.into(),
            link_type,
        }
    }

    /// Check if link is a web URL
    pub fn is_web_link(&self) -> bool {
        matches!(self.link_type, LinkType::Web)
    }

    /// Check if link is an email
    pub fn is_email(&self) -> bool {
        matches!(self.link_type, LinkType::Email)
    }

    /// Check if link is a phone number
    pub fn is_phone(&self) -> bool {
        matches!(self.link_type, LinkType::Phone)
    }
}

/// Notification data
///
/// Represents a notification from a remote device.
///
/// ## Example
///
/// ```rust
/// use cosmic_ext_connect_core::plugins::notification::Notification;
///
/// let notif = Notification {
///     id: "notif-123".to_string(),
///     app_name: "Messages".to_string(),
///     title: "New Message".to_string(),
///     text: "Hello!".to_string(),
///     ticker: Some("Messages: New Message - Hello!".to_string()),
///     is_clearable: true,
///     time: Some("1704067200000".to_string()),
///     silent: Some("false".to_string()),
///     only_once: None,
///     request_reply_id: None,
///     actions: None,
///     payload_hash: None,
/// };
///
/// assert_eq!(notif.id, "notif-123");
/// assert_eq!(notif.app_name, "Messages");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Notification {
    /// Unique notification ID
    pub id: String,

    /// Source application name
    #[serde(rename = "appName")]
    pub app_name: String,

    /// Notification title
    pub title: String,

    /// Notification body text
    pub text: String,

    /// Combined title and text in a single string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticker: Option<String>,

    /// Whether user can dismiss this notification
    #[serde(rename = "isClearable")]
    pub is_clearable: bool,

    /// UNIX epoch timestamp in milliseconds (as string)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,

    /// "true" for preexisting, "false" for newly received
    #[serde(skip_serializing_if = "Option::is_none")]
    pub silent: Option<String>,

    /// Whether to only show once
    #[serde(rename = "onlyOnce", skip_serializing_if = "Option::is_none")]
    pub only_once: Option<bool>,

    /// UUID for inline reply support
    #[serde(rename = "requestReplyId", skip_serializing_if = "Option::is_none")]
    pub request_reply_id: Option<String>,

    /// Available action button names
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,

    /// MD5 hash of notification icon
    #[serde(rename = "payloadHash", skip_serializing_if = "Option::is_none")]
    pub payload_hash: Option<String>,

    // Rich notification content (Issue #125)
    /// HTML-formatted rich text content
    #[serde(rename = "richText", skip_serializing_if = "Option::is_none")]
    pub rich_text: Option<String>,

    /// Whether notification has rich text
    #[serde(rename = "hasRichText", skip_serializing_if = "Option::is_none")]
    pub has_rich_text: Option<bool>,

    /// Whether notification has image
    #[serde(rename = "hasImage", skip_serializing_if = "Option::is_none")]
    pub has_image: Option<bool>,

    /// Image URL or base64 data
    #[serde(rename = "imageUrl", skip_serializing_if = "Option::is_none")]
    pub image_url: Option<String>,

    /// MIME type of image (e.g., "image/png", "image/jpeg")
    #[serde(rename = "imageMimeType", skip_serializing_if = "Option::is_none")]
    pub image_mime_type: Option<String>,

    /// Image width in pixels
    #[serde(rename = "imageWidth", skip_serializing_if = "Option::is_none")]
    pub image_width: Option<u32>,

    /// Image height in pixels
    #[serde(rename = "imageHeight", skip_serializing_if = "Option::is_none")]
    pub image_height: Option<u32>,

    /// Whether notification has video
    #[serde(rename = "hasVideo", skip_serializing_if = "Option::is_none")]
    pub has_video: Option<bool>,

    /// Video URL
    #[serde(rename = "videoUrl", skip_serializing_if = "Option::is_none")]
    pub video_url: Option<String>,

    /// Video thumbnail URL
    #[serde(rename = "videoThumbnailUrl", skip_serializing_if = "Option::is_none")]
    pub video_thumbnail_url: Option<String>,

    /// Video duration in milliseconds
    #[serde(rename = "videoDuration", skip_serializing_if = "Option::is_none")]
    pub video_duration: Option<i64>,

    /// MIME type of video (e.g., "video/mp4")
    #[serde(rename = "videoMimeType", skip_serializing_if = "Option::is_none")]
    pub video_mime_type: Option<String>,

    /// Embedded links in notification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<NotificationLink>>,
}

impl Notification {
    /// Create a new notification
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_ext_connect_core::plugins::notification::Notification;
    ///
    /// let notif = Notification::new(
    ///     "notif-123",
    ///     "Messages",
    ///     "New Message",
    ///     "Hello from your phone!",
    ///     true
    /// );
    ///
    /// assert_eq!(notif.id, "notif-123");
    /// assert!(notif.is_clearable);
    /// ```
    pub fn new(
        id: impl Into<String>,
        app_name: impl Into<String>,
        title: impl Into<String>,
        text: impl Into<String>,
        is_clearable: bool,
    ) -> Self {
        Self {
            id: id.into(),
            app_name: app_name.into(),
            title: title.into(),
            text: text.into(),
            ticker: None,
            is_clearable,
            time: None,
            silent: None,
            only_once: None,
            request_reply_id: None,
            actions: None,
            payload_hash: None,
            // Rich content fields
            rich_text: None,
            has_rich_text: None,
            has_image: None,
            image_url: None,
            image_mime_type: None,
            image_width: None,
            image_height: None,
            has_video: None,
            video_url: None,
            video_thumbnail_url: None,
            video_duration: None,
            video_mime_type: None,
            links: None,
        }
    }

    /// Check if notification is silent (preexisting)
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_ext_connect_core::plugins::notification::Notification;
    ///
    /// let mut notif = Notification::new("1", "App", "Title", "Text", true);
    /// notif.silent = Some("true".to_string());
    /// assert!(notif.is_silent());
    /// ```
    pub fn is_silent(&self) -> bool {
        self.silent.as_deref() == Some("true")
    }

    /// Check if notification supports inline replies
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_ext_connect_core::plugins::notification::Notification;
    ///
    /// let mut notif = Notification::new("1", "App", "Title", "Text", true);
    /// notif.request_reply_id = Some("reply-uuid".to_string());
    /// assert!(notif.is_repliable());
    /// ```
    pub fn is_repliable(&self) -> bool {
        self.request_reply_id.is_some()
    }

    /// Check if notification has action buttons
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_ext_connect_core::plugins::notification::Notification;
    ///
    /// let mut notif = Notification::new("1", "App", "Title", "Text", true);
    /// notif.actions = Some(vec!["Reply".to_string(), "Mark Read".to_string()]);
    /// assert!(notif.has_actions());
    /// ```
    pub fn has_actions(&self) -> bool {
        self.actions
            .as_ref()
            .map(|a| !a.is_empty())
            .unwrap_or(false)
    }

    // Rich notification helper methods (Issue #125)

    /// Check if notification has rich text content
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_ext_connect_core::plugins::notification::Notification;
    ///
    /// let mut notif = Notification::new("1", "App", "Title", "Text", true);
    /// notif.rich_text = Some("<b>Bold</b> text".to_string());
    /// notif.has_rich_text = Some(true);
    /// assert!(notif.has_rich_text());
    /// ```
    pub fn has_rich_text(&self) -> bool {
        self.has_rich_text.unwrap_or(false) && self.rich_text.is_some()
    }

    /// Check if notification has image
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_ext_connect_core::plugins::notification::Notification;
    ///
    /// let mut notif = Notification::new("1", "App", "Title", "Text", true);
    /// notif.has_image = Some(true);
    /// notif.image_url = Some("https://example.com/image.png".to_string());
    /// assert!(notif.has_image());
    /// ```
    pub fn has_image(&self) -> bool {
        self.has_image.unwrap_or(false) && self.image_url.is_some()
    }

    /// Check if notification has video
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_ext_connect_core::plugins::notification::Notification;
    ///
    /// let mut notif = Notification::new("1", "App", "Title", "Text", true);
    /// notif.has_video = Some(true);
    /// notif.video_url = Some("https://example.com/video.mp4".to_string());
    /// assert!(notif.has_video());
    /// ```
    pub fn has_video(&self) -> bool {
        self.has_video.unwrap_or(false) && self.video_url.is_some()
    }

    /// Check if notification has embedded links
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_ext_connect_core::plugins::notification::{Notification, NotificationLink, LinkType};
    ///
    /// let mut notif = Notification::new("1", "App", "Title", "Text", true);
    /// notif.links = Some(vec![
    ///     NotificationLink::new("https://example.com", "View", LinkType::Web)
    /// ]);
    /// assert!(notif.has_links());
    /// ```
    pub fn has_links(&self) -> bool {
        self.links
            .as_ref()
            .map(|l| !l.is_empty())
            .unwrap_or(false)
    }

    /// Get image dimensions if available
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_ext_connect_core::plugins::notification::Notification;
    ///
    /// let mut notif = Notification::new("1", "App", "Title", "Text", true);
    /// notif.image_width = Some(1920);
    /// notif.image_height = Some(1080);
    /// assert_eq!(notif.image_dimensions(), Some((1920, 1080)));
    /// ```
    pub fn image_dimensions(&self) -> Option<(u32, u32)> {
        match (self.image_width, self.image_height) {
            (Some(w), Some(h)) => Some((w, h)),
            _ => None,
        }
    }

    /// Check if this is a rich notification (has any rich content)
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_ext_connect_core::plugins::notification::Notification;
    ///
    /// let mut notif = Notification::new("1", "App", "Title", "Text", true);
    /// assert!(!notif.is_rich());
    ///
    /// notif.rich_text = Some("<b>Rich</b>".to_string());
    /// notif.has_rich_text = Some(true);
    /// assert!(notif.is_rich());
    /// ```
    pub fn is_rich(&self) -> bool {
        self.has_rich_text() || self.has_image() || self.has_video() || self.has_links()
    }
}

/// Notification sync plugin
///
/// Handles notification mirroring between devices.
///
/// ## Features
///
/// - Receive notifications from remote devices
/// - Store active notifications
/// - Dismiss notifications
/// - Request all notifications (future)
/// - Trigger actions (future)
/// - Send replies (future)
///
/// ## Example
///
/// ```rust
/// use cosmic_ext_connect_core::plugins::notification::NotificationPlugin;
/// use cosmic_ext_connect_core::plugins::Plugin;
///
/// let plugin = NotificationPlugin::new();
/// assert_eq!(plugin.name(), "notification");
///
/// // Initially no notifications
/// assert_eq!(plugin.notification_count(), 0);
/// ```
#[derive(Debug)]
pub struct NotificationPlugin {
    /// Device ID this plugin is attached to
    device_id: Option<String>,

    /// Active notifications by ID
    notifications: Arc<RwLock<HashMap<String, Notification>>>,
}

impl NotificationPlugin {
    /// Create a new notification plugin
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_ext_connect_core::plugins::notification::NotificationPlugin;
    ///
    /// let plugin = NotificationPlugin::new();
    /// assert_eq!(plugin.notification_count(), 0);
    /// ```
    pub fn new() -> Self {
        Self {
            device_id: None,
            notifications: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get notification count
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_ext_connect_core::plugins::notification::NotificationPlugin;
    ///
    /// let plugin = NotificationPlugin::new();
    /// assert_eq!(plugin.notification_count(), 0);
    /// ```
    pub fn notification_count(&self) -> usize {
        self.notifications.read().ok().map(|n| n.len()).unwrap_or(0)
    }

    /// Get a notification by ID
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_ext_connect_core::plugins::notification::NotificationPlugin;
    ///
    /// let plugin = NotificationPlugin::new();
    /// assert!(plugin.get_notification("notif-123").is_none());
    /// ```
    pub fn get_notification(&self, id: &str) -> Option<Notification> {
        self.notifications.read().ok()?.get(id).cloned()
    }

    /// Get all notifications
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_ext_connect_core::plugins::notification::NotificationPlugin;
    ///
    /// let plugin = NotificationPlugin::new();
    /// let notifications = plugin.get_all_notifications();
    /// assert_eq!(notifications.len(), 0);
    /// ```
    pub fn get_all_notifications(&self) -> Vec<Notification> {
        self.notifications
            .read()
            .ok()
            .map(|n| n.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Create a notification packet
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_ext_connect_core::plugins::notification::{NotificationPlugin, Notification};
    ///
    /// let plugin = NotificationPlugin::new();
    /// let notif = Notification::new("123", "App", "Title", "Text", true);
    /// let packet = plugin.create_notification_packet(&notif);
    ///
    /// assert_eq!(packet.packet_type, "cconnect.notification");
    /// ```
    pub fn create_notification_packet(&self, notification: &Notification) -> Packet {
        let body = serde_json::to_value(notification).unwrap_or(json!({}));
        Packet::new("cconnect.notification", body)
    }

    /// Create a cancel notification packet
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_ext_connect_core::plugins::notification::NotificationPlugin;
    ///
    /// let plugin = NotificationPlugin::new();
    /// let packet = plugin.create_cancel_packet("notif-123");
    ///
    /// assert_eq!(packet.packet_type, "cconnect.notification");
    /// ```
    pub fn create_cancel_packet(&self, notification_id: &str) -> Packet {
        let body = json!({
            "id": notification_id,
            "isCancel": true
        });
        Packet::new("cconnect.notification", body)
    }

    /// Create a request all notifications packet
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_ext_connect_core::plugins::notification::NotificationPlugin;
    ///
    /// let plugin = NotificationPlugin::new();
    /// let packet = plugin.create_request_packet();
    ///
    /// assert_eq!(packet.packet_type, "cconnect.notification.request");
    /// ```
    pub fn create_request_packet(&self) -> Packet {
        let body = json!({ "request": true });
        Packet::new("cconnect.notification.request", body)
    }

    /// Create a dismiss notification packet
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_ext_connect_core::plugins::notification::NotificationPlugin;
    ///
    /// let plugin = NotificationPlugin::new();
    /// let packet = plugin.create_dismiss_packet("notif-123");
    ///
    /// assert_eq!(packet.packet_type, "cconnect.notification.request");
    /// ```
    pub fn create_dismiss_packet(&self, notification_id: &str) -> Packet {
        let body = json!({ "cancel": notification_id });
        Packet::new("cconnect.notification.request", body)
    }

    /// Handle incoming notification
    fn handle_notification(&self, packet: &Packet) {
        let device_id = self.device_id.as_deref().unwrap_or("unknown");

        // Check for cancel
        if let Some(is_cancel) = packet.body.get("isCancel").and_then(|v| v.as_bool()) {
            if is_cancel {
                if let Some(id) = packet.body.get("id").and_then(|v| v.as_str()) {
                    if let Ok(mut notifications) = self.notifications.write() {
                        notifications.remove(id);
                        info!(
                            "Notification {} cancelled from device ({})",
                            id,
                            device_id
                        );
                    }
                }
                return;
            }
        }

        // Parse notification
        match serde_json::from_value::<Notification>(packet.body.clone()) {
            Ok(notification) => {
                let id = notification.id.clone();
                let silent = notification.is_silent();

                // Store notification
                if let Ok(mut notifications) = self.notifications.write() {
                    notifications.insert(id.clone(), notification.clone());
                }

                // Log notification
                if silent {
                    debug!(
                        "Preexisting notification from device ({}): {} - {}",
                        device_id,
                        notification.app_name,
                        notification.title
                    );
                } else {
                    info!(
                        "New notification from device ({}): {} - {} - {}",
                        device_id,
                        notification.app_name,
                        notification.title,
                        notification.text
                    );

                    if notification.is_repliable() {
                        debug!("Notification {} is repliable", id);
                    }
                    if notification.has_actions() {
                        debug!(
                            "Notification {} has actions: {:?}",
                            id,
                            notification.actions.as_ref().unwrap()
                        );
                    }
                }
            }
            Err(e) => {
                warn!("Failed to parse notification from device ({}): {}", device_id, e);
            }
        }
    }

    /// Handle notification request
    fn handle_request(&self, packet: &Packet) {
        let device_id = self.device_id.as_deref().unwrap_or("unknown");

        // Check for request all
        if let Some(true) = packet.body.get("request").and_then(|v| v.as_bool()) {
            info!(
                "Received request for all notifications from device ({})",
                device_id
            );
            // Future: Send all our local notifications to device
            // Requires: Integration with COSMIC notification system to enumerate active notifications
            return;
        }

        // Check for cancel/dismiss
        if let Some(cancel_id) = packet.body.get("cancel").and_then(|v| v.as_str()) {
            info!(
                "Received dismiss request for {} from device ({})",
                cancel_id,
                device_id
            );
            // Future: Dismiss our local notification
            // Requires: Track notification IDs and call CosmicNotifier.close(id)
        }
    }

    /// Handle notification action
    fn handle_action(&self, packet: &Packet) {
        let device_id = self.device_id.as_deref().unwrap_or("unknown");
        let key = packet.body.get("key").and_then(|v| v.as_str());
        let action = packet.body.get("action").and_then(|v| v.as_str());

        if let (Some(key), Some(action)) = (key, action) {
            info!(
                "Received action '{}' for notification {} from device ({})",
                action,
                key,
                device_id
            );
            // Future: Trigger the notification action button
            // Requires: Store action callbacks and execute on action packet
        }
    }

    /// Handle notification reply
    fn handle_reply(&self, packet: &Packet) {
        let device_id = self.device_id.as_deref().unwrap_or("unknown");
        let reply_id = packet.body.get("requestReplyId").and_then(|v| v.as_str());
        let message = packet.body.get("message").and_then(|v| v.as_str());

        if let (Some(reply_id), Some(message)) = (reply_id, message) {
            info!(
                "Received reply '{}' for {} from device ({})",
                message,
                reply_id,
                device_id
            );
            // Future: Send inline reply to originating app
            // Requires: Platform-specific integration with messaging apps
        }
    }
}

impl Default for NotificationPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for NotificationPlugin {
    fn name(&self) -> &str {
        "notification"
    }


    fn incoming_capabilities(&self) -> Vec<String> {
        vec![
            "cconnect.notification".to_string(),
            "cconnect.notification.request".to_string(),
            "cconnect.notification.action".to_string(),
            "cconnect.notification.reply".to_string(),
        ]
    }

    fn outgoing_capabilities(&self) -> Vec<String> {
        vec![
            "cconnect.notification".to_string(),
            "cconnect.notification.request".to_string(),
            "cconnect.notification.action".to_string(),
            "cconnect.notification.reply".to_string(),
        ]
    }


    async fn initialize(&mut self) -> Result<()> {
        info!("Notification plugin started");
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        let count = self.notification_count();
        info!(
            "Notification plugin stopped ({} active notifications)",
            count
        );
        Ok(())
    }

    async fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
        match packet.packet_type.as_str() {
            "cconnect.notification" => {
                self.handle_notification(packet);
            }
            "cconnect.notification.request" => {
                self.handle_request(packet);
            }
            "cconnect.notification.action" => {
                self.handle_action(packet);
            }
            "cconnect.notification.reply" => {
                self.handle_reply(packet);
            }
            _ => {
                // Ignore other packet types
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notification_new() {
        let notif = Notification::new("123", "Messages", "Title", "Text", true);
        assert_eq!(notif.id, "123");
        assert_eq!(notif.app_name, "Messages");
        assert_eq!(notif.title, "Title");
        assert_eq!(notif.text, "Text");
        assert!(notif.is_clearable);
    }

    #[test]
    fn test_notification_is_silent() {
        let mut notif = Notification::new("1", "App", "Title", "Text", true);
        assert!(!notif.is_silent());

        notif.silent = Some("true".to_string());
        assert!(notif.is_silent());

        notif.silent = Some("false".to_string());
        assert!(!notif.is_silent());
    }

    #[test]
    fn test_notification_is_repliable() {
        let mut notif = Notification::new("1", "App", "Title", "Text", true);
        assert!(!notif.is_repliable());

        notif.request_reply_id = Some("reply-uuid".to_string());
        assert!(notif.is_repliable());
    }

    #[test]
    fn test_notification_has_actions() {
        let mut notif = Notification::new("1", "App", "Title", "Text", true);
        assert!(!notif.has_actions());

        notif.actions = Some(vec![]);
        assert!(!notif.has_actions());

        notif.actions = Some(vec!["Reply".to_string()]);
        assert!(notif.has_actions());
    }

    #[test]
    fn test_plugin_creation() {
        let plugin = NotificationPlugin::new();
        assert_eq!(plugin.name(), "notification");
        assert_eq!(plugin.notification_count(), 0);
    }

    #[test]
    fn test_capabilities() {
        let plugin = NotificationPlugin::new();

        let incoming = plugin.incoming_capabilities();
        assert_eq!(incoming.len(), 4);
        assert!(incoming.contains(&"cconnect.notification".to_string()));
        assert!(incoming.contains(&"cconnect.notification.request".to_string()));
        assert!(incoming.contains(&"cconnect.notification.action".to_string()));
        assert!(incoming.contains(&"cconnect.notification.reply".to_string()));

        let outgoing = plugin.outgoing_capabilities();
        assert_eq!(outgoing.len(), 4);
    }

    #[tokio::test]
    async fn test_plugin_lifecycle() {
        let mut plugin = NotificationPlugin::new();

        // Set device ID manually for testing
        plugin.device_id = Some("test-device-id".to_string());
        assert!(plugin.device_id.is_some());

        plugin.initialize().await.unwrap();
        plugin.shutdown().await.unwrap();
    }

    #[test]
    fn test_create_notification_packet() {
        let plugin = NotificationPlugin::new();
        let notif = Notification::new("123", "Messages", "Title", "Text", true);
        let packet = plugin.create_notification_packet(&notif);

        assert_eq!(packet.packet_type, "cconnect.notification");
        assert_eq!(packet.body.get("id").and_then(|v| v.as_str()), Some("123"));
    }

    #[test]
    fn test_create_cancel_packet() {
        let plugin = NotificationPlugin::new();
        let packet = plugin.create_cancel_packet("notif-123");

        assert_eq!(packet.packet_type, "cconnect.notification");
        assert_eq!(
            packet.body.get("id").and_then(|v| v.as_str()),
            Some("notif-123")
        );
        assert_eq!(
            packet.body.get("isCancel").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn test_create_request_packet() {
        let plugin = NotificationPlugin::new();
        let packet = plugin.create_request_packet();

        assert_eq!(packet.packet_type, "cconnect.notification.request");
        assert_eq!(
            packet.body.get("request").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn test_create_dismiss_packet() {
        let plugin = NotificationPlugin::new();
        let packet = plugin.create_dismiss_packet("notif-123");

        assert_eq!(packet.packet_type, "cconnect.notification.request");
        assert_eq!(
            packet.body.get("cancel").and_then(|v| v.as_str()),
            Some("notif-123")
        );
    }

    #[tokio::test]
    async fn test_handle_notification() {
        let mut plugin = NotificationPlugin::new();
        plugin.device_id = Some("test-device-id".to_string());

        let notif = Notification::new("123", "Messages", "New Message", "Hello!", true);
        let packet = plugin.create_notification_packet(&notif);

        plugin.handle_packet(&packet).await.unwrap();

        assert_eq!(plugin.notification_count(), 1);
        let stored = plugin.get_notification("123").unwrap();
        assert_eq!(stored.title, "New Message");
    }

    #[tokio::test]
    async fn test_handle_cancel_notification() {
        let mut plugin = NotificationPlugin::new();
        plugin.device_id = Some("test-device-id".to_string());

        // Add notification
        let notif = Notification::new("123", "Messages", "Title", "Text", true);
        let packet = plugin.create_notification_packet(&notif);
        plugin.handle_packet(&packet).await.unwrap();
        assert_eq!(plugin.notification_count(), 1);

        // Cancel it
        let cancel_packet = plugin.create_cancel_packet("123");
        plugin
            .handle_packet(&cancel_packet)
            .await
            .unwrap();
        assert_eq!(plugin.notification_count(), 0);
    }

    #[tokio::test]
    async fn test_get_all_notifications() {
        let mut plugin = NotificationPlugin::new();
        plugin.device_id = Some("test-device-id".to_string());

        // Add multiple notifications
        for i in 1..=3 {
            let notif = Notification::new(
                format!("notif-{}", i),
                "App",
                format!("Title {}", i),
                "Text",
                true,
            );
            let packet = plugin.create_notification_packet(&notif);
            plugin.handle_packet(&packet).await.unwrap();
        }

        let all = plugin.get_all_notifications();
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn test_ignore_non_notification_packets() {
        let mut plugin = NotificationPlugin::new();
        plugin.device_id = Some("test-device-id".to_string());

        let packet = Packet::new("cconnect.ping", json!({}));

        plugin.handle_packet(&packet).await.unwrap();

        assert_eq!(plugin.notification_count(), 0);
    }

    #[test]
    fn test_notification_serialization() {
        let notif = Notification::new("123", "App", "Title", "Text", true);
        let json = serde_json::to_value(&notif).unwrap();

        assert_eq!(json["id"], "123");
        assert_eq!(json["appName"], "App");
        assert_eq!(json["title"], "Title");
        assert_eq!(json["text"], "Text");
        assert_eq!(json["isClearable"], true);
    }

    // Rich notification tests (Issue #125)

    #[test]
    fn test_notification_link_creation() {
        let link = NotificationLink::new(
            "https://example.com",
            "View Details",
            LinkType::Web,
        );

        assert_eq!(link.url, "https://example.com");
        assert_eq!(link.label, "View Details");
        assert_eq!(link.link_type, LinkType::Web);
        assert!(link.is_web_link());
        assert!(!link.is_email());
    }

    #[test]
    fn test_notification_link_types() {
        let web = NotificationLink::new("https://example.com", "Web", LinkType::Web);
        assert!(web.is_web_link());

        let email = NotificationLink::new("mailto:test@example.com", "Email", LinkType::Email);
        assert!(email.is_email());

        let phone = NotificationLink::new("tel:+1234567890", "Call", LinkType::Phone);
        assert!(phone.is_phone());
    }

    #[test]
    fn test_notification_rich_text() {
        let mut notif = Notification::new("1", "App", "Title", "Text", true);
        assert!(!notif.has_rich_text());

        notif.rich_text = Some("<b>Bold</b> text".to_string());
        notif.has_rich_text = Some(true);
        assert!(notif.has_rich_text());
        assert!(notif.is_rich());
    }

    #[test]
    fn test_notification_image() {
        let mut notif = Notification::new("1", "App", "Title", "Text", true);
        assert!(!notif.has_image());

        notif.has_image = Some(true);
        notif.image_url = Some("https://example.com/image.png".to_string());
        notif.image_mime_type = Some("image/png".to_string());
        notif.image_width = Some(1920);
        notif.image_height = Some(1080);

        assert!(notif.has_image());
        assert!(notif.is_rich());
        assert_eq!(notif.image_dimensions(), Some((1920, 1080)));
    }

    #[test]
    fn test_notification_video() {
        let mut notif = Notification::new("1", "App", "Title", "Text", true);
        assert!(!notif.has_video());

        notif.has_video = Some(true);
        notif.video_url = Some("https://example.com/video.mp4".to_string());
        notif.video_thumbnail_url = Some("https://example.com/thumb.jpg".to_string());
        notif.video_duration = Some(60000); // 60 seconds
        notif.video_mime_type = Some("video/mp4".to_string());

        assert!(notif.has_video());
        assert!(notif.is_rich());
        assert_eq!(notif.video_duration, Some(60000));
    }

    #[test]
    fn test_notification_links() {
        let mut notif = Notification::new("1", "App", "Title", "Text", true);
        assert!(!notif.has_links());

        notif.links = Some(vec![
            NotificationLink::new("https://example.com", "View Details", LinkType::Web),
            NotificationLink::new("mailto:contact@example.com", "Email Us", LinkType::Email),
        ]);

        assert!(notif.has_links());
        assert!(notif.is_rich());
        assert_eq!(notif.links.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_notification_is_rich() {
        let mut notif = Notification::new("1", "App", "Title", "Text", true);
        assert!(!notif.is_rich());

        // Rich text makes it rich
        notif.rich_text = Some("<b>Bold</b>".to_string());
        notif.has_rich_text = Some(true);
        assert!(notif.is_rich());

        // Reset
        notif = Notification::new("2", "App", "Title", "Text", true);

        // Image makes it rich
        notif.has_image = Some(true);
        notif.image_url = Some("https://example.com/image.png".to_string());
        assert!(notif.is_rich());

        // Reset
        notif = Notification::new("3", "App", "Title", "Text", true);

        // Video makes it rich
        notif.has_video = Some(true);
        notif.video_url = Some("https://example.com/video.mp4".to_string());
        assert!(notif.is_rich());

        // Reset
        notif = Notification::new("4", "App", "Title", "Text", true);

        // Links make it rich
        notif.links = Some(vec![
            NotificationLink::new("https://example.com", "Link", LinkType::Web)
        ]);
        assert!(notif.is_rich());
    }

    #[test]
    fn test_rich_notification_serialization() {
        let mut notif = Notification::new("123", "Messages", "New Message", "Check this out!", true);

        // Add rich content
        notif.rich_text = Some("<b>Check</b> <i>this</i> out!".to_string());
        notif.has_rich_text = Some(true);
        notif.has_image = Some(true);
        notif.image_url = Some("https://example.com/image.png".to_string());
        notif.image_mime_type = Some("image/png".to_string());
        notif.image_width = Some(800);
        notif.image_height = Some(600);
        notif.links = Some(vec![
            NotificationLink::new("https://example.com/details", "View Details", LinkType::Web),
        ]);

        let json = serde_json::to_value(&notif).unwrap();

        // Check basic fields
        assert_eq!(json["id"], "123");
        assert_eq!(json["appName"], "Messages");

        // Check rich fields
        assert_eq!(json["richText"], "<b>Check</b> <i>this</i> out!");
        assert_eq!(json["hasRichText"], true);
        assert_eq!(json["hasImage"], true);
        assert_eq!(json["imageUrl"], "https://example.com/image.png");
        assert_eq!(json["imageMimeType"], "image/png");
        assert_eq!(json["imageWidth"], 800);
        assert_eq!(json["imageHeight"], 600);

        // Check links
        assert!(json["links"].is_array());
        assert_eq!(json["links"][0]["url"], "https://example.com/details");
        assert_eq!(json["links"][0]["label"], "View Details");
        assert_eq!(json["links"][0]["linkType"], "web");
    }

    #[test]
    fn test_rich_notification_deserialization() {
        let json = serde_json::json!({
            "id": "123",
            "appName": "Messages",
            "title": "New Message",
            "text": "Check this out!",
            "isClearable": true,
            "richText": "<b>Rich</b> content",
            "hasRichText": true,
            "hasImage": true,
            "imageUrl": "https://example.com/image.png",
            "imageMimeType": "image/png",
            "imageWidth": 1920,
            "imageHeight": 1080,
            "hasVideo": true,
            "videoUrl": "https://example.com/video.mp4",
            "videoThumbnailUrl": "https://example.com/thumb.jpg",
            "videoDuration": 30000,
            "videoMimeType": "video/mp4",
            "links": [
                {
                    "url": "https://example.com",
                    "label": "View",
                    "linkType": "web"
                }
            ]
        });

        let notif: Notification = serde_json::from_value(json).unwrap();

        assert_eq!(notif.id, "123");
        assert_eq!(notif.app_name, "Messages");
        assert!(notif.has_rich_text());
        assert!(notif.has_image());
        assert!(notif.has_video());
        assert!(notif.has_links());
        assert!(notif.is_rich());
        assert_eq!(notif.image_dimensions(), Some((1920, 1080)));
        assert_eq!(notif.video_duration, Some(30000));
    }

    #[tokio::test]
    async fn test_handle_rich_notification() {
        let mut plugin = NotificationPlugin::new();
        plugin.device_id = Some("test-device".to_string());

        // Create rich notification
        let mut notif = Notification::new("rich-123", "Messages", "Rich Message", "Content", true);
        notif.rich_text = Some("<b>Bold</b> text".to_string());
        notif.has_rich_text = Some(true);
        notif.has_image = Some(true);
        notif.image_url = Some("https://example.com/image.png".to_string());

        let packet = plugin.create_notification_packet(&notif);
        plugin.handle_packet(&packet).await.unwrap();

        assert_eq!(plugin.notification_count(), 1);
        let stored = plugin.get_notification("rich-123").unwrap();
        assert!(stored.has_rich_text());
        assert!(stored.has_image());
        assert!(stored.is_rich());
    }

    #[test]
    fn test_link_type_serialization() {
        let link = NotificationLink::new("https://example.com", "Web", LinkType::Web);
        let json = serde_json::to_value(&link).unwrap();
        assert_eq!(json["linkType"], "web");

        let email = NotificationLink::new("mailto:test@example.com", "Email", LinkType::Email);
        let json = serde_json::to_value(&email).unwrap();
        assert_eq!(json["linkType"], "email");

        let phone = NotificationLink::new("tel:+1234567890", "Phone", LinkType::Phone);
        let json = serde_json::to_value(&phone).unwrap();
        assert_eq!(json["linkType"], "phone");

        let map = NotificationLink::new("geo:37.7749,-122.4194", "Map", LinkType::Map);
        let json = serde_json::to_value(&map).unwrap();
        assert_eq!(json["linkType"], "map");

        let deep = NotificationLink::new("app://action", "Open", LinkType::DeepLink);
        let json = serde_json::to_value(&deep).unwrap();
        assert_eq!(json["linkType"], "deeplink");
    }

    #[test]
    fn test_image_dimensions_helper() {
        let mut notif = Notification::new("1", "App", "Title", "Text", true);

        // No dimensions
        assert_eq!(notif.image_dimensions(), None);

        // Only width
        notif.image_width = Some(1920);
        assert_eq!(notif.image_dimensions(), None);

        // Both width and height
        notif.image_height = Some(1080);
        assert_eq!(notif.image_dimensions(), Some((1920, 1080)));
    }
}
