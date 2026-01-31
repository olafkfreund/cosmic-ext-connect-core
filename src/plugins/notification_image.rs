//! Notification Image Support
//!
//! Handles image data for rich notifications, including decoding, encoding,
//! and conversion to freedesktop notification hints format.
//!
//! ## Features
//!
//! - Decode PNG and JPEG images
//! - Scale images to reasonable sizes
//! - Convert to freedesktop notification hint format
//! - RGBA8888 pixel format
//!
//! ## Example
//!
//! ```rust
//! use cosmic_connect_core::plugins::notification_image::NotificationImage;
//!
//! // Create from RGBA data
//! let rgba_data = vec![255u8; 32 * 32 * 4]; // 32x32 red image
//! let image = NotificationImage::from_rgba(32, 32, rgba_data);
//! assert_eq!(image.width, 32);
//! assert_eq!(image.height, 32);
//!
//! // Convert to freedesktop hint
//! let hint = image.to_freedesktop_hint();
//! assert_eq!(hint.0, 32); // width
//! assert_eq!(hint.1, 32); // height
//! ```

use thiserror::Error;

/// Error types for image operations
#[derive(Debug, Error)]
pub enum ImageError {
    /// Invalid image dimensions
    #[error("Invalid dimensions: {0}")]
    InvalidDimensions(String),

    /// Image decoding failed
    #[error("Failed to decode image: {0}")]
    DecodingFailed(String),

    /// Invalid image format
    #[error("Invalid image format: {0}")]
    InvalidFormat(String),

    /// Image processing error
    #[error("Image processing error: {0}")]
    ProcessingError(String),
}

/// Notification image data
///
/// Represents an image for use in notifications, compatible with freedesktop
/// notification specification.
///
/// ## Format
///
/// - RGBA8888 pixel format
/// - Row-major ordering
/// - No compression
///
/// ## Example
///
/// ```rust
/// use cosmic_connect_core::plugins::notification_image::NotificationImage;
///
/// let rgba_data = vec![255u8; 16 * 16 * 4];
/// let image = NotificationImage::from_rgba(16, 16, rgba_data);
///
/// assert_eq!(image.width(), 16);
/// assert_eq!(image.height(), 16);
/// assert_eq!(image.channels(), 4);
/// assert!(image.has_alpha());
/// ```
#[derive(Debug, Clone)]
pub struct NotificationImage {
    /// Image width in pixels
    pub width: u32,

    /// Image height in pixels
    pub height: u32,

    /// Bytes per row (may include padding)
    pub rowstride: u32,

    /// Whether image has alpha channel
    pub has_alpha: bool,

    /// Bits per color sample (typically 8)
    pub bits_per_sample: u8,

    /// Number of color channels (3 for RGB, 4 for RGBA)
    pub channels: u8,

    /// Raw RGBA pixel data
    pub data: Vec<u8>,
}

impl NotificationImage {
    /// Create a notification image from RGBA data
    ///
    /// # Arguments
    ///
    /// * `width` - Image width in pixels
    /// * `height` - Image height in pixels
    /// * `data` - RGBA8888 pixel data (must be width * height * 4 bytes)
    ///
    /// # Panics
    ///
    /// Panics if data length doesn't match width * height * 4
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_connect_core::plugins::notification_image::NotificationImage;
    ///
    /// let data = vec![255u8; 10 * 10 * 4]; // 10x10 white image
    /// let image = NotificationImage::from_rgba(10, 10, data);
    /// assert_eq!(image.width, 10);
    /// assert_eq!(image.height, 10);
    /// ```
    pub fn from_rgba(width: u32, height: u32, data: Vec<u8>) -> Self {
        let expected_len = (width * height * 4) as usize;
        assert_eq!(
            data.len(),
            expected_len,
            "RGBA data must be width * height * 4 bytes"
        );

        Self {
            width,
            height,
            rowstride: width * 4,
            has_alpha: true,
            bits_per_sample: 8,
            channels: 4,
            data,
        }
    }

    /// Convert image to freedesktop notification hint format
    ///
    /// Returns a tuple matching the freedesktop specification:
    /// `(width, height, rowstride, has_alpha, bits_per_sample, channels, data)`
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_connect_core::plugins::notification_image::NotificationImage;
    ///
    /// let rgba_data = vec![255u8; 8 * 8 * 4];
    /// let image = NotificationImage::from_rgba(8, 8, rgba_data);
    /// let hint = image.to_freedesktop_hint();
    ///
    /// assert_eq!(hint.0, 8);  // width
    /// assert_eq!(hint.1, 8);  // height
    /// assert_eq!(hint.2, 32); // rowstride (8 * 4)
    /// assert_eq!(hint.3, true); // has_alpha
    /// assert_eq!(hint.4, 8);  // bits_per_sample
    /// assert_eq!(hint.5, 4);  // channels
    /// assert_eq!(hint.6.len(), 256); // data (8 * 8 * 4)
    /// ```
    pub fn to_freedesktop_hint(&self) -> (i32, i32, i32, bool, i32, i32, Vec<u8>) {
        (
            self.width as i32,
            self.height as i32,
            self.rowstride as i32,
            self.has_alpha,
            self.bits_per_sample as i32,
            self.channels as i32,
            self.data.clone(),
        )
    }

    /// Decode a PNG image from bytes
    ///
    /// # Arguments
    ///
    /// * `data` - PNG image data
    ///
    /// # Errors
    ///
    /// Returns `ImageError::DecodingFailed` if PNG decoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use cosmic_connect_core::plugins::notification_image::NotificationImage;
    ///
    /// let png_bytes = std::fs::read("icon.png").unwrap();
    /// let image = NotificationImage::from_png_bytes(&png_bytes).unwrap();
    /// ```
    pub fn from_png_bytes(data: &[u8]) -> Result<Self, ImageError> {
        use image::ImageFormat;

        let img = image::load_from_memory_with_format(data, ImageFormat::Png)
            .map_err(|e| ImageError::DecodingFailed(format!("PNG decode error: {}", e)))?;

        let rgba = img.to_rgba8();
        let (width, height) = rgba.dimensions();

        Ok(Self::from_rgba(width, height, rgba.into_raw()))
    }

    /// Decode a JPEG image from bytes
    ///
    /// # Arguments
    ///
    /// * `data` - JPEG image data
    ///
    /// # Errors
    ///
    /// Returns `ImageError::DecodingFailed` if JPEG decoding fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use cosmic_connect_core::plugins::notification_image::NotificationImage;
    ///
    /// let jpeg_bytes = std::fs::read("photo.jpg").unwrap();
    /// let image = NotificationImage::from_jpeg_bytes(&jpeg_bytes).unwrap();
    /// ```
    pub fn from_jpeg_bytes(data: &[u8]) -> Result<Self, ImageError> {
        use image::ImageFormat;

        let img = image::load_from_memory_with_format(data, ImageFormat::Jpeg)
            .map_err(|e| ImageError::DecodingFailed(format!("JPEG decode error: {}", e)))?;

        let rgba = img.to_rgba8();
        let (width, height) = rgba.dimensions();

        Ok(Self::from_rgba(width, height, rgba.into_raw()))
    }

    /// Scale image to fit within maximum dimensions
    ///
    /// Preserves aspect ratio. If image is already smaller than max dimensions,
    /// returns a clone unchanged.
    ///
    /// # Arguments
    ///
    /// * `max_width` - Maximum width in pixels
    /// * `max_height` - Maximum height in pixels
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_connect_core::plugins::notification_image::NotificationImage;
    ///
    /// let data = vec![255u8; 100 * 100 * 4]; // 100x100 image
    /// let image = NotificationImage::from_rgba(100, 100, data);
    ///
    /// let scaled = image.scale(50, 50);
    /// assert_eq!(scaled.width, 50);
    /// assert_eq!(scaled.height, 50);
    /// ```
    pub fn scale(&self, max_width: u32, max_height: u32) -> Self {
        // If already smaller, return clone
        if self.width <= max_width && self.height <= max_height {
            return self.clone();
        }

        // Calculate new dimensions preserving aspect ratio
        let width_ratio = max_width as f32 / self.width as f32;
        let height_ratio = max_height as f32 / self.height as f32;
        let ratio = width_ratio.min(height_ratio);

        let new_width = (self.width as f32 * ratio) as u32;
        let new_height = (self.height as f32 * ratio) as u32;

        // Use image crate for high-quality scaling
        use image::{ImageBuffer, Rgba};

        let img_buffer: ImageBuffer<Rgba<u8>, Vec<u8>> =
            ImageBuffer::from_raw(self.width, self.height, self.data.clone())
                .expect("Failed to create image buffer");

        let scaled = image::imageops::resize(
            &img_buffer,
            new_width,
            new_height,
            image::imageops::FilterType::Lanczos3,
        );

        Self::from_rgba(new_width, new_height, scaled.into_raw())
    }

    /// Get the size of the image data in bytes
    ///
    /// # Example
    ///
    /// ```rust
    /// use cosmic_connect_core::plugins::notification_image::NotificationImage;
    ///
    /// let data = vec![255u8; 20 * 20 * 4];
    /// let image = NotificationImage::from_rgba(20, 20, data);
    /// assert_eq!(image.data_size(), 1600); // 20 * 20 * 4
    /// ```
    pub fn data_size(&self) -> u64 {
        self.data.len() as u64
    }

    /// Get image width (for FFI interface)
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Get image height (for FFI interface)
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Get rowstride (for FFI interface)
    pub fn rowstride(&self) -> u32 {
        self.rowstride
    }

    /// Check if has alpha (for FFI interface)
    pub fn has_alpha(&self) -> bool {
        self.has_alpha
    }

    /// Get bits per sample (for FFI interface)
    pub fn bits_per_sample(&self) -> u8 {
        self.bits_per_sample
    }

    /// Get channels (for FFI interface)
    pub fn channels(&self) -> u8 {
        self.channels
    }
}

// FFI exports for Android/Kotlin integration
#[cfg(feature = "ffi")]
mod ffi {
    use super::*;

    /// Create a notification image from RGBA data
    ///
    /// # Arguments
    ///
    /// * `width` - Image width in pixels
    /// * `height` - Image height in pixels
    /// * `rgba_data` - RGBA8888 pixel data
    ///
    /// # Example (Kotlin)
    ///
    /// ```kotlin
    /// val bitmap: Bitmap = ... // Your Android bitmap
    /// val buffer = ByteBuffer.allocate(bitmap.byteCount)
    /// bitmap.copyPixelsToBuffer(buffer)
    /// val rgba = buffer.array()
    ///
    /// val image = createNotificationImage(
    ///     bitmap.width.toUInt(),
    ///     bitmap.height.toUInt(),
    ///     rgba.toList()
    /// )
    /// ```
    #[uniffi::export]
    pub fn create_notification_image(
        width: u32,
        height: u32,
        rgba_data: Vec<u8>,
    ) -> Arc<NotificationImage> {
        Arc::new(NotificationImage::from_rgba(width, height, rgba_data))
    }

    /// Create a notification image from encoded image bytes
    ///
    /// Supports PNG and JPEG formats.
    ///
    /// # Arguments
    ///
    /// * `data` - Image file data
    /// * `mime_type` - MIME type ("image/png" or "image/jpeg")
    ///
    /// # Errors
    ///
    /// Returns error string if decoding fails or format is unsupported
    ///
    /// # Example (Kotlin)
    ///
    /// ```kotlin
    /// val iconBytes = notification.getLargeIcon()?.toByteArray()
    /// if (iconBytes != null) {
    ///     val image = notificationImageFromBytes(
    ///         iconBytes.toList(),
    ///         "image/png"
    ///     ).getOrThrow()
    /// }
    /// ```
    #[uniffi::export]
    pub fn notification_image_from_bytes(
        data: Vec<u8>,
        mime_type: String,
    ) -> Result<Arc<NotificationImage>, String> {
        let image = match mime_type.as_str() {
            "image/png" => NotificationImage::from_png_bytes(&data)
                .map_err(|e| format!("PNG decode failed: {}", e))?,
            "image/jpeg" | "image/jpg" => NotificationImage::from_jpeg_bytes(&data)
                .map_err(|e| format!("JPEG decode failed: {}", e))?,
            _ => {
                return Err(format!(
                    "Unsupported image format: {}. Use image/png or image/jpeg",
                    mime_type
                ))
            }
        };

        Ok(Arc::new(image))
    }

    /// Scale a notification image to fit within maximum dimensions
    ///
    /// # Arguments
    ///
    /// * `image` - The image to scale
    /// * `max_width` - Maximum width in pixels
    /// * `max_height` - Maximum height in pixels
    ///
    /// # Example (Kotlin)
    ///
    /// ```kotlin
    /// val scaled = scaleNotificationImage(image, 128u, 128u)
    /// ```
    #[uniffi::export]
    pub fn scale_notification_image(
        image: Arc<NotificationImage>,
        max_width: u32,
        max_height: u32,
    ) -> Arc<NotificationImage> {
        Arc::new(image.scale(max_width, max_height))
    }

    /// Get the RGBA data from a notification image
    ///
    /// # Arguments
    ///
    /// * `image` - The notification image
    ///
    /// # Returns
    ///
    /// RGBA8888 pixel data
    ///
    /// # Example (Kotlin)
    ///
    /// ```kotlin
    /// val rgbaData = getNotificationImageData(image)
    /// val bitmap = Bitmap.createBitmap(
    ///     image.width.toInt(),
    ///     image.height.toInt(),
    ///     Bitmap.Config.ARGB_8888
    /// )
    /// bitmap.copyPixelsFromBuffer(ByteBuffer.wrap(rgbaData.toByteArray()))
    /// ```
    #[uniffi::export]
    pub fn get_notification_image_data(image: Arc<NotificationImage>) -> Vec<u8> {
        image.data.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_rgba() {
        let data = vec![255u8; 10 * 10 * 4];
        let image = NotificationImage::from_rgba(10, 10, data);

        assert_eq!(image.width, 10);
        assert_eq!(image.height, 10);
        assert_eq!(image.rowstride, 40);
        assert!(image.has_alpha);
        assert_eq!(image.bits_per_sample, 8);
        assert_eq!(image.channels, 4);
        assert_eq!(image.data.len(), 400);
    }

    #[test]
    #[should_panic(expected = "RGBA data must be width * height * 4 bytes")]
    fn test_from_rgba_invalid_size() {
        let data = vec![255u8; 100]; // Too small
        NotificationImage::from_rgba(10, 10, data);
    }

    #[test]
    fn test_to_freedesktop_hint() {
        let data = vec![255u8; 8 * 8 * 4];
        let image = NotificationImage::from_rgba(8, 8, data);
        let hint = image.to_freedesktop_hint();

        assert_eq!(hint.0, 8); // width
        assert_eq!(hint.1, 8); // height
        assert_eq!(hint.2, 32); // rowstride
        assert_eq!(hint.3, true); // has_alpha
        assert_eq!(hint.4, 8); // bits_per_sample
        assert_eq!(hint.5, 4); // channels
        assert_eq!(hint.6.len(), 256); // data
    }

    #[test]
    fn test_scale_smaller() {
        let data = vec![255u8; 100 * 100 * 4];
        let image = NotificationImage::from_rgba(100, 100, data);

        let scaled = image.scale(50, 50);
        assert_eq!(scaled.width, 50);
        assert_eq!(scaled.height, 50);
        assert_eq!(scaled.data.len(), 50 * 50 * 4);
    }

    #[test]
    fn test_scale_aspect_ratio() {
        let data = vec![255u8; 100 * 50 * 4]; // 2:1 aspect ratio
        let image = NotificationImage::from_rgba(100, 50, data);

        let scaled = image.scale(60, 60);
        // Should scale to 60x30 to preserve 2:1 ratio
        assert_eq!(scaled.width, 60);
        assert_eq!(scaled.height, 30);
    }

    #[test]
    fn test_scale_already_small() {
        let data = vec![255u8; 10 * 10 * 4];
        let image = NotificationImage::from_rgba(10, 10, data.clone());

        let scaled = image.scale(50, 50);
        // Should return unchanged
        assert_eq!(scaled.width, 10);
        assert_eq!(scaled.height, 10);
        assert_eq!(scaled.data, data);
    }

    #[test]
    fn test_data_size() {
        let data = vec![255u8; 20 * 20 * 4];
        let image = NotificationImage::from_rgba(20, 20, data);
        assert_eq!(image.data_size(), 1600);
    }

    // Integration test with PNG - simplified to test error handling
    // Creating valid minimal PNG in tests is complex, so we test with image crate
    #[test]
    fn test_from_png_bytes() {
        use image::{ImageBuffer, Rgba};

        // Create a 2x2 test image
        let img: ImageBuffer<Rgba<u8>, Vec<u8>> =
            ImageBuffer::from_fn(2, 2, |x, y| {
                if (x + y) % 2 == 0 {
                    Rgba([255, 0, 0, 255]) // Red
                } else {
                    Rgba([0, 0, 255, 255]) // Blue
                }
            });

        // Encode to PNG
        let mut png_data = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut png_data),
            image::ImageFormat::Png,
        )
        .expect("Failed to encode PNG");

        // Test decoding
        let result = NotificationImage::from_png_bytes(&png_data);
        assert!(result.is_ok(), "PNG decoding should succeed");

        let image = result.unwrap();
        assert_eq!(image.width(), 2);
        assert_eq!(image.height(), 2);
        assert_eq!(image.channels(), 4);
        assert!(image.has_alpha());
        assert_eq!(image.data_size(), 16); // 2 * 2 * 4 bytes
    }

    #[test]
    fn test_from_png_bytes_invalid() {
        let invalid_data = vec![0xFF, 0xD8, 0xFF]; // Not a PNG
        let result = NotificationImage::from_png_bytes(&invalid_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_clone() {
        let data = vec![255u8; 10 * 10 * 4];
        let image = NotificationImage::from_rgba(10, 10, data.clone());
        let cloned = image.clone();

        assert_eq!(cloned.width, image.width);
        assert_eq!(cloned.height, image.height);
        assert_eq!(cloned.data, image.data);
    }
}
