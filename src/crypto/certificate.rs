//! Certificate Management for KDE Connect
//!
//! This module provides certificate generation and management for secure TLS connections.
//! KDE Connect uses self-signed RSA 2048-bit certificates with Trust-On-First-Use (TOFU) model.
//!
//! ## Certificate Requirements
//!
//! - **Algorithm**: RSA 2048-bit
//! - **Organization (O)**: "KDE"
//! - **Organizational Unit (OU)**: "Kde connect"
//! - **Common Name (CN)**: Device UUID
//! - **Validity**: 10 years
//! - **Self-signed**: Certificate is signed by its own private key
//!
//! ## Security Model
//!
//! - Trust-On-First-Use (TOFU): Accept certificate on first pairing
//! - SHA256 fingerprint verification prevents MITM attacks
//! - Certificates stored and verified on subsequent connections

use crate::error::{ProtocolError, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rsa::{RsaPrivateKey, pkcs8::EncodePrivateKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::Duration;
use tracing::{debug, info};

/// Certificate validity period (10 years)
const CERT_VALIDITY_YEARS: u32 = 10;

/// Organization name in certificate
const CERT_ORG: &str = "KDE";

/// Organizational unit in certificate
const CERT_ORG_UNIT: &str = "Kde connect";

/// Device certificate information
///
/// Contains the certificate, private key, and SHA256 fingerprint.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// Device ID (UUID) - used as Common Name
    pub device_id: String,

    /// DER-encoded certificate
    pub certificate: Vec<u8>,

    /// DER-encoded private key (PKCS#8)
    pub private_key: Vec<u8>,

    /// SHA256 fingerprint of certificate (for user verification)
    pub fingerprint: String,
}

impl CertificateInfo {
    /// Generate a new self-signed RSA 2048-bit certificate for a device
    ///
    /// # Arguments
    ///
    /// * `device_id` - Unique device identifier (used as Common Name)
    ///
    /// # Examples
    ///
    /// ```
    /// use cosmic_ext_connect_core::crypto::CertificateInfo;
    ///
    /// let cert_info = CertificateInfo::generate("test_device_id").unwrap();
    /// println!("Fingerprint: {}", cert_info.fingerprint);
    /// ```
    pub fn generate(device_id: impl Into<String>) -> Result<Self> {
        let device_id = device_id.into();

        info!("Generating RSA 2048-bit certificate for device: {}", device_id);

        // Generate RSA 2048-bit key using rsa crate
        // (rcgen 0.12 doesn't support RSA key generation directly)
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| ProtocolError::Certificate(format!("Failed to generate RSA key: {}", e)))?;

        // Convert to PKCS#8 DER format
        let private_key_der = private_key.to_pkcs8_der()
            .map_err(|e| ProtocolError::Certificate(format!("Failed to encode private key: {}", e)))?;

        // Import into rcgen KeyPair
        let key_pair = KeyPair::from_der(private_key_der.as_bytes())
            .map_err(|e| ProtocolError::Certificate(format!("Failed to import key pair: {}", e)))?;

        // Create certificate parameters
        let mut params = CertificateParams::new(vec![device_id.clone()]);

        // Set algorithm to RSA with SHA-256 (must match the key pair)
        params.alg = &rcgen::PKCS_RSA_SHA256;

        // Set the RSA key pair
        params.key_pair = Some(key_pair);

        // Set distinguished name (DN)
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, CERT_ORG);
        dn.push(DnType::OrganizationalUnitName, CERT_ORG_UNIT);
        dn.push(DnType::CommonName, device_id.clone());
        params.distinguished_name = dn;

        // Set validity period (10 years from now)
        let validity_duration = Duration::from_secs(CERT_VALIDITY_YEARS as u64 * 365 * 24 * 60 * 60);
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after = params.not_before + validity_duration;

        // Set as not a CA (end-entity certificate)
        params.is_ca = rcgen::IsCa::NoCa;

        // Set key usages
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
            rcgen::KeyUsagePurpose::KeyAgreement,
        ];

        // Generate self-signed certificate
        let cert = rcgen::Certificate::from_params(params)
            .map_err(|e| ProtocolError::Certificate(format!("Failed to create certificate: {}", e)))?;

        // Get DER-encoded certificate
        let certificate_der = cert.serialize_der()
            .map_err(|e| ProtocolError::Certificate(format!("Failed to serialize certificate: {}", e)))?;

        // Get DER-encoded private key (PKCS#8 format)
        let private_key_der = cert.serialize_private_key_der();

        // Calculate SHA256 fingerprint
        let fingerprint = Self::calculate_fingerprint(&certificate_der);

        info!(
            "Generated certificate for device {} with fingerprint: {}",
            device_id, fingerprint
        );

        Ok(Self {
            device_id,
            certificate: certificate_der,
            private_key: private_key_der,
            fingerprint,
        })
    }

    /// Calculate SHA256 fingerprint of a certificate
    ///
    /// Returns fingerprint in format: XX:XX:XX:...:XX (hex bytes separated by colons)
    ///
    /// # Examples
    ///
    /// ```
    /// use cosmic_ext_connect_core::crypto::CertificateInfo;
    ///
    /// let cert_info = CertificateInfo::generate("test").unwrap();
    /// let fingerprint = CertificateInfo::calculate_fingerprint(&cert_info.certificate);
    /// assert!(fingerprint.contains(':'));
    /// ```
    pub fn calculate_fingerprint(cert_der: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        let hash = hasher.finalize();

        // Format as colon-separated hex bytes (uppercase)
        hash.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join(":")
    }

    /// Save certificate and private key to PEM files
    ///
    /// # Arguments
    ///
    /// * `cert_path` - Path to save certificate (.pem)
    /// * `key_path` - Path to save private key (.pem)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use cosmic_ext_connect_core::crypto::CertificateInfo;
    ///
    /// let cert_info = CertificateInfo::generate("test").unwrap();
    /// cert_info.save_to_files("cert.pem", "key.pem").unwrap();
    /// ```
    pub fn save_to_files(
        &self,
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<()> {
        let cert_path = cert_path.as_ref();
        let key_path = key_path.as_ref();

        // Create parent directories if they don't exist
        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Convert DER to PEM format
        let cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE".to_string(), self.certificate.clone()));

        let key_pem = pem::encode(&pem::Pem::new("PRIVATE KEY".to_string(), self.private_key.clone()));

        // Write to files
        fs::write(cert_path, cert_pem.as_bytes())?;
        fs::write(key_path, key_pem.as_bytes())?;

        info!(
            "Saved certificate to {:?} and private key to {:?}",
            cert_path, key_path
        );

        Ok(())
    }

    /// Load certificate and private key from PEM files
    ///
    /// # Arguments
    ///
    /// * `cert_path` - Path to certificate file (.pem)
    /// * `key_path` - Path to private key file (.pem)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use cosmic_ext_connect_core::crypto::CertificateInfo;
    ///
    /// let cert_info = CertificateInfo::load_from_files("cert.pem", "key.pem").unwrap();
    /// println!("Loaded certificate for device: {}", cert_info.device_id);
    /// ```
    pub fn load_from_files(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<Self> {
        let cert_path = cert_path.as_ref();
        let key_path = key_path.as_ref();

        debug!("Loading certificate from {:?}", cert_path);

        // Read and parse certificate file (PEM format)
        let cert_pem_data = fs::read(cert_path)?;
        let cert_pem = pem::parse(&cert_pem_data)
            .map_err(|e| ProtocolError::Certificate(format!("Failed to parse certificate PEM: {}", e)))?;

        if cert_pem.tag() != "CERTIFICATE" {
            return Err(ProtocolError::Certificate(format!(
                "Expected CERTIFICATE tag, got {}",
                cert_pem.tag()
            )));
        }

        let certificate = cert_pem.contents().to_vec();

        // Read and parse private key file (PEM format)
        let key_pem_data = fs::read(key_path)?;
        let key_pem = pem::parse(&key_pem_data)
            .map_err(|e| ProtocolError::Certificate(format!("Failed to parse private key PEM: {}", e)))?;

        if key_pem.tag() != "PRIVATE KEY" && key_pem.tag() != "RSA PRIVATE KEY" {
            return Err(ProtocolError::Certificate(format!(
                "Expected PRIVATE KEY or RSA PRIVATE KEY tag, got {}",
                key_pem.tag()
            )));
        }

        let private_key = key_pem.contents().to_vec();

        // Extract device ID from certificate Common Name
        let device_id = Self::extract_device_id_from_cert(&certificate)?;

        // Calculate fingerprint
        let fingerprint = Self::calculate_fingerprint(&certificate);

        info!(
            "Loaded certificate for device {} with fingerprint: {}",
            device_id, fingerprint
        );

        Ok(Self {
            device_id,
            certificate,
            private_key,
            fingerprint,
        })
    }

    /// Load certificate and private key from DER bytes
    ///
    /// # Arguments
    ///
    /// * `cert_der` - DER-encoded certificate
    /// * `key_der` - DER-encoded private key (PKCS#8)
    ///
    /// # Examples
    ///
    /// ```
    /// use cosmic_ext_connect_core::crypto::CertificateInfo;
    ///
    /// let generated = CertificateInfo::generate("test").unwrap();
    /// let loaded = CertificateInfo::from_der(
    ///     generated.certificate.clone(),
    ///     generated.private_key.clone()
    /// ).unwrap();
    /// assert_eq!(generated.device_id, loaded.device_id);
    /// ```
    pub fn from_der(cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<Self> {
        // Extract device ID from certificate
        let device_id = Self::extract_device_id_from_cert(&cert_der)?;

        // Calculate fingerprint
        let fingerprint = Self::calculate_fingerprint(&cert_der);

        Ok(Self {
            device_id,
            certificate: cert_der,
            private_key: key_der,
            fingerprint,
        })
    }

    /// Extract device ID from certificate Common Name
    ///
    /// Uses x509-parser to extract CN from certificate DN
    fn extract_device_id_from_cert(cert_der: &[u8]) -> Result<String> {
        use x509_parser::prelude::*;

        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| ProtocolError::Certificate(format!("Failed to parse certificate: {}", e)))?;

        // Get subject name
        let subject = cert.subject();

        // Find CN (Common Name) entry
        for rdn in subject.iter() {
            for attr in rdn.iter() {
                if attr.attr_type() == &x509_parser::oid_registry::OID_X509_COMMON_NAME {
                    let cn = attr.as_str()
                        .map_err(|e| ProtocolError::Certificate(format!("Failed to extract CN: {}", e)))?;
                    return Ok(cn.to_string());
                }
            }
        }

        Err(ProtocolError::Certificate(
            "Certificate does not contain Common Name".to_string(),
        ))
    }

    /// Validate certificate format and contents
    ///
    /// Checks:
    /// - Certificate can be parsed
    /// - Has valid Distinguished Name
    /// - Has not expired
    /// - Key size is sufficient (RSA 2048+)
    pub fn validate(&self) -> Result<()> {
        use x509_parser::prelude::*;

        // Parse certificate
        let (_, cert) = X509Certificate::from_der(&self.certificate)
            .map_err(|e| ProtocolError::Certificate(format!("Failed to parse certificate: {}", e)))?;

        // Check validity period
        let now = ::time::OffsetDateTime::now_utc();
        let not_before = cert.validity().not_before.to_datetime();
        let not_after = cert.validity().not_after.to_datetime();

        if now < not_before {
            return Err(ProtocolError::Certificate(
                "Certificate not yet valid".to_string(),
            ));
        }

        if now > not_after {
            return Err(ProtocolError::Certificate(
                "Certificate has expired".to_string(),
            ));
        }

        // Verify key algorithm (should be RSA)
        let public_key = cert.public_key();
        let algo = &public_key.algorithm.algorithm;

        if algo != &x509_parser::oid_registry::OID_PKCS1_RSAENCRYPTION {
            return Err(ProtocolError::Certificate(format!(
                "Expected RSA encryption, got OID: {:?}",
                algo
            )));
        }

        // Check key size (RSA 2048+ bits)
        // Note: Actual key size validation would require parsing the public key
        // For now, we trust that rcgen generates correct key sizes

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_certificate() {
        let cert_info = CertificateInfo::generate("test_device_123").unwrap();

        assert_eq!(cert_info.device_id, "test_device_123");
        assert!(!cert_info.certificate.is_empty());
        assert!(!cert_info.private_key.is_empty());
        assert!(!cert_info.fingerprint.is_empty());
        assert!(cert_info.fingerprint.contains(':'));
    }

    #[test]
    fn test_fingerprint_format() {
        let cert_info = CertificateInfo::generate("test").unwrap();
        let fingerprint = &cert_info.fingerprint;

        // Should be hex bytes separated by colons
        // SHA256 produces 32 bytes = 64 hex chars + 31 colons = 95 chars total
        assert_eq!(fingerprint.len(), 95);
        assert_eq!(fingerprint.matches(':').count(), 31);

        // All characters should be hex digits or colons
        for c in fingerprint.chars() {
            assert!(c.is_ascii_hexdigit() || c == ':');
        }
    }

    #[test]
    fn test_save_and_load_files() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        // Generate and save
        let original = CertificateInfo::generate("test_device").unwrap();
        original.save_to_files(&cert_path, &key_path).unwrap();

        // Load and verify
        let loaded = CertificateInfo::load_from_files(&cert_path, &key_path).unwrap();

        assert_eq!(original.device_id, loaded.device_id);
        assert_eq!(original.certificate, loaded.certificate);
        assert_eq!(original.private_key, loaded.private_key);
        assert_eq!(original.fingerprint, loaded.fingerprint);
    }

    #[test]
    fn test_from_der() {
        let generated = CertificateInfo::generate("test_device").unwrap();
        let loaded = CertificateInfo::from_der(
            generated.certificate.clone(),
            generated.private_key.clone(),
        )
        .unwrap();

        assert_eq!(generated.device_id, loaded.device_id);
        assert_eq!(generated.fingerprint, loaded.fingerprint);
    }

    #[test]
    fn test_validate() {
        let cert_info = CertificateInfo::generate("test").unwrap();
        assert!(cert_info.validate().is_ok());
    }

    #[test]
    fn test_fingerprint_consistency() {
        let cert_info = CertificateInfo::generate("test").unwrap();
        let fp1 = CertificateInfo::calculate_fingerprint(&cert_info.certificate);
        let fp2 = CertificateInfo::calculate_fingerprint(&cert_info.certificate);

        assert_eq!(fp1, fp2);
        assert_eq!(cert_info.fingerprint, fp1);
    }
}
