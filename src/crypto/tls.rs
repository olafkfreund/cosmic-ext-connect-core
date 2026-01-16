//! TLS Transport for KDE Connect
//!
//! Provides encrypted TCP connections using TLS with mutual certificate authentication.
//! Used for secure communication between paired devices.
//!
//! ## Security Model
//!
//! - **Trust-On-First-Use (TOFU)**: Accept any certificate, verify fingerprint at application layer
//! - **TLS 1.2+**: Modern TLS only (rustls doesn't support TLS 1.0)
//! - **Mutual TLS**: Both client and server present certificates
//! - **Self-signed certificates**: KDE Connect uses self-signed RSA 2048-bit certs
//!
//! ## KDE Connect TLS Role Quirk
//!
//! KDE Connect uses **inverted TLS roles** compared to standard TLS:
//! - Device that **accepts** TCP connection acts as **TLS CLIENT**
//! - Device that **initiates** TCP connection acts as **TLS SERVER**
//!
//! This matches Qt's `startClientEncryption()` behavior.
//!
//! ## Device ID Comparison for TCP Connection
//!
//! To prevent both devices from simultaneously trying to connect to each other,
//! KDE Connect uses device ID comparison to determine who initiates:
//!
//! - Lexicographically **smaller** device ID → Initiates TCP connection → TLS SERVER
//! - Lexicographically **larger** device ID → Accepts TCP connection → TLS CLIENT

use crate::crypto::CertificateInfo;
use crate::error::{ProtocolError, Result};
use crate::protocol::Packet;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ServerConfig};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use tracing::{debug, error, info, warn};

/// Default timeout for TLS operations (5 minutes for idle connections)
const TLS_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum packet size (10MB - supports file transfer metadata)
const MAX_PACKET_SIZE: usize = 10 * 1024 * 1024;

/// Trust-On-First-Use certificate verifier
///
/// Accepts any certificate without verification. Certificate fingerprint
/// verification happens at the application layer during pairing.
#[derive(Debug)]
struct TofuCertVerifier;

impl rustls::client::danger::ServerCertVerifier for TofuCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Accept any certificate (TOFU model)
        // Application layer will verify SHA256 fingerprint during pairing
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Accept any signature
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Accept any signature
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

/// Trust-On-First-Use client certificate verifier
#[derive(Debug)]
struct TofuClientCertVerifier;

impl rustls::server::danger::ClientCertVerifier for TofuClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        // No root CAs
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // Accept any certificate (TOFU model)
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Accept any signature
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Accept any signature
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }

    fn offer_client_auth(&self) -> bool {
        // Request client certificates
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        // Client certificates are required (mutual TLS)
        true
    }
}

/// Determine TLS role based on device ID comparison
///
/// Returns `true` if our device should act as TCP initiator (TLS server).
/// Returns `false` if our device should wait for connection (TLS client).
///
/// # Arguments
///
/// * `our_device_id` - Our device's UUID
/// * `peer_device_id` - Peer device's UUID
///
/// # Returns
///
/// - `true` → We initiate TCP (become TLS SERVER)
/// - `false` → We accept TCP (become TLS CLIENT)
pub fn should_initiate_connection(our_device_id: &str, peer_device_id: &str) -> bool {
    // Lexicographically smaller device ID initiates connection
    our_device_id < peer_device_id
}

/// TLS configuration for KDE Connect
///
/// Provides both client and server configurations for inverted TLS roles.
pub struct TlsConfig {
    /// Client configuration (used by TCP acceptor)
    client_config: Arc<ClientConfig>,
    /// Server configuration (used by TCP initiator)
    server_config: Arc<ServerConfig>,
}

impl TlsConfig {
    /// Create TLS configuration from certificate
    ///
    /// # Arguments
    ///
    /// * `cert_info` - Device certificate information
    pub fn new(cert_info: &CertificateInfo) -> Result<Self> {
        debug!("Creating TLS config for device {}", cert_info.device_id);

        // Parse certificate and private key
        let cert_der = CertificateDer::from(cert_info.certificate.clone());
        let key_der = PrivateKeyDer::try_from(cert_info.private_key.clone())
            .map_err(|e| ProtocolError::Certificate(format!("Invalid private key: {:?}", e)))?;

        // Create client config (for accepting TCP connections)
        let client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TofuCertVerifier))
            .with_client_auth_cert(vec![cert_der.clone()], key_der.clone_key())
            .map_err(|e| {
                ProtocolError::Certificate(format!("Failed to create client config: {}", e))
            })?;

        // Create server config (for initiating TCP connections)
        let server_config = ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(TofuClientCertVerifier))
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| {
                ProtocolError::Certificate(format!("Failed to create server config: {}", e))
            })?;

        Ok(Self {
            client_config: Arc::new(client_config),
            server_config: Arc::new(server_config),
        })
    }

    /// Get client configuration (for TCP acceptor → TLS client)
    pub fn client_config(&self) -> Arc<ClientConfig> {
        Arc::clone(&self.client_config)
    }

    /// Get server configuration (for TCP initiator → TLS server)
    pub fn server_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.server_config)
    }
}

/// TLS connection to a remote device
pub struct TlsConnection {
    /// TLS stream (client or server)
    stream: TlsStream<TcpStream>,
    /// Remote address
    remote_addr: SocketAddr,
    /// Device ID of remote peer (if known)
    device_id: Option<String>,
}

impl TlsConnection {
    /// Connect to a remote device using TLS (we become TLS SERVER)
    ///
    /// KDE Connect quirk: TCP initiator acts as TLS SERVER.
    ///
    /// # Arguments
    ///
    /// * `addr` - Remote socket address
    /// * `config` - TLS configuration
    pub async fn connect(addr: SocketAddr, config: &TlsConfig) -> Result<Self> {
        info!("Connecting to {} via TLS (we are TLS SERVER)", addr);

        // Connect TCP stream
        let tcp_stream = timeout(TLS_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| {
                ProtocolError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Connection timeout",
                ))
            })??;

        debug!("TCP connection established to {}", addr);

        // Create TLS acceptor with SERVER config (inverted role!)
        let acceptor = TlsAcceptor::from(config.server_config());

        // Perform TLS handshake as SERVER
        let tls_stream = timeout(TLS_TIMEOUT, acceptor.accept(tcp_stream))
            .await
            .map_err(|_| {
                ProtocolError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TLS handshake timeout",
                ))
            })?
            .map_err(|e| {
                error!("TLS handshake failed: {}", e);
                ProtocolError::Io(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("TLS handshake failed: {}", e),
                ))
            })?;

        info!("TLS connection established to {} (as TLS SERVER)", addr);

        Ok(Self {
            stream: tokio_rustls::TlsStream::Server(tls_stream),
            remote_addr: addr,
            device_id: None,
        })
    }

    /// Create from an accepted TLS stream
    fn from_stream(stream: TlsStream<TcpStream>, remote_addr: SocketAddr) -> Self {
        Self {
            stream,
            remote_addr,
            device_id: None,
        }
    }

    /// Set the device ID for this connection
    pub fn set_device_id(&mut self, device_id: String) {
        self.device_id = Some(device_id);
    }

    /// Get the device ID if known
    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

    /// Get remote address
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Send a packet over the TLS connection
    pub async fn send_packet(&mut self, packet: &Packet) -> Result<()> {
        let bytes = packet.to_bytes()?;

        if bytes.len() > MAX_PACKET_SIZE {
            return Err(ProtocolError::InvalidPacket(format!(
                "Packet too large: {} bytes (max {})",
                bytes.len(),
                MAX_PACKET_SIZE
            )));
        }

        debug!(
            "Sending packet '{}' ({} bytes) to {}",
            packet.packet_type,
            bytes.len(),
            self.remote_addr
        );

        // KDE Connect protocol: Send packet data followed by newline
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;

        debug!("Packet sent successfully to {}", self.remote_addr);
        Ok(())
    }

    /// Receive a packet from the TLS connection
    pub async fn receive_packet(&mut self) -> Result<Packet> {
        debug!("Waiting for packet from {}", self.remote_addr);

        // Read until newline (packet delimiter)
        let mut packet_bytes = Vec::new();
        let mut byte_buf = [0u8; 1];

        loop {
            match timeout(TLS_TIMEOUT, self.stream.read_exact(&mut byte_buf)).await {
                Ok(Ok(_)) => {
                    packet_bytes.push(byte_buf[0]);
                    if byte_buf[0] == b'\n' {
                        break;
                    }
                    if packet_bytes.len() > MAX_PACKET_SIZE {
                        error!("Packet too large: {} bytes", packet_bytes.len());
                        return Err(ProtocolError::InvalidPacket(format!(
                            "Packet too large: {} bytes (max {})",
                            packet_bytes.len(),
                            MAX_PACKET_SIZE
                        )));
                    }
                }
                Ok(Err(e)) => {
                    warn!("Error reading packet from {}: {}", self.remote_addr, e);
                    return Err(ProtocolError::Io(e));
                }
                Err(_) => {
                    return Err(ProtocolError::Io(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Read timeout",
                    )));
                }
            }
        }

        debug!(
            "Received packet ({} bytes) from {}",
            packet_bytes.len(),
            self.remote_addr
        );

        let packet = Packet::from_bytes(&packet_bytes)?;
        debug!(
            "Received packet type '{}' from {}",
            packet.packet_type, self.remote_addr
        );

        Ok(packet)
    }

    /// Close the TLS connection
    pub async fn close(mut self) -> Result<()> {
        debug!("Closing TLS connection to {}", self.remote_addr);
        self.stream.shutdown().await?;
        Ok(())
    }
}

/// Device information for identity packets
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub device_id: String,
    pub device_name: String,
    pub device_type: String,
    pub protocol_version: i32,
    pub incoming_capabilities: Vec<String>,
    pub outgoing_capabilities: Vec<String>,
    pub tcp_port: u16,
}

/// TLS server for accepting connections from paired devices
pub struct TlsServer {
    /// TCP listener
    listener: TcpListener,
    /// TLS configuration
    config: TlsConfig,
    /// Local address
    local_addr: SocketAddr,
    /// Our device information
    device_info: DeviceInfo,
}

impl TlsServer {
    /// Create a new TLS server
    ///
    /// # Arguments
    ///
    /// * `addr` - Local address to bind to
    /// * `cert_info` - Our device certificate
    /// * `device_info` - Our device information for identity packet
    pub async fn new(
        addr: SocketAddr,
        cert_info: &CertificateInfo,
        device_info: DeviceInfo,
    ) -> Result<Self> {
        info!("Starting TLS server on {}", addr);

        // Create TLS configuration
        let config = TlsConfig::new(cert_info)?;

        // Bind TCP listener
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;

        info!("TLS server listening on {}", local_addr);

        Ok(Self {
            listener,
            config,
            local_addr,
            device_info,
        })
    }

    /// Get the local address
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Accept an incoming connection with KDE Connect handshake
    ///
    /// KDE Connect protocol v8 handshake:
    /// 1. Accept TCP connection
    /// 2. Read plain-text identity packet from client
    /// 3. Perform TLS handshake as CLIENT (inverted role!)
    /// 4. Send our identity over encrypted connection
    /// 5. Read client's encrypted identity
    ///
    /// Returns the TLS connection and the remote device's identity packet.
    pub async fn accept(&self) -> Result<(TlsConnection, Packet)> {
        debug!("Waiting for incoming connection");

        // Accept TCP connection
        let (mut tcp_stream, remote_addr) = self.listener.accept().await?;

        debug!("TCP connection accepted from {}", remote_addr);

        // Read plain-text identity packet byte-by-byte
        let mut identity_bytes = Vec::new();
        let mut byte_buf = [0u8; 1];

        loop {
            match timeout(TLS_TIMEOUT, tcp_stream.read_exact(&mut byte_buf)).await {
                Ok(Ok(_)) => {
                    identity_bytes.push(byte_buf[0]);
                    if byte_buf[0] == b'\n' {
                        break;
                    }
                    if identity_bytes.len() > MAX_PACKET_SIZE {
                        warn!("Identity packet too large from {}", remote_addr);
                        return Err(ProtocolError::InvalidPacket(
                            "Identity packet exceeds maximum size".to_string(),
                        ));
                    }
                }
                Ok(Err(e)) => {
                    warn!("Error reading identity packet from {}: {}", remote_addr, e);
                    return Err(ProtocolError::Io(e));
                }
                Err(_) => {
                    warn!("Timeout reading identity packet from {}", remote_addr);
                    return Err(ProtocolError::Io(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Timeout reading identity packet",
                    )));
                }
            }
        }

        if identity_bytes.is_empty() {
            warn!(
                "Connection closed before receiving identity from {}",
                remote_addr
            );
            return Err(ProtocolError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Connection closed before identity packet",
            )));
        }

        debug!(
            "Received plain-text identity packet from {} ({} bytes)",
            remote_addr,
            identity_bytes.len()
        );

        // Parse identity packet
        let remote_identity = Packet::from_bytes(&identity_bytes)?;

        if remote_identity.packet_type != "cconnect.identity" {
            warn!(
                "Received non-identity packet from {}: {}",
                remote_addr, remote_identity.packet_type
            );
            return Err(ProtocolError::InvalidPacket(format!(
                "Expected identity packet, got {}",
                remote_identity.packet_type
            )));
        }

        let device_name = remote_identity
            .body
            .get("deviceName")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");

        info!("Received identity from {} at {}", device_name, remote_addr);

        // KDE Connect quirk: TCP acceptor acts as TLS CLIENT
        debug!("Starting TLS handshake as CLIENT with {}", remote_addr);

        // Create TLS connector with CLIENT config (inverted role!)
        let connector = TlsConnector::from(self.config.client_config());

        // Use IP address as SNI name (KDE Connect doesn't use real domain names)
        let server_name = ServerName::try_from(remote_addr.ip().to_string())
            .unwrap_or_else(|_| ServerName::try_from("cconnect.local").unwrap());

        // Perform TLS handshake as CLIENT
        let mut tls_stream = timeout(TLS_TIMEOUT, connector.connect(server_name, tcp_stream))
            .await
            .map_err(|_| {
                warn!("TLS handshake timeout from {}", remote_addr);
                ProtocolError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TLS handshake timeout",
                ))
            })?
            .map_err(|e| {
                warn!("TLS handshake failed from {}: {}", remote_addr, e);
                ProtocolError::Io(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("TLS handshake failed: {}", e),
                ))
            })?;

        info!("TLS connection established with {} at {}", device_name, remote_addr);

        // Protocol v8: Post-TLS identity exchange
        let protocol_version = remote_identity
            .body
            .get("protocolVersion")
            .and_then(|v| v.as_i64())
            .unwrap_or(7) as i32;

        if protocol_version >= 8 {
            debug!(
                "Protocol v8 detected - performing post-TLS identity exchange with {}",
                remote_addr
            );

            // Send our encrypted identity packet
            let our_identity_packet = Packet::new(
                "cconnect.identity",
                serde_json::json!({
                    "deviceId": self.device_info.device_id,
                    "deviceName": self.device_info.device_name,
                    "deviceType": self.device_info.device_type,
                    "protocolVersion": self.device_info.protocol_version,
                    "incomingCapabilities": self.device_info.incoming_capabilities,
                    "outgoingCapabilities": self.device_info.outgoing_capabilities,
                    "tcpPort": self.device_info.tcp_port,
                }),
            );

            let identity_bytes = our_identity_packet.to_bytes()?;
            tls_stream.write_all(&identity_bytes).await?;
            tls_stream.flush().await?;

            debug!(
                "Sent encrypted identity packet to {} ({} bytes)",
                remote_addr,
                identity_bytes.len()
            );

            // Read client's encrypted identity packet
            let mut encrypted_identity_bytes = Vec::new();
            let mut byte_buf = [0u8; 1];

            loop {
                match timeout(TLS_TIMEOUT, tls_stream.read_exact(&mut byte_buf)).await {
                    Ok(Ok(_)) => {
                        encrypted_identity_bytes.push(byte_buf[0]);
                        if byte_buf[0] == b'\n' {
                            break;
                        }
                        if encrypted_identity_bytes.len() > MAX_PACKET_SIZE {
                            warn!("Encrypted identity packet too large from {}", remote_addr);
                            return Err(ProtocolError::InvalidPacket(
                                "Encrypted identity packet exceeds maximum size".to_string(),
                            ));
                        }
                    }
                    Ok(Err(e)) => {
                        warn!(
                            "Error reading encrypted identity packet from {}: {}",
                            remote_addr, e
                        );
                        return Err(ProtocolError::Io(e));
                    }
                    Err(_) => {
                        warn!(
                            "Timeout reading encrypted identity packet from {}",
                            remote_addr
                        );
                        return Err(ProtocolError::Io(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "Timeout reading encrypted identity packet",
                        )));
                    }
                }
            }

            debug!(
                "Received encrypted identity packet from {} ({} bytes)",
                remote_addr,
                encrypted_identity_bytes.len()
            );

            // Parse and validate encrypted identity
            let encrypted_identity = Packet::from_bytes(&encrypted_identity_bytes)?;

            if encrypted_identity.packet_type != "cconnect.identity" {
                warn!(
                    "Received non-identity packet over TLS from {}: {}",
                    remote_addr, encrypted_identity.packet_type
                );
                return Err(ProtocolError::InvalidPacket(format!(
                    "Expected identity packet over TLS, got {}",
                    encrypted_identity.packet_type
                )));
            }

            // Validate device ID consistency
            let encrypted_device_id = encrypted_identity
                .body
                .get("deviceId")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let pre_tls_device_id = remote_identity
                .body
                .get("deviceId")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if encrypted_device_id != pre_tls_device_id {
                warn!(
                    "Device ID mismatch between pre-TLS ({}) and post-TLS ({}) identity from {}",
                    pre_tls_device_id, encrypted_device_id, remote_addr
                );
                return Err(ProtocolError::InvalidPacket(
                    "Device ID changed during TLS handshake".to_string(),
                ));
            }

            info!(
                "Protocol v8 post-TLS identity exchange completed successfully with {}",
                remote_addr
            );

            // Use encrypted identity as authoritative
            Ok((
                TlsConnection::from_stream(tokio_rustls::TlsStream::Client(tls_stream), remote_addr),
                encrypted_identity,
            ))
        } else {
            // Protocol v7: No post-TLS identity exchange
            Ok((
                TlsConnection::from_stream(tokio_rustls::TlsStream::Client(tls_stream), remote_addr),
                remote_identity,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_should_initiate_connection() {
        // Device with smaller ID should initiate
        assert!(should_initiate_connection("device1", "device2"));
        assert!(!should_initiate_connection("device2", "device1"));

        // Same device ID (shouldn't happen in practice)
        assert!(!should_initiate_connection("device1", "device1"));

        // UUID-like strings
        assert!(should_initiate_connection(
            "12345678-1234-1234-1234-123456789012",
            "87654321-4321-4321-4321-210987654321"
        ));
    }

    #[test]
    fn test_tls_config_creation() {
        let cert_info = CertificateInfo::generate("test_device").unwrap();
        let config = TlsConfig::new(&cert_info);
        assert!(config.is_ok());
    }

    #[tokio::test]
    async fn test_tls_server_creation() {
        let cert_info = CertificateInfo::generate("test_device").unwrap();
        let device_info = DeviceInfo {
            device_id: "test_device".to_string(),
            device_name: "Test Device".to_string(),
            device_type: "desktop".to_string(),
            protocol_version: 8,
            incoming_capabilities: vec![],
            outgoing_capabilities: vec![],
            tcp_port: 1816,
        };

        let server_addr = "127.0.0.1:0".parse().unwrap();
        let server = TlsServer::new(server_addr, &cert_info, device_info).await;
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_tls_handshake_and_packet_exchange() {
        // Generate certificates for two devices
        let device1_cert = CertificateInfo::generate("device1").unwrap();
        let device2_cert = CertificateInfo::generate("device2").unwrap();

        // Create device info for server (device2)
        let device2_info = DeviceInfo {
            device_id: "device2".to_string(),
            device_name: "Test Device 2".to_string(),
            device_type: "desktop".to_string(),
            protocol_version: 8,
            incoming_capabilities: vec!["cconnect.ping".to_string()],
            outgoing_capabilities: vec!["cconnect.ping".to_string()],
            tcp_port: 1816,
        };

        // Start TLS server on device2
        let server_addr = "127.0.0.1:0".parse().unwrap();
        let server = TlsServer::new(server_addr, &device2_cert, device2_info.clone())
            .await
            .unwrap();

        let server_port = server.local_addr().port();
        let connect_addr = format!("127.0.0.1:{}", server_port)
            .parse()
            .unwrap();

        // Spawn server task
        let server_task = tokio::spawn(async move {
            // Accept connection (will act as TLS CLIENT due to inverted roles)
            let (mut conn, identity) = server.accept().await.unwrap();

            // Verify we received identity packet
            assert_eq!(identity.packet_type, "cconnect.identity");
            assert_eq!(
                identity
                    .body
                    .get("deviceId")
                    .and_then(|v| v.as_str())
                    .unwrap(),
                "device1"
            );

            // Receive test packet from client
            let packet = conn.receive_packet().await.unwrap();
            assert_eq!(packet.packet_type, "cconnect.ping");
            assert_eq!(
                packet.body.get("message").and_then(|v| v.as_str()).unwrap(),
                "hello"
            );

            // Send response
            let response = Packet::new("cconnect.ping", json!({"message": "pong"}));
            conn.send_packet(&response).await.unwrap();

            conn.close().await.unwrap();
        });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Create client config for device1
        let client_config = TlsConfig::new(&device1_cert).unwrap();

        // Spawn client task that sends plain-text identity first
        let client_task = tokio::spawn(async move {
            // Connect TCP
            let mut tcp_stream = TcpStream::connect(connect_addr).await.unwrap();

            // Send plain-text identity packet (protocol requirement)
            let identity_packet = Packet::new(
                "cconnect.identity",
                json!({
                    "deviceId": "device1",
                    "deviceName": "Test Device 1",
                    "deviceType": "desktop",
                    "protocolVersion": 8,
                    "incomingCapabilities": ["cconnect.ping"],
                    "outgoingCapabilities": ["cconnect.ping"],
                    "tcpPort": 1816,
                }),
            );

            let identity_bytes = identity_packet.to_bytes().unwrap();
            tcp_stream.write_all(&identity_bytes).await.unwrap();
            tcp_stream.flush().await.unwrap();

            // Now perform TLS handshake as SERVER (inverted role!)
            let acceptor = TlsAcceptor::from(client_config.server_config());
            let mut tls_stream = acceptor.accept(tcp_stream).await.unwrap();

            // Protocol v8: Send identity over encrypted connection
            let encrypted_identity_packet = Packet::new(
                "cconnect.identity",
                json!({
                    "deviceId": "device1",
                    "deviceName": "Test Device 1",
                    "deviceType": "desktop",
                    "protocolVersion": 8,
                    "incomingCapabilities": ["cconnect.ping"],
                    "outgoingCapabilities": ["cconnect.ping"],
                    "tcpPort": 1816,
                }),
            );

            let encrypted_identity_bytes = encrypted_identity_packet.to_bytes().unwrap();
            tls_stream.write_all(&encrypted_identity_bytes).await.unwrap();
            tls_stream.flush().await.unwrap();

            // Receive server's encrypted identity
            let mut identity_bytes = Vec::new();
            let mut byte_buf = [0u8; 1];
            loop {
                tls_stream.read_exact(&mut byte_buf).await.unwrap();
                identity_bytes.push(byte_buf[0]);
                if byte_buf[0] == b'\n' {
                    break;
                }
            }

            let server_identity = Packet::from_bytes(&identity_bytes).unwrap();
            assert_eq!(server_identity.packet_type, "cconnect.identity");
            assert_eq!(
                server_identity
                    .body
                    .get("deviceId")
                    .and_then(|v| v.as_str())
                    .unwrap(),
                "device2"
            );

            // Now we can create TlsConnection and exchange packets
            let mut conn =
                TlsConnection::from_stream(tokio_rustls::TlsStream::Server(tls_stream), connect_addr);

            // Send test packet
            let test_packet = Packet::new("cconnect.ping", json!({"message": "hello"}));
            conn.send_packet(&test_packet).await.unwrap();

            // Receive response
            let response = conn.receive_packet().await.unwrap();
            assert_eq!(response.packet_type, "cconnect.ping");
            assert_eq!(
                response.body.get("message").and_then(|v| v.as_str()).unwrap(),
                "pong"
            );

            conn.close().await.unwrap();
        });

        // Wait for both tasks to complete
        let (server_result, client_result) = tokio::join!(server_task, client_task);
        server_result.unwrap();
        client_result.unwrap();
    }

    #[test]
    fn test_device_id_comparison_determines_roles() {
        // This test verifies the TLS role determination logic
        let device_a = "aaa-device-uuid";
        let device_b = "zzz-device-uuid";

        // Device A (smaller ID) should initiate TCP connection
        assert!(should_initiate_connection(device_a, device_b));
        // Which means Device A becomes TLS SERVER

        // Device B (larger ID) should accept TCP connection
        assert!(!should_initiate_connection(device_b, device_a));
        // Which means Device B becomes TLS CLIENT

        // This prevents both devices from simultaneously connecting
    }
}
