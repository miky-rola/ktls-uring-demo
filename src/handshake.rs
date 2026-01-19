//! TLS handshake driver using rustls unbuffered API
//!
//! Performs the TLS handshake and extracts secrets for kTLS configuration.
//! Uses blocking I/O during handshake (acceptable for the small amount of data).

use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::Arc;

use rustls::client::UnbufferedClientConnection;
use rustls::unbuffered::{
    ConnectionState, EncodeError, EncryptError, InsufficientSizeError, UnbufferedStatus,
};
use rustls::{ClientConfig, ConnectionTrafficSecrets, ProtocolVersion};
use rustls::pki_types::ServerName;

/// Result of a successful TLS handshake
pub struct HandshakeResult {
    /// TX secrets: (sequence_number, traffic_secrets)
    pub tx: (u64, ConnectionTrafficSecrets),
    /// RX secrets: (sequence_number, traffic_secrets)
    pub rx: (u64, ConnectionTrafficSecrets),
    /// Negotiated TLS version
    pub version: ProtocolVersion,
}

#[derive(Debug)]
pub enum HandshakeError {
    Io(std::io::Error),
    Tls(rustls::Error),
    Encode(EncodeError),
    Encrypt(EncryptError),
    InsufficientSize(InsufficientSizeError),
    ConnectionClosed,
    SecretExtractionFailed,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Io(e) => write!(f, "I/O error during handshake: {e}"),
            HandshakeError::Tls(e) => write!(f, "TLS error during handshake: {e}"),
            HandshakeError::Encode(e) => write!(f, "Encode error: {e:?}"),
            HandshakeError::Encrypt(e) => write!(f, "Encrypt error: {e:?}"),
            HandshakeError::InsufficientSize(e) => write!(f, "Buffer too small: {e:?}"),
            HandshakeError::ConnectionClosed => write!(f, "Connection closed during handshake"),
            HandshakeError::SecretExtractionFailed => write!(f, "Failed to extract TLS secrets"),
        }
    }
}

impl std::error::Error for HandshakeError {}

impl From<std::io::Error> for HandshakeError {
    fn from(e: std::io::Error) -> Self {
        HandshakeError::Io(e)
    }
}

impl From<rustls::Error> for HandshakeError {
    fn from(e: rustls::Error) -> Self {
        HandshakeError::Tls(e)
    }
}

impl From<EncodeError> for HandshakeError {
    fn from(e: EncodeError) -> Self {
        HandshakeError::Encode(e)
    }
}

impl From<EncryptError> for HandshakeError {
    fn from(e: EncryptError) -> Self {
        HandshakeError::Encrypt(e)
    }
}

impl From<InsufficientSizeError> for HandshakeError {
    fn from(e: InsufficientSizeError) -> Self {
        HandshakeError::InsufficientSize(e)
    }
}

/// Internal action to defer until after state is dropped
enum HandshakeAction {
    NeedData,
}

/// Wrapper for raw FD that doesn't close on drop
struct BorrowedSocket {
    fd: RawFd,
}

impl BorrowedSocket {
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }

    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut stream = unsafe { std::net::TcpStream::from_raw_fd(self.fd) };
        let result = stream.read(buf);
        std::mem::forget(stream); // Don't close the FD
        result
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        let mut stream = unsafe { std::net::TcpStream::from_raw_fd(self.fd) };
        let result = stream.write_all(buf);
        std::mem::forget(stream); // Don't close the FD
        result
    }

    fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        let stream = unsafe { std::net::TcpStream::from_raw_fd(self.fd) };
        let result = stream.set_nonblocking(nonblocking);
        std::mem::forget(stream);
        result
    }
}

/// Perform TLS handshake and extract secrets for kTLS
pub fn perform_handshake(
    fd: RawFd,
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
) -> Result<HandshakeResult, HandshakeError> {
    let mut socket = BorrowedSocket::new(fd);

    // Ensure blocking mode for handshake
    socket.set_nonblocking(false)?;

    let mut conn = UnbufferedClientConnection::new(config, server_name)?;

    let mut incoming_tls = vec![0u8; 16384];
    let mut outgoing_tls = vec![0u8; 16384];
    let mut incoming_used = 0usize;

    loop {
        let UnbufferedStatus { discard, state } =
            conn.process_tls_records(&mut incoming_tls[..incoming_used]);

        // Handle state first, then discard
        let result = match state? {
            ConnectionState::EncodeTlsData(mut encoder) => {
                // Encode handshake data to send
                let written = encoder.encode(&mut outgoing_tls)?;
                socket.write_all(&outgoing_tls[..written])?;
                None
            }

            ConnectionState::TransmitTlsData(transmit) => {
                // Data was already sent in EncodeTlsData, mark done
                transmit.done();
                None
            }

            ConnectionState::BlockedHandshake => {
                // Need more data from peer - handled after discard
                Some(HandshakeAction::NeedData)
            }

            ConnectionState::WriteTraffic(_) => {
                // Handshake complete! Extract secrets for kTLS
                let version = conn
                    .protocol_version()
                    .unwrap_or(ProtocolVersion::TLSv1_3);

                // Extract secrets for kTLS
                #[allow(deprecated)]
                let secrets = conn
                    .dangerous_extract_secrets()
                    .map_err(|_| HandshakeError::SecretExtractionFailed)?;

                return Ok(HandshakeResult {
                    tx: secrets.tx,
                    rx: secrets.rx,
                    version,
                });
            }

            ConnectionState::ReadTraffic(_) => {
                // Server sent early data - shouldn't happen for client
                // Continue to process and reach WriteTraffic state
                None
            }

            ConnectionState::Closed => {
                return Err(HandshakeError::ConnectionClosed);
            }

            ConnectionState::ReadEarlyData(_) => {
                // Early data state - continue processing
                None
            }

            _ => {
                // Other states - continue processing
                None
            }
        };

        // Discard processed bytes after state is handled
        if discard > 0 {
            incoming_tls.copy_within(discard..incoming_used, 0);
            incoming_used -= discard;
        }

        // Handle deferred actions
        if let Some(HandshakeAction::NeedData) = result {
            let n = socket.read(&mut incoming_tls[incoming_used..])?;
            if n == 0 {
                return Err(HandshakeError::ConnectionClosed);
            }
            incoming_used += n;
        }
    }
}
