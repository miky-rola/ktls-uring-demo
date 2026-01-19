//! kTLS (Kernel TLS) configuration module
//!
//! Configures Linux kernel to handle TLS encryption/decryption via setsockopt().
//! After setup, the kernel transparently encrypts/decrypts data on the socket.

use std::os::unix::io::RawFd;
use rustls::ConnectionTrafficSecrets;

// Constants from linux/tls.h
const TCP_ULP: libc::c_int = 31;
const SOL_TLS: libc::c_int = 282;
const TLS_TX: libc::c_int = 1;
const TLS_RX: libc::c_int = 2;

// TLS versions
const TLS_1_2_VERSION: u16 = 0x0303;
const TLS_1_3_VERSION: u16 = 0x0304;

// Cipher types
const TLS_CIPHER_AES_GCM_128: u16 = 51;
const TLS_CIPHER_AES_GCM_256: u16 = 52;
const TLS_CIPHER_CHACHA20_POLY1305: u16 = 54;

// Crypto info base structure
#[repr(C)]
struct TlsCryptoInfo {
    version: u16,
    cipher_type: u16,
}

// AES-128-GCM crypto info (TLS 1.2 and 1.3)
#[repr(C)]
struct Tls12CryptoInfoAesGcm128 {
    info: TlsCryptoInfo,
    iv: [u8; 8],
    key: [u8; 16],
    salt: [u8; 4],
    rec_seq: [u8; 8],
}

// AES-256-GCM crypto info (TLS 1.2 and 1.3)
#[repr(C)]
struct Tls12CryptoInfoAesGcm256 {
    info: TlsCryptoInfo,
    iv: [u8; 8],
    key: [u8; 32],
    salt: [u8; 4],
    rec_seq: [u8; 8],
}

// ChaCha20-Poly1305 crypto info (TLS 1.2 and 1.3)
#[repr(C)]
struct Tls12CryptoInfoChacha20Poly1305 {
    info: TlsCryptoInfo,
    iv: [u8; 12],
    key: [u8; 32],
    salt: [u8; 0],
    rec_seq: [u8; 8],
}

#[derive(Debug)]
pub enum KtlsError {
    UlpSetupFailed(std::io::Error),
    TxSetupFailed(std::io::Error),
    RxSetupFailed(std::io::Error),
}

impl std::fmt::Display for KtlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KtlsError::UlpSetupFailed(e) => write!(f, "Failed to enable TLS ULP: {e}"),
            KtlsError::TxSetupFailed(e) => write!(f, "Failed to configure TLS TX: {e}"),
            KtlsError::RxSetupFailed(e) => write!(f, "Failed to configure TLS RX: {e}"),
        }
    }
}

impl std::error::Error for KtlsError {}

/// Map rustls ProtocolVersion to kTLS version constant
pub fn tls_version(version: rustls::ProtocolVersion) -> u16 {
    match version {
        rustls::ProtocolVersion::TLSv1_2 => TLS_1_2_VERSION,
        rustls::ProtocolVersion::TLSv1_3 => TLS_1_3_VERSION,
        _ => TLS_1_3_VERSION, // Default to TLS 1.3
    }
}

/// Configure kTLS on a socket using extracted rustls secrets
pub fn configure_ktls(
    fd: RawFd,
    tx: (u64, ConnectionTrafficSecrets),
    rx: (u64, ConnectionTrafficSecrets),
    version: u16,
) -> Result<(), KtlsError> {
    // Step 1: Enable TLS ULP (Upper Layer Protocol)
    let ulp_name = b"tls\0";
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_TCP,
            TCP_ULP,
            ulp_name.as_ptr() as *const libc::c_void,
            ulp_name.len() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(KtlsError::UlpSetupFailed(std::io::Error::last_os_error()));
    }

    // Step 2: Configure TX (transmit/encrypt) direction
    configure_direction(fd, TLS_TX, tx.0, &tx.1, version)
        .map_err(KtlsError::TxSetupFailed)?;

    // Step 3: Configure RX (receive/decrypt) direction
    configure_direction(fd, TLS_RX, rx.0, &rx.1, version)
        .map_err(KtlsError::RxSetupFailed)?;

    Ok(())
}

fn configure_direction(
    fd: RawFd,
    direction: libc::c_int,
    seq_num: u64,
    secrets: &ConnectionTrafficSecrets,
    version: u16,
) -> Result<(), std::io::Error> {
    match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
            let iv_bytes = iv.as_ref();
            let mut crypto_info = Tls12CryptoInfoAesGcm128 {
                info: TlsCryptoInfo {
                    version,
                    cipher_type: TLS_CIPHER_AES_GCM_128,
                },
                iv: [0u8; 8],
                key: [0u8; 16],
                salt: [0u8; 4],
                rec_seq: seq_num.to_be_bytes(),
            };

            // For TLS 1.2 AES-GCM:
            // - salt (4 bytes) = implicit nonce (first 4 bytes of rustls IV)
            // - iv (8 bytes) = explicit nonce for next record (use sequence number)
            // - rec_seq (8 bytes) = record sequence number
            crypto_info.salt.copy_from_slice(&iv_bytes[..4]);
            crypto_info.iv = seq_num.to_be_bytes();
            crypto_info.key.copy_from_slice(key.as_ref());

            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    SOL_TLS,
                    direction,
                    &crypto_info as *const _ as *const libc::c_void,
                    std::mem::size_of::<Tls12CryptoInfoAesGcm128>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }

        ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
            let iv_bytes = iv.as_ref();
            let mut crypto_info = Tls12CryptoInfoAesGcm256 {
                info: TlsCryptoInfo {
                    version,
                    cipher_type: TLS_CIPHER_AES_GCM_256,
                },
                iv: [0u8; 8],
                key: [0u8; 32],
                salt: [0u8; 4],
                rec_seq: seq_num.to_be_bytes(),
            };

            // For TLS 1.2 AES-GCM: salt = implicit nonce, iv = explicit nonce (seq num)
            crypto_info.salt.copy_from_slice(&iv_bytes[..4]);
            crypto_info.iv = seq_num.to_be_bytes();
            crypto_info.key.copy_from_slice(key.as_ref());

            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    SOL_TLS,
                    direction,
                    &crypto_info as *const _ as *const libc::c_void,
                    std::mem::size_of::<Tls12CryptoInfoAesGcm256>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }

        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
            let mut crypto_info = Tls12CryptoInfoChacha20Poly1305 {
                info: TlsCryptoInfo {
                    version,
                    cipher_type: TLS_CIPHER_CHACHA20_POLY1305,
                },
                iv: [0u8; 12],
                key: [0u8; 32],
                salt: [0u8; 0],
                rec_seq: seq_num.to_be_bytes(),
            };

            crypto_info.iv.copy_from_slice(iv.as_ref());
            crypto_info.key.copy_from_slice(key.as_ref());

            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    SOL_TLS,
                    direction,
                    &crypto_info as *const _ as *const libc::c_void,
                    std::mem::size_of::<Tls12CryptoInfoChacha20Poly1305>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }

        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Cipher suite not supported by kTLS",
            ));
        }
    }

    Ok(())
}
