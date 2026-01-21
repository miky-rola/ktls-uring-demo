//! WebSocket framing implementation (RFC 6455)
//!
//! Minimal WebSocket protocol implementation for use with kTLS + io_uring.
//! Handles handshake, frame encoding/decoding, and message types.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use sha1::{Sha1, Digest};

/// WebSocket opcodes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

impl Opcode {
    fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x0 => Some(Opcode::Continuation),
            0x1 => Some(Opcode::Text),
            0x2 => Some(Opcode::Binary),
            0x8 => Some(Opcode::Close),
            0x9 => Some(Opcode::Ping),
            0xA => Some(Opcode::Pong),
            _ => None,
        }
    }
}

/// Decoded WebSocket message
#[derive(Debug)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
    Close(Option<(u16, String)>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
}

/// WebSocket frame header info
#[derive(Debug)]
pub struct FrameHeader {
    pub opcode: Opcode,
    pub payload_len: usize,
    pub header_len: usize,
}

/// Generate a random 16-byte key and encode as base64 for Sec-WebSocket-Key
pub fn generate_sec_key() -> String {
    let mut key = [0u8; 16];
    getrandom::fill(&mut key).expect("failed to get random bytes");
    BASE64.encode(key)
}

/// WebSocket GUID used in handshake (RFC 6455)
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Compute expected Sec-WebSocket-Accept value from client key (RFC 6455 Section 1.3)
fn compute_accept_key(sec_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(sec_key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    BASE64.encode(hasher.finalize())
}

/// Build WebSocket handshake request
pub fn build_handshake_request(host: &str, path: &str, sec_key: &str) -> String {
    format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n",
        path, host, sec_key
    )
}

/// Validate WebSocket handshake response (RFC 6455 Section 1.3)
pub fn validate_handshake_response(response: &str, sec_key: &str) -> Result<(), String> {
    // Check status line
    if !response.starts_with("HTTP/1.1 101") {
        return Err(format!("Expected 101 Switching Protocols, got: {}",
            response.lines().next().unwrap_or("empty")));
    }

    // Check required headers (case-insensitive)
    let lower = response.to_lowercase();
    if !lower.contains("upgrade: websocket") {
        return Err("Missing 'Upgrade: websocket' header".into());
    }
    if !lower.contains("connection: upgrade") {
        return Err("Missing 'Connection: Upgrade' header".into());
    }

    // Extract and validate Sec-WebSocket-Accept header
    let accept_value = response
        .lines()
        .find_map(|line| {
            let lower_line = line.to_lowercase();
            if lower_line.starts_with("sec-websocket-accept:") {
                Some(line.split_once(':')?.1.trim())
            } else {
                None
            }
        })
        .ok_or("Missing 'Sec-WebSocket-Accept' header")?;

    let expected = compute_accept_key(sec_key);
    if accept_value != expected {
        return Err(format!(
            "Invalid Sec-WebSocket-Accept: expected '{}', got '{}'",
            expected, accept_value
        ));
    }

    Ok(())
}

/// Generate a 4-byte masking key (RFC 6455 Section 5.3 requires strong entropy)
fn generate_mask_key() -> [u8; 4] {
    let mut key = [0u8; 4];
    getrandom::fill(&mut key).expect("failed to get random bytes");
    key
}

/// Encode a WebSocket text frame (client frames must be masked)
pub fn encode_text_frame(text: &str) -> Vec<u8> {
    encode_frame(Opcode::Text, text.as_bytes(), true)
}

/// Encode a WebSocket close frame
pub fn encode_close_frame(code: Option<u16>) -> Vec<u8> {
    let payload = match code {
        Some(c) => c.to_be_bytes().to_vec(),
        None => Vec::new(),
    };
    encode_frame(Opcode::Close, &payload, true)
}

/// Encode a WebSocket frame
fn encode_frame(opcode: Opcode, payload: &[u8], masked: bool) -> Vec<u8> {
    let payload_len = payload.len();

    // Calculate frame size
    let header_size = if payload_len < 126 {
        2
    } else if payload_len < 65536 {
        4
    } else {
        10
    };
    let mask_size = if masked { 4 } else { 0 };

    let mut frame = Vec::with_capacity(header_size + mask_size + payload_len);

    // First byte: FIN + opcode
    frame.push(0x80 | (opcode as u8));

    // Second byte: MASK bit + payload length
    let mask_bit = if masked { 0x80 } else { 0x00 };

    if payload_len < 126 {
        frame.push(mask_bit | (payload_len as u8));
    } else if payload_len < 65536 {
        frame.push(mask_bit | 126);
        frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
    } else {
        frame.push(mask_bit | 127);
        frame.extend_from_slice(&(payload_len as u64).to_be_bytes());
    }

    // Masking key (required for client-to-server frames)
    if masked {
        let mask_key = generate_mask_key();
        frame.extend_from_slice(&mask_key);

        // Apply mask to payload
        for (i, &byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask_key[i % 4]);
        }
    } else {
        frame.extend_from_slice(payload);
    }

    frame
}

/// Parse frame header from buffer, returns None if not enough data
pub fn parse_frame_header(data: &[u8]) -> Option<FrameHeader> {
    if data.len() < 2 {
        return None;
    }

    let opcode = Opcode::from_u8(data[0] & 0x0F)?;
    let masked = (data[1] & 0x80) != 0;
    let length_byte = data[1] & 0x7F;

    let (payload_len, header_len) = if length_byte < 126 {
        (length_byte as usize, 2)
    } else if length_byte == 126 {
        if data.len() < 4 {
            return None;
        }
        let len = u16::from_be_bytes([data[2], data[3]]) as usize;
        (len, 4)
    } else {
        if data.len() < 10 {
            return None;
        }
        let len = u64::from_be_bytes([
            data[2], data[3], data[4], data[5],
            data[6], data[7], data[8], data[9],
        ]) as usize;
        (len, 10)
    };

    // Add mask bytes to header length if masked
    let header_len = if masked { header_len + 4 } else { header_len };

    Some(FrameHeader {
        opcode,
        payload_len,
        header_len,
    })
}

/// Decode a complete WebSocket frame from buffer
/// Returns (message, total_bytes_consumed) or None if incomplete
pub fn decode_frame(data: &[u8]) -> Option<(Message, usize)> {
    let header = parse_frame_header(data)?;

    let total_len = header.header_len + header.payload_len;
    if data.len() < total_len {
        return None;
    }

    // Extract payload
    let mut payload = data[header.header_len..total_len].to_vec();

    // Check if server frame is masked (shouldn't be, but handle it)
    let masked = (data[1] & 0x80) != 0;
    if masked {
        let mask_start = header.header_len - 4;
        let mask_key = &data[mask_start..mask_start + 4];
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask_key[i % 4];
        }
    }

    let message = match header.opcode {
        Opcode::Text => {
            let text = String::from_utf8_lossy(&payload).into_owned();
            Message::Text(text)
        }
        Opcode::Binary => Message::Binary(payload),
        Opcode::Close => {
            if payload.len() >= 2 {
                let code = u16::from_be_bytes([payload[0], payload[1]]);
                let reason = if payload.len() > 2 {
                    String::from_utf8_lossy(&payload[2..]).into_owned()
                } else {
                    String::new()
                };
                Message::Close(Some((code, reason)))
            } else {
                Message::Close(None)
            }
        }
        Opcode::Ping => Message::Ping(payload),
        Opcode::Pong => Message::Pong(payload),
        Opcode::Continuation => {
            // For simplicity, treat continuation as binary
            Message::Binary(payload)
        }
    };

    Some((message, total_len))
}
