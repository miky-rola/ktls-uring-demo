# kTLS Migration - Thinking Log

## Initial Analysis

### Current Architecture Understanding

The project is an HTTPS client that combines:
1. **tokio-uring** - For io_uring-based async TCP connection
2. **rustls** - For userspace TLS encryption/decryption
3. **FD duplication hack** - Bridges the two incompatible I/O models

**The Problem:**
- tokio-uring uses completion-based async I/O (io_uring)
- rustls expects blocking Read/Write streams
- Current solution: duplicate the file descriptor so both can "own" it
- Result: TLS operations are blocking and don't leverage io_uring at all

**Code Flow (src/main.rs):**
```
Line 49: TcpStream::connect(addr).await  // io_uring async connect
Line 54-61: FD duplication hack          // Bridge to blocking I/O
Line 66-67: StreamOwned wrapper          // rustls takes over (blocking)
Line 90: tls.write_all()                 // Blocking write
Line 95: tls.read_to_string()            // Blocking read
```

### Why kTLS Solves This

kTLS (Kernel TLS) offloads encryption/decryption to the Linux kernel. After the TLS handshake:
1. Configure the socket with crypto keys via `setsockopt()`
2. Kernel handles all encryption/decryption transparently
3. io_uring can read/write directly - data is encrypted/decrypted by kernel
4. No more blocking userspace crypto operations

**New Flow:**
```
TCP connect (io_uring) → TLS handshake (rustls) → Extract secrets →
Configure kTLS (setsockopt) → io_uring read/write (kernel encrypts/decrypts)
```

## Research: kTLS Setup Process

### 1. Enable TLS ULP (Upper Layer Protocol)
```c
setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
```

### 2. Configure TX (transmit/encrypt)
```c
struct tls12_crypto_info_aes_gcm_128 crypto_info;
crypto_info.info.version = TLS_1_2_VERSION;  // or TLS_1_3_VERSION
crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
// Fill in: key, iv, salt, rec_seq
setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
```

### 3. Configure RX (receive/decrypt)
```c
setsockopt(fd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info));
```

### Key Constants (from linux/tls.h)
```
SOL_TLS = 282
TLS_TX = 1
TLS_RX = 2
TCP_ULP = 31

TLS_1_2_VERSION = 0x0303
TLS_1_3_VERSION = 0x0304

TLS_CIPHER_AES_GCM_128 = 51
TLS_CIPHER_AES_GCM_256 = 52
TLS_CIPHER_CHACHA20_POLY1305 = 54
```

## Research: Extracting Secrets from rustls

rustls provides `dangerous_extract_secrets()` method on connections that returns `ExtractedSecrets`:

```rust
pub struct ExtractedSecrets {
    pub tx: (u64, ConnectionTrafficSecrets),  // sequence number + secrets
    pub rx: (u64, ConnectionTrafficSecrets),
}

pub enum ConnectionTrafficSecrets {
    Aes128Gcm { key: AeadKey, iv: Iv },
    Aes256Gcm { key: AeadKey, iv: Iv },
    Chacha20Poly1305 { key: AeadKey, iv: Iv },
}
```

**Critical Detail - IV/Salt decomposition:**
- rustls provides 12-byte IV (nonce)
- kTLS expects: 4-byte salt (implicit) + 8-byte explicit IV
- Split: `salt = iv[0..4]`, `iv = iv[4..12]`

## Research: Unbuffered API

To extract secrets, we need to use rustls's `UnbufferedClientConnection` which gives us manual control over the handshake state machine. This is necessary because:

1. We need to call `dangerous_extract_secrets()` after handshake
2. The regular `ClientConnection` with `StreamOwned` doesn't expose this cleanly
3. Unbuffered API lets us drive I/O ourselves (can use blocking during handshake, it's only a few KB)

**State machine states:**
- `EncodeTlsData` - Need to send handshake data
- `TransmitTlsData` - Data ready to transmit
- `BlockedHandshake` - Need more data from peer
- `WriteTraffic` - Handshake complete, can write app data
- `ReadTraffic` - Can read app data

## Design Decisions

### 1. Handshake I/O: Blocking vs Async

**Decision:** Use blocking I/O during handshake

**Rationale:**
- Handshake is typically 2-4 round trips, < 10KB total
- Complexity of async handshake with unbuffered API is high
- After handshake, all data transfer uses io_uring (the important part)
- Simpler implementation, same end result

### 2. Fallback Strategy

**Decision:** Fall back to userspace TLS if kTLS fails

**Rationale:**
- Not all cipher suites are supported by kTLS
- Kernel might not have TLS ULP enabled
- Graceful degradation is better than hard failure
- User requested this behavior

### 3. Module Structure

**Decision:** Separate modules for ktls.rs and handshake.rs

**Rationale:**
- Clear separation of concerns
- ktls.rs: Low-level kernel interface (setsockopt, structs)
- handshake.rs: TLS handshake state machine driver
- main.rs: HTTP client logic orchestrating both

## Potential Challenges

### 1. Cipher Suite Mismatch
Server might negotiate a cipher not supported by kTLS. Solution: Fallback to userspace.

### 2. Kernel Support
Older kernels or kernels without TLS ULP. Kernel 6.2.0 should be fine. Can check `/proc/sys/net/ipv4/tcp_available_ulp`.

### 3. Sequence Number Byte Order
kTLS expects big-endian: `seq_num.to_be_bytes()`

### 4. tokio-uring Buffer Ownership
tokio-uring's read/write methods take ownership of buffers (completion-based I/O). Need to handle this in the data transfer phase.

## Implementation Order

1. **Cargo.toml** - Add nix dependency
2. **src/ktls.rs** - kTLS constants, structs, configure_ktls()
3. **src/handshake.rs** - Unbuffered handshake driver
4. **src/main.rs** - Integrate kTLS with fallback
5. **README.md** - Update architecture notes
6. **Test** - Run against httpbin.org

## Implementation Lessons Learned

### 1. Secret Extraction Must Be Enabled

rustls has `enable_secret_extraction = false` by default. Must set:
```rust
config.enable_secret_extraction = true;
```
Otherwise `dangerous_extract_secrets()` returns `General("Secret extraction is disabled")`.

### 2. IV Decomposition for TLS 1.2 AES-GCM

**Initial assumption (wrong):**
- Split rustls 12-byte IV into: salt[0..4] + explicit_iv[4..12]

**Correct approach:**
- salt = iv[0..4] (implicit nonce, fixed per connection)
- iv = sequence_number (explicit nonce, transmitted with each record)

The 8-byte explicit nonce in kTLS should be set to the sequence number, not the
last 8 bytes of rustls's IV.

### 3. Fallback Requires New Connection

When kTLS handshake fails, we can't reuse the same TCP connection for userspace
TLS fallback because:
- The socket state is corrupted by partial kTLS setup
- Or the TLS handshake partially completed

Solution: Create a new TCP connection for fallback.

### 4. EIO on Connection Close Without close_notify

When servers close TCP without sending TLS close_notify:
- Userspace rustls: Returns `UnexpectedEof` (handled gracefully)
- kTLS: Returns `EIO` (error code 5)

Solution: Treat EIO as EOF if we already received data:
```rust
if e.raw_os_error() == Some(5) && !response.is_empty() {
    break; // Treat as EOF
}
```

### 5. Borrow Checker vs Unbuffered API

The rustls unbuffered API's `process_tls_records()` borrows the input buffer,
and the returned `state` holds references into it. This causes borrow checker
issues when trying to discard processed bytes.

Solution: Use an action enum to defer buffer manipulation until after the
state is dropped:
```rust
enum HandshakeAction { NeedData }

let action = match state? { ... };

// Discard after state is dropped
if discard > 0 { ... }

// Handle deferred action
if let Some(HandshakeAction::NeedData) = action { ... }
```

## Final Architecture

```
src/
├── main.rs       # HTTP client, orchestrates kTLS + fallback
├── handshake.rs  # Unbuffered TLS handshake, secret extraction
└── ktls.rs       # kTLS socket configuration via setsockopt
```

All 5 HTTP methods (GET, POST, PUT, PATCH, DELETE) work with:
- kTLS + io_uring (primary path)
- Userspace TLS fallback (if kTLS fails)

---

## WebSocket Client Addition

### Goal
Add a WebSocket Secure (WSS) client that runs on top of the existing kTLS + io_uring infrastructure.

### Architecture Decision

**Why manual WebSocket implementation?**

Unlike the initial plan to use `tungstenite` library, which expects a `Read + Write` stream (blocking I/O), we need to implement WebSocket manually because:

1. kTLS + io_uring uses async completion-based I/O (`stream.write_all()`, `stream.read()`)
2. tungstenite's `client()` function requires synchronous `Read + Write` traits
3. Manual implementation lets us use io_uring directly for all WebSocket I/O
4. Maintains architectural consistency with the HTTP client

**Data Flow:**
```
tokio-uring TcpStream (async TCP via io_uring)
        ↓
rustls unbuffered API (TLS handshake in userspace)
        ↓
kTLS (kernel handles encryption via setsockopt)
        ↓
WebSocket protocol (manual implementation)
        ↓
io_uring read/write (kernel encrypts/decrypts transparently)
```

### WebSocket Protocol Essentials (RFC 6455)

#### 1. Opening Handshake
Standard HTTP Upgrade request over the encrypted channel:
```
GET /path HTTP/1.1
Host: echo.websocket.org
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==  (base64 of 16 random bytes)
Sec-WebSocket-Version: 13
```

Server responds with 101 Switching Protocols and `Sec-WebSocket-Accept` header (SHA-1 hash of key + magic GUID).

#### 2. Frame Format
```
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7
+-+-+-+-+-------+-+-------------+
|F|R|R|R| opcode|M| Payload len |
|I|S|S|S|  (4)  |A|     (7)     |
|N|V|V|V|       |S|             |
| |1|2|3|       |K|             |
+-+-+-+-+-------+-+-------------+
```

- **FIN bit**: 1 = final frame (no fragmentation for simple messages)
- **Opcode**: 0x1 = text, 0x2 = binary, 0x8 = close, 0x9 = ping, 0xA = pong
- **MASK bit**: 1 for client frames (required by spec), 0 for server frames
- **Payload length**:
  - 0-125: actual length
  - 126: next 2 bytes are length (16-bit)
  - 127: next 8 bytes are length (64-bit)

#### 3. Client Masking
Client frames MUST be masked with a 4-byte XOR key:
```
masked[i] = payload[i] XOR mask_key[i % 4]
```

### Implementation Plan

#### Files to Create/Modify
1. `src/websocket.rs` (new) - WebSocket framing and handshake
2. `src/main.rs` - Add WssClient struct and demo

#### websocket.rs Functions
- `build_handshake_request(host, path, key)` - Build HTTP Upgrade request
- `validate_handshake_response(response, key)` - Check 101 + Sec-WebSocket-Accept
- `encode_text_frame(payload)` - Create masked text frame
- `encode_close_frame()` - Create close frame
- `decode_frame(data)` - Parse incoming frame

#### WssClient Implementation
```rust
struct WssClient {
    tls_config: Arc<ClientConfig>,
}

impl WssClient {
    fn new() -> Self { ... }  // Same TLS config as HttpsClient

    async fn connect(&self, host: &str, path: &str) -> Result<TcpStream, ...> {
        // 1. TCP connect via io_uring
        // 2. TLS handshake + kTLS setup (reuse from HttpsClient)
        // 3. Send WebSocket upgrade request via io_uring
        // 4. Read and validate upgrade response
        // 5. Return stream ready for frame I/O
    }

    async fn send_text(stream: &TcpStream, msg: &str) -> Result<(), ...> {
        // Encode text frame with masking
        // stream.write_all(frame).await
    }

    async fn receive(stream: &TcpStream) -> Result<Message, ...> {
        // stream.read(buf).await
        // Decode frame, handle text/binary/close/ping
    }

    async fn close(stream: &TcpStream) -> Result<(), ...> {
        // Send close frame, await close response
    }
}
```

### Dependencies Needed
- `base64` crate for Sec-WebSocket-Key encoding
- `sha1` crate for Sec-WebSocket-Accept validation (or can skip validation for demo)
- Random bytes from `getrandom` or just use `/dev/urandom`

### Testing Target
`wss://echo.websocket.org` - Public WebSocket echo server

Expected output:
```
=== WebSocket Demo ===
Connecting to echo.websocket.org:443 via io_uring
Using kTLS (kernel TLS) + io_uring
WebSocket handshake complete
Sending: Hello from ktls-uring-demo!
Received: Hello from ktls-uring-demo!
Connection closed
```

### Potential Challenges

1. **Fragmented responses**: May receive partial frames, need to buffer until complete
2. **Server ping/pong**: Should respond to pings with pongs
3. **Close handshake**: Proper close requires sending close frame and waiting for response
4. **Variable-length encoding**: Must handle 16-bit and 64-bit length encodings for large payloads

### Implementation Results

#### Completed Implementation

**Files created:**
- `src/websocket.rs` - Complete WebSocket framing module (RFC 6455)

**Files modified:**
- `Cargo.toml` - Added `base64 = "0.22"` dependency
- `src/main.rs` - Added `WssClient` struct and WebSocket demo

#### websocket.rs Features
- **Handshake**: `build_handshake_request()`, `validate_handshake_response()`, `generate_sec_key()`
- **Frame encoding**: `encode_text_frame()`, `encode_close_frame()`, `encode_pong_frame()`
- **Frame decoding**: `parse_frame_header()`, `decode_frame()`
- **Message types**: Text, Binary, Close, Ping, Pong (Opcode enum)
- **Client masking**: All client frames properly masked with 4-byte XOR key
- **Payload lengths**: Supports 7-bit, 16-bit, and 64-bit length encodings

#### WssClient API
```rust
impl WssClient {
    fn new() -> Self;
    async fn connect(&self, host: &str, path: &str) -> Result<TcpStream, ...>;
    async fn send_text(stream: &TcpStream, msg: &str) -> Result<(), ...>;
    async fn receive(stream: &TcpStream) -> Result<Message, ...>;
    async fn close(stream: &TcpStream) -> Result<(), ...>;
}
```

#### Lessons Learned

##### 1. echo.websocket.org Is Defunct
The classic `echo.websocket.org` service has been shut down. Had to switch to `ws.postman-echo.com/raw` for testing.

##### 2. Sec-WebSocket-Accept Validation
For this demo, we skip SHA-1 validation of `Sec-WebSocket-Accept` header (would need another dependency). Instead, we just verify the header is present. Full validation formula:
```
base64(sha1(Sec-WebSocket-Key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
```

##### 3. Masking Key Generation
Used timestamp-based PRNG for simplicity. Production code should use `getrandom` or OS random source.

##### 4. kTLS Works Transparently
The beautiful part: once kTLS is set up, WebSocket frames go through the same `stream.write_all()` and `stream.read()` calls as HTTP. The kernel encrypts/decrypts at the socket layer - WebSocket framing is completely unaware of TLS.

#### Final Test Output
```
=== WebSocket Demo ===

Connecting to 3.212.69.204:443 via io_uring
Using kTLS (kernel TLS) + io_uring
WebSocket handshake complete
Sending: Hello from ktls-uring-demo!
Received: Hello from ktls-uring-demo!
Connection closed
```

#### Architecture Summary
```
src/
├── main.rs       # HTTP client + WebSocket client
├── handshake.rs  # Unbuffered TLS handshake, secret extraction
├── ktls.rs       # kTLS socket configuration via setsockopt
└── websocket.rs  # WebSocket framing (RFC 6455)
```

Both HTTP and WebSocket clients share the same kTLS + io_uring infrastructure:
- TCP connection via io_uring
- TLS handshake via rustls unbuffered API
- kTLS kernel encryption via setsockopt
- Application protocol (HTTP or WebSocket) over encrypted io_uring I/O

---

## Code Cleanup: Dead Code Removal

### Goal
Remove `#![allow(dead_code)]` from `websocket.rs` and fix all resulting warnings.

### Warnings Identified
After removing the allow attribute, `cargo check` showed:
1. `Message::Binary`, `Message::Close`, `Message::Ping`, `Message::Pong` - fields never read
2. `FrameHeader::fin` - field never read
3. `compute_accept_key()` - function never used
4. `encode_pong_frame()` - function never used

### Analysis

**Unused functions:**
- `compute_accept_key()` was intended for full RFC compliance (validating `Sec-WebSocket-Accept` header) but we chose to skip SHA-1 validation for the demo
- `encode_pong_frame()` was for responding to server pings, but the demo doesn't implement a full ping/pong handler

**Unused `fin` field:**
- Needed for fragmented message handling (when `fin=0`, message continues in next frame)
- Demo assumes single-frame messages, so never checked

**Message variant fields:**
- All variants were constructed in `decode_frame()` but only `Message::Text` was destructured in `main.rs`
- Other variants fell through to a catch-all `Ok(other) => println!("{other:?}")` which used Debug trait but didn't read the inner fields

### Changes Made

1. **Removed `compute_accept_key()`** - Unused, would need SHA-1 dependency for real implementation

2. **Removed `encode_pong_frame()`** - Demo doesn't handle ping/pong protocol

3. **Removed `fin` field from `FrameHeader`** - Demo assumes unfragmented messages

4. **Updated `main.rs` to handle all Message variants explicitly:**
   ```rust
   Ok(websocket::Message::Text(text)) => { println!("Received: {text}"); }
   Ok(websocket::Message::Binary(data)) => { println!("Received binary: {} bytes", data.len()); }
   Ok(websocket::Message::Close(info)) => { ... }
   Ok(websocket::Message::Ping(data)) => { println!("Received ping: {} bytes", data.len()); }
   Ok(websocket::Message::Pong(data)) => { println!("Received pong: {} bytes", data.len()); }
   ```

### Result
`cargo check` completes with no warnings. Code is cleaner and explicitly handles all WebSocket message types.

---

## Proper SHA-1 Validation for Sec-WebSocket-Accept

### Goal
Implement RFC 6455 compliant validation of the `Sec-WebSocket-Accept` header using SHA-1.

### RFC 6455 Section 1.3 Requirements
The server must respond with:
```
Sec-WebSocket-Accept = base64(SHA-1(Sec-WebSocket-Key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
```

The client must validate this value to confirm the server understands WebSocket protocol.

### Changes Made

1. **Added `sha1` crate to Cargo.toml**

2. **Added `compute_accept_key()` function in websocket.rs:**
   ```rust
   const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

   fn compute_accept_key(sec_key: &str) -> String {
       let mut hasher = Sha1::new();
       hasher.update(sec_key.as_bytes());
       hasher.update(WS_GUID.as_bytes());
       BASE64.encode(hasher.finalize())
   }
   ```

3. **Updated `validate_handshake_response()` signature:**
   - Now takes `sec_key` parameter
   - Extracts `Sec-WebSocket-Accept` value from response headers
   - Computes expected value and compares

4. **Updated main.rs** to pass `sec_key` to validation function

### Why This Matters
Without proper validation, a malicious or misconfigured server could:
- Accept the connection without actually supporting WebSocket
- MITM attack where proxy doesn't understand WebSocket and corrupts frames

The SHA-1 check cryptographically proves the server received and processed our specific key.

---

## Proper Random Key Generation

### Goal
Replace weak timestamp-based randomness with cryptographically secure random bytes.

### Problem
Both `generate_sec_key()` and `generate_mask_key()` used `SystemTime::now().as_nanos()` as a seed:
- Timestamps are predictable (can be guessed within milliseconds)
- Low entropy, especially in lower bytes
- RFC 6455 Section 5.3 requires masking keys from "a strong source of entropy"

### Solution
Added `getrandom` crate which uses OS-level randomness (`/dev/urandom` on Linux):

```rust
pub fn generate_sec_key() -> String {
    let mut key = [0u8; 16];
    getrandom::fill(&mut key).expect("failed to get random bytes");
    BASE64.encode(key)
}

fn generate_mask_key() -> [u8; 4] {
    let mut key = [0u8; 4];
    getrandom::fill(&mut key).expect("failed to get random bytes");
    key
}
```

### Why Masking Key Randomness Matters
The masking key prevents cache poisoning attacks where a malicious client could craft frames that, when XOR'd with a predictable mask, produce bytes that confuse intermediary proxies. Unpredictable masks ensure proxies can't be tricked into misinterpreting WebSocket traffic as HTTP.
