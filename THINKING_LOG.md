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
