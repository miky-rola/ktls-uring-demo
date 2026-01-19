# Plan: Migrate from Userspace TLS (rustls) to Kernel TLS (kTLS)

## Overview

Move TLS encryption/decryption from userspace (rustls `StreamOwned`) to the Linux kernel (kTLS), enabling true io_uring-based async TLS I/O.

**Current flow:**
```
TCP connect (io_uring) → FD duplication hack → rustls StreamOwned (blocking)
```

**Target flow:**
```
TCP connect (io_uring) → TLS handshake (rustls unbuffered) → kTLS setup → io_uring read/write
```

## Files to Modify/Create

| File | Action |
|------|--------|
| `Cargo.toml` | Add `nix` dependency for `setsockopt` |
| `src/main.rs` | Refactor `https_request()` to use kTLS flow |
| `src/ktls.rs` | **New** - kTLS socket configuration via `setsockopt` |
| `src/handshake.rs` | **New** - Unbuffered TLS handshake driver |
| `README.md` | Update architecture notes |

## Implementation Steps

### Step 1: Update Dependencies (`Cargo.toml`)

Add:
```toml
nix = { version = "0.29", features = ["socket"] }
```

Keep `rustls` (needed for handshake) and `libc` (for kTLS constants).

### Step 2: Create `src/ktls.rs` - kTLS Configuration Module

Implement:
1. Constants from `linux/tls.h`: `SOL_TLS`, `TLS_TX`, `TLS_RX`, cipher types
2. `#[repr(C)]` structs matching kernel crypto_info structures:
   - `Tls12CryptoInfoAesGcm128`
   - `Tls12CryptoInfoAesGcm256`
   - `Tls12CryptoInfoChacha20Poly1305`
3. `configure_ktls(fd, secrets, tls_version)` function:
   - Enable TLS ULP: `setsockopt(SOL_TCP, TCP_ULP, "tls")`
   - Configure TX: `setsockopt(SOL_TLS, TLS_TX, crypto_info)`
   - Configure RX: `setsockopt(SOL_TLS, TLS_RX, crypto_info)`

Key detail: Split rustls 12-byte IV into 4-byte salt + 8-byte IV for kTLS.

### Step 3: Create `src/handshake.rs` - Unbuffered Handshake Driver

Use rustls `UnbufferedClientConnection` API to:
1. Drive handshake state machine manually
2. Send/receive handshake data via io_uring (or blocking I/O during handshake)
3. Call `dangerous_extract_secrets()` after handshake completes
4. Return `ExtractedSecrets` for kTLS configuration

### Step 4: Refactor `src/main.rs`

Replace lines 51-107 with new flow:

```rust
// 1. TCP connect via io_uring (unchanged)
let stream = TcpStream::connect(addr).await?;
let fd = stream.as_raw_fd();

// 2. TLS handshake via unbuffered API
let server_name = ServerName::try_from(host.to_owned())?;
let result = handshake::perform_handshake(fd, self.tls_config.clone(), server_name).await?;

// 3. Configure kTLS
ktls::configure_ktls(fd, result.secrets, result.tls_version)?;

// 4. Send/receive via io_uring (kernel handles encryption)
stream.write_all(request.as_bytes().to_vec()).await.0?;
// ... read response via stream.read() ...
```

Remove:
- FD duplication hack (lines 51-62)
- `StreamOwned` wrapper (line 67)
- Blocking `tls.write_all()` / `tls.read_to_string()`

### Step 5: Update `README.md`

Update architecture notes to reflect kTLS usage.

## Technical Notes

### Cipher Suite Handling
kTLS supports: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305. Match `ConnectionTrafficSecrets` variant to appropriate crypto_info struct.

### Sequence Number
Convert to big-endian: `seq_num.to_be_bytes()`

### Fallback to Userspace TLS
If kTLS setup fails (unsupported cipher, kernel issue), fall back to the existing rustls `StreamOwned` approach:

```rust
match ktls::configure_ktls(fd, &secrets, tls_version) {
    Ok(()) => {
        // Use io_uring for encrypted I/O
        stream.write_all(...).await
    }
    Err(e) => {
        eprintln!("kTLS setup failed: {e}, falling back to userspace TLS");
        // Use rustls StreamOwned with FD duplication (current approach)
    }
}
```

This ensures the client works even if the server negotiates a cipher not supported by kTLS.

### TLS Version Detection
Extract from rustls connection: `conn.protocol_version()` → map to `0x0303` (TLS 1.2) or `0x0304` (TLS 1.3).
