# Plan: Add WebSocket Client on kTLS + io_uring

## Summary
Add a WebSocket Secure (WSS) client using manual WebSocket implementation on top of kTLS + io_uring, following the same architecture as the existing HTTP client.

## Architecture
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

## Files to Modify

1. **src/main.rs** - Add `WssClient` struct and WebSocket demo
2. **src/websocket.rs** (new) - WebSocket framing implementation

## Implementation Steps

### 1. Create `src/websocket.rs` - WebSocket Framing Module
Implement minimal WebSocket protocol (RFC 6455):

- **Handshake**: Generate Sec-WebSocket-Key, build HTTP Upgrade request, validate response
- **Frame encoding**: Opcode, masking (required for client), payload length encoding
- **Frame decoding**: Parse incoming frames, handle text/binary/close/ping/pong
- **Helper functions**: `encode_text_frame()`, `decode_frame()`, `build_handshake_request()`

### 2. Add `WssClient` struct to `src/main.rs`
Follow the same pattern as `HttpsClient`:

```rust
struct WssClient {
    tls_config: Arc<ClientConfig>,
}

impl WssClient {
    fn new() -> Self { /* same TLS config as HttpsClient */ }

    async fn connect(&self, host: &str, path: &str)
        -> Result<TcpStream, ...>
    {
        // 1. TCP connect via io_uring
        // 2. TLS handshake via rustls unbuffered
        // 3. Configure kTLS
        // 4. Send WebSocket upgrade request
        // 5. Read and validate upgrade response
        // 6. Return stream for send/receive
    }

    async fn send_text(stream: &TcpStream, msg: &str) { /* encode & send frame */ }
    async fn receive(stream: &TcpStream) -> Message { /* read & decode frame */ }
    async fn close(stream: &TcpStream) { /* send close frame */ }
}
```

### 3. Add WebSocket Demo to `main()`
```rust
println!("\n=== WebSocket Demo ===\n");
let ws_client = WssClient::new();
let stream = ws_client.connect("echo.websocket.org", "/").await?;
WssClient::send_text(&stream, "Hello from ktls-uring-demo!").await?;
let msg = WssClient::receive(&stream).await?;
println!("Received: {}", msg);
WssClient::close(&stream).await?;
```

## WebSocket Protocol Details

### Handshake (HTTP Upgrade)
```
GET / HTTP/1.1
Host: echo.websocket.org
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <base64 random 16 bytes>
Sec-WebSocket-Version: 13
```

### Frame Format
```
 0 1 2 3 4 5 6 7   0 1 2 3 4 5 6 7
+-+-+-+-+-------+ +-+-------------+
|F|R|R|R| opcode| |M| Payload len |
|I|S|S|S|  (4)  | |A|     (7)     |
|N|V|V|V|       | |S|             |
| |1|2|3|       | |K|             |
+-+-+-+-+-------+ +-+-------------+
```
- Opcodes: 0x1 (text), 0x2 (binary), 0x8 (close), 0x9 (ping), 0xA (pong)
- Client frames MUST be masked (4-byte XOR key)

## Dependencies
- `base64` crate for Sec-WebSocket-Key encoding
- `rand` or `getrandom` for masking key generation

Add to Cargo.toml:
```toml
base64 = "0.22"
```

## Verification

Run `cargo run` and verify:
1. Existing HTTP requests still work with kTLS
2. WebSocket connects with "Using kTLS" message
3. Echo message received correctly
4. Clean connection close

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
