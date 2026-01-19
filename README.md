# ktls-uring-demo

A demo HTTPS client showcasing kernel TLS (kTLS) integration with io_uring for
true asynchronous encrypted networking in Rust.

## Architecture

```
TCP connect (io_uring) → TLS handshake (rustls) → kTLS setup → io_uring read/write
```

**How it works:**

1. **TCP Connection**: Uses tokio-uring for async TCP connect via io_uring
2. **TLS Handshake**: Uses rustls unbuffered API to perform the handshake
3. **Secret Extraction**: Extracts TLS session keys from rustls
4. **kTLS Configuration**: Configures the Linux kernel to handle encryption via `setsockopt(SOL_TLS)`
5. **Encrypted I/O**: After kTLS setup, io_uring reads/writes plaintext while the kernel encrypts/decrypts

This approach offloads TLS encryption to the kernel, allowing io_uring to manage
the entire data transfer pipeline without blocking userspace crypto operations.

### Fallback Mode

If kTLS configuration fails (unsupported cipher, kernel issue), the client
automatically falls back to userspace TLS via rustls with the original
file descriptor duplication approach.

## HTTP Methods

Supports: GET, POST, PUT, PATCH, DELETE

## Requirements

- Linux kernel 4.13+ with kTLS support (kernel 6.x recommended)
- TLS ULP must be available (`/proc/sys/net/ipv4/tcp_available_ulp` should contain "tls")

## Usage

```bash
cargo run
```

Example output:
```
=== ktls-uring-demo (with kTLS support) ===

Connecting to 98.88.114.252:443 via io_uring
Using kTLS (kernel TLS) + io_uring
--- GET headers ---
HTTP/1.1 200 OK
...
```

## Supported Cipher Suites

kTLS supports: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305

## Known Behaviors

The client gracefully handles servers that close connections without sending
TLS `close_notify` alerts. This is common with `Connection: close` and is
intentionally tolerated.

## Resources

* [Linux kTLS Documentation](https://www.kernel.org/doc/html/latest/networking/tls.html)
* [tokio-uring Documentation](https://docs.rs/tokio-uring/)
* [rustls Documentation](https://docs.rs/rustls/)
* [io_uring Introduction](https://kernel.dk/io_uring.pdf)
* [rustls Manual – Unexpected EOF Handling](https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof)

**Use a Linux environment to run the project; if on Windows use WSL**
