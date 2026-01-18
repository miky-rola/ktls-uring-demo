# ktls-uring-demo

A demo HTTPS client exploring the integration boundaries between
io_uring-based networking (via tokio-uring) and userspace TLS (rustls) in rust

The project uses io_uring for asynchronous TCP connection setup and rustls
for portable TLS encryption. HTTP methods supported include GET, POST, PUT,
PATCH, and DELETE

## Architecture Notes

- TLS is handled in userspace thru rustls for portability
- Because rustls operates on blocking Read/Write streams, encrypted I/O
  does not fully leverage io_uring
- File descriptor duplication (via `libc::dup()`) bridges tokio-uring's
  ownership model with rustls's synchronous I/O requirement
- True zero-copy, zero-syscall HTTPS requires kernel TLS (kTLS) and a
  different architecture

## Known Behaviors

The client gracefully handles servers that close connections without sending
TLS `close_notify` alerts (commonly observed with `Connection: close`)
This behavior is technically a protocol violation under TLS 1.2, but is
widespread in real-world deployments and intentionally tolerated by most
TLS implementations

## Usage

```bash
cargo run
```

## Resources

* [tokio-uring Documentation](https://docs.rs/tokio-uring/)
* [rustls Documentation](https://docs.rs/rustls/)
* [rustls Manual – Unexpected EOF Handling](https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof)
* [io_uring Introduction](https://kernel.dk/io_uring.pdf)
* [Linux kTLS Documentation](https://www.kernel.org/doc/html/latest/networking/tls.html)


**use a Linux environment to run the project; if on windows use WSL to run the project**
