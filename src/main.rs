use std::io::{ErrorKind, Read, Write};
use std::net::ToSocketAddrs;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::Arc;

use tokio_uring::net::TcpStream;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

mod handshake;
mod ktls;
mod websocket;

struct HttpsClient {
    tls_config: Arc<ClientConfig>,
}

impl HttpsClient {
    fn new() -> Self {
        let mut root_store = rustls::RootCertStore::empty();

        for cert in rustls_native_certs::load_native_certs().expect("failed to load native certs") {
            let _ = root_store.add(cert);
        }

        let mut config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Enable secret extraction for kTLS
        config.enable_secret_extraction = true;

        Self {
            tls_config: Arc::new(config),
        }
    }

    async fn https_request(
        &self,
        method: &str,
        host: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let addr = format!("{host}:443")
            .to_socket_addrs()?
            .next()
            .ok_or("DNS resolution failed")?;

        println!("Connecting to {addr} via io_uring");

        // io_uring-based async TCP connect
        let stream = TcpStream::connect(addr).await?;
        let fd = stream.as_raw_fd();

        // Build HTTP request
        let request = Self::build_request(method, host, path, body);

        // Try kTLS path first
        let server_name = ServerName::try_from(host.to_owned())?;

        match handshake::perform_handshake(fd, self.tls_config.clone(), server_name.clone()) {
            Ok(result) => {
                let version = ktls::tls_version(result.version);

                match ktls::configure_ktls(fd, result.tx, result.rx, version) {
                    Ok(()) => {
                        println!("Using kTLS (kernel TLS) + io_uring");
                        self.ktls_request(stream, &request).await
                    }
                    Err(e) => {
                        eprintln!("kTLS setup failed ({e}), using userspace TLS fallback");
                        drop(stream);
                        self.fallback_new_connection(host, &request).await
                    }
                }
            }
            Err(e) => {
                eprintln!("kTLS handshake failed ({e}), using userspace TLS fallback");
                drop(stream);
                self.fallback_new_connection(host, &request).await
            }
        }
    }

    /// kTLS path: kernel handles encryption, use io_uring for I/O
    async fn ktls_request(
        &self,
        stream: TcpStream,
        request: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Send request via io_uring (kernel encrypts)
        let (result, _) = stream.write_all(request.as_bytes().to_vec()).await;
        result?;

        // Read response via io_uring (kernel decrypts)
        let mut response = Vec::new();
        loop {
            let buf = vec![0u8; 8192];
            let (result, buf) = stream.read(buf).await;
            match result {
                Ok(0) => break, // EOF
                Ok(n) => response.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                    if !response.is_empty() {
                        break;
                    }
                    return Err(e.into());
                }
                Err(e) => {
                    // kTLS returns EIO when connection closes without close_notify
                    // This is common with "Connection: close" - treat as EOF if we have data
                    if e.raw_os_error() == Some(5) && !response.is_empty() {
                        break;
                    }
                    return Err(e.into());
                }
            }
        }

        String::from_utf8(response).map_err(|e| e.into())
    }

    /// Fallback path: create new connection and use userspace TLS via rustls StreamOwned
    async fn fallback_new_connection(
        &self,
        host: &str,
        request: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let addr = format!("{host}:443")
            .to_socket_addrs()?
            .next()
            .ok_or("DNS resolution failed")?;

        println!("Reconnecting to {addr} for userspace TLS");

        // Create new TCP connection
        let stream = TcpStream::connect(addr).await?;
        let fd = stream.as_raw_fd();

        // Duplicate FD for rustls (it expects to own the stream)
        let dup_fd = unsafe { libc::dup(fd) };
        if dup_fd < 0 {
            return Err("dup() failed".into());
        }

        let std_stream = unsafe { std::net::TcpStream::from_raw_fd(dup_fd) };
        std_stream.set_nonblocking(false)?;

        let server_name = ServerName::try_from(host.to_owned())?;
        let conn = ClientConnection::new(self.tls_config.clone(), server_name)?;
        let mut tls = StreamOwned::new(conn, std_stream);

        tls.write_all(request.as_bytes())?;

        let mut response = String::new();
        match tls.read_to_string(&mut response) {
            Ok(_) => Ok(response),
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                if !response.is_empty() {
                    Ok(response)
                } else {
                    Err(e.into())
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    fn build_request(method: &str, host: &str, path: &str, body: Option<&str>) -> String {
        match body {
            Some(body) => format!(
                "{method} {path} HTTP/1.1\r\n\
                 Host: {host}\r\n\
                 User-Agent: ktls-uring-demo/0.1\r\n\
                 Content-Length: {}\r\n\
                 Content-Type: application/json\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {body}",
                body.len()
            ),
            None => format!(
                "{method} {path} HTTP/1.1\r\n\
                 Host: {host}\r\n\
                 User-Agent: ktls-uring-demo/0.1\r\n\
                 Connection: close\r\n\
                 \r\n"
            ),
        }
    }

    async fn get(&self, host: &str, path: &str) -> Result<String, Box<dyn std::error::Error>> {
        self.https_request("GET", host, path, None).await
    }

    async fn post(
        &self,
        host: &str,
        path: &str,
        body: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        self.https_request("POST", host, path, Some(body)).await
    }

    async fn put(
        &self,
        host: &str,
        path: &str,
        body: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        self.https_request("PUT", host, path, Some(body)).await
    }

    async fn patch(
        &self,
        host: &str,
        path: &str,
        body: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        self.https_request("PATCH", host, path, Some(body)).await
    }

    async fn delete(&self, host: &str, path: &str) -> Result<String, Box<dyn std::error::Error>> {
        self.https_request("DELETE", host, path, None).await
    }
}

struct WssClient {
    tls_config: Arc<ClientConfig>,
}

impl WssClient {
    fn new() -> Self {
        let mut root_store = rustls::RootCertStore::empty();

        for cert in rustls_native_certs::load_native_certs().expect("failed to load native certs") {
            let _ = root_store.add(cert);
        }

        let mut config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        config.enable_secret_extraction = true;

        Self {
            tls_config: Arc::new(config),
        }
    }

    async fn connect(
        &self,
        host: &str,
        path: &str,
    ) -> Result<TcpStream, Box<dyn std::error::Error>> {
        let addr = format!("{host}:443")
            .to_socket_addrs()?
            .next()
            .ok_or("DNS resolution failed")?;

        println!("Connecting to {addr} via io_uring");

        // io_uring-based async TCP connect
        let stream = TcpStream::connect(addr).await?;
        let fd = stream.as_raw_fd();

        // TLS handshake via rustls unbuffered API
        let server_name = ServerName::try_from(host.to_owned())?;

        let result = handshake::perform_handshake(fd, self.tls_config.clone(), server_name)?;
        let version = ktls::tls_version(result.version);

        // Configure kTLS
        ktls::configure_ktls(fd, result.tx, result.rx, version)?;
        println!("Using kTLS (kernel TLS) + io_uring");

        // Perform WebSocket handshake
        let sec_key = websocket::generate_sec_key();
        let handshake_request = websocket::build_handshake_request(host, path, &sec_key);

        // Send WebSocket upgrade request
        let (result, _) = stream.write_all(handshake_request.as_bytes().to_vec()).await;
        result?;

        // Read and validate upgrade response
        let mut response = Vec::new();
        loop {
            let buf = vec![0u8; 4096];
            let (result, buf) = stream.read(buf).await;
            match result {
                Ok(0) => return Err("Connection closed during handshake".into()),
                Ok(n) => {
                    response.extend_from_slice(&buf[..n]);
                    // Check if we have complete HTTP response
                    if response.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }

        let response_str = String::from_utf8_lossy(&response);
        websocket::validate_handshake_response(&response_str, &sec_key)?;
        println!("WebSocket handshake complete");

        Ok(stream)
    }

    async fn send_text(
        stream: &TcpStream,
        msg: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let frame = websocket::encode_text_frame(msg);
        let (result, _) = stream.write_all(frame).await;
        result?;
        Ok(())
    }

    async fn receive(stream: &TcpStream) -> Result<websocket::Message, Box<dyn std::error::Error>> {
        let mut buffer = Vec::new();

        loop {
            // Try to decode a frame from what we have
            if let Some((msg, _consumed)) = websocket::decode_frame(&buffer) {
                return Ok(msg);
            }

            // Need more data
            let buf = vec![0u8; 4096];
            let (result, buf) = stream.read(buf).await;
            match result {
                Ok(0) => return Err("Connection closed".into()),
                Ok(n) => buffer.extend_from_slice(&buf[..n]),
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn close(stream: &TcpStream) -> Result<(), Box<dyn std::error::Error>> {
        let frame = websocket::encode_close_frame(Some(1000)); // 1000 = normal closure
        let (result, _) = stream.write_all(frame).await;
        result?;
        Ok(())
    }
}

fn split_response(resp: &str) -> (&str, &str) {
    resp.split_once("\r\n\r\n").unwrap_or((resp, ""))
}

fn print_response(label: &str, resp: &str) {
    let (h, b) = split_response(resp);
    println!("--- {label} headers ---\n{h}\n");
    println!("--- {label} body ---\n{}\n", &b[..b.len().min(400)]);
}

fn main() {
    tokio_uring::start(async {
        println!("=== ktls-uring-demo (with kTLS support) ===\n");

        let client = HttpsClient::new();

        let r = client.get("httpbin.org", "/get").await.unwrap();
        print_response("GET", &r);

        let r = client
            .post("httpbin.org", "/post", r#"{"op":"create"}"#)
            .await
            .unwrap();
        print_response("POST", &r);

        let r = client
            .put("httpbin.org", "/put", r#"{"op":"replace"}"#)
            .await
            .unwrap();
        print_response("PUT", &r);

        let r = client
            .patch("httpbin.org", "/patch", r#"{"op":"modify"}"#)
            .await
            .unwrap();
        print_response("PATCH", &r);

        let r = client
            .delete("httpbin.org", "/delete")
            .await
            .unwrap();
        print_response("DELETE", &r);

        // WebSocket demo
        println!("\n=== WebSocket Demo ===\n");

        let ws_client = WssClient::new();
        match ws_client.connect("ws.postman-echo.com", "/raw").await {
            Ok(stream) => {
                let msg = "Hello from ktls-uring-demo!";
                println!("Sending: {msg}");

                if let Err(e) = WssClient::send_text(&stream, msg).await {
                    eprintln!("Failed to send: {e}");
                } else {
                    match WssClient::receive(&stream).await {
                        Ok(websocket::Message::Text(text)) => {
                            println!("Received: {text}");
                        }
                        Ok(websocket::Message::Binary(data)) => {
                            println!("Received binary: {} bytes", data.len());
                        }
                        Ok(websocket::Message::Close(info)) => {
                            if let Some((code, reason)) = info {
                                println!("Received close: {code} {reason}");
                            } else {
                                println!("Received close");
                            }
                        }
                        Ok(websocket::Message::Ping(data)) => {
                            println!("Received ping: {} bytes", data.len());
                        }
                        Ok(websocket::Message::Pong(data)) => {
                            println!("Received pong: {} bytes", data.len());
                        }
                        Err(e) => {
                            eprintln!("Failed to receive: {e}");
                        }
                    }
                }

                if let Err(e) = WssClient::close(&stream).await {
                    eprintln!("Failed to close: {e}");
                } else {
                    println!("Connection closed");
                }
            }
            Err(e) => {
                eprintln!("WebSocket connection failed: {e}");
            }
        }

        println!("\n=== done ===");
    });
}
