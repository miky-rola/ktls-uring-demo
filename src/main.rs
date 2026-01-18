use std::io::{ErrorKind, Read, Write};
use std::net::ToSocketAddrs;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::Arc;

use tokio_uring::net::TcpStream;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

mod handshake;
mod ktls;

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

        println!("=== done ===");
    });
}
