use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::io::{Read, Write, ErrorKind};
use std::os::unix::io::{AsRawFd, FromRawFd};

use tokio_uring::net::TcpStream;

use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls::pki_types::ServerName;

struct HttpsClient {
    tls_config: Arc<ClientConfig>,
}

impl HttpsClient {
    fn new() -> Self {
        let mut root_store = rustls::RootCertStore::empty();

        for cert in rustls_native_certs::load_native_certs()
            .expect("failed to load native certs")
        {
            let _ = root_store.add(cert);
        }

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

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

        // io_uring-based async connect
        let stream = TcpStream::connect(addr).await?;

        // this here is my file descriptor(FD) duplication boundary ----
        // tokio-uring owns the original  FD
        // I'll dup() it so std::net::TcpStream owns its *own* FD
        let raw_fd = stream.as_raw_fd();
        let dup_fd = unsafe { libc::dup(raw_fd) };
        if dup_fd < 0 {
            return Err("dup() failed".into());
        }

        let std_stream = unsafe { std::net::TcpStream::from_raw_fd(dup_fd) };
        std_stream.set_nonblocking(false)?;
        // ---------------------------------

        // rustls requires owned, 'static server name
        let server_name = ServerName::try_from(host.to_owned())?;
        let conn = ClientConnection::new(self.tls_config.clone(), server_name)?;
        let mut tls = StreamOwned::new(conn, std_stream);

        let request = match body {
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
        };

        tls.write_all(request.as_bytes())?;

        let mut response = String::new();

        // this'll handle the common case where servers close without close_notify
        match tls.read_to_string(&mut response) {
            Ok(_) => Ok(response),
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                // server closed connection without close_notify
                // this is common and acceptable when I've received data
                if !response.is_empty() {
                    Ok(response)
                } else {
                    Err(e.into())
                }
            }
            Err(e) => Err(e.into()),
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

    async fn delete(
        &self,
        host: &str,
        path: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        self.https_request("DELETE", host, path, None).await
    }
}

fn split_response(resp: &str) -> (&str, &str) {
    resp.split_once("\r\n\r\n").unwrap_or((resp, ""))
}

fn print_response(label: &str, resp: &str) {
    let (h, b) = split_response(resp);
    println!("--- {label} headers ---\n{h}\n");
    println!(
        "--- {label} body ---\n{}\n",
        &b[..b.len().min(400)]
    );
}

fn main() {
    tokio_uring::start(async {
        println!("=== ktls-uring-demo ===\n");

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
