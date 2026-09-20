//! M3 service proof: WhatsApp admission is a closed local command surface.

use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "msgriver-m3-whatsapp-e2e-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create test root");
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn whatsapp_admission_is_strict_and_uses_only_the_closed_local_route() {
    let root = TestDirectory::create();
    let state_dir = root.0.join("state");
    let socket = state_dir.join("msgriver.sock");
    let token_file = root.0.join("whatsapp.token");
    fs::write(&token_file, b"test-token\n").expect("write test token");
    fs::set_permissions(&token_file, fs::Permissions::from_mode(0o600))
        .expect("make test token owner-only");
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_msgriver"))
            .args([
                "serve",
                "--state-dir",
                state_dir.to_str().expect("state path"),
                "--socket",
                socket.to_str().expect("socket path"),
                "--ntfy-url",
                "http://127.0.0.1:1",
                "--ntfy-topic",
                "m2-e2e",
                "--whatsapp-url",
                "https://127.0.0.1:1/v1",
                "--whatsapp-phone-id",
                "123456789",
                "--whatsapp-token-file",
                token_file.to_str().expect("token path"),
                "--whatsapp-template",
                "delivery_notice",
                "--whatsapp-locale",
                "en_US",
                "--whatsapp-parameter-count",
                "1",
            ])
            .spawn()
            .expect("start service"),
    );
    wait_for_socket(&socket, &mut child.0);

    let accepted = post(
        &socket,
        r#"{"idempotency_key":"whatsapp-1","to":"+15551234567","template":"delivery_notice","locale":"en_US","params":["accepted"]}"#,
    );
    assert!(accepted.starts_with("HTTP/1.1 202 Accepted\r\n"));
    assert!(post(
        &socket,
        r#"{"idempotency_key":"whatsapp-2","to":"+15551234567","template":"delivery_notice","locale":"en_US","params":["accepted"],"extra":true}"#,
    )
    .starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(post(
        &socket,
        r#"{"idempotency_key":"whatsapp-3","to":"+15551234567","template":"delivery_notice","locale":"en_US","params":"accepted"}"#,
    )
    .starts_with("HTTP/1.1 400 Bad Request\r\n"));
}

#[test]
fn accepted_whatsapp_command_is_persisted_then_delivered_through_the_tls_driver() {
    let root = TestDirectory::create();
    let (certificate_der, key_der, ca_der) = create_loopback_certificate(&root.0);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind TLS provider");
    listener
        .set_nonblocking(true)
        .expect("set TLS provider nonblocking");
    let port = listener.local_addr().expect("TLS provider address").port();
    let request = thread::spawn(move || {
        let (tcp, _) = accept_with_deadline(&listener);
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(certificate_der)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
            )
            .expect("configure TLS provider");
        let connection = ServerConnection::new(std::sync::Arc::new(config)).expect("TLS server");
        let mut stream = StreamOwned::new(connection, tcp);
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let count = stream.read(&mut chunk).expect("read TLS request");
            if count == 0 {
                panic!("truncated TLS request");
            }
            request.extend_from_slice(&chunk[..count]);
            let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
            else {
                continue;
            };
            let head = std::str::from_utf8(&request[..header_end]).expect("request headers");
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .expect("content length")
                .parse::<usize>()
                .expect("numeric content length");
            if request.len() >= header_end + 4 + length {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 33\r\nConnection: close\r\n\r\n{\"messages\":[{\"id\":\"wamid-e2e-1\"}]}")
                    .expect("write Cloud acknowledgement");
                return request;
            }
        }
    });

    let state_dir = root.0.join("state");
    let socket = state_dir.join("msgriver.sock");
    let token_file = root.0.join("whatsapp.token");
    fs::write(&token_file, b"test-token\n").expect("write test token");
    fs::set_permissions(&token_file, fs::Permissions::from_mode(0o600))
        .expect("make test token owner-only");
    let certificate_file = root.0.join("loopback-ca.der");
    fs::write(&certificate_file, ca_der).expect("write test CA");
    fs::set_permissions(&certificate_file, fs::Permissions::from_mode(0o600))
        .expect("make test CA owner-only");
    let whatsapp_url = format!("https://127.0.0.1:{port}/v1");
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_msgriver"))
            .args([
                "serve",
                "--state-dir",
                state_dir.to_str().expect("state path"),
                "--socket",
                socket.to_str().expect("socket path"),
                "--ntfy-url",
                "http://127.0.0.1:1",
                "--ntfy-topic",
                "m2-e2e",
                "--whatsapp-url",
                &whatsapp_url,
                "--whatsapp-phone-id",
                "123456789",
                "--whatsapp-token-file",
                token_file.to_str().expect("token path"),
                "--whatsapp-ca-file",
                certificate_file.to_str().expect("certificate path"),
                "--whatsapp-template",
                "delivery_notice",
                "--whatsapp-locale",
                "en_US",
                "--whatsapp-parameter-count",
                "1",
            ])
            .spawn()
            .expect("start service"),
    );
    wait_for_socket(&socket, &mut child.0);
    assert!(post(
        &socket,
        r#"{"idempotency_key":"whatsapp-delivery-1","to":"+15551234567","template":"delivery_notice","locale":"en_US","params":["accepted"]}"#,
    )
    .starts_with("HTTP/1.1 202 Accepted\r\n"));
    let request =
        String::from_utf8(request.join().expect("TLS provider thread")).expect("request text");
    assert!(request.starts_with("POST /v1/123456789/messages HTTP/1.1\r\n"));
    assert!(request.ends_with("\r\n\r\n{\"messaging_product\":\"whatsapp\",\"template\":{\"components\":[{\"parameters\":[{\"text\":\"accepted\",\"type\":\"text\"}],\"type\":\"body\"}],\"language\":{\"code\":\"en_US\"},\"name\":\"delivery_notice\"},\"to\":\"+15551234567\",\"type\":\"template\"}"));
}

fn create_loopback_certificate(root: &Path) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let ca_key = root.join("loopback-ca-key.pem");
    let ca_certificate = root.join("loopback-ca-cert.pem");
    let server_key = root.join("loopback-server-key.pem");
    let server_request = root.join("loopback-server.csr");
    let server_certificate = root.join("loopback-server-cert.pem");
    let extensions = root.join("loopback-server.ext");
    let server_certificate_der = root.join("loopback-server-cert.der");
    let ca_certificate_der = root.join("loopback-ca-cert.der");
    let server_key_der = root.join("loopback-server-key.der");
    assert!(
        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                ca_key.to_str().expect("CA key path"),
                "-out",
                ca_certificate.to_str().expect("CA certificate path"),
                "-days",
                "1",
                "-subj",
                "/CN=msgriver-test-ca",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("launch openssl")
            .success()
    );
    assert!(
        Command::new("openssl")
            .args([
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                server_key.to_str().expect("server key path"),
                "-out",
                server_request.to_str().expect("server request path"),
                "-subj",
                "/CN=127.0.0.1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("launch openssl")
            .success()
    );
    fs::write(
        &extensions,
        b"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n",
    )
    .expect("write server certificate extensions");
    assert!(
        Command::new("openssl")
            .args([
                "x509",
                "-req",
                "-in",
                server_request.to_str().expect("server request path"),
                "-CA",
                ca_certificate.to_str().expect("CA certificate path"),
                "-CAkey",
                ca_key.to_str().expect("CA key path"),
                "-CAcreateserial",
                "-out",
                server_certificate
                    .to_str()
                    .expect("server certificate path"),
                "-days",
                "1",
                "-extfile",
                extensions.to_str().expect("extensions path"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("launch openssl")
            .success()
    );
    for (input, output) in [
        (&server_certificate, &server_certificate_der),
        (&ca_certificate, &ca_certificate_der),
    ] {
        assert!(
            Command::new("openssl")
                .args([
                    "x509",
                    "-in",
                    input.to_str().expect("certificate path"),
                    "-outform",
                    "DER",
                    "-out",
                    output.to_str().expect("DER certificate path"),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("launch openssl")
                .success()
        );
    }
    assert!(
        Command::new("openssl")
            .args([
                "pkcs8",
                "-topk8",
                "-nocrypt",
                "-in",
                server_key.to_str().expect("server key path"),
                "-outform",
                "DER",
                "-out",
                server_key_der.to_str().expect("DER key path"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("launch openssl")
            .success()
    );
    (
        fs::read(&server_certificate_der).expect("read server DER certificate"),
        fs::read(&server_key_der).expect("read server DER key"),
        fs::read(&ca_certificate_der).expect("read CA DER certificate"),
    )
}

fn post(socket: &Path, body: &str) -> String {
    let mut stream = UnixStream::connect(socket).expect("connect local service");
    let request = format!(
        "POST /v1/whatsapp/messages HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write request");
    stream.flush().expect("flush request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    response
}

fn wait_for_socket(socket: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if socket.exists() {
            return;
        }
        if child.try_wait().expect("poll service").is_some() {
            panic!("service exited before socket bind");
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("service did not bind local socket");
}

fn accept_with_deadline(
    listener: &std::net::TcpListener,
) -> (std::net::TcpStream, std::net::SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match listener.accept() {
            Ok(stream) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(error) => panic!("TLS provider accept failed: {error}"),
        }
    }
    panic!("TLS provider did not receive delivery");
}
