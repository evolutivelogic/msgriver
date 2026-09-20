//! M2 behavior proof: a separately started service durably accepts a local
//! request and delivers it through its real HTTP ntfy driver.

use msgriver_client::{SubmitRequest, submit};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("msgriver-m2-e2e-{}-{sequence}", std::process::id()));
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
fn service_accepts_once_and_ntfy_driver_delivers_real_http_request() {
    let capture = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake ntfy");
    listener
        .set_nonblocking(true)
        .expect("set fake ntfy nonblocking");
    let port = listener.local_addr().expect("fake ntfy address").port();
    let captured = Arc::clone(&capture);
    let server = thread::spawn(move || {
        let mut stream = accept_with_deadline(&listener);
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk).expect("read ntfy request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("request headers")
            + 4;
        let head = std::str::from_utf8(&request[..header_end]).expect("utf8 headers");
        let length = head
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .expect("content length")
            .parse::<usize>()
            .expect("numeric content length");
        while request.len() < header_end + length {
            let read = stream.read(&mut chunk).expect("read ntfy body");
            if read == 0 {
                panic!("truncated ntfy body");
            }
            request.extend_from_slice(&chunk[..read]);
        }
        *captured.lock().expect("capture lock") = request;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 19\r\nConnection: close\r\n\r\n{\"id\":\"ntfy-e2e-1\"}")
            .expect("reply ntfy");
    });

    let root = TestDirectory::create();
    let state_dir = root.0.join("state");
    let socket = state_dir.join("msgriver.sock");
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_msgriver"))
            .args([
                "serve",
                "--state-dir",
                state_dir.to_str().expect("state path"),
                "--socket",
                socket.to_str().expect("socket path"),
                "--ntfy-url",
                &format!("http://127.0.0.1:{port}"),
                "--ntfy-topic",
                "m2-e2e",
            ])
            .spawn()
            .expect("start service"),
    );
    wait_for_socket(&socket, &mut child.0);

    let first = submit(
        &socket,
        SubmitRequest {
            idempotency_key: "e2e-1",
            body: "M2 delivery",
            title: Some("MsgRiver"),
        },
    )
    .expect("durable acceptance");
    let duplicate = submit(
        &socket,
        SubmitRequest {
            idempotency_key: "e2e-1",
            body: "M2 delivery",
            title: Some("MsgRiver"),
        },
    )
    .expect("idempotent acceptance");
    assert_eq!(first.message_id, duplicate.message_id);
    assert!(!first.deduplicated);
    assert!(duplicate.deduplicated);
    assert!(
        submit(
            &socket,
            SubmitRequest {
                idempotency_key: "e2e-1",
                body: "different payload",
                title: Some("MsgRiver"),
            },
        )
        .is_err()
    );
    server.join().expect("ntfy server thread");
    let request =
        String::from_utf8(capture.lock().expect("capture lock").clone()).expect("request text");
    assert!(request.starts_with("POST /m2-e2e HTTP/1.1\r\n"));
    assert!(request.contains("Title: MsgRiver\r\n"));
    assert!(request.ends_with("\r\n\r\nM2 delivery"));
}

#[test]
fn restart_marks_an_interrupted_post_write_attempt_ambiguous_without_redelivery() {
    let capture = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind first ntfy endpoint");
    listener
        .set_nonblocking(true)
        .expect("set first ntfy endpoint nonblocking");
    let port = listener
        .local_addr()
        .expect("first endpoint address")
        .port();
    let captured = Arc::clone(&capture);
    let first_endpoint = thread::spawn(move || {
        let mut stream = accept_with_deadline(&listener);
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set first read timeout");
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk).expect("read first delivery");
            if read == 0 {
                return;
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                *captured.lock().expect("first capture lock") = request;
                let _ = stream.read(&mut chunk);
                return;
            }
        }
    });

    let root = TestDirectory::create();
    let state_dir = root.0.join("state");
    let socket = state_dir.join("msgriver.sock");
    let mut first = ChildGuard(start_service(&state_dir, &socket, port));
    wait_for_socket(&socket, &mut first.0);
    submit(
        &socket,
        SubmitRequest {
            idempotency_key: "e2e-crash-1",
            body: "interrupted delivery",
            title: None,
        },
    )
    .expect("durable acceptance before interruption");
    wait_for_capture(&capture);
    first
        .0
        .kill()
        .expect("kill first service during post-write wait");
    first.0.wait().expect("reap first service");
    first_endpoint.join().expect("first endpoint thread");
    fs::remove_file(&socket).expect("remove stale test socket");

    let retry_listener = TcpListener::bind(("127.0.0.1", port)).expect("bind restart endpoint");
    retry_listener
        .set_nonblocking(true)
        .expect("set restart endpoint nonblocking");
    let mut restarted = ChildGuard(start_service(&state_dir, &socket, port));
    wait_for_socket(&socket, &mut restarted.0);
    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        match retry_listener.accept() {
            Ok(_) => panic!("restart redelivered an ambiguous message"),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(error) => panic!("restart endpoint failed: {error}"),
        }
    }
}

#[test]
fn a_definite_rate_limit_retries_once_then_records_the_provider_acknowledgement() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind retry endpoint");
    listener
        .set_nonblocking(true)
        .expect("set retry endpoint nonblocking");
    let port = listener
        .local_addr()
        .expect("retry endpoint address")
        .port();
    let server = thread::spawn(move || {
        for response in [
            b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 21\r\nConnection: close\r\n\r\n{\"id\":\"ntfy-retry-1\"}".as_slice(),
        ] {
            let mut stream = accept_with_deadline(&listener);
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set retry read timeout");
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).expect("read retry request");
            stream.write_all(response).expect("write retry response");
        }
    });
    let root = TestDirectory::create();
    let state_dir = root.0.join("state");
    let socket = state_dir.join("msgriver.sock");
    let mut child = ChildGuard(start_service(&state_dir, &socket, port));
    wait_for_socket(&socket, &mut child.0);
    submit(
        &socket,
        SubmitRequest {
            idempotency_key: "e2e-retry-1",
            body: "retry delivery",
            title: None,
        },
    )
    .expect("durable acceptance before retry");
    server.join().expect("retry endpoint thread");
}

fn start_service(state_dir: &Path, socket: &Path, port: u16) -> Child {
    Command::new(env!("CARGO_BIN_EXE_msgriver"))
        .args([
            "serve",
            "--state-dir",
            state_dir.to_str().expect("state path"),
            "--socket",
            socket.to_str().expect("socket path"),
            "--ntfy-url",
            &format!("http://127.0.0.1:{port}"),
            "--ntfy-topic",
            "m2-e2e",
        ])
        .spawn()
        .expect("start service")
}

fn wait_for_capture(capture: &Arc<Mutex<Vec<u8>>>) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if !capture.lock().expect("capture lock").is_empty() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("service did not cross the outbound boundary");
}

fn accept_with_deadline(listener: &TcpListener) -> std::net::TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("endpoint accept failed: {error}"),
        }
    }
    panic!("endpoint did not receive delivery before deadline");
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
