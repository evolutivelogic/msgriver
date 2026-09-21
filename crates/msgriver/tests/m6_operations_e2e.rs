//! M6 operations proof: local operators can inspect delivery state and safely
//! requeue only a definite provider rejection.

use msgriver_client::{SubmitRequest, submit};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("msgriver-m6-e2e-{}-{sequence}", std::process::id()));
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
fn operator_can_inspect_and_retry_only_a_definite_failure() {
    let endpoint = TcpListener::bind("127.0.0.1:0").expect("bind fake ntfy");
    endpoint
        .set_nonblocking(true)
        .expect("set fake ntfy nonblocking");
    let port = endpoint.local_addr().expect("fake ntfy address").port();
    let endpoint_thread = thread::spawn(move || {
        reply(
            &endpoint,
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 26\r\nConnection: close\r\n\r\n{\"detail\":\"secret-reject\"}",
        );
        reply(
            &endpoint,
            b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\n{\"id\":\"m6-ok\"}",
        );
    });

    let root = TestDirectory::create();
    let state_dir = root.0.join("state");
    let socket = state_dir.join("msgriver.sock");
    let mut service = ChildGuard(start_service(&state_dir, &socket, port));
    wait_for_socket(&socket, &mut service.0);
    let accepted = submit(
        &socket,
        SubmitRequest {
            idempotency_key: "m6a",
            body: "inspect and recover",
            title: None,
        },
    )
    .expect("durably accept message");

    let failed = wait_for_status(&socket, &accepted.message_id, "failed");
    assert_message_status(
        &failed,
        &accepted.message_id,
        "failed",
        1,
        "retry_after_configuration_check",
    );
    assert_redacted(&failed, port);

    let summary = run_cli(&["status", "--socket", socket.to_str().expect("socket path")]);
    assert_eq!(summary.status.code(), Some(0));
    let summary = String::from_utf8(summary.stdout).expect("status output");
    assert_summary(&summary, 0, 0, 0, 0, 1, 0);
    assert_redacted(&summary, port);

    let retry = run_cli(&[
        "message",
        "retry",
        "--socket",
        socket.to_str().expect("socket path"),
        "--message-id",
        &accepted.message_id,
    ]);
    assert_eq!(retry.status.code(), Some(0));
    let retry = String::from_utf8(retry.stdout).expect("retry output");
    assert_retry(&retry, &accepted.message_id, true);
    assert_redacted(&retry, port);

    let delivered = wait_for_status(&socket, &accepted.message_id, "provider_accepted");
    assert_message_status(
        &delivered,
        &accepted.message_id,
        "provider_accepted",
        2,
        "none",
    );
    assert_redacted(&delivered, port);
    let summary = run_cli(&["status", "--socket", socket.to_str().expect("socket path")]);
    assert_eq!(summary.status.code(), Some(0));
    let summary = String::from_utf8(summary.stdout).expect("status output");
    assert_summary(&summary, 0, 0, 0, 1, 0, 0);
    assert_redacted(&summary, port);
    let refused = run_cli(&[
        "message",
        "retry",
        "--socket",
        socket.to_str().expect("socket path"),
        "--message-id",
        &accepted.message_id,
    ]);
    assert_ne!(refused.status.code(), Some(0));
    let refused = String::from_utf8(refused.stdout).expect("refused retry output");
    assert_retry(&refused, &accepted.message_id, false);
    endpoint_thread.join().expect("join fake ntfy");
}

#[test]
fn operator_cannot_requeue_an_ambiguous_delivery() {
    let endpoint = TcpListener::bind("127.0.0.1:0").expect("bind fake ntfy");
    endpoint
        .set_nonblocking(true)
        .expect("set fake ntfy nonblocking");
    let observer = endpoint.try_clone().expect("clone fake ntfy listener");
    let port = endpoint.local_addr().expect("fake ntfy address").port();
    let endpoint_thread = thread::spawn(move || {
        let mut stream = accept_with_deadline(&endpoint);
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).expect("read outbound request");
    });

    let root = TestDirectory::create();
    let state_dir = root.0.join("state");
    let socket = state_dir.join("msgriver.sock");
    let mut service = ChildGuard(start_service(&state_dir, &socket, port));
    wait_for_socket(&socket, &mut service.0);
    let accepted = submit(
        &socket,
        SubmitRequest {
            idempotency_key: "m6b",
            body: "ambiguous must not retry",
            title: None,
        },
    )
    .expect("durably accept message");
    endpoint_thread.join().expect("join ambiguous fake ntfy");

    let ambiguous = wait_for_status(&socket, &accepted.message_id, "ambiguous");
    assert_message_status(
        &ambiguous,
        &accepted.message_id,
        "ambiguous",
        1,
        "manual_resolution_required",
    );
    assert_redacted(&ambiguous, port);
    let refused = run_cli(&[
        "message",
        "retry",
        "--socket",
        socket.to_str().expect("socket path"),
        "--message-id",
        &accepted.message_id,
    ]);
    assert_ne!(refused.status.code(), Some(0));
    let refused = String::from_utf8(refused.stdout).expect("refused retry output");
    assert_retry(&refused, &accepted.message_id, false);
    assert_no_additional_delivery(&observer);
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
            "m6-e2e",
        ])
        .spawn()
        .expect("start service")
}

fn run_cli(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_msgriver"))
        .args(arguments)
        .output()
        .expect("run local operator command")
}

fn wait_for_status(socket: &Path, message_id: &str, expected_state: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let output = run_cli(&[
            "message",
            "status",
            "--socket",
            socket.to_str().expect("socket path"),
            "--message-id",
            message_id,
        ]);
        if output.status.success() {
            let output = String::from_utf8(output.stdout).expect("message status output");
            if output.contains(&format!("\"state\":\"{expected_state}\"")) {
                return output;
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("message did not reach expected state {expected_state}");
}

fn assert_message_status(
    output: &str,
    message_id: &str,
    state: &str,
    attempts: u64,
    recovery: &str,
) {
    let value: serde_json::Value = serde_json::from_str(output).expect("message status JSON");
    let object = value.as_object().expect("message status object");
    assert_eq!(object.len(), 4);
    assert_eq!(
        object.get("message_id").and_then(serde_json::Value::as_str),
        Some(message_id)
    );
    assert_eq!(
        object.get("state").and_then(serde_json::Value::as_str),
        Some(state)
    );
    assert_eq!(
        object.get("attempts").and_then(serde_json::Value::as_u64),
        Some(attempts)
    );
    assert_eq!(
        object.get("recovery").and_then(serde_json::Value::as_str),
        Some(recovery)
    );
}

fn assert_summary(
    output: &str,
    queued: u64,
    retry_scheduled: u64,
    sending: u64,
    provider_accepted: u64,
    failed: u64,
    ambiguous: u64,
) {
    let value: serde_json::Value = serde_json::from_str(output).expect("status JSON");
    let object = value.as_object().expect("status object");
    assert_eq!(object.len(), 1);
    let counts = object
        .get("counts")
        .and_then(serde_json::Value::as_object)
        .expect("status counts");
    assert_eq!(counts.len(), 6);
    for (state, expected) in [
        ("queued", queued),
        ("retry_scheduled", retry_scheduled),
        ("sending", sending),
        ("provider_accepted", provider_accepted),
        ("failed", failed),
        ("ambiguous", ambiguous),
    ] {
        assert_eq!(
            counts.get(state).and_then(serde_json::Value::as_u64),
            Some(expected)
        );
    }
}

fn assert_retry(output: &str, message_id: &str, requeued: bool) {
    let value: serde_json::Value = serde_json::from_str(output).expect("retry JSON");
    let object = value.as_object().expect("retry object");
    assert_eq!(object.len(), 2);
    assert_eq!(
        object.get("message_id").and_then(serde_json::Value::as_str),
        Some(message_id)
    );
    assert_eq!(
        object.get("requeued").and_then(serde_json::Value::as_bool),
        Some(requeued)
    );
}

fn assert_redacted(output: &str, port: u16) {
    for forbidden in [
        "inspect and recover",
        "ambiguous must not retry",
        "m6-e2e",
        "m6-ok",
        "secret-reject",
        "127.0.0.1",
        &port.to_string(),
    ] {
        assert!(
            !output.contains(forbidden),
            "operator output leaked {forbidden}"
        );
    }
}

fn assert_no_additional_delivery(listener: &TcpListener) {
    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        match listener.accept() {
            Ok(_) => panic!("ambiguous delivery was retried"),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("fake ntfy listener failed: {error}"),
        }
    }
}

fn reply(listener: &TcpListener, response: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request).expect("read ntfy request");
                stream.write_all(response).expect("write ntfy response");
                return;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("fake ntfy accept failed: {error}"),
        }
    }
    panic!("fake ntfy did not receive delivery");
}

fn accept_with_deadline(listener: &TcpListener) -> std::net::TcpStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("fake ntfy accept failed: {error}"),
        }
    }
    panic!("fake ntfy did not receive delivery");
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
