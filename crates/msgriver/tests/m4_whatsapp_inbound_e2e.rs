//! M4 RED: a signed WhatsApp callback is a closed, durable control surface.
//!
//! The test intentionally fails until the compiled service owns a separate
//! loopback-only webhook listener. It is not a test of the frozen Phase 0
//! reference fixtures: it drives TCP webhook ingress, the real SQLite store,
//! and a loopback ntfy endpoint that observes the fixed effect.

#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use sha2::Sha256;
use std::{
    fs,
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

type HmacSha256 = Hmac<Sha256>;

const APP_SECRET: &[u8] = b"m4-test-app-secret";
const AUTHORIZED_WA_ID: &str = "5511999999999";
const STATUS_ONLY_WA_ID: &str = "5511888888888";
const WABA_ID: &str = "waba-e2e-1";
const PHONE_ID: &str = "123456789";
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "msgriver-m4-whatsapp-e2e-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create test root");
        Self(path)
    }

    fn owner_file(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, contents).expect("write private fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("make private fixture owner-only");
        path
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

struct NtfyCapture {
    port: u16,
    count: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl NtfyCapture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ntfy capture");
        listener
            .set_nonblocking(true)
            .expect("set ntfy capture nonblocking");
        let port = listener.local_addr().expect("ntfy capture address").port();
        let count = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_count = Arc::clone(&count);
        let worker_requests = Arc::clone(&requests);
        let worker_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .expect("set ntfy capture read timeout");
                        let request = read_ntfy_request(&mut stream);
                        stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\n{\"id\":\"m4-e2e-1\"}")
                            .expect("acknowledge ntfy capture");
                        worker_requests
                            .lock()
                            .expect("ntfy capture lock")
                            .push(request);
                        worker_count.fetch_add(1, Ordering::AcqRel);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept ntfy capture: {error}"),
                }
            }
        });
        Self {
            port,
            count,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    fn wait_for_count(&self, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.count.load(Ordering::Acquire) >= expected {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!(
            "expected {expected} ntfy effects, observed {}",
            self.count.load(Ordering::Acquire)
        );
    }

    fn assert_count_stable(&self, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            assert_eq!(self.count.load(Ordering::Acquire), expected);
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn requests(&self) -> Vec<Vec<u8>> {
        self.requests.lock().expect("ntfy capture lock").clone()
    }
}

impl Drop for NtfyCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("join ntfy capture");
        }
    }
}

#[test]
fn signed_authorized_notify_is_durable_and_observed_at_the_fixed_ntfy_driver() {
    let root = TestDirectory::create();
    let ntfy = TcpListener::bind("127.0.0.1:0").expect("bind ntfy observer");
    ntfy.set_nonblocking(true)
        .expect("set ntfy observer nonblocking");
    let ntfy_port = ntfy.local_addr().expect("ntfy address").port();
    let observed = thread::spawn(move || observe_ntfy(ntfy));

    let webhook = TcpListener::bind("127.0.0.1:0").expect("reserve webhook listener");
    let webhook_port = webhook.local_addr().expect("webhook address").port();
    drop(webhook);

    let mut service = start_service(&root, ntfy_port, webhook_port);
    wait_for_webhook(webhook_port, &mut service.0);
    let socket = root.0.join("state/msgriver.sock");
    wait_for_socket(&socket, &mut service.0);
    inbound_control(&socket, "enable");

    let body = callback(AUTHORIZED_WA_ID, "m4-notify-1", "notify");
    let response = post_callback(webhook_port, &body, &signature(&body));
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));

    let request = observed.join().expect("collect ntfy observation");
    assert!(request.starts_with("POST /sol-triado HTTP/1.1\r\n"));
    assert!(request.ends_with("\r\n\r\nWhatsApp notify request accepted"));
}

#[test]
fn signed_authorized_status_returns_only_the_fixed_whatsapp_template() {
    let root = TestDirectory::create();
    let (certificate_der, key_der, ca_der) = create_loopback_certificate(&root.0);
    let provider = TcpListener::bind("127.0.0.1:0").expect("bind TLS WhatsApp provider");
    provider
        .set_nonblocking(true)
        .expect("set TLS WhatsApp provider nonblocking");
    let provider_port = provider
        .local_addr()
        .expect("TLS WhatsApp provider address")
        .port();
    let observed = thread::spawn(move || {
        let (tcp, _) = accept_with_deadline(&provider);
        tcp.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set TLS WhatsApp read timeout");
        tcp.set_write_timeout(Some(Duration::from_secs(2)))
            .expect("set TLS WhatsApp write timeout");
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(certificate_der)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
            )
            .expect("configure TLS WhatsApp provider");
        let connection = ServerConnection::new(Arc::new(config)).expect("TLS WhatsApp server");
        let mut stream = StreamOwned::new(connection, tcp);
        let request = read_tls_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 39\r\nConnection: close\r\n\r\n{\"messages\":[{\"id\":\"wamid-m4-status\"}]}")
            .expect("acknowledge WhatsApp status response");
        stream.conn.send_close_notify();
        stream.flush().expect("flush WhatsApp status response");
        request
    });

    let webhook = TcpListener::bind("127.0.0.1:0").expect("reserve webhook listener");
    let webhook_port = webhook.local_addr().expect("webhook address").port();
    drop(webhook);
    let token = root.owner_file("whatsapp-token", b"m4-whatsapp-token\n");
    let ca_file = root.owner_file("whatsapp-ca", &ca_der);
    let whatsapp_url = format!("https://127.0.0.1:{provider_port}/v1");
    let mut service =
        start_service_with_whatsapp(&root, 1, webhook_port, &whatsapp_url, &token, &ca_file);
    wait_for_webhook(webhook_port, &mut service.0);
    let socket = root.0.join("state/msgriver.sock");
    wait_for_socket(&socket, &mut service.0);
    inbound_control(&socket, "enable");

    let ungranted = callback(AUTHORIZED_WA_ID, "m4-status-denied", "status");
    assert!(
        post_callback(webhook_port, &ungranted, &signature(&ungranted))
            .starts_with("HTTP/1.1 200 OK\r\n")
    );
    let body = callback(STATUS_ONLY_WA_ID, "m4-status-1", "status");
    let response = post_callback(webhook_port, &body, &signature(&body));
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));

    let request = String::from_utf8(observed.join().expect("observe WhatsApp status"))
        .expect("WhatsApp status request text");
    assert!(request.starts_with("POST /v1/123456789/messages HTTP/1.1\r\n"));
    assert!(request.ends_with("\r\n\r\n{\"messaging_product\":\"whatsapp\",\"template\":{\"components\":[{\"parameters\":[{\"text\":\"ready\",\"type\":\"text\"}],\"type\":\"body\"}],\"language\":{\"code\":\"en_US\"},\"name\":\"delivery_notice\"},\"to\":\"+5511888888888\",\"type\":\"template\"}"));
    assert!(!request.contains("m4-status-1"));
}

#[test]
fn unsigned_or_ungranted_callbacks_never_reach_the_fixed_driver() {
    let root = TestDirectory::create();
    let ntfy = TcpListener::bind("127.0.0.1:0").expect("bind ntfy observer");
    ntfy.set_nonblocking(true)
        .expect("set ntfy observer nonblocking");
    let ntfy_port = ntfy.local_addr().expect("ntfy address").port();

    let webhook = TcpListener::bind("127.0.0.1:0").expect("reserve webhook listener");
    let webhook_port = webhook.local_addr().expect("webhook address").port();
    drop(webhook);

    let mut service = start_service(&root, ntfy_port, webhook_port);
    wait_for_webhook(webhook_port, &mut service.0);
    let socket = root.0.join("state/msgriver.sock");
    wait_for_socket(&socket, &mut service.0);
    inbound_control(&socket, "enable");

    let body = callback(AUTHORIZED_WA_ID, "m4-notify-2", "notify");
    assert!(
        post_callback(
            webhook_port,
            &body,
            "sha256=0000000000000000000000000000000000000000000000000000000000000000"
        )
        .starts_with("HTTP/1.1 401 Unauthorized\r\n")
    );

    assert!(
        post_callback_headers(webhook_port, &body, &[])
            .starts_with("HTTP/1.1 401 Unauthorized\r\n")
    );
    let valid_signature = signature(&body);
    assert!(
        post_callback_headers(
            webhook_port,
            &body,
            &[
                ("X-Hub-Signature-256", valid_signature.as_str()),
                ("X-Hub-Signature-256", valid_signature.as_str()),
            ],
        )
        .starts_with("HTTP/1.1 401 Unauthorized\r\n")
    );
    let mut whitespace_mutated = body.clone();
    whitespace_mutated.extend_from_slice(b" \n");
    assert!(
        post_callback(webhook_port, &whitespace_mutated, &valid_signature)
            .starts_with("HTTP/1.1 401 Unauthorized\r\n")
    );

    let other_sender = callback(STATUS_ONLY_WA_ID, "m4-notify-3", "notify");
    assert!(
        post_callback(webhook_port, &other_sender, &signature(&other_sender))
            .starts_with("HTTP/1.1 200 OK\r\n")
    );
    let unknown_sender = callback("5511777777777", "m4-notify-unknown", "notify");
    assert!(
        post_callback(webhook_port, &unknown_sender, &signature(&unknown_sender))
            .starts_with("HTTP/1.1 200 OK\r\n")
    );

    for (message_id, text) in [
        ("m4-notify-4", "Notify"),
        ("m4-notify-5", " notify"),
        ("m4-notify-6", "notify "),
        ("m4-notify-7", "notify x"),
        ("m4-notify-8", "enable"),
    ] {
        let unknown_verb = callback(AUTHORIZED_WA_ID, message_id, text);
        assert!(
            post_callback(webhook_port, &unknown_verb, &signature(&unknown_verb))
                .starts_with("HTTP/1.1 200 OK\r\n")
        );
    }

    assert_no_ntfy_connection(&ntfy);
    let positive = callback(AUTHORIZED_WA_ID, "m4-notify-9", "notify");
    assert!(
        post_callback(webhook_port, &positive, &signature(&positive))
            .starts_with("HTTP/1.1 200 OK\r\n")
    );
    let request = observe_ntfy(ntfy);
    assert!(request.starts_with("POST /sol-triado HTTP/1.1\r\n"));
    assert!(request.ends_with("\r\n\r\nWhatsApp notify request accepted"));
}

#[test]
fn webhook_subscription_echoes_only_the_exact_owner_verification_token() {
    let root = TestDirectory::create();
    let ntfy = TcpListener::bind("127.0.0.1:0").expect("bind ntfy observer");
    let ntfy_port = ntfy.local_addr().expect("ntfy address").port();
    let webhook = TcpListener::bind("127.0.0.1:0").expect("reserve webhook listener");
    let webhook_port = webhook.local_addr().expect("webhook address").port();
    drop(webhook);

    let mut service = start_service(&root, ntfy_port, webhook_port);
    wait_for_webhook(webhook_port, &mut service.0);

    let accepted = get_webhook(
        webhook_port,
        "hub.mode=subscribe&hub.verify_token=m4-verify-token&hub.challenge=m4challenge_1",
    );
    assert!(accepted.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(accepted.ends_with("\r\n\r\nm4challenge_1"));

    let refused = get_webhook(
        webhook_port,
        "hub.mode=subscribe&hub.verify_token=wrong&hub.challenge=not_for_you",
    );
    assert!(refused.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
    assert!(!refused.contains("not_for_you"));

    for query in [
        "hub.mode=unsubscribe&hub.verify_token=m4-verify-token&hub.challenge=wrong_mode",
        "hub.verify_token=m4-verify-token&hub.challenge=missing_mode",
    ] {
        let refused = get_webhook(webhook_port, query);
        assert!(refused.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(!refused.contains("wrong_mode"));
        assert!(!refused.contains("missing_mode"));
    }
    let oversized = format!(
        "hub.mode=subscribe&hub.verify_token=m4-verify-token&hub.challenge={}",
        "x".repeat(1_025)
    );
    let refused = get_webhook(webhook_port, &oversized);
    assert!(refused.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(!refused.contains(&"x".repeat(64)));
}

#[test]
fn local_switch_replay_and_notify_budget_survive_service_restart() {
    let root = TestDirectory::create();
    let capture = NtfyCapture::start();
    let webhook = TcpListener::bind("127.0.0.1:0").expect("reserve webhook listener");
    let webhook_port = webhook.local_addr().expect("webhook address").port();
    drop(webhook);
    let state_dir = root.0.join("state");
    let socket = state_dir.join("msgriver.sock");

    let mut service = start_service(&root, capture.port, webhook_port);
    wait_for_webhook(webhook_port, &mut service.0);
    wait_for_socket(&socket, &mut service.0);
    let remote_enable = callback(AUTHORIZED_WA_ID, "m4-remote-enable", "enable");
    assert!(
        post_callback(webhook_port, &remote_enable, &signature(&remote_enable))
            .starts_with("HTTP/1.1 200 OK\r\n")
    );
    let disabled = callback(AUTHORIZED_WA_ID, "m4-disabled-1", "notify");
    assert!(
        post_callback(webhook_port, &disabled, &signature(&disabled))
            .starts_with("HTTP/1.1 200 OK\r\n")
    );
    capture.assert_count_stable(0);

    inbound_control(&socket, "enable");
    let first = callback(AUTHORIZED_WA_ID, "m4-replay-1", "notify");
    let mut replay_with_valid_different_raw_body = first.clone();
    replay_with_valid_different_raw_body.extend_from_slice(b" \n");
    assert!(
        post_callback(
            webhook_port,
            &replay_with_valid_different_raw_body,
            &signature(&replay_with_valid_different_raw_body)
        )
        .starts_with("HTTP/1.1 200 OK\r\n")
    );
    capture.wait_for_count(1);
    stop_service(&mut service);
    fs::remove_file(&socket).expect("remove stopped service socket");

    let mut restarted = start_service(&root, capture.port, webhook_port);
    wait_for_webhook(webhook_port, &mut restarted.0);
    wait_for_socket(&socket, &mut restarted.0);
    let fresh_after_restart = callback(AUTHORIZED_WA_ID, "m4-restart-fresh", "notify");
    assert!(
        post_callback(
            webhook_port,
            &fresh_after_restart,
            &signature(&fresh_after_restart)
        )
        .starts_with("HTTP/1.1 200 OK\r\n")
    );
    capture.wait_for_count(2);
    assert!(
        post_callback(webhook_port, &first, &signature(&first)).starts_with("HTTP/1.1 200 OK\r\n")
    );
    capture.assert_count_stable(2);

    inbound_control(&socket, "disable");
    let disabled_after_restart = callback(AUTHORIZED_WA_ID, "m4-disabled-2", "notify");
    assert!(
        post_callback(
            webhook_port,
            &disabled_after_restart,
            &signature(&disabled_after_restart)
        )
        .starts_with("HTTP/1.1 200 OK\r\n")
    );
    capture.assert_count_stable(2);
    stop_service(&mut restarted);
    fs::remove_file(&socket).expect("remove disabled service socket");

    let mut limited = start_service(&root, capture.port, webhook_port);
    wait_for_webhook(webhook_port, &mut limited.0);
    wait_for_socket(&socket, &mut limited.0);
    let still_disabled = callback(AUTHORIZED_WA_ID, "m4-disabled-3", "notify");
    assert!(
        post_callback(webhook_port, &still_disabled, &signature(&still_disabled))
            .starts_with("HTTP/1.1 200 OK\r\n")
    );
    capture.assert_count_stable(2);
    inbound_control(&socket, "enable");
    for sequence in 0..2 {
        let message = callback(AUTHORIZED_WA_ID, &format!("m4-budget-{sequence}"), "notify");
        assert!(
            post_callback(webhook_port, &message, &signature(&message))
                .starts_with("HTTP/1.1 200 OK\r\n")
        );
        capture.wait_for_count(sequence + 3);
    }
    let over_budget = callback(AUTHORIZED_WA_ID, "m4-budget-over", "notify");
    assert!(
        post_callback(webhook_port, &over_budget, &signature(&over_budget))
            .starts_with("HTTP/1.1 200 OK\r\n")
    );
    capture.assert_count_stable(4);
    stop_service(&mut limited);
    fs::remove_file(&socket).expect("remove rate limited service socket");

    let mut persisted = start_service(&root, capture.port, webhook_port);
    wait_for_webhook(webhook_port, &mut persisted.0);
    wait_for_socket(&socket, &mut persisted.0);
    inbound_control(&socket, "enable");
    let after_restart = callback(AUTHORIZED_WA_ID, "m4-budget-persisted", "notify");
    assert!(
        post_callback(webhook_port, &after_restart, &signature(&after_restart))
            .starts_with("HTTP/1.1 200 OK\r\n")
    );
    capture.assert_count_stable(4);
    let requests = capture.requests();
    assert_eq!(requests.len(), 4);
    for request in requests {
        let request = String::from_utf8(request).expect("ntfy request text");
        assert!(request.starts_with("POST /sol-triado HTTP/1.1\r\n"));
        assert!(request.ends_with("\r\n\r\nWhatsApp notify request accepted"));
        assert!(!request.contains(AUTHORIZED_WA_ID));
        assert!(!request.contains("m4-"));
    }
}

fn start_service(root: &TestDirectory, ntfy_port: u16, webhook_port: u16) -> ChildGuard {
    let state_dir = root.0.join("state");
    let socket = state_dir.join("msgriver.sock");
    let app_secret = root.owner_file("whatsapp-app-secret", APP_SECRET);
    let verify_token = root.owner_file("whatsapp-verify-token", b"m4-verify-token\n");
    let policy = root.owner_file(
        "whatsapp-inbound-policy",
        b"5511999999999 notify\n5511888888888 status\n",
    );
    ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_msgriver"))
            .args([
                "serve",
                "--state-dir",
                state_dir.to_str().expect("state path"),
                "--socket",
                socket.to_str().expect("socket path"),
                "--ntfy-url",
                &format!("http://127.0.0.1:{ntfy_port}"),
                "--ntfy-topic",
                "ordinary-m2-topic",
                "--whatsapp-inbound-listen",
                &format!("127.0.0.1:{webhook_port}"),
                "--whatsapp-inbound-app-secret-file",
                app_secret.to_str().expect("app secret path"),
                "--whatsapp-inbound-verify-token-file",
                verify_token.to_str().expect("verify token path"),
                "--whatsapp-inbound-policy-file",
                policy.to_str().expect("policy path"),
                "--whatsapp-inbound-ntfy-topic",
                "sol-triado",
                "--whatsapp-inbound-waba-id",
                WABA_ID,
                "--whatsapp-inbound-phone-id",
                PHONE_ID,
            ])
            .spawn()
            .expect("start service"),
    )
}

fn start_service_with_whatsapp(
    root: &TestDirectory,
    ntfy_port: u16,
    webhook_port: u16,
    whatsapp_url: &str,
    whatsapp_token: &Path,
    whatsapp_ca: &Path,
) -> ChildGuard {
    let state_dir = root.0.join("state");
    let socket = state_dir.join("msgriver.sock");
    let app_secret = root.owner_file("whatsapp-app-secret", APP_SECRET);
    let verify_token = root.owner_file("whatsapp-verify-token", b"m4-verify-token\n");
    let policy = root.owner_file(
        "whatsapp-inbound-policy",
        b"5511999999999 notify\n5511888888888 status\n",
    );
    ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_msgriver"))
            .args([
                "serve",
                "--state-dir",
                state_dir.to_str().expect("state path"),
                "--socket",
                socket.to_str().expect("socket path"),
                "--ntfy-url",
                &format!("http://127.0.0.1:{ntfy_port}"),
                "--ntfy-topic",
                "ordinary-m2-topic",
                "--whatsapp-url",
                whatsapp_url,
                "--whatsapp-phone-id",
                PHONE_ID,
                "--whatsapp-token-file",
                whatsapp_token.to_str().expect("WhatsApp token path"),
                "--whatsapp-ca-file",
                whatsapp_ca.to_str().expect("WhatsApp CA path"),
                "--whatsapp-template",
                "delivery_notice",
                "--whatsapp-locale",
                "en_US",
                "--whatsapp-parameter-count",
                "1",
                "--whatsapp-inbound-listen",
                &format!("127.0.0.1:{webhook_port}"),
                "--whatsapp-inbound-app-secret-file",
                app_secret.to_str().expect("app secret path"),
                "--whatsapp-inbound-verify-token-file",
                verify_token.to_str().expect("verify token path"),
                "--whatsapp-inbound-policy-file",
                policy.to_str().expect("policy path"),
                "--whatsapp-inbound-ntfy-topic",
                "sol-triado",
                "--whatsapp-inbound-waba-id",
                WABA_ID,
                "--whatsapp-inbound-phone-id",
                PHONE_ID,
            ])
            .spawn()
            .expect("start service"),
    )
}

fn wait_for_webhook(port: u16, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("poll service") {
            panic!("service exited before webhook listener started: {status}");
        }
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => {
                drop(stream);
                return;
            }
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
    panic!("webhook listener did not start");
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

fn inbound_control(socket: &std::path::Path, action: &str) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_msgriver"))
        .args([
            "inbound",
            action,
            "--socket",
            socket.to_str().expect("socket path"),
        ])
        .spawn()
        .expect("start local inbound control");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("poll local inbound control") {
            assert!(status.success(), "local inbound {action} must succeed");
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("local inbound {action} timed out");
}

fn stop_service(service: &mut ChildGuard) {
    service.0.kill().expect("stop service");
    service.0.wait().expect("reap stopped service");
}

fn callback(sender: &str, message_id: &str, text: &str) -> Vec<u8> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_secs();
    format!(
        r#"{{"object":"whatsapp_business_account","entry":[{{"id":"{WABA_ID}","changes":[{{"field":"messages","value":{{"messaging_product":"whatsapp","metadata":{{"phone_number_id":"{PHONE_ID}"}},"messages":[{{"from":"{sender}","id":"{message_id}","timestamp":"{timestamp}","type":"text","text":{{"body":"{text}"}}}}]}}}}]}}]}}"#
    )
    .into_bytes()
}

fn signature(body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(APP_SECRET).expect("fixed HMAC key");
    mac.update(body);
    let encoded = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256={encoded}")
}

fn post_callback(port: u16, body: &[u8], signature: &str) -> String {
    post_callback_headers(port, body, &[("X-Hub-Signature-256", signature)])
}

fn post_callback_headers(port: u16, body: &[u8], headers: &[(&str, &str)]) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect webhook");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set webhook read timeout");
    write!(
        stream,
        "POST /v1/whatsapp/webhook HTTP/1.1\r\nHost: loopback\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    )
    .expect("write webhook head");
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n").expect("write webhook security header");
    }
    stream
        .write_all(b"Connection: close\r\n\r\n")
        .expect("finish webhook head");
    stream.write_all(body).expect("write webhook body");
    stream
        .shutdown(Shutdown::Write)
        .expect("finish webhook request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read webhook response");
    response
}

fn get_webhook(port: u16, query: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect webhook");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set webhook read timeout");
    write!(
        stream,
        "GET /v1/whatsapp/webhook?{query} HTTP/1.1\r\nHost: loopback\r\nConnection: close\r\n\r\n"
    )
    .expect("write webhook subscription request");
    stream
        .shutdown(Shutdown::Write)
        .expect("finish subscription request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read subscription response");
    response
}

fn read_ntfy_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut chunk).expect("read ntfy request headers");
        assert_ne!(read, 0, "truncated ntfy request headers");
        request.extend_from_slice(&chunk[..read]);
    }
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("ntfy request headers")
        + 4;
    let head = std::str::from_utf8(&request[..header_end]).expect("ntfy headers utf8");
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .expect("ntfy content length")
        .parse::<usize>()
        .expect("numeric ntfy content length");
    while request.len() < header_end + length {
        let read = stream.read(&mut chunk).expect("read ntfy request body");
        assert_ne!(read, 0, "truncated ntfy request body");
        request.extend_from_slice(&chunk[..read]);
    }
    request
}

fn observe_ntfy(listener: TcpListener) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .expect("set ntfy read timeout");
                let mut request = Vec::new();
                let mut chunk = [0_u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = stream.read(&mut chunk).expect("read ntfy request headers");
                    assert_ne!(read, 0, "truncated ntfy request headers");
                    request.extend_from_slice(&chunk[..read]);
                }
                let header_end = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .expect("ntfy request headers")
                    + 4;
                let head = std::str::from_utf8(&request[..header_end]).expect("ntfy headers utf8");
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .expect("ntfy content length")
                    .parse::<usize>()
                    .expect("numeric ntfy content length");
                while request.len() < header_end + length {
                    let read = stream.read(&mut chunk).expect("read ntfy request body");
                    assert_ne!(read, 0, "truncated ntfy request body");
                    request.extend_from_slice(&chunk[..read]);
                }
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\n{\"id\":\"m4-e2e-1\"}")
                    .expect("acknowledge ntfy request");
                return String::from_utf8(request).expect("ntfy request text");
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept ntfy request: {error}"),
        }
    }
    panic!("no ntfy delivery observed");
}

fn assert_no_ntfy_connection(listener: &TcpListener) {
    listener
        .set_nonblocking(true)
        .expect("set ntfy observer nonblocking");
    thread::sleep(Duration::from_secs(1));
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "refused callbacks must not create an ntfy effect"
    );
}

fn accept_with_deadline(listener: &TcpListener) -> (TcpStream, std::net::SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match listener.accept() {
            Ok(stream) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10))
            }
            Err(error) => panic!("TLS WhatsApp provider accept failed: {error}"),
        }
    }
    panic!("TLS WhatsApp provider did not receive delivery");
}

fn read_tls_request(stream: &mut StreamOwned<ServerConnection, TcpStream>) -> Vec<u8> {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).expect("read TLS WhatsApp request");
        assert_ne!(read, 0, "truncated TLS WhatsApp request");
        request.extend_from_slice(&chunk[..read]);
        let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let head = std::str::from_utf8(&request[..header_end]).expect("TLS WhatsApp headers");
        let length = head
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .expect("TLS WhatsApp content length")
            .parse::<usize>()
            .expect("numeric TLS WhatsApp content length");
        if request.len() >= header_end + 4 + length {
            return request;
        }
    }
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
    run_openssl(&[
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
    ]);
    run_openssl(&[
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
    ]);
    fs::write(
        &extensions,
        b"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n",
    )
    .expect("write server certificate extensions");
    run_openssl(&[
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
    ]);
    for (input, output) in [
        (&server_certificate, &server_certificate_der),
        (&ca_certificate, &ca_certificate_der),
    ] {
        run_openssl(&[
            "x509",
            "-in",
            input.to_str().expect("certificate path"),
            "-outform",
            "DER",
            "-out",
            output.to_str().expect("DER certificate path"),
        ]);
    }
    run_openssl(&[
        "pkcs8",
        "-topk8",
        "-nocrypt",
        "-in",
        server_key.to_str().expect("server key path"),
        "-outform",
        "DER",
        "-out",
        server_key_der.to_str().expect("DER key path"),
    ]);
    (
        fs::read(&server_certificate_der).expect("read server DER certificate"),
        fs::read(&server_key_der).expect("read server DER key"),
        fs::read(&ca_certificate_der).expect("read CA DER certificate"),
    )
}

fn run_openssl(arguments: &[&str]) {
    assert!(
        Command::new("openssl")
            .args(arguments)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("launch openssl")
            .success(),
        "openssl fixture generation failed"
    );
}
