//! Frozen Task 0192 RED: the ordinary executable reaches only the first
//! offline bootstrap boundary and never becomes a ready service.

#![forbid(unsafe_code)]

use msgriver::StateOwnerLock;
use std::ffi::OsString;
use std::fs::{self, File};
use std::net::TcpListener;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const BOOTSTRAP_ROOT_ENV: &str = "MSGRIVER_INTERNAL_BOOTSTRAP_ROOT";
const HOLD_ENV: &str = "MSGRIVER_INTERNAL_BOOTSTRAP_HOLD_PATH";
const RELEASE_ENV: &str = "MSGRIVER_INTERNAL_BOOTSTRAP_RELEASE_PATH";
const EXPECTED_EXIT: i32 = 78;
const EXPECTED_STDERR: &str =
    "msgriver: bootstrap selected state is unavailable; service is not ready.\n";
const HOLD_TIMEOUT: Duration = Duration::from_secs(3);
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct FixtureRoot {
    base: PathBuf,
    root: PathBuf,
}

impl FixtureRoot {
    fn new(label: &str) -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "msgriver-task0192-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&base).expect("create private fixture base");
        set_mode(&base, 0o700);
        let root = base.join("state");
        fs::create_dir(&root).expect("create private fixture root");
        set_mode(&root, 0o700);
        Self { base, root }
    }
}

impl Drop for FixtureRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .expect("set private fixture permissions");
}

fn command(root: &Path) -> Command {
    let executable = OsString::from(env!("CARGO_BIN_EXE_msgriver"));
    let mut command = Command::new(executable);
    command
        .env_clear()
        .env(
            "PATH",
            std::env::var_os("PATH").expect("inherit executable path"),
        )
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env(BOOTSTRAP_ROOT_ENV, root);
    command
}

fn invoke(root: &Path) -> Output {
    command(root)
        .output()
        .expect("run ordinary MsgRiver executable")
}

fn invoke_held(root: &Path, held: &Path, release: &Path) -> Child {
    command(root)
        // These names are a debug-test-only barrier, not an operator protocol.
        // The future executable may acknowledge `held` only after retaining the
        // owner lock and before its fixed SelectedState refusal, then wait for
        // `release`. Both paths are disposable, synthetic fixture files.
        .env(HOLD_ENV, held)
        .env(RELEASE_ENV, release)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ordinary MsgRiver executable")
}

fn wait_for_hold_or_exit(mut child: Child, held: &Path) -> Result<Child, Output> {
    let deadline = Instant::now() + HOLD_TIMEOUT;
    while Instant::now() < deadline {
        if held.is_file() {
            return Ok(child);
        }
        if let Some(status) = child.try_wait().expect("poll executable") {
            if status.success() {
                panic!("executable unexpectedly succeeded before bootstrap hold");
            }
            return Err(child
                .wait_with_output()
                .expect("collect early executable output"));
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("executable did not acknowledge the retained-lock boundary");
}

fn require_bootstrap_frontier(output: &Output) {
    let frontier = b"msgriver: server binary is an unreleased scaffold; no product behavior is implemented yet.";
    if output.stderr
        == b"msgriver: server binary is an unreleased scaffold; no product behavior is implemented yet.\n"
        || output.stdout.windows(frontier.len()).any(|window| window == frontier)
        || output.stderr.windows(frontier.len()).any(|window| window == frontier)
    {
        panic!("Task 0192 executable bootstrap frontier is intentionally RED");
    }
}

fn require_static_non_ready(output: &Output, root: &Path) {
    require_bootstrap_frontier(output);
    assert_eq!(output.status.code(), Some(EXPECTED_EXIT));
    assert_eq!(output.stdout, b"");
    assert_eq!(output.stderr, EXPECTED_STDERR.as_bytes());
    assert!(
        !output
            .stderr
            .windows(root.as_os_str().as_bytes().len())
            .any(|window| { window == root.as_os_str().as_bytes() })
    );
}

#[test]
fn valid_private_root_reaches_selected_state_boundary_and_releases_owner_lock() {
    let fixture = FixtureRoot::new("valid-root");
    let held = fixture.base.join("bootstrap-held");
    let release = fixture.base.join("bootstrap-release");
    let child = match wait_for_hold_or_exit(invoke_held(&fixture.root, &held, &release), &held) {
        Ok(child) => child,
        Err(output) => {
            require_bootstrap_frontier(&output);
            panic!("Task 0192 must retain the owner lock at the selected-state boundary");
        }
    };
    assert!(
        StateOwnerLock::acquire(&fixture.root).is_err(),
        "the selected-state boundary must still retain the exclusive owner lock"
    );
    fs::write(&release, "release private test barrier").expect("release retained owner lock");
    let output = child.wait_with_output().expect("collect executable output");
    require_static_non_ready(&output, &fixture.root);

    assert!(fixture.root.join("msgriver.lock").is_file());
    assert!(StateOwnerLock::acquire(&fixture.root).is_ok());
    assert!(!fixture.root.join("selected-state").exists());
    assert!(!fixture.root.join("store").exists());
}

#[test]
fn unsafe_root_is_redacted_and_cannot_create_bootstrap_artifacts() {
    let fixture = FixtureRoot::new("unsafe-root");
    set_mode(&fixture.root, 0o755);
    let output = invoke(&fixture.root);
    require_static_non_ready(&output, &fixture.root);

    assert!(!fixture.root.join("msgriver.lock").exists());
    assert!(!fixture.root.join("selected-state").exists());
    assert!(!fixture.root.join("store").exists());
}

#[test]
fn held_owner_lock_is_redacted_and_never_reaches_selected_state() {
    let fixture = FixtureRoot::new("contended-root");
    let owner = StateOwnerLock::acquire(&fixture.root).expect("retain competing owner lock");
    let output = invoke(&fixture.root);
    require_static_non_ready(&output, &fixture.root);

    assert!(!fixture.root.join("selected-state").exists());
    assert!(!fixture.root.join("store").exists());
    drop(owner);
    assert!(StateOwnerLock::acquire(&fixture.root).is_ok());
}

#[test]
#[ignore = "runs only through the Landlock-confined hermetic gate"]
fn executable_bootstrap_hermetic_negative_network_control() {
    assert!(
        TcpListener::bind("127.0.0.1:0").is_err(),
        "runner confinement must reject socket creation before bind"
    );
    println!("negative-control: network socket prevented before bind");
}

#[test]
#[ignore = "runs only through the Landlock-confined hermetic gate"]
fn executable_bootstrap_hermetic_negative_host_file_control() {
    assert!(
        File::open("/etc/passwd").is_err(),
        "runner confinement must reject host-file reads before data is returned"
    );
    println!("negative-control: host-file read prevented before data return");
}
