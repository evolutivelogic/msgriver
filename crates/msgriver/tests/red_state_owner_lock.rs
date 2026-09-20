//! Frozen subprocess contract for the fixed-root state-owner lock.
//!
//! The private child protocol exists only inside this integration test. It
//! drives the production `StateOwnerLock::acquire` primitive from a separate
//! process and communicates through a sibling signal directory, never through
//! the protected state root.

#![forbid(unsafe_code)]

use msgriver::StateOwnerLock;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const CHILD_ROOT: &str = "MSGRIVER_RED_OWNER_LOCK_ROOT";
const CHILD_SIGNALS: &str = "MSGRIVER_RED_OWNER_LOCK_SIGNALS";
const CHILD_NAME: &str = "MSGRIVER_RED_OWNER_LOCK_NAME";
const CHILD_ACTION: &str = "MSGRIVER_RED_OWNER_LOCK_ACTION";
const LOCK_NAME: &str = "msgriver.lock";
const READY_SUFFIX: &str = ".ready";
const PROTECTED_SUFFIX: &str = ".protected";
const REJECTED_SUFFIX: &str = ".rejected";
const RELEASE_SUFFIX: &str = ".release";
const ERROR_SUFFIX: &str = ".error";
const CHILD_TIMEOUT: Duration = Duration::from_secs(2);

static NEXT_LAYOUT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct Layout {
    base: PathBuf,
    root: PathBuf,
    signals: PathBuf,
}

impl Layout {
    fn new(label: &str) -> Result<Self, String> {
        let sequence = NEXT_LAYOUT.fetch_add(1, Ordering::Relaxed);
        let base = env::temp_dir().join(format!(
            "msgriver-red-owner-lock-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&base).map_err(|error| format!("create test base: {error}"))?;
        set_mode(&base, 0o700)?;
        let root = base.join("state");
        let signals = base.join("signals");
        fs::create_dir(&root).map_err(|error| format!("create state root: {error}"))?;
        fs::create_dir(&signals).map_err(|error| format!("create signal root: {error}"))?;
        set_mode(&root, 0o700)?;
        set_mode(&signals, 0o700)?;
        Ok(Self {
            base,
            root,
            signals,
        })
    }

    fn marker(&self, name: &str, suffix: &str) -> PathBuf {
        self.signals.join(format!("{name}{suffix}"))
    }

    fn lock_path(&self) -> PathBuf {
        self.root.join(LOCK_NAME)
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

struct ChildRun {
    child: Child,
    release: PathBuf,
}

impl ChildRun {
    fn stop(mut self) -> Result<(), String> {
        write_marker(&self.release, "release")?;
        let status = wait_for_exit(&mut self.child, CHILD_TIMEOUT)?;
        if status.success() {
            return Ok(());
        }
        Err("child exited unsuccessfully".to_owned())
    }

    fn kill(mut self) -> Result<(), String> {
        self.child
            .kill()
            .map_err(|error| format!("kill holder: {error}"))?;
        wait_for_exit(&mut self.child, CHILD_TIMEOUT).map(|_| ())
    }
}

impl Drop for ChildRun {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[test]
fn state_owner_lock_child() -> Result<(), String> {
    let Some(root) = env::var_os(CHILD_ROOT) else {
        return Ok(());
    };
    let signals = env::var_os(CHILD_SIGNALS).ok_or_else(|| "child signals missing".to_owned())?;
    let name = env::var(CHILD_NAME).map_err(|_| "child name missing".to_owned())?;
    let action = env::var(CHILD_ACTION).map_err(|_| "child action missing".to_owned())?;
    run_child(Path::new(&root), Path::new(&signals), &name, &action)
}

#[test]
fn owner_is_exclusive_before_any_protected_work() -> Result<(), String> {
    let layout = Layout::new("exclusive")?;
    let owner = spawn_child_with_umask(&layout, "normal-owner", "hold", "0777")?;
    require_ready(&layout, "normal-owner")?;
    require_protected(&layout, "normal-owner")?;
    assert_mode(&layout.lock_path(), 0o600)?;
    assert_state_root_has_only_lock(&layout)?;

    for contender in ["normal-contender", "maintenance-contender"] {
        let child = spawn_child(&layout, contender, "attempt")?;
        require_rejected(&layout, contender)?;
        require_absent(
            &layout.marker(contender, PROTECTED_SUFFIX),
            "rejected protected work",
        )?;
        child.stop()?;
    }
    owner.stop()
}

#[test]
fn simultaneous_normal_and_maintenance_contenders_have_one_owner() -> Result<(), String> {
    let layout = Layout::new("simultaneous")?;
    let normal = spawn_child(&layout, "normal", "hold")?;
    let maintenance = spawn_child(&layout, "maintenance", "hold")?;
    let normal_ready = wait_for(&layout.marker("normal", READY_SUFFIX), CHILD_TIMEOUT)?;
    let maintenance_ready = wait_for(&layout.marker("maintenance", READY_SUFFIX), CHILD_TIMEOUT)?;
    if normal_ready == maintenance_ready {
        return Err("state-owner lock must acknowledge exactly one simultaneous owner".to_owned());
    }
    if normal_ready {
        require_rejected(&layout, "maintenance")?;
        require_absent(
            &layout.marker("maintenance", PROTECTED_SUFFIX),
            "rejected simultaneous protected work",
        )?;
        normal.stop()?;
        maintenance.stop()
    } else {
        require_rejected(&layout, "normal")?;
        require_absent(
            &layout.marker("normal", PROTECTED_SUFFIX),
            "rejected simultaneous protected work",
        )?;
        maintenance.stop()?;
        normal.stop()
    }
}

#[test]
fn existing_unlocked_regular_entry_is_reused_without_replacement() -> Result<(), String> {
    let layout = Layout::new("reuse")?;
    write_lock(&layout.lock_path(), b"unchanged lock payload")?;
    let before = file_identity_and_bytes(&layout.lock_path())?;
    let owner = spawn_child(&layout, "reuser", "hold")?;
    require_ready(&layout, "reuser")?;
    owner.stop()?;
    if file_identity_and_bytes(&layout.lock_path())? != before {
        return Err(
            "state-owner lock must reuse the existing entry without replacement".to_owned(),
        );
    }
    Ok(())
}

#[test]
fn clean_and_forced_exit_release_the_same_lock_entry() -> Result<(), String> {
    let layout = Layout::new("recovery")?;
    let first = spawn_child(&layout, "clean-first", "hold")?;
    require_ready(&layout, "clean-first")?;
    let identity = file_identity_and_bytes(&layout.lock_path())?;
    first.stop()?;
    let second = spawn_child(&layout, "clean-second", "hold")?;
    require_ready(&layout, "clean-second")?;
    second.kill()?;
    let third = spawn_child(&layout, "killed-successor", "hold")?;
    require_ready(&layout, "killed-successor")?;
    third.stop()?;
    if file_identity_and_bytes(&layout.lock_path())? != identity {
        return Err("state-owner recovery must not delete or replace a stale entry".to_owned());
    }
    Ok(())
}

#[test]
fn unsafe_entries_are_rejected_without_following_or_mutating_them() -> Result<(), String> {
    let layout = Layout::new("unsafe")?;
    let target = layout.signals.join("symlink-target");
    write_lock(&target, b"target stays untouched")?;
    symlink(&target, layout.lock_path()).map_err(|error| format!("create symlink: {error}"))?;
    let child = spawn_child(&layout, "symlink", "attempt")?;
    require_rejected(&layout, "symlink")?;
    require_absent(
        &layout.marker("symlink", PROTECTED_SUFFIX),
        "symlink protected work",
    )?;
    assert_error_is_redacted(&layout, "symlink", &layout.root)?;
    child.stop()?;
    if fs::read(&target).map_err(|error| format!("read target: {error}"))?
        != b"target stays untouched"
    {
        return Err("state-owner lock must not follow or mutate a symlink target".to_owned());
    }
    Ok(())
}

#[test]
fn unsafe_modes_and_special_entries_are_rejected_before_protected_work() -> Result<(), String> {
    let unsafe_root = Layout::new("unsafe-root")?;
    set_mode(&unsafe_root.root, 0o750)?;
    let child = spawn_child(&unsafe_root, "unsafe-root", "attempt")?;
    require_rejected(&unsafe_root, "unsafe-root")?;
    require_absent(
        &unsafe_root.marker("unsafe-root", PROTECTED_SUFFIX),
        "unsafe-root protected work",
    )?;
    child.stop()?;

    let unsafe_file = Layout::new("unsafe-file")?;
    write_lock(&unsafe_file.lock_path(), b"mode must remain unchanged")?;
    set_mode(&unsafe_file.lock_path(), 0o640)?;
    let before = file_identity_and_bytes(&unsafe_file.lock_path())?;
    let child = spawn_child(&unsafe_file, "unsafe-file", "attempt")?;
    require_rejected(&unsafe_file, "unsafe-file")?;
    require_absent(
        &unsafe_file.marker("unsafe-file", PROTECTED_SUFFIX),
        "unsafe-file protected work",
    )?;
    child.stop()?;
    if file_identity_and_bytes(&unsafe_file.lock_path())? != before {
        return Err("unsafe lock entry must not be replaced or truncated".to_owned());
    }

    let special = Layout::new("special")?;
    let listener = UnixListener::bind(special.lock_path())
        .map_err(|error| format!("create special fixture: {error}"))?;
    drop(listener);
    let child = spawn_child(&special, "special", "attempt")?;
    require_rejected(&special, "special")?;
    require_absent(
        &special.marker("special", PROTECTED_SUFFIX),
        "special-entry protected work",
    )?;
    child.stop()
}

fn run_child(root: &Path, signals: &Path, name: &str, action: &str) -> Result<(), String> {
    match StateOwnerLock::acquire(root) {
        Ok(_owner) => {
            write_marker(&marker(signals, name, READY_SUFFIX), "ready")?;
            write_marker(&marker(signals, name, PROTECTED_SUFFIX), "protected")?;
            if action == "hold" {
                wait_for_release(&marker(signals, name, RELEASE_SUFFIX));
            }
        }
        Err(error) => {
            write_marker(&marker(signals, name, REJECTED_SUFFIX), "rejected")?;
            write_marker(&marker(signals, name, ERROR_SUFFIX), &error.to_string())?;
        }
    }
    Ok(())
}

fn spawn_child(layout: &Layout, name: &str, action: &str) -> Result<ChildRun, String> {
    spawn_child_with_umask(layout, name, action, "0022")
}

fn spawn_child_with_umask(
    layout: &Layout,
    name: &str,
    action: &str,
    umask: &str,
) -> Result<ChildRun, String> {
    let executable =
        env::current_exe().map_err(|error| format!("locate test executable: {error}"))?;
    let child = Command::new("/bin/sh")
        .arg("-c")
        .arg("umask \"$1\"; exec \"$2\" --exact state_owner_lock_child --nocapture")
        .arg("sh")
        .arg(umask)
        .arg(executable)
        .env(CHILD_ROOT, &layout.root)
        .env(CHILD_SIGNALS, &layout.signals)
        .env(CHILD_NAME, name)
        .env(CHILD_ACTION, action)
        .spawn()
        .map_err(|error| format!("spawn child: {error}"))?;
    Ok(ChildRun {
        child,
        release: layout.marker(name, RELEASE_SUFFIX),
    })
}

fn require_ready(layout: &Layout, name: &str) -> Result<(), String> {
    if wait_for(&layout.marker(name, READY_SUFFIX), CHILD_TIMEOUT)? {
        return Ok(());
    }
    Err(format!(
        "state-owner lock acquisition frontier: {name} was not acknowledged"
    ))
}

fn require_protected(layout: &Layout, name: &str) -> Result<(), String> {
    if wait_for(&layout.marker(name, PROTECTED_SUFFIX), CHILD_TIMEOUT)? {
        return Ok(());
    }
    Err(format!(
        "successful owner {name} did not reach protected work"
    ))
}

fn require_rejected(layout: &Layout, name: &str) -> Result<(), String> {
    if wait_for(&layout.marker(name, REJECTED_SUFFIX), CHILD_TIMEOUT)? {
        return Ok(());
    }
    Err(format!("contender {name} was not refused promptly"))
}

fn require_absent(path: &Path, what: &str) -> Result<(), String> {
    if path.exists() {
        return Err(format!("{what} must remain absent"));
    }
    Ok(())
}

fn assert_error_is_redacted(layout: &Layout, name: &str, sensitive: &Path) -> Result<(), String> {
    let error = fs::read_to_string(layout.marker(name, ERROR_SUFFIX))
        .map_err(|error| format!("read child error marker: {error}"))?;
    if error.contains(&sensitive.display().to_string()) {
        return Err("state-owner lock error disclosed a state path".to_owned());
    }
    Ok(())
}

fn assert_state_root_has_only_lock(layout: &Layout) -> Result<(), String> {
    let mut names = fs::read_dir(&layout.root)
        .map_err(|error| format!("read state root: {error}"))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("read state entry: {error}"))?;
    names.sort();
    if names != [LOCK_NAME] {
        return Err("lock acquisition created protected state work".to_owned());
    }
    Ok(())
}

fn write_lock(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("create lock fixture: {error}"))?;
    file.write_all(contents)
        .map_err(|error| format!("write lock fixture: {error}"))?;
    Ok(())
}

fn file_identity_and_bytes(path: &Path) -> Result<(u64, u64, Vec<u8>), String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(path).map_err(|error| format!("stat lock fixture: {error}"))?;
    let contents = fs::read(path).map_err(|error| format!("read lock fixture: {error}"))?;
    Ok((metadata.dev(), metadata.ino(), contents))
}

fn assert_mode(path: &Path, expected: u32) -> Result<(), String> {
    let mode = fs::metadata(path)
        .map_err(|error| format!("stat mode fixture: {error}"))?
        .permissions()
        .mode()
        & 0o777;
    if mode != expected {
        return Err(format!("lock mode must be {expected:04o}, got {mode:04o}"));
    }
    Ok(())
}

fn marker(signals: &Path, name: &str, suffix: &str) -> PathBuf {
    signals.join(format!("{name}{suffix}"))
}

fn write_marker(path: &Path, contents: &str) -> Result<(), String> {
    fs::write(path, contents).map_err(|error| format!("write test marker: {error}"))
}

fn wait_for(path: &Path, timeout: Duration) -> Result<bool, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if path.exists() {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_release(path: &Path) {
    while !path.exists() {
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Result<std::process::ExitStatus, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("poll child: {error}"))?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err("child did not exit before deadline".to_owned());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("set fixture mode: {error}"))
}
