//! Frozen post-exec contract for the Linux effective-UID root-refusal guard.

#![forbid(unsafe_code)]

use msgriver::{
    LinuxRootRefusalError, LinuxStartupPolicyAdapter, LinuxStartupPolicyAdapterError,
    LinuxStartupPolicyReadback, LinuxStartupPolicyStep, StateOwnerLock, apply_linux_startup_policy,
    apply_linux_startup_policy_with, ensure_linux_non_root, ensure_linux_non_root_with,
};
use rustix::process::{DumpableBehavior, Resource, dumpable_behavior, geteuid, getrlimit, getuid};
use std::cell::Cell;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const ROOT_ENV: &str = "MSGRIVER_RED_ROOT_REFUSAL_ROOT";
const SIGNALS_ENV: &str = "MSGRIVER_RED_ROOT_REFUSAL_SIGNALS";
const NAME_ENV: &str = "MSGRIVER_RED_ROOT_REFUSAL_NAME";
const EXPECTED_RUID_ENV: &str = "MSGRIVER_RED_ROOT_REFUSAL_RUID";
const EXPECTED_EUID_ENV: &str = "MSGRIVER_RED_ROOT_REFUSAL_EUID";
const RELEASE_ENV: &str = "MSGRIVER_RED_ROOT_REFUSAL_RELEASE";
const POLICY_FAILURE_ENV: &str = "MSGRIVER_RED_ROOT_REFUSAL_POLICY_FAILURE";
const SUPERVISION_ONLY_ENV: &str = "MSGRIVER_RED_ROOT_REFUSAL_SUPERVISION_ONLY";
const RETAIN_FIXTURE_ENV: &str = "MSGRIVER_RED_ROOT_REFUSAL_RETAIN_FIXTURE";
const TIMEOUT: Duration = Duration::from_secs(5);
static NEXT_LAYOUT: AtomicU64 = AtomicU64::new(0);

struct Layout {
    base: PathBuf,
    root: PathBuf,
    signals: PathBuf,
    cleanup_permit: Rc<Cell<bool>>,
}

impl Layout {
    fn new(label: &str) -> Result<Self, String> {
        let sequence = NEXT_LAYOUT.fetch_add(1, Ordering::Relaxed);
        let base = env::temp_dir().join(format!(
            "msgriver-red-root-refusal-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&base).map_err(|error| format!("create base: {error}"))?;
        set_mode(&base, 0o700)?;
        let root = base.join("state");
        let signals = base.join("signals");
        fs::create_dir(&root).map_err(|error| format!("create root: {error}"))?;
        fs::create_dir(&signals).map_err(|error| format!("create signals: {error}"))?;
        set_mode(&root, 0o700)?;
        // Mismatched fixture identities report through a test-only signal root.
        set_mode(&signals, 0o777)?;
        Ok(Self {
            base,
            root,
            signals,
            cleanup_permit: Rc::new(Cell::new(false)),
        })
    }

    fn marker(&self, name: &str, outcome: &str) -> PathBuf {
        self.signals.join(format!("{name}.{outcome}"))
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        // Preserve a failed fixture: removal cannot race a live privileged worker.
        if self.cleanup_permit.get() && env::var_os(RETAIN_FIXTURE_ENV).is_none() {
            let _ = fs::remove_dir_all(&self.base);
        }
    }
}

struct ChildRun {
    child: Child,
    release: PathBuf,
    signals: PathBuf,
    name: String,
    cleanup_permit: Rc<Cell<bool>>,
}

impl ChildRun {
    fn finish(mut self) -> Result<(), String> {
        let status = wait_for_exit(&mut self.child, TIMEOUT)?;
        self.permit_fixture_cleanup_if_reaped();
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "root-owned supervisor exited unsuccessfully: {status}"
            ))
        }
    }
}

impl Drop for ChildRun {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            // Cooperative release only: the root supervisor owns TERM/KILL/reap.
            let _ = fs::write(&self.release, "release after parent failure");
            if wait_for_exit(&mut self.child, TIMEOUT).is_ok() {
                self.permit_fixture_cleanup_if_reaped();
            }
        }
    }
}

impl ChildRun {
    fn permit_fixture_cleanup_if_reaped(&self) {
        if self
            .signals
            .join(format!("{}.worker-reaped", self.name))
            .exists()
            && !self
                .signals
                .join(format!("{}.supervisor-failed", self.name))
                .exists()
        {
            self.cleanup_permit.set(true);
        }
    }
}

#[test]
fn linux_root_refusal_child() -> Result<(), String> {
    let Some(root) = env::var_os(ROOT_ENV) else {
        return Ok(());
    };
    let signals = env::var_os(SIGNALS_ENV).ok_or_else(|| "signals missing".to_owned())?;
    let name = env::var(NAME_ENV).map_err(|_| "name missing".to_owned())?;
    let expected_ruid = parse_uid(EXPECTED_RUID_ENV)?;
    let expected_euid = parse_uid(EXPECTED_EUID_ENV)?;
    let release = env::var_os(RELEASE_ENV).ok_or_else(|| "release missing".to_owned())?;
    if getuid().as_raw() != expected_ruid || geteuid().as_raw() != expected_euid {
        marker(
            Path::new(&signals),
            &name,
            "fixture-failed",
            "identity mismatch",
        )?;
        return Err("privileged UID fixture was not established".to_owned());
    }
    marker(
        Path::new(&signals),
        &name,
        "fixture-ready",
        &format!("ruid={expected_ruid} euid={expected_euid} host-root-evidence"),
    )?;

    let policy = if env::var_os(POLICY_FAILURE_ENV).is_some() {
        let mut adapter = PolicyFailureAdapter;
        apply_linux_startup_policy_with(&mut adapter)
    } else {
        apply_linux_startup_policy()
    };
    if let Err(error) = policy {
        marker(
            Path::new(&signals),
            &name,
            "policy-failed",
            &error.to_string(),
        )?;
        return Ok(());
    }
    let before = policy_snapshot()?;
    marker(Path::new(&signals), &name, "policy-ready", &before)?;
    if env::var_os(SUPERVISION_ONLY_ENV).is_some() {
        marker(
            Path::new(&signals),
            &name,
            "supervision-hold",
            "awaiting root-supervisor deadline",
        )?;
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }

    let first = ensure_linux_non_root();
    let second = ensure_linux_non_root();
    let after = policy_snapshot()?;
    if before != after {
        marker(
            Path::new(&signals),
            &name,
            "policy-mutated",
            "guard changed policy or identity",
        )?;
        return Err("guard changed identity or process policy".to_owned());
    }
    marker(Path::new(&signals), &name, "guard-called", "twice")?;
    match (expected_euid, first, second) {
        (0, Err(LinuxRootRefusalError::RootRefused), Err(LinuxRootRefusalError::RootRefused)) => {
            marker(Path::new(&signals), &name, "root-refused", "twice")
        }
        (_, Ok(()), Ok(())) => {
            let lock = StateOwnerLock::acquire(Path::new(&root))
                .map_err(|error| format!("owner lock after UID guard: {error}"))?;
            marker(Path::new(&signals), &name, "ready", "lock-retained")?;
            if !wait_for(Path::new(&release), TIMEOUT)? {
                marker(
                    Path::new(&signals),
                    &name,
                    "release-timeout",
                    "no protected work",
                )?;
                drop(lock);
                return Err("supervised release was not acknowledged".to_owned());
            }
            marker(Path::new(&signals), &name, "protected", "after-release")
        }
        (_, Err(LinuxRootRefusalError::MissingGuard), _)
        | (_, _, Err(LinuxRootRefusalError::MissingGuard)) => marker(
            Path::new(&signals),
            &name,
            "missing",
            "guard frontier missing",
        ),
        _ => marker(
            Path::new(&signals),
            &name,
            "wrong-decision",
            "guard decision mismatch",
        ),
    }
}

#[test]
fn injected_effective_uid_oracle_is_closed_stable_and_redacted() -> Result<(), String> {
    if ensure_linux_non_root_with(0) != Err(LinuxRootRefusalError::RootRefused) {
        return Err("effective UID zero was not specifically refused".to_owned());
    }
    for uid in [1, 1003, u32::MAX] {
        if ensure_linux_non_root_with(uid) != Ok(()) || ensure_linux_non_root_with(uid) != Ok(()) {
            return Err(format!(
                "effective non-root UID {uid} was not stably accepted"
            ));
        }
    }
    let refusal = LinuxRootRefusalError::RootRefused;
    let display = refusal.to_string();
    let debug = format!("{refusal:?}");
    if display.contains("/private/msgriver-state")
        || debug.contains("/private/msgriver-state")
        || std::error::Error::source(&refusal).is_some()
    {
        return Err("root refusal error disclosed diagnostics".to_owned());
    }
    Ok(())
}

#[test]
fn root_effective_uid_is_refused_after_final_exec_without_state_mutation() -> Result<(), String> {
    let layout = Layout::new("root-effective")?;
    let child = spawn_privileged_child(&layout, "root-effective", 1003, 0, false, false)?;
    require_marker_contains(&layout, "root-effective", "launcher-ready", "ruid=0 euid=0")?;
    require_marker_contains(
        &layout,
        "root-effective",
        "fixture-ready",
        "ruid=1003 euid=0 host-root-evidence",
    )?;
    require_marker_contains(
        &layout,
        "root-effective",
        "policy-ready",
        "core=Some(0)/Some(0) dumpable=false umask=077",
    )?;
    require_marker(&layout, "root-effective", "guard-called")?;
    require_marker_contains(&layout, "root-effective", "root-refused", "twice")?;
    child.finish()?;
    require_absent(&layout.root.join("msgriver.lock"), "root-refused lock")?;
    require_absent(
        &layout.marker("root-effective", "protected"),
        "root protected work",
    )?;
    require_empty(&layout.root, "root-refused state root")
}

#[test]
fn nonroot_effective_uid_retains_owner_lock_through_supervised_release() -> Result<(), String> {
    let layout = Layout::new("nonroot-effective")?;
    let child = spawn_privileged_child(&layout, "nonroot-effective", 0, 1003, false, false)?;
    require_marker_contains(
        &layout,
        "nonroot-effective",
        "launcher-ready",
        "ruid=0 euid=0",
    )?;
    require_marker_contains(
        &layout,
        "nonroot-effective",
        "fixture-ready",
        "ruid=0 euid=1003 host-root-evidence",
    )?;
    require_marker_contains(
        &layout,
        "nonroot-effective",
        "policy-ready",
        "core=Some(0)/Some(0) dumpable=false umask=077",
    )?;
    require_marker(&layout, "nonroot-effective", "guard-called")?;
    require_marker_contains(&layout, "nonroot-effective", "ready", "lock-retained")?;
    if !matches!(
        StateOwnerLock::acquire(&layout.root),
        Err(msgriver::StateOwnerLockError::Contended)
    ) {
        return Err("accepted UID guard must retain owner lock through hold".to_owned());
    }
    fs::write(layout.marker("nonroot-effective", "release"), "release")
        .map_err(|error| format!("release accepted child: {error}"))?;
    require_marker(&layout, "nonroot-effective", "protected")?;
    child.finish()?;
    require_marker(&layout, "nonroot-effective", "worker-reaped")?;
    if !layout.root.join("msgriver.lock").is_file() {
        return Err("accepted completion must preserve the owner-lock entry".to_owned());
    }
    Ok(())
}

#[test]
fn policy_failure_remains_before_guard_lock_and_protected_work() -> Result<(), String> {
    let layout = Layout::new("policy-failure")?;
    let child = spawn_privileged_child(&layout, "policy-failure", 0, 1003, true, false)?;
    require_marker_contains(
        &layout,
        "policy-failure",
        "launcher-ready",
        "root-supervisor",
    )?;
    require_marker_contains(
        &layout,
        "policy-failure",
        "fixture-ready",
        "ruid=0 euid=1003 host-root-evidence",
    )?;
    require_marker_contains(
        &layout,
        "policy-failure",
        "policy-failed",
        "Linux startup policy installation failed",
    )?;
    child.finish()?;
    for outcome in ["policy-ready", "guard-called", "ready", "protected"] {
        require_absent(&layout.marker("policy-failure", outcome), outcome)?;
    }
    require_empty(&layout.root, "policy-failed state root")
}

#[test]
fn root_supervisor_terminates_and_reaps_a_stuck_privileged_worker() -> Result<(), String> {
    let layout = Layout::new("supervision")?;
    let child = spawn_privileged_child(&layout, "supervision", 0, 1003, false, true)?;
    require_marker_contains(&layout, "supervision", "launcher-ready", "root-supervisor")?;
    require_marker_contains(
        &layout,
        "supervision",
        "fixture-ready",
        "ruid=0 euid=1003 host-root-evidence",
    )?;
    require_marker(&layout, "supervision", "supervision-hold")?;
    if child.finish().is_ok() {
        return Err("root supervisor accepted its TERM-killed worker".to_owned());
    }
    require_marker_contains(
        &layout,
        "supervision",
        "supervisor-term",
        "worker process group TERM",
    )?;
    require_marker_contains(&layout, "supervision", "worker-reaped", "exit=-15")?;
    require_absent(
        &layout.marker("supervision", "supervisor-failed"),
        "supervisor reap failure",
    )?;
    require_empty(&layout.root, "supervised stuck-worker state root")
}

fn spawn_privileged_child(
    layout: &Layout,
    name: &str,
    real_uid: u32,
    effective_uid: u32,
    inject_policy_failure: bool,
    supervision_only: bool,
) -> Result<ChildRun, String> {
    let executable = env::current_exe().map_err(|error| format!("current exe: {error}"))?;
    let launcher = r#"import os, signal, sys, time
r, e = int(sys.argv[1]), int(sys.argv[2])
x, root, signals, name, release, fail, supervise = sys.argv[3:10]
def marker(outcome, text):
    path = os.path.join(signals, name + '.' + outcome)
    temporary = path + '.tmp-' + str(os.getpid())
    with open(temporary, 'w', encoding='ascii') as out:
        out.write(text)
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)
if os.geteuid() != 0:
    marker('launcher-failed', 'sudo did not provide host root')
    sys.exit(97)
deadline = time.monotonic() + 5.0
pid = os.fork()
if pid == 0:
    os.setpgrp()
    os.environ.update({
        'MSGRIVER_RED_ROOT_REFUSAL_ROOT': root,
        'MSGRIVER_RED_ROOT_REFUSAL_SIGNALS': signals,
        'MSGRIVER_RED_ROOT_REFUSAL_NAME': name,
        'MSGRIVER_RED_ROOT_REFUSAL_RUID': str(r),
        'MSGRIVER_RED_ROOT_REFUSAL_EUID': str(e),
        'MSGRIVER_RED_ROOT_REFUSAL_RELEASE': release,
    })
    if fail == 'yes':
        os.environ['MSGRIVER_RED_ROOT_REFUSAL_POLICY_FAILURE'] = 'yes'
    if supervise == 'yes':
        os.environ['MSGRIVER_RED_ROOT_REFUSAL_SUPERVISION_ONLY'] = 'yes'
    os.setresgid(r, e, e)
    os.setresuid(r, e, e)
    os.execv(x, [x, '--exact', 'linux_root_refusal_child', '--nocapture'])
marker('launcher-ready', 'ruid=%d euid=%d worker=%d root-supervisor' % (os.getuid(), os.geteuid(), pid))
status = None
while time.monotonic() < deadline:
    found, candidate = os.waitpid(pid, os.WNOHANG)
    if found:
        status = candidate
        break
    time.sleep(0.01)
if status is None:
    marker('supervisor-term', 'worker process group TERM')
    os.killpg(pid, signal.SIGTERM)
    cleanup_deadline = time.monotonic() + 1.0
    while time.monotonic() < cleanup_deadline:
        found, candidate = os.waitpid(pid, os.WNOHANG)
        if found:
            status = candidate
            break
        time.sleep(0.01)
if status is None:
    marker('supervisor-kill', 'worker process group KILL')
    os.killpg(pid, signal.SIGKILL)
    cleanup_deadline = time.monotonic() + 1.0
    while time.monotonic() < cleanup_deadline:
        found, candidate = os.waitpid(pid, os.WNOHANG)
        if found:
            status = candidate
            break
        time.sleep(0.01)
if status is None:
    marker('supervisor-failed', 'worker was not reaped')
    sys.exit(98)
code = os.waitstatus_to_exitcode(status)
marker('worker-reaped', 'exit=%d' % code)
sys.exit(0 if code == 0 else 99)"#;
    let release = layout.marker(name, "release");
    let child = Command::new("sudo")
        .arg("-n")
        .arg("/usr/bin/python3")
        .arg("-c")
        .arg(launcher)
        .arg(real_uid.to_string())
        .arg(effective_uid.to_string())
        .arg(executable)
        .arg(&layout.root)
        .arg(&layout.signals)
        .arg(name)
        .arg(&release)
        .arg(if inject_policy_failure { "yes" } else { "no" })
        .arg(if supervision_only { "yes" } else { "no" })
        .spawn()
        .map_err(|error| format!("spawn sudo root supervisor: {error}"))?;
    Ok(ChildRun {
        child,
        release,
        signals: layout.signals.clone(),
        name: name.to_owned(),
        cleanup_permit: Rc::clone(&layout.cleanup_permit),
    })
}

fn parse_uid(key: &str) -> Result<u32, String> {
    env::var(key)
        .map_err(|_| format!("{key} missing"))?
        .parse::<u32>()
        .map_err(|_| format!("{key} invalid"))
}

fn marker(signals: &Path, name: &str, outcome: &str, content: &str) -> Result<(), String> {
    let path = signals.join(format!("{name}.{outcome}"));
    let temporary = signals.join(format!(".{name}.{outcome}.tmp-{}", std::process::id()));
    fs::write(&temporary, content).map_err(|error| format!("write marker: {error}"))?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644))
        .map_err(|error| format!("prepare marker: {error}"))?;
    fs::rename(temporary, path).map_err(|error| format!("publish marker: {error}"))
}

fn require_marker(layout: &Layout, name: &str, outcome: &str) -> Result<(), String> {
    let path = layout.marker(name, outcome);
    if wait_for(&path, TIMEOUT)? {
        let deadline = Instant::now() + TIMEOUT;
        while Instant::now() < deadline {
            let content =
                fs::read_to_string(&path).map_err(|error| format!("read {outcome}: {error}"))?;
            if !content.is_empty() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(10));
        }
        return Err(format!("{name} acknowledged empty {outcome}"));
    }
    for terminal in [
        "launcher-failed",
        "fixture-failed",
        "policy-failed",
        "missing",
        "wrong-decision",
        "policy-mutated",
        "supervisor-failed",
    ] {
        if terminal != outcome && layout.marker(name, terminal).exists() {
            return Err(format!(
                "{name} reached distinct terminal {terminal}, not {outcome}"
            ));
        }
    }
    Err(format!("{name} did not acknowledge {outcome}"))
}

fn require_marker_contains(
    layout: &Layout,
    name: &str,
    outcome: &str,
    expected: &str,
) -> Result<(), String> {
    require_marker(layout, name, outcome)?;
    let content = fs::read_to_string(layout.marker(name, outcome))
        .map_err(|error| format!("read {outcome}: {error}"))?;
    if content.contains(expected) {
        Ok(())
    } else {
        Err(format!(
            "{name} {outcome} acknowledgement lacked {expected:?}"
        ))
    }
}

fn policy_snapshot() -> Result<String, String> {
    let core = getrlimit(Resource::Core);
    let dumpable = dumpable_behavior().map_err(|_| "read dumpability".to_owned())?;
    let previous_umask = rustix::process::umask(rustix::fs::Mode::empty());
    rustix::process::umask(previous_umask);
    Ok(format!(
        "ruid={} euid={} core={:?}/{:?} dumpable={:?} umask={:03o}",
        getuid().as_raw(),
        geteuid().as_raw(),
        core.current,
        core.maximum,
        dumpable == DumpableBehavior::Dumpable,
        previous_umask.as_raw_mode(),
    ))
}

fn wait_for(path: &Path, timeout: Duration) -> Result<bool, String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(path.exists())
}

fn require_absent(path: &Path, label: &str) -> Result<(), String> {
    if path.exists() {
        return Err(format!("{label} must remain absent"));
    }
    Ok(())
}

fn require_empty(path: &Path, label: &str) -> Result<(), String> {
    if fs::read_dir(path)
        .map_err(|error| format!("read {label}: {error}"))?
        .next()
        .is_some()
    {
        return Err(format!("{label} must remain untouched"));
    }
    Ok(())
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Result<ExitStatus, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("poll root supervisor: {error}"))?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err("root supervisor deadline elapsed".to_owned());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("set mode: {error}"))
}

struct PolicyFailureAdapter;

impl LinuxStartupPolicyAdapter for PolicyFailureAdapter {
    fn run_step(
        &mut self,
        _step: LinuxStartupPolicyStep,
    ) -> Result<(), LinuxStartupPolicyAdapterError> {
        Err(LinuxStartupPolicyAdapterError::Failed)
    }

    fn readback(&mut self) -> Result<LinuxStartupPolicyReadback, LinuxStartupPolicyAdapterError> {
        Ok(LinuxStartupPolicyReadback {
            core_soft: 0,
            core_hard: 0,
            dumpable: false,
        })
    }
}
