//! Frozen subprocess contract for the Linux startup process policy.

#![forbid(unsafe_code)]

use msgriver::{
    LinuxStartupPolicyAdapter, LinuxStartupPolicyAdapterError, LinuxStartupPolicyReadback,
    LinuxStartupPolicyStep, StateOwnerLock, apply_linux_startup_policy,
    apply_linux_startup_policy_with,
};
use rustix::process::{
    DumpableBehavior, Resource, dumpable_behavior, getrlimit, set_dumpable_behavior,
};
use std::env;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const ROOT_ENV: &str = "MSGRIVER_RED_POLICY_ROOT";
const SIGNAL_ENV: &str = "MSGRIVER_RED_POLICY_SIGNALS";
const NAME_ENV: &str = "MSGRIVER_RED_POLICY_NAME";
const CORE_ENV: &str = "MSGRIVER_RED_POLICY_CORE";
const POSITIVE_CORE_ENV: &str = "MSGRIVER_RED_POLICY_POSITIVE_CORE";
const FAIL_STEP_ENV: &str = "MSGRIVER_RED_POLICY_FAIL_STEP";
const TIMEOUT: Duration = Duration::from_secs(2);
static NEXT_LAYOUT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct Layout {
    base: PathBuf,
    root: PathBuf,
    signals: PathBuf,
}

impl Layout {
    fn new(label: &str) -> Result<Self, String> {
        let id = NEXT_LAYOUT.fetch_add(1, Ordering::Relaxed);
        let base = env::temp_dir().join(format!(
            "msgriver-red-policy-{label}-{}-{id}",
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
        self.signals.join(format!("{name}.{suffix}"))
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

struct ChildRun {
    child: Child,
}

impl ChildRun {
    fn finish(mut self) -> Result<(), String> {
        let status = wait_for_exit(&mut self.child, TIMEOUT)?;
        if status.success() {
            Ok(())
        } else {
            Err("policy child exited unsuccessfully".to_owned())
        }
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
fn linux_startup_policy_child() -> Result<(), String> {
    let Some(root) = env::var_os(ROOT_ENV) else {
        return Ok(());
    };
    let signals = env::var_os(SIGNAL_ENV).ok_or_else(|| "policy signals missing".to_owned())?;
    let name = env::var(NAME_ENV).map_err(|_| "policy name missing".to_owned())?;
    let expected_core = env::var(CORE_ENV).map_err(|_| "policy core fixture missing".to_owned())?;
    let positive_core = env::var(POSITIVE_CORE_ENV)
        .map_err(|_| "policy core fixture mode missing".to_owned())?
        == "yes";
    run_child(
        Path::new(&root),
        Path::new(&signals),
        &name,
        &expected_core,
        positive_core,
        injected_failure_from_env()?,
    )
}

#[test]
fn policy_hardens_each_inherited_umask_after_final_exec() -> Result<(), String> {
    for mask in ["0000", "0022", "0077", "0777"] {
        let layout = Layout::new(mask)?;
        let name = format!("umask-{mask}");
        let child = spawn_child(&layout, &name, mask, "1024")?;
        require_ready(&layout, &name)?;
        require_absent(
            &layout.marker(&name, "rejected"),
            "successful policy rejection",
        )?;
        child.finish()?;
    }
    Ok(())
}

#[test]
fn policy_reduces_verified_positive_core_limits_and_is_repeatable() -> Result<(), String> {
    let layout = Layout::new("core")?;
    let child = spawn_child(&layout, "core", "0000", "1024")?;
    require_ready(&layout, "core")?;
    child.finish()
}

#[test]
fn policy_is_idempotent_with_inherited_zero_core_limits() -> Result<(), String> {
    let layout = Layout::new("already-zero")?;
    let child = spawn_child_with_core_mode(&layout, "already-zero", "0077", "0", false)?;
    require_ready(&layout, "already-zero")?;
    child.finish()
}

#[test]
fn policy_failure_frontier_prevents_owner_lock_and_protected_work() -> Result<(), String> {
    let layout = Layout::new("ordering")?;
    let child = spawn_child_with_failure(
        &layout,
        "ordering",
        "0022",
        "1024",
        LinuxStartupPolicyStep::SetCoreLimits,
    )?;
    if !wait_for(&layout.marker("ordering", "rejected"), TIMEOUT)? {
        return Err("failing policy child was not rejected".to_owned());
    }
    child.finish()?;
    require_absent(
        &layout.marker("ordering", "ready"),
        "failed policy readiness",
    )?;
    require_absent(
        &layout.marker("ordering", "protected"),
        "failed policy protected-work acknowledgement",
    )?;
    require_absent(
        &layout.root.join("msgriver.lock"),
        "failed policy state-owner lock entry",
    )?;
    Ok(())
}

#[test]
fn policy_adapter_rejects_each_failure_and_wrong_readback_without_diagnostics() -> Result<(), String>
{
    let sensitive = "/private/msgriver-state";
    let scenarios = [
        None,
        Some(LinuxStartupPolicyStep::InstallUmask),
        Some(LinuxStartupPolicyStep::SetCoreLimits),
        Some(LinuxStartupPolicyStep::SetNotDumpable),
        Some(LinuxStartupPolicyStep::ReadCoreLimits),
        Some(LinuxStartupPolicyStep::ReadDumpability),
    ];
    for failure in scenarios {
        let mut adapter = FixtureAdapter {
            failure,
            readback_failure: false,
            readback: LinuxStartupPolicyReadback {
                core_soft: 0,
                core_hard: 0,
                dumpable: false,
            },
        };
        let result = apply_linux_startup_policy_with(&mut adapter);
        if failure.is_none() {
            if result.is_err() {
                return Err("healthy policy adapter frontier did not succeed".to_owned());
            }
        } else if let Err(error) = result {
            let display = error.to_string();
            let debug = format!("{error:?}");
            if display.contains(sensitive)
                || debug.contains(sensitive)
                || std::error::Error::source(&error).is_some()
            {
                return Err("policy failure error disclosed diagnostics".to_owned());
            }
        } else {
            return Err("injected policy operation failure succeeded".to_owned());
        }
    }
    for readback in [
        LinuxStartupPolicyReadback {
            core_soft: 1,
            core_hard: 0,
            dumpable: false,
        },
        LinuxStartupPolicyReadback {
            core_soft: 0,
            core_hard: 1,
            dumpable: false,
        },
        LinuxStartupPolicyReadback {
            core_soft: 0,
            core_hard: 0,
            dumpable: true,
        },
    ] {
        let mut adapter = FixtureAdapter {
            failure: None,
            readback_failure: false,
            readback,
        };
        require_closed_failure(
            apply_linux_startup_policy_with(&mut adapter),
            "wrong successful policy readback was accepted",
        )?;
    }
    let mut adapter = FixtureAdapter {
        failure: None,
        readback_failure: true,
        readback: LinuxStartupPolicyReadback {
            core_soft: 0,
            core_hard: 0,
            dumpable: false,
        },
    };
    require_closed_failure(
        apply_linux_startup_policy_with(&mut adapter),
        "injected policy readback failure succeeded",
    )?;
    Ok(())
}

fn require_closed_failure(
    result: Result<(), msgriver::LinuxStartupPolicyError>,
    success_message: &str,
) -> Result<(), String> {
    let error = result.err().ok_or_else(|| success_message.to_owned())?;
    let display = error.to_string();
    let debug = format!("{error:?}");
    if display.contains("/private/msgriver-state")
        || debug.contains("/private/msgriver-state")
        || std::error::Error::source(&error).is_some()
    {
        return Err("policy failure error disclosed diagnostics".to_owned());
    }
    Ok(())
}

struct FixtureAdapter {
    failure: Option<LinuxStartupPolicyStep>,
    readback_failure: bool,
    readback: LinuxStartupPolicyReadback,
}

impl LinuxStartupPolicyAdapter for FixtureAdapter {
    fn run_step(
        &mut self,
        step: LinuxStartupPolicyStep,
    ) -> Result<(), LinuxStartupPolicyAdapterError> {
        if self.failure == Some(step) {
            Err(LinuxStartupPolicyAdapterError::Failed)
        } else {
            Ok(())
        }
    }

    fn readback(&mut self) -> Result<LinuxStartupPolicyReadback, LinuxStartupPolicyAdapterError> {
        if self.readback_failure {
            Err(LinuxStartupPolicyAdapterError::Failed)
        } else {
            Ok(self.readback)
        }
    }
}

fn run_child(
    root: &Path,
    signals: &Path,
    name: &str,
    expected_core: &str,
    positive_core: bool,
    injected_failure: Option<LinuxStartupPolicyStep>,
) -> Result<(), String> {
    let expected_core = expected_core
        .parse::<u64>()
        .map_err(|_| "invalid core fixture".to_owned())?
        .checked_mul(512)
        .ok_or_else(|| "core fixture overflow".to_owned())?;
    let before = getrlimit(Resource::Core);
    if before.current != Some(expected_core)
        || before.maximum != Some(expected_core)
        || (positive_core && expected_core == 0)
    {
        write_marker(
            signals,
            name,
            "fixture-failed",
            "core fixture was not positive and finite",
        )?;
        return Err("positive core fixture was not established".to_owned());
    }
    set_dumpable_behavior(DumpableBehavior::Dumpable)
        .map_err(|error| format!("enable dumpability fixture: {error}"))?;
    if dumpable_behavior().map_err(|error| format!("read dumpability fixture: {error}"))?
        != DumpableBehavior::Dumpable
    {
        return Err("dumpability fixture was not established".to_owned());
    }

    let policy = match injected_failure {
        None => apply_linux_startup_policy(),
        Some(failure) => {
            let mut adapter = FixtureAdapter {
                failure: Some(failure),
                readback_failure: false,
                readback: LinuxStartupPolicyReadback {
                    core_soft: 0,
                    core_hard: 0,
                    dumpable: false,
                },
            };
            apply_linux_startup_policy_with(&mut adapter)
        }
    };
    match policy {
        Ok(()) => {
            verify_effective_policy(root)?;
            apply_linux_startup_policy().map_err(|error| format!("repeat policy: {error}"))?;
            verify_effective_policy(root)?;
            if fs::read_dir(root)
                .map_err(|error| format!("read policy root before lock: {error}"))?
                .next()
                .is_some()
            {
                return Err("policy alone created a state entry".to_owned());
            }
            StateOwnerLock::acquire(root)
                .map_err(|error| format!("owner lock after policy: {error}"))?;
            write_marker(signals, name, "ready", "ready")?;
            write_marker(signals, name, "protected", "protected")?;
        }
        Err(error) => {
            write_marker(signals, name, "rejected", &error.to_string())?;
        }
    }
    Ok(())
}

fn verify_effective_policy(root: &Path) -> Result<(), String> {
    let limits = getrlimit(Resource::Core);
    if limits.current != Some(0) || limits.maximum != Some(0) {
        return Err("core policy did not reduce both verified positive limits to zero".to_owned());
    }
    if dumpable_behavior().map_err(|error| format!("read dumpability: {error}"))?
        != DumpableBehavior::NotDumpable
    {
        return Err("process remained dumpable after startup policy".to_owned());
    }
    let file = root.join("policy-file");
    let directory = root.join("policy-directory");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o666)
        .open(&file)
        .map_err(|error| format!("create policy fixture file: {error}"))?;
    fs::create_dir(&directory)
        .map_err(|error| format!("create policy fixture directory: {error}"))?;
    if unix_mode(&file)? != 0o600 || unix_mode(&directory)? != 0o700 {
        return Err("startup policy did not install umask 0077".to_owned());
    }
    fs::remove_file(&file).map_err(|error| format!("remove policy fixture file: {error}"))?;
    fs::remove_dir(&directory)
        .map_err(|error| format!("remove policy fixture directory: {error}"))?;
    Ok(())
}

fn spawn_child(layout: &Layout, name: &str, umask: &str, core: &str) -> Result<ChildRun, String> {
    spawn_child_with_core_mode(layout, name, umask, core, true)
}

fn spawn_child_with_core_mode(
    layout: &Layout,
    name: &str,
    umask: &str,
    core: &str,
    positive_core: bool,
) -> Result<ChildRun, String> {
    spawn_child_with_failure_mode(layout, name, umask, core, positive_core, None)
}

fn spawn_child_with_failure(
    layout: &Layout,
    name: &str,
    umask: &str,
    core: &str,
    failure: LinuxStartupPolicyStep,
) -> Result<ChildRun, String> {
    spawn_child_with_failure_mode(layout, name, umask, core, true, Some(failure))
}

fn spawn_child_with_failure_mode(
    layout: &Layout,
    name: &str,
    umask: &str,
    core: &str,
    positive_core: bool,
    failure: Option<LinuxStartupPolicyStep>,
) -> Result<ChildRun, String> {
    let executable =
        env::current_exe().map_err(|error| format!("locate test executable: {error}"))?;
    let child = Command::new("/bin/sh")
        .arg("-c")
        .arg("umask \"$1\"; ulimit -Sc \"$2\"; ulimit -Hc \"$2\"; exec \"$3\" --exact linux_startup_policy_child --nocapture")
        .arg("sh").arg(umask).arg(core).arg(executable)
        .env(ROOT_ENV, &layout.root).env(SIGNAL_ENV, &layout.signals).env(NAME_ENV, name).env(CORE_ENV, core)
        .env(POSITIVE_CORE_ENV, if positive_core { "yes" } else { "no" })
        .env_remove(FAIL_STEP_ENV)
        .envs(failure.map(|step| (FAIL_STEP_ENV, step_token(step))))
        .spawn().map_err(|error| format!("spawn policy child: {error}"))?;
    Ok(ChildRun { child })
}

fn injected_failure_from_env() -> Result<Option<LinuxStartupPolicyStep>, String> {
    match env::var(FAIL_STEP_ENV).ok().as_deref() {
        None => Ok(None),
        Some("install-umask") => Ok(Some(LinuxStartupPolicyStep::InstallUmask)),
        Some("set-core-limits") => Ok(Some(LinuxStartupPolicyStep::SetCoreLimits)),
        Some("set-not-dumpable") => Ok(Some(LinuxStartupPolicyStep::SetNotDumpable)),
        Some("read-core-limits") => Ok(Some(LinuxStartupPolicyStep::ReadCoreLimits)),
        Some("read-dumpability") => Ok(Some(LinuxStartupPolicyStep::ReadDumpability)),
        Some(_) => Err("invalid injected policy failure step".to_owned()),
    }
}

fn step_token(step: LinuxStartupPolicyStep) -> &'static str {
    match step {
        LinuxStartupPolicyStep::InstallUmask => "install-umask",
        LinuxStartupPolicyStep::SetCoreLimits => "set-core-limits",
        LinuxStartupPolicyStep::SetNotDumpable => "set-not-dumpable",
        LinuxStartupPolicyStep::ReadCoreLimits => "read-core-limits",
        LinuxStartupPolicyStep::ReadDumpability => "read-dumpability",
    }
}

fn require_ready(layout: &Layout, name: &str) -> Result<(), String> {
    if wait_for(&layout.marker(name, "ready"), TIMEOUT)? {
        return Ok(());
    }
    if layout.marker(name, "fixture-failed").exists() {
        return Err("positive core fixture evidence is missing".to_owned());
    }
    Err(format!(
        "Linux startup policy frontier: {name} was not acknowledged"
    ))
}

fn require_absent(path: &Path, what: &str) -> Result<(), String> {
    if path.exists() {
        return Err(format!("{what} must remain absent"));
    }
    Ok(())
}

fn write_marker(signals: &Path, name: &str, suffix: &str, contents: &str) -> Result<(), String> {
    fs::write(signals.join(format!("{name}.{suffix}")), contents)
        .map_err(|error| format!("write policy marker: {error}"))
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

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Result<ExitStatus, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("poll policy child: {error}"))?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err("policy child did not exit before deadline".to_owned());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn unix_mode(path: &Path) -> Result<u32, String> {
    Ok(fs::metadata(path)
        .map_err(|error| format!("stat policy fixture: {error}"))?
        .permissions()
        .mode()
        & 0o777)
}

fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("set fixture mode: {error}"))
}
