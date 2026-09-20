//! Additive production-primitive contract for private-root refusal.
//!
//! This suite deliberately supplements the frozen owner-lock contract without
//! changing it.  It proves that an untrusted root never reaches creation of
//! `msgriver.lock`, which is the primitive's sole protected-work surrogate.

#![forbid(unsafe_code)]

use msgriver::{StateOwnerLock, StateOwnerLockError};
use std::env;
use std::fs::{self, Metadata};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_LAYOUT: AtomicU64 = AtomicU64::new(0);

struct Layout {
    base: PathBuf,
}

impl Layout {
    fn new(label: &str) -> Result<Self, String> {
        let sequence = NEXT_LAYOUT.fetch_add(1, Ordering::Relaxed);
        let base = env::temp_dir().join(format!(
            "msgriver-red-private-root-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&base).map_err(|error| format!("create test base: {error}"))?;
        set_mode(&base, 0o700)?;
        Ok(Self { base })
    }

    fn root(&self) -> PathBuf {
        self.base.join("state")
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

struct RestoredOwner {
    root: PathBuf,
    owner: u32,
    group: u32,
}

impl RestoredOwner {
    fn restore(&self) -> Result<(), String> {
        let status = Command::new("sudo")
            .args(["-n", "chown"])
            .arg(format!("{}:{}", self.owner, self.group))
            .arg("--")
            .arg(&self.root)
            .status()
            .map_err(|error| format!("start owner-fixture cleanup: {error}"))?;
        if status.success() {
            Ok(())
        } else {
            Err("owner-fixture cleanup was refused".to_owned())
        }
    }
}

impl Drop for RestoredOwner {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[test]
fn missing_private_root_is_refused_before_owner_lock_creation() -> Result<(), String> {
    let layout = Layout::new("missing")?;
    let root = layout.root();

    require_unsafe_root(&root, "missing")?;
    require_absent(&root.join("msgriver.lock"), "missing-root owner lock")
}

#[test]
fn symlinked_private_root_is_refused_without_touching_the_target() -> Result<(), String> {
    let layout = Layout::new("symlink")?;
    let target = layout.base.join("target");
    fs::create_dir(&target).map_err(|error| format!("create target root: {error}"))?;
    set_mode(&target, 0o700)?;
    let root = layout.root();
    symlink(&target, &root).map_err(|error| format!("create root symlink: {error}"))?;

    require_unsafe_root(&root, "symlink")?;
    require_empty(&target, "symlink target")
}

#[test]
fn wrong_mode_private_root_is_refused_before_owner_lock_creation() -> Result<(), String> {
    let layout = Layout::new("wrong-mode")?;
    let root = layout.root();
    fs::create_dir(&root).map_err(|error| format!("create root: {error}"))?;
    set_mode(&root, 0o750)?;

    require_unsafe_root(&root, "wrong-mode")?;
    require_empty(&root, "wrong-mode root")
}

#[test]
fn wrong_owner_private_root_is_refused_before_owner_lock_creation() -> Result<(), String> {
    let layout = Layout::new("wrong-owner")?;
    let root = layout.root();
    fs::create_dir(&root).map_err(|error| format!("create root: {error}"))?;
    set_mode(&root, 0o700)?;
    let metadata = fs::symlink_metadata(&root).map_err(|error| format!("stat root: {error}"))?;
    let _restore = RestoredOwner {
        root: root.clone(),
        owner: metadata.uid(),
        group: metadata.gid(),
    };
    let status = Command::new("sudo")
        .args(["-n", "chown", "0:0", "--"])
        .arg(&root)
        .status()
        .map_err(|error| format!("start privileged owner fixture: {error}"))?;
    if !status.success() {
        return Err("privileged owner fixture was refused".to_owned());
    }
    let wrong_owner =
        fs::symlink_metadata(&root).map_err(|error| format!("stat wrong-owner root: {error}"))?;
    if wrong_owner.uid() == metadata.uid() || unix_mode(&wrong_owner) != 0o700 {
        return Err("wrong-owner fixture was not established with mode 0700".to_owned());
    }

    require_unsafe_root(&root, "wrong-owner")?;
    _restore.restore()?;
    require_empty(&root, "wrong-owner root")
}

fn require_unsafe_root(root: &Path, label: &str) -> Result<(), String> {
    match StateOwnerLock::acquire(root) {
        Err(StateOwnerLockError::UnsafeRoot) => Ok(()),
        Ok(_) => Err(format!("{label} root was accepted")),
        Err(error) => Err(format!("{label} root returned {error:?}, not UnsafeRoot")),
    }
}

fn require_empty(path: &Path, label: &str) -> Result<(), String> {
    let mut entries = fs::read_dir(path).map_err(|error| format!("read {label}: {error}"))?;
    if entries.next().is_some() {
        return Err(format!(
            "{label} gained an owner lock or protected artifact"
        ));
    }
    Ok(())
}

fn require_absent(path: &Path, label: &str) -> Result<(), String> {
    if path.exists() {
        return Err(format!("{label} was created"));
    }
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("set mode {mode:o}: {error}"))
}

fn unix_mode(metadata: &Metadata) -> u32 {
    metadata.permissions().mode() & 0o777
}
