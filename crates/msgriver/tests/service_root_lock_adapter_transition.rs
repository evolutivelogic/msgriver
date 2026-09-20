//! Task 0009 concrete root/lock adapter successor.

#![forbid(unsafe_code)]

use msgriver::{
    StateOwnerLock,
    service_bootstrap::{BootstrapStep, RootLockAdapter},
};
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn root() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("msgriver-root-lock-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[test]
fn retained_adapter_excludes_a_second_owner_until_drop() {
    let root = root();
    let mut adapter = RootLockAdapter::new(&root);
    adapter.run_root_step(BootstrapStep::TrustedRoot).unwrap();
    adapter.run_root_step(BootstrapStep::OwnerLock).unwrap();
    assert!(adapter.retains_owner_lock());
    assert!(StateOwnerLock::acquire(&root).is_err());
    drop(adapter);
    assert!(StateOwnerLock::acquire(&root).is_ok());
    fs::remove_dir_all(root).unwrap();
}
