//! Frozen Task 0065 RED: compose only the trusted-root/owner-lock steps.

#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use msgriver::{
    StateOwnerLock,
    service_bootstrap::{
        BootstrapAdapter, BootstrapAdapterError, BootstrapError, BootstrapStep, RootLockAdapter,
        RootLockBootstrapAdapter, bootstrap_owned,
    },
};

#[derive(Default)]
struct Probe {
    steps: Vec<BootstrapStep>,
    fail_at: Option<BootstrapStep>,
}

impl BootstrapAdapter for Probe {
    fn run(&mut self, step: BootstrapStep) -> Result<(), BootstrapAdapterError> {
        self.steps.push(step);
        if self.fail_at == Some(step) {
            Err(BootstrapAdapterError::Failed)
        } else {
            Ok(())
        }
    }
}

fn root(label: &str) -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("msgriver-task0065-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir(&path).expect("private root fixture");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .expect("private root permissions");
    path
}

#[test]
fn owner_lock_requires_a_successful_trusted_root_transition() {
    let root = root("ordered");
    let mut adapter = RootLockAdapter::new(&root);

    assert_eq!(
        adapter.run_root_step(BootstrapStep::OwnerLock),
        Err(BootstrapAdapterError::Failed)
    );
    assert!(StateOwnerLock::acquire(&root).is_ok());
    adapter
        .run_root_step(BootstrapStep::TrustedRoot)
        .expect("trusted root");
    adapter
        .run_root_step(BootstrapStep::OwnerLock)
        .expect("owner lock after trusted root");
    assert!(StateOwnerLock::acquire(&root).is_err());

    drop(adapter);
    fs::remove_dir_all(root).expect("fixture cleanup");
}

#[test]
fn composed_runtime_delegates_other_steps_and_retains_the_owner_lock() {
    let root = root("runtime");
    let adapter = RootLockBootstrapAdapter::new(RootLockAdapter::new(&root), Probe::default());
    let runtime = bootstrap_owned(adapter).expect("complete injected composition");

    assert_eq!(
        runtime.adapter().delegate().steps,
        [
            BootstrapStep::ProcessPolicy,
            BootstrapStep::NonRoot,
            BootstrapStep::SelectedState,
            BootstrapStep::Store,
            BootstrapStep::StructuralConfiguration,
            BootstrapStep::ProviderCatalog,
        ]
    );
    assert!(runtime.adapter().root_lock().retains_owner_lock());
    assert!(StateOwnerLock::acquire(&root).is_err());

    let adapter = runtime.into_adapter();
    assert!(StateOwnerLock::acquire(&root).is_err());
    drop(adapter);
    assert!(StateOwnerLock::acquire(&root).is_ok());
    fs::remove_dir_all(root).expect("fixture cleanup");
}

#[test]
fn injected_failures_before_and_after_lock_leave_no_retained_owner() {
    for step in [
        BootstrapStep::ProcessPolicy,
        BootstrapStep::NonRoot,
        BootstrapStep::SelectedState,
    ] {
        let root = root(match step {
            BootstrapStep::ProcessPolicy => "policy",
            BootstrapStep::NonRoot => "nonroot",
            BootstrapStep::SelectedState => "selected-state",
            _ => unreachable!("only selected probe steps"),
        });
        let adapter = RootLockBootstrapAdapter::new(
            RootLockAdapter::new(&root),
            Probe {
                steps: Vec::new(),
                fail_at: Some(step),
            },
        );

        assert!(matches!(
            bootstrap_owned(adapter),
            Err(BootstrapError::Rejected)
        ));
        assert!(StateOwnerLock::acquire(&root).is_ok());
        fs::remove_dir_all(root).expect("fixture cleanup");
    }
}
