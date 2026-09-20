//! Frozen Task 0066 RED: policy and UID precede trusted-root ownership.

#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use msgriver::{
    StateOwnerLock,
    service_bootstrap::{
        BootstrapAdapter, BootstrapAdapterError, BootstrapError, BootstrapProcessPrimitive,
        BootstrapStep, LinuxProcessBootstrapAdapter, RootLockAdapter, RootLockBootstrapAdapter,
        bootstrap_owned,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessStep {
    Policy,
    NonRoot,
}

#[derive(Default)]
struct ProcessProbe {
    steps: Vec<ProcessStep>,
    fail_at: Option<ProcessStep>,
}

impl BootstrapProcessPrimitive for ProcessProbe {
    fn apply_policy(&mut self) -> Result<(), BootstrapAdapterError> {
        self.steps.push(ProcessStep::Policy);
        if self.fail_at == Some(ProcessStep::Policy) {
            Err(BootstrapAdapterError::Failed)
        } else {
            Ok(())
        }
    }

    fn require_non_root(&mut self) -> Result<(), BootstrapAdapterError> {
        self.steps.push(ProcessStep::NonRoot);
        if self.fail_at == Some(ProcessStep::NonRoot) {
            Err(BootstrapAdapterError::Failed)
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct DelegateProbe {
    steps: Vec<BootstrapStep>,
    fail_at: Option<BootstrapStep>,
}

impl BootstrapAdapter for DelegateProbe {
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
        std::env::temp_dir().join(format!("msgriver-task0066-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir(&path).expect("private root fixture");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .expect("private root permissions");
    path
}

fn composed(
    root: &std::path::Path,
    process: ProcessProbe,
    delegate: DelegateProbe,
) -> RootLockBootstrapAdapter<LinuxProcessBootstrapAdapter<ProcessProbe, DelegateProbe>> {
    RootLockBootstrapAdapter::new(
        RootLockAdapter::new(root),
        LinuxProcessBootstrapAdapter::new(process, delegate),
    )
}

#[test]
fn full_composition_orders_process_uid_root_lock_then_remaining_steps() {
    let root = root("full-order");
    let runtime = bootstrap_owned(composed(
        &root,
        ProcessProbe::default(),
        DelegateProbe::default(),
    ))
    .expect("complete injected composition");

    assert_eq!(
        runtime.adapter().delegate().primitive().steps,
        [ProcessStep::Policy, ProcessStep::NonRoot]
    );
    assert_eq!(
        runtime.adapter().delegate().delegate().steps,
        [
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
fn root_lock_wrapper_refuses_out_of_order_and_guard_failures_without_locking() {
    let root = root("ordered-refusal");
    let mut adapter = composed(&root, ProcessProbe::default(), DelegateProbe::default());
    assert_eq!(
        adapter.run(BootstrapStep::NonRoot),
        Err(BootstrapAdapterError::Failed)
    );
    assert_eq!(
        adapter.run(BootstrapStep::TrustedRoot),
        Err(BootstrapAdapterError::Failed)
    );
    assert_eq!(
        adapter.run(BootstrapStep::OwnerLock),
        Err(BootstrapAdapterError::Failed)
    );
    assert!(StateOwnerLock::acquire(&root).is_ok());
    drop(adapter);

    for failed_guard in [ProcessStep::Policy, ProcessStep::NonRoot] {
        let adapter = composed(
            &root,
            ProcessProbe {
                steps: Vec::new(),
                fail_at: Some(failed_guard),
            },
            DelegateProbe::default(),
        );
        assert!(matches!(
            bootstrap_owned(adapter),
            Err(BootstrapError::Rejected)
        ));
        assert!(StateOwnerLock::acquire(&root).is_ok());
    }
    fs::remove_dir_all(root).expect("fixture cleanup");
}

#[test]
fn later_delegate_failure_releases_the_lock_after_both_process_guards() {
    let root = root("later-failure");
    let adapter = composed(
        &root,
        ProcessProbe::default(),
        DelegateProbe {
            steps: Vec::new(),
            fail_at: Some(BootstrapStep::SelectedState),
        },
    );
    assert!(matches!(
        bootstrap_owned(adapter),
        Err(BootstrapError::Rejected)
    ));
    assert!(StateOwnerLock::acquire(&root).is_ok());
    fs::remove_dir_all(root).expect("fixture cleanup");
}
