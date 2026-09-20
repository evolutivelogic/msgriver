use super::active_state_pointer_coordinator::{
    ActiveStatePointerCoordinatorError, PreTerminalCoordinator,
};
use super::*;
use crate::initialization_key_pair::{
    active_state_pointer::{ActiveStatePointer, PointerOrigin},
    active_state_pointer_publisher::ActiveStatePointerPublicationMode,
    test_journal_integrity_key,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};

static SERIAL: AtomicUsize = AtomicUsize::new(0);

fn pointer() -> ActiveStatePointer {
    ActiveStatePointer {
        protocol_version: 7,
        transition_id: "coordinator-transition-17".to_owned(),
        final_generation: 9,
        lineage_id: "coordinator-lineage-9".to_owned(),
        target_history_epoch: [0x22; 32],
        origin: PointerOrigin::Restore,
        database_certificate_digest: [0x33; 32],
    }
}

#[test]
fn renamed_observation_enters_one_root_bound_coordinator_with_exact_pointer_facts() {
    let root = std::env::temp_dir().join(format!(
        "msgriver-active-state-coordinator-red-{}-{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed),
    ));
    fs::create_dir(&root).expect("create isolated coordinator root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("set isolated coordinator root mode");
    let key = test_journal_integrity_key([0x41; 32]);
    let pointer = pointer();
    let mut capability = ActiveStatePointerCallerCapability::acquire(&root)
        .expect("acquire isolated coordinator capability");
    let renamed = capability
        .publish(
            &key,
            &pointer,
            ActiveStatePointerPublicationMode::RequireAbsent,
        )
        .expect("publish pointer before coordinator handoff");
    let coordinator = match PreTerminalCoordinator::enter(renamed, &pointer) {
        Err(ActiveStatePointerCoordinatorError::MissingActiveStatePointerCoordinator) => {
            drop(capability);
            let _ = fs::remove_dir_all(&root);
            panic!("MissingActiveStatePointerCoordinator: enter");
        }
        Ok(coordinator) => coordinator,
    };
    let handle = match coordinator.pointer_named_generation() {
        Err(ActiveStatePointerCoordinatorError::MissingActiveStatePointerCoordinator) => {
            drop(capability);
            let _ = fs::remove_dir_all(&root);
            panic!("MissingActiveStatePointerCoordinator: handle");
        }
        Ok(handle) => handle,
    };
    assert_eq!(handle.final_generation(), pointer.final_generation);
    assert_ne!(handle.final_generation(), 0);
    assert_eq!(
        handle.certificate_digest(),
        pointer.database_certificate_digest
    );
    fs::remove_dir_all(&root).expect("remove isolated coordinator root");
}

#[test]
fn coordinator_source_stays_private_root_bound_and_has_no_lower_boundary_authority() {
    let caller = include_str!("active_state_pointer_caller.rs");
    let source = include_str!("active_state_pointer_coordinator.rs");
    assert!(caller.contains("BorrowedFd<'capability>"));
    assert!(caller.contains("PointerRenamed<'capability>"));
    assert!(source.contains("FRONTIER: active_state_pointer_coordinator"));
    assert!(source.contains("PreTerminalCoordinator"));
    assert!(source.contains("PointerNamedGeneration"));
    for forbidden in [
        "openat",
        "std::fs",
        "Path",
        "sqlite",
        "journal",
        "PostRenameValidated",
        "selection",
        "cleanup",
        "response",
        "provider",
        "service",
        "api",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden coordinator surface: {forbidden}"
        );
    }
}
