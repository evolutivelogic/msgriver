use super::*;
use crate::initialization_key_pair::{
    active_state_pointer::{ActiveStatePointer, PointerOrigin, decode_active_state_pointer},
    active_state_pointer_publisher::ActiveStatePointerPublicationMode,
    test_journal_integrity_key,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};

static SERIAL: AtomicUsize = AtomicUsize::new(0);

#[test]
fn retained_caller_capability_is_the_only_missing_frontier() {
    let root = std::env::temp_dir().join(format!(
        "msgriver-active-state-caller-red-{}-{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed),
    ));
    fs::create_dir(&root).expect("create isolated caller root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("set isolated caller root mode");
    match ActiveStatePointerCallerCapability::acquire(&root) {
        Err(ActiveStatePointerCallerError::MissingActiveStatePointerCallerCapability) => {
            let _ = fs::remove_dir_all(&root);
            panic!("MissingActiveStatePointerCallerCapability: acquire");
        }
        Err(error) => {
            let _ = fs::remove_dir_all(&root);
            panic!("unexpected caller capability error: {error:?}");
        }
        Ok(capability) => {
            drop(capability);
            fs::remove_dir_all(&root).expect("remove isolated caller root");
        }
    }
}

#[test]
fn capability_exclusively_publishes_the_renamed_pointer_observation() {
    let root = std::env::temp_dir().join(format!(
        "msgriver-active-state-caller-publication-red-{}-{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed),
    ));
    fs::create_dir(&root).expect("create isolated caller publication root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("set isolated caller publication root mode");
    let key = test_journal_integrity_key([0x41; 32]);
    let pointer = ActiveStatePointer {
        protocol_version: 7,
        transition_id: "caller-transition-17".to_owned(),
        final_generation: 9,
        lineage_id: "caller-lineage-9".to_owned(),
        target_history_epoch: [0x22; 32],
        origin: PointerOrigin::Restore,
        database_certificate_digest: [0x33; 32],
    };
    let mut capability = ActiveStatePointerCallerCapability::acquire(&root)
        .expect("acquire isolated caller publication capability");
    match capability.publish(
        &key,
        &pointer,
        ActiveStatePointerPublicationMode::RequireAbsent,
    ) {
        Err(ActiveStatePointerCallerError::MissingActiveStatePointerCallerPublication) => {
            drop(capability);
            let _ = fs::remove_dir_all(&root);
            panic!("MissingActiveStatePointerCallerPublication: publish");
        }
        Err(error) => panic!("unexpected caller publication error: {error:?}"),
        Ok(observation) => {
            drop(observation);
            let wire = fs::read(root.join("active-state")).expect("read published pointer");
            assert_eq!(
                decode_active_state_pointer(&key, &wire).expect("decode published pointer"),
                pointer
            );
            drop(capability);
            fs::remove_dir_all(&root).expect("remove isolated caller publication root");
        }
    }
}

#[test]
fn caller_publication_signature_carries_an_exclusive_capability_borrow() {
    let source = include_str!("active_state_pointer_caller.rs");
    assert!(source.contains("fn publish<'capability>("));
    assert!(source.contains("&'capability mut self"));
    assert!(source.contains("PointerRenamed<'capability>"));
    assert!(source.contains("PhantomData<&'capability mut ActiveStatePointerCallerCapability>"));
}
