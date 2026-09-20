use super::*;
use crate::initialization_key_pair::{
    JournalIntegrityKey,
    active_state_pointer::{
        ActiveStatePointer, PointerOrigin, decode_active_state_pointer, encode_active_state_pointer,
    },
    active_state_pointer_caller::{
        ActiveStatePointerCallerCapability, ActiveStatePointerCallerError, PointerRenamed,
    },
    test_journal_integrity_key,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

const TEMPORARY_NAME_DOMAIN: &[u8] = b"msgriver/active-state-pointer-temp/v1";
static ROOT_SERIAL: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: PathBuf,
    key: JournalIntegrityKey,
    pointer: ActiveStatePointer,
    capability: ActiveStatePointerCallerCapability,
}

impl Fixture {
    fn create() -> Self {
        let root = std::env::temp_dir().join(format!(
            "msgriver-active-state-publisher-red-{}-{}",
            std::process::id(),
            ROOT_SERIAL.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).expect("create isolated publisher root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("set isolated publisher root mode");
        let capability = ActiveStatePointerCallerCapability::acquire(&root)
            .expect("acquire isolated publisher capability");
        Self {
            root,
            key: test_journal_integrity_key([0x41; 32]),
            pointer: pointer("transition-17", "lineage-9"),
            capability,
        }
    }

    fn active_path(&self) -> PathBuf {
        self.root.join("active-state")
    }

    fn temporary_path(&self) -> PathBuf {
        self.root.join(temporary_basename(&self.pointer))
    }

    fn wire(&self) -> Vec<u8> {
        encode_active_state_pointer(&self.key, &self.pointer).expect("encode fixture pointer")
    }

    fn write_owner_only(&self, path: PathBuf, bytes: &[u8]) {
        fs::write(path.as_path(), bytes).expect("write fixture entry");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("set fixture entry mode");
    }

    fn publish(
        &mut self,
        mode: ActiveStatePointerPublicationMode,
    ) -> Result<PointerRenamed<'_>, ActiveStatePointerCallerError> {
        self.capability.publish(&self.key, &self.pointer, mode)
    }

    fn publish_with_fault(
        &mut self,
        mode: ActiveStatePointerPublicationMode,
        fault: PublisherTestFault,
    ) -> Result<PointerRenamed<'_>, ActiveStatePointerCallerError> {
        self.capability
            .publish_with_test_fault(&self.key, &self.pointer, mode, fault)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn pointer(transition: &str, lineage: &str) -> ActiveStatePointer {
    ActiveStatePointer {
        protocol_version: 7,
        transition_id: transition.to_owned(),
        final_generation: 9,
        lineage_id: lineage.to_owned(),
        target_history_epoch: [0x22; 32],
        origin: PointerOrigin::Restore,
        database_certificate_digest: [0x33; 32],
    }
}

fn temporary_basename(pointer: &ActiveStatePointer) -> String {
    let mut digest = Sha256::new();
    digest.update(TEMPORARY_NAME_DOMAIN);
    digest.update(pointer.transition_id.as_bytes());
    format!("active-state.tmp.{:x}", digest.finalize())
}

fn require_publish(result: Result<PointerRenamed<'_>, ActiveStatePointerCallerError>) {
    match result {
        Ok(_) => {}
        Err(ActiveStatePointerCallerError::MissingActiveStatePointerCallerPublication) => {
            panic!("MissingActiveStatePointerCallerPublication: publish")
        }
        Err(error) => panic!("unexpected caller publication error: {error:?}"),
    }
}

fn reject_publish(result: Result<PointerRenamed<'_>, ActiveStatePointerCallerError>) {
    match result {
        Ok(_) => panic!("unsafe pointer publication succeeded"),
        Err(ActiveStatePointerCallerError::MissingActiveStatePointerCallerPublication) => {
            panic!("MissingActiveStatePointerCallerPublication: publish")
        }
        Err(ActiveStatePointerCallerError::Publication(
            ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher,
        )) => {}
        Err(error) => panic!("unexpected caller publication error: {error:?}"),
    }
}

fn assert_owner_only_pointer(fixture: &Fixture) {
    let metadata = fs::metadata(fixture.active_path()).expect("published active-state metadata");
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(
        fs::read(fixture.active_path()).expect("published active-state"),
        fixture.wire()
    );
    decode_active_state_pointer(&fixture.key, &fixture.wire()).expect("published pointer decodes");
}

fn retained(path: &PathBuf) -> (u64, u64, usize, Vec<u8>) {
    let metadata = fs::symlink_metadata(path).expect("rejected entry metadata");
    (
        metadata.dev(),
        metadata.ino(),
        usize::try_from(metadata.size()).expect("fixture entry size"),
        fs::read(path).expect("rejected entry bytes"),
    )
}

#[test]
fn require_absent_publishes_one_owner_only_pointer_and_removes_its_temporary() {
    let mut fixture = Fixture::create();
    require_publish(fixture.publish(ActiveStatePointerPublicationMode::RequireAbsent));
    assert_owner_only_pointer(&fixture);
    assert!(!fixture.temporary_path().exists());
}

#[test]
fn replace_existing_requires_a_valid_existing_destination() {
    let mut replacement = Fixture::create();
    let old = pointer("old-transition", "old-lineage");
    let old_wire =
        encode_active_state_pointer(&replacement.key, &old).expect("encode valid existing pointer");
    replacement.write_owner_only(replacement.active_path(), &old_wire);
    require_publish(replacement.publish(ActiveStatePointerPublicationMode::ReplaceExisting));
    assert_owner_only_pointer(&replacement);

    let mut absent = Fixture::create();
    reject_publish(absent.publish(ActiveStatePointerPublicationMode::ReplaceExisting));
    assert!(!absent.active_path().exists());
}

#[test]
fn exact_same_certificate_leftover_temporary_is_reused() {
    let mut fixture = Fixture::create();
    fixture.write_owner_only(fixture.temporary_path(), &fixture.wire());
    require_publish(fixture.publish(ActiveStatePointerPublicationMode::RequireAbsent));
    assert_owner_only_pointer(&fixture);
    assert!(!fixture.temporary_path().exists());
}

#[test]
fn rejected_temporary_and_destination_entries_are_preserved_byte_for_byte() {
    for kind in ["different", "wrong-mode", "linked"] {
        let mut fixture = Fixture::create();
        let temporary = fixture.temporary_path();
        fixture.write_owner_only(temporary.clone(), b"different certificate");
        if kind == "wrong-mode" {
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644))
                .expect("set wrong temporary mode");
        }
        if kind == "linked" {
            fs::hard_link(&temporary, fixture.root.join("linked-temporary"))
                .expect("create linked temporary");
        }
        let before = retained(&temporary);
        reject_publish(fixture.publish(ActiveStatePointerPublicationMode::RequireAbsent));
        assert_eq!(retained(&temporary), before, "temporary kind {kind}");
    }

    let mut fixture = Fixture::create();
    fixture.write_owner_only(fixture.active_path(), b"not a pointer");
    fs::set_permissions(fixture.active_path(), fs::Permissions::from_mode(0o644))
        .expect("set invalid destination mode");
    let before = retained(&fixture.active_path());
    reject_publish(fixture.publish(ActiveStatePointerPublicationMode::ReplaceExisting));
    assert_eq!(retained(&fixture.active_path()), before);
}

#[test]
fn absent_collision_and_no_replace_failure_never_select_replacement_or_fallback() {
    let mut collision = Fixture::create();
    collision.write_owner_only(collision.active_path(), b"existing pointer must remain");
    let before = retained(&collision.active_path());
    reject_publish(collision.publish(ActiveStatePointerPublicationMode::RequireAbsent));
    assert_eq!(retained(&collision.active_path()), before);

    let mut unavailable = Fixture::create();
    reject_publish(unavailable.publish_with_fault(
        ActiveStatePointerPublicationMode::RequireAbsent,
        PublisherTestFault::RenameNoReplace,
    ));
    assert!(!unavailable.active_path().exists());
}

#[test]
fn temporary_and_root_fsync_failures_are_closed_before_success() {
    for fault in [
        PublisherTestFault::TemporaryFsync,
        PublisherTestFault::RootFsync,
    ] {
        let mut fixture = Fixture::create();
        reject_publish(
            fixture.publish_with_fault(ActiveStatePointerPublicationMode::RequireAbsent, fault),
        );
    }
}

#[test]
fn publisher_is_private_descriptor_bound_and_derives_only_a_fixed_basename() {
    let fixture = Fixture::create();
    let temporary = temporary_basename(&fixture.pointer);
    assert_eq!(temporary.len(), "active-state.tmp.".len() + 64);
    assert!(temporary.starts_with("active-state.tmp."));
    assert!(temporary.bytes().all(|byte| byte.is_ascii_lowercase()
        || byte.is_ascii_digit()
        || byte == b'.'
        || byte == b'-'));
    assert!(!temporary.contains('/'));

    let source = include_str!("active_state_pointer_publisher.rs");
    for forbidden in [
        "std::fs",
        "Path",
        "StateOwnerLock",
        "open_private_root",
        "sqlite",
        "journal mutation",
        "provider",
        "service",
        "api",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden publisher surface: {forbidden}"
        );
    }
    assert!(source.contains("BorrowedFd"));
    assert!(source.contains("active_state_pointer_publisher"));
    assert!(source.contains("FRONTIER: active_state_pointer_publisher"));
}
