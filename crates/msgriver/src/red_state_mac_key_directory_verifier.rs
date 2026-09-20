use super::{StateMacKeyDirectoryVerifierError, verify_state_mac_key_directory};
use crate::initialization_key_pair::{test_journal_integrity_key, test_state_mac_key_wire};
use crate::state_mac_key_manifest_row::{StateMacKeyManifestRow, StateMacKeyManifestStatus};
use crate::state_mac_key_path::state_mac_key_relative_path;
use msgriver_core::canon::{MacKeyId, MacKeyRef, MacPurpose};
use rustix::fd::AsFd;
use rustix::fs::{Mode, OFlags};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

static ROOT_SERIAL: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: PathBuf,
    key: crate::initialization_key_pair::JournalIntegrityKey,
    rows: Vec<StateMacKeyManifestRow>,
}

impl Fixture {
    fn complete(rows_per_purpose: u64) -> Self {
        let root = std::env::temp_dir().join(format!(
            "msgriver-state-mac-key-directory-verifier-red-{}-{}",
            std::process::id(),
            ROOT_SERIAL.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).expect("create isolated verifier root");
        set_mode(&root, 0o700);
        fs::create_dir(root.join("mac")).expect("create state-key namespace");
        set_mode(&root.join("mac"), 0o700);

        let mut rows = Vec::new();
        for purpose_byte in 1..=11 {
            let directory = root.join("mac").join(format!("{purpose_byte:02x}"));
            fs::create_dir(&directory).expect("create closed purpose directory");
            set_mode(&directory, 0o700);
            for serial in 1..=rows_per_purpose {
                rows.push(row(purpose_byte, serial));
            }
        }

        let fixture = Self {
            root,
            key: test_journal_integrity_key([0x41; 32]),
            rows,
        };
        for row in &fixture.rows {
            fixture.write(row.reference);
        }
        fixture
    }

    fn write(&self, reference: MacKeyRef) {
        let path = self.path(reference);
        fs::write(&path, test_state_mac_key_wire(&self.key, reference))
            .expect("write authenticated state-key fixture");
        set_mode(&path, 0o600);
    }

    fn path(&self, reference: MacKeyRef) -> PathBuf {
        let path = state_mac_key_relative_path(reference).expect("derive fixture path");
        self.root
            .join(std::str::from_utf8(&path.0).expect("ASCII state-key fixture path"))
    }

    fn purpose_directory(&self, purpose_byte: u8) -> PathBuf {
        self.root.join("mac").join(format!("{purpose_byte:02x}"))
    }

    fn verify(&self) -> Result<(), StateMacKeyDirectoryVerifierError> {
        let root = std::ffi::CString::new(self.root.as_os_str().as_bytes())
            .expect("verifier fixture root C string");
        let generation = rustix::fs::openat(
            rustix::fs::CWD,
            root.as_c_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open verifier generation descriptor");
        verify_state_mac_key_directory(generation.as_fd(), &self.key, &self.rows)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn set_mode(path: &std::path::Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set fixture mode");
}

fn purpose(byte: u8) -> MacPurpose {
    match byte {
        1 => MacPurpose::ApiKeyVerifyV1,
        2 => MacPurpose::IdempotencyLookupV1,
        3 => MacPurpose::IdempotencyFingerprintV1,
        4 => MacPurpose::ReplayLookupV1,
        5 => MacPurpose::ReplayFingerprintV1,
        6 => MacPurpose::CommandLookupV1,
        7 => MacPurpose::CommandSemanticFingerprintV1,
        8 => MacPurpose::CommandPhaseFingerprintV1,
        9 => MacPurpose::RetryJitterV1,
        10 => MacPurpose::ArtifactInternalAuthV1,
        11 => MacPurpose::PortableReservationV1,
        _ => panic!("test purpose must be closed"),
    }
}

fn row(purpose_byte: u8, serial: u64) -> StateMacKeyManifestRow {
    let mut key_id = [purpose_byte; 40];
    key_id[32..].copy_from_slice(&serial.to_be_bytes());
    StateMacKeyManifestRow {
        reference: MacKeyRef::new(purpose(purpose_byte), MacKeyId::from_bytes(key_id)),
        status: StateMacKeyManifestStatus::Active,
        created_at: 0,
    }
}

fn require(fixture: &Fixture) {
    match fixture.verify() {
        Ok(()) => {}
        Err(StateMacKeyDirectoryVerifierError::MissingStateMacKeyDirectoryVerifier) => {
            panic!("MissingStateMacKeyDirectoryVerifier: state_mac_key_directory_verifier")
        }
        Err(error) => panic!("complete state-key tree rejected: {error:?}"),
    }
}

fn reject(fixture: &Fixture) {
    match fixture.verify() {
        Ok(()) => panic!("invalid state-key directory accepted"),
        Err(StateMacKeyDirectoryVerifierError::MissingStateMacKeyDirectoryVerifier) => {
            panic!("MissingStateMacKeyDirectoryVerifier: state_mac_key_directory_verifier")
        }
        Err(StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier) => {}
    }
}

#[test]
fn verifier_accepts_the_exact_eleven_purpose_tree_without_a_secret_return() {
    require(&Fixture::complete(1));
}

#[test]
fn verifier_accepts_the_exact_eleven_by_sixteen_manifest_boundary() {
    require(&Fixture::complete(16));
}

#[test]
fn verifier_rejects_extra_or_missing_namespace_and_purpose_entries() {
    let extra_namespace = Fixture::complete(1);
    fs::write(extra_namespace.root.join("mac/.unexpected"), b"x")
        .expect("write unexpected namespace entry");
    reject(&extra_namespace);

    let missing_purpose = Fixture::complete(1);
    let directory = missing_purpose.purpose_directory(3);
    fs::remove_file(missing_purpose.path(missing_purpose.rows[2].reference))
        .expect("remove required leaf before purpose removal");
    fs::remove_dir(directory).expect("remove required purpose directory");
    reject(&missing_purpose);

    let missing_leaf = Fixture::complete(1);
    fs::remove_file(missing_leaf.path(missing_leaf.rows[7].reference))
        .expect("remove required state-key leaf");
    reject(&missing_leaf);
}

#[test]
fn verifier_rejects_non_directory_or_linked_intermediates_and_nested_entries() {
    let regular = Fixture::complete(1);
    let directory = regular.purpose_directory(4);
    fs::remove_file(regular.path(regular.rows[3].reference)).expect("remove regular leaf");
    fs::remove_dir(&directory).expect("remove purpose directory");
    fs::write(&directory, b"not a directory").expect("replace purpose with regular file");
    reject(&regular);

    let linked = Fixture::complete(1);
    let directory = linked.purpose_directory(5);
    let target = linked.root.join("purpose-target");
    fs::rename(&directory, &target).expect("move purpose directory");
    symlink("purpose-target", &directory).expect("replace purpose with symlink");
    reject(&linked);

    let nested = Fixture::complete(1);
    fs::create_dir(nested.purpose_directory(6).join("nested"))
        .expect("create forbidden nested directory");
    reject(&nested);
}

#[test]
fn verifier_rejects_invalid_or_replaced_expected_leaf() {
    let invalid_hmac = Fixture::complete(1);
    let reference = invalid_hmac.rows[0].reference;
    let mut wire = test_state_mac_key_wire(&invalid_hmac.key, reference);
    wire[105] ^= 1;
    fs::write(invalid_hmac.path(reference), wire).expect("replace fixture with invalid HMAC");
    set_mode(&invalid_hmac.path(reference), 0o600);
    reject(&invalid_hmac);

    let wrong_mode = Fixture::complete(1);
    set_mode(&wrong_mode.path(wrong_mode.rows[1].reference), 0o644);
    reject(&wrong_mode);

    let nonregular = Fixture::complete(1);
    let path = nonregular.path(nonregular.rows[2].reference);
    fs::remove_file(&path).expect("remove expected leaf");
    fs::create_dir(&path).expect("replace expected leaf with directory");
    reject(&nonregular);
}

#[test]
fn verifier_rejects_duplicate_or_over_bound_manifest_expectations_before_scan() {
    let mut duplicate = Fixture::complete(1);
    duplicate.rows.push(row(1, 1));
    reject(&duplicate);

    let over_bound = Fixture::complete(17);
    reject(&over_bound);
}

#[test]
fn verifier_keeps_the_descriptor_only_redacted_no_provider_boundary() {
    let source = include_str!("state_mac_key_directory_verifier.rs");
    for forbidden in [
        "std::fs",
        "Path",
        "Store",
        "SQLite",
        "bootstrap",
        "publish_",
        "MacProvider",
        "service",
        "release",
    ] {
        assert!(
            !source.contains(forbidden),
            "directory verifier must not gain {forbidden} capability"
        );
    }
    assert!(source.contains("BorrowedFd"));
    assert!(source.contains("MissingStateMacKeyDirectoryVerifier"));
}
