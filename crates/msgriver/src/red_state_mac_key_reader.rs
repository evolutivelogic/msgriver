use super::{StateMacKeyReaderError, read_state_mac_key};
use crate::initialization_key_pair::{test_journal_integrity_key, test_state_mac_key_wire};
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
    reference: MacKeyRef,
}

impl Fixture {
    fn create() -> Self {
        let root = std::env::temp_dir().join(format!(
            "msgriver-state-mac-key-reader-red-{}-{}",
            std::process::id(),
            ROOT_SERIAL.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).expect("create isolated reader root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("set isolated reader root mode");

        let reference = reference();
        let key = test_journal_integrity_key([0x41; 32]);
        let fixture = Self {
            root,
            key,
            reference,
        };
        fixture.write(&test_state_mac_key_wire(&fixture.key, reference));
        fixture
    }

    fn write(&self, bytes: &[u8]) {
        let path = self.path();
        fs::create_dir_all(path.parent().expect("state-key parent"))
            .expect("create state-key directories");
        for directory in [self.root.join("mac"), self.root.join("mac/06")] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("set state-key directory mode");
        }
        fs::write(&path, bytes).expect("write state-key fixture");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("set state-key fixture mode");
    }

    fn path(&self) -> PathBuf {
        let path =
            state_mac_key_relative_path(self.reference).expect("derive state-key fixture path");
        self.root
            .join(std::str::from_utf8(&path.0).expect("ASCII state-key fixture path"))
    }

    fn read(
        &self,
    ) -> Result<crate::initialization_key_pair::StateMacKeySecret, StateMacKeyReaderError> {
        let root = std::ffi::CString::new(self.root.as_os_str().as_bytes())
            .expect("reader fixture root C string");
        let directory = rustix::fs::openat(
            rustix::fs::CWD,
            root.as_c_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open reader root descriptor");
        read_state_mac_key(directory.as_fd(), &self.key, self.reference)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn reference() -> MacKeyRef {
    let mut key_id = [0x22; 40];
    key_id[32..].copy_from_slice(&1_u64.to_be_bytes());
    MacKeyRef::new(MacPurpose::CommandLookupV1, MacKeyId::from_bytes(key_id))
}

fn require_reader(fixture: &Fixture) {
    match fixture.read() {
        Ok(_) => {}
        Err(StateMacKeyReaderError::MissingStateKeyReader) => {
            panic!("MissingStateKeyReader: read_state_mac_key")
        }
        Err(error) => panic!("unexpected reader error: {error:?}"),
    }
}

fn reject_reader(fixture: &Fixture) {
    match fixture.read() {
        Ok(_) => panic!("invalid state key read"),
        Err(StateMacKeyReaderError::MissingStateKeyReader) => {
            panic!("MissingStateKeyReader: read_state_mac_key")
        }
        Err(StateMacKeyReaderError::InvalidStateKeyReader) => {}
    }
}

#[test]
fn reader_opens_one_authenticated_owner_only_key_relative_to_descriptor() {
    require_reader(&Fixture::create());
}

#[test]
fn reader_rejects_leaf_and_intermediate_symlinks() {
    let leaf = Fixture::create();
    let target = leaf.root.join("target");
    fs::write(&target, test_state_mac_key_wire(&leaf.key, leaf.reference))
        .expect("write symlink target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
        .expect("set symlink target mode");
    fs::remove_file(leaf.path()).expect("remove fixture leaf");
    symlink(&target, leaf.path()).expect("create leaf symlink");
    reject_reader(&leaf);

    let intermediate = Fixture::create();
    let mac = intermediate.root.join("mac");
    let target_mac = intermediate.root.join("mac-target");
    fs::rename(&mac, &target_mac).expect("move intermediate directory");
    symlink("mac-target", &mac).expect("create intermediate symlink");
    reject_reader(&intermediate);
}

#[test]
fn reader_rejects_nonregular_and_wrong_length_entries() {
    let nonregular = Fixture::create();
    fs::remove_file(nonregular.path()).expect("remove fixture leaf");
    fs::create_dir(nonregular.path()).expect("create nonregular fixture");
    reject_reader(&nonregular);

    let wrong_length = Fixture::create();
    wrong_length.write(&[0x7a; 105]);
    reject_reader(&wrong_length);
}

#[test]
fn reader_collapses_authenticated_decoder_failure() {
    let fixture = Fixture::create();
    let mut invalid = test_state_mac_key_wire(&fixture.key, fixture.reference);
    invalid[105] ^= 1;
    fixture.write(&invalid);
    reject_reader(&fixture);
}

#[test]
fn reader_has_no_root_or_runtime_capability() {
    let source = include_str!("state_mac_key_reader.rs");
    for forbidden in [
        "std::fs",
        "Path",
        "Store",
        "active_state",
        "bootstrap",
        "publish",
        "service",
        "release",
        "tag",
    ] {
        assert!(
            !source.contains(forbidden),
            "reader must not gain {forbidden} capability"
        );
    }
    assert!(source.contains("BorrowedFd"));
    assert!(source.contains("MissingStateKeyReader"));
}
