use super::super::{super::ActiveStatePointerCallerCapability, PreTerminalCoordinator};
use super::{ActiveStatePointerGenerationReopenError, PointerReopenedGeneration};
use crate::initialization_key_pair::{
    active_state_pointer::{ActiveStatePointer, PointerOrigin},
    active_state_pointer_publisher::ActiveStatePointerPublicationMode,
    test_journal_integrity_key,
};
use rustix::fs;
use std::fs as stdfs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static SERIAL: AtomicUsize = AtomicUsize::new(0);
enum Observed {
    Missing,
    Rejected,
    Candidate { device: u64, inode: u64 },
}

fn pointer() -> ActiveStatePointer {
    ActiveStatePointer {
        protocol_version: 7,
        transition_id: "reopen-transition".to_owned(),
        final_generation: 0x0000_0000_0abc_def0,
        lineage_id: "reopen-lineage".to_owned(),
        target_history_epoch: [0x22; 32],
        origin: PointerOrigin::Restore,
        database_certificate_digest: [0x33; 32],
    }
}
fn fresh_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "msgriver-active-state-reopen-red-{}-{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ))
}
fn mode_700(path: &Path) {
    stdfs::set_permissions(path, stdfs::Permissions::from_mode(0o700)).expect("set directory mode");
}
fn standard_root() -> (PathBuf, PathBuf, PathBuf) {
    let root = fresh_root();
    let generations = root.join("generations");
    let candidate = generations.join("g-000000000abcdef0");
    stdfs::create_dir_all(&candidate).expect("create exact candidate");
    for p in [&root, &generations, &candidate] {
        mode_700(p);
    }
    (root, generations, candidate)
}

fn observe(root: &Path) -> Observed {
    let key = test_journal_integrity_key([0x41; 32]);
    let pointer = pointer();
    let mut capability =
        ActiveStatePointerCallerCapability::acquire(root).expect("acquire capability");
    let renamed = capability
        .publish(
            &key,
            &pointer,
            ActiveStatePointerPublicationMode::RequireAbsent,
        )
        .expect("publish pointer");
    let coordinator = PreTerminalCoordinator::enter(renamed, &pointer).expect("enter coordinator");
    let handle = coordinator
        .pointer_named_generation()
        .expect("derive handle");
    match handle.reopen_candidate() {
        Err(ActiveStatePointerGenerationReopenError::MissingCandidateReopen) => Observed::Missing,
        Err(ActiveStatePointerGenerationReopenError::RejectedCandidateReopen) => Observed::Rejected,
        Ok(PointerReopenedGeneration { _candidate, .. }) => {
            let m = fs::fstat(&_candidate).expect("candidate metadata");
            Observed::Candidate {
                device: m.st_dev,
                inode: m.st_ino,
            }
        }
    }
}
fn expect_candidate(root: &Path, candidate: &Path, case: &str) {
    let m = stdfs::metadata(candidate).expect("candidate metadata");
    let observed = observe(root);
    let _ = stdfs::remove_dir_all(root);
    match observed {
        Observed::Missing => panic!("MissingCandidateReopen: {case}"),
        Observed::Rejected => panic!("unexpected rejection: {case}"),
        Observed::Candidate { device, inode } => assert_eq!(
            (device, inode),
            (m.dev(), m.ino()),
            "candidate identity: {case}"
        ),
    }
}
fn expect_rejected(root: &Path, case: &str) {
    let observed = observe(root);
    let _ = stdfs::remove_dir_all(root);
    match observed {
        Observed::Missing => panic!("MissingCandidateReopen: {case}"),
        Observed::Rejected => {}
        Observed::Candidate { .. } => panic!("unexpected candidate acceptance: {case}"),
    }
}

#[test]
fn exact_private_candidate_reopen_is_a_named_missing_frontier() {
    let (root, _, candidate) = standard_root();
    expect_candidate(&root, &candidate, "exact private candidate");
}
#[test]
fn alternate_generation_never_substitutes_for_the_authenticated_name() {
    let root = fresh_root();
    let g = root.join("generations");
    let a = g.join("g-000000000abcdef1");
    stdfs::create_dir_all(&a).expect("create alternate");
    for p in [&root, &g, &a] {
        mode_700(p);
    }
    expect_rejected(&root, "alternate generation");
}
#[test]
fn missing_generations_child_is_a_named_missing_frontier() {
    let root = fresh_root();
    stdfs::create_dir(&root).expect("root");
    mode_700(&root);
    expect_rejected(&root, "missing generations");
}
#[test]
fn missing_exact_candidate_is_a_named_missing_frontier() {
    let root = fresh_root();
    let g = root.join("generations");
    stdfs::create_dir_all(&g).expect("generations");
    mode_700(&root);
    mode_700(&g);
    expect_rejected(&root, "missing exact candidate");
}
#[test]
fn generations_symlink_is_a_named_missing_frontier() {
    let root = fresh_root();
    let outside = root.join("outside");
    let expected = outside.join("g-000000000abcdef0");
    stdfs::create_dir_all(&expected).expect("outside candidate");
    for p in [&root, &outside, &expected] {
        mode_700(p);
    }
    symlink(&outside, root.join("generations")).expect("generations symlink");
    expect_rejected(&root, "generations symlink");
}
#[test]
fn candidate_symlink_is_a_named_missing_frontier() {
    let (root, _, candidate) = standard_root();
    stdfs::remove_dir(&candidate).expect("remove candidate");
    let outside = root.join("outside");
    stdfs::create_dir(&outside).expect("outside");
    mode_700(&outside);
    symlink(&outside, &candidate).expect("candidate symlink");
    expect_rejected(&root, "candidate symlink");
}
#[test]
fn generations_non_directory_is_a_named_missing_frontier() {
    let root = fresh_root();
    stdfs::create_dir(&root).expect("root");
    mode_700(&root);
    stdfs::write(root.join("generations"), b"not directory").expect("file");
    expect_rejected(&root, "generations non-directory");
}
#[test]
fn candidate_non_directory_is_a_named_missing_frontier() {
    let root = fresh_root();
    let g = root.join("generations");
    stdfs::create_dir_all(&g).expect("generations");
    mode_700(&root);
    mode_700(&g);
    stdfs::write(g.join("g-000000000abcdef0"), b"not directory").expect("file");
    expect_rejected(&root, "candidate non-directory");
}
#[test]
fn generations_wrong_mode_is_a_named_missing_frontier() {
    let (root, g, _) = standard_root();
    stdfs::set_permissions(&g, stdfs::Permissions::from_mode(0o755)).expect("wrong mode");
    expect_rejected(&root, "generations wrong mode");
}
#[test]
fn candidate_wrong_mode_is_a_named_missing_frontier() {
    let (root, _, c) = standard_root();
    stdfs::set_permissions(&c, stdfs::Permissions::from_mode(0o755)).expect("wrong mode");
    expect_rejected(&root, "candidate wrong mode");
}

#[test]
fn reopen_remains_anchored_to_the_retained_operational_descriptor() {
    let (root, _, candidate) = standard_root();
    let expected = stdfs::metadata(&candidate).expect("candidate metadata");
    let retained = root.with_extension("retained");
    let key = test_journal_integrity_key([0x41; 32]);
    let pointer = pointer();
    let observed = {
        let mut capability =
            ActiveStatePointerCallerCapability::acquire(&root).expect("capability");
        let renamed = capability
            .publish(
                &key,
                &pointer,
                ActiveStatePointerPublicationMode::RequireAbsent,
            )
            .expect("publish");
        let coordinator = PreTerminalCoordinator::enter(renamed, &pointer).expect("coordinator");
        let handle = coordinator.pointer_named_generation().expect("handle");
        stdfs::rename(&root, &retained).expect("rename root");
        stdfs::create_dir(&root).expect("replacement root");
        mode_700(&root);
        match handle.reopen_candidate() {
            Err(ActiveStatePointerGenerationReopenError::MissingCandidateReopen) => {
                Observed::Missing
            }
            Err(ActiveStatePointerGenerationReopenError::RejectedCandidateReopen) => {
                Observed::Rejected
            }
            Ok(PointerReopenedGeneration { _candidate, .. }) => {
                let m = fs::fstat(&_candidate).expect("metadata");
                Observed::Candidate {
                    device: m.st_dev,
                    inode: m.st_ino,
                }
            }
        }
    };
    let _ = stdfs::remove_dir_all(&root);
    let _ = stdfs::remove_dir_all(&retained);
    match observed {
        Observed::Missing => panic!("MissingCandidateReopen: retained descriptor anchor"),
        Observed::Rejected => panic!("unexpected retained descriptor rejection"),
        Observed::Candidate { device, inode } => {
            assert_eq!((device, inode), (expected.dev(), expected.ino()))
        }
    }
}

#[test]
fn reopen_scaffold_stays_private_and_preserves_the_task0128_test() {
    let source = include_str!("active_state_pointer_generation_reopen.rs");
    let frozen = include_str!("red_active_state_pointer_coordinator.rs");
    assert!(source.contains("PointerReopenedGeneration<'handle, 'coordinator, 'capability>"));
    assert!(source.contains("PhantomData<&'handle PointerNamedGeneration"));
    assert!(source.contains("fn reopen_candidate<'handle>("));
    assert!(source.contains("_candidate: OwnedFd"));
    assert!(source.contains("MissingCandidateReopen"));
    assert!(source.contains("RejectedCandidateReopen"));
    assert!(frozen.contains("coordinator_source_stays_private_root_bound"));
    for forbidden in [
        "pub(crate)",
        "pub ",
        "fn candidate",
        "sqlite",
        "journal",
        "selection",
        "service",
        "api",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden reopen surface: {forbidden}"
        );
    }
}
