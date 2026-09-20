//! Frozen Task 0014 contract for private fixed-root key-pair loading.
//!
//! The only RED failure accepted by the worker is the named load frontier.
//! Once that body is implemented, the same tests require real retained-lock,
//! descriptor-relative validation and read behavior; they are not a mock-only
//! success path.

use super::super::{InitializationKeyPair, JournalIntegrityKey, PortableReservationKey};
use super::*;
use std::cell::RefCell;
use std::error::Error;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::{ZeroizeOnDrop, Zeroizing};

const J: InitializationKeyRole = InitializationKeyRole::JournalIntegrity;
const R: InitializationKeyRole = InitializationKeyRole::PortableReservation;
const TEMPORARIES: [&str; 2] = [
    ".initialization-journal-integrity.tmp",
    ".initialization-portable-reservation.tmp",
];
const FINALS: [&str; 2] = [
    "initialization-journal-integrity.key",
    "initialization-portable-reservation.key",
];
const JOURNAL: [u8; 32] = [0x35; 32];
const RESERVATION: [u8; 32] = [0xa9; 32];
const WORKER: &str = "initialization_key_pair::publication::red_load::worker";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Boundary(LoadStep, Phase),
}

type Trace = Rc<RefCell<Vec<Event>>>;

fn marker(signals: &Path, name: &str, text: &str) {
    fs::write(signals.join(name), text).expect("write secret-free load marker");
}

fn expected_trace() -> Vec<Event> {
    let mut trace = Vec::new();
    for step in [
        LoadStep::Policy,
        LoadStep::Guard,
        LoadStep::Lock,
        LoadStep::OpenRoot,
        LoadStep::TemporaryPreflight(0),
        LoadStep::TemporaryPreflight(1),
        LoadStep::Open(J),
        LoadStep::Read(J),
        LoadStep::Verify(J),
        LoadStep::Open(R),
        LoadStep::Read(R),
        LoadStep::Verify(R),
    ] {
        trace.extend([
            Event::Boundary(step, Phase::Before),
            Event::Boundary(step, Phase::After),
        ]);
    }
    trace
}

struct Hooks {
    case: String,
    root: PathBuf,
    trace: Trace,
    retained_identity: Option<(u64, u64)>,
}

impl LoadHooks for Hooks {
    fn at(
        &mut self,
        step: LoadStep,
        phase: Phase,
        directory: Option<BorrowedFd<'_>>,
    ) -> LoadDirective {
        self.trace.borrow_mut().push(Event::Boundary(step, phase));
        let needs_directory = matches!(
            step,
            LoadStep::TemporaryPreflight(_)
                | LoadStep::Open(_)
                | LoadStep::Read(_)
                | LoadStep::Verify(_)
        ) || (step == LoadStep::OpenRoot && phase == Phase::After);
        assert_eq!(
            directory.is_some(),
            needs_directory,
            "directory observation contract"
        );
        if let Some(fd) = directory {
            let metadata = rustix::fs::fstat(fd).expect("directory descriptor metadata");
            let identity = (metadata.st_dev, metadata.st_ino);
            if let Some(expected) = self.retained_identity {
                assert_eq!(identity, expected, "loader reopened the root");
            } else {
                let root = fs::symlink_metadata(&self.root).expect("root metadata");
                assert_eq!(
                    identity,
                    (root.dev(), root.ino()),
                    "descriptor/root identity"
                );
                self.retained_identity = Some(identity);
            }
            assert_eq!(metadata.st_mode & 0o7777, 0o700, "private root mode");
        }
        if self.case == "rebind" && step == LoadStep::OpenRoot && phase == Phase::After {
            fs::rename(&self.root, self.root.with_extension("anchored")).expect("anchor root");
            fs::create_dir(&self.root).expect("decoy root");
            fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700)).expect("decoy mode");
        }
        if self.case == "preopen-rebind" && step == LoadStep::Lock && phase == Phase::After {
            fs::rename(&self.root, self.root.with_extension("anchored")).expect("anchor root");
            fs::create_dir(&self.root).expect("decoy root");
            fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700)).expect("decoy mode");
        }
        if self.case == "read-error" && matches!(step, LoadStep::Read(_)) && phase == Phase::Before
        {
            return LoadDirective::Fail;
        }
        LoadDirective::Continue
    }
}

fn stop_at_red_frontier(result: &Result<InitializationKeyPair, LoadError>, signals: &Path) {
    if matches!(result, Err(LoadError::MissingLoad)) {
        marker(
            signals,
            "missing",
            "MissingLoad: initialization_key_pair_load",
        );
        panic!("MissingLoad: initialization_key_pair_load");
    }
}

fn assert_closed(error: LoadError) {
    let expected = match error {
        LoadError::MissingLoad => "initialization key-pair load is not implemented",
        LoadError::Policy => "initialization process policy failed",
        LoadError::Root => "initialization root execution refused",
        LoadError::Lock => "initialization owner lock failed",
        LoadError::Directory => "initialization directory unavailable",
        LoadError::TemporaryEntry => "initialization key temporary entry exists",
        LoadError::Entry(_) => "initialization key entry is unsafe",
        LoadError::Io(_) => "initialization key load failed",
        LoadError::Invalid(_) => "initialization key material is invalid",
        LoadError::Equal => "initialization key materials are equal",
    };
    assert_eq!(error.to_string(), expected);
    assert!(error.source().is_none());
    let diagnostic = format!("{error:?}");
    assert!(!diagnostic.contains('/'));
    assert!(!diagnostic.contains("35") && !diagnostic.contains("a9"));
}

fn expected_error(case: &str) -> LoadError {
    match case {
        "missing-j" => LoadError::Entry(J),
        "missing-r" => LoadError::Entry(R),
        "temporary-j" | "temporary-r" => LoadError::TemporaryEntry,
        "rebind" => unreachable!("post-open rebind succeeds"),
        "preopen-rebind" => LoadError::Directory,
        "zero-j" => LoadError::Invalid(J),
        "zero-r" => LoadError::Invalid(R),
        "short-j" | "oversized-j" => LoadError::Invalid(J),
        "short-r" | "oversized-r" => LoadError::Invalid(R),
        "equal" => LoadError::Equal,
        "read-error" => LoadError::Io(LoadStep::Read(J)),
        case if case.starts_with("unsafe-j-") => LoadError::Entry(J),
        case if case.starts_with("unsafe-r-") => LoadError::Entry(R),
        _ => panic!("unknown load case"),
    }
}

fn assert_pair(pair: &InitializationKeyPair) {
    fn wrapped(_: &Zeroizing<[u8; 32]>) {}
    wrapped(&pair.journal_integrity.0);
    wrapped(&pair.portable_reservation.0);
    assert!(std::mem::needs_drop::<InitializationKeyPair>());
    assert_eq!(format!("{pair:?}"), "InitializationKeyPair([REDACTED])");
}

#[test]
fn worker() {
    let Ok(case) = std::env::var("MSGRIVER_LOAD_CASE") else {
        for case in [
            "success",
            "missing-j",
            "missing-r",
            "temporary-j",
            "temporary-r",
            "rebind",
            "preopen-rebind",
            "zero-j",
            "zero-r",
            "short-j",
            "short-r",
            "oversized-j",
            "oversized-r",
            "equal",
            "read-error",
            "unsafe-j-symlink",
            "unsafe-r-directory",
            "unsafe-j-fifo",
            "unsafe-r-socket",
            "unsafe-j-device",
            "unsafe-r-hardlink",
            "unsafe-j-mode",
            "unsafe-r-owner",
        ] {
            supervise(case);
        }
        return;
    };
    let root = PathBuf::from(std::env::var_os("MSGRIVER_LOAD_ROOT").expect("load root"));
    let signals = PathBuf::from(std::env::var_os("MSGRIVER_LOAD_SIGNALS").expect("load signals"));
    marker(&signals, "ready", "load worker");
    let trace = Rc::new(RefCell::new(Vec::new()));
    let mut hooks = Hooks {
        case: case.clone(),
        root: root.clone(),
        trace: Rc::clone(&trace),
        retained_identity: None,
    };
    marker(&signals, "scope-begin", "load-call");
    let result = load_with(&root, &mut hooks);
    marker(&signals, "scope-end", "load-return");
    stop_at_red_frontier(&result, &signals);
    if case == "success" || case == "rebind" {
        let pair = result.as_ref().expect("successful key load");
        assert_eq!(*pair.journal_integrity.0, JOURNAL);
        assert_eq!(*pair.portable_reservation.0, RESERVATION);
        assert_pair(pair);
        assert_eq!(*trace.borrow(), expected_trace());
        let actual = if case == "rebind" {
            root.with_extension("anchored")
        } else {
            root
        };
        for final_name in FINALS {
            assert_eq!(
                fs::metadata(actual.join(final_name))
                    .expect("final metadata")
                    .len(),
                32
            );
        }
    } else {
        assert!(matches!(result, Err(error) if error == expected_error(&case)));
    }
    marker(&signals, "passed", "load contract-passed");
}

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn supervise(case: &str) {
    let base = std::env::temp_dir().join(format!(
        "msgriver-load-red-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&base).expect("isolated load fixture");
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).expect("fixture mode");
    let output = Command::new("sudo")
        .args(["-n", "/usr/bin/python3"])
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/initialization_key_pair/supervise_load.py"),
        )
        .arg(std::env::current_exe().expect("test binary"))
        .arg(WORKER)
        .arg(&base)
        .arg(case)
        .arg(rustix::process::getuid().as_raw().to_string())
        .arg(rustix::process::getgid().as_raw().to_string())
        .output()
        .expect("launch bounded root-owned load supervisor");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "supervisor emitted unexpected diagnostics"
    );
}

#[test]
fn private_ownership_and_static_surface_are_redacted() {
    fn zeroizing<T: ZeroizeOnDrop>() {}
    zeroizing::<Zeroizing<[u8; 32]>>();
    assert_pair(&InitializationKeyPair {
        journal_integrity: JournalIntegrityKey(Zeroizing::new(JOURNAL)),
        portable_reservation: PortableReservationKey(Zeroizing::new(RESERVATION)),
    });
    for error in [
        LoadError::MissingLoad,
        LoadError::Policy,
        LoadError::Root,
        LoadError::Lock,
        LoadError::Directory,
        LoadError::TemporaryEntry,
        LoadError::Equal,
        LoadError::Entry(J),
        LoadError::Entry(R),
        LoadError::Invalid(J),
        LoadError::Invalid(R),
        LoadError::Io(LoadStep::Read(J)),
        LoadError::Io(LoadStep::Read(R)),
    ] {
        assert_closed(error);
    }
    let source = include_str!("publication.rs");
    for forbidden in [
        "pub fn load",
        "MacKeyId",
        "serialize",
        "impl Display for InitializationKeyPair",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden loader surface: {forbidden}"
        );
    }
    let _ = load as fn(&Path) -> Result<InitializationKeyPair, LoadError>;
}
