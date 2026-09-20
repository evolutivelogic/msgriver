//! Frozen Task 0008 contract. Every scenario reaches the same production seam.
//! Test callbacks observe/fault individual operations; they never publish keys.
//! SIGKILL checks process ordering and retained prefixes, not power-loss or
//! terminated-memory zeroization. Byte assertions are Boolean and synthetic.

use super::super::{
    EntropyFailure, InitializationKeyPair, JournalIntegrityKey, PortableReservationKey,
};
use super::*;
use std::cell::RefCell;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::{ZeroizeOnDrop, Zeroizing};

const J: InitializationKeyRole = InitializationKeyRole::JournalIntegrity;
const R: InitializationKeyRole = InitializationKeyRole::PortableReservation;
const NAMES: [&str; 4] = [
    ".initialization-journal-integrity.tmp",
    "initialization-journal-integrity.key",
    ".initialization-portable-reservation.tmp",
    "initialization-portable-reservation.key",
];
const JOURNAL: [u8; 32] = [0x35; 32];
const RESERVATION: [u8; 32] = [0xa9; 32];
const WORKER: &str = "initialization_key_pair::publication::red_publication::worker";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Boundary(Step, Phase),
    Entropy(InitializationKeyRole),
}
type Trace = Rc<RefCell<Vec<Event>>>;

fn marker(signals: &Path, name: &str, text: &str) {
    fs::write(signals.join(name), text).expect("write secret-free supervisor marker");
}

fn role(text: &str) -> InitializationKeyRole {
    match text {
        "j" => J,
        "r" => R,
        _ => panic!("unknown test role"),
    }
}
fn operation(text: &str, role: InitializationKeyRole) -> Step {
    match text {
        "create" => Step::Create(role),
        "write" => Step::Write(role),
        "file_sync" => Step::FileSync(role),
        "rename" => Step::Rename(role),
        "directory_sync" => Step::DirectorySync(role),
        _ => panic!("unknown test operation"),
    }
}
fn operations(role: InitializationKeyRole) -> [Step; 5] {
    [
        Step::Create(role),
        Step::Write(role),
        Step::FileSync(role),
        Step::Rename(role),
        Step::DirectorySync(role),
    ]
}
fn prefix() -> Vec<Event> {
    let mut result = Vec::new();
    for step in [
        Step::Policy,
        Step::Guard,
        Step::Lock,
        Step::OpenRoot,
        Step::Preflight(0),
        Step::Preflight(1),
        Step::Preflight(2),
        Step::Preflight(3),
    ] {
        result.push(Event::Boundary(step, Phase::Before));
        result.push(Event::Boundary(step, Phase::After));
    }
    result
}
fn complete_trace() -> Vec<Event> {
    let mut result = prefix();
    result.extend([Event::Entropy(J), Event::Entropy(R)]);
    for r in [J, R] {
        for step in operations(r) {
            result.extend([
                Event::Boundary(step, Phase::Before),
                Event::Boundary(step, Phase::After),
            ]);
        }
    }
    result
}

struct Entropy {
    scenario: Vec<String>,
    trace: Trace,
    signals: PathBuf,
    calls: usize,
    root: PathBuf,
}
impl InitializationEntropySource for Entropy {
    fn acquire(
        &mut self,
        r: InitializationKeyRole,
        output: &mut [u8; 32],
    ) -> Result<usize, EntropyFailure> {
        self.trace.borrow_mut().push(Event::Entropy(r));
        let actual = if self.scenario[0] == "rebind" {
            self.root.with_extension("anchored")
        } else {
            self.root.clone()
        };
        assert!(
            matches!(
                crate::StateOwnerLock::acquire(&actual),
                Err(crate::StateOwnerLockError::Contended)
            ),
            "owner lock not retained during entropy"
        );
        self.calls += 1;
        marker(&self.signals, "entropy", &self.calls.to_string());
        assert!(self.calls <= 2, "entropy retried");
        assert_eq!(r, if self.calls == 1 { J } else { R });
        assert!(
            output.iter().all(|b| *b == 0),
            "entropy destination was not initially zero"
        );
        let swapped = self.scenario[0] == "swapped"
            || self.scenario.get(4).map(String::as_str) == Some("swapped");
        let bytes = if (r == J) != swapped {
            JOURNAL
        } else {
            RESERVATION
        };
        if self.scenario[0] == "entropy" && r == role(&self.scenario[1]) {
            let kind = self.scenario[2].as_str();
            let n = self.scenario[3].parse::<usize>().expect("entropy count");
            if kind == "error" {
                output[..n].copy_from_slice(&bytes[..n]);
                return Err(EntropyFailure::Failed);
            }
            if kind == "zero" {
                return Ok(32);
            }
            if kind == "equal" {
                output.copy_from_slice(if swapped { &RESERVATION } else { &JOURNAL });
                return Ok(32);
            }
            // Deliberately write all bytes even for a false count; count is authority.
            output.copy_from_slice(&bytes);
            return Ok(n);
        }
        output.copy_from_slice(&bytes);
        Ok(32)
    }
}

struct Hooks {
    scenario: Vec<String>,
    trace: Trace,
    root: PathBuf,
    signals: PathBuf,
    identity: Option<(u64, u64)>,
}
impl PublicationHooks for Hooks {
    fn at(&mut self, step: Step, phase: Phase, directory: Option<BorrowedFd<'_>>) -> Directive {
        self.trace.borrow_mut().push(Event::Boundary(step, phase));
        marker(
            &self.signals,
            &format!("boundary-{step:?}-{phase:?}"),
            "boundary",
        );
        assert!(
            !self.signals.join("continued").exists(),
            "success before final barrier returned"
        );
        marker(
            &self.signals,
            "events",
            &format!("{:?}", self.trace.borrow()),
        );
        if step == Step::Guard && phase == Phase::Before {
            let limits = rustix::process::getrlimit(rustix::process::Resource::Core);
            assert_eq!(limits.current, Some(0));
            assert_eq!(limits.maximum, Some(0));
            assert_eq!(
                rustix::process::dumpable_behavior().expect("dumpability"),
                rustix::process::DumpableBehavior::NotDumpable
            );
            assert_eq!(
                rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077)).as_raw_mode(),
                0o077
            );
        }
        if step == Step::Lock && phase == Phase::Before {
            assert_ne!(rustix::process::geteuid().as_raw(), 0);
        }
        let needs_fd = matches!(
            step,
            Step::Preflight(_)
                | Step::Create(_)
                | Step::Write(_)
                | Step::FileSync(_)
                | Step::Rename(_)
                | Step::DirectorySync(_)
        ) || (step == Step::OpenRoot && phase == Phase::After);
        assert_eq!(
            directory.is_some(),
            needs_fd,
            "directory observation contract"
        );
        if let Some(fd) = directory {
            let stat = rustix::fs::fstat(fd).expect("directory descriptor metadata");
            let identity = (stat.st_dev, stat.st_ino);
            if let Some(expected) = self.identity {
                assert_eq!(identity, expected);
            } else {
                let metadata = fs::symlink_metadata(&self.root).expect("root metadata");
                assert_eq!(identity, (metadata.dev(), metadata.ino()));
                self.identity = Some(identity);
            }
            assert_eq!(stat.st_mode & 0o7777, 0o700);
            assert_eq!(
                stat.st_mode & rustix::fs::FileType::Directory.as_raw_mode(),
                rustix::fs::FileType::Directory.as_raw_mode()
            );
        }
        // An independent open-file description must lose at every retained-lock point.
        if needs_fd || (step == Step::Lock && phase == Phase::After) {
            let actual =
                if self.scenario[0] == "rebind" && self.root.with_extension("anchored").exists() {
                    self.root.with_extension("anchored")
                } else {
                    self.root.clone()
                };
            assert!(
                matches!(
                    crate::StateOwnerLock::acquire(&actual),
                    Err(crate::StateOwnerLockError::Contended)
                ),
                "owner lock not retained"
            );
        }
        if self.scenario[0] == "policy" && step == Step::Policy && phase == Phase::Before {
            return Directive::Fail;
        }
        if self.scenario[0] == "rebind" && step == Step::OpenRoot && phase == Phase::After {
            fs::rename(&self.root, self.root.with_extension("anchored"))
                .expect("rebind root fixture");
            fs::create_dir(&self.root).expect("decoy root");
            fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700)).expect("decoy mode");
        }
        if ["fault", "short", "interrupt", "race"].contains(&self.scenario[0].as_str()) {
            let target = operation(&self.scenario[2], role(&self.scenario[1]));
            if step == target && phase == Phase::Before {
                match self.scenario[0].as_str() {
                    "fault" => return Directive::Fail,
                    "short" => {
                        return Directive::WriteLimit(
                            self.scenario[3].parse().expect("write limit"),
                        );
                    }
                    "race" => {
                        let base = if role(&self.scenario[1]) == J { 0 } else { 2 };
                        let index = base + usize::from(matches!(step, Step::Rename(_)));
                        create_fixture(&self.root, index, &self.scenario[3]);
                    }
                    _ => {}
                }
            }
            let requested_phase = if self.scenario.get(3).map(String::as_str) == Some("after") {
                Phase::After
            } else {
                Phase::Before
            };
            if self.scenario[0] == "interrupt" && step == target && phase == requested_phase {
                marker(&self.signals, "paused", &format!("{step:?}/{phase:?}"));
                loop {
                    std::thread::park_timeout(std::time::Duration::from_millis(100));
                }
            }
        }
        Directive::Continue
    }
}

fn create_fixture(root: &Path, index: usize, kind: &str) {
    let path = root.join(NAMES[index]);
    match kind {
        "regular" => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .expect("fixture file");
            file.write_all(b"public-fixture").expect("fixture write");
        }
        "directory" => fs::create_dir(path).expect("fixture directory"),
        "fifo" => {
            let text = path.to_string_lossy();
            rustix::fs::mkfifoat(
                rustix::fs::CWD,
                text.as_ref(),
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )
            .expect("fixture fifo")
        }
        "symlink" => {
            std::os::unix::fs::symlink(root.parent().expect("parent").join("target"), path)
                .expect("fixture symlink")
        }
        "dangling" => {
            std::os::unix::fs::symlink("absent-target", path).expect("fixture dangling symlink")
        }
        "hardlink" => fs::hard_link(root.parent().expect("parent").join("target"), path)
            .expect("fixture hardlink"),
        _ => panic!("unknown fixture kind"),
    }
}

// Safe metadata only, including inode identity and symlink identity, never contents.
type Entry = (String, u64, u64, u32, u64, u64, i64, i64, Option<PathBuf>);
fn inventory(root: &Path) -> Vec<Entry> {
    let mut items = fs::read_dir(root)
        .expect("inventory root")
        .map(|entry| {
            let entry = entry.expect("inventory entry");
            let m = fs::symlink_metadata(entry.path()).expect("inventory metadata");
            (
                entry.file_name().to_string_lossy().into_owned(),
                m.dev(),
                m.ino(),
                m.mode(),
                m.nlink(),
                m.len(),
                m.mtime(),
                m.mtime_nsec(),
                if m.is_symlink() {
                    Some(fs::read_link(entry.path()).expect("symlink identity"))
                } else {
                    None
                },
            )
        })
        .collect::<Vec<_>>();
    items.sort();
    items
}
fn assert_files(root: &Path, expected: &[(usize, u64)], contents: bool, swapped: bool) {
    let names = inventory(root).into_iter().map(|x| x.0).collect::<Vec<_>>();
    let mut wanted = expected
        .iter()
        .map(|(i, _)| NAMES[*i].to_owned())
        .collect::<Vec<_>>();
    wanted.push("msgriver.lock".into());
    wanted.sort();
    assert_eq!(names, wanted, "unexpected state effect");
    for (index, size) in expected {
        let path = root.join(NAMES[*index]);
        let m = fs::symlink_metadata(&path).expect("key metadata");
        assert!(m.is_file());
        assert_eq!(m.mode() & 0o7777, 0o600);
        assert_eq!(m.nlink(), 1);
        assert_eq!(m.len(), *size);
        if contents {
            let bytes = fs::read(&path).expect("synthetic key read");
            let wanted = if (*index < 2) != swapped {
                JOURNAL
            } else {
                RESERVATION
            };
            assert!(
                bytes == wanted[..*size as usize],
                "role/raw32 content mismatch"
            );
        }
    }
}
fn checked(result: Result<(), PublicationError>, signals: &Path) -> Result<(), PublicationError> {
    if result == Err(PublicationError::MissingPublication) {
        marker(
            signals,
            "missing",
            "MissingPublication: initialization_key_pair_publication",
        );
        panic!("MissingPublication: initialization_key_pair_publication");
    }
    result
}
fn error_contract(error: PublicationError) {
    let expected = match error {
        PublicationError::MissingPublication => {
            "initialization key-pair publication is not implemented"
        }
        PublicationError::Policy => "initialization process policy failed",
        PublicationError::Root => "initialization root execution refused",
        PublicationError::Lock => "initialization owner lock failed",
        PublicationError::Directory => "initialization directory unavailable",
        PublicationError::ExistingEntry => "initialization key entry already exists",
        PublicationError::Entropy(_) => "initialization key acquisition failed",
        PublicationError::Io(_) => "initialization key publication failed",
    };
    assert!(error.to_string() == expected);
    assert!(error.source().is_none());
    // All Debug payloads are closed enums/integers; no path, bytes or source.
    let debug = match error {
        PublicationError::MissingPublication => "MissingPublication".to_owned(),
        PublicationError::Policy => "Policy".to_owned(),
        PublicationError::Root => "Root".to_owned(),
        PublicationError::Lock => "Lock".to_owned(),
        PublicationError::Directory => "Directory".to_owned(),
        PublicationError::ExistingEntry => "ExistingEntry".to_owned(),
        PublicationError::Entropy(e) => format!("Entropy({e:?})"),
        PublicationError::Io(step) => format!("Io({step:?})"),
    };
    assert!(
        format!("{error:?}") == debug,
        "diagnostics were not closed and static"
    );
}

#[test]
fn worker() {
    let Ok(case) = std::env::var("MSGRIVER_PUBLICATION_CASE") else {
        supervise("success");
        return;
    };
    let scenario = case.split(':').map(str::to_owned).collect::<Vec<_>>();
    let root = PathBuf::from(std::env::var_os("MSGRIVER_PUBLICATION_ROOT").expect("root"));
    let signals = PathBuf::from(std::env::var_os("MSGRIVER_PUBLICATION_SIGNALS").expect("signals"));
    assert_eq!(
        rustix::process::geteuid().as_raw(),
        if scenario[0] == "root" {
            0
        } else {
            std::env::var("MSGRIVER_PUBLICATION_UID")
                .expect("uid")
                .parse()
                .expect("numeric uid")
        }
    );
    marker(&signals, "ready", &std::process::id().to_string());
    if scenario[0] == "supervision" {
        marker(&signals, "paused", "supervision-control");
        loop {
            std::thread::park_timeout(std::time::Duration::from_millis(100));
        }
    }
    let mut before = None;
    if scenario[0] == "existing" {
        create_fixture(&root, scenario[1].parse().expect("index"), &scenario[2]);
        before = Some(inventory(&root));
    }
    if scenario[0] == "prefix" {
        for index in scenario[1..]
            .iter()
            .map(|s| s.parse::<usize>().expect("prefix index"))
        {
            create_fixture(&root, index, "regular");
        }
        before = Some(inventory(&root));
    }
    if scenario[0] == "restart" {
        before = Some(inventory(&root));
    }
    let trace = Rc::new(RefCell::new(Vec::new()));
    let mut entropy = Entropy {
        scenario: scenario.clone(),
        trace: Rc::clone(&trace),
        signals: signals.clone(),
        calls: 0,
        root: root.clone(),
    };
    let mut hooks = Hooks {
        scenario: scenario.clone(),
        trace: Rc::clone(&trace),
        root: root.clone(),
        signals: signals.clone(),
        identity: None,
    };
    marker(&signals, "scope-begin", "publication-call");
    let mut continued = 0;
    let result = if scenario[0] == "production" {
        publish(&root)
    } else {
        publish_with(&root, &mut entropy, &mut hooks)
    }
    .inspect(|()| {
        continued += 1;
        marker(&signals, "continued", "complete-pair");
    });
    marker(&signals, "scope-end", "publication-return");
    let result = checked(result, &signals);
    if let Err(error) = result {
        error_contract(error);
    }
    let observed = trace.borrow().clone();
    match scenario[0].as_str() {
        "success" | "swapped" | "rebind" | "fresh_restart" => {
            assert_eq!(result, Ok(()));
            assert_eq!(continued, 1);
            assert_eq!(observed, complete_trace());
            assert_eq!(entropy.calls, 2);
            let actual = if scenario[0] == "rebind" {
                root.with_extension("anchored")
            } else {
                root.clone()
            };
            assert_files(
                &actual,
                &[(1, 32), (3, 32)],
                scenario[0] != "fresh_restart",
                scenario[0] == "swapped",
            );
            if scenario[0] == "rebind" {
                assert!(inventory(&root).is_empty());
            }
        }
        "production" => {
            assert_eq!(result, Ok(()));
            assert_eq!(continued, 1);
            assert_files(&root, &[(1, 32), (3, 32)], false, false);
        }
        "existing" | "prefix" | "restart" => {
            assert_eq!(result, Err(PublicationError::ExistingEntry));
            assert_eq!(continued, 0);
            assert_eq!(entropy.calls, 0);
            let without_lock = |items: Vec<Entry>| {
                items
                    .into_iter()
                    .filter(|x| x.0 != "msgriver.lock")
                    .collect::<Vec<_>>()
            };
            let prior = before.expect("prior inventory");
            let first = NAMES
                .iter()
                .position(|name| prior.iter().any(|entry| entry.0 == *name))
                .expect("existing basename");
            let mut wanted = prefix();
            let stop = wanted
                .iter()
                .position(|e| *e == Event::Boundary(Step::Preflight(first as u8), Phase::Before))
                .expect("preflight event");
            wanted.truncate(stop + 1);
            assert_eq!(observed, wanted);
            assert_eq!(without_lock(inventory(&root)), without_lock(prior));
            assert!(!observed.iter().any(|e| matches!(
                e,
                Event::Entropy(_)
                    | Event::Boundary(
                        Step::Create(_)
                            | Step::Write(_)
                            | Step::FileSync(_)
                            | Step::Rename(_)
                            | Step::DirectorySync(_),
                        _
                    )
            )));
        }
        "policy" | "root" | "contender" => {
            let (error, step) = match scenario[0].as_str() {
                "policy" => (PublicationError::Policy, Step::Policy),
                "root" => (PublicationError::Root, Step::Guard),
                _ => (PublicationError::Lock, Step::Lock),
            };
            assert_eq!(result, Err(error));
            assert_eq!(continued, 0);
            assert_eq!(entropy.calls, 0);
            let mut wanted = prefix();
            let end = wanted
                .iter()
                .position(|e| *e == Event::Boundary(step, Phase::Before))
                .expect("stop event");
            wanted.truncate(end + 1);
            assert_eq!(observed, wanted);
            if scenario[0] != "contender" {
                assert!(inventory(&root).is_empty());
            }
        }
        "entropy" => {
            let r = role(&scenario[1]);
            let error = match scenario[2].as_str() {
                "error" => InitializationKeyPairError::Entropy(r),
                "zero" => InitializationKeyPairError::Zero(r),
                "equal" => InitializationKeyPairError::Equal,
                _ => InitializationKeyPairError::Incomplete(r),
            };
            assert_eq!(result, Err(PublicationError::Entropy(error)));
            assert_eq!(continued, 0);
            let mut wanted = prefix();
            wanted.push(Event::Entropy(J));
            if r == R {
                wanted.push(Event::Entropy(R));
            }
            assert_eq!(observed, wanted);
            assert_files(&root, &[], false, false);
        }
        "fault" | "short" => {
            let r = role(&scenario[1]);
            let step = operation(&scenario[2], r);
            assert_eq!(result, Err(PublicationError::Io(step)));
            assert_eq!(continued, 0);
            let mut wanted = complete_trace();
            let end = wanted
                .iter()
                .position(|e| *e == Event::Boundary(step, Phase::Before))
                .expect("fault event");
            wanted.truncate(end + 1);
            assert_eq!(observed, wanted);
            let mut files = if r == R { vec![(1, 32)] } else { Vec::new() };
            let base = if r == J { 0 } else { 2 };
            match step {
                Step::Create(_) => {}
                Step::Write(_) => files.push((
                    base,
                    if scenario[0] == "short" {
                        scenario[3].parse().expect("short size")
                    } else {
                        0
                    },
                )),
                Step::FileSync(_) | Step::Rename(_) => files.push((base, 32)),
                Step::DirectorySync(_) => files.push((base + 1, 32)),
                _ => unreachable!(),
            }
            assert_files(&root, &files, true, false);
        }
        "race" => {
            let r = role(&scenario[1]);
            let step = operation(&scenario[2], r);
            assert_eq!(result, Err(PublicationError::Io(step)));
            assert_eq!(continued, 0);
            let index = (if r == J { 0 } else { 2 }) + usize::from(matches!(step, Step::Rename(_)));
            let mut names = inventory(&root)
                .into_iter()
                .map(|entry| entry.0)
                .collect::<Vec<_>>();
            let mut expected = vec!["msgriver.lock".to_owned(), NAMES[index].to_owned()];
            if r == R {
                expected.push(NAMES[1].to_owned());
            }
            if matches!(step, Step::Rename(_)) {
                expected.push(NAMES[index - 1].to_owned());
            }
            names.sort();
            expected.sort();
            assert_eq!(names, expected, "race changed an unrelated entry");
            let m = fs::symlink_metadata(root.join(NAMES[index])).expect("race preserved");
            match scenario[3].as_str() {
                "regular" => {
                    assert_eq!(m.len(), 14);
                    assert!(
                        fs::read(root.join(NAMES[index])).expect("race fixture contents")
                            == b"public-fixture"
                    );
                }
                "symlink" => assert!(m.is_symlink()),
                "fifo" => assert_eq!(m.mode() & 0o170000, 0o010000),
                _ => unreachable!(),
            }
            let mut wanted = complete_trace();
            let end = wanted
                .iter()
                .position(|e| *e == Event::Boundary(step, Phase::Before))
                .expect("race event");
            wanted.truncate(end + 1);
            assert_eq!(observed, wanted);
        }
        "interrupt" => panic!("interruption checkpoint was bypassed"),
        _ => panic!("unknown scenario"),
    }
    // The external target must remain unchanged even for hardlinks/symlinks.
    assert!(
        fs::read(root.parent().expect("parent").join("target")).expect("target read")
            == b"public-fixture"
    );
    marker(&signals, "passed", "contract-passed");
}

static NEXT: AtomicUsize = AtomicUsize::new(0);
fn supervise(case: &str) {
    let base = std::env::temp_dir().join(format!(
        "msgriver-publication-red-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&base).expect("isolated fixture");
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).expect("fixture mode");
    let output = Command::new("sudo")
        .args(["-n", "/usr/bin/python3"])
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/initialization_key_pair/supervise_publication.py"),
        )
        .arg(std::env::current_exe().expect("test binary"))
        .arg(WORKER)
        .arg(&base)
        .arg(case)
        .arg(rustix::process::getuid().as_raw().to_string())
        .arg(rustix::process::getgid().as_raw().to_string())
        .output()
        .expect("launch bounded root-owned supervisor");
    // Supervisor owns teardown, including files left by a root-refused child.
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stderr.is_empty(),
        "supervisor emitted unexpected diagnostics"
    );
}

#[test]
fn zeroizing_ownership_and_static_errors() {
    fn wrapped(_: &Zeroizing<[u8; 32]>) {}
    fn zeroizing<T: ZeroizeOnDrop>() {}
    let pair = InitializationKeyPair {
        journal_integrity: JournalIntegrityKey(Zeroizing::new(JOURNAL)),
        portable_reservation: PortableReservationKey(Zeroizing::new(RESERVATION)),
    };
    wrapped(&pair.journal_integrity.0);
    wrapped(&pair.portable_reservation.0);
    zeroizing::<Zeroizing<[u8; 32]>>();
    assert!(std::mem::needs_drop::<InitializationKeyPair>());
    assert!(format!("{pair:?}") == "InitializationKeyPair([REDACTED])");
    for e in [
        PublicationError::MissingPublication,
        PublicationError::Policy,
        PublicationError::Root,
        PublicationError::Lock,
        PublicationError::Directory,
        PublicationError::ExistingEntry,
    ] {
        error_contract(e);
    }
    for r in [J, R] {
        for step in operations(r) {
            error_contract(PublicationError::Io(step));
        }
        for e in [
            InitializationKeyPairError::Entropy(r),
            InitializationKeyPairError::Incomplete(r),
            InitializationKeyPairError::Zero(r),
            InitializationKeyPairError::Equal,
        ] {
            error_contract(PublicationError::Entropy(e));
        }
    }
}

macro_rules! cases { ($($name:ident => $case:literal),+ $(,)?) => { $(#[test] fn $name() { supervise($case); })+ }; }

cases! {
    success => "success",
    swapped => "swapped",
    rebind => "rebind",
    production => "production",
    policy => "policy",
    root => "root",
    contender => "contender",
    entropy_j_error_0 => "entropy:j:error:0",
    entropy_j_error_1 => "entropy:j:error:1",
    entropy_j_error_31 => "entropy:j:error:31",
    entropy_j_error_32 => "entropy:j:error:32",
    entropy_j_count_0 => "entropy:j:count:0",
    entropy_j_count_1 => "entropy:j:count:1",
    entropy_j_count_2 => "entropy:j:count:2",
    entropy_j_count_3 => "entropy:j:count:3",
    entropy_j_count_4 => "entropy:j:count:4",
    entropy_j_count_5 => "entropy:j:count:5",
    entropy_j_count_6 => "entropy:j:count:6",
    entropy_j_count_7 => "entropy:j:count:7",
    entropy_j_count_8 => "entropy:j:count:8",
    entropy_j_count_9 => "entropy:j:count:9",
    entropy_j_count_10 => "entropy:j:count:10",
    entropy_j_count_11 => "entropy:j:count:11",
    entropy_j_count_12 => "entropy:j:count:12",
    entropy_j_count_13 => "entropy:j:count:13",
    entropy_j_count_14 => "entropy:j:count:14",
    entropy_j_count_15 => "entropy:j:count:15",
    entropy_j_count_16 => "entropy:j:count:16",
    entropy_j_count_17 => "entropy:j:count:17",
    entropy_j_count_18 => "entropy:j:count:18",
    entropy_j_count_19 => "entropy:j:count:19",
    entropy_j_count_20 => "entropy:j:count:20",
    entropy_j_count_21 => "entropy:j:count:21",
    entropy_j_count_22 => "entropy:j:count:22",
    entropy_j_count_23 => "entropy:j:count:23",
    entropy_j_count_24 => "entropy:j:count:24",
    entropy_j_count_25 => "entropy:j:count:25",
    entropy_j_count_26 => "entropy:j:count:26",
    entropy_j_count_27 => "entropy:j:count:27",
    entropy_j_count_28 => "entropy:j:count:28",
    entropy_j_count_29 => "entropy:j:count:29",
    entropy_j_count_30 => "entropy:j:count:30",
    entropy_j_count_31 => "entropy:j:count:31",
    entropy_j_count_33 => "entropy:j:count:33",
    entropy_j_count_18446744073709551615 => "entropy:j:count:18446744073709551615",
    entropy_j_zero => "entropy:j:zero:32",
    entropy_r_error_0 => "entropy:r:error:0",
    entropy_r_error_1 => "entropy:r:error:1",
    entropy_r_error_31 => "entropy:r:error:31",
    entropy_r_error_32 => "entropy:r:error:32",
    entropy_r_count_0 => "entropy:r:count:0",
    entropy_r_count_1 => "entropy:r:count:1",
    entropy_r_count_2 => "entropy:r:count:2",
    entropy_r_count_3 => "entropy:r:count:3",
    entropy_r_count_4 => "entropy:r:count:4",
    entropy_r_count_5 => "entropy:r:count:5",
    entropy_r_count_6 => "entropy:r:count:6",
    entropy_r_count_7 => "entropy:r:count:7",
    entropy_r_count_8 => "entropy:r:count:8",
    entropy_r_count_9 => "entropy:r:count:9",
    entropy_r_count_10 => "entropy:r:count:10",
    entropy_r_count_11 => "entropy:r:count:11",
    entropy_r_count_12 => "entropy:r:count:12",
    entropy_r_count_13 => "entropy:r:count:13",
    entropy_r_count_14 => "entropy:r:count:14",
    entropy_r_count_15 => "entropy:r:count:15",
    entropy_r_count_16 => "entropy:r:count:16",
    entropy_r_count_17 => "entropy:r:count:17",
    entropy_r_count_18 => "entropy:r:count:18",
    entropy_r_count_19 => "entropy:r:count:19",
    entropy_r_count_20 => "entropy:r:count:20",
    entropy_r_count_21 => "entropy:r:count:21",
    entropy_r_count_22 => "entropy:r:count:22",
    entropy_r_count_23 => "entropy:r:count:23",
    entropy_r_count_24 => "entropy:r:count:24",
    entropy_r_count_25 => "entropy:r:count:25",
    entropy_r_count_26 => "entropy:r:count:26",
    entropy_r_count_27 => "entropy:r:count:27",
    entropy_r_count_28 => "entropy:r:count:28",
    entropy_r_count_29 => "entropy:r:count:29",
    entropy_r_count_30 => "entropy:r:count:30",
    entropy_r_count_31 => "entropy:r:count:31",
    entropy_r_count_33 => "entropy:r:count:33",
    entropy_r_count_18446744073709551615 => "entropy:r:count:18446744073709551615",
    entropy_r_zero => "entropy:r:zero:32",
    entropy_equal => "entropy:r:equal:32",
    entropy_equal_swapped => "entropy:r:equal:32:swapped",
    existing_0_regular => "existing:0:regular",
    existing_0_directory => "existing:0:directory",
    existing_0_fifo => "existing:0:fifo",
    existing_0_symlink => "existing:0:symlink",
    existing_0_dangling => "existing:0:dangling",
    existing_0_hardlink => "existing:0:hardlink",
    existing_1_regular => "existing:1:regular",
    existing_1_directory => "existing:1:directory",
    existing_1_fifo => "existing:1:fifo",
    existing_1_symlink => "existing:1:symlink",
    existing_1_dangling => "existing:1:dangling",
    existing_1_hardlink => "existing:1:hardlink",
    existing_2_regular => "existing:2:regular",
    existing_2_directory => "existing:2:directory",
    existing_2_fifo => "existing:2:fifo",
    existing_2_symlink => "existing:2:symlink",
    existing_2_dangling => "existing:2:dangling",
    existing_2_hardlink => "existing:2:hardlink",
    existing_3_regular => "existing:3:regular",
    existing_3_directory => "existing:3:directory",
    existing_3_fifo => "existing:3:fifo",
    existing_3_symlink => "existing:3:symlink",
    existing_3_dangling => "existing:3:dangling",
    existing_3_hardlink => "existing:3:hardlink",
    prefix_0_1 => "prefix:0:1",
    prefix_0_2 => "prefix:0:2",
    prefix_1_2 => "prefix:1:2",
    prefix_0_1_2 => "prefix:0:1:2",
    prefix_0_3 => "prefix:0:3",
    prefix_1_3 => "prefix:1:3",
    prefix_0_1_3 => "prefix:0:1:3",
    prefix_2_3 => "prefix:2:3",
    prefix_0_2_3 => "prefix:0:2:3",
    prefix_1_2_3 => "prefix:1:2:3",
    prefix_0_1_2_3 => "prefix:0:1:2:3",
    fault_j_create => "fault:j:create",
    interrupt_j_create_before => "interrupt:j:create:before",
    interrupt_j_create_after => "interrupt:j:create:after",
    fault_j_write => "fault:j:write",
    interrupt_j_write_before => "interrupt:j:write:before",
    interrupt_j_write_after => "interrupt:j:write:after",
    fault_j_file_sync => "fault:j:file_sync",
    interrupt_j_file_sync_before => "interrupt:j:file_sync:before",
    interrupt_j_file_sync_after => "interrupt:j:file_sync:after",
    fault_j_rename => "fault:j:rename",
    interrupt_j_rename_before => "interrupt:j:rename:before",
    interrupt_j_rename_after => "interrupt:j:rename:after",
    fault_j_directory_sync => "fault:j:directory_sync",
    interrupt_j_directory_sync_before => "interrupt:j:directory_sync:before",
    interrupt_j_directory_sync_after => "interrupt:j:directory_sync:after",
    short_j_0 => "short:j:write:0",
    short_j_1 => "short:j:write:1",
    short_j_2 => "short:j:write:2",
    short_j_3 => "short:j:write:3",
    short_j_4 => "short:j:write:4",
    short_j_5 => "short:j:write:5",
    short_j_6 => "short:j:write:6",
    short_j_7 => "short:j:write:7",
    short_j_8 => "short:j:write:8",
    short_j_9 => "short:j:write:9",
    short_j_10 => "short:j:write:10",
    short_j_11 => "short:j:write:11",
    short_j_12 => "short:j:write:12",
    short_j_13 => "short:j:write:13",
    short_j_14 => "short:j:write:14",
    short_j_15 => "short:j:write:15",
    short_j_16 => "short:j:write:16",
    short_j_17 => "short:j:write:17",
    short_j_18 => "short:j:write:18",
    short_j_19 => "short:j:write:19",
    short_j_20 => "short:j:write:20",
    short_j_21 => "short:j:write:21",
    short_j_22 => "short:j:write:22",
    short_j_23 => "short:j:write:23",
    short_j_24 => "short:j:write:24",
    short_j_25 => "short:j:write:25",
    short_j_26 => "short:j:write:26",
    short_j_27 => "short:j:write:27",
    short_j_28 => "short:j:write:28",
    short_j_29 => "short:j:write:29",
    short_j_30 => "short:j:write:30",
    short_j_31 => "short:j:write:31",
    race_j_create_regular => "race:j:create:regular",
    race_j_create_symlink => "race:j:create:symlink",
    race_j_create_fifo => "race:j:create:fifo",
    race_j_rename_regular => "race:j:rename:regular",
    race_j_rename_symlink => "race:j:rename:symlink",
    race_j_rename_fifo => "race:j:rename:fifo",
    fault_r_create => "fault:r:create",
    interrupt_r_create_before => "interrupt:r:create:before",
    interrupt_r_create_after => "interrupt:r:create:after",
    fault_r_write => "fault:r:write",
    interrupt_r_write_before => "interrupt:r:write:before",
    interrupt_r_write_after => "interrupt:r:write:after",
    fault_r_file_sync => "fault:r:file_sync",
    interrupt_r_file_sync_before => "interrupt:r:file_sync:before",
    interrupt_r_file_sync_after => "interrupt:r:file_sync:after",
    fault_r_rename => "fault:r:rename",
    interrupt_r_rename_before => "interrupt:r:rename:before",
    interrupt_r_rename_after => "interrupt:r:rename:after",
    fault_r_directory_sync => "fault:r:directory_sync",
    interrupt_r_directory_sync_before => "interrupt:r:directory_sync:before",
    interrupt_r_directory_sync_after => "interrupt:r:directory_sync:after",
    short_r_0 => "short:r:write:0",
    short_r_1 => "short:r:write:1",
    short_r_2 => "short:r:write:2",
    short_r_3 => "short:r:write:3",
    short_r_4 => "short:r:write:4",
    short_r_5 => "short:r:write:5",
    short_r_6 => "short:r:write:6",
    short_r_7 => "short:r:write:7",
    short_r_8 => "short:r:write:8",
    short_r_9 => "short:r:write:9",
    short_r_10 => "short:r:write:10",
    short_r_11 => "short:r:write:11",
    short_r_12 => "short:r:write:12",
    short_r_13 => "short:r:write:13",
    short_r_14 => "short:r:write:14",
    short_r_15 => "short:r:write:15",
    short_r_16 => "short:r:write:16",
    short_r_17 => "short:r:write:17",
    short_r_18 => "short:r:write:18",
    short_r_19 => "short:r:write:19",
    short_r_20 => "short:r:write:20",
    short_r_21 => "short:r:write:21",
    short_r_22 => "short:r:write:22",
    short_r_23 => "short:r:write:23",
    short_r_24 => "short:r:write:24",
    short_r_25 => "short:r:write:25",
    short_r_26 => "short:r:write:26",
    short_r_27 => "short:r:write:27",
    short_r_28 => "short:r:write:28",
    short_r_29 => "short:r:write:29",
    short_r_30 => "short:r:write:30",
    short_r_31 => "short:r:write:31",
    race_r_create_regular => "race:r:create:regular",
    race_r_create_symlink => "race:r:create:symlink",
    race_r_create_fifo => "race:r:create:fifo",
    race_r_rename_regular => "race:r:rename:regular",
    race_r_rename_symlink => "race:r:rename:symlink",
    race_r_rename_fifo => "race:r:rename:fifo",
}
