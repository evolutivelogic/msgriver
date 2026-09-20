//! Task 0008 private durable-publication boundary.
//! The child alone owns the future filesystem boundary; Task 0007 is frozen.

use super::{
    InitializationEntropySource, InitializationKeyPair, InitializationKeyPairError,
    InitializationKeyRole,
};
use rustix::fd::BorrowedFd;
use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Policy,
    Guard,
    Lock,
    OpenRoot,
    Preflight(u8),
    Create(InitializationKeyRole),
    Write(InitializationKeyRole),
    FileSync(InitializationKeyRole),
    Rename(InitializationKeyRole),
    DirectorySync(InitializationKeyRole),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Before,
    After,
}

/// Secret-free fault controls. A write limit requests one actual short write,
/// not a fabricated successful completion. No retry is authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Directive {
    Continue,
    Fail,
    WriteLimit(usize),
}

/// Notifications bracket the actual operation, not a simulated algorithm.
/// After(OpenRoot) and every preflight/key operation borrow the retained dirfd.
/// Before(Policy/Guard/Lock/OpenRoot) and After(Policy/Guard/Lock) carry no fd.
/// After is emitted only following successful completion. Fail is mapped to
/// the corresponding closed error; callbacks never receive key material.
trait PublicationHooks {
    fn at(&mut self, step: Step, phase: Phase, directory: Option<BorrowedFd<'_>>) -> Directive;
}

struct NoFaults;

impl PublicationHooks for NoFaults {
    fn at(&mut self, _: Step, _: Phase, _: Option<BorrowedFd<'_>>) -> Directive {
        Directive::Continue
    }
}

/// Task 0014 observes only the private load boundary. The hook carries an
/// optional borrowed directory descriptor so the frozen tests can prove that
/// every future child operation is rooted in the one retained descriptor
/// without granting any caller a filesystem capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoadStep {
    Policy,
    Guard,
    Lock,
    OpenRoot,
    TemporaryPreflight(u8),
    Open(InitializationKeyRole),
    Read(InitializationKeyRole),
    Verify(InitializationKeyRole),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoadDirective {
    Continue,
    Fail,
}

trait LoadHooks {
    fn at(
        &mut self,
        step: LoadStep,
        phase: Phase,
        directory: Option<BorrowedFd<'_>>,
    ) -> LoadDirective;
}

struct NoLoadFaults;

impl LoadHooks for NoLoadFaults {
    fn at(&mut self, _: LoadStep, _: Phase, _: Option<BorrowedFd<'_>>) -> LoadDirective {
        LoadDirective::Continue
    }
}

/// Static, redacted failures for the private existing-key load boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoadError {
    MissingLoad,
    Policy,
    Root,
    Lock,
    Directory,
    TemporaryEntry,
    Entry(InitializationKeyRole),
    Io(LoadStep),
    Invalid(InitializationKeyRole),
    Equal,
}

impl fmt::Display for LoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingLoad => "initialization key-pair load is not implemented",
            Self::Policy => "initialization process policy failed",
            Self::Root => "initialization root execution refused",
            Self::Lock => "initialization owner lock failed",
            Self::Directory => "initialization directory unavailable",
            Self::TemporaryEntry => "initialization key temporary entry exists",
            Self::Entry(_) => "initialization key entry is unsafe",
            Self::Io(_) => "initialization key load failed",
            Self::Invalid(_) => "initialization key material is invalid",
            Self::Equal => "initialization key materials are equal",
        })
    }
}

impl std::error::Error for LoadError {}

/// The composition entry returns the private zeroizing pair only to a future
/// sibling fixed-root component; it exports neither role nor raw material.
fn load(root: &Path) -> Result<InitializationKeyPair, LoadError> {
    load_with(root, &mut NoLoadFaults)
}

/// The sole Task 0014 implementation frontier. The production body must
/// retain the owner lock and its identity-only root reference, open exactly
/// one matching readable directory descriptor, then validate and read the two
/// fixed final entries relative to that descriptor. It must not publish,
/// repair, rename, derive, or expose material.
fn load_with(root: &Path, hooks: &mut dyn LoadHooks) -> Result<InitializationKeyPair, LoadError> {
    use rustix::fd::AsFd;
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    use std::os::unix::ffi::OsStrExt;
    use zeroize::Zeroizing;

    const TEMPORARIES: [&str; 2] = [
        ".initialization-journal-integrity.tmp",
        ".initialization-portable-reservation.tmp",
    ];
    const FINALS: [&str; 2] = [
        "initialization-journal-integrity.key",
        "initialization-portable-reservation.key",
    ];

    fn observe(
        hooks: &mut dyn LoadHooks,
        step: LoadStep,
        phase: Phase,
        directory: Option<BorrowedFd<'_>>,
    ) -> Result<(), LoadError> {
        if hooks.at(step, phase, directory) == LoadDirective::Continue {
            return Ok(());
        }
        Err(match step {
            LoadStep::Policy => LoadError::Policy,
            LoadStep::Guard => LoadError::Root,
            LoadStep::Lock => LoadError::Lock,
            LoadStep::OpenRoot | LoadStep::TemporaryPreflight(_) => LoadError::Directory,
            _ => LoadError::Io(step),
        })
    }

    fn read_final(
        directory: BorrowedFd<'_>,
        name: &str,
        role: InitializationKeyRole,
        hooks: &mut dyn LoadHooks,
    ) -> Result<Zeroizing<[u8; 32]>, LoadError> {
        let open = LoadStep::Open(role);
        observe(hooks, open, Phase::Before, Some(directory))?;
        let before = match rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) => metadata,
            Err(rustix::io::Errno::NOENT) => return Err(LoadError::Entry(role)),
            Err(_) => return Err(LoadError::Io(open)),
        };
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_mode & 0o7777 != 0o600
            || before.st_uid != rustix::process::geteuid().as_raw()
            || before.st_nlink != 1
        {
            return Err(LoadError::Entry(role));
        }
        let file = match rustix::fs::openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => file,
            Err(rustix::io::Errno::NOENT | rustix::io::Errno::LOOP) => {
                return Err(LoadError::Entry(role));
            }
            Err(_) => return Err(LoadError::Io(open)),
        };
        let metadata = rustix::fs::fstat(&file).map_err(|_| LoadError::Io(open))?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_mode & 0o7777 != 0o600
            || metadata.st_uid != rustix::process::geteuid().as_raw()
            || metadata.st_nlink != 1
        {
            return Err(LoadError::Entry(role));
        }
        observe(hooks, open, Phase::After, Some(directory))?;

        let read = LoadStep::Read(role);
        observe(hooks, read, Phase::Before, Some(directory))?;
        let mut material = Zeroizing::new([0; 32]);
        if rustix::io::read(&file, &mut material[..]).map_err(|_| LoadError::Io(read))?
            != material.len()
        {
            return Err(LoadError::Invalid(role));
        }
        let mut eof = [0; 1];
        if rustix::io::read(&file, &mut eof).map_err(|_| LoadError::Io(read))? != 0 {
            return Err(LoadError::Invalid(role));
        }
        observe(hooks, read, Phase::After, Some(directory))?;

        let verify = LoadStep::Verify(role);
        observe(hooks, verify, Phase::Before, Some(directory))?;
        if material.iter().all(|byte| *byte == 0) {
            return Err(LoadError::Invalid(role));
        }
        observe(hooks, verify, Phase::After, Some(directory))?;
        Ok(material)
    }

    observe(hooks, LoadStep::Policy, Phase::Before, None)?;
    crate::apply_linux_startup_policy().map_err(|_| LoadError::Policy)?;
    observe(hooks, LoadStep::Policy, Phase::After, None)?;
    observe(hooks, LoadStep::Guard, Phase::Before, None)?;
    crate::ensure_linux_non_root().map_err(|_| LoadError::Root)?;
    observe(hooks, LoadStep::Guard, Phase::After, None)?;
    observe(hooks, LoadStep::Lock, Phase::Before, None)?;
    let (_owner_lock, root_reference) =
        crate::StateOwnerLock::acquire_with_private_root_reference(root)
            .map_err(|_| LoadError::Lock)?;
    observe(hooks, LoadStep::Lock, Phase::After, None)?;

    observe(hooks, LoadStep::OpenRoot, Phase::Before, None)?;
    let root_path =
        std::ffi::CString::new(root.as_os_str().as_bytes()).map_err(|_| LoadError::Directory)?;
    let directory = rustix::fs::openat(
        rustix::fs::CWD,
        root_path.as_c_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| LoadError::Directory)?;
    let opened = rustix::fs::fstat(&directory).map_err(|_| LoadError::Directory)?;
    let referenced = rustix::fs::fstat(&root_reference).map_err(|_| LoadError::Directory)?;
    if FileType::from_raw_mode(opened.st_mode) != FileType::Directory
        || opened.st_mode & 0o7777 != 0o700
        || opened.st_uid != rustix::process::geteuid().as_raw()
        || opened.st_dev != referenced.st_dev
        || opened.st_ino != referenced.st_ino
    {
        return Err(LoadError::Directory);
    }
    let dirfd = directory.as_fd();
    observe(hooks, LoadStep::OpenRoot, Phase::After, Some(dirfd))?;

    for (index, temporary) in (0_u8..).zip(TEMPORARIES) {
        let step = LoadStep::TemporaryPreflight(index);
        observe(hooks, step, Phase::Before, Some(dirfd))?;
        match rustix::fs::statat(directory.as_fd(), temporary, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            Ok(_) => return Err(LoadError::TemporaryEntry),
            Err(_) => return Err(LoadError::Directory),
        }
        observe(hooks, step, Phase::After, Some(dirfd))?;
    }

    let journal_integrity = read_final(
        dirfd,
        FINALS[0],
        InitializationKeyRole::JournalIntegrity,
        hooks,
    )?;
    let portable_reservation = read_final(
        dirfd,
        FINALS[1],
        InitializationKeyRole::PortableReservation,
        hooks,
    )?;
    if journal_integrity == portable_reservation {
        return Err(LoadError::Equal);
    }
    Ok(InitializationKeyPair {
        journal_integrity: super::JournalIntegrityKey(journal_integrity),
        portable_reservation: super::PortableReservationKey(portable_reservation),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicationError {
    MissingPublication,
    Policy,
    Root,
    Lock,
    Directory,
    ExistingEntry,
    Entropy(InitializationKeyPairError),
    Io(Step),
}

impl fmt::Display for PublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingPublication => "initialization key-pair publication is not implemented",
            Self::Policy => "initialization process policy failed",
            Self::Root => "initialization root execution refused",
            Self::Lock => "initialization owner lock failed",
            Self::Directory => "initialization directory unavailable",
            Self::ExistingEntry => "initialization key entry already exists",
            Self::Entropy(_) => "initialization key acquisition failed",
            Self::Io(_) => "initialization key publication failed",
        })
    }
}

impl std::error::Error for PublicationError {}

/// The composition entry exports neither the pair nor either role's bytes.
fn publish(root: &Path) -> Result<(), PublicationError> {
    publish_with(root, &mut super::OsInitializationEntropy, &mut NoFaults)
}

/// The sole Task 0008 implementation frontier. Future implementation must run
/// existing policy -> non-root guard -> retained StateOwnerLock here, then open
/// one root descriptor, preflight all four names, acquire through Task 0007,
/// and perform the two independent barriers. Only this body is unfrozen.
fn publish_with(
    _root: &Path,
    _source: &mut dyn InitializationEntropySource,
    _hooks: &mut dyn PublicationHooks,
) -> Result<(), PublicationError> {
    // FRONTIER: initialization_key_pair_publication
    use rustix::fd::AsFd;
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags};
    use std::os::unix::ffi::OsStrExt;

    const NAMES: [&str; 4] = [
        ".initialization-journal-integrity.tmp",
        "initialization-journal-integrity.key",
        ".initialization-portable-reservation.tmp",
        "initialization-portable-reservation.key",
    ];

    fn observe(
        hooks: &mut dyn PublicationHooks,
        step: Step,
        phase: Phase,
        directory: Option<BorrowedFd<'_>>,
    ) -> Result<Directive, PublicationError> {
        match hooks.at(step, phase, directory) {
            Directive::Continue => Ok(Directive::Continue),
            directive @ Directive::WriteLimit(_)
                if matches!((step, phase), (Step::Write(_), Phase::Before)) =>
            {
                Ok(directive)
            }
            _ => Err(match step {
                Step::Policy => PublicationError::Policy,
                Step::Guard => PublicationError::Root,
                Step::Lock => PublicationError::Lock,
                Step::OpenRoot | Step::Preflight(_) => PublicationError::Directory,
                _ => PublicationError::Io(step),
            }),
        }
    }

    observe(_hooks, Step::Policy, Phase::Before, None)?;
    crate::apply_linux_startup_policy().map_err(|_| PublicationError::Policy)?;
    observe(_hooks, Step::Policy, Phase::After, None)?;
    observe(_hooks, Step::Guard, Phase::Before, None)?;
    crate::ensure_linux_non_root().map_err(|_| PublicationError::Root)?;
    observe(_hooks, Step::Guard, Phase::After, None)?;
    observe(_hooks, Step::Lock, Phase::Before, None)?;
    let (_owner_lock, root_reference) =
        crate::StateOwnerLock::acquire_with_private_root_reference(_root)
            .map_err(|_| PublicationError::Lock)?;
    observe(_hooks, Step::Lock, Phase::After, None)?;

    observe(_hooks, Step::OpenRoot, Phase::Before, None)?;
    let root_path = std::ffi::CString::new(_root.as_os_str().as_bytes())
        .map_err(|_| PublicationError::Directory)?;
    let directory = rustix::fs::openat(
        rustix::fs::CWD,
        root_path.as_c_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| PublicationError::Directory)?;
    let dirfd = Some(directory.as_fd());
    let opened = rustix::fs::fstat(&directory).map_err(|_| PublicationError::Directory)?;
    let referenced = rustix::fs::fstat(&root_reference).map_err(|_| PublicationError::Directory)?;
    if FileType::from_raw_mode(opened.st_mode) != FileType::Directory
        || opened.st_mode & 0o7777 != 0o700
        || opened.st_uid != rustix::process::geteuid().as_raw()
        || opened.st_dev != referenced.st_dev
        || opened.st_ino != referenced.st_ino
    {
        return Err(PublicationError::Directory);
    }
    observe(_hooks, Step::OpenRoot, Phase::After, dirfd)?;
    for (index, name) in (0_u8..).zip(NAMES) {
        let step = Step::Preflight(index);
        observe(_hooks, step, Phase::Before, dirfd)?;
        match rustix::fs::statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            Ok(_) => return Err(PublicationError::ExistingEntry),
            Err(_) => return Err(PublicationError::Directory),
        }
        observe(_hooks, step, Phase::After, dirfd)?;
    }

    let pair =
        super::acquire_initialization_key_pair_with(_source).map_err(PublicationError::Entropy)?;
    // Borrow the original zeroizing owners; no intermediate secret copy exists.
    for (role, temporary, final_name, bytes) in [
        (
            InitializationKeyRole::JournalIntegrity,
            NAMES[0],
            NAMES[1],
            &pair.journal_integrity.0,
        ),
        (
            InitializationKeyRole::PortableReservation,
            NAMES[2],
            NAMES[3],
            &pair.portable_reservation.0,
        ),
    ] {
        let step = Step::Create(role);
        observe(_hooks, step, Phase::Before, dirfd)?;
        let file = rustix::fs::openat(
            &directory,
            temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| PublicationError::Io(step))?;
        observe(_hooks, step, Phase::After, dirfd)?;

        let step = Step::Write(role);
        let count = match observe(_hooks, step, Phase::Before, dirfd)? {
            Directive::WriteLimit(count) => count.min(bytes.len()),
            _ => bytes.len(),
        };
        let written =
            rustix::io::write(&file, &bytes[..count]).map_err(|_| PublicationError::Io(step))?;
        if written != bytes.len() {
            return Err(PublicationError::Io(step));
        }
        observe(_hooks, step, Phase::After, dirfd)?;

        let step = Step::FileSync(role);
        observe(_hooks, step, Phase::Before, dirfd)?;
        rustix::fs::fsync(&file).map_err(|_| PublicationError::Io(step))?;
        observe(_hooks, step, Phase::After, dirfd)?;

        let step = Step::Rename(role);
        observe(_hooks, step, Phase::Before, dirfd)?;
        rustix::fs::renameat_with(
            &directory,
            temporary,
            &directory,
            final_name,
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| PublicationError::Io(step))?;
        observe(_hooks, step, Phase::After, dirfd)?;

        let step = Step::DirectorySync(role);
        observe(_hooks, step, Phase::Before, dirfd)?;
        rustix::fs::fsync(&directory).map_err(|_| PublicationError::Io(step))?;
        observe(_hooks, step, Phase::After, dirfd)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "red_publication.rs"]
mod red_publication;

#[cfg(test)]
#[path = "red_load.rs"]
mod red_load;
