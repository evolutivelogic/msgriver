//! Private descriptor-bound active-state pointer publication boundary.

use super::{
    super::active_state_pointer::{ActiveStatePointer, encode_active_state_pointer},
    ActiveStatePointerCallerCapability, JournalIntegrityKey, PointerRenamed,
};
use rustix::fd::BorrowedFd;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags};
use sha2::{Digest, Sha256};

const ACTIVE_STATE_NAME: &str = "active-state";
const TEMPORARY_NAME_DOMAIN: &[u8] = b"msgriver/active-state-pointer-temp/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum ActiveStatePointerPublicationMode {
    RequireAbsent,
    ReplaceExisting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum ActiveStatePointerPublisherError {
    MissingActiveStatePointerPublisher,
    InvalidActiveStatePointerPublisher,
}

pub(super) fn publish_active_state_pointer<'capability>(
    capability: &'capability mut ActiveStatePointerCallerCapability,
    key: &JournalIntegrityKey,
    pointer: &ActiveStatePointer,
    mode: ActiveStatePointerPublicationMode,
) -> Result<PointerRenamed<'capability>, ActiveStatePointerPublisherError> {
    publish_active_state_pointer_inner(
        capability.operational_directory(),
        key,
        pointer,
        mode,
        PublisherFault::None,
    )?;
    Ok(capability.renamed())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublisherFault {
    None,
    #[cfg(test)]
    TemporaryFsync,
    #[cfg(test)]
    RootFsync,
    #[cfg(test)]
    RenameNoReplace,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum PublisherTestFault {
    TemporaryFsync,
    RootFsync,
    RenameNoReplace,
}

#[cfg(test)]
pub(super) fn publish_active_state_pointer_with_test_fault<'capability>(
    capability: &'capability mut ActiveStatePointerCallerCapability,
    key: &JournalIntegrityKey,
    pointer: &ActiveStatePointer,
    mode: ActiveStatePointerPublicationMode,
    fault: PublisherTestFault,
) -> Result<PointerRenamed<'capability>, ActiveStatePointerPublisherError> {
    let fault = match fault {
        PublisherTestFault::TemporaryFsync => PublisherFault::TemporaryFsync,
        PublisherTestFault::RootFsync => PublisherFault::RootFsync,
        PublisherTestFault::RenameNoReplace => PublisherFault::RenameNoReplace,
    };
    publish_active_state_pointer_inner(
        capability.operational_directory(),
        key,
        pointer,
        mode,
        fault,
    )?;
    Ok(capability.renamed())
}

fn publish_active_state_pointer_inner(
    directory: BorrowedFd<'_>,
    key: &JournalIntegrityKey,
    pointer: &ActiveStatePointer,
    mode: ActiveStatePointerPublicationMode,
    fault: PublisherFault,
) -> Result<(), ActiveStatePointerPublisherError> {
    // FRONTIER: active_state_pointer_publisher (closed by this private helper).
    let directory_metadata = rustix::fs::fstat(directory)
        .map_err(|_| ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher)?;
    if FileType::from_raw_mode(directory_metadata.st_mode) != FileType::Directory {
        return Err(ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher);
    }
    let wire = encode_active_state_pointer(key, pointer)
        .map_err(|_| ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher)?;
    let temporary = temporary_basename(pointer);
    let temporary_file = open_or_verify_temporary(directory, temporary.as_str(), &wire)?;
    sync_temporary(&temporary_file, fault)?;

    match mode {
        ActiveStatePointerPublicationMode::RequireAbsent => {
            rename_require_absent(directory, temporary.as_str(), fault)?
        }
        ActiveStatePointerPublicationMode::ReplaceExisting => {
            verify_replaceable_destination(directory)?;
            rustix::fs::renameat(directory, temporary.as_str(), directory, ACTIVE_STATE_NAME)
                .map_err(|_| {
                    ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher
                })?;
        }
    }
    sync_root(directory, fault)?;
    Ok(())
}

fn temporary_basename(pointer: &ActiveStatePointer) -> String {
    let mut digest = Sha256::new();
    digest.update(TEMPORARY_NAME_DOMAIN);
    digest.update(pointer.transition_id.as_bytes());
    format!("active-state.tmp.{:x}", digest.finalize())
}

fn open_or_verify_temporary(
    directory: BorrowedFd<'_>,
    temporary: &str,
    wire: &[u8],
) -> Result<rustix::fd::OwnedFd, ActiveStatePointerPublisherError> {
    match rustix::fs::openat(
        directory,
        temporary,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(file) => {
            write_all(&file, wire)?;
            Ok(file)
        }
        Err(rustix::io::Errno::EXIST) => verify_exact_temporary(directory, temporary, wire),
        Err(_) => Err(ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher),
    }
}

fn verify_exact_temporary(
    directory: BorrowedFd<'_>,
    temporary: &str,
    wire: &[u8],
) -> Result<rustix::fd::OwnedFd, ActiveStatePointerPublisherError> {
    let before = rustix::fs::statat(directory, temporary, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher)?;
    if !is_owner_only_file(&before, Some(wire.len())) {
        return Err(ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher);
    }
    let file = rustix::fs::openat(
        directory,
        temporary,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher)?;
    let after = rustix::fs::fstat(&file)
        .map_err(|_| ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher)?;
    if !is_owner_only_file(&after, Some(wire.len()))
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
    {
        return Err(ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher);
    }
    let mut actual = vec![0; wire.len()];
    read_exact(&file, &mut actual)?;
    if actual != wire {
        return Err(ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher);
    }
    Ok(file)
}

fn verify_replaceable_destination(
    directory: BorrowedFd<'_>,
) -> Result<(), ActiveStatePointerPublisherError> {
    let before = rustix::fs::statat(directory, ACTIVE_STATE_NAME, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher)?;
    if !is_owner_only_file(&before, None) {
        return Err(ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher);
    }
    let file = rustix::fs::openat(
        directory,
        ACTIVE_STATE_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher)?;
    let after = rustix::fs::fstat(&file)
        .map_err(|_| ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher)?;
    if !is_owner_only_file(&after, None)
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
    {
        return Err(ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher);
    }
    Ok(())
}

fn is_owner_only_file(metadata: &rustix::fs::Stat, expected_size: Option<usize>) -> bool {
    FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile
        && metadata.st_mode & 0o7777 == 0o600
        && metadata.st_uid == rustix::process::geteuid().as_raw()
        && metadata.st_nlink == 1
        && expected_size.is_none_or(|size| metadata.st_size == size as i64)
}

fn write_all(
    file: &rustix::fd::OwnedFd,
    mut bytes: &[u8],
) -> Result<(), ActiveStatePointerPublisherError> {
    while !bytes.is_empty() {
        match rustix::io::write(file, bytes) {
            Ok(0) => {
                return Err(ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher);
            }
            Ok(count) => bytes = &bytes[count..],
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => {
                return Err(ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher);
            }
        }
    }
    Ok(())
}

fn read_exact(
    file: &rustix::fd::OwnedFd,
    bytes: &mut [u8],
) -> Result<(), ActiveStatePointerPublisherError> {
    let mut offset = 0;
    while offset < bytes.len() {
        match rustix::io::read(file, &mut bytes[offset..]) {
            Ok(0) => {
                return Err(ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher);
            }
            Ok(count) => offset += count,
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => {
                return Err(ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher);
            }
        }
    }
    let mut trailing = [0; 1];
    loop {
        match rustix::io::read(file, &mut trailing) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                return Err(ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher);
            }
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => {
                return Err(ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher);
            }
        }
    }
}

fn rename_require_absent(
    directory: BorrowedFd<'_>,
    temporary: &str,
    fault: PublisherFault,
) -> Result<(), ActiveStatePointerPublisherError> {
    #[cfg(test)]
    if fault == PublisherFault::RenameNoReplace {
        return Err(ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher);
    }
    #[cfg(not(test))]
    let _ = fault;
    rustix::fs::renameat_with(
        directory,
        temporary,
        directory,
        ACTIVE_STATE_NAME,
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher)
}

fn sync_temporary(
    file: &rustix::fd::OwnedFd,
    fault: PublisherFault,
) -> Result<(), ActiveStatePointerPublisherError> {
    #[cfg(test)]
    if fault == PublisherFault::TemporaryFsync {
        return Err(ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher);
    }
    #[cfg(not(test))]
    let _ = fault;
    rustix::fs::fsync(file)
        .map_err(|_| ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher)
}

fn sync_root(
    directory: BorrowedFd<'_>,
    fault: PublisherFault,
) -> Result<(), ActiveStatePointerPublisherError> {
    #[cfg(test)]
    if fault == PublisherFault::RootFsync {
        return Err(ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher);
    }
    #[cfg(not(test))]
    let _ = fault;
    rustix::fs::fsync(directory)
        .map_err(|_| ActiveStatePointerPublisherError::InvalidActiveStatePointerPublisher)
}

#[cfg(test)]
#[path = "red_active_state_pointer_publisher.rs"]
mod red_active_state_pointer_publisher;
