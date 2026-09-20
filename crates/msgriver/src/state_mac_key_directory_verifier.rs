//! Private complete staged state-MAC-key directory verification boundary.
//!
//! This verifier receives only an already-open generation descriptor and
//! already-validated manifest rows. It cannot discover, select, make state
//! active, or otherwise mutate it.

#![allow(dead_code)]

use crate::initialization_key_pair::{JournalIntegrityKey, decode_state_mac_key_file};
use crate::state_mac_key_manifest_row::StateMacKeyManifestRow;
use crate::state_mac_key_path::state_mac_key_relative_path;
use msgriver_core::canon::MacKeyRef;
use rustix::fd::{AsFd, BorrowedFd};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use zeroize::Zeroizing;

const PURPOSE_NAMES: [&[u8]; 11] = [
    b"01", b"02", b"03", b"04", b"05", b"06", b"07", b"08", b"09", b"0a", b"0b",
];

#[derive(Clone, Copy)]
struct ExpectedPurpose {
    references: [Option<MacKeyRef>; 16],
    count: usize,
}

const EMPTY_EXPECTED_PURPOSE: ExpectedPurpose = ExpectedPurpose {
    references: [None; 16],
    count: 0,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StateMacKeyDirectoryVerifierError {
    MissingStateMacKeyDirectoryVerifier,
    InvalidStateMacKeyDirectoryVerifier,
}

pub(super) fn verify_state_mac_key_directory(
    generation: BorrowedFd<'_>,
    key: &JournalIntegrityKey,
    rows: &[StateMacKeyManifestRow],
) -> Result<(), StateMacKeyDirectoryVerifierError> {
    // FRONTIER: state_mac_key_directory_verifier
    let expected = expected_purposes(rows)?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mac = rustix::fs::openat(generation, c"mac", directory_flags, Mode::empty())
        .map_err(|_| StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier)?;
    verify_namespace_entries(mac.as_fd())?;

    for (purpose_index, purpose_name) in PURPOSE_NAMES.iter().enumerate() {
        let purpose_name = std::ffi::CString::new(*purpose_name)
            .map_err(|_| StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier)?;
        let purpose = rustix::fs::openat(
            &mac,
            purpose_name.as_c_str(),
            directory_flags,
            Mode::empty(),
        )
        .map_err(|_| StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier)?;
        let metadata = rustix::fs::fstat(&purpose)
            .map_err(|_| StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier)?;
        if !is_owner_only_purpose_directory(&metadata) {
            return Err(StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier);
        }
        verify_purpose_entries(purpose.as_fd(), key, expected[purpose_index])?;
    }
    Ok(())
}

fn expected_purposes(
    rows: &[StateMacKeyManifestRow],
) -> Result<[ExpectedPurpose; 11], StateMacKeyDirectoryVerifierError> {
    let mut purposes = [EMPTY_EXPECTED_PURPOSE; 11];
    for row in rows {
        let purpose_index = usize::from(row.reference.purpose() as u8)
            .checked_sub(1)
            .filter(|index| *index < purposes.len())
            .ok_or(StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier)?;
        let expected = &mut purposes[purpose_index];
        if expected.count == expected.references.len() {
            return Err(StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier);
        }
        let leaf = leaf_name(row.reference)?;
        for reference in expected.references[..expected.count].iter().flatten() {
            if leaf_name(*reference)? == leaf {
                return Err(StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier);
            }
        }
        expected.references[expected.count] = Some(row.reference);
        expected.count += 1;
    }
    Ok(purposes)
}

fn verify_namespace_entries(mac: BorrowedFd<'_>) -> Result<(), StateMacKeyDirectoryVerifierError> {
    let mut seen = [false; 11];
    let mut entries = Dir::read_from(mac)
        .map_err(|_| StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier)?;
    while let Some(entry) = entries.read() {
        let entry = entry
            .map_err(|_| StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let Some(index) = PURPOSE_NAMES.iter().position(|expected| *expected == name) else {
            return Err(StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier);
        };
        if seen[index] {
            return Err(StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier);
        }
        seen[index] = true;
    }
    if seen.into_iter().any(|present| !present) {
        return Err(StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier);
    }
    Ok(())
}

fn verify_purpose_entries(
    purpose: BorrowedFd<'_>,
    key: &JournalIntegrityKey,
    expected: ExpectedPurpose,
) -> Result<(), StateMacKeyDirectoryVerifierError> {
    let mut seen = [false; 16];
    let mut entries = Dir::read_from(purpose)
        .map_err(|_| StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier)?;
    while let Some(entry) = entries.read() {
        let entry = entry
            .map_err(|_| StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let Some(index) = expected.references[..expected.count]
            .iter()
            .enumerate()
            .find_map(|(index, reference)| {
                let reference = (*reference)?;
                (leaf_name(reference).ok()?.as_slice() == name).then_some(index)
            })
        else {
            return Err(StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier);
        };
        if seen[index] {
            return Err(StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier);
        }
        seen[index] = true;
    }
    if seen[..expected.count].iter().any(|present| !present) {
        return Err(StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier);
    }
    for reference in expected.references[..expected.count].iter().flatten() {
        read_authenticated_leaf(purpose, key, *reference)?;
    }
    Ok(())
}

fn read_authenticated_leaf(
    purpose: BorrowedFd<'_>,
    key: &JournalIntegrityKey,
    reference: MacKeyRef,
) -> Result<(), StateMacKeyDirectoryVerifierError> {
    let leaf = std::ffi::CString::new(leaf_name(reference)?)
        .map_err(|_| StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier)?;
    let before = rustix::fs::statat(purpose, leaf.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier)?;
    if !is_owner_only_state_key_file(&before) {
        return Err(StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier);
    }
    let file = rustix::fs::openat(
        purpose,
        leaf.as_c_str(),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier)?;
    let after = rustix::fs::fstat(&file)
        .map_err(|_| StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier)?;
    if !is_owner_only_state_key_file(&after)
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
    {
        return Err(StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier);
    }

    let mut wire = Zeroizing::new([0; 106]);
    if rustix::io::read(&file, &mut wire[..])
        .map_err(|_| StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier)?
        != wire.len()
    {
        return Err(StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier);
    }
    let mut eof = Zeroizing::new([0; 1]);
    if rustix::io::read(&file, &mut eof[..])
        .map_err(|_| StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier)?
        != 0
    {
        return Err(StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier);
    }
    let _secret = decode_state_mac_key_file(key, reference, &wire[..])
        .map_err(|_| StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier)?;
    Ok(())
}

fn leaf_name(reference: MacKeyRef) -> Result<[u8; 83], StateMacKeyDirectoryVerifierError> {
    state_mac_key_relative_path(reference)
        .map_err(|_| StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier)?
        .0[7..]
        .try_into()
        .map_err(|_| StateMacKeyDirectoryVerifierError::InvalidStateMacKeyDirectoryVerifier)
}

fn is_owner_only_purpose_directory(metadata: &rustix::fs::Stat) -> bool {
    FileType::from_raw_mode(metadata.st_mode) == FileType::Directory
        && metadata.st_mode & 0o7777 == 0o700
        && metadata.st_uid == rustix::process::geteuid().as_raw()
}

fn is_owner_only_state_key_file(metadata: &rustix::fs::Stat) -> bool {
    FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile
        && metadata.st_mode & 0o7777 == 0o600
        && metadata.st_uid == rustix::process::geteuid().as_raw()
        && metadata.st_nlink == 1
        && metadata.st_size == 106
}

#[cfg(test)]
#[path = "red_state_mac_key_directory_verifier.rs"]
mod red_state_mac_key_directory_verifier;
