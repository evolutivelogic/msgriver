//! Private descriptor-relative state-MAC-key reader boundary.

#![allow(dead_code)]

use crate::initialization_key_pair::{
    JournalIntegrityKey, StateMacKeySecret, decode_state_mac_key_file,
};
use crate::state_mac_key_path::state_mac_key_relative_path;
use msgriver_core::canon::MacKeyRef;
use rustix::fd::BorrowedFd;
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StateMacKeyReaderError {
    MissingStateKeyReader,
    InvalidStateKeyReader,
}

pub(super) fn read_state_mac_key(
    directory: BorrowedFd<'_>,
    key: &JournalIntegrityKey,
    reference: MacKeyRef,
) -> Result<StateMacKeySecret, StateMacKeyReaderError> {
    let path = state_mac_key_relative_path(reference)
        .map_err(|_| StateMacKeyReaderError::InvalidStateKeyReader)?;
    let purpose = std::ffi::CString::new(path.0[4..6].to_vec())
        .map_err(|_| StateMacKeyReaderError::InvalidStateKeyReader)?;
    let leaf = std::ffi::CString::new(path.0[7..].to_vec())
        .map_err(|_| StateMacKeyReaderError::InvalidStateKeyReader)?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mac = rustix::fs::openat(directory, c"mac", directory_flags, Mode::empty())
        .map_err(|_| StateMacKeyReaderError::InvalidStateKeyReader)?;
    let purpose_directory =
        rustix::fs::openat(&mac, purpose.as_c_str(), directory_flags, Mode::empty())
            .map_err(|_| StateMacKeyReaderError::InvalidStateKeyReader)?;

    let before = rustix::fs::statat(
        &purpose_directory,
        leaf.as_c_str(),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|_| StateMacKeyReaderError::InvalidStateKeyReader)?;
    if !is_owner_only_state_key_file(&before) {
        return Err(StateMacKeyReaderError::InvalidStateKeyReader);
    }
    let file = rustix::fs::openat(
        &purpose_directory,
        leaf.as_c_str(),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| StateMacKeyReaderError::InvalidStateKeyReader)?;
    let after =
        rustix::fs::fstat(&file).map_err(|_| StateMacKeyReaderError::InvalidStateKeyReader)?;
    if !is_owner_only_state_key_file(&after)
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
    {
        return Err(StateMacKeyReaderError::InvalidStateKeyReader);
    }

    let mut wire = Zeroizing::new([0; 106]);
    if rustix::io::read(&file, &mut wire[..])
        .map_err(|_| StateMacKeyReaderError::InvalidStateKeyReader)?
        != wire.len()
    {
        return Err(StateMacKeyReaderError::InvalidStateKeyReader);
    }
    let mut eof = [0; 1];
    if rustix::io::read(&file, &mut eof)
        .map_err(|_| StateMacKeyReaderError::InvalidStateKeyReader)?
        != 0
    {
        return Err(StateMacKeyReaderError::InvalidStateKeyReader);
    }
    decode_state_mac_key_file(key, reference, &wire[..])
        .map_err(|_| StateMacKeyReaderError::InvalidStateKeyReader)
}

fn is_owner_only_state_key_file(metadata: &rustix::fs::Stat) -> bool {
    FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile
        && metadata.st_mode & 0o7777 == 0o600
        && metadata.st_uid == rustix::process::geteuid().as_raw()
        && metadata.st_nlink == 1
        && metadata.st_size == 106
}

#[cfg(test)]
#[path = "red_state_mac_key_reader.rs"]
mod red_state_mac_key_reader;
