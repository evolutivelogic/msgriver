//! MsgRiver platform primitives.
//!
//! This library is intentionally private to the unpublished composition-root
//! package. Its first frozen RED seam is the fixed-root owner lock; it is not
//! a service, maintenance command, or client protocol.

#![forbid(unsafe_code)]

pub mod bootstrap_envelope;
pub mod jitter_source;
// Task 0007 remains a private compiling RED frontier.
#[allow(dead_code)]
mod initialization_key_pair;
#[cfg(test)]
mod phase_zero;
#[cfg(test)]
mod phase_zero_deployment_hermetic_negative;
#[cfg(test)]
mod phase_zero_deployment_red;
#[cfg(test)]
mod phase_zero_reference_loop_fixture;
#[cfg(test)]
mod phase_zero_reference_loop_hermetic_negative;
#[cfg(test)]
mod phase_zero_reference_loop_red;
pub mod service_bootstrap;
mod state_mac_key_directory_verifier;
mod state_mac_key_high_water;
mod state_mac_key_manifest;
mod state_mac_key_manifest_row;
mod state_mac_key_meta_row;
mod state_mac_key_path;
mod state_mac_key_reader;
mod state_mac_key_snapshot;

use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, FileType, FlockOperation, Mode, OFlags};
use rustix::process::{
    DumpableBehavior, Resource, Rlimit, dumpable_behavior, getrlimit, set_dumpable_behavior,
    setrlimit, umask,
};
use std::ffi::CString;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// Private, redacted Task 0006 frontier in the unpublished composition root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum LinuxRootRefusalError {
    /// The service process must not run with effective UID zero.
    RootRefused,
    /// The frozen RED guard has not been implemented.
    MissingGuard,
}

impl fmt::Display for LinuxRootRefusalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RootRefused => "Linux service process must not run as root",
            Self::MissingGuard => "Linux root refusal guard is not implemented",
        })
    }
}

impl std::error::Error for LinuxRootRefusalError {}

/// Task 0006 production observation frontier; only this body may change after RED.
#[doc(hidden)]
pub fn ensure_linux_non_root() -> Result<(), LinuxRootRefusalError> {
    ensure_linux_non_root_with(rustix::process::geteuid().as_raw())
}

/// Task 0006 injected decision frontier; only this body may change after RED.
#[doc(hidden)]
pub fn ensure_linux_non_root_with(_effective_uid: u32) -> Result<(), LinuxRootRefusalError> {
    if _effective_uid == 0 {
        Err(LinuxRootRefusalError::RootRefused)
    } else {
        Ok(())
    }
}

/// One fallible operation in the Linux startup-policy sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum LinuxStartupPolicyStep {
    /// Install the exact restrictive creation mask.
    InstallUmask,
    /// Reduce both core resource limits.
    SetCoreLimits,
    /// Disable process dumpability.
    SetNotDumpable,
    /// Read verified core limits.
    ReadCoreLimits,
    /// Read verified dumpability.
    ReadDumpability,
}

/// Non-sensitive process-policy values verified after installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct LinuxStartupPolicyReadback {
    /// Current core soft limit.
    pub core_soft: u64,
    /// Current core hard limit.
    pub core_hard: u64,
    /// Whether the process remains dumpable.
    pub dumpable: bool,
}

/// Opaque adapter failure used only by the private process-policy seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum LinuxStartupPolicyAdapterError {
    /// A platform operation or its observation failed.
    Failed,
}

/// Private OS adapter used to freeze fallible-policy behavior without mutating
/// the test runner's process-wide settings.
#[doc(hidden)]
pub trait LinuxStartupPolicyAdapter {
    /// Execute one state-changing or read operation.
    fn run_step(
        &mut self,
        step: LinuxStartupPolicyStep,
    ) -> Result<(), LinuxStartupPolicyAdapterError>;
    /// Return the independently observed process-policy state.
    fn readback(&mut self) -> Result<LinuxStartupPolicyReadback, LinuxStartupPolicyAdapterError>;
}

/// Closed, redacted Linux startup-policy failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxStartupPolicyError {
    /// Installing a required process setting failed.
    Install,
    /// A required process-policy readback was unavailable or inconsistent.
    Verification,
}

impl fmt::Display for LinuxStartupPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Install => "Linux startup policy installation failed",
            Self::Verification => "Linux startup policy verification failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for LinuxStartupPolicyError {}

/// Install the restrictive process policy before any protected work.
#[doc(hidden)]
pub fn apply_linux_startup_policy() -> Result<(), LinuxStartupPolicyError> {
    let mut adapter = RustixLinuxStartupPolicyAdapter;
    apply_linux_startup_policy_with(&mut adapter)
}

/// Private injectable counterpart of [`apply_linux_startup_policy`].
#[doc(hidden)]
pub fn apply_linux_startup_policy_with(
    adapter: &mut dyn LinuxStartupPolicyAdapter,
) -> Result<(), LinuxStartupPolicyError> {
    for step in [
        LinuxStartupPolicyStep::InstallUmask,
        LinuxStartupPolicyStep::SetCoreLimits,
        LinuxStartupPolicyStep::SetNotDumpable,
        LinuxStartupPolicyStep::ReadCoreLimits,
        LinuxStartupPolicyStep::ReadDumpability,
    ] {
        adapter
            .run_step(step)
            .map_err(|_| LinuxStartupPolicyError::Install)?;
    }
    let readback = adapter
        .readback()
        .map_err(|_| LinuxStartupPolicyError::Verification)?;
    if readback.core_soft != 0 || readback.core_hard != 0 || readback.dumpable {
        return Err(LinuxStartupPolicyError::Verification);
    }
    Ok(())
}

struct RustixLinuxStartupPolicyAdapter;

impl LinuxStartupPolicyAdapter for RustixLinuxStartupPolicyAdapter {
    fn run_step(
        &mut self,
        step: LinuxStartupPolicyStep,
    ) -> Result<(), LinuxStartupPolicyAdapterError> {
        match step {
            LinuxStartupPolicyStep::InstallUmask => {
                umask(Mode::from_raw_mode(0o077));
                Ok(())
            }
            LinuxStartupPolicyStep::SetCoreLimits => setrlimit(
                Resource::Core,
                Rlimit {
                    current: Some(0),
                    maximum: Some(0),
                },
            )
            .map_err(|_| LinuxStartupPolicyAdapterError::Failed),
            LinuxStartupPolicyStep::SetNotDumpable => {
                set_dumpable_behavior(DumpableBehavior::NotDumpable)
                    .map_err(|_| LinuxStartupPolicyAdapterError::Failed)
            }
            LinuxStartupPolicyStep::ReadCoreLimits => {
                let _ = getrlimit(Resource::Core);
                Ok(())
            }
            LinuxStartupPolicyStep::ReadDumpability => {
                let _ = dumpable_behavior().map_err(|_| LinuxStartupPolicyAdapterError::Failed)?;
                Ok(())
            }
        }
    }

    fn readback(&mut self) -> Result<LinuxStartupPolicyReadback, LinuxStartupPolicyAdapterError> {
        let limits = getrlimit(Resource::Core);
        let dumpable = dumpable_behavior().map_err(|_| LinuxStartupPolicyAdapterError::Failed)?;
        Ok(LinuxStartupPolicyReadback {
            core_soft: limits.current.unwrap_or(u64::MAX),
            core_hard: limits.maximum.unwrap_or(u64::MAX),
            dumpable: dumpable != DumpableBehavior::NotDumpable,
        })
    }
}

/// Closed, redacted state-owner-lock failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateOwnerLockError {
    /// The fixed state root is not a private directory.
    UnsafeRoot,
    /// The fixed lock entry is not a safe private regular file.
    UnsafeEntry,
    /// Opening the lock entry failed.
    Open,
    /// Another process currently retains ownership.
    Contended,
    /// The operating-system lock operation failed.
    Lock,
}

impl fmt::Display for StateOwnerLockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafeRoot => formatter.write_str("state owner root is unsafe"),
            Self::UnsafeEntry => formatter.write_str("state owner lock entry is unsafe"),
            Self::Open => formatter.write_str("state owner lock open failed"),
            Self::Contended => formatter.write_str("state owner lock is active"),
            Self::Lock => formatter.write_str("state owner lock acquisition failed"),
        }
    }
}

impl std::error::Error for StateOwnerLockError {}

/// Retained exclusive ownership of one fixed state-root lock entry.
pub struct StateOwnerLock {
    file: OwnedFd,
}

impl StateOwnerLock {
    /// Acquire the fixed-root lock before any protected state work.
    pub fn acquire(root: &Path) -> Result<Self, StateOwnerLockError> {
        let root_reference = open_private_root_reference(root)?;
        acquire_owner_lock(&root_reference)
    }

    /// Acquire the owner lock and retain a no-follow root identity reference.
    ///
    /// The descriptor is intentionally crate-private: the publication boundary
    /// needs it to reject a root rebind before opening its sole operational
    /// directory descriptor. Public callers retain the original lock-only API
    /// above.
    pub(crate) fn acquire_with_private_root_reference(
        root: &Path,
    ) -> Result<(Self, OwnedFd), StateOwnerLockError> {
        let root_reference = open_private_root_reference(root)?;
        let lock = acquire_owner_lock(&root_reference)?;
        Ok((lock, root_reference))
    }
}

impl fmt::Debug for StateOwnerLock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StateOwnerLock(..)")
    }
}

impl Drop for StateOwnerLock {
    fn drop(&mut self) {
        let _ = rustix::fs::flock(&self.file, FlockOperation::Unlock);
    }
}

pub(crate) fn validate_private_root(root: &Path) -> Result<(), StateOwnerLockError> {
    let _root = open_private_root(root)?;
    Ok(())
}

fn open_private_root(root: &Path) -> Result<OwnedFd, StateOwnerLockError> {
    open_private_root_with(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
    )
}

/// Hold an identity-only, no-follow root reference while a caller obtains the
/// one readable directory descriptor it will use for protected child I/O.
/// `O_PATH` deliberately has no directory-read capability, so it cannot be
/// mistaken for that operational descriptor or used for key operations.
fn open_private_root_reference(root: &Path) -> Result<OwnedFd, StateOwnerLockError> {
    open_private_root_with(root, OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC)
}

fn open_private_root_with(root: &Path, flags: OFlags) -> Result<OwnedFd, StateOwnerLockError> {
    let metadata = std::fs::symlink_metadata(root).map_err(|_| StateOwnerLockError::UnsafeRoot)?;
    if !metadata.file_type().is_dir()
        || unix_mode(&metadata) != 0o700
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(StateOwnerLockError::UnsafeRoot);
    }
    let root_path =
        CString::new(root.as_os_str().as_bytes()).map_err(|_| StateOwnerLockError::UnsafeRoot)?;
    let directory = rustix::fs::openat(rustix::fs::CWD, root_path.as_c_str(), flags, Mode::empty())
        .map_err(|_| StateOwnerLockError::UnsafeRoot)?;
    let opened = rustix::fs::fstat(&directory).map_err(|_| StateOwnerLockError::UnsafeRoot)?;
    if FileType::from_raw_mode(opened.st_mode) != FileType::Directory
        || opened.st_mode & 0o7777 != 0o700
        || opened.st_uid != rustix::process::geteuid().as_raw()
        || opened.st_dev != metadata.dev()
        || opened.st_ino != metadata.ino()
    {
        return Err(StateOwnerLockError::UnsafeRoot);
    }
    Ok(directory)
}

fn acquire_owner_lock(root_reference: &OwnedFd) -> Result<StateOwnerLock, StateOwnerLockError> {
    let file = open_lock_entry(root_reference)?;
    match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(StateOwnerLock { file }),
        #[allow(unreachable_patterns)]
        Err(rustix::io::Errno::AGAIN | rustix::io::Errno::WOULDBLOCK) => {
            Err(StateOwnerLockError::Contended)
        }
        Err(_) => Err(StateOwnerLockError::Lock),
    }
}

/// Open the fixed lock entry only relative to the already-validated identity
/// reference. This prevents a later pathname rebind from selecting a lock in
/// a different root between root validation and ownership acquisition.
fn open_lock_entry(root_reference: &OwnedFd) -> Result<OwnedFd, StateOwnerLockError> {
    match rustix::fs::openat(
        root_reference,
        "msgriver.lock",
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(file) => {
            rustix::fs::fchmod(&file, Mode::RUSR | Mode::WUSR)
                .map_err(|_| StateOwnerLockError::Open)?;
            let metadata = rustix::fs::fstat(&file).map_err(|_| StateOwnerLockError::Open)?;
            validate_lock_metadata(&metadata)?;
            Ok(file)
        }
        Err(rustix::io::Errno::EXIST) => open_existing_lock_entry(root_reference),
        Err(_) => Err(StateOwnerLockError::Open),
    }
}

fn open_existing_lock_entry(root_reference: &OwnedFd) -> Result<OwnedFd, StateOwnerLockError> {
    let before = safe_lock_entry_metadata(root_reference)?;
    let file = rustix::fs::openat(
        root_reference,
        "msgriver.lock",
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| StateOwnerLockError::Open)?;
    let opened = rustix::fs::fstat(&file).map_err(|_| StateOwnerLockError::Open)?;
    validate_lock_metadata(&opened)?;
    if !same_identity(&before, &opened) {
        return Err(StateOwnerLockError::UnsafeEntry);
    }
    let after = safe_lock_entry_metadata(root_reference)?;
    if !same_identity(&opened, &after) {
        return Err(StateOwnerLockError::UnsafeEntry);
    }
    Ok(file)
}

fn safe_lock_entry_metadata(
    root_reference: &OwnedFd,
) -> Result<rustix::fs::Stat, StateOwnerLockError> {
    let metadata = rustix::fs::statat(root_reference, "msgriver.lock", AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| StateOwnerLockError::Open)?;
    validate_lock_metadata(&metadata)?;
    Ok(metadata)
}

fn validate_lock_metadata(metadata: &rustix::fs::Stat) -> Result<(), StateOwnerLockError> {
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_mode & 0o7777 != 0o600
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_nlink != 1
    {
        return Err(StateOwnerLockError::UnsafeEntry);
    }
    Ok(())
}

fn same_identity(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

fn unix_mode(metadata: &std::fs::Metadata) -> u32 {
    metadata.permissions().mode() & 0o777
}
