//! Private candidate-generation reopen RED frontier.

use super::PointerNamedGeneration;
use rustix::fd::OwnedFd;
use rustix::fs::{FileType, Mode, OFlags};
use std::marker::PhantomData;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ActiveStatePointerGenerationReopenError {
    MissingCandidateReopen,
    RejectedCandidateReopen,
}

/// Private descriptor ownership cannot outlive the pointer-named handle.
pub(super) struct PointerReopenedGeneration<'handle, 'coordinator, 'capability> {
    _handle: PhantomData<&'handle PointerNamedGeneration<'coordinator, 'capability>>,
    _candidate: OwnedFd,
}

impl<'coordinator, 'capability> PointerNamedGeneration<'coordinator, 'capability> {
    // FRONTIER: active_state_pointer_generation_reopen
    pub(super) fn reopen_candidate<'handle>(
        &'handle self,
    ) -> Result<
        PointerReopenedGeneration<'handle, 'coordinator, 'capability>,
        ActiveStatePointerGenerationReopenError,
    > {
        if self.final_generation == 0 {
            return Err(ActiveStatePointerGenerationReopenError::RejectedCandidateReopen);
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let generations = rustix::fs::openat(
            self._operational_directory,
            c"generations",
            flags,
            Mode::empty(),
        )
        .map_err(|_| ActiveStatePointerGenerationReopenError::RejectedCandidateReopen)?;
        require_owner_directory(&generations)?;
        let name = std::ffi::CString::new(format!("g-{:016x}", self.final_generation))
            .map_err(|_| ActiveStatePointerGenerationReopenError::RejectedCandidateReopen)?;
        let candidate = rustix::fs::openat(&generations, name.as_c_str(), flags, Mode::empty())
            .map_err(|_| ActiveStatePointerGenerationReopenError::RejectedCandidateReopen)?;
        require_owner_directory(&candidate)?;
        Ok(PointerReopenedGeneration {
            _handle: PhantomData,
            _candidate: candidate,
        })
    }
}

fn require_owner_directory(
    descriptor: &OwnedFd,
) -> Result<(), ActiveStatePointerGenerationReopenError> {
    let metadata = rustix::fs::fstat(descriptor)
        .map_err(|_| ActiveStatePointerGenerationReopenError::RejectedCandidateReopen)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_mode & 0o7777 != 0o700
        || metadata.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(ActiveStatePointerGenerationReopenError::RejectedCandidateReopen);
    }
    Ok(())
}

#[cfg(test)]
#[path = "red_active_state_pointer_generation_reopen.rs"]
mod red_active_state_pointer_generation_reopen;
