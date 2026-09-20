//! Private A-14.3 step-6 caller capability RED frontier.

#[path = "active_state_pointer_coordinator.rs"]
mod active_state_pointer_coordinator;
#[path = "active_state_pointer_publisher.rs"]
mod active_state_pointer_publisher;

use super::{JournalIntegrityKey, active_state_pointer::ActiveStatePointer};
use active_state_pointer_publisher::publish_active_state_pointer;
pub(super) use active_state_pointer_publisher::{
    ActiveStatePointerPublicationMode, ActiveStatePointerPublisherError,
};
#[cfg(test)]
use active_state_pointer_publisher::{
    PublisherTestFault, publish_active_state_pointer_with_test_fault,
};
use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{Mode, OFlags};
use std::marker::PhantomData;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ActiveStatePointerCallerError {
    MissingActiveStatePointerCallerCapability,
    MissingActiveStatePointerCallerPublication,
    Publication(ActiveStatePointerPublisherError),
}

/// Private pre-step-7 observation that exclusively borrows its capability.
pub(super) struct PointerRenamed<'capability> {
    _operational_directory: BorrowedFd<'capability>,
    _capability: PhantomData<&'capability mut ActiveStatePointerCallerCapability>,
}

/// Retained private lock/reference/operational-descriptor capability.
pub(super) struct ActiveStatePointerCallerCapability {
    _lock: crate::StateOwnerLock,
    _root_reference: OwnedFd,
    _operational_directory: OwnedFd,
}

impl ActiveStatePointerCallerCapability {
    pub(super) fn acquire(root: &Path) -> Result<Self, ActiveStatePointerCallerError> {
        // FRONTIER: active_state_pointer_caller_capability
        let (lock, root_reference) =
            crate::StateOwnerLock::acquire_with_private_root_reference(root).map_err(|_| {
                ActiveStatePointerCallerError::MissingActiveStatePointerCallerCapability
            })?;
        let operational_directory = rustix::fs::openat(
            &root_reference,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ActiveStatePointerCallerError::MissingActiveStatePointerCallerCapability)?;
        Ok(Self {
            _lock: lock,
            _root_reference: root_reference,
            _operational_directory: operational_directory,
        })
    }

    pub(super) fn publish<'capability>(
        &'capability mut self,
        key: &JournalIntegrityKey,
        pointer: &ActiveStatePointer,
        mode: ActiveStatePointerPublicationMode,
    ) -> Result<PointerRenamed<'capability>, ActiveStatePointerCallerError> {
        publish_active_state_pointer(self, key, pointer, mode)
            .map_err(ActiveStatePointerCallerError::Publication)
    }

    /// Keeps the existing test-only fault seam capability-bound.
    #[cfg(test)]
    pub(super) fn publish_with_test_fault<'capability>(
        &'capability mut self,
        key: &JournalIntegrityKey,
        pointer: &ActiveStatePointer,
        mode: ActiveStatePointerPublicationMode,
        fault: PublisherTestFault,
    ) -> Result<PointerRenamed<'capability>, ActiveStatePointerCallerError> {
        publish_active_state_pointer_with_test_fault(self, key, pointer, mode, fault)
            .map_err(ActiveStatePointerCallerError::Publication)
    }

    fn operational_directory(&self) -> BorrowedFd<'_> {
        self._operational_directory.as_fd()
    }

    fn renamed<'capability>(&'capability mut self) -> PointerRenamed<'capability> {
        PointerRenamed {
            _operational_directory: self.operational_directory(),
            _capability: PhantomData,
        }
    }
}

#[cfg(test)]
#[allow(clippy::drop_non_drop)]
#[path = "red_active_state_pointer_caller.rs"]
mod red_active_state_pointer_caller;
#[cfg(test)]
#[path = "red_active_state_pointer_coordinator.rs"]
mod red_active_state_pointer_coordinator;
