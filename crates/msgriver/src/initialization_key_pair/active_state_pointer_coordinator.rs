//! Private A-14.3 root-bound pre-terminal coordinator RED frontier.
//!
//! This module intentionally has no successful behavior until Task 0128's
//! frozen RED provides the smallest capability-preserving implementation.

use super::{ActiveStatePointerCallerCapability, PointerRenamed};
use crate::initialization_key_pair::active_state_pointer::ActiveStatePointer;
use rustix::fd::BorrowedFd;
use std::marker::PhantomData;

#[path = "active_state_pointer_generation_reopen.rs"]
mod active_state_pointer_generation_reopen;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ActiveStatePointerCoordinatorError {
    MissingActiveStatePointerCoordinator,
}

/// Private affine step-7 handoff rooted in the caller's retained descriptor.
pub(super) struct PreTerminalCoordinator<'capability> {
    operational_directory: BorrowedFd<'capability>,
    _capability: PhantomData<&'capability mut ActiveStatePointerCallerCapability>,
    final_generation: u64,
    certificate_digest: [u8; 32],
}

/// Private root-bound pointer identity with no lower-boundary authority.
pub(super) struct PointerNamedGeneration<'coordinator, 'capability> {
    _coordinator: PhantomData<&'coordinator PreTerminalCoordinator<'capability>>,
    _operational_directory: BorrowedFd<'capability>,
    final_generation: u64,
    certificate_digest: [u8; 32],
}

impl<'capability> PreTerminalCoordinator<'capability> {
    // FRONTIER: active_state_pointer_coordinator
    pub(super) fn enter(
        renamed: PointerRenamed<'capability>,
        pointer: &ActiveStatePointer,
    ) -> Result<Self, ActiveStatePointerCoordinatorError> {
        let PointerRenamed {
            _operational_directory,
            _capability,
        } = renamed;
        Ok(Self {
            operational_directory: _operational_directory,
            _capability,
            final_generation: pointer.final_generation,
            certificate_digest: pointer.database_certificate_digest,
        })
    }

    pub(super) fn pointer_named_generation<'coordinator>(
        &'coordinator self,
    ) -> Result<PointerNamedGeneration<'coordinator, 'capability>, ActiveStatePointerCoordinatorError>
    {
        Ok(PointerNamedGeneration {
            _coordinator: PhantomData,
            _operational_directory: self.operational_directory,
            final_generation: self.final_generation,
            certificate_digest: self.certificate_digest,
        })
    }
}

impl PointerNamedGeneration<'_, '_> {
    pub(super) fn final_generation(&self) -> u64 {
        self.final_generation
    }

    pub(super) fn certificate_digest(&self) -> [u8; 32] {
        self.certificate_digest
    }
}
