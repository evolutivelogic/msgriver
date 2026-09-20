//! Fail-closed composition seam for Task 0009.
//!
//! This module deliberately has no startup behavior yet. Its only job at the
//! RED checkpoint is to make the ordered adapter contract compile without
//! granting filesystem, listener, credential, queue, or network authority.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::{
    StateOwnerLock, apply_linux_startup_policy, ensure_linux_non_root, validate_private_root,
};

/// Ordered, side-effecting prerequisites owned by the future composition root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum BootstrapStep {
    ProcessPolicy,
    NonRoot,
    TrustedRoot,
    OwnerLock,
    SelectedState,
    Store,
    StructuralConfiguration,
    ProviderCatalog,
}

/// The sole reviewed prerequisite order for the composition-foundation seam.
#[doc(hidden)]
pub const BOOTSTRAP_ORDER: [BootstrapStep; 8] = [
    BootstrapStep::ProcessPolicy,
    BootstrapStep::NonRoot,
    BootstrapStep::TrustedRoot,
    BootstrapStep::OwnerLock,
    BootstrapStep::SelectedState,
    BootstrapStep::Store,
    BootstrapStep::StructuralConfiguration,
    BootstrapStep::ProviderCatalog,
];

/// Opaque adapter failure; detailed evidence remains protected at the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum BootstrapAdapterError {
    Failed,
}

/// Injectable prerequisite boundary. It intentionally exposes no listener,
/// credential, provider, queue, or readiness operation.
#[doc(hidden)]
pub trait BootstrapAdapter {
    fn run(&mut self, step: BootstrapStep) -> Result<(), BootstrapAdapterError>;
}

/// The two process prerequisites owned by Tasks 0005 and 0006.
///
/// It deliberately has no root, state, credential, listener, or network
/// operation. A test can inject this narrow boundary without changing its own
/// process-wide policy or effective UID.
#[doc(hidden)]
pub trait BootstrapProcessPrimitive {
    fn apply_policy(&mut self) -> Result<(), BootstrapAdapterError>;
    fn require_non_root(&mut self) -> Result<(), BootstrapAdapterError>;
}

/// Production bridge to the already verified Task 0005/0006 primitives.
#[doc(hidden)]
pub struct LinuxBootstrapProcessPrimitive;

impl BootstrapProcessPrimitive for LinuxBootstrapProcessPrimitive {
    fn apply_policy(&mut self) -> Result<(), BootstrapAdapterError> {
        apply_linux_startup_policy().map_err(|_| BootstrapAdapterError::Failed)
    }

    fn require_non_root(&mut self) -> Result<(), BootstrapAdapterError> {
        ensure_linux_non_root().map_err(|_| BootstrapAdapterError::Failed)
    }
}

/// Compose the process policy and effective-UID guard with later injected
/// prerequisites. This component owns only the first two bootstrap steps.
#[doc(hidden)]
pub struct LinuxProcessBootstrapAdapter<P, A> {
    primitive: P,
    delegate: A,
    policy_applied: bool,
    non_root_confirmed: bool,
}

impl<P, A> LinuxProcessBootstrapAdapter<P, A> {
    #[doc(hidden)]
    pub fn new(primitive: P, delegate: A) -> Self {
        Self {
            primitive,
            delegate,
            policy_applied: false,
            non_root_confirmed: false,
        }
    }

    #[doc(hidden)]
    pub fn primitive(&self) -> &P {
        &self.primitive
    }

    #[doc(hidden)]
    pub fn delegate(&self) -> &A {
        &self.delegate
    }
}

impl<A> LinuxProcessBootstrapAdapter<LinuxBootstrapProcessPrimitive, A> {
    /// Construct the production process-precondition adapter.
    #[doc(hidden)]
    pub fn production(delegate: A) -> Self {
        Self::new(LinuxBootstrapProcessPrimitive, delegate)
    }
}

impl<P: BootstrapProcessPrimitive, A: BootstrapAdapter> BootstrapAdapter
    for LinuxProcessBootstrapAdapter<P, A>
{
    fn run(&mut self, step: BootstrapStep) -> Result<(), BootstrapAdapterError> {
        match step {
            BootstrapStep::ProcessPolicy => {
                if self.policy_applied {
                    return Err(BootstrapAdapterError::Failed);
                }
                self.primitive.apply_policy()?;
                self.policy_applied = true;
                Ok(())
            }
            BootstrapStep::NonRoot => {
                if !self.policy_applied || self.non_root_confirmed {
                    return Err(BootstrapAdapterError::Failed);
                }
                self.primitive.require_non_root()?;
                self.non_root_confirmed = true;
                Ok(())
            }
            _ => {
                if !self.non_root_confirmed {
                    return Err(BootstrapAdapterError::Failed);
                }
                self.delegate.run(step)
            }
        }
    }
}

/// Concrete, non-ready adapter for the first fixed-root capability.
#[doc(hidden)]
pub struct RootLockAdapter {
    root: PathBuf,
    trusted_root: bool,
    owner_lock: Option<StateOwnerLock>,
}

impl RootLockAdapter {
    #[doc(hidden)]
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            trusted_root: false,
            owner_lock: None,
        }
    }

    #[doc(hidden)]
    pub fn retains_owner_lock(&self) -> bool {
        self.owner_lock.is_some()
    }

    /// Run only one of the two steps owned by this component.
    ///
    /// The component is deliberately not a complete `BootstrapAdapter`: a
    /// caller must compose it with explicit implementations for the other six
    /// prerequisites instead of silently accepting them.
    #[doc(hidden)]
    pub fn run_root_step(&mut self, step: BootstrapStep) -> Result<(), BootstrapAdapterError> {
        match step {
            BootstrapStep::TrustedRoot => {
                validate_private_root(&self.root).map_err(|_| BootstrapAdapterError::Failed)?;
                self.trusted_root = true;
                Ok(())
            }
            BootstrapStep::OwnerLock => {
                if !self.trusted_root {
                    return Err(BootstrapAdapterError::Failed);
                }
                if self.owner_lock.is_none() {
                    self.owner_lock = Some(
                        StateOwnerLock::acquire(&self.root)
                            .map_err(|_| BootstrapAdapterError::Failed)?,
                    );
                }
                Ok(())
            }
            _ => Err(BootstrapAdapterError::Failed),
        }
    }
}

/// Compose the concrete root/lock component with injected implementations of
/// every other prerequisite. It grants no readiness or service capability.
#[doc(hidden)]
pub struct RootLockBootstrapAdapter<A> {
    root_lock: RootLockAdapter,
    delegate: A,
    process_policy_applied: bool,
    non_root_confirmed: bool,
    trusted_root: bool,
    owner_lock_acquired: bool,
}

impl<A> RootLockBootstrapAdapter<A> {
    #[doc(hidden)]
    pub fn new(root_lock: RootLockAdapter, delegate: A) -> Self {
        Self {
            root_lock,
            delegate,
            process_policy_applied: false,
            non_root_confirmed: false,
            trusted_root: false,
            owner_lock_acquired: false,
        }
    }

    #[doc(hidden)]
    pub fn root_lock(&self) -> &RootLockAdapter {
        &self.root_lock
    }

    #[doc(hidden)]
    pub fn delegate(&self) -> &A {
        &self.delegate
    }
}

impl<A: BootstrapAdapter> BootstrapAdapter for RootLockBootstrapAdapter<A> {
    fn run(&mut self, step: BootstrapStep) -> Result<(), BootstrapAdapterError> {
        match step {
            BootstrapStep::ProcessPolicy => {
                if self.process_policy_applied {
                    return Err(BootstrapAdapterError::Failed);
                }
                self.delegate.run(step)?;
                self.process_policy_applied = true;
                Ok(())
            }
            BootstrapStep::NonRoot => {
                if !self.process_policy_applied || self.non_root_confirmed {
                    return Err(BootstrapAdapterError::Failed);
                }
                self.delegate.run(step)?;
                self.non_root_confirmed = true;
                Ok(())
            }
            BootstrapStep::TrustedRoot => {
                if !self.non_root_confirmed || self.trusted_root {
                    return Err(BootstrapAdapterError::Failed);
                }
                self.root_lock.run_root_step(step)?;
                self.trusted_root = true;
                Ok(())
            }
            BootstrapStep::OwnerLock => {
                if !self.trusted_root || self.owner_lock_acquired {
                    return Err(BootstrapAdapterError::Failed);
                }
                self.root_lock.run_root_step(step)?;
                self.owner_lock_acquired = true;
                Ok(())
            }
            _ => {
                if !self.owner_lock_acquired {
                    return Err(BootstrapAdapterError::Failed);
                }
                self.delegate.run(step)
            }
        }
    }
}

/// Closed bootstrap outcome vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    clippy::manual_non_exhaustive,
    reason = "the frozen bootstrap contract requires its hidden MissingBootstrap diagnostic"
)]
pub enum BootstrapError {
    #[doc(hidden)]
    MissingBootstrap,
    Rejected,
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingBootstrap => "service bootstrap is not available",
            Self::Rejected => "service bootstrap was rejected",
        })
    }
}

impl std::error::Error for BootstrapError {}

/// Proof only that the injected prerequisite sequence did not reject.
/// It deliberately carries no readiness, listener, or delivery authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct BootstrapOrderVerified(());

/// Owns the adapter resources after a successful ordered bootstrap. It is not
/// a daemon and has no readiness or delivery API.
#[doc(hidden)]
pub struct BootstrapRuntime<A> {
    adapter: A,
}

impl<A> BootstrapRuntime<A> {
    /// Borrow the retained adapter for future, separately authorized stages.
    #[doc(hidden)]
    pub fn adapter(&self) -> &A {
        &self.adapter
    }

    /// Consume the sealed bootstrap result for a separately authorized stage.
    /// This transfers ownership without exposing mutable interior state.
    #[doc(hidden)]
    pub fn into_adapter(self) -> A {
        self.adapter
    }
}

/// Run the ordered, injected composition boundary.
///
/// This establishes ordering only. Concrete adapters and the retained runtime
/// capability are still separate work; this function never receives or creates
/// a filesystem, listener, credential, provider, queue, or network handle.
#[doc(hidden)]
pub fn bootstrap_with(
    adapter: &mut dyn BootstrapAdapter,
) -> Result<BootstrapOrderVerified, BootstrapError> {
    for step in BOOTSTRAP_ORDER {
        adapter.run(step).map_err(|_| BootstrapError::Rejected)?;
    }
    Ok(BootstrapOrderVerified(()))
}

/// Owned successor for adapters that retain a root lock or descriptor.
///
/// The returned value communicates only that ordering completed; callers still
/// cannot treat it as a ready service.
#[doc(hidden)]
pub fn bootstrap_owned<A: BootstrapAdapter>(
    mut adapter: A,
) -> Result<BootstrapRuntime<A>, BootstrapError> {
    bootstrap_with(&mut adapter)?;
    Ok(BootstrapRuntime { adapter })
}
