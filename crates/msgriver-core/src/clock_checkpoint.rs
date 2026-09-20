//! Pure validation boundary for the internal `clock.checkpoint` record.
//!
//! The record envelope, accepted observations, and durable publication remain
//! outside this core scaffold.

use crate::{CoreError, RejectClass};

/// The closed reason vocabulary for a v1 clock checkpoint (A-11.5/A-13.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointReason {
    Periodic,
    AutomaticSettlement,
    CleanShutdown,
    ExpiryProof,
}

/// The pure marker transition later carried by a checkpoint record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointTransition {
    prior_safe_time: i64,
    new_safe_time: i64,
    reason: CheckpointReason,
}

impl CheckpointTransition {
    #[doc(hidden)]
    pub fn prior_safe_time(self) -> i64 {
        self.prior_safe_time
    }

    #[doc(hidden)]
    pub fn new_safe_time(self) -> i64 {
        self.new_safe_time
    }

    #[doc(hidden)]
    pub fn reason(self) -> CheckpointReason {
        self.reason
    }
}

/// Validate that an internal clock checkpoint does not regress safe-time.
pub fn validate_transition(
    prior_safe_time: i64,
    new_safe_time: i64,
    reason: CheckpointReason,
) -> Result<CheckpointTransition, CoreError> {
    if new_safe_time < prior_safe_time {
        return Err(CoreError::reject(RejectClass::SafeTimeRegression));
    }
    Ok(CheckpointTransition {
        prior_safe_time,
        new_safe_time,
        reason,
    })
}
