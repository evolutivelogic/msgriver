//! Fence and lease arbitration (PR-081, A-09.4).
//!
//! Matching ordinary outcomes and lease configuration are complete. An
//! unmatched acceptance remains at the [`FenceArbitrate`](crate::Frontier)
//! scaffold because this pure boundary has no retained acknowledgement proof.

use crate::{CoreError, Frontier, RejectClass};

/// A typed provider outcome presented for fenced commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceOutcome {
    Accepted,
    Transient,
    Permanent,
    Ambiguous,
}

/// Connector-normalized provider evidence; raw response parsing is outside the
/// pure core boundary (PR-083).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderResponseEvidence {
    Accepted,
    Transient,
    RateLimited,
    PermanentValidation,
    AuthenticationConfiguration,
    Ambiguous,
}

/// Closed provider outcome vocabulary used by classification and retry policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NormalizedProviderOutcome {
    Accepted,
    Transient,
    RateLimited,
    Permanent,
    AuthenticationConfiguration,
    Ambiguous,
}

/// Classify connector-normalized provider evidence (PR-083).
///
/// The signature is installed before its frozen RED cases; behavior remains at
/// the registered fence frontier until that test slice lands.
pub fn classify_provider_response(
    evidence: ProviderResponseEvidence,
) -> Result<NormalizedProviderOutcome, CoreError> {
    Ok(match evidence {
        ProviderResponseEvidence::Accepted => NormalizedProviderOutcome::Accepted,
        ProviderResponseEvidence::Transient => NormalizedProviderOutcome::Transient,
        ProviderResponseEvidence::RateLimited => NormalizedProviderOutcome::RateLimited,
        ProviderResponseEvidence::PermanentValidation => NormalizedProviderOutcome::Permanent,
        ProviderResponseEvidence::AuthenticationConfiguration => {
            NormalizedProviderOutcome::AuthenticationConfiguration
        }
        ProviderResponseEvidence::Ambiguous => NormalizedProviderOutcome::Ambiguous,
    })
}

/// The arbitration decision for a fenced outcome update (A-09.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceArbitration {
    /// `lease_generation` and `fence_token` matched: the outcome applies.
    Applied { outcome: FenceOutcome },
    /// Stale evidence: zero changed rows. A stale transient/permanent result is
    /// orphaned; stale ambiguity ORs sticky uncertainty/duplicate flags. The
    /// attempt count is never decremented (`attempt_delta == 0`).
    Stale {
        ambiguity_orred: bool,
        attempt_delta: u32,
    },
}

/// Arbitrate an outcome update against the current lease generation and fence
/// token (A-09.4). A match applies; a mismatch is stale and never decrements an
/// attempt count, clears sticky flags, deletes newer evidence, or reuses a fence.
pub fn arbitrate_outcome(
    current_lease_generation: u64,
    current_fence_token: u128,
    update_lease_generation: u64,
    update_fence_token: u128,
    outcome: FenceOutcome,
) -> Result<FenceArbitration, CoreError> {
    if (current_lease_generation, current_fence_token)
        == (update_lease_generation, update_fence_token)
    {
        return Ok(FenceArbitration::Applied { outcome });
    }

    match outcome {
        FenceOutcome::Transient | FenceOutcome::Permanent => Ok(FenceArbitration::Stale {
            ambiguity_orred: false,
            attempt_delta: 0,
        }),
        FenceOutcome::Ambiguous => Ok(FenceArbitration::Stale {
            ambiguity_orred: true,
            attempt_delta: 0,
        }),
        // A late acceptance needs retained, verifiable attempt evidence. This
        // pure function does not receive that proof, so it must not call it
        // stale or apply it under an unrelated current fence.
        FenceOutcome::Accepted => Err(CoreError::scaffold(Frontier::FenceArbitrate)),
    }
}

/// Validate a lease configuration (A-09.4): `lease_ttl > timeout + margin` with
/// at least a minimum 5-second margin; exact equality is invalid.
pub fn validate_lease_config(
    lease_ttl_millis: u64,
    timeout_millis: u64,
    margin_millis: u64,
) -> Result<(), CoreError> {
    let required = timeout_millis
        .checked_add(margin_millis)
        .ok_or_else(|| CoreError::reject(RejectClass::LeaseConfigInvalid))?;
    if margin_millis >= 5_000 && lease_ttl_millis > required {
        Ok(())
    } else {
        Err(CoreError::reject(RejectClass::LeaseConfigInvalid))
    }
}
