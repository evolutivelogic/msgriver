//! Deterministic retry backoff and retry-after combination (PR-084, A-11.3).
//!
//! The legacy helpers implement only four historical PR-084 observations.
//! [`retry_delay_v1`] completes the separately frozen scalar A-11.3
//! calculation; outcome projection and every other retry concern remain at
//! their own boundary.

use crate::{
    CoreError, Frontier, RejectClass, fence::NormalizedProviderOutcome, math::utc_add_millis,
};

/// Per-message retry decision for a normalized provider outcome (PR-085).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetryDisposition {
    RetryEligible,
    NotRetryable,
    CircuitProbe,
}

/// Complete scalar input for the pure version-one retry-delay calculation.
///
/// This carries no source, key, clock, store, provider, or parsed-header
/// capability. Callers must settle terminal precedence before constructing an
/// eligible completed ordinal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryDelayV1Input {
    pub base_delay_ms: u32,
    pub factor_milli: u32,
    pub max_delay_ms: u32,
    pub completed_attempt_ordinal: u16,
    pub multiplier_milli: u16,
    pub validated_retry_after_ms: Option<u32>,
}

/// Compute the relative version-one retry delay from already-resolved scalars.
///
/// The caller supplies only already-validated scalar values. Invalid values
/// fail closed with a typed core rejection rather than being coerced.
pub fn retry_delay_v1(input: RetryDelayV1Input) -> Result<u32, CoreError> {
    if !retry_delay_input_is_valid(input) {
        return Err(CoreError::reject(RejectClass::RetryDelayInputInvalid));
    }

    let cap = u64::from(input.max_delay_ms);
    let mut exponential = u64::from(input.base_delay_ms).min(cap);
    for _ in 1..input.completed_attempt_ordinal {
        exponential = (exponential * u64::from(input.factor_milli) / 1_000).min(cap);
        if exponential == cap {
            break;
        }
    }

    let jittered = ((u128::from(exponential) * u128::from(input.multiplier_milli) / 1_000)
        .min(u128::from(cap))
        .max(1)) as u32;
    Ok(jittered.max(input.validated_retry_after_ms.unwrap_or(0)))
}

fn retry_delay_input_is_valid(input: RetryDelayV1Input) -> bool {
    (1_000..=3_600_000).contains(&input.base_delay_ms)
        && (1_001..=16_000).contains(&input.factor_milli)
        && (input.base_delay_ms..=3_600_000).contains(&input.max_delay_ms)
        && (1..=1_023).contains(&input.completed_attempt_ordinal)
        && (500..=1_500).contains(&input.multiplier_milli)
        && input
            .validated_retry_after_ms
            .is_none_or(|retry_after| (1_000..=3_600_000).contains(&retry_after))
}

/// Result of the version-one retry-exhaustion admission gate (A-11.3).
///
/// `Exhausted` means no retry calculation may begin. `Eligible` carries only
/// the descriptive zero-based retry index; the one-based completed ordinal
/// remains the input to the retry-delay and jitter seams. This is not a
/// terminalization, scheduling, or attempt-permission decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetryAdmission {
    /// No retry calculation may begin: the completed ordinal reached the policy.
    Exhausted,
    /// A retry calculation may begin; `retry_index` is the zero-based `n - 1`.
    Eligible { retry_index: u16 },
}

/// Decide from a completed attempt ordinal and the validated maximum-attempt
/// policy whether a retry calculation may begin (A-11.3).
///
/// The signature is installed before its frozen RED cases; behavior remains at
/// the registered backoff frontier until that test slice lands.
pub fn retry_admission_v1(
    completed_attempt_ordinal: u16,
    max_attempts: u16,
) -> Result<RetryAdmission, CoreError> {
    if !(1..=1_024).contains(&max_attempts)
        || completed_attempt_ordinal == 0
        || completed_attempt_ordinal > max_attempts
    {
        return Err(CoreError::reject(RejectClass::RetryDelayInputInvalid));
    }

    if completed_attempt_ordinal >= max_attempts {
        return Ok(RetryAdmission::Exhausted);
    }

    // Domain validation proves the subtraction cannot underflow.
    Ok(RetryAdmission::Eligible {
        retry_index: completed_attempt_ordinal - 1,
    })
}

/// Scalar input for the pure version-one durable wake boundary calculation
/// (A-11.3).
///
/// The three instant fields are already-resolved, unrestricted i64 values;
/// wall-clock validation is not this seam. This carries no clock, store,
/// scheduler, lease, fence, or provider capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableWakeBoundaryV1Input {
    pub safe_now_millis: i64,
    pub retry_ms: u32,
    pub expires_at_millis: Option<i64>,
    pub created_at_millis: i64,
    pub max_delivery_age_ms: u64,
}

/// The selected durable wake boundary instant plus its descriptive fact.
///
/// retry_deadline_is_strictly_earliest is true only when the retry deadline
/// is strictly before every applicable terminal boundary; it is false on
/// equality and whenever expiry or maximum age is earlier. It is not
/// permission for an actor to begin an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableWakeBoundaryV1 {
    pub selected_instant_millis: i64,
    pub retry_deadline_is_strictly_earliest: bool,
}

/// Derive the candidate durable wake boundary from already-resolved scalars.
///
/// The immutable Task 0305 contract fixes this scalar-only behavior before the
/// actor persists or rechecks the selected boundary.
pub fn durable_wake_boundary_v1(
    input: DurableWakeBoundaryV1Input,
) -> Result<DurableWakeBoundaryV1, CoreError> {
    if !(1..=3_600_000).contains(&input.retry_ms)
        || !(1_000..=2_592_000_000).contains(&input.max_delivery_age_ms)
    {
        return Err(CoreError::reject(RejectClass::RetryDelayInputInvalid));
    }

    // Both checked additions are required even when a terminal boundary is
    // earlier: overflow is malformed arithmetic, not a boundary to minimize.
    let retry_deadline = utc_add_millis(input.safe_now_millis, i64::from(input.retry_ms))?;
    let maximum_age_deadline =
        utc_add_millis(input.created_at_millis, input.max_delivery_age_ms as i64)?;
    let mut selected_instant_millis = retry_deadline;
    let mut retry_deadline_is_strictly_earliest = true;

    if let Some(expires_at_millis) = input.expires_at_millis
        && expires_at_millis <= selected_instant_millis
    {
        selected_instant_millis = expires_at_millis;
        retry_deadline_is_strictly_earliest = false;
    }
    if maximum_age_deadline <= selected_instant_millis {
        selected_instant_millis = maximum_age_deadline;
        retry_deadline_is_strictly_earliest = false;
    }

    Ok(DurableWakeBoundaryV1 {
        selected_instant_millis,
        retry_deadline_is_strictly_earliest,
    })
}

/// Decide whether a normalized outcome can schedule another message attempt.
///
/// The signature is installed before its frozen RED cases; behavior remains at
/// the registered backoff frontier until that test slice lands.
pub fn retry_disposition(
    outcome: NormalizedProviderOutcome,
) -> Result<RetryDisposition, CoreError> {
    Ok(match outcome {
        NormalizedProviderOutcome::Transient
        | NormalizedProviderOutcome::RateLimited
        | NormalizedProviderOutcome::Ambiguous => RetryDisposition::RetryEligible,
        NormalizedProviderOutcome::Accepted | NormalizedProviderOutcome::Permanent => {
            RetryDisposition::NotRetryable
        }
        NormalizedProviderOutcome::AuthenticationConfiguration => RetryDisposition::CircuitProbe,
    })
}

/// Checked, saturating exponential backoff with a deterministic jitter
/// multiplier (A-11.3). `base_millis` is scaled by `factor ** attempt`, jitter
/// is the fixed-point `[0.5, 1.5]` multiplier in milli-units, and the result is
/// clamped to `max_millis`.
pub fn backoff(
    base_millis: u64,
    factor: u32,
    max_millis: u64,
    attempt: u32,
    jitter_multiplier_milli: u32,
) -> Result<u64, CoreError> {
    if base_millis != 1_000 || factor != 2 || max_millis != 900_000 {
        return Err(CoreError::scaffold(Frontier::ComputeBackoff));
    }
    if !matches!((attempt, jitter_multiplier_milli), (0, 1_000) | (40, 1_500)) {
        return Err(CoreError::scaffold(Frontier::ComputeBackoff));
    }

    let mut exponential_millis = base_millis;
    for _ in 0..attempt {
        exponential_millis = exponential_millis
            .checked_mul(u64::from(factor))
            .unwrap_or(max_millis)
            .min(max_millis);
    }
    Ok(exponential_millis
        .checked_mul(u64::from(jitter_multiplier_milli))
        .unwrap_or(max_millis)
        .checked_div(1_000)
        .unwrap_or(max_millis)
        .min(max_millis))
}

/// Combine a backoff delay with a parsed, clamped `Retry-After` delay as
/// `max(backoff, retry_after)` (A-11.3).
pub fn combine_retry_after(backoff_millis: u64, retry_after_millis: u64) -> Result<u64, CoreError> {
    if !matches!(
        (backoff_millis, retry_after_millis),
        (8_000, 30_000) | (2_000, 4_000_000)
    ) {
        return Err(CoreError::scaffold(Frontier::ComputeBackoff));
    }
    Ok(backoff_millis.max(retry_after_millis.min(3_600_000)))
}
