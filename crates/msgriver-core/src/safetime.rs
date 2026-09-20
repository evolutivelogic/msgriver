//! Authenticated safe-time high-water arithmetic (PR-149, A-11.5).
//!
//! The caller supplies only authenticated markers and already-measured deltas.
//! Clock collection, acceptance, persistence, and the hold lifecycle are
//! deliberately outside this pure domain reduction.

use crate::{CoreError, RejectClass};

const CLOCK_STEP_THRESHOLD_MILLIS: i64 = 30_000;

/// Effective comparison high-water: the maximum of the authenticated fixed-root
/// and selected-state markers that exist, never their minimum (PR-149/A-11.5).
pub fn effective_high_water(
    fixed_root_millis: i64,
    selected_millis: Option<i64>,
) -> Result<i64, CoreError> {
    Ok(selected_millis.map_or(fixed_root_millis, |selected| {
        fixed_root_millis.max(selected)
    }))
}

/// Carry all already-authenticated transition markers forward by their maximum.
/// Authentication, source collection, and persistence remain outside the pure
/// core; this function only makes the monotone reduction explicit.
pub fn carry_forward_high_water(markers: &[i64]) -> Result<i64, CoreError> {
    markers
        .iter()
        .copied()
        .max()
        .ok_or_else(|| CoreError::reject(RejectClass::SafeTimeAuthorityEmpty))
}

/// Advance a high-water monotonically: the result is `max(current, candidate)`
/// and never decreases (PR-149/A-11.5).
pub fn advance_high_water(current: i64, candidate: i64) -> Result<i64, CoreError> {
    Ok(current.max(candidate))
}

/// Whether an expiry/command boundary at or below the effective durable
/// high-water is proven expired and therefore stays logically absent forever,
/// even while physical bytes remain (PR-149/A-11.5).
pub fn proven_expired(boundary_millis: i64, high_water_millis: i64) -> Result<bool, CoreError> {
    Ok(boundary_millis <= high_water_millis)
}

/// Whether a `(wall_delta - monotonic_delta)` absolute deviation beyond the
/// configured threshold enters the clock hold (A-11.5; default 30 seconds).
pub fn clock_step_holds(
    wall_delta_millis: i64,
    monotonic_delta_millis: i64,
) -> Result<bool, CoreError> {
    let Some(delta) = wall_delta_millis.checked_sub(monotonic_delta_millis) else {
        return Ok(true);
    };
    Ok(delta
        .checked_abs()
        .is_none_or(|absolute| absolute > CLOCK_STEP_THRESHOLD_MILLIS))
}
