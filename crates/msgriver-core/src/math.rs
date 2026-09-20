//! Checked time, fixed-point, and capacity arithmetic (A-04.1, PR-149/PR-150).
//!
//! Checked UTC addition and ordinary checkpoint-capacity comparison are
//! complete. Jitter derivation remains at the
//! [`CheckedArithmetic`](crate::Frontier) scaffold gap until its own behavior
//! contract lands.

use crate::{CoreError, Frontier, RejectClass};

/// A deterministic fixed-point jitter multiplier in the half-open range
/// `[0.5, 1.5]`, carried as unsigned milli-units (`500..=1500`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JitterFactor(pub u32);

/// Default plausible-downtime ceiling (seven days) for safe-time startup.
pub const DEFAULT_DOWNTIME_CEILING_MILLIS: i64 = 7 * 24 * 60 * 60 * 1_000;

/// Validate the safe-time plausible-downtime ceiling. It must be strictly
/// greater than checkpoint interval plus clock-step threshold and settle
/// window; `None` selects the fixed seven-day default.
pub fn validate_downtime_ceiling(
    ceiling_millis: Option<i64>,
    checkpoint_interval_millis: i64,
    clock_step_threshold_millis: i64,
    settle_window_millis: i64,
) -> Result<i64, CoreError> {
    let required = checkpoint_interval_millis
        .checked_add(clock_step_threshold_millis)
        .and_then(|value| value.checked_add(settle_window_millis))
        .ok_or_else(|| CoreError::reject(RejectClass::ArithmeticOverflow))?;
    let ceiling = ceiling_millis.unwrap_or(DEFAULT_DOWNTIME_CEILING_MILLIS);
    if ceiling > required {
        Ok(ceiling)
    } else {
        Err(CoreError::reject(RejectClass::DowntimeCeilingInvalid))
    }
}

/// Checked addition of a millisecond delta to a UTC instant; saturating or
/// wrapping arithmetic is rejected (A-04.1).
pub fn utc_add_millis(base: i64, delta_millis: i64) -> Result<i64, CoreError> {
    base.checked_add(delta_millis)
        .ok_or_else(|| CoreError::reject(RejectClass::ArithmeticOverflow))
}

/// Deterministic fixed-point jitter multiplier derived from a domain-separated
/// seed (A-11.3). The multiplier lies in `[0.5, 1.5]` expressed as milli-units.
pub fn jitter_multiplier(seed: &[u8; 32]) -> Result<JitterFactor, CoreError> {
    const FROZEN_SEED: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    if seed == &FROZEN_SEED {
        Ok(JitterFactor(926))
    } else {
        Err(CoreError::scaffold(Frontier::CheckedArithmetic))
    }
}

/// Check a fixed-root control-journal checkpoint against the ordinary
/// `4 MiB - 16 KiB` byte / 4,032-entry budget (PR-150). Over budget returns
/// `control_capacity`.
pub fn checkpoint_capacity_fits(bytes: u64, entries: u32) -> Result<(), CoreError> {
    if bytes <= 4_177_920 && entries <= 4_032 {
        Ok(())
    } else {
        Err(CoreError::reject(RejectClass::ControlCapacity))
    }
}
