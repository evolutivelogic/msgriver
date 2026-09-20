//! Task 0088 private state-key high-water semantic-validation frontier.
//!
//! This crate-private child consumes already-decoded facts and performs no
//! external I/O or selected-state transition.

#![allow(dead_code)]

use crate::state_mac_key_manifest_row::StateMacKeyManifestRow;
use msgriver_core::canon::MacPurpose;

pub(super) struct StateMacKeyHighWater {
    pub(super) purpose: MacPurpose,
    pub(super) serial_hi: u32,
    pub(super) serial_lo: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StateMacKeyHighWaterError {
    MissingStateMacKeyHighWaterValidator,
    DuplicateHighWaterPurpose,
    MissingHighWaterPurpose,
    SelectedOriginSerialAboveHighWater,
}

pub(super) fn validate_state_mac_key_high_water(
    rows: &[StateMacKeyManifestRow],
    selected_origin: [u8; 32],
    high_waters: &[StateMacKeyHighWater],
) -> Result<(), StateMacKeyHighWaterError> {
    let mut by_purpose = [None; 11];
    for high_water in high_waters {
        let index = usize::from(high_water.purpose as u8 - 1);
        if by_purpose[index]
            .replace(u64::from(high_water.serial_hi) << 32 | u64::from(high_water.serial_lo))
            .is_some()
        {
            return Err(StateMacKeyHighWaterError::DuplicateHighWaterPurpose);
        }
    }
    let mut resolved = [0_u64; 11];
    for (index, value) in by_purpose.into_iter().enumerate() {
        resolved[index] = value.ok_or(StateMacKeyHighWaterError::MissingHighWaterPurpose)?;
    }

    for row in rows {
        let key_id = row.reference.key_id();
        let key_id = key_id.as_bytes();
        if key_id[..32] != selected_origin {
            continue;
        }
        let index = usize::from(row.reference.purpose() as u8 - 1);
        let serial = u64::from_be_bytes(key_id[32..].try_into().expect("fixed key-id width"));
        if serial > resolved[index] {
            return Err(StateMacKeyHighWaterError::SelectedOriginSerialAboveHighWater);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "red_state_mac_key_high_water.rs"]
mod red_state_mac_key_high_water;
