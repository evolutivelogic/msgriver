//! Task 0090 private selected-state meta-row decoder frontier.

#![allow(dead_code)]

use crate::state_mac_key_high_water::StateMacKeyHighWater;
use msgriver_core::canon::MacPurpose;

pub(super) struct RawStateMacKeyHighWater {
    pub(super) purpose: i64,
    pub(super) serial_hi: i64,
    pub(super) serial_lo: i64,
}

pub(super) struct StateMacKeyMetaFacts {
    pub(super) selected_origin: [u8; 32],
    pub(super) high_waters: Vec<StateMacKeyHighWater>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StateMacKeyMetaRowError {
    MissingStateMacKeyMetaRowDecoder,
    InvalidSelectedOriginLength,
    InvalidPurpose,
    LimbOutOfRange,
}

pub(super) fn decode_state_mac_key_meta_rows(
    selected_origin: Vec<u8>,
    high_waters: Vec<RawStateMacKeyHighWater>,
) -> Result<StateMacKeyMetaFacts, StateMacKeyMetaRowError> {
    let selected_origin = selected_origin
        .try_into()
        .map_err(|_| StateMacKeyMetaRowError::InvalidSelectedOriginLength)?;
    let high_waters = high_waters
        .into_iter()
        .map(|row| {
            Ok(StateMacKeyHighWater {
                purpose: purpose_from_i64(row.purpose)?,
                serial_hi: u32::try_from(row.serial_hi)
                    .map_err(|_| StateMacKeyMetaRowError::LimbOutOfRange)?,
                serial_lo: u32::try_from(row.serial_lo)
                    .map_err(|_| StateMacKeyMetaRowError::LimbOutOfRange)?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(StateMacKeyMetaFacts {
        selected_origin,
        high_waters,
    })
}

fn purpose_from_i64(value: i64) -> Result<MacPurpose, StateMacKeyMetaRowError> {
    match value {
        1 => Ok(MacPurpose::ApiKeyVerifyV1),
        2 => Ok(MacPurpose::IdempotencyLookupV1),
        3 => Ok(MacPurpose::IdempotencyFingerprintV1),
        4 => Ok(MacPurpose::ReplayLookupV1),
        5 => Ok(MacPurpose::ReplayFingerprintV1),
        6 => Ok(MacPurpose::CommandLookupV1),
        7 => Ok(MacPurpose::CommandSemanticFingerprintV1),
        8 => Ok(MacPurpose::CommandPhaseFingerprintV1),
        9 => Ok(MacPurpose::RetryJitterV1),
        10 => Ok(MacPurpose::ArtifactInternalAuthV1),
        11 => Ok(MacPurpose::PortableReservationV1),
        _ => Err(StateMacKeyMetaRowError::InvalidPurpose),
    }
}

#[cfg(test)]
#[path = "red_state_mac_key_meta_row.rs"]
mod red_state_mac_key_meta_row;
