//! Task 0086 private state-key manifest-row decoder frontier.
//!
//! This crate-private child models one already-fetched row only. It has no
//! SQLite, clock, key material, aggregate manifest, or selected-state ability.

#![allow(dead_code)]

use msgriver_core::canon::{MacKeyId, MacKeyRef, MacPurpose};

pub(super) struct RawStateMacKeyManifestRow {
    pub(super) purpose: i64,
    pub(super) origin: Vec<u8>,
    pub(super) serial_hi: i64,
    pub(super) serial_lo: i64,
    pub(super) status: i64,
    pub(super) created_at: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StateMacKeyManifestStatus {
    Active,
    Retained,
}

pub(super) struct StateMacKeyManifestRow {
    pub(super) reference: MacKeyRef,
    pub(super) status: StateMacKeyManifestStatus,
    pub(super) created_at: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StateMacKeyManifestRowError {
    MissingStateMacKeyManifestRowDecoder,
    InvalidPurpose,
    InvalidStatus,
    InvalidOriginLength,
    LimbOutOfRange,
    ZeroSerial,
}

pub(super) fn decode_state_mac_key_manifest_row(
    raw: RawStateMacKeyManifestRow,
) -> Result<StateMacKeyManifestRow, StateMacKeyManifestRowError> {
    // FRONTIER: state_mac_key_manifest_row_decoder
    let purpose = purpose_from_i64(raw.purpose)?;
    let status = status_from_i64(raw.status)?;
    let origin: [u8; 32] = raw
        .origin
        .try_into()
        .map_err(|_| StateMacKeyManifestRowError::InvalidOriginLength)?;
    let serial_hi = limb_from_i64(raw.serial_hi)?;
    let serial_lo = limb_from_i64(raw.serial_lo)?;
    if serial_hi == 0 && serial_lo == 0 {
        return Err(StateMacKeyManifestRowError::ZeroSerial);
    }
    let mut key_id = [0; 40];
    key_id[..32].copy_from_slice(&origin);
    key_id[32..36].copy_from_slice(&serial_hi.to_be_bytes());
    key_id[36..].copy_from_slice(&serial_lo.to_be_bytes());
    Ok(StateMacKeyManifestRow {
        reference: MacKeyRef::new(purpose, MacKeyId::from_bytes(key_id)),
        status,
        created_at: raw.created_at,
    })
}

fn purpose_from_i64(value: i64) -> Result<MacPurpose, StateMacKeyManifestRowError> {
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
        _ => Err(StateMacKeyManifestRowError::InvalidPurpose),
    }
}

fn status_from_i64(value: i64) -> Result<StateMacKeyManifestStatus, StateMacKeyManifestRowError> {
    match value {
        1 => Ok(StateMacKeyManifestStatus::Active),
        2 => Ok(StateMacKeyManifestStatus::Retained),
        _ => Err(StateMacKeyManifestRowError::InvalidStatus),
    }
}

fn limb_from_i64(value: i64) -> Result<u32, StateMacKeyManifestRowError> {
    u32::try_from(value).map_err(|_| StateMacKeyManifestRowError::LimbOutOfRange)
}

#[cfg(test)]
#[path = "red_state_mac_key_manifest_row.rs"]
mod red_state_mac_key_manifest_row;
