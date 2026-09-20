use super::{StateMacKeyHighWater, StateMacKeyHighWaterError, validate_state_mac_key_high_water};
use crate::state_mac_key_manifest_row::{StateMacKeyManifestRow, StateMacKeyManifestStatus};
use msgriver_core::canon::{MacKeyId, MacKeyRef, MacPurpose};

const SELECTED: [u8; 32] = [0x44; 32];
const FOREIGN: [u8; 32] = [0x99; 32];

fn purpose(byte: u8) -> MacPurpose {
    match byte {
        1 => MacPurpose::ApiKeyVerifyV1,
        2 => MacPurpose::IdempotencyLookupV1,
        3 => MacPurpose::IdempotencyFingerprintV1,
        4 => MacPurpose::ReplayLookupV1,
        5 => MacPurpose::ReplayFingerprintV1,
        6 => MacPurpose::CommandLookupV1,
        7 => MacPurpose::CommandSemanticFingerprintV1,
        8 => MacPurpose::CommandPhaseFingerprintV1,
        9 => MacPurpose::RetryJitterV1,
        10 => MacPurpose::ArtifactInternalAuthV1,
        11 => MacPurpose::PortableReservationV1,
        _ => panic!("test purpose must be closed"),
    }
}

fn row(purpose_byte: u8, origin: [u8; 32], serial: u64) -> StateMacKeyManifestRow {
    let mut key_id = [0; 40];
    key_id[..32].copy_from_slice(&origin);
    key_id[32..].copy_from_slice(&serial.to_be_bytes());
    StateMacKeyManifestRow {
        reference: MacKeyRef::new(purpose(purpose_byte), MacKeyId::from_bytes(key_id)),
        status: StateMacKeyManifestStatus::Retained,
        created_at: 0,
    }
}

fn high_waters(value: u64) -> Vec<StateMacKeyHighWater> {
    (1..=11)
        .map(|purpose_byte| StateMacKeyHighWater {
            purpose: purpose(purpose_byte),
            serial_hi: (value >> 32) as u32,
            serial_lo: value as u32,
        })
        .collect()
}

fn validate(rows: &[StateMacKeyManifestRow], high_waters: &[StateMacKeyHighWater]) {
    match validate_state_mac_key_high_water(rows, SELECTED, high_waters) {
        Ok(()) => {}
        Err(StateMacKeyHighWaterError::MissingStateMacKeyHighWaterValidator) => {
            panic!("MissingStateMacKeyHighWaterValidator: state_mac_key_high_water_validator")
        }
        Err(error) => panic!("canonical state MAC high water rejected: {error:?}"),
    }
}

fn reject(
    rows: &[StateMacKeyManifestRow],
    high_waters: &[StateMacKeyHighWater],
    expected: StateMacKeyHighWaterError,
) {
    match validate_state_mac_key_high_water(rows, SELECTED, high_waters) {
        Ok(()) => panic!("invalid state MAC high water accepted"),
        Err(StateMacKeyHighWaterError::MissingStateMacKeyHighWaterValidator) => {
            panic!("MissingStateMacKeyHighWaterValidator: state_mac_key_high_water_validator")
        }
        Err(error) => assert_eq!(error, expected),
    }
}

#[test]
fn complete_eleven_purpose_vector_bounds_selected_origin_rows() {
    validate(
        &[row(1, SELECTED, 1), row(10, SELECTED, 1)],
        &high_waters(1),
    );
}

#[test]
fn foreign_origin_rows_cannot_supply_or_exceed_selected_high_water_evidence() {
    validate(&[row(1, FOREIGN, u64::MAX)], &high_waters(0));
}

#[test]
fn every_closed_purpose_appears_once() {
    let mut missing = high_waters(0);
    missing.pop();
    reject(
        &[],
        &missing,
        StateMacKeyHighWaterError::MissingHighWaterPurpose,
    );
    let mut duplicate = high_waters(0);
    duplicate.push(StateMacKeyHighWater {
        purpose: MacPurpose::ApiKeyVerifyV1,
        serial_hi: 0,
        serial_lo: 0,
    });
    reject(
        &[],
        &duplicate,
        StateMacKeyHighWaterError::DuplicateHighWaterPurpose,
    );
}

#[test]
fn selected_origin_serial_uses_both_u32be_limbs() {
    validate(
        &[row(1, SELECTED, 0x0000_0001_0000_0000)],
        &high_waters(0x0000_0001_0000_0000),
    );
    reject(
        &[row(1, SELECTED, 0x0000_0001_0000_0001)],
        &high_waters(0x0000_0001_0000_0000),
        StateMacKeyHighWaterError::SelectedOriginSerialAboveHighWater,
    );
}

#[test]
fn high_water_validator_remains_private_and_in_memory_only() {
    let source = include_str!("state_mac_key_high_water.rs");
    for forbidden in [
        "pub struct",
        "pub enum",
        "pub fn",
        "rusqlite",
        "std::fs",
        "std::path",
        "std::time",
        "File",
        "Path",
        "header",
        "authenticate",
        "bootstrap",
        "pointer",
        "service",
        "release",
        "tag",
    ] {
        assert!(
            !source.contains(forbidden),
            "high-water validator boundary must not contain {forbidden:?}"
        );
    }
}
