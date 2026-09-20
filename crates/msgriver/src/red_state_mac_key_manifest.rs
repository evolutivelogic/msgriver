use super::{StateMacKeyManifestError, validate_state_mac_key_manifest};
use crate::state_mac_key_manifest_row::{StateMacKeyManifestRow, StateMacKeyManifestStatus};
use msgriver_core::canon::{MacKeyId, MacKeyRef, MacPurpose};

const SELECTED: [u8; 32] = [0x31; 32];
const PREBOOTSTRAP: [u8; 32] = [0x62; 32];
const RETAINED: [u8; 32] = [0x93; 32];

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

fn row(
    purpose_byte: u8,
    origin: [u8; 32],
    serial: u64,
    status: StateMacKeyManifestStatus,
) -> StateMacKeyManifestRow {
    let mut key_id = [0; 40];
    key_id[..32].copy_from_slice(&origin);
    key_id[32..].copy_from_slice(&serial.to_be_bytes());
    StateMacKeyManifestRow {
        reference: MacKeyRef::new(purpose(purpose_byte), MacKeyId::from_bytes(key_id)),
        status,
        created_at: -19,
    }
}

fn canonical_manifest() -> Vec<StateMacKeyManifestRow> {
    (1..=11)
        .map(|purpose_byte| {
            let origin = if purpose_byte == 11 {
                PREBOOTSTRAP
            } else {
                SELECTED
            };
            row(purpose_byte, origin, 1, StateMacKeyManifestStatus::Active)
        })
        .collect()
}

fn validate(rows: &[StateMacKeyManifestRow]) {
    match validate_state_mac_key_manifest(rows, SELECTED, PREBOOTSTRAP) {
        Ok(()) => {}
        Err(StateMacKeyManifestError::MissingStateMacKeyManifestValidator) => {
            panic!("MissingStateMacKeyManifestValidator: state_mac_key_manifest_validator")
        }
        Err(error) => panic!("canonical state MAC manifest rejected: {error:?}"),
    }
}

fn reject(rows: &[StateMacKeyManifestRow], expected: StateMacKeyManifestError) {
    match validate_state_mac_key_manifest(rows, SELECTED, PREBOOTSTRAP) {
        Ok(()) => panic!("invalid state MAC manifest accepted"),
        Err(StateMacKeyManifestError::MissingStateMacKeyManifestValidator) => {
            panic!("MissingStateMacKeyManifestValidator: state_mac_key_manifest_validator")
        }
        Err(error) => assert_eq!(error, expected),
    }
}

#[test]
fn canonical_manifest_has_one_active_row_for_every_purpose() {
    validate(&canonical_manifest());
}

#[test]
fn retained_foreign_history_is_allowed_in_canonical_order() {
    let mut rows = canonical_manifest();
    rows.insert(1, row(1, RETAINED, 2, StateMacKeyManifestStatus::Retained));
    validate(&rows);
}

#[test]
fn noncanonical_order_and_duplicate_reference_are_rejected() {
    let mut out_of_order = canonical_manifest();
    out_of_order.swap(0, 1);
    reject(
        &out_of_order,
        StateMacKeyManifestError::OutOfOrderOrDuplicate,
    );

    let mut duplicate = canonical_manifest();
    duplicate.insert(1, row(1, SELECTED, 1, StateMacKeyManifestStatus::Retained));
    reject(&duplicate, StateMacKeyManifestError::OutOfOrderOrDuplicate);
}

#[test]
fn active_completeness_and_per_purpose_bound_are_rejected() {
    let mut missing = canonical_manifest();
    missing.remove(3);
    reject(&missing, StateMacKeyManifestError::MissingActivePurpose);

    let mut two_active = canonical_manifest();
    two_active.insert(1, row(1, SELECTED, 2, StateMacKeyManifestStatus::Active));
    reject(
        &two_active,
        StateMacKeyManifestError::MultipleActiveRowsForPurpose,
    );

    let mut too_many = canonical_manifest();
    for serial in 2..=17 {
        too_many.insert(
            (serial - 1) as usize,
            row(1, RETAINED, serial, StateMacKeyManifestStatus::Retained),
        );
    }
    reject(&too_many, StateMacKeyManifestError::TooManyRowsForPurpose);
}

#[test]
fn active_origin_rules_are_purpose_specific() {
    let mut internal_foreign = canonical_manifest();
    internal_foreign[0] = row(1, RETAINED, 1, StateMacKeyManifestStatus::Active);
    reject(
        &internal_foreign,
        StateMacKeyManifestError::ActiveOriginMismatch,
    );

    let mut portable_selected = canonical_manifest();
    portable_selected[10] = row(11, SELECTED, 1, StateMacKeyManifestStatus::Active);
    reject(
        &portable_selected,
        StateMacKeyManifestError::ActiveOriginMismatch,
    );
}

#[test]
fn manifest_validator_remains_private_and_in_memory_only() {
    let source = include_str!("state_mac_key_manifest.rs");
    for forbidden in [
        "pub struct",
        "pub enum",
        "pub fn",
        "rusqlite",
        "SELECT ",
        "std::fs",
        "std::path",
        "std::time",
        "File",
        "Path",
        "key material",
        "MacProvider",
        "pointer",
        "service",
        "release",
        "tag",
    ] {
        assert!(
            !source.contains(forbidden),
            "manifest validator boundary must not contain {forbidden:?}"
        );
    }
}
