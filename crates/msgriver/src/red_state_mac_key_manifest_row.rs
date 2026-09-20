use super::*;
use msgriver_core::canon::MacPurpose;

fn raw(
    purpose: i64,
    origin: Vec<u8>,
    serial_hi: i64,
    serial_lo: i64,
    status: i64,
    created_at: i64,
) -> RawStateMacKeyManifestRow {
    RawStateMacKeyManifestRow {
        purpose,
        origin,
        serial_hi,
        serial_lo,
        status,
        created_at,
    }
}

fn valid(purpose: i64, serial_hi: i64, serial_lo: i64, status: i64) -> RawStateMacKeyManifestRow {
    raw(purpose, vec![0x22; 32], serial_hi, serial_lo, status, -17)
}

fn decode(raw: RawStateMacKeyManifestRow) -> StateMacKeyManifestRow {
    match decode_state_mac_key_manifest_row(raw) {
        Ok(value) => value,
        Err(StateMacKeyManifestRowError::MissingStateMacKeyManifestRowDecoder) => {
            panic!("MissingStateMacKeyManifestRowDecoder: state_mac_key_manifest_row_decoder")
        }
        Err(error) => panic!("canonical state MAC manifest row rejected: {error:?}"),
    }
}

fn reject(raw: RawStateMacKeyManifestRow, expected: StateMacKeyManifestRowError) {
    match decode_state_mac_key_manifest_row(raw) {
        Ok(_) => panic!("invalid state MAC manifest row decoded"),
        Err(StateMacKeyManifestRowError::MissingStateMacKeyManifestRowDecoder) => {
            panic!("MissingStateMacKeyManifestRowDecoder: state_mac_key_manifest_row_decoder")
        }
        Err(error) => assert_eq!(error, expected),
    }
}

#[test]
fn active_and_retained_vectors_preserve_exact_identity_and_created_at() {
    let active = decode(valid(6, 0, 1, 1));
    assert_eq!(active.status, StateMacKeyManifestStatus::Active);
    assert_eq!(active.reference.purpose(), MacPurpose::CommandLookupV1);
    assert_eq!(&active.reference.key_id().as_bytes()[..32], &[0x22; 32]);
    assert_eq!(
        &active.reference.key_id().as_bytes()[32..],
        &1_u64.to_be_bytes()
    );
    assert_eq!(active.created_at, -17);
    let retained = decode(valid(11, 1, 0, 2));
    assert_eq!(retained.status, StateMacKeyManifestStatus::Retained);
    assert_eq!(
        retained.reference.purpose(),
        MacPurpose::PortableReservationV1
    );
    assert_eq!(
        &retained.reference.key_id().as_bytes()[32..],
        &(1_u64 << 32).to_be_bytes()
    );
}

#[test]
fn every_closed_purpose_and_status_is_accepted() {
    for purpose in 1..=11 {
        for status in [1, 2] {
            let row = decode(valid(purpose, 0, 1, status));
            assert_eq!(row.created_at, -17);
        }
    }
}

#[test]
fn raw_field_boundaries_fail_closed() {
    for purpose in [-1, 0, 12, i64::MAX] {
        reject(
            valid(purpose, 0, 1, 1),
            StateMacKeyManifestRowError::InvalidPurpose,
        );
    }
    for status in [-1, 0, 3, i64::MAX] {
        reject(
            valid(1, 0, 1, status),
            StateMacKeyManifestRowError::InvalidStatus,
        );
    }
    for length in 0..32 {
        reject(
            raw(1, vec![0; length], 0, 1, 1, 0),
            StateMacKeyManifestRowError::InvalidOriginLength,
        );
    }
    reject(
        raw(1, vec![0; 33], 0, 1, 1, 0),
        StateMacKeyManifestRowError::InvalidOriginLength,
    );
    for (hi, lo) in [
        (-1, 0),
        (0, -1),
        (1_i64 << 32, 0),
        (0, 1_i64 << 32),
        (i64::MAX, 0),
        (0, i64::MAX),
    ] {
        reject(
            valid(1, hi, lo, 1),
            StateMacKeyManifestRowError::LimbOutOfRange,
        );
    }
    reject(valid(1, 0, 0, 1), StateMacKeyManifestRowError::ZeroSerial);
    let _ = decode(valid(1, i64::from(u32::MAX), i64::from(u32::MAX), 1));
}

#[test]
fn boundary_is_private_and_has_no_store_or_manifest_capability() {
    let source = include_str!("state_mac_key_manifest_row.rs");
    for forbidden in [
        "pub struct",
        "pub fn",
        "rusqlite",
        "SELECT",
        "std::fs",
        "Path",
        "std::time",
        "MacProvider",
        "StateMacKeyManifest {",
        "bootstrap",
        "pointer",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }
    assert!(source.contains("FRONTIER: state_mac_key_manifest_row_decoder"));
}
