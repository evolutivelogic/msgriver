use super::{RawStateMacKeyHighWater, StateMacKeyMetaRowError, decode_state_mac_key_meta_rows};
use msgriver_core::canon::MacPurpose;

fn raw(purpose: i64, high: i64, low: i64) -> RawStateMacKeyHighWater {
    RawStateMacKeyHighWater {
        purpose,
        serial_hi: high,
        serial_lo: low,
    }
}

fn decode(origin: Vec<u8>, values: Vec<RawStateMacKeyHighWater>) {
    match decode_state_mac_key_meta_rows(origin, values) {
        Ok(_) => {}
        Err(StateMacKeyMetaRowError::MissingStateMacKeyMetaRowDecoder) => {
            panic!("MissingStateMacKeyMetaRowDecoder: state_mac_key_meta_row_decoder")
        }
        Err(error) => panic!("canonical state key meta row rejected: {error:?}"),
    }
}

fn reject(
    origin: Vec<u8>,
    values: Vec<RawStateMacKeyHighWater>,
    expected: StateMacKeyMetaRowError,
) {
    match decode_state_mac_key_meta_rows(origin, values) {
        Ok(_) => panic!("invalid state key meta row decoded"),
        Err(StateMacKeyMetaRowError::MissingStateMacKeyMetaRowDecoder) => {
            panic!("MissingStateMacKeyMetaRowDecoder: state_mac_key_meta_row_decoder")
        }
        Err(error) => assert_eq!(error, expected),
    }
}

#[test]
fn exact_origin_and_closed_high_water_rows_decode() {
    let values = (1..=11).map(|purpose| raw(purpose, 0, purpose)).collect();
    match decode_state_mac_key_meta_rows(vec![0x5a; 32], values) {
        Ok(facts) => {
            assert_eq!(facts.selected_origin, [0x5a; 32]);
            assert_eq!(facts.high_waters.len(), 11);
            assert_eq!(
                facts.high_waters[10].purpose,
                MacPurpose::PortableReservationV1
            );
            assert_eq!(facts.high_waters[10].serial_lo, 11);
        }
        Err(StateMacKeyMetaRowError::MissingStateMacKeyMetaRowDecoder) => {
            panic!("MissingStateMacKeyMetaRowDecoder: state_mac_key_meta_row_decoder")
        }
        Err(error) => panic!("canonical state key meta row rejected: {error:?}"),
    }
}

#[test]
fn origin_length_and_closed_purpose_fail_closed() {
    for length in 0..32 {
        reject(
            vec![0; length],
            vec![raw(1, 0, 1)],
            StateMacKeyMetaRowError::InvalidSelectedOriginLength,
        );
    }
    reject(
        vec![0; 33],
        vec![raw(1, 0, 1)],
        StateMacKeyMetaRowError::InvalidSelectedOriginLength,
    );
    for purpose in [-1, 0, 12, i64::MAX] {
        reject(
            vec![0; 32],
            vec![raw(purpose, 0, 1)],
            StateMacKeyMetaRowError::InvalidPurpose,
        );
    }
}

#[test]
fn signed_limb_boundaries_fail_closed() {
    for value in [-1, 1_i64 << 32, i64::MAX] {
        reject(
            vec![0; 32],
            vec![raw(1, value, 0)],
            StateMacKeyMetaRowError::LimbOutOfRange,
        );
        reject(
            vec![0; 32],
            vec![raw(1, 0, value)],
            StateMacKeyMetaRowError::LimbOutOfRange,
        );
    }
    decode(
        vec![0; 32],
        vec![raw(1, 0, 0), raw(11, u32::MAX.into(), u32::MAX.into())],
    );
}

#[test]
fn meta_row_decoder_remains_private_and_in_memory_only() {
    let source = include_str!("state_mac_key_meta_row.rs");
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
            "meta row decoder boundary must not contain {forbidden:?}"
        );
    }
}
