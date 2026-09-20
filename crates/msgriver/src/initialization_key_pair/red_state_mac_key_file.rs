use super::*;
use hmac::{Hmac, Mac};
use msgriver_core::canon::{MacKeyId, MacKeyRef, MacPurpose};
use sha2::Sha256;
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"msgriver/state-mac-key/v1";
const PRECEDING_BYTES: usize = 74;
const WIRE_BYTES: usize = 106;

fn journal(byte: u8) -> JournalIntegrityKey {
    JournalIntegrityKey(Zeroizing::new([byte; 32]))
}

fn reference(purpose: MacPurpose, origin: u8, serial: u64) -> MacKeyRef {
    let mut bytes = [origin; 40];
    bytes[32..].copy_from_slice(&serial.to_be_bytes());
    MacKeyRef::new(purpose, MacKeyId::from_bytes(bytes))
}

fn secret(byte: u8) -> StateMacKeySecret {
    StateMacKeySecret(Zeroizing::new([byte; 32]))
}

fn expected(reference: MacKeyRef, secret: &StateMacKeySecret) -> [u8; WIRE_BYTES] {
    let mut wire = [0; WIRE_BYTES];
    wire[0] = 1;
    wire[1] = reference.purpose() as u8;
    wire[2..42].copy_from_slice(reference.key_id().as_bytes());
    wire[42..74].copy_from_slice(&secret.0[..]);
    resign(&mut wire);
    wire
}

fn resign(wire: &mut [u8; WIRE_BYTES]) {
    let mut mac = Hmac::<Sha256>::new_from_slice(&[0x41; 32]).expect("fixed test journal key");
    mac.update(DOMAIN);
    mac.update(&wire[..PRECEDING_BYTES]);
    wire[PRECEDING_BYTES..].copy_from_slice(&mac.finalize().into_bytes());
}

fn encode(reference: MacKeyRef, secret: &StateMacKeySecret) -> [u8; WIRE_BYTES] {
    match encode_state_mac_key_file(&journal(0x41), reference, secret) {
        Ok(wire) => wire,
        Err(StateMacKeyFileError::MissingStateMacKeyFile) => {
            panic!("MissingStateMacKeyFile: state_mac_key_file")
        }
        Err(error) => panic!("canonical state MAC key rejected: {error:?}"),
    }
}

fn decode(reference: MacKeyRef, wire: &[u8]) -> StateMacKeySecret {
    match decode_state_mac_key_file(&journal(0x41), reference, wire) {
        Ok(value) => value,
        Err(StateMacKeyFileError::MissingStateMacKeyFile) => {
            panic!("MissingStateMacKeyFile: state_mac_key_file")
        }
        Err(error) => panic!("canonical state MAC key rejected: {error:?}"),
    }
}

fn reject(reference: MacKeyRef, wire: &[u8]) {
    match decode_state_mac_key_file(&journal(0x41), reference, wire) {
        Ok(_) => panic!("invalid state MAC key decoded"),
        Err(StateMacKeyFileError::MissingStateMacKeyFile) => {
            panic!("MissingStateMacKeyFile: state_mac_key_file")
        }
        Err(StateMacKeyFileError::InvalidStateMacKeyFile) => {}
    }
}

fn reject_encode(reference: MacKeyRef, value: &StateMacKeySecret) {
    match encode_state_mac_key_file(&journal(0x41), reference, value) {
        Ok(_) => panic!("invalid state MAC key encoded"),
        Err(StateMacKeyFileError::MissingStateMacKeyFile) => {
            panic!("MissingStateMacKeyFile: state_mac_key_file")
        }
        Err(StateMacKeyFileError::InvalidStateMacKeyFile) => {}
    }
}

#[test]
fn canonical_106_byte_hmac_vector_round_trips() {
    let reference = reference(MacPurpose::CommandLookupV1, 0x22, 1);
    let value = secret(0x33);
    let wire = expected(reference, &value);
    assert_eq!(wire.len(), WIRE_BYTES);
    assert_eq!(&wire[..2], &[1, 0x06]);
    assert_eq!(encode(reference, &value), wire);
    assert_eq!(decode(reference, &wire).0[..], value.0[..]);
}

#[test]
fn exact_length_and_authentication_fail_closed() {
    let reference = reference(MacPurpose::CommandLookupV1, 0x22, 1);
    let wire = expected(reference, &secret(0x33));
    for length in 0..WIRE_BYTES {
        reject(reference, &wire[..length]);
    }
    let mut trailing = wire.to_vec();
    trailing.push(0);
    reject(reference, &trailing);
    let mut bad_tag = wire;
    bad_tag[WIRE_BYTES - 1] ^= 1;
    reject(reference, &bad_tag);
    assert!(decode_state_mac_key_file(&journal(0x42), reference, &wire).is_err());
}

#[test]
fn authenticated_semantic_and_reference_failures_are_closed() {
    let expected_reference = reference(MacPurpose::CommandLookupV1, 0x22, 1);
    let wire = expected(expected_reference, &secret(0x33));
    for (offset, byte) in [(0, 2), (1, 0), (1, 0x0c)] {
        let mut invalid = wire;
        invalid[offset] = byte;
        resign(&mut invalid);
        reject(expected_reference, &invalid);
    }
    let mut zero_serial = wire;
    zero_serial[34..42].copy_from_slice(&0_u64.to_be_bytes());
    resign(&mut zero_serial);
    reject(expected_reference, &zero_serial);
    let mut zero_raw_key = wire;
    zero_raw_key[42..74].fill(0);
    resign(&mut zero_raw_key);
    reject(expected_reference, &zero_raw_key);
    reject(
        reference(MacPurpose::CommandSemanticFingerprintV1, 0x22, 1),
        &wire,
    );
    reject(reference(MacPurpose::CommandLookupV1, 0x23, 1), &wire);
}

#[test]
fn encode_rejects_zero_serial_and_raw_key() {
    reject_encode(
        reference(MacPurpose::CommandLookupV1, 0x22, 0),
        &secret(0x33),
    );
    reject_encode(reference(MacPurpose::CommandLookupV1, 0x22, 1), &secret(0));
}

#[test]
fn boundary_is_private_and_has_no_store_or_provider_capability() {
    let source = include_str!("state_mac_key_file.rs");
    for forbidden in [
        "pub struct StateMacKeySecret",
        "pub fn encode_state_mac_key_file",
        "std::fs",
        "rustix::fs",
        "Path",
        "SQLite",
        "MacProvider",
        "bootstrap",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }
    assert!(source.contains("FRONTIER: state_mac_key_file"));
}
