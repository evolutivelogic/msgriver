//! Frozen Task 0015 contract for the private control-journal header component.

use super::super::JournalIntegrityKey;
use super::*;
use msgriver_core::generation::OwnerNamespace;
use std::error::Error;
use zeroize::Zeroizing;

const JOURNAL_KEY: [u8; 32] = [0x35; 32];
const OTHER_KEY: [u8; 32] = [0x53; 32];
const EXPECTED_NAMESPACE: [u8; 24] = [
    0x8c, 0x46, 0x45, 0xd0, 0x63, 0xfc, 0xa4, 0x84, 0x41, 0x4f, 0x4d, 0x27, 0x31, 0xe5, 0x0b, 0x18,
    0x98, 0x4d, 0x95, 0x33, 0x46, 0x72, 0xde, 0x19,
];
const EXPECTED_TAG: [u8; 32] = [
    0xa2, 0x58, 0xc2, 0xa8, 0xce, 0xb0, 0x08, 0x5e, 0xb5, 0x88, 0x19, 0xe5, 0x2a, 0xbd, 0x61, 0x61,
    0xa9, 0x36, 0x0c, 0x1f, 0x71, 0x22, 0x06, 0x92, 0x34, 0x2c, 0x5c, 0xa1, 0x70, 0x68, 0x84, 0x12,
];
const FOREIGN_NAMESPACE: [u8; 24] = [0x99; 24];
const FOREIGN_NAMESPACE_TAG: [u8; 32] = [
    0x0b, 0x3d, 0x55, 0xc0, 0x40, 0x21, 0x22, 0xbb, 0x5a, 0x8d, 0xdb, 0xa0, 0xbd, 0xdc, 0xe7, 0x6e,
    0xa3, 0x69, 0x2b, 0x08, 0x5b, 0xee, 0x41, 0x4e, 0x5d, 0xce, 0x72, 0xd7, 0x02, 0x97, 0x78, 0x36,
];

fn key(bytes: [u8; 32]) -> JournalIntegrityKey {
    JournalIntegrityKey(Zeroizing::new(bytes))
}

fn require_header(key: &JournalIntegrityKey) -> ControlJournalHeader {
    match key.fresh_control_journal_header() {
        Ok(header) => header,
        Err(ControlJournalHeaderError::MissingControlJournalHeader) => {
            panic!("MissingControlJournalHeader: control_journal_header")
        }
        Err(error) => panic!("unexpected fresh-header error: {error:?}"),
    }
}

fn require_wire(key: &JournalIntegrityKey, header: ControlJournalHeader) -> [u8; WIRE_BYTES] {
    match key.encode_control_journal_header(header) {
        Ok(wire) => wire,
        Err(ControlJournalHeaderError::MissingControlJournalHeader) => {
            panic!("MissingControlJournalHeader: control_journal_header")
        }
        Err(error) => panic!("unexpected header-encode error: {error:?}"),
    }
}

fn require_decoded(key: &JournalIntegrityKey, wire: &[u8]) -> ControlJournalHeader {
    match key.decode_control_journal_header(wire) {
        Ok(header) => header,
        Err(ControlJournalHeaderError::MissingControlJournalHeader) => {
            panic!("MissingControlJournalHeader: control_journal_header")
        }
        Err(error) => panic!("unexpected header-decode error: {error:?}"),
    }
}

#[test]
fn fresh_header_and_exact_authenticated_round_trip() {
    let journal = key(JOURNAL_KEY);
    let header = require_header(&journal);
    let expected_namespace = match journal.derive_resource_incarnation_namespace_v1() {
        Ok(capability) => capability.0,
        Err(_) => panic!("existing private namespace derivation"),
    };
    assert_eq!(header.owner_namespace.as_bytes(), expected_namespace);
    assert_eq!(
        expected_namespace, EXPECTED_NAMESPACE,
        "independent namespace KAT"
    );
    assert_eq!(header.branch_serial_high_water, 0);
    let wire = require_wire(&journal, header);
    assert_eq!(wire.len(), WIRE_BYTES);
    assert_eq!(&wire[..16], &MAGIC);
    assert_eq!(
        u16::from_be_bytes(wire[16..18].try_into().expect("format width")),
        FORMAT_VERSION
    );
    assert_eq!(
        u16::from_be_bytes(wire[18..20].try_into().expect("key format width")),
        KEY_FORMAT_VERSION
    );
    assert_eq!(
        &wire[20..56],
        &[
            MAX_CONTROL_IMAGE_BYTES.to_be_bytes(),
            MAX_CONTROL_HEADER_BYTES.to_be_bytes(),
            MAX_CONTROL_CHECKPOINT_BYTES.to_be_bytes(),
            MAX_CONTROL_ORDINARY_CHECKPOINT_BYTES.to_be_bytes(),
            MAX_CONTROL_RECONCILIATION_CHECKPOINT_BYTES.to_be_bytes(),
            MAX_CONTROL_CHECKPOINT_ENTRIES.to_be_bytes(),
            MAX_CONTROL_TAIL_BYTES.to_be_bytes(),
            MAX_CONTROL_TAIL_RECORDS.to_be_bytes(),
            MAX_CONTROL_RECORD_BYTES.to_be_bytes(),
        ]
        .concat()
    );
    assert_eq!(&wire[56..80], &EXPECTED_NAMESPACE);
    assert_eq!(&wire[80..88], &[0; 8]);
    assert_eq!(&wire[88..], &EXPECTED_TAG, "independent header HMAC KAT");
    assert!(require_decoded(&journal, &wire) == header);
    assert_eq!(
        require_wire(&journal, header),
        wire,
        "deterministic tag/wire"
    );

    let nonzero = ControlJournalHeader {
        owner_namespace: OwnerNamespace::from_bytes(EXPECTED_NAMESPACE),
        branch_serial_high_water: 0x0102_0304_0506_0708,
    };
    let nonzero_wire = require_wire(&journal, nonzero);
    assert_eq!(&nonzero_wire[80..88], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(require_decoded(&journal, &nonzero_wire) == nonzero);

    let foreign = ControlJournalHeader {
        owner_namespace: OwnerNamespace::from_bytes(FOREIGN_NAMESPACE),
        branch_serial_high_water: 0,
    };
    assert!(matches!(
        journal.encode_control_journal_header(foreign),
        Err(ControlJournalHeaderError::InvalidHeader)
    ));
    let mut foreign_wire = wire;
    foreign_wire[56..80].copy_from_slice(&FOREIGN_NAMESPACE);
    foreign_wire[88..].copy_from_slice(&FOREIGN_NAMESPACE_TAG);
    assert!(matches!(
        journal.decode_control_journal_header(&foreign_wire),
        Err(ControlJournalHeaderError::InvalidHeader)
    ));
}

#[test]
fn mutations_and_wrong_key_fail_closed_before_returning_a_header() {
    let journal = key(JOURNAL_KEY);
    let wire = require_wire(&journal, require_header(&journal));
    for index in 0..WIRE_BYTES {
        let mut mutated = wire;
        mutated[index] ^= 0x01;
        assert!(
            matches!(
                journal.decode_control_journal_header(&mutated),
                Err(ControlJournalHeaderError::InvalidHeader)
            ),
            "mutation index {index}"
        );
    }
    for width in 0..WIRE_BYTES {
        assert!(
            matches!(
                journal.decode_control_journal_header(&wire[..width]),
                Err(ControlJournalHeaderError::InvalidHeader)
            ),
            "truncation width {width}"
        );
    }
    let mut trailing = wire.to_vec();
    trailing.push(0);
    assert!(matches!(
        journal.decode_control_journal_header(&trailing),
        Err(ControlJournalHeaderError::InvalidHeader)
    ));
    assert!(matches!(
        key(OTHER_KEY).decode_control_journal_header(&wire),
        Err(ControlJournalHeaderError::InvalidHeader)
    ));
}

#[test]
fn private_static_surface_and_closed_diagnostics() {
    let error = ControlJournalHeaderError::InvalidHeader;
    assert_eq!(error.to_string(), "control journal header is invalid");
    assert!(error.source().is_none());
    let source = include_str!("control_journal_header.rs");
    for forbidden in [
        "pub struct ControlJournalHeader",
        "pub fn encode_control_journal_header",
        "MacKeyId",
        "std::fs",
        "rustix::fs",
        "impl fmt::Debug for ControlJournalHeader {",
        "impl fmt::Display for ControlJournalHeader {",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }
}
