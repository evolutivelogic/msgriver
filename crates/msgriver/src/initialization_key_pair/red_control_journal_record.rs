//! Frozen Task 0020 contract for the private A-13.2.1 lifecycle envelope.

use super::super::JournalIntegrityKey;
use super::*;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::error::Error;
use zeroize::Zeroizing;

const JOURNAL_KEY: [u8; 32] = [0x35; 32];
const OTHER_KEY: [u8; 32] = [0x53; 32];
const RECORD_LABEL: &[u8] = b"msgriver/control-journal-record/v1";
const AUTH_LABEL: &[u8] = b"msgriver/control-journal-record-auth/v1";
const MIN_FRAME_BYTES: usize = 110;
const MAX_FRAME_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = MAX_FRAME_BYTES - MIN_FRAME_BYTES;
const EXPECTED_DIGEST: [u8; 32] = [
    0xfb, 0x45, 0x5a, 0x40, 0x3c, 0x08, 0xdb, 0x64, 0xb6, 0x30, 0xda, 0x78, 0xdd, 0xc4, 0xc6, 0xc2,
    0x44, 0x1b, 0xaa, 0xd2, 0xc0, 0x07, 0xb1, 0x30, 0x3f, 0x86, 0x9b, 0x98, 0xf6, 0x09, 0xe2, 0xc0,
];
const EXPECTED_TAG: [u8; 32] = [
    0x4e, 0x30, 0x4c, 0x7f, 0x10, 0x73, 0x2a, 0x54, 0xc4, 0xed, 0x29, 0x75, 0x6e, 0x3d, 0x02, 0x91,
    0xe4, 0xa9, 0x04, 0x08, 0xe4, 0x59, 0x7a, 0x49, 0x1c, 0xa8, 0x9b, 0xb4, 0x01, 0x95, 0x80, 0x97,
];

fn key(bytes: [u8; 32]) -> JournalIntegrityKey {
    JournalIntegrityKey(Zeroizing::new(bytes))
}

fn require_wire(
    key: &JournalIntegrityKey,
    kind: ControlJournalRecordKind,
    body: &[u8],
    prior: JournalHead,
) -> Vec<u8> {
    match key.encode_control_journal_record(kind, body, prior) {
        Ok(wire) => wire,
        Err(ControlJournalRecordError::MissingControlJournalRecord) => {
            panic!("MissingControlJournalRecord: control_journal_record")
        }
        Err(error) => panic!("unexpected record-encode error: {error:?}"),
    }
}

fn require_record<'a>(
    key: &JournalIntegrityKey,
    wire: &'a [u8],
    prior: JournalHead,
) -> ControlJournalRecord<'a> {
    match key.decode_control_journal_record(wire, prior) {
        Ok(record) => record,
        Err(ControlJournalRecordError::MissingControlJournalRecord) => {
            panic!("MissingControlJournalRecord: control_journal_record")
        }
        Err(error) => panic!("unexpected record-decode error: {error:?}"),
    }
}

fn require_invalid(key: &JournalIntegrityKey, wire: &[u8], prior: JournalHead) {
    match key.decode_control_journal_record(wire, prior) {
        Err(ControlJournalRecordError::InvalidRecord) => {}
        Err(ControlJournalRecordError::MissingControlJournalRecord) => {
            panic!("MissingControlJournalRecord: control_journal_record")
        }
        Ok(_) | Err(ControlJournalRecordError::SequenceExhausted) => {
            panic!("unexpected record-decode result")
        }
    }
}

fn require_encode_invalid(
    key: &JournalIntegrityKey,
    kind: ControlJournalRecordKind,
    body: &[u8],
    prior: JournalHead,
) {
    match key.encode_control_journal_record(kind, body, prior) {
        Err(ControlJournalRecordError::InvalidRecord) => {}
        Err(ControlJournalRecordError::MissingControlJournalRecord) => {
            panic!("MissingControlJournalRecord: control_journal_record")
        }
        Ok(_) | Err(ControlJournalRecordError::SequenceExhausted) => {
            panic!("unexpected record-encode result")
        }
    }
}

fn kind_code(kind: ControlJournalRecordKind) -> u16 {
    match kind {
        ControlJournalRecordKind::ClockCheckpoint => 1,
        ControlJournalRecordKind::ClockAcknowledge => 2,
        ControlJournalRecordKind::SystemShutdown => 3,
    }
}

fn externally_authenticated_frame(
    kind: u16,
    sequence: u64,
    prior: [u8; 32],
    body: &[u8],
) -> Vec<u8> {
    let length = MIN_FRAME_BYTES + body.len();
    let mut frame = Vec::with_capacity(length);
    frame.extend_from_slice(&(length as u32).to_be_bytes());
    frame.extend_from_slice(&kind.to_be_bytes());
    frame.extend_from_slice(&sequence.to_be_bytes());
    frame.extend_from_slice(&prior);
    frame.extend_from_slice(body);
    let mut digest = Sha256::new();
    digest.update(RECORD_LABEL);
    digest.update(&frame[4..]);
    let digest: [u8; 32] = digest.finalize().into();
    frame.extend_from_slice(&digest);
    let mut mac = Hmac::<Sha256>::new_from_slice(&JOURNAL_KEY).expect("fixed test key");
    mac.update(AUTH_LABEL);
    mac.update(&frame);
    frame.extend_from_slice(&mac.finalize().into_bytes());
    frame
}

fn retag(frame: &mut [u8]) {
    let tag_start = frame.len() - 32;
    let mut mac = Hmac::<Sha256>::new_from_slice(&JOURNAL_KEY).expect("fixed test key");
    mac.update(AUTH_LABEL);
    mac.update(&frame[..tag_start]);
    frame[tag_start..].copy_from_slice(&mac.finalize().into_bytes());
}

#[test]
fn exact_kat_round_trips_all_kinds_and_frame_bounds() {
    let journal = key(JOURNAL_KEY);
    let genesis = JournalHead::genesis();
    let wire = require_wire(
        &journal,
        ControlJournalRecordKind::ClockCheckpoint,
        b"alpha",
        genesis,
    );
    assert_eq!(wire.len(), 115);
    assert_eq!(&wire[..4], &[0, 0, 0, 115]);
    assert_eq!(&wire[4..6], &[0, 1]);
    assert_eq!(&wire[6..14], &[0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(&wire[14..46], &[0; 32]);
    assert_eq!(&wire[46..51], b"alpha");
    assert_eq!(&wire[51..83], &EXPECTED_DIGEST, "external SHA-256 KAT");
    assert_eq!(&wire[83..], &EXPECTED_TAG, "external HMAC-SHA-256 KAT");
    let record = require_record(&journal, &wire, genesis);
    assert_eq!(record.kind, ControlJournalRecordKind::ClockCheckpoint);
    assert_eq!(record.sequence, 1);
    assert_eq!(record.record_digest, EXPECTED_DIGEST);
    assert_eq!(record.body, b"alpha");

    for kind in [
        ControlJournalRecordKind::ClockCheckpoint,
        ControlJournalRecordKind::ClockAcknowledge,
        ControlJournalRecordKind::SystemShutdown,
    ] {
        let frame = require_wire(&journal, kind, &[], genesis);
        assert_eq!(frame.len(), MIN_FRAME_BYTES);
        assert_eq!(
            u16::from_be_bytes(frame[4..6].try_into().expect("kind width")),
            kind_code(kind)
        );
        let empty = require_record(&journal, &frame, genesis);
        assert_eq!(empty.kind, kind);
        assert_eq!(empty.body, &[]);
        let maximum = require_wire(&journal, kind, &[0xa5; MAX_BODY_BYTES], genesis);
        assert_eq!(maximum.len(), MAX_FRAME_BYTES);
        let maximum_record = require_record(&journal, &maximum, genesis);
        assert_eq!(maximum_record.kind, kind);
        assert_eq!(maximum_record.body, &[0xa5; MAX_BODY_BYTES]);
    }
}

#[test]
fn chained_heads_and_final_sequence_are_exact() {
    let journal = key(JOURNAL_KEY);
    let genesis = JournalHead::genesis();
    let first_frame = require_wire(
        &journal,
        ControlJournalRecordKind::ClockCheckpoint,
        b"a",
        genesis,
    );
    let first = require_record(&journal, &first_frame, genesis);
    let prior = JournalHead {
        sequence: first.sequence,
        record_digest: first.record_digest,
    };
    let second_frame = require_wire(
        &journal,
        ControlJournalRecordKind::SystemShutdown,
        b"b",
        prior,
    );
    let second = require_record(&journal, &second_frame, prior);
    assert_eq!(second.sequence, 2);
    let final_prior = JournalHead {
        sequence: u64::MAX - 1,
        record_digest: [0x44; 32],
    };
    let final_frame = require_wire(
        &journal,
        ControlJournalRecordKind::ClockAcknowledge,
        &[],
        final_prior,
    );
    let final_record = require_record(&journal, &final_frame, final_prior);
    assert_eq!(final_record.sequence, u64::MAX);
    let exhausted = JournalHead {
        sequence: u64::MAX,
        record_digest: final_record.record_digest,
    };
    assert!(matches!(
        journal.encode_control_journal_record(
            ControlJournalRecordKind::ClockCheckpoint,
            &[],
            exhausted
        ),
        Err(ControlJournalRecordError::SequenceExhausted)
    ));
}

#[test]
fn malformed_or_noncontiguous_frames_fail_closed() {
    let journal = key(JOURNAL_KEY);
    let genesis = JournalHead::genesis();
    let wire = externally_authenticated_frame(1, 1, [0; 32], b"alpha");
    assert_eq!(wire[51..83], EXPECTED_DIGEST);
    assert_eq!(wire[83..], EXPECTED_TAG);
    for width in 0..wire.len() {
        require_invalid(&journal, &wire[..width], genesis);
    }
    let mut trailing = wire.clone();
    trailing.push(0);
    require_invalid(&journal, &trailing, genesis);
    for index in 0..wire.len() {
        let mut mutated = wire.clone();
        mutated[index] ^= 1;
        require_invalid(&journal, &mutated, genesis);
    }
    for length in [
        0u32,
        (MIN_FRAME_BYTES - 1) as u32,
        (MAX_FRAME_BYTES + 1) as u32,
    ] {
        let mut malformed = wire.clone();
        malformed[..4].copy_from_slice(&length.to_be_bytes());
        require_invalid(&journal, &malformed, genesis);
    }
    let oversized = externally_authenticated_frame(1, 1, [0; 32], &[0xa5; MAX_BODY_BYTES + 1]);
    assert_eq!(oversized.len(), MAX_FRAME_BYTES + 1);
    require_invalid(&journal, &oversized, genesis);
    require_encode_invalid(
        &journal,
        ControlJournalRecordKind::ClockCheckpoint,
        &[0xa5; MAX_BODY_BYTES + 1],
        genesis,
    );
    require_invalid(&key(OTHER_KEY), &wire, genesis);

    let unknown = externally_authenticated_frame(4, 1, [0; 32], b"");
    require_invalid(&journal, &unknown, genesis);
    let mut wrong_digest = wire.clone();
    wrong_digest[51] ^= 1;
    retag(&mut wrong_digest);
    require_invalid(&journal, &wrong_digest, genesis);
    require_invalid(
        &journal,
        &wire,
        JournalHead {
            sequence: 1,
            record_digest: EXPECTED_DIGEST,
        },
    );
    let gap = externally_authenticated_frame(1, 2, [0; 32], b"");
    require_invalid(&journal, &gap, genesis);
}

#[test]
fn private_surface_has_only_the_closed_diagnostics() {
    assert_eq!(
        ControlJournalRecordError::InvalidRecord.to_string(),
        "control journal record is invalid"
    );
    assert!(ControlJournalRecordError::InvalidRecord.source().is_none());
    let source = include_str!("control_journal_record.rs");
    for forbidden in [
        "pub struct ControlJournalRecord",
        "pub fn encode_control_journal_record",
        "std::fs",
        "rustix::fs",
        "MacKeyId",
        "pub trait",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }
}
