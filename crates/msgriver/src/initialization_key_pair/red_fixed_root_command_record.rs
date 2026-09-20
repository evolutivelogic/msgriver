//! Frozen Task 0069 contract for the private A-13.2.1 `0x0020` envelope.

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
    0x28, 0x36, 0xec, 0x20, 0xc0, 0x61, 0xe3, 0x78, 0x80, 0x8d, 0x0e, 0x1a, 0xeb, 0xf2, 0x59, 0xf2,
    0x91, 0xdb, 0x2e, 0x9c, 0x23, 0x52, 0x32, 0xd3, 0x7d, 0x3b, 0x03, 0xea, 0xb5, 0x53, 0x3d, 0xcb,
];
const EXPECTED_TAG: [u8; 32] = [
    0x49, 0xac, 0xad, 0xe2, 0xab, 0xc3, 0xc7, 0x91, 0xe4, 0x28, 0xa5, 0xdc, 0x7f, 0x46, 0xff, 0x35,
    0x21, 0x60, 0x5e, 0x00, 0xeb, 0x4e, 0x20, 0x00, 0x94, 0xb2, 0x5c, 0xb0, 0xcd, 0x2c, 0x98, 0xea,
];

fn key(bytes: [u8; 32]) -> JournalIntegrityKey {
    JournalIntegrityKey(Zeroizing::new(bytes))
}

fn require_wire(
    key: &JournalIntegrityKey,
    body: &[u8],
    prior: FixedRootCommandJournalHead,
) -> Vec<u8> {
    match key.encode_fixed_root_command_record(body, prior) {
        Ok(wire) => wire,
        Err(error) => panic!("unexpected fixed-root command record encode error: {error:?}"),
    }
}

fn require_record<'a>(
    key: &JournalIntegrityKey,
    wire: &'a [u8],
    prior: FixedRootCommandJournalHead,
) -> FixedRootCommandRecord<'a> {
    match key.decode_fixed_root_command_record(wire, prior) {
        Ok(record) => record,
        Err(error) => panic!("unexpected fixed-root command record decode error: {error:?}"),
    }
}

fn require_invalid(key: &JournalIntegrityKey, wire: &[u8], prior: FixedRootCommandJournalHead) {
    assert!(matches!(
        key.decode_fixed_root_command_record(wire, prior),
        Err(FixedRootCommandRecordError::InvalidRecord)
    ));
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
fn exact_generic_kind_kat_round_trips_frame_bounds_and_head() {
    let journal = key(JOURNAL_KEY);
    let genesis = FixedRootCommandJournalHead::genesis();
    let wire = require_wire(&journal, b"alpha", genesis);
    assert_eq!(wire.len(), 115);
    assert_eq!(&wire[..4], &[0, 0, 0, 115]);
    assert_eq!(&wire[4..6], &[0, 0x20]);
    assert_eq!(&wire[6..14], &[0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(&wire[14..46], &[0; 32]);
    assert_eq!(&wire[46..51], b"alpha");
    assert_eq!(&wire[51..83], &EXPECTED_DIGEST, "external SHA-256 KAT");
    assert_eq!(&wire[83..], &EXPECTED_TAG, "external HMAC-SHA-256 KAT");
    let record = require_record(&journal, &wire, genesis);
    assert_eq!(record.sequence, 1);
    assert_eq!(record.record_digest, EXPECTED_DIGEST);
    assert_eq!(record.body, b"alpha");

    let empty = require_wire(&journal, &[], genesis);
    assert_eq!(empty.len(), MIN_FRAME_BYTES);
    assert_eq!(require_record(&journal, &empty, genesis).body, &[]);
    let maximum = require_wire(&journal, &[0xa5; MAX_BODY_BYTES], genesis);
    assert_eq!(maximum.len(), MAX_FRAME_BYTES);
    assert_eq!(
        require_record(&journal, &maximum, genesis).body,
        &[0xa5; MAX_BODY_BYTES]
    );
}

#[test]
fn chained_heads_final_sequence_and_encoder_bounds_are_exact() {
    let journal = key(JOURNAL_KEY);
    let genesis = FixedRootCommandJournalHead::genesis();
    let first_wire = require_wire(&journal, b"a", genesis);
    let first = require_record(&journal, &first_wire, genesis);
    let prior = FixedRootCommandJournalHead {
        sequence: first.sequence,
        record_digest: first.record_digest,
    };
    let second_wire = require_wire(&journal, b"b", prior);
    let second = require_record(&journal, &second_wire, prior);
    assert_eq!(second.sequence, 2);
    let final_prior = FixedRootCommandJournalHead {
        sequence: u64::MAX - 1,
        record_digest: [0x44; 32],
    };
    assert_eq!(
        require_record(
            &journal,
            &require_wire(&journal, &[], final_prior),
            final_prior,
        )
        .sequence,
        u64::MAX
    );
    let exhausted = FixedRootCommandJournalHead {
        sequence: u64::MAX,
        record_digest: [0x55; 32],
    };
    assert!(matches!(
        journal.encode_fixed_root_command_record(&[], exhausted),
        Err(FixedRootCommandRecordError::SequenceExhausted)
    ));
    assert!(matches!(
        journal.encode_fixed_root_command_record(&[0xa5; MAX_BODY_BYTES + 1], genesis),
        Err(FixedRootCommandRecordError::InvalidRecord)
    ));
}

#[test]
fn malformed_retagged_wrong_digest_kind_and_chain_attacks_fail_closed() {
    let journal = key(JOURNAL_KEY);
    let genesis = FixedRootCommandJournalHead::genesis();
    let wire = externally_authenticated_frame(0x0020, 1, [0; 32], b"alpha");
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
    let oversized = externally_authenticated_frame(0x0020, 1, [0; 32], &[0xa5; MAX_BODY_BYTES + 1]);
    assert_eq!(oversized.len(), MAX_FRAME_BYTES + 1);
    require_invalid(&journal, &oversized, genesis);
    require_invalid(&key(OTHER_KEY), &wire, genesis);

    for kind in [0x0000, 0x0001, 0x0003, 0xffff] {
        require_invalid(
            &journal,
            &externally_authenticated_frame(kind, 1, [0; 32], b""),
            genesis,
        );
    }
    let mut wrong_digest = wire.clone();
    wrong_digest[51] ^= 1;
    retag(&mut wrong_digest);
    require_invalid(&journal, &wrong_digest, genesis);

    let head_digest = [0x42; 32];
    let head = FixedRootCommandJournalHead {
        sequence: 1,
        record_digest: head_digest,
    };
    require_invalid(
        &journal,
        &externally_authenticated_frame(0x0020, 3, head_digest, b""),
        head,
    );
    require_invalid(
        &journal,
        &externally_authenticated_frame(0x0020, 1, head_digest, b""),
        head,
    );
    let regression_head = FixedRootCommandJournalHead {
        sequence: 3,
        record_digest: head_digest,
    };
    require_invalid(
        &journal,
        &externally_authenticated_frame(0x0020, 2, head_digest, b""),
        regression_head,
    );
    require_invalid(
        &journal,
        &externally_authenticated_frame(0x0020, 2, [0x43; 32], b""),
        head,
    );
}

#[test]
fn private_surface_cannot_leak_key_or_command_body_capabilities() {
    assert_eq!(
        FixedRootCommandRecordError::InvalidRecord.to_string(),
        "fixed-root command record is invalid"
    );
    assert!(
        FixedRootCommandRecordError::InvalidRecord
            .source()
            .is_none()
    );
    let source = include_str!("fixed_root_command_record.rs");
    for forbidden in [
        "pub ",
        "std::fs",
        "rustix::fs",
        "MacKeyId",
        "fixed_root_command::",
        "encode_fixed_root_command(",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }
}
