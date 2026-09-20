//! Frozen Task 0071 contract for private authenticated generic-command composition.

use super::super::JournalIntegrityKey;
use super::super::fixed_root_command_authenticated::{
    FixedRootCommandAuthenticatedError, decode_fixed_root_command_authenticated,
    encode_fixed_root_command_authenticated,
};
use super::super::fixed_root_command_record::FixedRootCommandJournalHead;
use super::*;
use msgriver_core::canon::{MacKeyId, MacKeyRef, MacPurpose};
use zeroize::Zeroizing;

const JOURNAL_KEY: [u8; 32] = [0x35; 32];
const OTHER_KEY: [u8; 32] = [0x53; 32];
const PRE_BOOTSTRAP: [u8; 32] = [
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0, 0, 0, 0, 0, 0, 0, 0,
];
const ALLOCATED: [u8; 32] = [
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0, 0, 0, 0, 0, 0, 0, 1,
];

fn key(bytes: [u8; 32]) -> JournalIntegrityKey {
    JournalIntegrityKey(Zeroizing::new(bytes))
}

fn codec() -> FixedRootCommandCodec {
    FixedRootCommandCodec::new(PRE_BOOTSTRAP)
}

fn key_id(origin: [u8; 32], serial: u64) -> MacKeyId {
    let mut bytes = [0; 40];
    bytes[..32].copy_from_slice(&origin);
    bytes[32..].copy_from_slice(&serial.to_be_bytes());
    MacKeyId::from_bytes(bytes)
}

fn tag(purpose: MacPurpose, origin: [u8; 32], serial: u64, byte: u8) -> FixedRootCommandTag {
    FixedRootCommandTag {
        key: MacKeyRef::new(purpose, key_id(origin, serial)),
        tag: [byte; 32],
    }
}

fn tags() -> [FixedRootCommandTag; 4] {
    [
        tag(MacPurpose::CommandLookupV1, ALLOCATED, 1, 0x61),
        tag(MacPurpose::CommandSemanticFingerprintV1, ALLOCATED, 2, 0x62),
        tag(MacPurpose::CommandPhaseFingerprintV1, ALLOCATED, 3, 0x63),
        tag(MacPurpose::PortableReservationV1, PRE_BOOTSTRAP, 4, 0x64),
    ]
}

fn continuation() -> FixedRootCommand {
    FixedRootCommand {
        operation: FixedRootCommandOperation::RecoveryKeyGenerate,
        actor: FixedRootCommandActor::Principal(b"principal-1".to_vec()),
        tags: tags(),
        runtime: FixedRootCommandRuntime::Normal,
        process_instance: [0x51; 16],
        original_deadline: None,
        phase: 1,
        retention: FixedRootCommandRetention::Continuation,
        safe_result: None,
        target_binding: None,
        profile_body: vec![0xa5, 0x5a],
    }
}

fn maximum_command() -> FixedRootCommand {
    FixedRootCommand {
        operation: FixedRootCommandOperation::RecoveryKeyGenerate,
        actor: FixedRootCommandActor::Principal(vec![b'a'; 128]),
        tags: tags(),
        runtime: FixedRootCommandRuntime::Maintenance,
        process_instance: [0x52; 16],
        original_deadline: Some(-17),
        phase: 0x0102,
        retention: FixedRootCommandRetention::Terminal {
            terminal_time: 101,
            expires_at: 102,
        },
        safe_result: Some(FixedRootCommandSafeResult {
            codec: 1,
            version: 2,
            digest: [0x71; 32],
        }),
        target_binding: Some(FixedRootCommandTargetBinding {
            source: ALLOCATED,
            target: ALLOCATED,
            source_generation: Some(9),
            target_generation: Some(10),
            parent_witness: Some((ALLOCATED, 11, [0x72; 32], [0x73; 32])),
        }),
        profile_body: vec![0x33; 15_580],
    }
}

fn require_composed_wire(
    journal: &JournalIntegrityKey,
    command: FixedRootCommand,
    prior: FixedRootCommandJournalHead,
) -> Vec<u8> {
    match encode_fixed_root_command_authenticated(journal, &codec(), command, prior) {
        Ok(wire) => wire,
        Err(error) => panic!("unexpected authenticated command encode error: {error:?}"),
    }
}

#[test]
fn encoder_is_exactly_body_then_existing_generic_envelope_at_both_valid_extremes() {
    let journal = key(JOURNAL_KEY);
    let genesis = FixedRootCommandJournalHead::genesis();
    for command in [continuation(), maximum_command()] {
        let body = encode_fixed_root_command(&codec(), command.clone()).expect("valid body");
        let expected = journal
            .encode_fixed_root_command_record(&body, genesis)
            .expect("valid envelope");
        let actual = require_composed_wire(&journal, command.clone(), genesis);
        assert_eq!(
            actual, expected,
            "composition must not reframe or alter body bytes"
        );
        let decoded = decode_fixed_root_command_authenticated(&journal, &codec(), &actual, genesis)
            .expect("authenticated composed command");
        assert_eq!(decoded.command, command);
        assert_eq!(decoded.sequence, 1);
    }
    assert_eq!(
        require_composed_wire(&journal, maximum_command(), genesis).len(),
        16_384
    );
}

#[test]
fn decoder_authenticates_frame_before_body_and_never_returns_partial_state() {
    let journal = key(JOURNAL_KEY);
    let genesis = FixedRootCommandJournalHead::genesis();
    let canonical = require_composed_wire(&journal, continuation(), genesis);
    let mut unauthenticated_body_mutation = canonical.clone();
    unauthenticated_body_mutation[46] ^= 1;
    assert!(matches!(
        decode_fixed_root_command_authenticated(
            &journal,
            &codec(),
            &unauthenticated_body_mutation,
            genesis,
        ),
        Err(FixedRootCommandAuthenticatedError::InvalidCommand)
    ));
    let authenticated_invalid_body = journal
        .encode_fixed_root_command_record(&[0xff], genesis)
        .expect("authenticates opaque bytes");
    assert!(matches!(
        decode_fixed_root_command_authenticated(
            &journal,
            &codec(),
            &authenticated_invalid_body,
            genesis
        ),
        Err(FixedRootCommandAuthenticatedError::InvalidCommand)
    ));
    assert!(matches!(
        decode_fixed_root_command_authenticated(&key(OTHER_KEY), &codec(), &canonical, genesis),
        Err(FixedRootCommandAuthenticatedError::InvalidCommand)
    ));
    let source = include_str!("fixed_root_command_authenticated.rs");
    assert!(
        source
            .find("decode_fixed_root_command_record")
            .expect("record decode")
            < source
                .find("decode_fixed_root_command(")
                .expect("body decode"),
        "the record must authenticate before the body decoder is reached"
    );
}

#[test]
fn trusted_head_and_exhaustion_are_preserved_without_head_mutation() {
    let journal = key(JOURNAL_KEY);
    let genesis = FixedRootCommandJournalHead::genesis();
    let first_wire = require_composed_wire(&journal, continuation(), genesis);
    let first = decode_fixed_root_command_authenticated(&journal, &codec(), &first_wire, genesis)
        .expect("first record");
    let prior = FixedRootCommandJournalHead {
        sequence: first.sequence,
        record_digest: first.record_digest,
    };
    let second_wire = require_composed_wire(&journal, continuation(), prior);
    let second = decode_fixed_root_command_authenticated(&journal, &codec(), &second_wire, prior)
        .expect("second record");
    assert_eq!(second.sequence, 2);
    assert_eq!(
        decode_fixed_root_command_authenticated(&journal, &codec(), &first_wire, genesis)
            .expect("same trusted prior remains usable")
            .command,
        continuation()
    );
    let exhausted = FixedRootCommandJournalHead {
        sequence: u64::MAX,
        record_digest: [0x44; 32],
    };
    assert!(matches!(
        encode_fixed_root_command_authenticated(&journal, &codec(), continuation(), exhausted),
        Err(FixedRootCommandAuthenticatedError::SequenceExhausted)
    ));
}

#[test]
fn composition_and_exact_internal_bridge_have_no_public_or_durable_capability() {
    let composition = include_str!("fixed_root_command_authenticated.rs");
    for forbidden in [
        "pub ",
        "pub(crate)",
        "pub(in crate)",
        "std::fs",
        "rustix::fs",
        "Sha256",
        "Hmac",
        "fixed_root_command_record_digest",
        "fixed_root_command_record_tag",
    ] {
        assert!(
            !composition.contains(forbidden),
            "forbidden composition capability: {forbidden}"
        );
    }
    let body_bridge: Vec<_> = include_str!("fixed_root_command.rs")
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("pub(super)"))
        .collect();
    assert_eq!(
        body_bridge,
        [
            "pub(super) struct FixedRootCommand {",
            "pub(super) struct FixedRootCommandCodec {",
            "pub(super) enum FixedRootCommandError {",
            "pub(super) fn encode_fixed_root_command(",
            "pub(super) fn decode_fixed_root_command(",
        ]
    );
    let record_bridge: Vec<_> = include_str!("fixed_root_command_record.rs")
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("pub(super)"))
        .collect();
    assert_eq!(
        record_bridge,
        [
            "pub(super) struct FixedRootCommandJournalHead {",
            "pub(super) sequence: u64,",
            "pub(super) record_digest: [u8; 32],",
            "pub(super) fn genesis() -> Self {",
            "pub(super) struct FixedRootCommandRecord<'a> {",
            "pub(super) sequence: u64,",
            "pub(super) record_digest: [u8; 32],",
            "pub(super) body: &'a [u8],",
            "pub(super) enum FixedRootCommandRecordError {",
            "pub(super) fn encode_fixed_root_command_record(",
            "pub(super) fn decode_fixed_root_command_record<'a>(",
        ]
    );
}
