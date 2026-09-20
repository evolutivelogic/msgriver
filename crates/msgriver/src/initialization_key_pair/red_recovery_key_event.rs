use super::*;

const COMMAND: [u8; 32] = [0x11; 32];
const SEMANTIC: [u8; 32] = [0x22; 32];
const PHASE: [u8; 32] = [0x33; 32];
const PORTABLE: [u8; 32] = [0x44; 32];
const CONFIRMATION: [u8; 32] = [0x55; 32];

fn event(
    phase: RecoveryKeyEventPhase,
    key_confirmation_digest: Option<[u8; 32]>,
    retention: RecoveryKeyEventRetention,
) -> RecoveryKeyEvent {
    RecoveryKeyEvent {
        generation: RecoveryKeyEventGeneration(7),
        command_digest: COMMAND,
        semantic_fingerprint: SEMANTIC,
        phase_fingerprint: PHASE,
        portable_reservation_digest: PORTABLE,
        key_confirmation_digest,
        phase,
        retention,
    }
}

fn phase_code(phase: RecoveryKeyEventPhase) -> u8 {
    match phase {
        RecoveryKeyEventPhase::IntentGenerate => 1,
        RecoveryKeyEventPhase::KeyDurable => 2,
        RecoveryKeyEventPhase::SecretConsumed => 3,
        RecoveryKeyEventPhase::PendingEscrow => 4,
        RecoveryKeyEventPhase::Activated => 5,
        RecoveryKeyEventPhase::TerminalFailed => 6,
    }
}

fn expected(value: RecoveryKeyEvent) -> Vec<u8> {
    let mut wire = vec![1, 1, 1, phase_code(value.phase)];
    wire.extend_from_slice(&value.generation.0.to_be_bytes());
    wire.extend_from_slice(&value.command_digest);
    wire.extend_from_slice(&value.semantic_fingerprint);
    wire.extend_from_slice(&value.phase_fingerprint);
    wire.extend_from_slice(&value.portable_reservation_digest);
    match value.key_confirmation_digest {
        None => wire.push(0),
        Some(digest) => {
            wire.push(1);
            wire.extend_from_slice(&digest);
        }
    }
    match value.retention {
        RecoveryKeyEventRetention::Null => wire.push(0),
        RecoveryKeyEventRetention::Terminal { expires_at } => {
            wire.push(1);
            wire.extend_from_slice(&expires_at.to_be_bytes());
        }
    }
    wire
}

fn encode(value: RecoveryKeyEvent) -> Vec<u8> {
    match encode_recovery_key_event(value) {
        Ok(wire) => wire,
        Err(RecoveryKeyEventError::MissingRecoveryKeyEvent) => {
            panic!("MissingRecoveryKeyEvent: recovery_key_event")
        }
        Err(error) => panic!("canonical recovery-key event rejected: {error:?}"),
    }
}

fn decode(wire: &[u8]) -> RecoveryKeyEvent {
    match decode_recovery_key_event(wire) {
        Ok(value) => value,
        Err(RecoveryKeyEventError::MissingRecoveryKeyEvent) => {
            panic!("MissingRecoveryKeyEvent: recovery_key_event")
        }
        Err(error) => panic!("canonical recovery-key event rejected: {error:?}"),
    }
}

fn reject(wire: &[u8]) {
    match decode_recovery_key_event(wire) {
        Ok(_) => panic!("invalid recovery-key event decoded"),
        Err(RecoveryKeyEventError::MissingRecoveryKeyEvent) => {
            panic!("MissingRecoveryKeyEvent: recovery_key_event")
        }
        Err(RecoveryKeyEventError::InvalidRecoveryKeyEvent) => {}
    }
}

fn valid_events() -> [RecoveryKeyEvent; 6] {
    [
        event(
            RecoveryKeyEventPhase::IntentGenerate,
            None,
            RecoveryKeyEventRetention::Null,
        ),
        event(
            RecoveryKeyEventPhase::KeyDurable,
            Some(CONFIRMATION),
            RecoveryKeyEventRetention::Null,
        ),
        event(
            RecoveryKeyEventPhase::SecretConsumed,
            Some(CONFIRMATION),
            RecoveryKeyEventRetention::Null,
        ),
        event(
            RecoveryKeyEventPhase::PendingEscrow,
            Some(CONFIRMATION),
            RecoveryKeyEventRetention::Null,
        ),
        event(
            RecoveryKeyEventPhase::Activated,
            Some(CONFIRMATION),
            RecoveryKeyEventRetention::Null,
        ),
        event(
            RecoveryKeyEventPhase::TerminalFailed,
            None,
            RecoveryKeyEventRetention::Terminal { expires_at: -5 },
        ),
    ]
}

#[test]
fn canonical_phase_forms_round_trip_at_exact_lengths() {
    for value in valid_events() {
        let wire = expected(value);
        assert!(matches!(wire.len(), 142 | 150 | 174));
        assert_eq!(encode(value), wire, "independent body vector");
        assert_eq!(decode(&wire), value);
    }
}

#[test]
fn malformed_tags_lengths_and_zero_digests_fail_closed() {
    for value in valid_events() {
        let wire = expected(value);
        for length in 0..wire.len() {
            reject(&wire[..length]);
        }
        let mut trailing = wire;
        trailing.push(0);
        reject(&trailing);
    }

    let intent = expected(valid_events()[0]);
    for (offset, value) in [(0, 2), (1, 2), (2, 2), (3, 0), (140, 2), (141, 2)] {
        let mut invalid = intent.clone();
        invalid[offset] = value;
        reject(&invalid);
    }
    for start in [4, 12, 44, 76, 108] {
        let mut invalid = intent.clone();
        invalid[start..start + if start == 4 { 8 } else { 32 }].fill(0);
        reject(&invalid);
    }
    let durable = expected(valid_events()[1]);
    let mut zero_confirmation = durable;
    zero_confirmation[141..173].fill(0);
    reject(&zero_confirmation);
}

#[test]
fn phase_specific_confirmation_retention_and_182_form_fail_closed() {
    let valid = valid_events();
    let durable = expected(valid[1]);
    let terminal = expected(valid[5]);

    let mut intent_with_confirmation = durable.clone();
    intent_with_confirmation[3] = 1;
    reject(&intent_with_confirmation);
    let mut durable_with_terminal_retention = durable.clone();
    durable_with_terminal_retention[173] = 1;
    durable_with_terminal_retention.extend_from_slice(&0_i64.to_be_bytes());
    reject(&durable_with_terminal_retention);
    let mut terminal_without_terminal_retention = terminal.clone();
    terminal_without_terminal_retention[141] = 0;
    terminal_without_terminal_retention.truncate(142);
    reject(&terminal_without_terminal_retention);
    let mut terminal_with_confirmation = terminal;
    terminal_with_confirmation[140] = 1;
    terminal_with_confirmation.splice(141..141, CONFIRMATION);
    reject(&terminal_with_confirmation);
}

#[test]
fn boundary_is_private_and_side_effect_free() {
    let source = include_str!("recovery_key_event.rs");
    for forbidden in [
        "pub struct RecoveryKeyEvent",
        "pub fn encode_recovery_key_event",
        "std::fs",
        "rustix::fs",
        "std::net",
        "JournalIntegrityKey",
        "Hmac",
        "sha2",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }
    assert!(source.contains("FRONTIER: recovery_key_event"));
}
