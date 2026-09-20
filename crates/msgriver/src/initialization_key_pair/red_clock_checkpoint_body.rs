//! Frozen Task 0022 contract for the private A-13.2.2 checkpoint body.

use super::*;

fn valid(
    reason: CheckpointReason,
    hold: Option<NamedHold>,
    mirror: Option<PreMirrorWitness>,
) -> ClockCheckpointBody {
    ClockCheckpointBody {
        runtime_mode: RuntimeMode::Normal,
        process_instance: [0x11; 16],
        accepted_wall_time: 10,
        accepted_monotonic_tick: 7,
        prior_safe_time: 10,
        new_safe_time: 10,
        reason,
        hold,
        pre_mirror: mirror,
    }
}

fn named_hold() -> NamedHold {
    NamedHold {
        generation: 1,
        observation_digest: [0x22; 32],
    }
}

fn pre_mirror() -> PreMirrorWitness {
    let mut origin = [0x33; 32];
    origin[24..].copy_from_slice(&1u64.to_be_bytes());
    PreMirrorWitness {
        selected_origin: origin,
        transaction_sequence: 9,
        transaction_digest: [0x44; 32],
    }
}

fn require_wire(body: ClockCheckpointBody) -> Vec<u8> {
    match encode_clock_checkpoint_body(body) {
        Ok(wire) => wire,
        Err(ClockCheckpointBodyError::MissingClockCheckpointBody) => {
            panic!("MissingClockCheckpointBody: clock_checkpoint_body")
        }
        Err(ClockCheckpointBodyError::InvalidBody) => panic!("unexpected body encode failure"),
    }
}

fn require_invalid(wire: &[u8]) {
    match decode_clock_checkpoint_body(wire) {
        Err(ClockCheckpointBodyError::InvalidBody) => {}
        Err(ClockCheckpointBodyError::MissingClockCheckpointBody) => {
            panic!("MissingClockCheckpointBody: clock_checkpoint_body")
        }
        Ok(_) => panic!("invalid checkpoint body accepted"),
    }
}

#[test]
fn canonical_layouts_and_closed_tags_round_trip() {
    let cases = [
        (CheckpointReason::Periodic, None, None, 53usize),
        (
            CheckpointReason::AutomaticSettlement,
            Some(named_hold()),
            None,
            93,
        ),
        (
            CheckpointReason::CleanShutdown,
            None,
            Some(pre_mirror()),
            125,
        ),
        (CheckpointReason::ExpiryProof, None, Some(pre_mirror()), 125),
        (
            CheckpointReason::AutomaticSettlement,
            Some(named_hold()),
            Some(pre_mirror()),
            165,
        ),
    ];
    for (reason, hold, mirror, expected_len) in cases {
        let body = valid(reason, hold, mirror);
        let wire = require_wire(body);
        assert_eq!(wire.len(), expected_len);
        assert_eq!(wire[0], 1);
        assert_eq!(wire[1], 1);
        assert_eq!(&wire[2..18], &[0x11; 16]);
        assert_eq!(decode_clock_checkpoint_body(&wire), Ok(body));
    }
}

#[test]
fn equality_and_advance_are_canonical() {
    let equality = valid(CheckpointReason::Periodic, None, None);
    let equality_wire = require_wire(equality);
    assert_eq!(decode_clock_checkpoint_body(&equality_wire), Ok(equality));
    let mut lower_wall = equality;
    lower_wall.accepted_wall_time = 9;
    let lower_wall_wire = require_wire(lower_wall);
    assert_eq!(
        decode_clock_checkpoint_body(&lower_wall_wire),
        Ok(lower_wall)
    );
    let mut advance = equality;
    advance.runtime_mode = RuntimeMode::Maintenance;
    advance.accepted_wall_time = -5;
    advance.prior_safe_time = -9;
    advance.new_safe_time = -5;
    let advance_wire = require_wire(advance);
    assert_eq!(decode_clock_checkpoint_body(&advance_wire), Ok(advance));
}

#[test]
fn malformed_and_semantically_invalid_bodies_fail_closed() {
    let wire = require_wire(valid(CheckpointReason::Periodic, None, None));
    for width in 0..wire.len() {
        require_invalid(&wire[..width]);
    }
    let mut trailing = wire.clone();
    trailing.push(0);
    require_invalid(&trailing);
    for index in [0usize, 1, 26, 42, 50, 51, 52] {
        let mut changed = wire.clone();
        changed[index] ^= 0xff;
        require_invalid(&changed);
    }
    let mut width_mismatch = require_wire(valid(
        CheckpointReason::AutomaticSettlement,
        Some(named_hold()),
        None,
    ));
    width_mismatch[51] = 0;
    width_mismatch[52] = 1;
    require_invalid(&width_mismatch);
    let mut zero_process = valid(CheckpointReason::Periodic, None, None);
    zero_process.process_instance = [0; 16];
    assert!(matches!(
        encode_clock_checkpoint_body(zero_process),
        Err(ClockCheckpointBodyError::InvalidBody)
    ));
    let mut negative_tick = valid(CheckpointReason::Periodic, None, None);
    negative_tick.accepted_monotonic_tick = -1;
    assert!(matches!(
        encode_clock_checkpoint_body(negative_tick),
        Err(ClockCheckpointBodyError::InvalidBody)
    ));
    let mut regression = valid(CheckpointReason::Periodic, None, None);
    regression.new_safe_time = 9;
    assert!(matches!(
        encode_clock_checkpoint_body(regression),
        Err(ClockCheckpointBodyError::InvalidBody)
    ));
    let mut not_max = valid(CheckpointReason::Periodic, None, None);
    not_max.accepted_wall_time = 11;
    assert!(matches!(
        encode_clock_checkpoint_body(not_max),
        Err(ClockCheckpointBodyError::InvalidBody)
    ));
    assert!(matches!(
        encode_clock_checkpoint_body(valid(CheckpointReason::AutomaticSettlement, None, None)),
        Err(ClockCheckpointBodyError::InvalidBody)
    ));
    assert!(matches!(
        encode_clock_checkpoint_body(valid(CheckpointReason::Periodic, Some(named_hold()), None)),
        Err(ClockCheckpointBodyError::InvalidBody)
    ));
    let mut bad_hold = named_hold();
    bad_hold.generation = 0;
    assert!(matches!(
        encode_clock_checkpoint_body(valid(
            CheckpointReason::AutomaticSettlement,
            Some(bad_hold),
            None
        )),
        Err(ClockCheckpointBodyError::InvalidBody)
    ));
    let mut zero_hold_digest = named_hold();
    zero_hold_digest.observation_digest = [0; 32];
    assert!(matches!(
        encode_clock_checkpoint_body(valid(
            CheckpointReason::AutomaticSettlement,
            Some(zero_hold_digest),
            None
        )),
        Err(ClockCheckpointBodyError::InvalidBody)
    ));
    let mut reserved = pre_mirror();
    reserved.selected_origin[24..].copy_from_slice(&0u64.to_be_bytes());
    assert!(matches!(
        encode_clock_checkpoint_body(valid(CheckpointReason::Periodic, None, Some(reserved))),
        Err(ClockCheckpointBodyError::InvalidBody)
    ));
    let mut zero_mirror_digest = pre_mirror();
    zero_mirror_digest.transaction_digest = [0; 32];
    assert!(matches!(
        encode_clock_checkpoint_body(valid(
            CheckpointReason::Periodic,
            None,
            Some(zero_mirror_digest)
        )),
        Err(ClockCheckpointBodyError::InvalidBody)
    ));
}

#[test]
fn body_boundary_is_private_and_side_effect_free() {
    let source = include_str!("clock_checkpoint_body.rs");
    for forbidden in [
        "pub fn encode_clock_checkpoint_body",
        "std::fs",
        "tokio",
        "JournalIntegrityKey",
        "control_journal_record",
    ] {
        assert!(
            !source.contains(forbidden),
            "private body boundary leaked {forbidden}"
        );
    }
}
