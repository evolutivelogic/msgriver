//! Compatible old-checkpoint coverage retained from 70e1146c.
use super::*;

fn absent_addressed() -> [AddressedCell; 4] {
    [
        absent_cell(AddressedOperation::ClockAcknowledge, true),
        absent_cell(AddressedOperation::ClockAcknowledge, false),
        absent_cell(AddressedOperation::SystemShutdown, true),
        absent_cell(AddressedOperation::SystemShutdown, false),
    ]
}

fn addressed_image(
    journal: &JournalIntegrityKey,
    clock_authority: ClockAuthority,
    addressed: [AddressedCell; 4],
) -> CompleteControlJournalImage {
    let owner_namespace = match journal.derive_resource_incarnation_namespace_v1() {
        Ok(namespace) => namespace.0,
        Err(_) => panic!("derived namespace"),
    };
    CompleteControlJournalImage {
        header: AuthenticatedControlJournalHeader {
            owner_namespace,
            branch_serial_high_water: 1,
        },
        checkpoint: CompleteCheckpoint {
            generation: 2,
            covered_head: head(9, 0x39),
            clock_authority,
            active_pointer: None,
            recovery_ring: vec![],
            local_commands: vec![],
            addressed,
            provenance: vec![],
            coordinator: None,
            open_upgrade: None,
        },
        tail: vec![],
    }
}

fn hold_authority(generation: u64, safe_time: i64) -> ClockAuthority {
    ClockAuthority {
        safe_time,
        hold: Some(ClockHold {
            generation,
            observation_digest: [0x71; 32],
        }),
        last_shutdown_observation: None,
    }
}

fn mirror_origin() -> [u8; 32] {
    let mut origin = [0; 32];
    origin[..24].copy_from_slice(&complete_genesis(&key(0x35)).header.owner_namespace);
    origin[24..].copy_from_slice(&1_u64.to_be_bytes());
    origin
}

fn ack_pending_mirror() -> AddressedMirror {
    AddressedMirror::Pending {
        origin: mirror_origin(),
        pre: head(30, 0xB1),
        policy: 1,
    }
}

fn ack_committed_mirror() -> AddressedMirror {
    AddressedMirror::Committed {
        origin: mirror_origin(),
        pre: head(30, 0xB1),
        policy: 1,
        post: head(35, 0xE2),
    }
}

fn shutdown_pending_mirror() -> AddressedMirror {
    AddressedMirror::Pending {
        origin: mirror_origin(),
        pre: head(31, 0xB3),
        policy: 3,
    }
}

fn shutdown_committed_mirror() -> AddressedMirror {
    AddressedMirror::Committed {
        origin: mirror_origin(),
        pre: head(31, 0xB3),
        policy: 3,
        post: head(36, 0xE3),
    }
}

fn ack_evidence(selected: Option<i64>) -> AddressedEvidence {
    AddressedEvidence::Acknowledge {
        accepted_wall_time: 900,
        accepted_monotonic_tick: 40,
        prior_fixed_safe_time: 800,
        prior_selected_safe_time: selected,
        target_safe_time: 900,
    }
}

fn ack_address(generation: u64) -> AddressedOperationAddress {
    AddressedOperationAddress::ClockHold {
        generation,
        observation_digest: [0x71; 32],
    }
}

fn ack_value(
    generation: u64,
    phase: u8,
    selected: Option<i64>,
    mirror: AddressedMirror,
    record: JournalHead,
) -> AddressedStateValue {
    AddressedStateValue {
        desired_transition: DesiredMonotonicTransition::SettleHold {
            risk_acknowledged: true,
        },
        actor: AddressedActor::StateOwner,
        address: ack_address(generation),
        evidence: ack_evidence(selected),
        phase,
        safe_result: AddressedResult::Acknowledge {
            settled_safe_time: 900,
            settled: phase == 3,
        },
        application_head: record,
        publication_head: record,
        mirror,
    }
}

fn ack_request_action(generation: u64, pending: bool) -> AddressedAction {
    AddressedAction::PublishRequest(Box::new(AddressedStateValue {
        phase: 1,
        application_head: head(1, 1),
        publication_head: head(1, 1),
        desired_transition: DesiredMonotonicTransition::SettleHold {
            risk_acknowledged: true,
        },
        actor: AddressedActor::StateOwner,
        address: ack_address(generation),
        evidence: ack_evidence(pending.then_some(850)),
        safe_result: AddressedResult::Acknowledge {
            settled_safe_time: 900,
            settled: false,
        },
        mirror: if pending {
            ack_pending_mirror()
        } else {
            AddressedMirror::NotApplicable
        },
    }))
}

fn ack_phase_action(new_phase: u8) -> AddressedAction {
    AddressedAction::PublishPhase {
        phase: new_phase,
        result: AddressedResult::Acknowledge {
            settled_safe_time: 900,
            settled: new_phase == 3,
        },
    }
}

fn shutdown_evidence() -> AddressedEvidence {
    AddressedEvidence::Shutdown {
        accepted_monotonic_tick: 10,
        grace_deadline_tick: 260,
    }
}

fn shutdown_value(
    instance: u8,
    phase: u8,
    mirror: AddressedMirror,
    record: JournalHead,
) -> AddressedStateValue {
    AddressedStateValue {
        desired_transition: DesiredMonotonicTransition::StopProcess { grace_ms: 250 },
        actor: AddressedActor::StateOwner,
        address: AddressedOperationAddress::ProcessInstance([instance; 16]),
        evidence: shutdown_evidence(),
        phase,
        safe_result: AddressedResult::Shutdown {
            ungraceful_reason: u8::from(phase == 4) * 2,
        },
        application_head: if matches!(mirror, AddressedMirror::Committed { .. }) {
            head(record.sequence - 1, 0x37)
        } else {
            record
        },
        publication_head: record,
        mirror,
    }
}

fn shutdown_request_action(instance: u8, pending: bool) -> AddressedAction {
    AddressedAction::PublishRequest(Box::new(AddressedStateValue {
        phase: 1,
        application_head: head(1, 1),
        publication_head: head(1, 1),
        desired_transition: DesiredMonotonicTransition::StopProcess { grace_ms: 250 },
        actor: AddressedActor::StateOwner,
        address: AddressedOperationAddress::ProcessInstance([instance; 16]),
        evidence: shutdown_evidence(),
        safe_result: AddressedResult::Shutdown {
            ungraceful_reason: 0,
        },
        mirror: if pending {
            shutdown_pending_mirror()
        } else {
            AddressedMirror::NotApplicable
        },
    }))
}

fn shutdown_phase_action(new_phase: u8, reason: u8) -> AddressedAction {
    AddressedAction::PublishPhase {
        phase: new_phase,
        result: AddressedResult::Shutdown {
            ungraceful_reason: reason,
        },
    }
}

fn commit_action(sequence: u64) -> AddressedAction {
    AddressedAction::CommitMirror(head(sequence, 0xE5))
}

fn populated_ack_shutdown_image(journal: &JournalIntegrityKey) -> CompleteControlJournalImage {
    let mut cells = absent_addressed();
    cells[0].state = AddressedState::Present(Box::new(ack_value(
        7,
        2,
        Some(850),
        ack_pending_mirror(),
        head(6, 0x36),
    )));
    cells[2].state = AddressedState::Present(Box::new(shutdown_value(
        0x70,
        2,
        shutdown_pending_mirror(),
        head(9, 0x39),
    )));
    addressed_image(journal, hold_authority(7, 900), cells)
}

fn populated_ack_shutdown_last_image(journal: &JournalIntegrityKey) -> CompleteControlJournalImage {
    let mut image = populated_ack_shutdown_image(journal);
    let cells = &mut image.checkpoint.addressed;
    cells[2].state = AddressedState::Absent;
    cells[3].state = AddressedState::Present(Box::new(shutdown_value(
        0x60,
        3,
        shutdown_committed_mirror(),
        head(8, 0x38),
    )));
    image
}

fn require_checkpoint_payload(
    journal: &JournalIntegrityKey,
    image: &CompleteControlJournalImage,
) -> Vec<u8> {
    match encode_checkpoint(journal, image.header.owner_namespace, &image.checkpoint) {
        Ok(payload) => payload,
        Err(ControlJournalImageError::MissingControlJournalImage) => {
            panic!("MissingControlJournalImage: control_journal_image")
        }
        Err(error) => panic!("unexpected checkpoint encode error: {error:?}"),
    }
}

fn refuse_image(journal: &JournalIntegrityKey, image: &CompleteControlJournalImage) {
    match encode_control_journal_image(journal, image) {
        Err(ControlJournalImageError::InvalidControlJournalImage) => {}
        Err(ControlJournalImageError::MissingControlJournalImage) => {
            panic!("MissingControlJournalImage: control_journal_image")
        }
        Err(error) => panic!("expected invalid addressed image, got {error:?}"),
        Ok(_) => panic!("invalid addressed image unexpectedly encoded"),
    }
}

fn normal_authority() -> ([u8; 16], bool) {
    ([0x70; 16], false)
}

fn selected_image(mut image: CompleteControlJournalImage) -> CompleteControlJournalImage {
    image.header.branch_serial_high_water = 1;
    image.checkpoint.active_pointer = Some(ActiveStatePointerCertificate {
        protocol_version: 1,
        transition_id: "bootstrap-1".to_owned(),
        final_generation: 1,
        lineage_id: "lineage-1".to_owned(),
        target_history_epoch: mirror_origin(),
        origin: active_state_pointer::PointerOrigin::Bootstrap,
        database_certificate_digest: [0x76; 32],
    });
    image
}

fn require_append(
    journal: &JournalIntegrityKey,
    image: &CompleteControlJournalImage,
    operation: AddressedOperation,
    action: AddressedAction,
) -> CompleteControlJournalImage {
    let next = match append_addressed_action_with_authority(
        journal,
        image,
        operation,
        action,
        normal_authority(),
    ) {
        Ok(next) => next,
        Err(ControlJournalImageError::MissingControlJournalImage) => {
            panic!("MissingControlJournalImage: control_journal_image")
        }
        Err(error) => panic!("unexpected addressed append error: {error:?}"),
    };
    let wire = require_wire(journal, &next);
    match decode_control_journal_image(journal, &wire) {
        Ok(decoded) => assert_eq!(decoded, next),
        Err(ControlJournalImageError::MissingControlJournalImage) => {
            panic!("MissingControlJournalImage: control_journal_image")
        }
        Err(error) => panic!("unexpected appended image decode error: {error:?}"),
    }
    next
}

fn refuse_append(
    journal: &JournalIntegrityKey,
    image: &CompleteControlJournalImage,
    operation: AddressedOperation,
    action: AddressedAction,
) {
    match append_addressed_action_with_authority(
        journal,
        image,
        operation,
        action,
        normal_authority(),
    ) {
        Err(ControlJournalImageError::InvalidControlJournalImage) => {}
        Err(ControlJournalImageError::MissingControlJournalImage) => {
            panic!("MissingControlJournalImage: control_journal_image")
        }
        Err(error) => panic!("expected invalid addressed append, got {error:?}"),
        Ok(_) => panic!("illegal addressed action unexpectedly appended"),
    }
}

fn require_projection(
    _journal: &JournalIntegrityKey,
    image: &CompleteControlJournalImage,
) -> CompleteCheckpoint {
    match replay_tail(image) {
        Ok(checkpoint) => checkpoint,
        Err(ControlJournalImageError::MissingControlJournalImage) => {
            panic!("MissingControlJournalImage: control_journal_image")
        }
        Err(error) => panic!("unexpected addressed replay error: {error:?}"),
    }
}

fn projected_cell(
    checkpoint: &CompleteCheckpoint,
    operation: AddressedOperation,
    current: bool,
) -> &AddressedState {
    &checkpoint.addressed[operation.slot() + usize::from(!current)].state
}

fn present_value(state: &AddressedState) -> &AddressedStateValue {
    let AddressedState::Present(value) = state else {
        panic!("populated addressed cell")
    };
    value
}

fn require_clock_append(
    journal: &JournalIntegrityKey,
    image: &CompleteControlJournalImage,
    body: clock_checkpoint_body::ClockCheckpointBody,
) -> CompleteControlJournalImage {
    match append_clock_checkpoint(journal, image, body) {
        Ok(next) => next,
        Err(ControlJournalImageError::MissingControlJournalImage) => {
            panic!("MissingControlJournalImage: control_journal_image")
        }
        Err(error) => panic!("unexpected clock append error: {error:?}"),
    }
}

fn automatic_settlement(
    generation: u64,
    prior_safe_time: i64,
    new_safe_time: i64,
) -> clock_checkpoint_body::ClockCheckpointBody {
    clock_checkpoint_body::ClockCheckpointBody {
        runtime_mode: clock_checkpoint_body::RuntimeMode::Maintenance,
        process_instance: [0x75; 16],
        accepted_wall_time: new_safe_time,
        accepted_monotonic_tick: 50,
        prior_safe_time,
        new_safe_time,
        reason: clock_checkpoint_body::CheckpointReason::AutomaticSettlement,
        hold: Some(clock_checkpoint_body::NamedHold {
            generation,
            observation_digest: [0x71; 32],
        }),
        pre_mirror: None,
    }
}

#[test]
fn addressed_genesis_members_are_exact_and_populated_cells_round_trip() {
    let journal = key(0x35);
    let genesis = complete_genesis(&journal);
    let genesis_payload = require_checkpoint_payload(&journal, &genesis);
    let mut reader = ImageReader::new(&genesis_payload);
    for tag in 1..=6u16 {
        reader.member(tag).expect("genesis ordinary member");
    }
    let start = reader.offset;
    for tag in 7..=10u16 {
        reader.member(tag).expect("genesis addressed member");
    }
    let absent_members = &genesis_payload[start..reader.offset];
    let mut expected = Vec::new();
    for tag in 7..=10u16 {
        expected.extend_from_slice(&[0, tag as u8, 0, 0, 0, 1, 0]);
    }
    assert_eq!(absent_members.len(), 28);
    assert_eq!(absent_members, expected.as_slice());

    let image = populated_ack_shutdown_image(&journal);
    let wire = require_wire(&journal, &image);
    assert_eq!(
        decode_control_journal_image(&journal, &wire).expect("authenticated addressed decode"),
        image
    );
    let payload = require_checkpoint_payload(&journal, &image);
    let mut reader = ImageReader::new(&payload);
    for tag in 1..=6u16 {
        reader.member(tag).expect("ordinary member");
    }
    // Source-derived body lengths: 143 + n + E + M and 130 + n + M for the
    // 23-byte state-owner actor.
    assert_eq!(
        reader.member(7).expect("member 7").len(),
        143 + 23 + 41 + 74
    );
    assert_eq!(reader.member(8).expect("member 8"), &[0]);
    assert_eq!(reader.member(9).expect("member 9").len(), 130 + 23 + 74);
    assert_eq!(reader.member(10).expect("member 10"), &[0]);
    let image = populated_ack_shutdown_last_image(&journal);
    let wire = require_wire(&journal, &image);
    assert_eq!(
        decode_control_journal_image(&journal, &wire),
        Ok(image.clone())
    );
    let members = t78_members(&journal, &wire);
    assert_eq!(members[9].1.len(), 130 + 23 + 114);
}

#[test]
fn addressed_projection_rejects_every_source_violation_before_exposure() {
    let journal = key(0x35);
    let with_ack = |mutate: &dyn Fn(&mut AddressedStateValue)| {
        let mut image = populated_ack_shutdown_image(&journal);
        let AddressedState::Present(value) = &mut image.checkpoint.addressed[0].state else {
            panic!("populated acknowledge current")
        };
        mutate(value);
        image
    };
    let with_shutdown = |mutate: &dyn Fn(&mut AddressedStateValue)| {
        let mut image = populated_ack_shutdown_image(&journal);
        let AddressedState::Present(value) = &mut image.checkpoint.addressed[2].state else {
            panic!("populated shutdown current")
        };
        mutate(value);
        image
    };
    let with_shutdown_last = |mutate: &dyn Fn(&mut AddressedStateValue)| {
        let mut image = populated_ack_shutdown_last_image(&journal);
        let AddressedState::Present(value) = &mut image.checkpoint.addressed[3].state else {
            panic!("populated shutdown last")
        };
        mutate(value);
        image
    };
    let with_cells = |mutate: &dyn Fn(&mut [AddressedCell; 4])| {
        let mut image = populated_ack_shutdown_image(&journal);
        mutate(&mut image.checkpoint.addressed);
        image
    };

    // Actor grammar and length.
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.actor = AddressedActor::Principal(b"-bad".to_vec());
        }),
    );
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.actor = AddressedActor::Principal(vec![]);
        }),
    );
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.actor = AddressedActor::Principal(vec![b'a'; 129]);
        }),
    );
    // Address shape and nonzero address bytes.
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.address = AddressedOperationAddress::ClockHold {
                generation: 0,
                observation_digest: [0x71; 32],
            };
        }),
    );
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.address = AddressedOperationAddress::ClockHold {
                generation: 7,
                observation_digest: [0; 32],
            };
        }),
    );
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.address = AddressedOperationAddress::ProcessInstance([9; 16]);
        }),
    );
    // Evidence relations: nonnegative tick, exact target maximum, and the
    // evidence-width/mirror-tag pairing.
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.evidence = AddressedEvidence::Acknowledge {
                accepted_wall_time: 900,
                accepted_monotonic_tick: -1,
                prior_fixed_safe_time: 800,
                prior_selected_safe_time: None,
                target_safe_time: 900,
            };
        }),
    );
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.evidence = AddressedEvidence::Acknowledge {
                accepted_wall_time: 900,
                accepted_monotonic_tick: 40,
                prior_fixed_safe_time: 800,
                prior_selected_safe_time: Some(850),
                target_safe_time: 901,
            };
        }),
    );
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.evidence = ack_evidence(None);
        }),
    );
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.mirror = AddressedMirror::NotApplicable;
        }),
    );
    // Phase table and phase/result consistency, including phase-1 tag 2.
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.phase = 0;
        }),
    );
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.phase = 4;
        }),
    );
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.phase = 1;
            value.mirror = ack_committed_mirror();
        }),
    );
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.safe_result = AddressedResult::Acknowledge {
                settled_safe_time: 900,
                settled: true,
            };
        }),
    );
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.safe_result = AddressedResult::Acknowledge {
                settled_safe_time: 901,
                settled: false,
            };
        }),
    );
    // Mirror serial, head, and policy relations.
    let mut zero_serial = [0x41; 32];
    zero_serial[24..].fill(0);
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.mirror = AddressedMirror::Pending {
                origin: zero_serial,
                pre: head(30, 0xB1),
                policy: 1,
            };
        }),
    );
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.mirror = AddressedMirror::Pending {
                origin: mirror_origin(),
                pre: head(30, 0),
                policy: 1,
            };
        }),
    );
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.mirror = AddressedMirror::Pending {
                origin: mirror_origin(),
                pre: head(30, 0xB1),
                policy: 3,
            };
        }),
    );
    refuse_image(
        &journal,
        &with_shutdown_last(&|value: &mut AddressedStateValue| {
            value.mirror = AddressedMirror::Committed {
                origin: mirror_origin(),
                pre: head(31, 0xB3),
                policy: 3,
                post: head(36, 0),
            };
        }),
    );
    refuse_image(
        &journal,
        &with_shutdown_last(&|value: &mut AddressedStateValue| {
            value.mirror = AddressedMirror::Committed {
                origin: mirror_origin(),
                pre: head(31, 0xB3),
                policy: 3,
                post: head(31, 0xB3),
            };
        }),
    );
    // Paired fixed-root head relations and the folded covered head.
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.application_head = head(10, 0x3A);
        }),
    );
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.application_head = head(9, 0x3A);
        }),
    );
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.application_head = head(0, 0);
        }),
    );
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.application_head = head(10, 0x3A);
            value.publication_head = head(10, 0x3B);
        }),
    );
    refuse_image(
        &journal,
        &with_ack(&|value: &mut AddressedStateValue| {
            value.application_head = head(9, 0x40);
        }),
    );
    // Shutdown evidence: zero grace, deadline sum, and address bytes.
    refuse_image(
        &journal,
        &with_shutdown(&|value: &mut AddressedStateValue| {
            value.desired_transition = DesiredMonotonicTransition::StopProcess { grace_ms: 0 };
            value.evidence = AddressedEvidence::Shutdown {
                accepted_monotonic_tick: 10,
                grace_deadline_tick: 260,
            };
        }),
    );
    refuse_image(
        &journal,
        &with_shutdown(&|value: &mut AddressedStateValue| {
            value.evidence = AddressedEvidence::Shutdown {
                accepted_monotonic_tick: 10,
                grace_deadline_tick: 259,
            };
        }),
    );
    refuse_image(
        &journal,
        &with_shutdown(&|value: &mut AddressedStateValue| {
            value.evidence = AddressedEvidence::Shutdown {
                accepted_monotonic_tick: i64::MAX,
                grace_deadline_tick: i64::MIN,
            };
        }),
    );
    refuse_image(
        &journal,
        &with_shutdown(&|value: &mut AddressedStateValue| {
            value.address = AddressedOperationAddress::ProcessInstance([0; 16]);
        }),
    );
    // Shutdown phase/reason pairing and mirror policy.
    refuse_image(
        &journal,
        &with_shutdown(&|value: &mut AddressedStateValue| {
            value.safe_result = AddressedResult::Shutdown {
                ungraceful_reason: 1,
            };
        }),
    );
    refuse_image(
        &journal,
        &with_shutdown(&|value: &mut AddressedStateValue| {
            value.phase = 4;
        }),
    );
    refuse_image(
        &journal,
        &with_shutdown(&|value: &mut AddressedStateValue| {
            value.phase = 4;
            value.safe_result = AddressedResult::Shutdown {
                ungraceful_reason: 5,
            };
        }),
    );
    refuse_image(
        &journal,
        &with_shutdown(&|value: &mut AddressedStateValue| {
            value.mirror = AddressedMirror::Pending {
                origin: mirror_origin(),
                pre: head(31, 0xB3),
                policy: 1,
            };
        }),
    );
    // Slot invariants: completed cells never rest in current, last holds only
    // eligible terminal tag-0/2 completions, and acknowledge pairing.
    refuse_image(
        &journal,
        &with_cells(&|cells: &mut [AddressedCell; 4]| {
            cells[0].state = AddressedState::Present(Box::new(ack_value(
                7,
                3,
                None,
                AddressedMirror::NotApplicable,
                head(9, 0x39),
            )));
        }),
    );
    refuse_image(
        &journal,
        &with_cells(&|cells: &mut [AddressedCell; 4]| {
            cells[1].state = AddressedState::Present(Box::new(ack_value(
                6,
                2,
                None,
                AddressedMirror::NotApplicable,
                head(8, 0x38),
            )));
        }),
    );
    refuse_image(
        &journal,
        &with_cells(&|cells: &mut [AddressedCell; 4]| {
            cells[1].state = AddressedState::Present(Box::new(ack_value(
                6,
                3,
                Some(850),
                ack_pending_mirror(),
                head(8, 0x38),
            )));
        }),
    );
    refuse_image(
        &journal,
        &with_cells(&|cells: &mut [AddressedCell; 4]| {
            cells[1].state = AddressedState::Present(Box::new(ack_value(
                6,
                3,
                None,
                AddressedMirror::NotApplicable,
                head(8, 0x38),
            )));
        }),
    );
    require_wire(
        &journal,
        &with_cells(&|cells: &mut [AddressedCell; 4]| {
            cells[0].state = AddressedState::Absent;
            cells[1].state = AddressedState::Present(Box::new(ack_value(
                7,
                3,
                None,
                AddressedMirror::NotApplicable,
                head(6, 0x36),
            )));
        }),
    );
    refuse_image(
        &journal,
        &with_cells(&|cells: &mut [AddressedCell; 4]| {
            cells[0].state = AddressedState::Present(Box::new(ack_value(
                9,
                2,
                None,
                AddressedMirror::NotApplicable,
                head(9, 0x39),
            )));
        }),
    );

    // A pending mirror cannot advance publication without producing a phase.
    let mut newer_publication = populated_ack_shutdown_image(&journal);
    let AddressedState::Present(value) = &mut newer_publication.checkpoint.addressed[0].state
    else {
        panic!("populated acknowledge current")
    };
    value.application_head = head(8, 0x38);
    value.publication_head = head(9, 0x39);
    refuse_image(&journal, &newer_publication);

    // Cell wire bodies: unknown actor kind, phase, and mirror tags plus
    // trailing bytes fail the image's own cell decoder.
    let valid_body = encode_addressed_cell(
        AddressedOperation::ClockAcknowledge,
        &ack_value(7, 2, Some(850), ack_pending_mirror(), head(9, 0x39)),
    )
    .expect("canonical acknowledge cell body");
    assert_eq!(
        decode_addressed_cell(AddressedOperation::ClockAcknowledge, &valid_body),
        Ok(ack_value(
            7,
            2,
            Some(850),
            ack_pending_mirror(),
            head(9, 0x39)
        ))
    );
    for (offset, byte) in [(3usize, 3u8), (111, 4), (111, 0), (207, 3)] {
        let mut patched = valid_body.clone();
        patched[offset] = byte;
        assert!(
            matches!(
                decode_addressed_cell(AddressedOperation::ClockAcknowledge, &patched),
                Err(ControlJournalImageError::InvalidControlJournalImage)
            ),
            "patched cell byte {offset} must fail"
        );
    }
    let mut trailing = valid_body.clone();
    trailing.push(0);
    assert!(matches!(
        decode_addressed_cell(AddressedOperation::ClockAcknowledge, &trailing),
        Err(ControlJournalImageError::InvalidControlJournalImage)
    ));

    // Member inventory: reorder, duplication, omission, unknown tag, and a
    // non-00 absence byte all fail before projection exposure.
    let namespace = populated_ack_shutdown_image(&journal)
        .header
        .owner_namespace;
    let payload = require_checkpoint_payload(&journal, &populated_ack_shutdown_image(&journal));
    let mut reader = ImageReader::new(&payload);
    for tag in 1..=6u16 {
        reader.member(tag).expect("ordinary member");
    }
    let start = reader.offset;
    let mut ends = [0usize; 4];
    for (index, tag) in (7..=10u16).enumerate() {
        reader.member(tag).expect("addressed member");
        ends[index] = reader.offset;
    }
    let suffix = payload[ends[3]..].to_vec();
    let block = |index: usize| {
        payload[(if index == 0 { start } else { ends[index - 1] })..ends[index]].to_vec()
    };
    let splice = |blocks: &[Vec<u8>]| -> Vec<u8> {
        let mut spliced = payload[..start].to_vec();
        for member in blocks {
            spliced.extend_from_slice(member);
        }
        spliced.extend_from_slice(&suffix);
        spliced
    };
    assert_eq!(
        decode_checkpoint(
            &journal,
            namespace,
            &splice(&[block(0), block(1), block(2), block(3)])
        ),
        Ok(populated_ack_shutdown_image(&journal).checkpoint)
    );
    for blocks in [
        vec![block(1), block(0), block(2), block(3)],
        vec![block(0), block(0), block(2), block(3)],
        vec![block(0), block(1), block(2)],
        vec![block(0), block(1), block(2), member_bytes(11, &[0])],
    ] {
        assert!(
            matches!(
                decode_checkpoint(&journal, namespace, &splice(&blocks)),
                Err(ControlJournalImageError::InvalidControlJournalImage)
            ),
            "reordered, duplicate, missing, or unknown member must fail"
        );
    }
    let mut member_with_trailing = block(0);
    let body_length = u32::from_be_bytes(member_with_trailing[2..6].try_into().expect("length"));
    member_with_trailing.push(0);
    member_with_trailing[2..6].copy_from_slice(&(body_length + 1).to_be_bytes());
    assert!(matches!(
        decode_checkpoint(
            &journal,
            namespace,
            &splice(&[member_with_trailing, block(1), block(2), block(3)])
        ),
        Err(ControlJournalImageError::InvalidControlJournalImage)
    ));
    let genesis = complete_genesis(&journal);
    let genesis_payload = require_checkpoint_payload(&journal, &genesis);
    let mut reader = ImageReader::new(&genesis_payload);
    for tag in 1..=6u16 {
        reader.member(tag).expect("genesis member");
    }
    let genesis_start = reader.offset;
    let mut non_zero_absence = genesis_payload[..genesis_start].to_vec();
    non_zero_absence.extend_from_slice(&member_bytes(7, &[1]));
    non_zero_absence.extend_from_slice(&genesis_payload[genesis_start + 7..]);
    assert!(matches!(
        decode_checkpoint(&journal, genesis.header.owner_namespace, &non_zero_absence),
        Err(ControlJournalImageError::InvalidControlJournalImage)
    ));

    // Action bodies: only the three closed actions decode.
    let valid_action =
        encode_addressed_action(AddressedOperation::ClockAcknowledge, &ack_phase_action(2))
            .expect("canonical phase action");
    assert_eq!(
        decode_addressed_action(AddressedOperation::ClockAcknowledge, &valid_action),
        Ok(ack_phase_action(2))
    );
    let mut trailing_action = valid_action.clone();
    trailing_action.push(0);
    for (name, body) in [
        ("unknown action", action_bytes(4, &[0; 4])),
        ("action version", vec![2, 1, 0, 0]),
        ("unknown phase", {
            let mut payload = vec![5];
            payload.extend_from_slice(&valid_action[5..]);
            action_bytes(2, &payload)
        }),
        ("truncated result", action_bytes(2, &[2, 0x00, 0x77])),
        ("trailing payload", trailing_action),
        ("zero mirror post digest", action_bytes(3, &[0; 40])),
    ] {
        if !matches!(name, "unknown phase" | "zero mirror post digest") {
            assert_eq!(
                decode_addressed_action(AddressedOperation::ClockAcknowledge, &body),
                Err(INVALID),
                "{name}"
            );
        }
        let base = addressed_image(&journal, hold_authority(7, 800), absent_addressed());
        let base = require_append(
            &journal,
            &base,
            AddressedOperation::ClockAcknowledge,
            ack_request_action(7, false),
        );
        let base = require_fold(&base, FoldTrigger::TailFrameLimit);
        assert_invalid(
            &journal,
            &authenticated_action_wire(
                &journal,
                &base,
                AddressedOperation::ClockAcknowledge,
                &body,
            ),
        );
    }
}

fn action_bytes(action: u8, payload: &[u8]) -> Vec<u8> {
    let mut body = vec![1, action];
    body.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    body.extend_from_slice(payload);
    body
}

fn member_bytes(tag: u16, body: &[u8]) -> Vec<u8> {
    let mut member = tag.to_be_bytes().to_vec();
    member.extend_from_slice(&(body.len() as u32).to_be_bytes());
    member.extend_from_slice(body);
    member
}

#[test]
fn addressed_lifecycle_actions_apply_only_legal_edges_with_exact_results() {
    let journal = key(0x35);

    // Acknowledge tag-0 settlement: 1→2 raises safe time and retains the
    // hold; 2→3 clears the exact hold and completes into the last slot.
    let base = addressed_image(&journal, hold_authority(7, 800), absent_addressed());
    let installed = require_append(
        &journal,
        &base,
        AddressedOperation::ClockAcknowledge,
        ack_request_action(7, false),
    );
    let projection = require_projection(&journal, &installed);
    let cell = present_value(projected_cell(
        &projection,
        AddressedOperation::ClockAcknowledge,
        true,
    ));
    assert_eq!(cell.phase, 1);
    assert_eq!(cell.mirror, AddressedMirror::NotApplicable);
    assert_eq!(cell.application_head, installed.tail[0].resulting_head);
    assert_eq!(cell.publication_head, installed.tail[0].resulting_head);
    assert_eq!(
        cell.safe_result,
        AddressedResult::Acknowledge {
            settled_safe_time: 900,
            settled: false,
        }
    );
    let progressed = require_append(
        &journal,
        &installed,
        AddressedOperation::ClockAcknowledge,
        ack_phase_action(2),
    );
    let projection = require_projection(&journal, &progressed);
    let cell = present_value(projected_cell(
        &projection,
        AddressedOperation::ClockAcknowledge,
        true,
    ));
    assert_eq!(cell.phase, 2);
    assert_eq!(cell.mirror, AddressedMirror::NotApplicable);
    assert_eq!(cell.application_head, progressed.tail[1].resulting_head);
    assert_eq!(
        projection.clock_authority.hold,
        Some(ClockHold {
            generation: 7,
            observation_digest: [0x71; 32],
        })
    );
    assert_eq!(projection.clock_authority.safe_time, 900);
    let settled = require_append(
        &journal,
        &progressed,
        AddressedOperation::ClockAcknowledge,
        ack_phase_action(3),
    );
    let projection = require_projection(&journal, &settled);
    assert!(matches!(
        projected_cell(&projection, AddressedOperation::ClockAcknowledge, true),
        AddressedState::Absent
    ));
    let completed = present_value(projected_cell(
        &projection,
        AddressedOperation::ClockAcknowledge,
        false,
    ));
    assert_eq!(completed.phase, 3);
    assert_eq!(
        completed.safe_result,
        AddressedResult::Acknowledge {
            settled_safe_time: 900,
            settled: true,
        }
    );
    assert_eq!(projection.clock_authority.hold, None);
    assert_eq!(projection.clock_authority.safe_time, 900);
    assert_eq!(completed.application_head, settled.tail[2].resulting_head);
    let folded = require_fold(&settled, FoldTrigger::TailByteLimit);
    assert_eq!(
        folded.checkpoint.addressed[AddressedOperation::ClockAcknowledge.slot() + 1].state,
        AddressedState::Present(Box::new(ack_value(
            7,
            3,
            None,
            AddressedMirror::NotApplicable,
            settled.tail[2].resulting_head,
        )))
    );
    require_wire(&journal, &folded);
    let root = IsolatedOwnerRoot::create();
    require_publish(&journal, &root, &complete_genesis(&journal));
    require_publish(&journal, &root, &base);
    require_publish(&journal, &root, &settled);
    assert_eq!(
        reopen_control_journal_image(&journal, &root.path).expect("reopen settled lifecycle"),
        settled
    );

    // Acknowledge phase-2/tag-1 settles only through commit_mirror.
    let tag_one_base = selected_image(addressed_image(
        &journal,
        hold_authority(7, 800),
        absent_addressed(),
    ));
    let requested = require_append(
        &journal,
        &tag_one_base,
        AddressedOperation::ClockAcknowledge,
        ack_request_action(7, true),
    );
    let waiting = require_append(
        &journal,
        &requested,
        AddressedOperation::ClockAcknowledge,
        ack_phase_action(2),
    );
    let projection = require_projection(&journal, &waiting);
    let cell = present_value(projected_cell(
        &projection,
        AddressedOperation::ClockAcknowledge,
        true,
    ));
    assert_eq!(cell.phase, 2);
    assert_eq!(cell.mirror, ack_pending_mirror());
    assert_eq!(
        projection.clock_authority.hold,
        Some(ClockHold {
            generation: 7,
            observation_digest: [0x71; 32],
        })
    );
    refuse_append(
        &journal,
        &waiting,
        AddressedOperation::ClockAcknowledge,
        ack_phase_action(3),
    );
    refuse_append(
        &journal,
        &requested,
        AddressedOperation::ClockAcknowledge,
        commit_action(40),
    );
    refuse_append(
        &journal,
        &progressed,
        AddressedOperation::ClockAcknowledge,
        commit_action(40),
    );
    let mirrored = require_append(
        &journal,
        &waiting,
        AddressedOperation::ClockAcknowledge,
        commit_action(40),
    );
    let projection = require_projection(&journal, &mirrored);
    assert!(matches!(
        projected_cell(&projection, AddressedOperation::ClockAcknowledge, true),
        AddressedState::Absent
    ));
    let completed = present_value(projected_cell(
        &projection,
        AddressedOperation::ClockAcknowledge,
        false,
    ));
    assert_eq!(completed.phase, 3);
    assert_eq!(completed.mirror, ack_committed_mirror_with(head(40, 0xE5)));
    assert_eq!(
        completed.application_head,
        mirrored.tail.last().expect("commit frame").resulting_head
    );
    assert_eq!(
        completed.publication_head,
        mirrored.tail.last().expect("commit frame").resulting_head
    );
    assert_eq!(projection.clock_authority.hold, None);

    // Shutdown lifecycle never changes clock authority.
    let shutdown_base = addressed_image(&journal, hold_authority(7, 800), absent_addressed());
    let accepted = require_append(
        &journal,
        &shutdown_base,
        AddressedOperation::SystemShutdown,
        shutdown_request_action(0x70, false),
    );
    let projection = require_projection(&journal, &accepted);
    let cell = present_value(projected_cell(
        &projection,
        AddressedOperation::SystemShutdown,
        true,
    ));
    assert_eq!(cell.phase, 1);
    assert_eq!(projection.clock_authority.safe_time, 800);
    assert_eq!(
        projection.clock_authority.hold,
        Some(ClockHold {
            generation: 7,
            observation_digest: [0x71; 32],
        })
    );
    let stopping = require_append(
        &journal,
        &accepted,
        AddressedOperation::SystemShutdown,
        shutdown_phase_action(2, 0),
    );
    let graceful = require_append(
        &journal,
        &stopping,
        AddressedOperation::SystemShutdown,
        shutdown_phase_action(3, 0),
    );
    let projection = require_projection(&journal, &graceful);
    assert!(matches!(
        projected_cell(&projection, AddressedOperation::SystemShutdown, true),
        AddressedState::Absent
    ));
    let finished = present_value(projected_cell(
        &projection,
        AddressedOperation::SystemShutdown,
        false,
    ));
    assert_eq!(finished.phase, 3);
    assert_eq!(
        finished.safe_result,
        AddressedResult::Shutdown {
            ungraceful_reason: 0,
        }
    );
    assert_eq!(projection.clock_authority.safe_time, 800);
    let ungraceful = require_append(
        &journal,
        &stopping,
        AddressedOperation::SystemShutdown,
        shutdown_phase_action(4, 2),
    );
    let projection = require_projection(&journal, &ungraceful);
    let finished = present_value(projected_cell(
        &projection,
        AddressedOperation::SystemShutdown,
        false,
    ));
    assert_eq!(finished.phase, 4);
    assert_eq!(
        finished.safe_result,
        AddressedResult::Shutdown {
            ungraceful_reason: 2,
        }
    );

    // Recovery-only 1→4 admits the honest crash reason; normal-operation
    // 1→4 and every phase skip are rejected.
    refuse_append(
        &journal,
        &accepted,
        AddressedOperation::SystemShutdown,
        shutdown_phase_action(4, 1),
    );
    let recovered = append_addressed_action_with_authority(
        &journal,
        &accepted,
        AddressedOperation::SystemShutdown,
        shutdown_phase_action(4, 1),
        ([0x80; 16], true),
    )
    .expect("fence-recovered old shutdown");
    let projection = require_projection(&journal, &recovered);
    assert_eq!(projection.addressed[2].state, AddressedState::Absent);
    assert_eq!(projection.addressed[3].state, AddressedState::Absent);
    assert_eq!(
        projection.clock_authority,
        shutdown_base.checkpoint.clock_authority
    );
    refuse_append(
        &journal,
        &accepted,
        AddressedOperation::SystemShutdown,
        shutdown_phase_action(4, 2),
    );
    refuse_append(
        &journal,
        &accepted,
        AddressedOperation::SystemShutdown,
        shutdown_phase_action(4, 3),
    );
    refuse_append(
        &journal,
        &accepted,
        AddressedOperation::SystemShutdown,
        shutdown_phase_action(3, 0),
    );
    refuse_append(
        &journal,
        &installed,
        AddressedOperation::ClockAcknowledge,
        ack_phase_action(3),
    );
    refuse_append(
        &journal,
        &base,
        AddressedOperation::ClockAcknowledge,
        ack_phase_action(2),
    );
    refuse_append(
        &journal,
        &shutdown_base,
        AddressedOperation::SystemShutdown,
        shutdown_phase_action(2, 0),
    );
    refuse_append(
        &journal,
        &stopping,
        AddressedOperation::SystemShutdown,
        shutdown_phase_action(3, 1),
    );
    refuse_append(
        &journal,
        &installed,
        AddressedOperation::ClockAcknowledge,
        AddressedAction::PublishPhase {
            phase: 2,
            result: AddressedResult::Acknowledge {
                settled_safe_time: 901,
                settled: false,
            },
        },
    );

    // A terminal tag-1 shutdown stays current and undisclosable until its
    // mirror commit preserves the terminal-producing application head.
    let pending_base = selected_image(addressed_image(
        &journal,
        hold_authority(7, 800),
        absent_addressed(),
    ));
    let pending_accepted = require_append(
        &journal,
        &pending_base,
        AddressedOperation::SystemShutdown,
        shutdown_request_action(0x70, true),
    );
    let pending_stopping = require_append(
        &journal,
        &pending_accepted,
        AddressedOperation::SystemShutdown,
        shutdown_phase_action(2, 0),
    );
    let pending_terminal = require_append(
        &journal,
        &pending_stopping,
        AddressedOperation::SystemShutdown,
        shutdown_phase_action(3, 0),
    );
    let projection = require_projection(&journal, &pending_terminal);
    let cell = present_value(projected_cell(
        &projection,
        AddressedOperation::SystemShutdown,
        true,
    ));
    assert_eq!(cell.phase, 3);
    assert_eq!(cell.mirror, shutdown_pending_mirror());
    assert!(matches!(
        projected_cell(&projection, AddressedOperation::SystemShutdown, false),
        AddressedState::Absent
    ));
    let terminal_head = pending_terminal
        .tail
        .last()
        .expect("terminal frame")
        .resulting_head;
    let folded_pending = require_fold(&pending_terminal, FoldTrigger::TailFrameLimit);
    let AddressedState::Present(folded_cell) =
        &folded_pending.checkpoint.addressed[AddressedOperation::SystemShutdown.slot()].state
    else {
        panic!("terminal tag-1 obligation survives folding")
    };
    assert_eq!(folded_cell.application_head, terminal_head);
    refuse_append(
        &journal,
        &pending_stopping,
        AddressedOperation::SystemShutdown,
        commit_action(40),
    );
    refuse_append(
        &journal,
        &graceful,
        AddressedOperation::SystemShutdown,
        commit_action(40),
    );
    let committed = require_append(
        &journal,
        &pending_terminal,
        AddressedOperation::SystemShutdown,
        commit_action(40),
    );
    let projection = require_projection(&journal, &committed);
    assert!(matches!(
        projected_cell(&projection, AddressedOperation::SystemShutdown, true),
        AddressedState::Absent
    ));
    let finished = present_value(projected_cell(
        &projection,
        AddressedOperation::SystemShutdown,
        false,
    ));
    assert_eq!(finished.phase, 3);
    assert_eq!(
        finished.mirror,
        shutdown_committed_mirror_with(head(40, 0xE5))
    );
    assert_eq!(finished.application_head, terminal_head);
    assert_eq!(
        finished.publication_head,
        committed.tail.last().expect("commit frame").resulting_head
    );
}

fn ack_committed_mirror_with(post: JournalHead) -> AddressedMirror {
    AddressedMirror::Committed {
        origin: mirror_origin(),
        pre: head(30, 0xB1),
        policy: 1,
        post,
    }
}

fn shutdown_committed_mirror_with(post: JournalHead) -> AddressedMirror {
    AddressedMirror::Committed {
        origin: mirror_origin(),
        pre: head(31, 0xB3),
        policy: 3,
        post,
    }
}

#[test]
fn hold_entry_eviction_and_hold_clear_finalization_survive_fold_and_reopen() {
    let journal = key(0x35);
    let base = addressed_image(&journal, hold_authority(7, 800), absent_addressed());
    let requested = require_append(
        &journal,
        &base,
        AddressedOperation::ClockAcknowledge,
        ack_request_action(7, false),
    );
    let progress = require_append(
        &journal,
        &requested,
        AddressedOperation::ClockAcknowledge,
        ack_phase_action(2),
    );
    let completed = require_append(
        &journal,
        &progress,
        AddressedOperation::ClockAcknowledge,
        ack_phase_action(3),
    );
    let h1 = require_fold(&completed, FoldTrigger::TailFrameLimit);
    assert!(matches!(
        h1.checkpoint.addressed[1].state,
        AddressedState::Present(_)
    ));
    let h2 = enter_clock_hold(
        &h1,
        ClockHold {
            generation: 8,
            observation_digest: [0x71; 32],
        },
    )
    .expect("atomic hold entry");
    assert_eq!(h2.checkpoint.addressed[1].state, AddressedState::Absent);
    assert_eq!(h2.checkpoint.clock_authority.safe_time, 900);
    let cleared = require_clock_append(&journal, &h2, automatic_settlement(8, 900, 950));
    let folded = require_fold(&cleared, FoldTrigger::TailByteLimit);
    assert_eq!(folded.checkpoint.addressed[0].state, AddressedState::Absent);
    assert_eq!(folded.checkpoint.addressed[1].state, AddressedState::Absent);

    // H2 clearance preserves the unrelated H1 mirror obligation. Its own late
    // receipt drops it without restoring H1 completion eligibility.
    let pending_base = selected_image(base.clone());
    let pending = require_append(
        &journal,
        &pending_base,
        AddressedOperation::ClockAcknowledge,
        ack_request_action(7, true),
    );
    let pending = require_append(
        &journal,
        &pending,
        AddressedOperation::ClockAcknowledge,
        ack_phase_action(2),
    );
    let pending_projection = require_projection(&journal, &pending);
    let h2_pending = enter_clock_hold(
        &pending,
        ClockHold {
            generation: 8,
            observation_digest: [0x71; 32],
        },
    )
    .expect("retain old obligation");
    assert_eq!(
        h2_pending.checkpoint.addressed[0],
        pending_projection.addressed[0]
    );
    let blocked = append_addressed_action(
        &journal,
        &h2_pending,
        AddressedOperation::ClockAcknowledge,
        ack_request_action(8, true),
        [0x70; 16],
        false,
    );
    assert_eq!(blocked, Err(INVALID));
    let dropped = require_clock_append(&journal, &h2_pending, automatic_settlement(8, 900, 950));
    let dropped = require_fold(&dropped, FoldTrigger::TailFrameLimit);
    assert_eq!(
        dropped.checkpoint.addressed[0],
        pending_projection.addressed[0]
    );
    assert_eq!(
        dropped.checkpoint.addressed[1].state,
        AddressedState::Absent
    );
    let resolved = require_append(
        &journal,
        &dropped,
        AddressedOperation::ClockAcknowledge,
        commit_action(40),
    );
    let resolved = require_projection(&journal, &resolved);
    assert_eq!(resolved.addressed[0].state, AddressedState::Absent);
    assert_eq!(resolved.addressed[1].state, AddressedState::Absent);

    // A matching pending mirror cannot be invented by an automatic clock
    // observation. The exact existing commit_mirror barrier must resolve it.
    assert_eq!(
        append_clock_checkpoint(&journal, &pending, automatic_settlement(7, 900, 950)),
        Err(INVALID)
    );
    assert_eq!(require_projection(&journal, &pending), pending_projection);

    let root = IsolatedOwnerRoot::create();
    require_publish(&journal, &root, &complete_genesis(&journal));
    require_publish(&journal, &root, &h1);
    for fault in [
        PublicationFault::UniqueTemporaryCreate,
        PublicationFault::TemporaryWrite,
        PublicationFault::FileSync,
        PublicationFault::ReplacementRename,
    ] {
        assert!(
            publish_control_journal_image_with_fault(&journal, &root.path, &h2, fault).is_err()
        );
        assert_eq!(
            reopen_control_journal_image(&journal, &root.path).expect("old publication"),
            h1
        );
    }
    require_publish(&journal, &root, &h2);
    assert_eq!(
        reopen_control_journal_image(&journal, &root.path).expect("entry publication"),
        h2
    );
    require_publish(&journal, &root, &folded);
    assert_eq!(
        reopen_control_journal_image(&journal, &root.path).expect("clear publication"),
        folded
    );
}

// Repair regressions: these compile against the reviewed candidate and fail
// for the missing semantics, before the corresponding repair is applied.
#[test]
fn repair_automatic_clear_completes_in_the_same_publication() {
    let journal = key(0x35);
    let mut cells = absent_addressed();
    cells[0].state = AddressedState::Present(Box::new(ack_value(
        7,
        2,
        None,
        AddressedMirror::NotApplicable,
        head(9, 0x39),
    )));
    let base = addressed_image(&journal, hold_authority(7, 900), cells);
    let next = require_clock_append(&journal, &base, automatic_settlement(7, 900, 950));
    let projection = require_projection(&journal, &next);
    assert_eq!(projection.clock_authority.safe_time, 950);
    assert_eq!(projection.clock_authority.hold, None);
    assert_eq!(projection.addressed[0].state, AddressedState::Absent);
    let last = present_value(&projection.addressed[1].state);
    assert_eq!(last.phase, 3);
    assert_eq!(
        last.application_head,
        next.tail.last().expect("clear frame").resulting_head
    );
    let folded = require_fold(&next, FoldTrigger::TailFrameLimit);
    assert_eq!(folded.checkpoint.addressed, projection.addressed);
}

#[test]
fn repair_absent_authority_drops_late_completion() {
    let journal = key(0x35);
    let mut cells = absent_addressed();
    cells[0].state = AddressedState::Present(Box::new(ack_value(
        7,
        2,
        None,
        AddressedMirror::NotApplicable,
        head(9, 0x39),
    )));
    let mut authority = hold_authority(7, 900);
    authority.hold = None;
    let base = addressed_image(&journal, authority, cells);
    let next = require_append(
        &journal,
        &base,
        AddressedOperation::ClockAcknowledge,
        ack_phase_action(3),
    );
    assert_eq!(
        require_projection(&journal, &next).addressed[1].state,
        AddressedState::Absent
    );
}

#[test]
fn repair_phase_two_requires_fixed_root_high_water() {
    let journal = key(0x35);
    let mut cells = absent_addressed();
    cells[0].state = AddressedState::Present(Box::new(ack_value(
        7,
        2,
        None,
        AddressedMirror::NotApplicable,
        head(9, 0x39),
    )));
    require_wire(
        &journal,
        &addressed_image(&journal, hold_authority(7, 900), cells.clone()),
    );
    refuse_image(
        &journal,
        &addressed_image(&journal, hold_authority(7, 899), cells),
    );
}

#[test]
fn repair_rejects_unreachable_pending_phase_and_heads() {
    let mut value = ack_value(7, 3, Some(850), ack_pending_mirror(), head(9, 0x39));
    assert_eq!(
        validate_addressed_value(AddressedOperation::ClockAcknowledge, &value),
        Err(INVALID)
    );
    value.phase = 2;
    value.safe_result = AddressedResult::Acknowledge {
        settled_safe_time: 900,
        settled: false,
    };
    assert!(validate_addressed_value(AddressedOperation::ClockAcknowledge, &value).is_ok());
    value.application_head = head(8, 0x38);
    assert_eq!(
        validate_addressed_value(AddressedOperation::ClockAcknowledge, &value),
        Err(INVALID)
    );
}

#[test]
fn repair_pending_request_requires_selected_state() {
    let journal = key(0x35);
    let base = addressed_image(&journal, hold_authority(7, 800), absent_addressed());
    refuse_append(
        &journal,
        &base,
        AddressedOperation::ClockAcknowledge,
        ack_request_action(7, true),
    );
}

#[test]
fn repair_fold_recomputes_addressed_action_digest() {
    let journal = key(0x35);
    for operation in [
        AddressedOperation::ClockAcknowledge,
        AddressedOperation::SystemShutdown,
    ] {
        let base = addressed_image(&journal, hold_authority(7, 800), absent_addressed());
        let action = match operation {
            AddressedOperation::ClockAcknowledge => ack_request_action(7, false),
            AddressedOperation::SystemShutdown => shutdown_request_action(0x70, false),
        };
        let mut next = require_append(&journal, &base, operation, action);
        let action = match &mut next.tail[0].record {
            TailRecord::ClockAcknowledge(action) | TailRecord::SystemShutdown(action) => action,
            _ => panic!("addressed frame"),
        };
        let AddressedAction::PublishRequest(request) = action else {
            panic!("request")
        };
        request.actor = AddressedActor::Principal(b"another-authorized-actor".to_vec());
        assert_eq!(
            fold_control_journal_image(&next, FoldTrigger::TailFrameLimit),
            Err(INVALID),
            "{operation:?}"
        );
    }
}

fn request_from(action: AddressedAction) -> Box<AddressedStateValue> {
    let AddressedAction::PublishRequest(request) = action else {
        panic!("request action")
    };
    request
}

#[test]
fn repair_shutdown_authority_retry_and_recovery_are_separate_from_result_bytes() {
    let journal = key(0x35);
    let operation = AddressedOperation::SystemShutdown;
    let base = addressed_image(&journal, hold_authority(7, 800), absent_addressed());
    for process in [0, 0x60, 0x80] {
        refuse_append(
            &journal,
            &base,
            operation,
            shutdown_request_action(process, false),
        );
    }
    assert_eq!(
        append_addressed_action(
            &journal,
            &base,
            operation,
            shutdown_request_action(0x70, false),
            [0; 16],
            false
        ),
        Err(INVALID)
    );
    let accepted = require_append(
        &journal,
        &base,
        operation,
        shutdown_request_action(0x70, false),
    );
    let mut retry = request_from(shutdown_request_action(0x70, false));
    retry.actor = AddressedActor::Principal(b"another-authorized-actor".to_vec());
    retry.evidence = AddressedEvidence::Shutdown {
        accepted_monotonic_tick: 20,
        grace_deadline_tick: 270,
    };
    refuse_append(
        &journal,
        &accepted,
        operation,
        AddressedAction::PublishRequest(retry.clone()),
    );
    retry.desired_transition = DesiredMonotonicTransition::StopProcess { grace_ms: 251 };
    retry.evidence = AddressedEvidence::Shutdown {
        accepted_monotonic_tick: 20,
        grace_deadline_tick: 271,
    };
    refuse_append(
        &journal,
        &accepted,
        operation,
        AddressedAction::PublishRequest(retry),
    );
    for process in [0x70, 0x80] {
        assert_eq!(
            append_addressed_action(
                &journal,
                &accepted,
                operation,
                shutdown_phase_action(4, 1),
                [process; 16],
                false
            ),
            Err(INVALID)
        );
    }
    assert_eq!(
        addressed_completion(
            &accepted,
            operation,
            AddressedOperationAddress::ProcessInstance([0x70; 16]),
            [0x80; 16]
        ),
        Ok(None)
    );
    assert_eq!(
        append_addressed_action(
            &journal,
            &accepted,
            operation,
            shutdown_request_action(0x80, false),
            [0x80; 16],
            false
        ),
        Err(INVALID)
    );
    let cleared = append_addressed_action(
        &journal,
        &accepted,
        operation,
        shutdown_phase_action(4, 1),
        [0x80; 16],
        true,
    )
    .expect("honest recovery");
    let checkpoint = require_projection(&journal, &cleared);
    assert_eq!(checkpoint.addressed[2].state, AddressedState::Absent);
    assert_eq!(checkpoint.addressed[3].state, AddressedState::Absent);
    assert_eq!(checkpoint.clock_authority, base.checkpoint.clock_authority);
    let new = append_addressed_action(
        &journal,
        &cleared,
        operation,
        shutdown_request_action(0x80, false),
        [0x80; 16],
        false,
    )
    .expect("new process after recovery");
    assert_eq!(
        present_value(&require_projection(&journal, &new).addressed[2].state).address,
        AddressedOperationAddress::ProcessInstance([0x80; 16])
    );
    let stopping = require_append(&journal, &accepted, operation, shutdown_phase_action(2, 0));
    let completed = require_append(&journal, &stopping, operation, shutdown_phase_action(3, 0));
    let folded = require_fold(&completed, FoldTrigger::TailByteLimit);
    assert_eq!(
        addressed_completion(
            &folded,
            operation,
            AddressedOperationAddress::ProcessInstance([0x70; 16]),
            [0x70; 16]
        ),
        Ok(Some(AddressedResult::Shutdown {
            ungraceful_reason: 0
        }))
    );
    assert_eq!(
        addressed_completion(
            &folded,
            operation,
            AddressedOperationAddress::ProcessInstance([0x70; 16]),
            [0x80; 16]
        ),
        Ok(None)
    );
    refuse_append(
        &journal,
        &completed,
        operation,
        shutdown_request_action(0x70, false),
    );
}

#[test]
fn repair_recovered_shutdown_keeps_pending_mirror_until_receipt_then_drops() {
    let journal = key(0x35);
    let operation = AddressedOperation::SystemShutdown;
    let base = selected_image(addressed_image(
        &journal,
        hold_authority(7, 800),
        absent_addressed(),
    ));
    let accepted = require_append(
        &journal,
        &base,
        operation,
        shutdown_request_action(0x70, true),
    );
    let authority = ([0x80; 16], true);
    for reason in 1..=4 {
        assert_eq!(
            append_addressed_action_with_authority(
                &journal,
                &accepted,
                operation,
                shutdown_phase_action(4, reason),
                normal_authority(),
            ),
            Err(INVALID),
            "normal execution cannot authorize the recovery edge by reason"
        );
        let recovered = append_addressed_action_with_authority(
            &journal,
            &accepted,
            operation,
            shutdown_phase_action(4, reason),
            authority,
        )
        .expect("recovery context authorizes each closed honest reason");
        assert_eq!(
            present_value(&require_projection(&journal, &recovered).addressed[2].state).safe_result,
            AddressedResult::Shutdown {
                ungraceful_reason: reason
            }
        );
    }
    let terminal = append_addressed_action_with_authority(
        &journal,
        &accepted,
        operation,
        shutdown_phase_action(4, 1),
        authority,
    )
    .expect("recovery terminal pending mirror");
    let terminal = require_fold(&terminal, FoldTrigger::TailFrameLimit);
    let value = present_value(&terminal.checkpoint.addressed[2].state);
    assert_eq!(value.phase, 4);
    assert_eq!(
        value.safe_result,
        AddressedResult::Shutdown {
            ungraceful_reason: 1
        }
    );
    assert_eq!(value.mirror, shutdown_pending_mirror());
    assert_eq!(
        addressed_completion(
            &terminal,
            operation,
            AddressedOperationAddress::ProcessInstance([0x70; 16]),
            [0x80; 16]
        ),
        Ok(None)
    );
    assert_eq!(
        append_addressed_action(
            &journal,
            &terminal,
            operation,
            shutdown_request_action(0x80, true),
            [0x80; 16],
            false
        ),
        Err(INVALID)
    );
    let complete = append_addressed_action_with_authority(
        &journal,
        &terminal,
        operation,
        commit_action(40),
        authority,
    )
    .expect("existing recovery mirror barrier");
    let projection = require_projection(&journal, &complete);
    assert_eq!(projection.addressed[2].state, AddressedState::Absent);
    assert_eq!(projection.addressed[3].state, AddressedState::Absent);
    assert_eq!(projection.clock_authority, base.checkpoint.clock_authority);
    let root = IsolatedOwnerRoot::create();
    require_publish(&journal, &root, &complete_genesis(&journal));
    require_publish(&journal, &root, &terminal);
    assert_eq!(
        reopen_control_journal_image(&journal, &root.path).expect("pending obligation"),
        terminal
    );
    require_publish(&journal, &root, &complete);
    assert_eq!(
        reopen_control_journal_image(&journal, &root.path).expect("resolved obligation"),
        complete
    );
}

#[test]
fn repair_selected_applicability_is_checked_at_request_not_on_historical_cells() {
    let journal = key(0x35);
    let base = addressed_image(&journal, hold_authority(7, 800), absent_addressed());
    for operation in [
        AddressedOperation::ClockAcknowledge,
        AddressedOperation::SystemShutdown,
    ] {
        let action = |pending| match operation {
            AddressedOperation::ClockAcknowledge => ack_request_action(7, pending),
            AddressedOperation::SystemShutdown => shutdown_request_action(0x70, pending),
        };
        refuse_append(&journal, &base, operation, action(true));
        let selected = selected_image(base.clone());
        refuse_append(&journal, &selected, operation, action(false));
        let mut wrong = request_from(action(true));
        let AddressedMirror::Pending { origin, .. } = &mut wrong.mirror else {
            panic!("pending")
        };
        origin[31] = 2;
        refuse_append(
            &journal,
            &selected,
            operation,
            AddressedAction::PublishRequest(wrong),
        );
        let installed = require_append(&journal, &selected, operation, action(true));
        let mut historical = require_fold(&installed, FoldTrigger::TailFrameLimit);
        historical.checkpoint.active_pointer = None;
        let wire = require_wire(&journal, &historical);
        assert_eq!(
            decode_control_journal_image(&journal, &wire),
            Ok(historical.clone()),
            "old mirror facts survive selection changes"
        );
        assert_eq!(
            historical.checkpoint.addressed[operation.slot()],
            require_projection(&journal, &installed).addressed[operation.slot()]
        );
    }
    let mut stale_evidence = request_from(ack_request_action(7, false));
    let AddressedEvidence::Acknowledge {
        prior_fixed_safe_time,
        ..
    } = &mut stale_evidence.evidence
    else {
        panic!("ack evidence")
    };
    *prior_fixed_safe_time = 799;
    refuse_append(
        &journal,
        &base,
        AddressedOperation::ClockAcknowledge,
        AddressedAction::PublishRequest(stale_evidence),
    );
}

#[test]
fn repair_ack_retry_authority_and_policy_two_pending_derivation() {
    let journal = key(0x35);
    let operation = AddressedOperation::ClockAcknowledge;
    let base = selected_image(addressed_image(
        &journal,
        hold_authority(7, 800),
        absent_addressed(),
    ));
    let mut request = request_from(ack_request_action(7, true));
    let AddressedMirror::Pending { policy, .. } = &mut request.mirror else {
        panic!("pending")
    };
    *policy = 2;
    let accepted = require_append(
        &journal,
        &base,
        operation,
        AddressedAction::PublishRequest(request),
    );
    let progress = require_append(&journal, &accepted, operation, ack_phase_action(2));
    let complete = require_append(&journal, &progress, operation, commit_action(40));
    let projection = require_projection(&journal, &complete);
    assert!(matches!(
        present_value(&projection.addressed[1].state).mirror,
        AddressedMirror::Committed { policy: 2, .. }
    ));
    assert_eq!(
        addressed_completion(&complete, operation, ack_address(7), [0x70; 16]),
        Ok(Some(AddressedResult::Acknowledge {
            settled_safe_time: 900,
            settled: true
        }))
    );
    for generation in [6, 8] {
        assert_eq!(
            addressed_completion(&complete, operation, ack_address(generation), [0x70; 16]),
            Ok(None)
        );
    }
    let newer = enter_clock_hold(
        &complete,
        ClockHold {
            generation: 8,
            observation_digest: [0x71; 32],
        },
    )
    .expect("new hold");
    assert_eq!(
        addressed_completion(&newer, operation, ack_address(7), [0x70; 16]),
        Ok(None)
    );
    let cleared = require_clock_append(&journal, &newer, automatic_settlement(8, 900, 950));
    let folded = require_fold(&cleared, FoldTrigger::TailFrameLimit);
    assert_eq!(
        addressed_completion(&folded, operation, ack_address(7), [0x70; 16]),
        Ok(None)
    );
}

// Seal malformed semantic bodies with valid envelope and image authentication,
// so rejection cannot be attributed to an earlier framing/MAC failure.
fn authenticated_action_wire(
    journal: &JournalIntegrityKey,
    image: &CompleteControlJournalImage,
    operation: AddressedOperation,
    body: &[u8],
) -> Vec<u8> {
    assert!(image.tail.is_empty());
    let header = encode_image_header(journal, image.header).expect("header");
    let binding = region_digest(&header);
    let payload = require_checkpoint_payload(journal, image);
    let checkpoint = seal_region(
        journal,
        ImageRegion::Checkpoint,
        CHECKPOINT_MEMBERS,
        binding,
        None,
        &payload,
    )
    .expect("checkpoint");
    let frame = journal
        .encode_control_journal_record(
            operation.kind(),
            body,
            component_head(image.checkpoint.covered_head),
        )
        .expect("authenticated action");
    let tail = seal_region(
        journal,
        ImageRegion::Tail,
        1,
        binding,
        Some(region_digest(&checkpoint)),
        &frame,
    )
    .expect("tail");
    [header.as_slice(), checkpoint.as_slice(), tail.as_slice()].concat()
}

#[test]
fn repair_canonical_action_decoder_negatives_reach_the_intended_fields() {
    let journal = key(0x35);
    let base = addressed_image(&journal, hold_authority(7, 800), absent_addressed());
    for operation in [
        AddressedOperation::ClockAcknowledge,
        AddressedOperation::SystemShutdown,
    ] {
        let action = match operation {
            AddressedOperation::ClockAcknowledge => ack_request_action(7, false),
            AddressedOperation::SystemShutdown => shutdown_request_action(0x70, false),
        };
        let valid = encode_addressed_action(operation, &action).expect("canonical action");
        assert_eq!(
            decode_addressed_action(operation, &valid),
            Ok(action.clone())
        );
        assert!(
            decode_control_journal_image(
                &journal,
                &authenticated_action_wire(&journal, &base, operation, &valid)
            )
            .is_ok()
        );
        let mut negatives = vec![action_bytes(4, &valid[4..])];
        for offset in [7usize, 8] {
            // populated payload actor kind and actor length
            let mut bad = valid.clone();
            bad[offset] = 0;
            negatives.push(bad);
        }
        for cut in 0..valid.len() {
            negatives.push(valid[..cut].to_vec());
        }
        let mut bad = valid.clone();
        bad.push(0);
        negatives.push(bad);
        negatives.push(action_bytes(1, &[&valid[4..], &[0]].concat()));
        let phase = match operation {
            AddressedOperation::ClockAcknowledge => ack_phase_action(2),
            AddressedOperation::SystemShutdown => shutdown_phase_action(2, 0),
        };
        let phase_wire = encode_addressed_action(operation, &phase).expect("phase framing control");
        assert_eq!(decode_addressed_action(operation, &phase_wire), Ok(phase));
        let mut bad = phase_wire.clone();
        bad[4] = 5;
        negatives.push(bad);
        for offset in [6usize, 8, 10] {
            // result codec, version, length low bytes
            let mut bad = phase_wire.clone();
            bad[offset] ^= 0x10;
            negatives.push(bad);
        }
        let mut bad = phase_wire.clone();
        *bad.last_mut().expect("result byte") = 2;
        negatives.push(bad);
        negatives.push(action_bytes(2, &phase_wire[4..phase_wire.len() - 1]));
        negatives.push(action_bytes(2, &[&phase_wire[4..], &[0]].concat()));
        let mirror_wire =
            encode_addressed_action(operation, &commit_action(40)).expect("mirror control");
        assert_eq!(
            decode_addressed_action(operation, &mirror_wire),
            Ok(commit_action(40))
        );
        negatives.push(action_bytes(3, &[0; 40]));
        negatives.push(action_bytes(3, &mirror_wire[4..43]));
        negatives.push(action_bytes(3, &[&mirror_wire[4..], &[0]].concat()));
        let phase_base = require_append(&journal, &base, operation, action.clone());
        let phase_base = require_fold(&phase_base, FoldTrigger::TailFrameLimit);
        let selected = selected_image(base.clone());
        let pending_request = match operation {
            AddressedOperation::ClockAcknowledge => ack_request_action(7, true),
            AddressedOperation::SystemShutdown => shutdown_request_action(0x70, true),
        };
        let mirror_base = require_append(&journal, &selected, operation, pending_request);
        let mut mirror_base = require_append(
            &journal,
            &mirror_base,
            operation,
            match operation {
                AddressedOperation::ClockAcknowledge => ack_phase_action(2),
                AddressedOperation::SystemShutdown => shutdown_phase_action(2, 0),
            },
        );
        if operation == AddressedOperation::SystemShutdown {
            mirror_base = require_append(
                &journal,
                &mirror_base,
                operation,
                shutdown_phase_action(3, 0),
            );
        }
        let mirror_base = require_fold(&mirror_base, FoldTrigger::TailFrameLimit);
        for (control, fixture) in [(&phase_wire, &phase_base), (&mirror_wire, &mirror_base)] {
            assert!(
                decode_control_journal_image(
                    &journal,
                    &authenticated_action_wire(&journal, fixture, operation, control)
                )
                .is_ok()
            );
        }
        for body in &negatives {
            // Give semantic negatives legal pre-state controls, so rejection
            // cannot be attributed to a missing current obligation.
            let fixture = match body.get(1) {
                Some(2) => &phase_base,
                Some(3) => &mirror_base,
                _ => &base,
            };
            assert_invalid(
                &journal,
                &authenticated_action_wire(&journal, fixture, operation, body),
            );
        }
    }
}

fn replace_checkpoint_member(payload: &[u8], tag: u16, replacement: &[u8]) -> Vec<u8> {
    let mut reader = ImageReader::new(payload);
    let mut output = Vec::new();
    for current in 1..=CHECKPOINT_MEMBERS {
        let body = reader.member(current).expect("ordered member");
        output.extend_from_slice(&member_bytes(
            current,
            if current == tag { replacement } else { body },
        ));
    }
    output
}

fn authenticated_checkpoint_wire(
    journal: &JournalIntegrityKey,
    image: &CompleteControlJournalImage,
    payload: &[u8],
) -> Vec<u8> {
    let header = encode_image_header(journal, image.header).expect("header");
    let binding = region_digest(&header);
    let checkpoint = seal_region(
        journal,
        ImageRegion::Checkpoint,
        CHECKPOINT_MEMBERS,
        binding,
        None,
        payload,
    )
    .expect("checkpoint");
    let tail = seal_region(
        journal,
        ImageRegion::Tail,
        0,
        binding,
        Some(region_digest(&checkpoint)),
        &[],
    )
    .expect("tail");
    [header.as_slice(), checkpoint.as_slice(), tail.as_slice()].concat()
}

#[test]
fn repair_checkpoint_decoder_rejects_unreachable_states_after_authentication() {
    let journal = key(0x35);
    let image = populated_ack_shutdown_image(&journal);
    let payload = require_checkpoint_payload(&journal, &image);
    assert_eq!(
        decode_control_journal_image(
            &journal,
            &authenticated_checkpoint_wire(&journal, &image, &payload)
        ),
        Ok(image.clone())
    );
    // Each mutation starts with a valid member and changes only the named
    // invariant. Result bytes stay consistent when phase changes.
    for (operation, tag) in [
        (AddressedOperation::ClockAcknowledge, 7),
        (AddressedOperation::SystemShutdown, 9),
    ] {
        let value = present_value(&image.checkpoint.addressed[operation.slot()].state);
        let body = encode_addressed_cell(operation, value).expect("cell control");
        let prefix_len = body.len() - 80 - 74; // heads then pending mirror
        let mut bad = body.clone();
        bad[prefix_len..prefix_len + 40]
            .copy_from_slice(&[8_u64.to_be_bytes().as_slice(), &[0x38; 32]].concat());
        let malformed = replace_checkpoint_member(&payload, tag, &bad);
        assert_invalid(
            &journal,
            &authenticated_checkpoint_wire(&journal, &image, &malformed),
        );
        if operation == AddressedOperation::ClockAcknowledge {
            let mut bad = body.clone();
            bad[prefix_len - 16] = 3;
            bad[prefix_len - 1] = 1;
            let malformed = replace_checkpoint_member(&payload, tag, &bad);
            assert_invalid(
                &journal,
                &authenticated_checkpoint_wire(&journal, &image, &malformed),
            );
        }
    }
    let image = populated_ack_shutdown_last_image(&journal);
    let payload = require_checkpoint_payload(&journal, &image);
    let value = present_value(&image.checkpoint.addressed[3].state);
    let mut body = encode_addressed_cell(AddressedOperation::SystemShutdown, value)
        .expect("committed shutdown");
    let prefix_len = body.len() - 80 - 114;
    body.copy_within(prefix_len + 40..prefix_len + 80, prefix_len);
    assert_invalid(
        &journal,
        &authenticated_checkpoint_wire(
            &journal,
            &image,
            &replace_checkpoint_member(&payload, 10, &body),
        ),
    );
    let mut authority = image.checkpoint.clock_authority;
    authority.safe_time = 899;
    let clock_body = clock_authority_projection::encode_clock_authority_projection(authority)
        .expect("valid clock body");
    assert_invalid(
        &journal,
        &authenticated_checkpoint_wire(
            &journal,
            &image,
            &replace_checkpoint_member(&payload, 3, &clock_body),
        ),
    );
}

#[test]
fn repair_completion_retention_uses_exact_prepublication_authority_for_both_mirrors() {
    let journal = key(0x35);
    let operation = AddressedOperation::ClockAcknowledge;
    for pending in [false, true] {
        for authority_generation in [None, Some(7), Some(8)] {
            let mut cells = absent_addressed();
            cells[0].state = AddressedState::Present(Box::new(ack_value(
                7,
                2,
                pending.then_some(850),
                if pending {
                    ack_pending_mirror()
                } else {
                    AddressedMirror::NotApplicable
                },
                head(9, 0x39),
            )));
            let mut authority = hold_authority(authority_generation.unwrap_or(7), 950);
            if authority_generation.is_none() {
                authority.hold = None;
            }
            let base = addressed_image(&journal, authority, cells);
            let next = require_append(
                &journal,
                &base,
                operation,
                if pending {
                    commit_action(40)
                } else {
                    ack_phase_action(3)
                },
            );
            let projection = require_projection(&journal, &next);
            assert_eq!(projection.clock_authority.safe_time, 950);
            assert_eq!(projection.addressed[0].state, AddressedState::Absent);
            assert_eq!(
                matches!(projection.addressed[1].state, AddressedState::Present(_)),
                authority_generation == Some(7)
            );
            assert_eq!(
                projection.clock_authority.hold,
                if authority_generation == Some(8) {
                    authority.hold
                } else {
                    None
                }
            );
            let folded = require_fold(&next, FoldTrigger::TailFrameLimit);
            assert_eq!(folded.checkpoint.addressed, projection.addressed);
            let wire = require_wire(&journal, &folded);
            assert_eq!(decode_control_journal_image(&journal, &wire), Ok(folded));
        }
    }
}

#[test]
fn repair_automatic_clear_crash_prefix_preserves_hold_and_obligation() {
    let journal = key(0x35);
    let base = addressed_image(&journal, hold_authority(7, 800), absent_addressed());
    let accepted = require_append(
        &journal,
        &base,
        AddressedOperation::ClockAcknowledge,
        ack_request_action(7, false),
    );
    // Phase 1 cannot skip phase 2 through automatic settlement.
    assert_eq!(
        append_clock_checkpoint(&journal, &accepted, automatic_settlement(7, 800, 899)),
        Err(INVALID)
    );
    assert_eq!(
        append_clock_checkpoint(&journal, &accepted, automatic_settlement(7, 800, 950)),
        Err(INVALID)
    );
    let accepted = require_append(
        &journal,
        &accepted,
        AddressedOperation::ClockAcknowledge,
        ack_phase_action(2),
    );
    let completed = require_clock_append(&journal, &accepted, automatic_settlement(7, 900, 950));
    let root = IsolatedOwnerRoot::create();
    require_publish(&journal, &root, &complete_genesis(&journal));
    require_publish(&journal, &root, &accepted);
    for fault in [
        PublicationFault::UniqueTemporaryCreate,
        PublicationFault::TemporaryWrite,
        PublicationFault::FileSync,
        PublicationFault::ReplacementRename,
    ] {
        assert!(
            publish_control_journal_image_with_fault(&journal, &root.path, &completed, fault)
                .is_err()
        );
        assert_eq!(
            reopen_control_journal_image(&journal, &root.path).expect("old current and hold"),
            accepted
        );
    }
    require_publish(&journal, &root, &completed);
    let reopened =
        reopen_control_journal_image(&journal, &root.path).expect("completed publication");
    let projection = require_projection(&journal, &reopened);
    assert_eq!(projection.clock_authority.hold, None);
    assert_eq!(projection.addressed[0].state, AddressedState::Absent);
    assert_eq!(present_value(&projection.addressed[1].state).phase, 3);
}

fn retained_mirror_image(
    journal: &JournalIntegrityKey,
    slot: usize,
) -> CompleteControlJournalImage {
    let mut cells = absent_addressed();
    let value = match slot {
        0 => ack_value(7, 2, Some(850), ack_pending_mirror(), head(6, 0x36)),
        1 => ack_value(7, 3, Some(850), ack_committed_mirror(), head(6, 0x36)),
        2 => shutdown_value(0x70, 2, shutdown_pending_mirror(), head(8, 0x38)),
        3 => shutdown_value(0x60, 3, shutdown_committed_mirror(), head(8, 0x38)),
        _ => panic!("addressed slot"),
    };
    cells[slot].state = AddressedState::Present(Box::new(value));
    addressed_image(journal, hold_authority(7, 900), cells)
}

fn refuse_retained_cell_mutation(
    journal: &JournalIntegrityKey,
    valid: &CompleteControlJournalImage,
    invalid: &CompleteControlJournalImage,
    slot: usize,
) {
    // Seal individually valid cell bytes without invoking whole-image checks.
    let cell = &invalid.checkpoint.addressed[slot];
    let body = encode_addressed_cell(cell.operation, present_value(&cell.state))
        .expect("locally canonical cell");
    let payload = replace_checkpoint_member(
        &require_checkpoint_payload(journal, valid),
        7 + slot as u16,
        &body,
    );
    let wire = authenticated_checkpoint_wire(journal, invalid, &payload);
    assert_eq!(
        (
            encode_control_journal_image(journal, invalid).err(),
            decode_control_journal_image(journal, &wire).err(),
        ),
        (Some(INVALID), Some(INVALID)),
        "both image construction and authenticated decoding must reject slot {slot}"
    );
}

#[test]
fn rereview_retained_mirror_origins_require_local_namespace_and_high_water() {
    let journal = key(0x35);
    for slot in 0..4 {
        for high_water in [1, 2] {
            let mut valid = retained_mirror_image(&journal, slot);
            valid.header.branch_serial_high_water = high_water;
            assert_eq!(
                decode_control_journal_image(&journal, &require_wire(&journal, &valid)),
                Ok(valid.clone()),
                "retained origin may equal or precede high-water without a selected pointer"
            );
            for foreign in [true, false] {
                let mut invalid = valid.clone();
                let AddressedState::Present(value) = &mut invalid.checkpoint.addressed[slot].state
                else {
                    panic!("retained cell")
                };
                let (AddressedMirror::Pending { origin, .. }
                | AddressedMirror::Committed { origin, .. }) = &mut value.mirror
                else {
                    panic!("retained mirror")
                };
                if foreign {
                    origin[..24]
                        .copy_from_slice(&complete_genesis(&key(0x36)).header.owner_namespace);
                } else {
                    origin[24..].copy_from_slice(&(high_water + 1).to_be_bytes());
                }
                refuse_retained_cell_mutation(&journal, &valid, &invalid, slot);
            }
            let mut invalid = valid.clone();
            invalid.header.branch_serial_high_water = 0;
            refuse_retained_cell_mutation(&journal, &valid, &invalid, slot);
        }
    }
}

#[test]
fn rereview_cross_operation_histories_require_distinct_fixed_root_heads() {
    let journal = key(0x35);
    for ack_slot in 0..2 {
        for shutdown_slot in 2..4 {
            let mut valid = retained_mirror_image(&journal, ack_slot);
            valid.checkpoint.addressed[shutdown_slot] =
                retained_mirror_image(&journal, shutdown_slot)
                    .checkpoint
                    .addressed[shutdown_slot]
                    .clone();
            assert_eq!(
                decode_control_journal_image(&journal, &require_wire(&journal, &valid)),
                Ok(valid.clone()),
                "distinct phase and receipt heads are legal in current and last slots"
            );
            let shutdown = present_value(&valid.checkpoint.addressed[shutdown_slot].state);
            for reused in [shutdown.application_head, shutdown.publication_head] {
                for changed_digest in [false, true] {
                    let mut invalid = valid.clone();
                    let AddressedState::Present(ack) =
                        &mut invalid.checkpoint.addressed[ack_slot].state
                    else {
                        panic!("acknowledge cell")
                    };
                    let mut reused = reused;
                    if changed_digest {
                        reused.digest = [0xAB; 32];
                    }
                    ack.application_head = reused;
                    ack.publication_head = reused;
                    refuse_retained_cell_mutation(&journal, &valid, &invalid, ack_slot);
                }
            }
        }
    }
}

// Thin signature adapters call the accepted implementation; they contain no validation or replay logic.
fn append_addressed_action_with_authority(
    key: &JournalIntegrityKey,
    image: &CompleteControlJournalImage,
    operation: AddressedOperation,
    action: AddressedAction,
    authority: ([u8; 16], bool),
) -> Result<CompleteControlJournalImage, ControlJournalImageError> {
    append_addressed_action(key, image, operation, action, authority.0, authority.1)
}
fn encode_addressed_cell(
    operation: AddressedOperation,
    value: &AddressedStateValue,
) -> Result<Vec<u8>, ControlJournalImageError> {
    encode_addressed_value(operation, value, true)
}
fn decode_addressed_cell(
    operation: AddressedOperation,
    body: &[u8],
) -> Result<AddressedStateValue, ControlJournalImageError> {
    decode_addressed_value(operation, body, None)
}
fn decode_addressed_action(
    operation: AddressedOperation,
    body: &[u8],
) -> Result<AddressedAction, ControlJournalImageError> {
    super::decode_addressed_action(operation, body, head(1, 1))
}
fn enter_clock_hold(
    image: &CompleteControlJournalImage,
    hold: ClockHold,
) -> Result<CompleteControlJournalImage, ControlJournalImageError> {
    let mut clock = replay_tail(image)?.clock_authority;
    clock.hold = Some(hold);
    publish_addressed_authority(&key(0x35), image, clock, [0x70; 16])
}
