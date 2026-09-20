//! Frozen Task 0073 complete control-journal image RED.

use super::super::JournalIntegrityKey;
use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroizing;

static ROOT_SERIAL: AtomicUsize = AtomicUsize::new(0);

struct IsolatedOwnerRoot {
    path: PathBuf,
}

impl IsolatedOwnerRoot {
    fn create() -> Self {
        let path = std::env::temp_dir().join(format!(
            "msgriver-control-journal-image-red-{}-{}",
            std::process::id(),
            ROOT_SERIAL.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).expect("create isolated owner root");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("set owner-only root mode");
        Self { path }
    }
}

impl Drop for IsolatedOwnerRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn head(sequence: u64, byte: u8) -> JournalHead {
    JournalHead {
        sequence,
        digest: [byte; 32],
    }
}

fn key(byte: u8) -> JournalIntegrityKey {
    JournalIntegrityKey(Zeroizing::new([byte; 32]))
}

fn clock() -> ClockAuthority {
    ClockAuthority {
        safe_time: 0,
        hold: None,
        last_shutdown_observation: None,
    }
}

fn absent_cell(operation: AddressedOperation, current: bool) -> AddressedCell {
    AddressedCell {
        operation,
        current,
        state: AddressedState::Absent,
    }
}

fn complete_genesis(key: &JournalIntegrityKey) -> CompleteControlJournalImage {
    CompleteControlJournalImage {
        header: AuthenticatedControlJournalHeader {
            owner_namespace: match key.derive_resource_incarnation_namespace_v1() {
                Ok(namespace) => namespace.0,
                Err(_) => panic!("derived namespace"),
            },
            branch_serial_high_water: 0,
        },
        checkpoint: CompleteCheckpoint {
            generation: 1,
            covered_head: head(0, 0),
            clock_authority: clock(),
            active_pointer: None,
            recovery_ring: vec![],
            local_commands: vec![],
            addressed: [
                absent_cell(AddressedOperation::ClockAcknowledge, true),
                absent_cell(AddressedOperation::ClockAcknowledge, false),
                absent_cell(AddressedOperation::SystemShutdown, true),
                absent_cell(AddressedOperation::SystemShutdown, false),
            ],
            provenance: vec![],
            coordinator: None,
            open_upgrade: None,
        },
        tail: vec![],
    }
}

fn require_wire(key: &JournalIntegrityKey, image: &CompleteControlJournalImage) -> Vec<u8> {
    match encode_control_journal_image(key, image) {
        Ok(wire) => wire,
        Err(ControlJournalImageError::MissingControlJournalImage) => {
            panic!("MissingControlJournalImage: control_journal_image")
        }
        Err(error) => panic!("unexpected image encoding error: {error:?}"),
    }
}

fn require_publish(
    key: &JournalIntegrityKey,
    root: &IsolatedOwnerRoot,
    image: &CompleteControlJournalImage,
) {
    match publish_control_journal_image(key, &root.path, image) {
        Ok(()) => {}
        Err(ControlJournalImageError::MissingControlJournalImage) => {
            panic!("MissingControlJournalImage: control_journal_image")
        }
        Err(error) => panic!("unexpected complete image publication error: {error:?}"),
    }
}

fn require_fold(
    image: &CompleteControlJournalImage,
    trigger: FoldTrigger,
) -> CompleteControlJournalImage {
    match fold_control_journal_image(image, trigger) {
        Ok(folded) => folded,
        Err(ControlJournalImageError::MissingControlJournalImage) => {
            panic!("MissingControlJournalImage: control_journal_image")
        }
        Err(error) => panic!("unexpected complete image fold error: {error:?}"),
    }
}

fn assert_invalid(key: &JournalIntegrityKey, wire: &[u8]) {
    assert!(matches!(
        decode_control_journal_image(key, wire),
        Err(ControlJournalImageError::InvalidControlJournalImage)
    ));
}

fn require_mutation(key: &JournalIntegrityKey, wire: &[u8], mutation: ImageMutation) -> Vec<u8> {
    match mutate_control_journal_image(key, wire, mutation) {
        Ok(mutated) => mutated,
        Err(ControlJournalImageError::MissingControlJournalImage) => {
            panic!("MissingControlJournalImage: control_journal_image")
        }
        Err(error) => panic!("unexpected image mutation error: {error:?}"),
    }
}

fn chained_tail(last_sequence: u64) -> Vec<AuthenticatedTailFrame> {
    let mut prior = head(0, 0);
    let mut tail = Vec::with_capacity(last_sequence as usize);
    for sequence in 1..=last_sequence {
        let body = clock_checkpoint_body::ClockCheckpointBody {
            runtime_mode: clock_checkpoint_body::RuntimeMode::Maintenance,
            process_instance: [0x75; 16],
            accepted_wall_time: 0,
            accepted_monotonic_tick: sequence as i64,
            prior_safe_time: 0,
            new_safe_time: 0,
            reason: clock_checkpoint_body::CheckpointReason::Periodic,
            hold: None,
            pre_mirror: None,
        };
        let bytes = clock_checkpoint_body::encode_clock_checkpoint_body(body)
            .expect("complete canonical checkpoint body");
        let computed = JournalIntegrityKey::control_journal_clock_checkpoint_head(
            &bytes,
            control_journal_record::JournalHead {
                sequence: prior.sequence,
                record_digest: prior.digest,
            },
        )
        .expect("computed canonical record head");
        let resulting_head = JournalHead {
            sequence: computed.sequence,
            digest: computed.record_digest,
        };
        tail.push(AuthenticatedTailFrame {
            prior_head: prior,
            resulting_head,
            record: TailRecord::ClockCheckpointEvent(body),
        });
        prior = resulting_head;
    }
    tail
}

fn command_tag(purpose: msgriver_core::canon::MacPurpose, byte: u8) -> CommandTag {
    use msgriver_core::canon::{MacKeyId, MacKeyRef};
    let mut key_id = [0x72; 40];
    key_id[24..32].copy_from_slice(&1_u64.to_be_bytes());
    key_id[32..].copy_from_slice(&1_u64.to_be_bytes());
    CommandTag {
        key: MacKeyRef::new(purpose, MacKeyId::from_bytes(key_id)),
        tag: [byte; 32],
    }
}

fn live_command() -> FixedRootCommandProjection {
    FixedRootCommandProjection {
        operation: FixedRootOperation::RecoveryKeyGenerate,
        actor: StableActorNamespace::StateOwner,
        lookup: command_tag(msgriver_core::canon::MacPurpose::CommandLookupV1, 0x61),
        semantic_fingerprint: command_tag(
            msgriver_core::canon::MacPurpose::CommandSemanticFingerprintV1,
            0x62,
        ),
        phase_fingerprint: command_tag(
            msgriver_core::canon::MacPurpose::CommandPhaseFingerprintV1,
            0x63,
        ),
        portable_reservation: command_tag(
            msgriver_core::canon::MacPurpose::PortableReservationV1,
            0x73,
        ),
        runtime: CommandRuntime::Maintenance,
        process_instance: [0x75; 16],
        original_deadline: None,
        phase: 1,
        retention: CommandRetention::Continuation,
        safe_result: None,
        target_binding: None,
        profile: RecoveryKeyGenerateProfile(
            recovery_key_generate_profile::RecoveryKeyGenerateProfile {
                variant: recovery_key_generate_profile::RecoveryKeyGenerateVariant::Generate,
                issuance_digest: None,
                confirmation_digest: None,
            },
        ),
    }
}

#[test]
fn ordinary_command_entries_cannot_exceed_the_source_partition() {
    let journal = key(0x35);
    let owner_namespace = match journal.derive_resource_incarnation_namespace_v1() {
        Ok(namespace) => namespace.0,
        Err(_) => panic!("derived namespace"),
    };
    let commands = vec![live_command(); ORDINARY_COMMAND_ENTRY_LIMIT + 1];
    assert_eq!(
        encode_command_member(owner_namespace, &commands),
        Err(INVALID)
    );
}

#[test]
fn complete_genesis_publishes_and_reopens_the_same_typed_projection() {
    let journal = key(0x35);
    let root = IsolatedOwnerRoot::create();
    let image = complete_genesis(&journal);
    let wire = require_wire(&journal, &image);
    assert_eq!(
        decode_control_journal_image(&journal, &wire).expect("authenticated genesis decode"),
        image
    );
    require_publish(&journal, &root, &image);
    assert_eq!(
        reopen_control_journal_image(&journal, &root.path).expect("reopen complete genesis"),
        image
    );
    assert_invalid(&key(0x53), &wire);
}

#[test]
fn command_only_and_every_complete_image_integrity_mutation_fail_closed() {
    let journal = key(0x35);
    let first = complete_genesis(&journal);
    let wire = require_wire(&journal, &first);
    for prefix_length in [1, wire.len() / 2, wire.len() - 1] {
        assert_invalid(&journal, &wire[..prefix_length]);
    }
    let mut trailing = wire.clone();
    trailing.push(0xff);
    assert_invalid(&journal, &trailing);
    for offset in (0..wire.len()).step_by((wire.len() / 7).max(1)) {
        let mut mutated = wire.clone();
        mutated[offset] ^= 1;
        assert_invalid(&journal, &mutated);
    }
    let second = CompleteControlJournalImage {
        header: AuthenticatedControlJournalHeader {
            owner_namespace: first.header.owner_namespace,
            branch_serial_high_water: 1,
        },
        checkpoint: CompleteCheckpoint {
            generation: 2,
            covered_head: head(0, 0),
            ..first.checkpoint.clone()
        },
        tail: chained_tail(1),
    };
    let other = require_wire(&journal, &second);
    for offset in (1..wire.len().min(other.len())).step_by((wire.len() / 5).max(1)) {
        if wire[..offset] == other[..offset] || wire[offset..] == other[offset..] {
            continue;
        }
        let mut transplanted = wire[..offset].to_vec();
        transplanted.extend_from_slice(&other[offset..]);
        assert_invalid(&journal, &transplanted);
    }
    for mutation in [
        ImageMutation::ReorderedCheckpointMember,
        ImageMutation::ReorderedTailFrame,
        ImageMutation::NoncontiguousTailSequence,
        ImageMutation::CoveredHeadMismatch,
        ImageMutation::CommandOnlyArtifact,
    ] {
        assert_invalid(&journal, &require_mutation(&journal, &wire, mutation));
    }
}

#[test]
fn publication_faults_select_only_old_or_next_authenticated_images() {
    let journal = key(0x35);
    let root = IsolatedOwnerRoot::create();
    let old = complete_genesis(&journal);
    let next = CompleteControlJournalImage {
        checkpoint: CompleteCheckpoint {
            generation: 2,
            ..old.checkpoint.clone()
        },
        ..old.clone()
    };
    require_publish(&journal, &root, &old);
    for fault in [
        PublicationFault::UniqueTemporaryCreate,
        PublicationFault::TemporaryWrite,
        PublicationFault::FileSync,
        PublicationFault::ReplacementRename,
        PublicationFault::DirectorySync,
    ] {
        match publish_control_journal_image_with_fault(&journal, &root.path, &next, fault) {
            Err(ControlJournalImageError::PublishUncertain)
                if fault == PublicationFault::DirectorySync => {}
            Err(ControlJournalImageError::WriteFailed)
                if fault != PublicationFault::DirectorySync => {}
            outcome => panic!("unexpected publication fault outcome {outcome:?}"),
        }
        let selected =
            reopen_control_journal_image(&journal, &root.path).expect("reopen selected image");
        assert!(
            selected == old || selected == next,
            "no unauthenticated hybrid is selectable"
        );
    }
}

#[test]
fn fold_precedes_both_tail_limits_without_losing_hold_or_live_continuation() {
    let journal = key(0x35);
    let genesis = complete_genesis(&journal);
    let image = CompleteControlJournalImage {
        checkpoint: CompleteCheckpoint {
            generation: 2,
            local_commands: vec![live_command()],
            ..genesis.checkpoint
        },
        tail: chained_tail(128),
        ..genesis
    };
    let command_wire = require_wire(&journal, &image);
    assert_eq!(
        decode_control_journal_image(&journal, &command_wire).expect("lossless live command"),
        image
    );
    let last_tail_head = image.tail.last().expect("128-frame tail").resulting_head;
    let mut held = image.clone();
    held.tail.clear();
    held.checkpoint.clock_authority.hold = Some(ClockHold {
        generation: 7,
        observation_digest: [0x71; 32],
    });
    // A-13.2.2 forbids periodic checkpoints during hold. Keep the nonempty
    // cap proof and the held fold proof as separate legal projections.
    // The byte cap remains an injected trigger: typed clock bodies are small.
    for trigger in [FoldTrigger::TailFrameLimit, FoldTrigger::TailByteLimit] {
        for source in [&image, &held] {
            let folded = require_fold(source, trigger);
            assert!(folded.tail.is_empty());
            assert_eq!(
                folded.checkpoint.generation,
                source.checkpoint.generation + 1
            );
            assert_eq!(
                folded.checkpoint.covered_head,
                if source.tail.is_empty() {
                    source.checkpoint.covered_head
                } else {
                    last_tail_head
                }
            );
            assert_eq!(
                folded.checkpoint.clock_authority.hold,
                source.checkpoint.clock_authority.hold
            );
            assert_eq!(
                folded.checkpoint.local_commands,
                source.checkpoint.local_commands
            );
        }
    }
}

#[test]
fn selected_pointer_accepts_absent_optional_pre_mirror_and_checks_present_origin() {
    let journal = key(0x35);
    let mut image = complete_genesis(&journal);
    image.header.branch_serial_high_water = 1;
    image.checkpoint.generation = 2;
    let mut selected_origin = [0; 32];
    selected_origin[..24].copy_from_slice(&image.header.owner_namespace);
    selected_origin[31] = 1;
    image.checkpoint.active_pointer = Some(ActiveStatePointerCertificate {
        protocol_version: 1,
        transition_id: "bootstrap-1".to_owned(),
        final_generation: 1,
        lineage_id: "lineage-1".to_owned(),
        target_history_epoch: selected_origin,
        origin: active_state_pointer::PointerOrigin::Bootstrap,
        database_certificate_digest: [0x76; 32],
    });
    image.tail = chained_tail(1);
    let wire = require_wire(&journal, &image);
    assert_eq!(
        decode_control_journal_image(&journal, &wire),
        Ok(image.clone())
    );
    let TailRecord::ClockCheckpointEvent(mut body) = image.tail[0].record else {
        panic!("typed checkpoint event");
    };
    body.pre_mirror = Some(clock_checkpoint_body::PreMirrorWitness {
        selected_origin,
        transaction_sequence: 1,
        transaction_digest: [0x77; 32],
    });
    assert!(replay_clock(&mut image.checkpoint.clone(), body).is_ok());
    body.pre_mirror
        .as_mut()
        .expect("present witness")
        .selected_origin[31] = 2;
    assert_eq!(
        replay_clock(&mut image.checkpoint.clone(), body),
        Err(INVALID)
    );
    body.pre_mirror
        .as_mut()
        .expect("present witness")
        .selected_origin = selected_origin;
    image.checkpoint.active_pointer = None;
    assert_eq!(replay_clock(&mut image.checkpoint, body), Err(INVALID));
}

// Task 0078 starts here. Everything above is the exact cc14219c predecessor.
// Literal wire oracles below are test fixtures, not production codecs. They
// deliberately bypass semantic validation so authenticated negatives reach it.
const T78_PROCESS: [u8; 16] = [0x78; 16];

fn t78_require<T: std::fmt::Debug>(result: Result<T, ControlJournalImageError>) -> T {
    match result {
        Ok(value) => value,
        Err(ControlJournalImageError::UnsupportedConstruction) => {
            panic!("Task 0078 addressed projection is not implemented: UnsupportedConstruction")
        }
        Err(error) => panic!("Task 0078 unexpected failure: {error:?}"),
    }
}

fn t78_hold(generation: u64) -> ClockHold {
    ClockHold {
        generation,
        observation_digest: [generation as u8; 32],
    }
}

fn t78_base(journal: &JournalIntegrityKey, selected: bool) -> CompleteControlJournalImage {
    let mut image = complete_genesis(journal);
    image.checkpoint.generation = 2;
    image.checkpoint.covered_head = head(10, 0x10);
    image.checkpoint.clock_authority.safe_time = 20;
    image.checkpoint.clock_authority.hold = Some(t78_hold(1));
    if selected {
        image.header.branch_serial_high_water = 1;
        let mut origin = [0; 32];
        origin[..24].copy_from_slice(&image.header.owner_namespace);
        origin[31] = 1;
        image.checkpoint.active_pointer = Some(ActiveStatePointerCertificate {
            protocol_version: 1,
            transition_id: "bootstrap-1".to_owned(),
            final_generation: 1,
            lineage_id: "lineage-1".to_owned(),
            target_history_epoch: origin,
            origin: active_state_pointer::PointerOrigin::Bootstrap,
            database_certificate_digest: [0x76; 32],
        });
    }
    image
}

fn t78_value(image: &CompleteControlJournalImage, acknowledge: bool) -> AddressedStateValue {
    let mirror = image.checkpoint.active_pointer.as_ref().map_or(
        AddressedMirror::NotApplicable,
        |pointer| AddressedMirror::Pending {
            origin: pointer.target_history_epoch,
            pre: head(4, 0x44),
            policy: if acknowledge { 1 } else { 3 },
        },
    );
    AddressedStateValue {
        actor: AddressedActor::Principal(b"operator/A-1".to_vec()),
        address: if acknowledge {
            AddressedOperationAddress::ClockHold {
                generation: 1,
                observation_digest: [1; 32],
            }
        } else {
            AddressedOperationAddress::ProcessInstance(T78_PROCESS)
        },
        desired_transition: if acknowledge {
            DesiredMonotonicTransition::SettleHold {
                risk_acknowledged: true,
            }
        } else {
            DesiredMonotonicTransition::StopProcess { grace_ms: 50 }
        },
        evidence: if acknowledge {
            AddressedEvidence::Acknowledge {
                accepted_wall_time: 30,
                accepted_monotonic_tick: 100,
                prior_fixed_safe_time: 20,
                prior_selected_safe_time: image.checkpoint.active_pointer.as_ref().map(|_| 25),
                target_safe_time: 30,
            }
        } else {
            AddressedEvidence::Shutdown {
                accepted_monotonic_tick: 100,
                grace_deadline_tick: 150,
            }
        },
        phase: 1,
        safe_result: if acknowledge {
            AddressedResult::Acknowledge {
                settled_safe_time: 30,
                settled: false,
            }
        } else {
            AddressedResult::Shutdown {
                ungraceful_reason: 0,
            }
        },
        application_head: if acknowledge {
            head(7, 0x77)
        } else {
            head(8, 0x88)
        },
        publication_head: if acknowledge {
            head(7, 0x77)
        } else {
            head(8, 0x88)
        },
        mirror,
    }
}

fn t78_present(value: AddressedStateValue) -> AddressedState {
    AddressedState::Present(Box::new(value))
}

fn t78_cell(checkpoint: &CompleteCheckpoint, slot: usize) -> &AddressedStateValue {
    match &checkpoint.addressed[slot].state {
        AddressedState::Present(value) => value,
        AddressedState::Absent => panic!("Task 0078 expected populated slot {slot}"),
    }
}

fn t78_head_bytes(bytes: &mut Vec<u8>, value: JournalHead) {
    bytes.extend_from_slice(&value.sequence.to_be_bytes());
    bytes.extend_from_slice(&value.digest);
}

fn t78_result_bytes(result: AddressedResult) -> Vec<u8> {
    match result {
        AddressedResult::Acknowledge {
            settled_safe_time,
            settled,
        } => {
            let mut bytes = vec![0, 0x77, 0, 1, 0, 9];
            bytes.extend_from_slice(&settled_safe_time.to_be_bytes());
            bytes.push(u8::from(settled));
            bytes
        }
        AddressedResult::Shutdown { ungraceful_reason } => {
            vec![0, 0x78, 0, 1, 0, 1, ungraceful_reason]
        }
    }
}

fn t78_body(value: &AddressedStateValue, with_heads: bool) -> Vec<u8> {
    let acknowledge = matches!(value.address, AddressedOperationAddress::ClockHold { .. });
    let mut bytes = vec![1, 0, if acknowledge { 2 } else { 3 }];
    let (kind, actor) = match &value.actor {
        AddressedActor::Principal(actor) => (1, actor.as_slice()),
        AddressedActor::StateOwner => (2, b"msgriver/state-owner/v1".as_slice()),
    };
    bytes.extend_from_slice(&[kind, actor.len() as u8]);
    bytes.extend_from_slice(actor);
    match value.address {
        AddressedOperationAddress::ClockHold {
            generation,
            observation_digest,
        } => {
            bytes.extend_from_slice(&generation.to_be_bytes());
            bytes.extend_from_slice(&observation_digest);
        }
        AddressedOperationAddress::ProcessInstance(process) => bytes.extend_from_slice(&process),
    }
    match value.desired_transition {
        DesiredMonotonicTransition::SettleHold { risk_acknowledged } => {
            bytes.extend_from_slice(&[1, u8::from(risk_acknowledged)]);
        }
        DesiredMonotonicTransition::StopProcess { grace_ms } => {
            bytes.push(1);
            bytes.extend_from_slice(&grace_ms.to_be_bytes());
        }
    }
    match value.evidence {
        AddressedEvidence::Acknowledge {
            accepted_wall_time,
            accepted_monotonic_tick,
            prior_fixed_safe_time,
            prior_selected_safe_time,
            target_safe_time,
        } => {
            for tick in [
                accepted_wall_time,
                accepted_monotonic_tick,
                prior_fixed_safe_time,
            ] {
                bytes.extend_from_slice(&tick.to_be_bytes());
            }
            bytes.push(u8::from(prior_selected_safe_time.is_some()));
            if let Some(tick) = prior_selected_safe_time {
                bytes.extend_from_slice(&tick.to_be_bytes());
            }
            bytes.extend_from_slice(&target_safe_time.to_be_bytes());
        }
        AddressedEvidence::Shutdown {
            accepted_monotonic_tick,
            grace_deadline_tick,
        } => {
            bytes.extend_from_slice(&accepted_monotonic_tick.to_be_bytes());
            bytes.extend_from_slice(&grace_deadline_tick.to_be_bytes());
        }
    }
    bytes.push(value.phase);
    bytes.extend_from_slice(&t78_result_bytes(value.safe_result));
    if with_heads {
        t78_head_bytes(&mut bytes, value.application_head);
        t78_head_bytes(&mut bytes, value.publication_head);
    }
    match value.mirror {
        AddressedMirror::NotApplicable => bytes.push(0),
        AddressedMirror::Pending {
            origin,
            pre,
            policy,
        }
        | AddressedMirror::Committed {
            origin,
            pre,
            policy,
            ..
        } => {
            bytes.push(if matches!(value.mirror, AddressedMirror::Pending { .. }) {
                1
            } else {
                2
            });
            bytes.extend_from_slice(&origin);
            t78_head_bytes(&mut bytes, pre);
            bytes.push(policy);
            if let AddressedMirror::Committed { post, .. } = value.mirror {
                t78_head_bytes(&mut bytes, post);
            }
        }
    }
    bytes
}

fn t78_members(journal: &JournalIntegrityKey, wire: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut reader = ImageReader::new(&wire[120..]);
    let opened = open_region(
        journal,
        &mut reader,
        ImageRegion::Checkpoint,
        region_digest(&wire[..120]),
        None,
    )
    .expect("authenticated fixture checkpoint");
    let mut reader = ImageReader::new(opened.payload);
    let mut members = Vec::new();
    for tag in 1..=13 {
        members.push((
            tag,
            reader.member(tag).expect("ordered fixture member").to_vec(),
        ));
    }
    reader.end().expect("exact fixture inventory");
    members
}

fn t78_reseal(
    journal: &JournalIntegrityKey,
    image: &CompleteControlJournalImage,
    members: &[(u16, Vec<u8>)],
    frames: &[Vec<u8>],
) -> Vec<u8> {
    let header = encode_image_header(journal, image.header).expect("fixture header");
    let mut payload = ImageWriter::new(CHECKPOINT_LIMIT);
    for (tag, body) in members {
        payload.member(*tag, body).expect("bounded test member");
    }
    let checkpoint = seal_region(
        journal,
        ImageRegion::Checkpoint,
        members.len() as u16,
        region_digest(&header),
        None,
        &payload.finish(),
    )
    .expect("authenticate mutated checkpoint");
    let tail = seal_region(
        journal,
        ImageRegion::Tail,
        frames.len() as u16,
        region_digest(&header),
        Some(region_digest(&checkpoint)),
        &frames.concat(),
    )
    .expect("authenticate mutated tail");
    [header.as_slice(), &checkpoint, &tail].concat()
}

fn t78_check_image(journal: &JournalIntegrityKey, image: &CompleteControlJournalImage) {
    let wire = t78_require(encode_control_journal_image(journal, image));
    assert_eq!(
        t78_require(decode_control_journal_image(journal, &wire)),
        *image
    );
    let projected = t78_require(replay_tail(image));
    let root = IsolatedOwnerRoot::create();
    // A missing journal accepts only the authenticated genesis image.
    // Publish that predecessor first so this generation-2 fixture exercises a
    // monotonic replacement, rather than asking publication to adopt a later
    // snapshot into an empty root.
    let genesis = complete_genesis(journal);
    require_publish(journal, &root, &genesis);
    require_publish(journal, &root, image);
    assert_eq!(
        t78_require(reopen_control_journal_image(journal, &root.path)),
        *image
    );
    for trigger in [FoldTrigger::TailFrameLimit, FoldTrigger::TailByteLimit] {
        let folded = t78_require(fold_control_journal_image(image, trigger));
        assert!(folded.tail.is_empty());
        let mut expected = projected.clone();
        expected.generation += 1;
        assert_eq!(
            folded.checkpoint, expected,
            "fold retains the entire projection"
        );
        require_publish(journal, &root, &folded);
        assert_eq!(
            t78_require(reopen_control_journal_image(journal, &root.path)),
            folded
        );
    }
}

fn t78_step(
    journal: &JournalIntegrityKey,
    image: &CompleteControlJournalImage,
    operation: AddressedOperation,
    action: AddressedAction,
    process: [u8; 16],
    recovery: bool,
) -> CompleteControlJournalImage {
    let expected_body = t78_action_bytes(&action);
    let next = t78_require(append_addressed_action(
        journal, image, operation, action, process, recovery,
    ));
    t78_check_image(journal, &next);
    if let Some(frame) = next.tail.last() {
        let wire = t78_require(encode_tail_frame(journal, frame.prior_head, frame));
        let record = journal
            .decode_control_journal_record(&wire, component_head(frame.prior_head))
            .expect("authenticated action frame");
        assert_eq!(record.body, expected_body);
        assert_eq!(
            record.kind,
            if operation == AddressedOperation::ClockAcknowledge {
                control_journal_record::ControlJournalRecordKind::ClockAcknowledge
            } else {
                control_journal_record::ControlJournalRecordKind::SystemShutdown
            }
        );
    }
    next
}

fn t78_action_bytes(action: &AddressedAction) -> Vec<u8> {
    let (tag, payload) = match action {
        AddressedAction::PublishRequest(value) => (1, t78_body(value, false)),
        AddressedAction::PublishPhase { phase, result } => {
            let mut bytes = vec![*phase];
            bytes.extend_from_slice(&t78_result_bytes(*result));
            (2, bytes)
        }
        AddressedAction::CommitMirror(post) => {
            let mut bytes = vec![];
            t78_head_bytes(&mut bytes, *post);
            (3, bytes)
        }
    };
    let mut bytes = vec![1, tag];
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&payload);
    bytes
}

fn t78_reject_step(
    journal: &JournalIntegrityKey,
    image: &CompleteControlJournalImage,
    operation: AddressedOperation,
    action: AddressedAction,
) {
    let before = t78_require(encode_control_journal_image(journal, image));
    assert_eq!(
        append_addressed_action(journal, image, operation, action, T78_PROCESS, false),
        Err(INVALID)
    );
    assert_eq!(
        t78_require(encode_control_journal_image(journal, image)),
        before
    );
}

fn t78_phase(acknowledge: bool, phase: u8, reason: u8) -> AddressedAction {
    AddressedAction::PublishPhase {
        phase,
        result: if acknowledge {
            AddressedResult::Acknowledge {
                settled_safe_time: 30,
                settled: phase == 3,
            }
        } else {
            AddressedResult::Shutdown {
                ungraceful_reason: reason,
            }
        },
    }
}

#[test]
fn task0078_addressed_cells_round_trip_and_bounds() {
    let journal = key(0x35);
    let genesis = complete_genesis(&journal);
    let members = t78_members(&journal, &require_wire(&journal, &genesis));
    assert_eq!(
        &members[6..10],
        &[(7, vec![0]), (8, vec![0]), (9, vec![0]), (10, vec![0])]
    );
    assert_eq!(
        members[6..10]
            .iter()
            .map(|(_, body)| 6 + body.len())
            .sum::<usize>(),
        28
    );
    for selected in [false, true] {
        for actor in [
            AddressedActor::Principal(vec![b'A']),
            AddressedActor::StateOwner,
            AddressedActor::Principal(vec![b'A'; 128]),
        ] {
            let mut image = t78_base(&journal, selected);
            let mut ack = t78_value(&image, true);
            let mut shutdown = t78_value(&image, false);
            ack.actor = actor.clone();
            shutdown.actor = actor.clone();
            image.checkpoint.addressed[0].state = t78_present(ack.clone());
            image.checkpoint.addressed[2].state = t78_present(shutdown.clone());
            let wire = t78_require(encode_control_journal_image(&journal, &image));
            let members = t78_members(&journal, &wire);
            let n = match actor {
                AddressedActor::Principal(ref value) => value.len(),
                AddressedActor::StateOwner => 23,
            };
            assert_eq!(members[6].1, t78_body(&ack, true));
            assert_eq!(members[8].1, t78_body(&shutdown, true));
            assert_eq!(
                members[6].1.len(),
                143 + n + if selected { 41 + 74 } else { 33 + 1 }
            );
            assert_eq!(members[8].1.len(), 130 + n + if selected { 74 } else { 1 });
            t78_check_image(&journal, &image);
            // Committed terminal bodies exercise both last slots and maximum widths.
            for (slot, mut value) in [(1, ack), (3, shutdown)] {
                value.phase = 3;
                if slot == 1 {
                    value.safe_result = AddressedResult::Acknowledge {
                        settled_safe_time: 30,
                        settled: true,
                    };
                    image.checkpoint.clock_authority.safe_time = 30;
                    image.checkpoint.clock_authority.hold = None;
                }
                if let AddressedMirror::Pending {
                    origin,
                    pre,
                    policy,
                } = value.mirror
                {
                    value.mirror = AddressedMirror::Committed {
                        origin,
                        pre,
                        policy,
                        post: head(5, 0x55),
                    };
                    if slot == 3 {
                        value.publication_head = head(9, 0x99);
                    }
                }
                image.checkpoint.addressed[slot - 1].state = AddressedState::Absent;
                image.checkpoint.addressed[slot].state = t78_present(value.clone());
                let wire = t78_require(encode_control_journal_image(&journal, &image));
                let members = t78_members(&journal, &wire);
                assert_eq!(members[6 + slot].1, t78_body(&value, true));
                let expected = if slot == 1 {
                    143 + n + if selected { 41 + 114 } else { 33 + 1 }
                } else {
                    130 + n + if selected { 114 } else { 1 }
                };
                assert_eq!(members[6 + slot].1.len(), expected);
                t78_check_image(&journal, &image);
            }
        }
    }
    // Wall, fixed-root and selected times each win the exact maximum. Signed
    // times are legal; only monotonic ticks must be nonnegative.
    for (wall, fixed, selected, target) in [
        (30, 20, 25, 30),
        (10, 20, 15, 20),
        (10, 20, 25, 25),
        (-20, -10, -5, -5),
    ] {
        let mut image = t78_base(&journal, true);
        image.checkpoint.clock_authority.safe_time = fixed;
        let mut ack = t78_value(&image, true);
        ack.evidence = AddressedEvidence::Acknowledge {
            accepted_wall_time: wall,
            accepted_monotonic_tick: 0,
            prior_fixed_safe_time: fixed,
            prior_selected_safe_time: Some(selected),
            target_safe_time: target,
        };
        ack.safe_result = AddressedResult::Acknowledge {
            settled_safe_time: target,
            settled: false,
        };
        image.checkpoint.addressed[0].state = t78_present(ack);
        let mut shutdown = t78_value(&image, false);
        shutdown.evidence = AddressedEvidence::Shutdown {
            accepted_monotonic_tick: i64::MAX - 50,
            grace_deadline_tick: i64::MAX,
        };
        image.checkpoint.addressed[2].state = t78_present(shutdown);
        if fixed < 0 {
            // Signed codec values are valid, but publishing this image after
            // genesis would regress its durable safe-time high-water. Exercise
            // the codec/replay contract directly; the monotonic cases above
            // retain the publish/reopen/fold coverage.
            let wire = t78_require(encode_control_journal_image(&journal, &image));
            assert_eq!(
                t78_require(decode_control_journal_image(&journal, &wire)),
                image
            );
            assert_eq!(t78_require(replay_tail(&image)), image.checkpoint);
        } else {
            t78_check_image(&journal, &image);
        }
    }
    let base = t78_base(&journal, true);
    let mut maximum = t78_value(&base, true);
    maximum.actor = AddressedActor::Principal(vec![b'A'; 128]);
    let accepted = t78_step(
        &journal,
        &base,
        AddressedOperation::ClockAcknowledge,
        AddressedAction::PublishRequest(Box::new(maximum)),
        T78_PROCESS,
        false,
    );
    let frame = accepted
        .tail
        .last()
        .expect("first maximum request remains in tail");
    let frame_bytes = t78_require(encode_tail_frame(&journal, frame.prior_head, frame));
    assert_eq!(frame_bytes.len(), 420);
    assert_eq!(128 * frame_bytes.len(), 53_760);
    // Append must fold before frame 129 and retain the pending shutdown request.
    let mut full = t78_base(&journal, true);
    full.checkpoint.covered_head = head(0, 0);
    full.checkpoint.clock_authority = clock();
    full.tail = chained_tail(128);
    let mut request = t78_value(&full, false);
    request.actor = AddressedActor::Principal(vec![b'A'; 128]);
    let next = t78_step(
        &journal,
        &full,
        AddressedOperation::SystemShutdown,
        AddressedAction::PublishRequest(Box::new(request)),
        T78_PROCESS,
        false,
    );
    assert!(next.tail.len() <= 1);
    assert!(next.checkpoint.generation > full.checkpoint.generation);
    let projected = t78_require(replay_tail(&next));
    assert_eq!(projected.covered_head.sequence, 129);
    assert_eq!(t78_cell(&projected, 2).phase, 1);
    assert!(matches!(
        t78_cell(&projected, 2).mirror,
        AddressedMirror::Pending { policy: 3, .. }
    ));
}

fn t78_bad_body(
    journal: &JournalIntegrityKey,
    image: &CompleteControlJournalImage,
    members: &[(u16, Vec<u8>)],
    slot: usize,
    body: Vec<u8>,
    label: &str,
) {
    let mut mutated = members.to_vec();
    mutated[6 + slot].1 = body;
    assert_eq!(
        decode_control_journal_image(journal, &t78_reseal(journal, image, &mutated, &[])),
        Err(INVALID),
        "authenticated cell rejection: {label}"
    );
}

#[test]
fn task0078_authenticated_member_and_cell_rejections() {
    let journal = key(0x35);
    for selected in [false, true] {
        let mut image = t78_base(&journal, selected);
        let ack = t78_value(&image, true);
        let shutdown = t78_value(&image, false);
        image.checkpoint.addressed[0].state = t78_present(ack.clone());
        image.checkpoint.addressed[2].state = t78_present(shutdown.clone());
        let wire = t78_require(encode_control_journal_image(&journal, &image));
        let members = t78_members(&journal, &wire);
        // Positive authenticated control: the mutation apparatus itself must work.
        assert_eq!(
            decode_control_journal_image(&journal, &t78_reseal(&journal, &image, &members, &[])),
            Ok(image.clone())
        );
        for slot in 0..4 {
            for mutation in 0..4 {
                let mut changed = members.clone();
                match mutation {
                    0 => {
                        changed.swap(6 + slot, 6 + (slot + 1) % 4);
                    }
                    1 => {
                        changed.remove(6 + slot);
                    }
                    2 => {
                        changed.insert(6 + slot, changed[6 + slot].clone());
                    }
                    _ => {
                        changed[6 + slot].0 = 14;
                    }
                }
                assert_invalid(&journal, &t78_reseal(&journal, &image, &changed, &[]));
            }
            for body in [vec![], vec![0, 0], vec![2], vec![0xff]] {
                t78_bad_body(&journal, &image, &members, slot, body, "closed absence");
            }
        }
        for (slot, value) in [(0, &ack), (2, &shutdown)] {
            let body = t78_body(value, true);
            assert_eq!(members[6 + slot].1, body);
            let n = 12; // literal actor "operator/A-1" is twelve ASCII bytes
            assert_eq!(body[4] as usize, n);
            let address = 5 + n;
            let evidence = address + if slot == 0 { 42 } else { 21 };
            let phase = evidence
                + if slot == 0 {
                    if selected { 41 } else { 33 }
                } else {
                    16
                };
            let result = phase + 1;
            let heads = result + if slot == 0 { 15 } else { 7 };
            let mirror = heads + 80;
            let mut changes: Vec<(&str, Vec<u8>)> = Vec::new();
            for (label, offset, byte) in [
                ("format", 0, 2),
                ("operation/slot", 2, if slot == 0 { 3 } else { 2 }),
                ("actor kind", 3, 3),
                ("principal first byte", 5, b'/'),
                ("principal body byte", 6, b' '),
                ("principal non-ASCII", 6, 0xff),
                ("phase zero", phase, 0),
                ("phase unknown", phase, 5),
                ("result codec", result + 1, 0xff),
                ("result version", result + 3, 2),
                ("result width", result + 5, 0),
                ("mirror tag", mirror, 3),
                (
                    "desired transition",
                    evidence - if slot == 0 { 2 } else { 5 },
                    2,
                ),
            ] {
                let mut bad = body.clone();
                bad[offset] = byte;
                changes.push((label, bad));
            }
            let mut empty_actor = body.clone();
            empty_actor.drain(5..5 + n);
            empty_actor[4] = 0;
            changes.push(("empty actor", empty_actor));
            let mut long_actor = value.clone();
            long_actor.actor = AddressedActor::Principal(vec![b'A'; 129]);
            changes.push(("129-byte actor", t78_body(&long_actor, true)));
            let mut wrong_owner = value.clone();
            wrong_owner.actor = AddressedActor::StateOwner;
            let mut bad = t78_body(&wrong_owner, true);
            bad[5] = b'M';
            changes.push(("nonexact owner", bad));
            let mut bad = t78_body(&wrong_owner, true);
            bad[4] = 22;
            bad.remove(5);
            changes.push(("owner length", bad));
            for (label, start, length) in if slot == 0 {
                vec![
                    ("zero hold", address, 8),
                    ("zero observation digest", address + 8, 32),
                ]
            } else {
                vec![
                    ("zero process", address, 16),
                    ("zero grace", evidence - 4, 4),
                ]
            } {
                let mut bad = body.clone();
                bad[start..start + length].fill(0);
                changes.push((label, bad));
            }
            let mut bad = body.clone();
            let tick = evidence + if slot == 0 { 8 } else { 0 };
            bad[tick..tick + 8].copy_from_slice(&(-1_i64).to_be_bytes());
            changes.push(("negative monotonic tick", bad));
            if slot == 0 {
                let mut bad = body.clone();
                bad[evidence - 1] = 0;
                changes.push(("risk acknowledgement required", bad));
                let mut bad = body.clone();
                bad[evidence + 24] = 2;
                changes.push(("selected presence tag", bad));
                let mut bad = body.clone();
                bad[phase - 8..phase].copy_from_slice(&29_i64.to_be_bytes());
                bad[result + 6..result + 14].copy_from_slice(&29_i64.to_be_bytes());
                changes.push(("target is exact maximum", bad));
                let mut bad = body.clone();
                bad[result + 6..result + 14].copy_from_slice(&29_i64.to_be_bytes());
                changes.push(("result equals target", bad));
                let mut bad = body.clone();
                bad[result + 14] = 2;
                changes.push(("settled boolean", bad));
                for p in 1..=3 {
                    let mut bad = body.clone();
                    bad[phase] = p;
                    bad[result + 14] = u8::from(p != 3);
                    changes.push(("phase/settled mismatch", bad));
                }
                let mut bad = body.clone();
                if selected {
                    bad.truncate(mirror);
                    bad.push(0);
                } else {
                    let selected_image = t78_base(&journal, true);
                    let selected_value = t78_value(&selected_image, true);
                    let selected_body = t78_body(&selected_value, true);
                    bad.truncate(mirror);
                    bad.extend_from_slice(&selected_body[selected_body.len() - 74..]);
                }
                changes.push(("evidence width/mirror mismatch", bad));
            } else {
                let mut bad = body.clone();
                bad[evidence..evidence + 8].copy_from_slice(&i64::MAX.to_be_bytes());
                bad[evidence + 8..phase].copy_from_slice(&i64::MIN.to_be_bytes());
                changes.push(("checked deadline overflow", bad));
                let mut bad = body.clone();
                bad[evidence + 8..phase].copy_from_slice(&149_i64.to_be_bytes());
                changes.push(("deadline sum", bad));
                for p in 1..=4 {
                    for reason in 0..=5 {
                        if (p == 4 && (1..=4).contains(&reason)) || (p != 4 && reason == 0) {
                            continue;
                        }
                        let mut bad = body.clone();
                        bad[phase] = p;
                        bad[result + 6] = reason;
                        changes.push(("phase/reason mismatch", bad));
                    }
                }
            }
            for (label, start, replacement) in [
                ("genesis application head", heads, head(0, 0)),
                (
                    "zero application digest",
                    heads,
                    head(value.application_head.sequence, 0),
                ),
                ("application exceeds publication", heads, head(9, 0x99)),
                (
                    "equal head sequence/digest mismatch",
                    heads + 40,
                    head(value.application_head.sequence, 0x99),
                ),
                ("publication exceeds covered", heads + 40, head(11, 0x11)),
                (
                    "covered sequence/digest mismatch",
                    heads + 40,
                    head(10, 0x11),
                ),
            ] {
                let mut encoded = vec![];
                t78_head_bytes(&mut encoded, replacement);
                let mut bad = body.clone();
                bad[start..start + 40].copy_from_slice(&encoded);
                changes.push((label, bad));
            }
            if selected {
                for (label, start, length) in [
                    ("zero origin serial", mirror + 25, 8),
                    ("zero pre digest", mirror + 41, 32),
                ] {
                    let mut bad = body.clone();
                    bad[start..start + length].fill(0);
                    changes.push((label, bad));
                }
                for policy in 0..=4 {
                    if (slot == 0 && (policy == 1 || policy == 2)) || (slot == 2 && policy == 3) {
                        continue;
                    }
                    let mut bad = body.clone();
                    bad[mirror + 73] = policy;
                    changes.push(("operation mirror policy", bad));
                }
                let mut bad = body.clone();
                bad[mirror] = 2;
                t78_head_bytes(&mut bad, head(5, 0x55));
                changes.push(("phase-1 committed mirror", bad));
                for post in [head(4, 0x55), head(3, 0x55), head(5, 0)] {
                    let mut bad = body.clone();
                    bad[phase] = 3;
                    if slot == 0 {
                        bad[result + 14] = 1;
                    }
                    bad[mirror] = 2;
                    t78_head_bytes(&mut bad, post);
                    changes.push(("post head must advance with nonzero digest", bad));
                }
                if slot == 0 {
                    let mut bad = body.clone();
                    bad[phase] = 3;
                    bad[result + 14] = 1;
                    changes.push(("ack phase-3 pending mirror unreachable", bad));
                }
            }
            for end in [0, 3, address + 1, phase, heads + 79, body.len() - 1] {
                changes.push(("truncated body", body[..end].to_vec()));
            }
            let mut bad = body.clone();
            bad.push(0);
            changes.push(("trailing body", bad));
            for (label, bad) in changes {
                t78_bad_body(&journal, &image, &members, slot, bad, label);
            }
        }
    }
}

#[test]
fn task0078_acknowledge_actions_and_mirror_settlement() {
    let journal = key(0x35);
    let operation = AddressedOperation::ClockAcknowledge;
    for policy in 0..=2 {
        let base = t78_base(&journal, policy != 0);
        let mut request = t78_value(&base, true);
        if let AddressedMirror::Pending { policy: stored, .. } = &mut request.mirror {
            *stored = policy;
        }
        let accepted = t78_step(
            &journal,
            &base,
            operation,
            AddressedAction::PublishRequest(Box::new(request.clone())),
            T78_PROCESS,
            false,
        );
        let first = t78_require(replay_tail(&accepted));
        assert_eq!(first.clock_authority, base.checkpoint.clock_authority);
        assert_eq!(t78_cell(&first, 0).phase, 1);
        assert_eq!(t78_cell(&first, 0).mirror, request.mirror);
        assert_eq!(t78_cell(&first, 0).application_head, first.covered_head);
        assert_eq!(t78_cell(&first, 0).publication_head, first.covered_head);
        for address in [
            AddressedOperationAddress::ClockHold {
                generation: 2,
                observation_digest: [2; 32],
            },
            AddressedOperationAddress::ClockHold {
                generation: 1,
                observation_digest: [2; 32],
            },
        ] {
            let mut wrong = request.clone();
            wrong.address = address;
            t78_reject_step(
                &journal,
                &base,
                operation,
                AddressedAction::PublishRequest(Box::new(wrong)),
            );
            assert_eq!(
                t78_require(addressed_completion(
                    &accepted,
                    operation,
                    address,
                    T78_PROCESS
                )),
                None
            );
        }
        t78_reject_step(&journal, &accepted, operation, t78_phase(true, 3, 0));
        t78_reject_step(
            &journal,
            &accepted,
            operation,
            AddressedAction::CommitMirror(head(5, 0x55)),
        );
        t78_reject_step(
            &journal,
            &accepted,
            operation,
            AddressedAction::PublishRequest(Box::new(request.clone())),
        );
        let progress = t78_step(
            &journal,
            &accepted,
            operation,
            t78_phase(true, 2, 0),
            T78_PROCESS,
            false,
        );
        let second = t78_require(replay_tail(&progress));
        assert_eq!(second.clock_authority.safe_time, 30);
        assert_eq!(second.clock_authority.hold, Some(t78_hold(1)));
        assert_eq!(t78_cell(&second, 0).phase, 2);
        assert_eq!(
            t78_cell(&second, 0).safe_result,
            AddressedResult::Acknowledge {
                settled_safe_time: 30,
                settled: false
            }
        );
        assert_eq!(t78_cell(&second, 0).mirror, request.mirror);
        assert_eq!(t78_cell(&second, 0).application_head, second.covered_head);
        assert_eq!(t78_cell(&second, 0).publication_head, second.covered_head);
        assert_eq!(
            t78_require(addressed_completion(
                &progress,
                operation,
                request.address,
                T78_PROCESS
            )),
            None
        );
        t78_reject_step(&journal, &progress, operation, t78_phase(true, 1, 0));
        t78_reject_step(&journal, &progress, operation, t78_phase(true, 2, 0));
        let completion = if policy == 0 {
            t78_reject_step(
                &journal,
                &progress,
                operation,
                AddressedAction::CommitMirror(head(5, 0x55)),
            );
            t78_phase(true, 3, 0)
        } else {
            t78_reject_step(&journal, &progress, operation, t78_phase(true, 3, 0));
            for post in [head(4, 0x55), head(3, 0x55), head(5, 0)] {
                t78_reject_step(
                    &journal,
                    &progress,
                    operation,
                    AddressedAction::CommitMirror(post),
                );
            }
            AddressedAction::CommitMirror(head(5, 0x55))
        };
        let done = t78_step(
            &journal,
            &progress,
            operation,
            completion,
            T78_PROCESS,
            false,
        );
        let final_state = t78_require(replay_tail(&done));
        assert_eq!(final_state.clock_authority.safe_time, 30);
        assert_eq!(final_state.clock_authority.hold, None);
        assert_eq!(final_state.addressed[0].state, AddressedState::Absent);
        let last = t78_cell(&final_state, 1);
        assert_eq!(last.phase, 3);
        assert_eq!(last.application_head, final_state.covered_head);
        assert_eq!(last.publication_head, final_state.covered_head);
        assert_eq!(
            last.safe_result,
            AddressedResult::Acknowledge {
                settled_safe_time: 30,
                settled: true
            }
        );
        assert_eq!(
            last.mirror,
            match request.mirror {
                AddressedMirror::NotApplicable => AddressedMirror::NotApplicable,
                AddressedMirror::Pending {
                    origin,
                    pre,
                    policy,
                } => AddressedMirror::Committed {
                    origin,
                    pre,
                    policy,
                    post: head(5, 0x55)
                },
                _ => panic!("request mirror"),
            }
        );
        assert_eq!(
            t78_require(addressed_completion(
                &done,
                operation,
                request.address,
                T78_PROCESS
            )),
            Some(last.safe_result)
        );
        t78_reject_step(&journal, &done, operation, t78_phase(true, 3, 0));
        t78_reject_step(
            &journal,
            &done,
            operation,
            AddressedAction::CommitMirror(head(6, 0x66)),
        );
        // Safe time is a high-water input: a stale accepted prior cannot lower it.
        let mut stale = base.clone();
        stale.checkpoint.clock_authority.safe_time = 31;
        t78_reject_step(
            &journal,
            &stale,
            operation,
            AddressedAction::PublishRequest(Box::new(request.clone())),
        );
        let mut no_hold = base.clone();
        no_hold.checkpoint.clock_authority.hold = None;
        t78_reject_step(
            &journal,
            &no_hold,
            operation,
            AddressedAction::PublishRequest(Box::new(request)),
        );
    }
}

#[test]
fn task0078_shutdown_actions_recovery_and_mirror_retention() {
    let journal = key(0x35);
    let operation = AddressedOperation::SystemShutdown;
    for selected in [false, true] {
        // Every closed phase-4 reason is legal on 2→4; 1→4 requires recovery.
        for (recovery, terminal, reason) in [
            (false, 3, 0),
            (false, 4, 1),
            (false, 4, 2),
            (false, 4, 3),
            (false, 4, 4),
            (true, 4, 1),
        ] {
            let base = t78_base(&journal, selected);
            let request = t78_value(&base, false);
            let accepted = t78_step(
                &journal,
                &base,
                operation,
                AddressedAction::PublishRequest(Box::new(request.clone())),
                T78_PROCESS,
                false,
            );
            let first = t78_require(replay_tail(&accepted));
            assert_eq!(first.clock_authority, base.checkpoint.clock_authority);
            assert_eq!(t78_cell(&first, 2).phase, 1);
            let mut wrong = request.clone();
            wrong.address = AddressedOperationAddress::ProcessInstance([0x79; 16]);
            t78_reject_step(
                &journal,
                &base,
                operation,
                AddressedAction::PublishRequest(Box::new(wrong)),
            );
            t78_reject_step(&journal, &accepted, operation, t78_phase(false, 3, 0));
            t78_reject_step(&journal, &accepted, operation, t78_phase(false, 4, 1));
            t78_reject_step(
                &journal,
                &accepted,
                operation,
                AddressedAction::CommitMirror(head(5, 0x55)),
            );
            let progress = if recovery {
                accepted
            } else {
                t78_step(
                    &journal,
                    &accepted,
                    operation,
                    t78_phase(false, 2, 0),
                    T78_PROCESS,
                    false,
                )
            };
            assert_eq!(
                t78_require(replay_tail(&progress)).clock_authority,
                base.checkpoint.clock_authority
            );
            let terminal_image = t78_step(
                &journal,
                &progress,
                operation,
                t78_phase(false, terminal, reason),
                T78_PROCESS,
                recovery,
            );
            let terminal_state = t78_require(replay_tail(&terminal_image));
            assert_eq!(
                terminal_state.clock_authority,
                base.checkpoint.clock_authority
            );
            let terminal_cell = t78_cell(&terminal_state, if selected { 2 } else { 3 });
            assert_eq!(terminal_cell.phase, terminal);
            assert_eq!(
                terminal_cell.safe_result,
                AddressedResult::Shutdown {
                    ungraceful_reason: reason
                }
            );
            assert_eq!(terminal_cell.application_head, terminal_state.covered_head);
            assert_eq!(terminal_cell.publication_head, terminal_state.covered_head);
            assert_eq!(terminal_cell.mirror, request.mirror);
            t78_reject_step(&journal, &terminal_image, operation, t78_phase(false, 2, 0));
            if selected {
                assert_eq!(terminal_state.addressed[3].state, AddressedState::Absent);
                assert_eq!(
                    t78_require(addressed_completion(
                        &terminal_image,
                        operation,
                        request.address,
                        T78_PROCESS
                    )),
                    None
                );
                let committed = t78_step(
                    &journal,
                    &terminal_image,
                    operation,
                    AddressedAction::CommitMirror(head(5, 0x55)),
                    T78_PROCESS,
                    false,
                );
                let committed_state = t78_require(replay_tail(&committed));
                assert_eq!(
                    committed_state.clock_authority,
                    base.checkpoint.clock_authority
                );
                assert_eq!(committed_state.addressed[2].state, AddressedState::Absent);
                let last = t78_cell(&committed_state, 3);
                assert_eq!(last.application_head, terminal_cell.application_head);
                assert_eq!(last.publication_head, committed_state.covered_head);
                assert!(last.publication_head.sequence > last.application_head.sequence);
                assert_eq!(last.phase, terminal_cell.phase);
                assert_eq!(last.safe_result, terminal_cell.safe_result);
                assert_eq!(
                    t78_require(addressed_completion(
                        &committed,
                        operation,
                        request.address,
                        T78_PROCESS
                    )),
                    Some(last.safe_result)
                );
                let newer = t78_authority(
                    &journal,
                    &committed,
                    base.checkpoint.clock_authority,
                    [0x79; 16],
                );
                assert_eq!(
                    t78_require(replay_tail(&newer)).addressed[3].state,
                    AddressedState::Absent
                );
                assert_eq!(
                    t78_require(addressed_completion(
                        &newer,
                        operation,
                        request.address,
                        [0x79; 16]
                    )),
                    None
                );
            } else {
                assert_eq!(terminal_state.addressed[2].state, AddressedState::Absent);
                assert_eq!(
                    t78_require(addressed_completion(
                        &terminal_image,
                        operation,
                        request.address,
                        T78_PROCESS
                    )),
                    Some(terminal_cell.safe_result)
                );
                let newer = t78_authority(
                    &journal,
                    &terminal_image,
                    base.checkpoint.clock_authority,
                    [0x79; 16],
                );
                assert_eq!(
                    t78_require(replay_tail(&newer)).addressed[3].state,
                    AddressedState::Absent
                );
                assert_eq!(
                    t78_require(addressed_completion(
                        &newer,
                        operation,
                        request.address,
                        [0x79; 16]
                    )),
                    None
                );
            }
        }
    }
}

fn t78_tail_wire(
    journal: &JournalIntegrityKey,
    image: &CompleteControlJournalImage,
    operation: AddressedOperation,
    bodies: &[Vec<u8>],
) -> Vec<u8> {
    assert!(image.tail.is_empty());
    let members = t78_members(
        journal,
        &t78_require(encode_control_journal_image(journal, image)),
    );
    let mut prior = image.checkpoint.covered_head;
    let mut frames = vec![];
    for body in bodies {
        let frame = journal
            .encode_control_journal_record(
                if operation == AddressedOperation::ClockAcknowledge {
                    control_journal_record::ControlJournalRecordKind::ClockAcknowledge
                } else {
                    control_journal_record::ControlJournalRecordKind::SystemShutdown
                },
                body,
                component_head(prior),
            )
            .expect("authenticate literal action");
        let record = journal
            .decode_control_journal_record(&frame, component_head(prior))
            .expect("literal action framing positive control");
        prior = JournalHead {
            sequence: record.sequence,
            digest: record.record_digest,
        };
        frames.push(frame);
    }
    t78_reseal(journal, image, &members, &frames)
}

#[test]
fn task0078_authenticated_tail_actions_reject_invalid_transitions() {
    let journal = key(0x35);
    for acknowledge in [true, false] {
        let operation = if acknowledge {
            AddressedOperation::ClockAcknowledge
        } else {
            AddressedOperation::SystemShutdown
        };
        for selected in [false, true] {
            let base = t78_base(&journal, selected);
            let value = t78_value(&base, acknowledge);
            let request =
                t78_action_bytes(&AddressedAction::PublishRequest(Box::new(value.clone())));
            // First establish the missing typed path, so initial RED cannot be
            // confused with the predecessor decoder's generic kind refusal.
            t78_step(
                &journal,
                &base,
                operation,
                AddressedAction::PublishRequest(Box::new(value.clone())),
                T78_PROCESS,
                false,
            );
            // The envelope and both region tags are valid for every case below.
            let valid = t78_tail_wire(&journal, &base, operation, std::slice::from_ref(&request));
            let decoded = t78_require(decode_control_journal_image(&journal, &valid));
            let projected = t78_require(replay_tail(&decoded));
            assert_eq!(
                t78_cell(&projected, if acknowledge { 0 } else { 2 }).phase,
                1
            );
            t78_check_image(&journal, &decoded);
            let mut bad_bodies = vec![];
            for (offset, byte) in [(0, 2), (1, 0), (1, 4), (2, 0xff), (3, 0)] {
                let mut bad = request.clone();
                bad[offset] = byte;
                bad_bodies.push(bad);
            }
            let mut bad = request.clone();
            bad.push(0);
            bad_bodies.push(bad);
            bad_bodies.push(request[..request.len() - 1].to_vec());
            let mut wrong_phase = value.clone();
            wrong_phase.phase = 2;
            bad_bodies.push(t78_action_bytes(&AddressedAction::PublishRequest(
                Box::new(wrong_phase),
            )));
            if let AddressedMirror::Pending {
                origin,
                pre,
                policy,
            } = value.mirror
            {
                let mut committed = value.clone();
                committed.mirror = AddressedMirror::Committed {
                    origin,
                    pre,
                    policy,
                    post: head(5, 0x55),
                };
                bad_bodies.push(t78_action_bytes(&AddressedAction::PublishRequest(
                    Box::new(committed),
                )));
            }
            // A body for the other operation cannot cross the envelope boundary.
            bad_bodies.push(t78_action_bytes(&AddressedAction::PublishRequest(
                Box::new(t78_value(&base, !acknowledge)),
            )));
            for bad in bad_bodies {
                assert_invalid(&journal, &t78_tail_wire(&journal, &base, operation, &[bad]));
            }
            let phase2 = t78_action_bytes(&t78_phase(acknowledge, 2, 0));
            let phase3 = t78_action_bytes(&t78_phase(acknowledge, 3, 0));
            let commit = t78_action_bytes(&AddressedAction::CommitMirror(head(5, 0x55)));
            for bodies in [
                vec![phase2.clone()],
                vec![commit.clone()],
                vec![request.clone(), phase3.clone()],
                vec![request.clone(), commit.clone()],
                vec![request.clone(), request.clone()],
                vec![request.clone(), phase2.clone(), phase2.clone()],
            ] {
                assert_invalid(
                    &journal,
                    &t78_tail_wire(&journal, &base, operation, &bodies),
                );
            }
            if acknowledge && selected {
                assert_invalid(
                    &journal,
                    &t78_tail_wire(
                        &journal,
                        &base,
                        operation,
                        &[request.clone(), phase2.clone(), phase3.clone()],
                    ),
                );
            }
            let mut malformed_phase = phase2.clone();
            malformed_phase.push(0);
            let mut malformed_commit = commit.clone();
            malformed_commit.pop();
            for bad in [
                malformed_phase,
                malformed_commit,
                t78_action_bytes(&t78_phase(!acknowledge, 2, 0)),
            ] {
                assert_invalid(
                    &journal,
                    &t78_tail_wire(&journal, &base, operation, &[request.clone(), bad]),
                );
            }
            // Full legal causal sequence, with the exact inline result at each edge.
            let mut legal = vec![request, phase2];
            if acknowledge && selected {
                legal.push(commit);
            } else {
                legal.push(phase3);
                if selected {
                    legal.push(commit);
                }
            }
            let legal_wire = t78_tail_wire(&journal, &base, operation, &legal);
            let recovered = t78_require(decode_control_journal_image(&journal, &legal_wire));
            let completed = t78_require(replay_tail(&recovered));
            assert_eq!(
                t78_cell(&completed, if acknowledge { 1 } else { 3 }).phase,
                3
            );
            t78_check_image(&journal, &recovered);
            legal.push(t78_action_bytes(&t78_phase(acknowledge, 2, 0)));
            assert_invalid(&journal, &t78_tail_wire(&journal, &base, operation, &legal));
        }
    }
}

fn t78_authority(
    journal: &JournalIntegrityKey,
    image: &CompleteControlJournalImage,
    clock: ClockAuthority,
    process: [u8; 16],
) -> CompleteControlJournalImage {
    let next = t78_require(publish_addressed_authority(journal, image, clock, process));
    t78_check_image(journal, &next);
    assert_eq!(t78_require(replay_tail(&next)).clock_authority, clock);
    next
}

fn t78_automatic(
    journal: &JournalIntegrityKey,
    image: &CompleteControlJournalImage,
    generation: u64,
) -> CompleteControlJournalImage {
    let prior = t78_require(replay_tail(image)).clock_authority.safe_time;
    let next = t78_require(append_clock_checkpoint(
        journal,
        image,
        clock_checkpoint_body::ClockCheckpointBody {
            runtime_mode: clock_checkpoint_body::RuntimeMode::Maintenance,
            process_instance: T78_PROCESS,
            accepted_wall_time: prior,
            accepted_monotonic_tick: 200,
            prior_safe_time: prior,
            new_safe_time: prior,
            reason: clock_checkpoint_body::CheckpointReason::AutomaticSettlement,
            hold: Some(clock_checkpoint_body::NamedHold {
                generation,
                observation_digest: [generation as u8; 32],
            }),
            pre_mirror: None,
        },
    ));
    t78_check_image(journal, &next);
    next
}

#[test]
fn task0078_authority_replay_fold_and_reopen_retention() {
    let journal = key(0x35);
    let acknowledge = AddressedOperation::ClockAcknowledge;
    let shutdown = AddressedOperation::SystemShutdown;
    for selected in [false, true] {
        let base = t78_base(&journal, selected);
        let request = t78_value(&base, true);
        let accepted = t78_step(
            &journal,
            &base,
            acknowledge,
            AddressedAction::PublishRequest(Box::new(request.clone())),
            T78_PROCESS,
            false,
        );
        let progress = t78_step(
            &journal,
            &accepted,
            acknowledge,
            t78_phase(true, 2, 0),
            T78_PROCESS,
            false,
        );
        let completion = if selected {
            AddressedAction::CommitMirror(head(5, 0x55))
        } else {
            t78_phase(true, 3, 0)
        };
        let done = t78_step(
            &journal,
            &progress,
            acknowledge,
            completion.clone(),
            T78_PROCESS,
            false,
        );
        let new_clock = ClockAuthority {
            safe_time: 30,
            hold: Some(t78_hold(2)),
            last_shutdown_observation: None,
        };
        let entered = t78_authority(&journal, &done, new_clock, T78_PROCESS);
        let after_entry = t78_require(replay_tail(&entered));
        assert_eq!(
            after_entry.addressed[1].state,
            AddressedState::Absent,
            "H2 evicts completed H1"
        );
        assert_eq!(
            t78_require(addressed_completion(
                &entered,
                acknowledge,
                request.address,
                T78_PROCESS
            )),
            None
        );
        let cleared = t78_automatic(&journal, &entered, 2);
        assert_eq!(
            t78_require(replay_tail(&cleared)).addressed[1].state,
            AddressedState::Absent
        );
        assert_eq!(
            t78_require(addressed_completion(
                &cleared,
                acknowledge,
                request.address,
                T78_PROCESS
            )),
            None
        );
        // An unresolved H1 survives H2 entry, but cannot become retryable later.
        for pending in [&accepted, &progress] {
            let before = t78_require(replay_tail(pending));
            let newer = t78_authority(&journal, pending, new_clock, T78_PROCESS);
            let after = t78_require(replay_tail(&newer));
            assert_eq!(
                after.addressed[0], before.addressed[0],
                "obsolete obligation stays lossless"
            );
            assert_eq!(
                t78_require(addressed_completion(
                    &newer,
                    acknowledge,
                    request.address,
                    T78_PROCESS
                )),
                None
            );
            let mut next_request = request.clone();
            next_request.address = AddressedOperationAddress::ClockHold {
                generation: 2,
                observation_digest: [2; 32],
            };
            if let AddressedEvidence::Acknowledge {
                prior_fixed_safe_time,
                ..
            } = &mut next_request.evidence
            {
                *prior_fixed_safe_time = 30;
            }
            t78_reject_step(
                &journal,
                &newer,
                acknowledge,
                AddressedAction::PublishRequest(Box::new(next_request)),
            );
            if before.addressed[0].state == t78_require(replay_tail(&accepted)).addressed[0].state {
                t78_reject_step(&journal, &newer, acknowledge, t78_phase(true, 2, 0));
            }
        }
        let newer = t78_authority(&journal, &progress, new_clock, T78_PROCESS);
        let obsolete_done = t78_step(
            &journal,
            &newer,
            acknowledge,
            completion.clone(),
            T78_PROCESS,
            false,
        );
        let obsolete_state = t78_require(replay_tail(&obsolete_done));
        assert_eq!(
            obsolete_state.clock_authority, new_clock,
            "H1 cannot clear H2"
        );
        assert_eq!(obsolete_state.addressed[0].state, AddressedState::Absent);
        assert_eq!(
            obsolete_state.addressed[1].state,
            AddressedState::Absent,
            "completion uses pre-publication H2"
        );
        let after_h2_clear = t78_automatic(&journal, &obsolete_done, 2);
        assert_eq!(
            t78_require(addressed_completion(
                &after_h2_clear,
                acknowledge,
                request.address,
                T78_PROCESS
            )),
            None
        );
        // H2 clearing must not finalize a different-address tag-1 obligation;
        // resolving that retained H1 under absent authority drops it, never last.
        let h2_cleared_pending = t78_automatic(&journal, &newer, 2);
        assert_eq!(
            t78_require(replay_tail(&h2_cleared_pending)).addressed[0],
            t78_require(replay_tail(&newer)).addressed[0]
        );
        let absent_done = t78_step(
            &journal,
            &h2_cleared_pending,
            acknowledge,
            completion,
            T78_PROCESS,
            false,
        );
        let absent_state = t78_require(replay_tail(&absent_done));
        assert_eq!(absent_state.clock_authority.hold, None);
        assert_eq!(absent_state.addressed[0].state, AddressedState::Absent);
        assert_eq!(absent_state.addressed[1].state, AddressedState::Absent);
        assert_eq!(
            t78_require(addressed_completion(
                &absent_done,
                acknowledge,
                request.address,
                T78_PROCESS
            )),
            None
        );
        if !selected {
            let auto_done = t78_automatic(&journal, &progress, 1);
            let auto_state = t78_require(replay_tail(&auto_done));
            assert_eq!(auto_state.clock_authority.hold, None);
            assert_eq!(auto_state.addressed[0].state, AddressedState::Absent);
            assert_eq!(
                t78_cell(&auto_state, 1).phase,
                3,
                "automatic exact hold clear finalizes H1"
            );
            assert_eq!(
                t78_cell(&auto_state, 1).safe_result,
                AddressedResult::Acknowledge {
                    settled_safe_time: 30,
                    settled: true
                }
            );
        }
    }
    // Startup process authority is external; no process is added to the image.
    let base = t78_base(&journal, true);
    let request = t78_value(&base, false);
    let accepted = t78_step(
        &journal,
        &base,
        shutdown,
        AddressedAction::PublishRequest(Box::new(request.clone())),
        T78_PROCESS,
        false,
    );
    let next_process = [0x79; 16];
    let newer = t78_authority(
        &journal,
        &accepted,
        base.checkpoint.clock_authority,
        next_process,
    );
    assert_eq!(
        t78_require(replay_tail(&newer)).addressed[2],
        t78_require(replay_tail(&accepted)).addressed[2]
    );
    let mut new_request = request.clone();
    new_request.address = AddressedOperationAddress::ProcessInstance(next_process);
    assert_eq!(
        append_addressed_action(
            &journal,
            &newer,
            shutdown,
            AddressedAction::PublishRequest(Box::new(new_request.clone())),
            next_process,
            false
        ),
        Err(INVALID)
    );
    let recovered = t78_step(
        &journal,
        &newer,
        shutdown,
        t78_phase(false, 4, 1),
        next_process,
        true,
    );
    let terminal = t78_require(replay_tail(&recovered));
    assert_eq!(t78_cell(&terminal, 2).phase, 4);
    assert_eq!(terminal.addressed[3].state, AddressedState::Absent);
    assert_eq!(
        t78_require(addressed_completion(
            &recovered,
            shutdown,
            request.address,
            next_process
        )),
        None
    );
    assert_eq!(
        append_addressed_action(
            &journal,
            &recovered,
            shutdown,
            AddressedAction::PublishRequest(Box::new(new_request.clone())),
            next_process,
            false
        ),
        Err(INVALID)
    );
    let committed = t78_step(
        &journal,
        &recovered,
        shutdown,
        AddressedAction::CommitMirror(head(5, 0x55)),
        next_process,
        true,
    );
    let resolved = t78_require(replay_tail(&committed));
    assert_eq!(resolved.addressed[2].state, AddressedState::Absent);
    assert_eq!(
        resolved.addressed[3].state,
        AddressedState::Absent,
        "old process completion is superseded"
    );
    assert_eq!(
        t78_require(addressed_completion(
            &committed,
            shutdown,
            request.address,
            next_process
        )),
        None
    );
    let next = t78_step(
        &journal,
        &committed,
        shutdown,
        AddressedAction::PublishRequest(Box::new(new_request)),
        next_process,
        false,
    );
    assert_eq!(
        t78_cell(&t78_require(replay_tail(&next)), 2).address,
        AddressedOperationAddress::ProcessInstance(next_process)
    );
}

// Task 0078 post-freeze review regressions. All frozen bytes above are unchanged.

#[test]
fn task0078_post_freeze_request_heads_reject_before_mutation() {
    let journal = key(0x35);
    let base = t78_base(&journal, false);
    let wire = t78_tail_wire(
        &journal,
        &base,
        AddressedOperation::ClockAcknowledge,
        &[t78_action_bytes(&AddressedAction::PublishRequest(
            Box::new(t78_value(&base, true)),
        ))],
    );
    let mut image = t78_require(decode_control_journal_image(&journal, &wire));
    assert_eq!(
        t78_require(encode_control_journal_image(&journal, &image)),
        wire
    );
    let frame = &mut image.tail[0];
    let TailRecord::ClockAcknowledge(AddressedAction::PublishRequest(value)) = &mut frame.record
    else {
        panic!("authenticated acknowledge request");
    };
    assert_eq!(value.application_head, frame.resulting_head);
    assert_eq!(value.publication_head, frame.resulting_head);
    assert_eq!(frame.resulting_head.sequence, 11);
    // Heads are omitted from the authenticated payload; only the typed heads
    // change, leaving the genuine frame digest and all request facts intact.
    value.application_head = head(999, 0x99);
    value.publication_head = head(999, 0x99);
    let before = image.clone();
    let root = IsolatedOwnerRoot::create();
    require_publish(&journal, &root, &complete_genesis(&journal));
    require_publish(&journal, &root, &base);
    let durable_before = fs::read(root.path.join(JOURNAL_NAME)).expect("read predecessor");

    // Evaluate every boundary before asserting, including durable non-mutation.
    let outcomes = [
        replay_tail(&image).map(|_| ()),
        encode_control_journal_image(&journal, &image).map(|_| ()),
        fold_control_journal_image(&image, FoldTrigger::TailFrameLimit).map(|_| ()),
        fold_control_journal_image(&image, FoldTrigger::TailByteLimit).map(|_| ()),
        publish_control_journal_image(&journal, &root.path, &image),
    ];
    let durable_after = fs::read(root.path.join(JOURNAL_NAME)).expect("read after rejection");
    let reopened = reopen_control_journal_image(&journal, &root.path);
    assert_eq!(
        (
            outcomes,
            image == before,
            durable_after == durable_before,
            reopened == Ok(base)
        ),
        ([Err(INVALID); 5], true, true, true),
        "replay, encode, frame fold, byte fold, publish must reject; input, durable bytes and reopened predecessor must stay unchanged"
    );
}

#[test]
fn task0078_post_freeze_new_process_evicts_shutdown_last() {
    let journal = key(0x35);
    let base = t78_base(&journal, false);
    let old = t78_value(&base, false);
    let mut new = old.clone();
    new.address = AddressedOperationAddress::ProcessInstance([0x79; 16]);
    let bodies = [
        t78_action_bytes(&AddressedAction::PublishRequest(Box::new(old.clone()))),
        t78_action_bytes(&t78_phase(false, 2, 0)),
        t78_action_bytes(&t78_phase(false, 3, 0)),
        t78_action_bytes(&AddressedAction::PublishRequest(Box::new(new.clone()))),
    ];
    let terminal = t78_require(decode_control_journal_image(
        &journal,
        &t78_tail_wire(
            &journal,
            &base,
            AddressedOperation::SystemShutdown,
            &bodies[..3],
        ),
    ));
    let terminal = t78_require(replay_tail(&terminal));
    assert_eq!(terminal.addressed[2].state, AddressedState::Absent);
    assert_eq!(t78_cell(&terminal, 3).address, old.address);
    assert_eq!(t78_cell(&terminal, 3).phase, 3);
    assert_eq!(
        t78_cell(&terminal, 3).mirror,
        AddressedMirror::NotApplicable
    );

    // Literal authenticated history bypasses append's separate eviction path.
    let wire = t78_tail_wire(&journal, &base, AddressedOperation::SystemShutdown, &bodies);
    let image = t78_require(decode_control_journal_image(&journal, &wire));
    assert_eq!(image.tail.len(), 4);
    assert_eq!(
        t78_require(encode_control_journal_image(&journal, &image)),
        wire
    );
    let decoded = t78_require(decode_control_journal_image(&journal, &wire));
    let projections = [
        t78_require(replay_tail(&image)),
        t78_require(replay_tail(&decoded)),
        t78_require(fold_control_journal_image(
            &image,
            FoldTrigger::TailFrameLimit,
        ))
        .checkpoint,
        t78_require(fold_control_journal_image(
            &image,
            FoldTrigger::TailByteLimit,
        ))
        .checkpoint,
    ];
    for projected in &projections {
        assert_eq!(t78_cell(projected, 2).address, new.address);
        assert_eq!(t78_cell(projected, 2).phase, 1);
        assert_eq!(projected.clock_authority, base.checkpoint.clock_authority);
    }
    assert_eq!(
        projections.map(|projected| projected.addressed[3].state.clone()),
        std::array::from_fn::<_, 4, _>(|_| AddressedState::Absent),
        "P1 last must be absent after replay, decode/replay, frame fold and byte fold of P2 request"
    );
}

#[test]
fn task0078_post_freeze_signed_time_publish_and_both_fold_reopen() {
    let journal = key(0x35);
    let mut image = t78_base(&journal, true);
    image.checkpoint.clock_authority.safe_time = -10;
    let mut ack = t78_value(&image, true);
    ack.evidence = AddressedEvidence::Acknowledge {
        accepted_wall_time: -20,
        accepted_monotonic_tick: 0,
        prior_fixed_safe_time: -10,
        prior_selected_safe_time: Some(-5),
        target_safe_time: -5,
    };
    ack.safe_result = AddressedResult::Acknowledge {
        settled_safe_time: -5,
        settled: false,
    };
    image.checkpoint.addressed[0].state = t78_present(ack);
    let mut shutdown = t78_value(&image, false);
    shutdown.evidence = AddressedEvidence::Shutdown {
        accepted_monotonic_tick: i64::MAX - 50,
        grace_deadline_tick: i64::MAX,
    };
    image.checkpoint.addressed[2].state = t78_present(shutdown);
    let wire = t78_require(encode_control_journal_image(&journal, &image));
    assert_eq!(
        t78_require(decode_control_journal_image(&journal, &wire)),
        image
    );
    assert_eq!(t78_require(replay_tail(&image)), image.checkpoint);

    let root = IsolatedOwnerRoot::create();
    let mut genesis = complete_genesis(&journal);
    genesis.checkpoint.clock_authority.safe_time = -10;
    require_publish(&journal, &root, &genesis);
    require_publish(&journal, &root, &image);
    assert_eq!(
        t78_require(reopen_control_journal_image(&journal, &root.path)),
        image
    );
    for trigger in [FoldTrigger::TailFrameLimit, FoldTrigger::TailByteLimit] {
        let folded = t78_require(fold_control_journal_image(&image, trigger));
        assert!(folded.tail.is_empty());
        let mut expected = image.checkpoint.clone();
        expected.generation += 1;
        assert_eq!(folded.checkpoint, expected);
        require_publish(&journal, &root, &folded);
        assert_eq!(
            t78_require(reopen_control_journal_image(&journal, &root.path)),
            folded
        );
    }
}

#[path = "red_control_journal_image_reconciled.rs"]
mod reconciled_old_checkpoint;
