use super::{
    FixedRootCommand, FixedRootCommandActor, FixedRootCommandCodec, FixedRootCommandError,
    FixedRootCommandOperation, FixedRootCommandRetention, FixedRootCommandRuntime,
    FixedRootCommandSafeResult, FixedRootCommandTag, FixedRootCommandTargetBinding,
    decode_fixed_root_command, encode_fixed_root_command,
};
use msgriver_core::canon::{MacKeyId, MacKeyRef, MacPurpose};

const PRE_BOOTSTRAP: [u8; 32] = [
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0, 0, 0, 0, 0, 0, 0, 0,
];
const ALLOCATED: [u8; 32] = [
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0, 0, 0, 0, 0, 0, 0, 1,
];

fn codec() -> FixedRootCommandCodec {
    FixedRootCommandCodec::new(PRE_BOOTSTRAP)
}

fn key(origin: [u8; 32], serial: u64) -> MacKeyId {
    let mut bytes = [0; 40];
    bytes[..32].copy_from_slice(&origin);
    bytes[32..].copy_from_slice(&serial.to_be_bytes());
    MacKeyId::from_bytes(bytes)
}

fn tag(purpose: MacPurpose, origin: [u8; 32], serial: u64, byte: u8) -> FixedRootCommandTag {
    FixedRootCommandTag {
        key: MacKeyRef::new(purpose, key(origin, serial)),
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

fn terminal_bootstrap() -> FixedRootCommand {
    FixedRootCommand {
        operation: FixedRootCommandOperation::BootstrapCreate,
        actor: FixedRootCommandActor::StateOwner,
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
            source: PRE_BOOTSTRAP,
            target: ALLOCATED,
            source_generation: Some(9),
            target_generation: Some(10),
            parent_witness: Some((ALLOCATED, 11, [0x72; 32], [0x73; 32])),
        }),
        profile_body: vec![0x33; 15_580],
    }
}

fn require_invalid_command(command: FixedRootCommand) {
    assert!(matches!(
        encode_fixed_root_command(&codec(), command),
        Err(FixedRootCommandError::InvalidFixedRootCommand)
    ));
}

fn require_invalid_wire(wire: &[u8]) {
    assert!(matches!(
        decode_fixed_root_command(&codec(), wire),
        Err(FixedRootCommandError::InvalidFixedRootCommand)
    ));
}

#[test]
fn canonical_common_prefix_round_trips_at_both_capacity_extremes() {
    for command in [continuation(), terminal_bootstrap()] {
        let wire = encode_fixed_root_command(&codec(), command.clone()).expect("encode canonical");
        assert_eq!(decode_fixed_root_command(&codec(), &wire), Ok(command));
    }
    let mut maximum_command = terminal_bootstrap();
    maximum_command.operation = FixedRootCommandOperation::RecoveryKeyGenerate;
    maximum_command.actor = FixedRootCommandActor::Principal(vec![b'a'; 128]);
    let binding = maximum_command.target_binding.as_mut().expect("binding");
    binding.source = ALLOCATED;
    binding.target = ALLOCATED;
    let maximum = encode_fixed_root_command(&codec(), maximum_command).expect("encode maximum");
    assert_eq!(maximum.len(), 16_274);
    assert!(maximum.len() <= 16_274);
}

#[test]
fn encoder_rejects_common_invariant_and_exact_prebootstrap_violations() {
    let mut command = continuation();
    command.actor = FixedRootCommandActor::Principal(b".invalid".to_vec());
    require_invalid_command(command);

    let mut command = continuation();
    command.tags[0] = tag(MacPurpose::CommandLookupV1, ALLOCATED, 0, 0x61);
    require_invalid_command(command);

    let mut command = continuation();
    command.tags.swap(0, 1);
    require_invalid_command(command);

    let mut command = continuation();
    command.process_instance = [0; 16];
    require_invalid_command(command);

    let mut command = continuation();
    command.phase = 0;
    require_invalid_command(command);

    let mut command = continuation();
    command.retention = FixedRootCommandRetention::Terminal {
        terminal_time: 5,
        expires_at: 5,
    };
    command.safe_result = None;
    require_invalid_command(command);

    let mut command = terminal_bootstrap();
    command.target_binding.as_mut().expect("binding").source = [0x30; 24]
        .into_iter()
        .chain([0u8; 8])
        .collect::<Vec<_>>()
        .try_into()
        .expect("width");
    require_invalid_command(command);

    let mut command = terminal_bootstrap();
    command.target_binding.as_mut().expect("binding").target[24..].fill(0);
    require_invalid_command(command);

    let mut command = terminal_bootstrap();
    command.profile_body.push(0x99);
    require_invalid_command(command);
}

#[test]
fn decoder_rejects_wrong_discriminants_key_layout_and_noncanonical_trailing_bytes() {
    let canonical = encode_fixed_root_command(&codec(), continuation()).expect("canonical wire");
    let actor_length = usize::from(canonical[3]);
    let tags_offset = 4 + actor_length;
    let runtime_offset = tags_offset + 4 * 72;

    let mut wrong_format = canonical.clone();
    wrong_format[0] = 2;
    require_invalid_wire(&wrong_format);

    let mut unknown_operation = canonical.clone();
    unknown_operation[1] = 0;
    require_invalid_wire(&unknown_operation);

    let mut unknown_actor = canonical.clone();
    unknown_actor[2] = 3;
    require_invalid_wire(&unknown_actor);

    let mut zero_key_serial = canonical.clone();
    zero_key_serial[tags_offset + 32..tags_offset + 40].fill(0);
    require_invalid_wire(&zero_key_serial);

    let mut unknown_runtime = canonical.clone();
    unknown_runtime[runtime_offset] = 3;
    require_invalid_wire(&unknown_runtime);

    let mut trailing = canonical;
    trailing.push(0);
    require_invalid_wire(&trailing);
}
