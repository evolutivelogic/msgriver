use super::{
    FixedRootCommand, FixedRootCommandActor, FixedRootCommandCodec, FixedRootCommandError,
    FixedRootCommandOperation, FixedRootCommandRetention, FixedRootCommandRuntime,
    FixedRootCommandTag, FixedRootCommandTargetBinding, encode_fixed_root_command,
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

fn tag(purpose: MacPurpose, origin: [u8; 32], serial: u64, byte: u8) -> FixedRootCommandTag {
    let mut key = [0; 40];
    key[..32].copy_from_slice(&origin);
    key[32..].copy_from_slice(&serial.to_be_bytes());
    FixedRootCommandTag {
        key: MacKeyRef::new(purpose, MacKeyId::from_bytes(key)),
        tag: [byte; 32],
    }
}

fn command() -> FixedRootCommand {
    FixedRootCommand {
        operation: FixedRootCommandOperation::RecoveryKeyGenerate,
        actor: FixedRootCommandActor::Principal(b"principal-1".to_vec()),
        tags: [
            tag(MacPurpose::CommandLookupV1, ALLOCATED, 1, 1),
            tag(MacPurpose::CommandSemanticFingerprintV1, ALLOCATED, 2, 2),
            tag(MacPurpose::CommandPhaseFingerprintV1, ALLOCATED, 3, 3),
            tag(MacPurpose::PortableReservationV1, PRE_BOOTSTRAP, 4, 4),
        ],
        runtime: FixedRootCommandRuntime::Normal,
        process_instance: [1; 16],
        original_deadline: None,
        phase: 1,
        retention: FixedRootCommandRetention::Continuation,
        safe_result: None,
        target_binding: Some(FixedRootCommandTargetBinding {
            source: ALLOCATED,
            target: ALLOCATED,
            source_generation: None,
            target_generation: None,
            parent_witness: None,
        }),
        profile_body: vec![],
    }
}

fn require_invalid(command: FixedRootCommand) {
    assert!(matches!(
        encode_fixed_root_command(&FixedRootCommandCodec::new(PRE_BOOTSTRAP), command),
        Err(FixedRootCommandError::InvalidFixedRootCommand)
    ));
}

#[test]
fn common_origin_invariants_require_exact_prebootstrap_and_equal_continuation_binding() {
    let mut wrong_portable_origin = command();
    let mut different_prebootstrap = PRE_BOOTSTRAP;
    different_prebootstrap[0] ^= 1;
    wrong_portable_origin.tags[3] = tag(
        MacPurpose::PortableReservationV1,
        different_prebootstrap,
        4,
        4,
    );
    require_invalid(wrong_portable_origin);

    let mut unequal_continuation = command();
    unequal_continuation
        .target_binding
        .as_mut()
        .expect("binding")
        .target = [
        0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43,
        0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0, 0, 0, 0, 0, 0, 0, 2,
    ];
    require_invalid(unequal_continuation);
}
