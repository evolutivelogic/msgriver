use super::{
    FixedRootCommand, FixedRootCommandActor, FixedRootCommandCodec, FixedRootCommandError,
    FixedRootCommandOperation, FixedRootCommandRetention, FixedRootCommandRuntime,
    FixedRootCommandTag, encode_fixed_root_command,
};
use msgriver_core::canon::{MacKeyId, MacKeyRef, MacPurpose};

const ALLOCATED: [u8; 32] = [
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0, 0, 0, 0, 0, 0, 0, 1,
];

fn tag(purpose: MacPurpose, origin: [u8; 32], serial: u64) -> FixedRootCommandTag {
    let mut key = [0; 40];
    key[..32].copy_from_slice(&origin);
    key[32..].copy_from_slice(&serial.to_be_bytes());
    FixedRootCommandTag {
        key: MacKeyRef::new(purpose, MacKeyId::from_bytes(key)),
        tag: [1; 32],
    }
}

fn bootstrap_command(expected_prebootstrap_origin: [u8; 32]) -> FixedRootCommand {
    FixedRootCommand {
        operation: FixedRootCommandOperation::BootstrapCreate,
        actor: FixedRootCommandActor::StateOwner,
        tags: [
            tag(MacPurpose::CommandLookupV1, ALLOCATED, 1),
            tag(MacPurpose::CommandSemanticFingerprintV1, ALLOCATED, 2),
            tag(MacPurpose::CommandPhaseFingerprintV1, ALLOCATED, 3),
            tag(
                MacPurpose::PortableReservationV1,
                expected_prebootstrap_origin,
                4,
            ),
        ],
        runtime: FixedRootCommandRuntime::Maintenance,
        process_instance: [1; 16],
        original_deadline: None,
        phase: 1,
        retention: FixedRootCommandRetention::Continuation,
        safe_result: None,
        target_binding: Some(super::FixedRootCommandTargetBinding {
            source: expected_prebootstrap_origin,
            target: expected_prebootstrap_origin,
            source_generation: None,
            target_generation: None,
            parent_witness: None,
        }),
        profile_body: vec![],
    }
}

#[test]
fn injected_prebootstrap_origin_must_itself_have_serial_zero() {
    let invalid_expected_origin = [0x31; 32];
    assert!(matches!(
        encode_fixed_root_command(
            &FixedRootCommandCodec::new(invalid_expected_origin),
            bootstrap_command(invalid_expected_origin),
        ),
        Err(FixedRootCommandError::InvalidFixedRootCommand)
    ));
}
