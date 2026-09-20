use super::{StateMacKeyRelativePathError, state_mac_key_relative_path};
use msgriver_core::canon::{MacKeyId, MacKeyRef, MacPurpose};

fn reference(purpose: MacPurpose, origin: u8, serial: u64) -> MacKeyRef {
    let mut key_id = [origin; 40];
    key_id[32..].copy_from_slice(&serial.to_be_bytes());
    MacKeyRef::new(purpose, MacKeyId::from_bytes(key_id))
}

fn path(reference: MacKeyRef) -> [u8; 90] {
    match state_mac_key_relative_path(reference) {
        Ok(path) => path.0,
        Err(StateMacKeyRelativePathError::MissingStateMacKeyRelativePath) => {
            panic!("MissingStateMacKeyRelativePath: state_mac_key_relative_path")
        }
    }
}

#[test]
fn path_is_exact_for_lowest_purpose_and_mixed_serial_bytes() {
    assert_eq!(
        path(reference(
            MacPurpose::ApiKeyVerifyV1,
            0xab,
            0x0102_0304_0506_0708,
        )),
        *b"mac/01/mk_abababababababababababababababababababababababababababababababab0102030405060708"
    );
}

#[test]
fn path_is_exact_for_highest_closed_purpose() {
    assert_eq!(
        path(reference(MacPurpose::PortableReservationV1, 0, 1)),
        *b"mac/0b/mk_00000000000000000000000000000000000000000000000000000000000000000000000000000001"
    );
}

#[test]
fn path_boundary_stays_private_and_in_memory_only() {
    let source = include_str!("state_mac_key_path.rs");
    for forbidden in [
        "std::fs", "rustix", "openat", "sqlite", "secret", "provider",
    ] {
        assert!(
            !source.contains(forbidden),
            "path derivation must not gain {forbidden} capability"
        );
    }
    assert!(source.contains("pub(super) fn state_mac_key_relative_path"));
}
