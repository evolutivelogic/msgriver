//! Task 0098 frozen crate-private reader bridge contract.

#[test]
fn state_key_reader_bridge_exposes_only_opaque_crate_private_symbols() {
    let root = include_str!("../initialization_key_pair.rs");
    let codec = include_str!("state_mac_key_file.rs");
    for required in [
        "pub(crate) struct JournalIntegrityKey(Zeroizing<[u8; 32]>);",
        "pub(crate) struct StateMacKeySecret(pub(super) Zeroizing<[u8; 32]>);",
        "pub(crate) fn decode_state_mac_key_file(",
    ] {
        assert!(
            root.contains(required) || codec.contains(required),
            "MissingStateMacKeyReaderBridge: {required}"
        );
    }
    for forbidden in [
        "pub struct JournalIntegrityKey",
        "pub fn decode_state_mac_key_file",
    ] {
        assert!(
            !root.contains(forbidden) && !codec.contains(forbidden),
            "reader bridge must not become public: {forbidden}"
        );
    }
}
