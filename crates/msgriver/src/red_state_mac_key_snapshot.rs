use super::{StateMacKeySnapshotError, compose_state_mac_key_snapshot};
use msgriver_store::{RawHighWaterCell, RawManifestCell, SelectedKeySnapshotRaw};

const SELECTED: [u8; 32] = [0x31; 32];
const PREBOOTSTRAP: [u8; 32] = [0x62; 32];

fn canonical_raw() -> SelectedKeySnapshotRaw {
    SelectedKeySnapshotRaw {
        selected_origin: SELECTED.to_vec(),
        high_waters: (1_i64..=11)
            .map(|purpose| RawHighWaterCell {
                purpose,
                serial_hi: 0,
                serial_lo: 1,
            })
            .collect(),
        manifest_rows: (1_i64..=11)
            .map(|purpose| RawManifestCell {
                purpose,
                origin: if purpose == 11 {
                    PREBOOTSTRAP.to_vec()
                } else {
                    SELECTED.to_vec()
                },
                serial_hi: 0,
                serial_lo: 1,
                status: 1,
                created_at: -1,
            })
            .collect(),
    }
}

fn compose(raw: SelectedKeySnapshotRaw) -> super::StateMacKeySnapshotFacts {
    match compose_state_mac_key_snapshot(raw, PREBOOTSTRAP) {
        Ok(snapshot) => snapshot,
        Err(StateMacKeySnapshotError::MissingStateMacKeySnapshotComposer) => {
            panic!("MissingStateMacKeySnapshotComposer: state_mac_key_snapshot_composer")
        }
        Err(error) => panic!("canonical raw state-key snapshot rejected: {error:?}"),
    }
}

#[test]
fn canonical_raw_snapshot_composes_all_private_facts() {
    let snapshot = compose(canonical_raw());
    assert_eq!(snapshot.selected_origin, SELECTED);
    assert_eq!(snapshot.high_waters.len(), 11);
    assert_eq!(snapshot.manifest_rows.len(), 11);
}

#[test]
fn malformed_raw_cell_is_closed_before_any_selected_state_use() {
    let mut raw = canonical_raw();
    raw.high_waters[0].serial_hi = -1;
    match compose_state_mac_key_snapshot(raw, PREBOOTSTRAP) {
        Err(StateMacKeySnapshotError::MissingStateMacKeySnapshotComposer) => {
            panic!("MissingStateMacKeySnapshotComposer: state_mac_key_snapshot_composer")
        }
        Err(StateMacKeySnapshotError::InvalidSnapshot) => {}
        Ok(_) => panic!("malformed raw snapshot accepted"),
    }
}

#[test]
fn selected_origin_serial_cannot_exceed_its_high_water() {
    let mut raw = canonical_raw();
    raw.manifest_rows[0].serial_lo = 2;
    match compose_state_mac_key_snapshot(raw, PREBOOTSTRAP) {
        Err(StateMacKeySnapshotError::MissingStateMacKeySnapshotComposer) => {
            panic!("MissingStateMacKeySnapshotComposer: state_mac_key_snapshot_composer")
        }
        Err(StateMacKeySnapshotError::InvalidSnapshot) => {}
        Ok(_) => panic!("high-water-violating raw snapshot accepted"),
    }
}

#[test]
fn composition_stays_private_and_has_no_external_capability() {
    let source = include_str!("state_mac_key_snapshot.rs");
    for forbidden in [
        "rusqlite",
        "std::fs",
        "std::path",
        "key_file",
        "pointer",
        "service",
        "release",
        "publication",
    ] {
        assert!(
            !source.contains(forbidden),
            "composition source must not gain {forbidden} capability"
        );
    }
    assert!(source.contains("pub(super) fn compose_state_mac_key_snapshot"));
}
