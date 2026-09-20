//! Task 0094 private raw selected-key snapshot composition frontier.

#![allow(dead_code)]

use crate::state_mac_key_high_water::StateMacKeyHighWater;
use crate::state_mac_key_high_water::validate_state_mac_key_high_water;
use crate::state_mac_key_manifest::validate_state_mac_key_manifest;
use crate::state_mac_key_manifest_row::{
    RawStateMacKeyManifestRow, StateMacKeyManifestRow, decode_state_mac_key_manifest_row,
};
use crate::state_mac_key_meta_row::{RawStateMacKeyHighWater, decode_state_mac_key_meta_rows};
use msgriver_store::SelectedKeySnapshotRaw;

pub(super) struct StateMacKeySnapshotFacts {
    pub(super) selected_origin: [u8; 32],
    pub(super) high_waters: Vec<StateMacKeyHighWater>,
    pub(super) manifest_rows: Vec<StateMacKeyManifestRow>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StateMacKeySnapshotError {
    MissingStateMacKeySnapshotComposer,
    InvalidSnapshot,
}

pub(super) fn compose_state_mac_key_snapshot(
    raw: SelectedKeySnapshotRaw,
    prebootstrap_origin: [u8; 32],
) -> Result<StateMacKeySnapshotFacts, StateMacKeySnapshotError> {
    let meta = decode_state_mac_key_meta_rows(
        raw.selected_origin,
        raw.high_waters
            .into_iter()
            .map(|row| RawStateMacKeyHighWater {
                purpose: row.purpose,
                serial_hi: row.serial_hi,
                serial_lo: row.serial_lo,
            })
            .collect(),
    )
    .map_err(|_| StateMacKeySnapshotError::InvalidSnapshot)?;
    let manifest_rows = raw
        .manifest_rows
        .into_iter()
        .map(|row| {
            decode_state_mac_key_manifest_row(RawStateMacKeyManifestRow {
                purpose: row.purpose,
                origin: row.origin,
                serial_hi: row.serial_hi,
                serial_lo: row.serial_lo,
                status: row.status,
                created_at: row.created_at,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StateMacKeySnapshotError::InvalidSnapshot)?;
    validate_state_mac_key_manifest(&manifest_rows, meta.selected_origin, prebootstrap_origin)
        .map_err(|_| StateMacKeySnapshotError::InvalidSnapshot)?;
    validate_state_mac_key_high_water(&manifest_rows, meta.selected_origin, &meta.high_waters)
        .map_err(|_| StateMacKeySnapshotError::InvalidSnapshot)?;
    Ok(StateMacKeySnapshotFacts {
        selected_origin: meta.selected_origin,
        high_waters: meta.high_waters,
        manifest_rows,
    })
}

#[cfg(test)]
#[path = "red_state_mac_key_snapshot.rs"]
mod red_state_mac_key_snapshot;
