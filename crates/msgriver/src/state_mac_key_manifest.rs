//! Task 0087 private state-key manifest semantic-validation frontier.
//!
//! This crate-private child accepts already-decoded rows only and performs no
//! external I/O or selected-state transition.

#![allow(dead_code)]

use crate::state_mac_key_manifest_row::{StateMacKeyManifestRow, StateMacKeyManifestStatus};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StateMacKeyManifestError {
    MissingStateMacKeyManifestValidator,
    OutOfOrderOrDuplicate,
    TooManyRowsForPurpose,
    MissingActivePurpose,
    MultipleActiveRowsForPurpose,
    ActiveOriginMismatch,
}

pub(super) fn validate_state_mac_key_manifest(
    rows: &[StateMacKeyManifestRow],
    selected_origin: [u8; 32],
    prebootstrap_origin: [u8; 32],
) -> Result<(), StateMacKeyManifestError> {
    let mut previous = None;
    let mut rows_per_purpose = [0_u8; 11];
    let mut active_per_purpose = [0_u8; 11];

    for row in rows {
        let purpose = row.reference.purpose() as u8;
        let key_id = *row.reference.key_id().as_bytes();
        let order = (purpose, key_id);
        if previous.is_some_and(|prior| order <= prior) {
            return Err(StateMacKeyManifestError::OutOfOrderOrDuplicate);
        }
        previous = Some(order);

        let purpose_index = usize::from(purpose - 1);
        rows_per_purpose[purpose_index] += 1;
        if rows_per_purpose[purpose_index] > 16 {
            return Err(StateMacKeyManifestError::TooManyRowsForPurpose);
        }

        if row.status == StateMacKeyManifestStatus::Active {
            active_per_purpose[purpose_index] += 1;
            if active_per_purpose[purpose_index] > 1 {
                return Err(StateMacKeyManifestError::MultipleActiveRowsForPurpose);
            }

            let expected_origin = if purpose == 11 {
                prebootstrap_origin
            } else {
                selected_origin
            };
            if key_id[..32] != expected_origin {
                return Err(StateMacKeyManifestError::ActiveOriginMismatch);
            }
        }
    }

    if active_per_purpose.into_iter().any(|count| count != 1) {
        return Err(StateMacKeyManifestError::MissingActivePurpose);
    }
    Ok(())
}

#[cfg(test)]
#[path = "red_state_mac_key_manifest.rs"]
mod red_state_mac_key_manifest;
