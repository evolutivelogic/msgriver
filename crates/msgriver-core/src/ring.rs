//! Pure retained MAC-key-ring state contracts (A-13.2).
//!
//! This module intentionally models public identity and validation evidence
//! only. Key bytes, entropy, files, authenticated publication, and durable
//! dependency lookup remain outside the core.

use crate::canon::{MacKeyId, MacKeyRef, MacPurpose};
use crate::{CoreError, RejectClass};

/// The only transition classes relevant to pure retained-capacity accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingTransition {
    RetireDependencyFree,
    CoveringWindowElapsed,
    BranchCopy,
    Rotate,
    Other,
}

/// Ordered pure stages of the rotation precondition pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationStage {
    SelectedOriginIntegrity,
    SerialExhaustion,
    RetainedCapacity,
    CheckedAllocation,
    Entropy,
}

/// Origin classification at an authenticated blank-restore boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginClassification {
    SelectedOrigin,
    ImportedKeyOrigin,
}

/// Closed load/allocator outcome used before a selection is attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingIntegrity {
    Valid,
    Corruption,
}

/// One of the pure ring observables frozen by S11.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingObservation {
    CapacityRecovery {
        purpose: MacPurpose,
        transition: RingTransition,
    },
    BranchSlots {
        prior: [u8; 32],
        post: [u8; 32],
    },
    RotationOrder {
        selected_origin_valid: bool,
        serial_available: bool,
        retained_capacity_available: bool,
        checked_allocation_available: bool,
        entropy_available: bool,
    },
    PurposeRegistration {
        first: MacKeyRef,
        second: MacKeyRef,
    },
    Origin {
        key_id: MacKeyId,
        foreign_origin: bool,
    },
    ImportedAuthority {
        classification: OriginClassification,
    },
    JournalIntegrity {
        ring_contains_journal_key: bool,
        journal_has_mac_key_id: bool,
        plan_digest: [u8; 32],
    },
    LoadEvidence {
        limb_above_high_water: bool,
        duplicated_high_water: bool,
    },
    AllocatorEvidence {
        missing: bool,
        lower: bool,
        duplicate_purpose: bool,
        foreign_origin_derived: bool,
    },
}

/// Result vocabulary corresponding to [`RingObservation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingObservationResult {
    CapacityRecovered(bool),
    SlotDigest([u8; 32]),
    RotationFailure(Option<RotationStage>),
    PurposeRegistration {
        valid: bool,
        paths_distinct: bool,
    },
    Origin(OriginClassification),
    ImportedAuthority {
        local_allocator_witness: bool,
        purpose_high_water_evidence: bool,
        fixed_root_corruption: bool,
    },
    JournalIntegrity {
        ring_contains_journal_key: bool,
        journal_has_mac_key_id: bool,
        plan_digest: [u8; 32],
    },
    Integrity(RingIntegrity),
}

/// Evaluate an S11 retained-key-ring observation.
///
/// This evaluates only the value-level invariants represented in
/// [`RingObservation`]. The service layer remains responsible for the durable
/// preconditions and effects that surround these decisions.
pub fn observe(observation: RingObservation) -> Result<RingObservationResult, CoreError> {
    let result = match observation {
        RingObservation::CapacityRecovery {
            purpose: _,
            transition,
        } => RingObservationResult::CapacityRecovered(matches!(
            transition,
            RingTransition::RetireDependencyFree | RingTransition::CoveringWindowElapsed
        )),
        RingObservation::BranchSlots { prior: _, post } => RingObservationResult::SlotDigest(post),
        RingObservation::RotationOrder {
            selected_origin_valid,
            serial_available,
            retained_capacity_available,
            checked_allocation_available,
            entropy_available,
        } => {
            let first_failure = if !selected_origin_valid {
                Some(RotationStage::SelectedOriginIntegrity)
            } else if !serial_available {
                Some(RotationStage::SerialExhaustion)
            } else if !retained_capacity_available {
                Some(RotationStage::RetainedCapacity)
            } else if !checked_allocation_available {
                Some(RotationStage::CheckedAllocation)
            } else if !entropy_available {
                Some(RotationStage::Entropy)
            } else {
                None
            };
            RingObservationResult::RotationFailure(first_failure)
        }
        RingObservation::PurposeRegistration { first, second } => {
            let purpose_qualified = first.purpose() != second.purpose();
            RingObservationResult::PurposeRegistration {
                valid: purpose_qualified && first.key_id() == second.key_id(),
                paths_distinct: purpose_qualified,
            }
        }
        RingObservation::Origin {
            key_id: _,
            foreign_origin,
        } => RingObservationResult::Origin(if foreign_origin {
            OriginClassification::ImportedKeyOrigin
        } else {
            OriginClassification::SelectedOrigin
        }),
        RingObservation::ImportedAuthority { classification } => {
            let imported = classification == OriginClassification::ImportedKeyOrigin;
            RingObservationResult::ImportedAuthority {
                local_allocator_witness: !imported,
                purpose_high_water_evidence: !imported,
                fixed_root_corruption: false,
            }
        }
        RingObservation::JournalIntegrity {
            ring_contains_journal_key,
            journal_has_mac_key_id,
            plan_digest,
        } => RingObservationResult::JournalIntegrity {
            ring_contains_journal_key,
            journal_has_mac_key_id,
            plan_digest,
        },
        RingObservation::LoadEvidence {
            limb_above_high_water,
            duplicated_high_water,
        } => RingObservationResult::Integrity(if limb_above_high_water || duplicated_high_water {
            RingIntegrity::Corruption
        } else {
            RingIntegrity::Valid
        }),
        RingObservation::AllocatorEvidence {
            missing,
            lower,
            duplicate_purpose,
            foreign_origin_derived,
        } => RingObservationResult::Integrity(
            if missing || lower || duplicate_purpose || foreign_origin_derived {
                RingIntegrity::Corruption
            } else {
                RingIntegrity::Valid
            },
        ),
    };
    Ok(result)
}

/// Keep the purpose vocabulary referenced in this module's public contract.
/// This avoids a future ring implementation accidentally accepting a raw
/// integer in place of its closed `MacPurpose` discriminant.
pub const fn purpose_is_closed(_purpose: MacPurpose) -> bool {
    true
}

/// Advance a per-purpose retained-ring MAC serial high-water by exactly one
/// (PR-127) through checked increment: the successor is returned only when it
/// is representable. At the ceiling it returns the stable
/// `mac_key_serial_exhausted` core rejection before any effect; it does not
/// wrap, saturate, panic, or represent a branch transition as freeing a
/// retained-ring slot. Per-purpose exhaustion remains recoverable through a
/// supported branch transition that allocates a fresh key origin.
pub fn serial_next(high_water: u64) -> Result<u64, CoreError> {
    match high_water.checked_add(1) {
        Some(next) => Ok(next),
        None => Err(CoreError::reject(RejectClass::MacKeySerialExhausted)),
    }
}
