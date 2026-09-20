use super::harness::{CompareResult, Oracle, TestCaseError, case, outcome};
use msgriver_core::Frontier;
use msgriver_core::canon::{MacKeyId, MacKeyRef, MacPurpose};
use msgriver_core::ring::{
    OriginClassification, RingIntegrity, RingObservation, RingObservationResult, RingTransition,
    RotationStage, observe,
};

const DIGEST: [u8; 32] = [0x5a; 32];
const PLAN_DIGEST: [u8; 32] = [0xa1; 32];

fn key_id(fill: u8) -> MacKeyId {
    MacKeyId::from_bytes([fill; 40])
}

fn capacity(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    for (transition, expected) in [
        (RingTransition::RetireDependencyFree, true),
        (RingTransition::CoveringWindowElapsed, true),
        (RingTransition::BranchCopy, false),
        (RingTransition::Rotate, false),
        (RingTransition::Other, false),
    ] {
        match outcome(
            observe(RingObservation::CapacityRecovery {
                purpose: MacPurpose::IdempotencyLookupV1,
                transition,
            }),
            oracle,
            |value| *value == RingObservationResult::CapacityRecovered(expected),
        )? {
            CompareResult::Pass => {}
            other => return Ok(other),
        }
    }
    Ok(CompareResult::Pass)
}

fn slots(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    outcome(
        observe(RingObservation::BranchSlots {
            prior: DIGEST,
            post: DIGEST,
        }),
        oracle,
        |value| *value == RingObservationResult::SlotDigest(DIGEST),
    )
}

fn rotation(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let rows = [
        (
            false,
            true,
            true,
            true,
            true,
            Some(RotationStage::SelectedOriginIntegrity),
        ),
        (
            true,
            false,
            true,
            true,
            true,
            Some(RotationStage::SerialExhaustion),
        ),
        (
            true,
            true,
            false,
            true,
            true,
            Some(RotationStage::RetainedCapacity),
        ),
        (
            true,
            true,
            true,
            false,
            true,
            Some(RotationStage::CheckedAllocation),
        ),
        (true, true, true, true, false, Some(RotationStage::Entropy)),
        (true, true, true, true, true, None),
    ];
    for (selected, serial, capacity, allocation, entropy, expected) in rows {
        match outcome(
            observe(RingObservation::RotationOrder {
                selected_origin_valid: selected,
                serial_available: serial,
                retained_capacity_available: capacity,
                checked_allocation_available: allocation,
                entropy_available: entropy,
            }),
            oracle,
            |value| *value == RingObservationResult::RotationFailure(expected),
        )? {
            CompareResult::Pass => {}
            other => return Ok(other),
        }
    }
    Ok(CompareResult::Pass)
}

fn dual_purpose(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    outcome(
        observe(RingObservation::PurposeRegistration {
            first: MacKeyRef::new(MacPurpose::ApiKeyVerifyV1, key_id(0x20)),
            second: MacKeyRef::new(MacPurpose::IdempotencyLookupV1, key_id(0x20)),
        }),
        oracle,
        |value| {
            *value
                == RingObservationResult::PurposeRegistration {
                    valid: true,
                    paths_distinct: true,
                }
        },
    )
}

fn imported_origin(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    outcome(
        observe(RingObservation::Origin {
            key_id: key_id(0x33),
            foreign_origin: true,
        }),
        oracle,
        |value| *value == RingObservationResult::Origin(OriginClassification::ImportedKeyOrigin),
    )
}

fn imported_authority(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    outcome(
        observe(RingObservation::ImportedAuthority {
            classification: OriginClassification::ImportedKeyOrigin,
        }),
        oracle,
        |value| {
            *value
                == RingObservationResult::ImportedAuthority {
                    local_allocator_witness: false,
                    purpose_high_water_evidence: false,
                    fixed_root_corruption: false,
                }
        },
    )
}

fn journal_key(oracle: &Oracle, has_mac_key_id: bool) -> Result<CompareResult, TestCaseError> {
    outcome(
        observe(RingObservation::JournalIntegrity {
            ring_contains_journal_key: false,
            journal_has_mac_key_id: has_mac_key_id,
            plan_digest: PLAN_DIGEST,
        }),
        oracle,
        |value| {
            *value
                == RingObservationResult::JournalIntegrity {
                    ring_contains_journal_key: false,
                    journal_has_mac_key_id: false,
                    plan_digest: PLAN_DIGEST,
                }
        },
    )
}

fn load_defects(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    for (above, duplicate, expected) in [
        (true, false, RingIntegrity::Corruption),
        (false, true, RingIntegrity::Corruption),
        (false, false, RingIntegrity::Valid),
    ] {
        match outcome(
            observe(RingObservation::LoadEvidence {
                limb_above_high_water: above,
                duplicated_high_water: duplicate,
            }),
            oracle,
            |value| *value == RingObservationResult::Integrity(expected),
        )? {
            CompareResult::Pass => {}
            other => return Ok(other),
        }
    }
    Ok(CompareResult::Pass)
}

fn allocator_defects(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    for observation in [
        RingObservation::AllocatorEvidence {
            missing: true,
            lower: false,
            duplicate_purpose: false,
            foreign_origin_derived: false,
        },
        RingObservation::AllocatorEvidence {
            missing: false,
            lower: true,
            duplicate_purpose: false,
            foreign_origin_derived: false,
        },
        RingObservation::AllocatorEvidence {
            missing: false,
            lower: false,
            duplicate_purpose: true,
            foreign_origin_derived: false,
        },
        RingObservation::AllocatorEvidence {
            missing: false,
            lower: false,
            duplicate_purpose: false,
            foreign_origin_derived: true,
        },
    ] {
        match outcome(observe(observation), oracle, |value| {
            *value == RingObservationResult::Integrity(RingIntegrity::Corruption)
        })? {
            CompareResult::Pass => {}
            other => return Ok(other),
        }
    }
    Ok(CompareResult::Pass)
}

#[test]
fn core_s11_ring_capacity_recovery() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-RING-CAPACITY-RECOVERY",
        "tests/fixtures/oracles/core/core-s11-ring-capacity-recovery.txt",
        "8eceb4120002e507d316060d418d182bfc2dd7f06ba992fd10c7c040e69c85a4",
        Frontier::KeyRingState,
        capacity,
    )
}

#[test]
fn core_s11_ring_slots_stable() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-RING-SLOTS-STABLE",
        "tests/fixtures/oracles/core/core-s11-ring-slots-stable.txt",
        "adc865a2af412ae8380fb1316aef34ea1dbbe852e5ca8b64c0d24f1c8f4a22f7",
        Frontier::KeyRingState,
        slots,
    )
}

#[test]
fn core_s11_ring_rotation_order() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-RING-ROTATION-ORDER",
        "tests/fixtures/oracles/core/core-s11-ring-rotation-order.txt",
        "0bddc4dcfd93f1f5e7cbbe3b2da8e919fcb1e30e6d279bbdf125ee0da5327cd1",
        Frontier::KeyRingState,
        rotation,
    )
}

#[test]
fn core_s11_ring_keyid_dual_purpose() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-RING-KEYID-DUAL-PURPOSE",
        "tests/fixtures/oracles/core/core-s11-ring-keyid-dual-purpose.txt",
        "fde7f8a047b6ad93ba5c45156c06411ea7ae2728052cde32e6a5bac1702c866b",
        Frontier::KeyRingState,
        dual_purpose,
    )
}

#[test]
fn core_s11_ring_imported_origin() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-RING-IMPORTED-ORIGIN",
        "tests/fixtures/oracles/core/core-s11-ring-imported-origin.txt",
        "489fa9e1bd899177189816818214a946572e37cf76f2b11390f79698753dc90d",
        Frontier::KeyRingState,
        imported_origin,
    )
}

#[test]
fn core_s11_ring_imported_no_authority() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-RING-IMPORTED-NO-AUTHORITY",
        "tests/fixtures/oracles/core/core-s11-ring-imported-no-authority.txt",
        "e6b4b10a9be18082cf271ccaa676ca2cd648b120691a00f9b456361c50a8b949",
        Frontier::KeyRingState,
        imported_authority,
    )
}

#[test]
fn core_s11_ring_journalkey_excluded() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-RING-JOURNALKEY-EXCLUDED",
        "tests/fixtures/oracles/core/core-s11-ring-journalkey-excluded.txt",
        "f464cf55c8165966d87c0a4ae75523285a1a322e5ee3bbe1212a3cf288bfb220",
        Frontier::KeyRingState,
        |oracle| journal_key(oracle, false),
    )
}

#[test]
fn core_s11_ring_journalkey_no_macid() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-RING-JOURNALKEY-NO-MACID",
        "tests/fixtures/oracles/core/core-s11-ring-journalkey-no-macid.txt",
        "23cf5ac1a922839e3895458d743cac712df67a82119407dd3ea1bd59ad49b04a",
        Frontier::KeyRingState,
        |oracle| journal_key(oracle, false),
    )
}

#[test]
fn core_s11_ring_load_defects() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-RING-LOAD-DEFECTS",
        "tests/fixtures/oracles/core/core-s11-ring-load-defects.txt",
        "c06f1d64314d3d857ab53d7dd9c5dbeb45443f7c5b92719ed8f2fd1336b7e655",
        Frontier::KeyRingState,
        load_defects,
    )
}

#[test]
fn core_s11_ring_alloc_defects() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-RING-ALLOC-DEFECTS",
        "tests/fixtures/oracles/core/core-s11-ring-alloc-defects.txt",
        "0fb406d9e68ba600e8de7cb382fdc9cf5a6e9dc84755dc54aded8d548eb16f6a",
        Frontier::KeyRingState,
        allocator_defects,
    )
}
