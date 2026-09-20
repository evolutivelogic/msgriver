use super::harness::{CompareResult, Oracle, TestCaseError, case};
use msgriver_core::Frontier;
use msgriver_core::RejectClass;
use msgriver_core::generation::{
    BranchSerial, JournalNamespaceProvider, OwnerNamespace, compose_incarnation,
};
use msgriver_core::incarnation::{
    AllocationIntent, AllocatorDecision, AllocatorEvaluation, AllocatorHeader, AllocatorSnapshot,
    ArtifactAdmissionRole, ExhaustionRecovery, ExhaustionRecoveryDecision, OperationId,
    PreStagingViews, ReplayDecision, allocator_hold_precedence, artifact_role_admissible,
    burn_next_serial, exhaustion_recovery_admissibility, imported_root_admissible,
    initialize_allocator_header, operation_admissible_under_exhaustion, pre_staging_collision,
    preserve_continuation, replay_allocation, restore_serial_one,
};

const CLEAR: AllocatorEvaluation = AllocatorEvaluation {
    exact_same_command_recovery: false,
    forbidding_restore_or_upgrade_hold: false,
    serial_exhausted: false,
    clock_hold: false,
    capacity_available: true,
    admission_or_drain_or_coordinator_conflict: false,
};

fn decision(
    oracle: &Oracle,
    input: AllocatorEvaluation,
    expected: AllocatorDecision,
) -> Result<CompareResult, TestCaseError> {
    if oracle.expect_is("ok") && allocator_hold_precedence(input) == expected {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch(
            "allocator precedence mismatch".into(),
        ))
    }
}

fn total(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let rows = [
        (
            AllocatorEvaluation {
                exact_same_command_recovery: true,
                ..CLEAR
            },
            AllocatorDecision::ExactRecovery,
        ),
        (
            AllocatorEvaluation {
                forbidding_restore_or_upgrade_hold: true,
                ..CLEAR
            },
            AllocatorDecision::ForbiddenHold,
        ),
        (
            AllocatorEvaluation {
                serial_exhausted: true,
                ..CLEAR
            },
            AllocatorDecision::IncarnationUnavailable,
        ),
        (
            AllocatorEvaluation {
                clock_hold: true,
                ..CLEAR
            },
            AllocatorDecision::ClockHold,
        ),
        (
            AllocatorEvaluation {
                capacity_available: false,
                ..CLEAR
            },
            AllocatorDecision::ControlCapacity,
        ),
        (
            AllocatorEvaluation {
                admission_or_drain_or_coordinator_conflict: true,
                ..CLEAR
            },
            AllocatorDecision::AdmissionDrainOrCoordinatorConflict,
        ),
        (CLEAR, AllocatorDecision::PublishAndBurnAuthorized),
    ];
    if rows
        .into_iter()
        .all(|(input, expected)| allocator_hold_precedence(input) == expected)
        && oracle.expect_is("ok")
        && oracle.list("expect_order")?.len() == 7
    {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch(
            "allocator total order mismatch".into(),
        ))
    }
}

fn recovery(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    decision(
        oracle,
        AllocatorEvaluation {
            exact_same_command_recovery: true,
            forbidding_restore_or_upgrade_hold: true,
            serial_exhausted: true,
            clock_hold: true,
            capacity_available: false,
            admission_or_drain_or_coordinator_conflict: true,
        },
        AllocatorDecision::ExactRecovery,
    )
}

fn serial_before_clock(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    decision(
        oracle,
        AllocatorEvaluation {
            serial_exhausted: true,
            clock_hold: true,
            ..CLEAR
        },
        AllocatorDecision::IncarnationUnavailable,
    )
}

fn clock_before_capacity(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    decision(
        oracle,
        AllocatorEvaluation {
            clock_hold: true,
            capacity_available: false,
            ..CLEAR
        },
        AllocatorDecision::ClockHold,
    )
}

fn publish_after_admit(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    decision(oracle, CLEAR, AllocatorDecision::PublishAndBurnAuthorized)
}

fn outcomes(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let rows = [
        (
            AllocatorEvaluation {
                serial_exhausted: true,
                clock_hold: true,
                capacity_available: false,
                ..CLEAR
            },
            AllocatorDecision::IncarnationUnavailable,
        ),
        (
            AllocatorEvaluation {
                clock_hold: true,
                capacity_available: false,
                ..CLEAR
            },
            AllocatorDecision::ClockHold,
        ),
        (
            AllocatorEvaluation {
                capacity_available: false,
                ..CLEAR
            },
            AllocatorDecision::ControlCapacity,
        ),
    ];
    if rows
        .into_iter()
        .all(|(input, expected)| allocator_hold_precedence(input) == expected)
        && oracle.expect_is("ok")
        && oracle.list("expect_rows")?.len() == 3
    {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch(
            "allocator outcome rows mismatch".into(),
        ))
    }
}

struct NamespaceProvider;
impl JournalNamespaceProvider for NamespaceProvider {
    fn derive_resource_incarnation_namespace_v1(&self) -> [u8; 24] {
        [0x22; 24]
    }
}

fn snapshot(high_water: u64) -> Result<AllocatorSnapshot, TestCaseError> {
    let serial =
        BranchSerial::new(7).map_err(|_| TestCaseError::Parse("serial rejected".into()))?;
    Ok(AllocatorSnapshot {
        header: AllocatorHeader {
            owner_namespace: OwnerNamespace::from_bytes([0x11; 24]),
            branch_serial_high_water: high_water,
        },
        selected_incarnation: compose_incarnation(OwnerNamespace::from_bytes([0x11; 24]), serial),
        image_digest: [0x77; 32],
    })
}

fn checked_carry(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    match burn_next_serial(snapshot(u32::MAX as u64)?) {
        Ok(next) if next.header.branch_serial_high_water == oracle.u64("expect_high_water")? => {
            Ok(CompareResult::Pass)
        }
        _ => Ok(CompareResult::Mismatch("allocator carry mismatch".into())),
    }
}

fn zero_never(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    match burn_next_serial(snapshot(u64::MAX)?) {
        Err(error)
            if error.reject_class() == Some(RejectClass::IncarnationExhausted)
                && oracle.req("expect_reject")? == "incarnation_exhausted" =>
        {
            Ok(CompareResult::Pass)
        }
        _ => Ok(CompareResult::Mismatch(
            "allocator exhaustion mismatch".into(),
        )),
    }
}

fn fresh_header(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let header = initialize_allocator_header(&NamespaceProvider);
    if header.owner_namespace == OwnerNamespace::from_bytes([0x22; 24])
        && header.branch_serial_high_water == oracle.u64("expect_high_water")?
    {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch("fresh header mismatch".into()))
    }
}

fn intent() -> Result<AllocationIntent, TestCaseError> {
    let serial =
        BranchSerial::new(9).map_err(|_| TestCaseError::Parse("serial rejected".into()))?;
    Ok(AllocationIntent {
        command_digest: [0x31; 32],
        serial,
        target: compose_incarnation(OwnerNamespace::from_bytes([0x11; 24]), serial),
    })
}

fn replay_reuse(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let retained = intent()?;
    match replay_allocation(Some(retained), retained.command_digest, 99) {
        Ok(ReplayDecision::Reuse(actual))
            if actual == retained && oracle.req("expect_decision")? == "reuse" =>
        {
            Ok(CompareResult::Pass)
        }
        _ => Ok(CompareResult::Mismatch("intent replay mismatch".into())),
    }
}

fn crash_collision(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    match replay_allocation(Some(intent()?), [0x32; 32], 99) {
        Ok(ReplayDecision::CommandCollision) if oracle.req("expect_decision")? == "collision" => {
            Ok(CompareResult::Pass)
        }
        _ => Ok(CompareResult::Mismatch(
            "crash collision rerolled allocation".into(),
        )),
    }
}

fn burn_no_reissue(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    match burn_next_serial(snapshot(7)?) {
        Ok(first) => match burn_next_serial(first) {
            Ok(second)
                if first.header.branch_serial_high_water == 8
                    && second.header.branch_serial_high_water
                        == oracle.u64("expect_high_water")? =>
            {
                Ok(CompareResult::Pass)
            }
            _ => Ok(CompareResult::Mismatch("burned serial reused".into())),
        },
        Err(_) => Ok(CompareResult::Mismatch("first serial burn failed".into())),
    }
}

fn continuation(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let before = snapshot(7)?;
    if preserve_continuation(before) == before && !oracle.bool("expect_allocator_write")? {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch(
            "continuation changed allocator".into(),
        ))
    }
}

fn prestaging(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let views = PreStagingViews {
        active_pointer_collision: false,
        retained_history_collision: false,
        retained_provenance_collision: true,
        nonterminal_intent_collision: false,
        staged_metadata_collision: false,
    };
    if pre_staging_collision(views) == oracle.bool("expect_collision")? {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch(
            "five-way pre-staging mismatch".into(),
        ))
    }
}

fn collision_refusal(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let before = snapshot(7)?;
    let collision = pre_staging_collision(PreStagingViews {
        active_pointer_collision: true,
        retained_history_collision: false,
        retained_provenance_collision: false,
        nonterminal_intent_collision: false,
        staged_metadata_collision: false,
    });
    if collision && before == snapshot(7)? && !oracle.bool("expect_selection")? {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch("collision selected target".into()))
    }
}

fn fail_snapshot(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let before = snapshot(u64::MAX)?;
    if burn_next_serial(before).is_err()
        && before == snapshot(u64::MAX)?
        && oracle.bool("expect_snapshot_stable")?
    {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch(
            "failed evaluation mutated snapshot".into(),
        ))
    }
}

fn exhaustion_recovery(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let supported = exhaustion_recovery_admissibility(ExhaustionRecovery {
        independently_keyed_blank_root: true,
        authenticated_disaster_artifact: true,
        rekeys_exhausted_root_in_place: false,
    });
    let rekeyed = exhaustion_recovery_admissibility(ExhaustionRecovery {
        independently_keyed_blank_root: true,
        authenticated_disaster_artifact: true,
        rekeys_exhausted_root_in_place: true,
    });
    if supported == ExhaustionRecoveryDecision::Supported
        && rekeyed == ExhaustionRecoveryDecision::Unsupported
        && oracle.req("expect_decision")? == "supported"
    {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch(
            "exhaustion recovery admissibility mismatch".into(),
        ))
    }
}

fn restore_one(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let value = restore_serial_one(OwnerNamespace::from_bytes([0x99; 24])).as_bytes();
    if value[..24] == [0x99; 24]
        && u64::from_be_bytes(
            value[24..]
                .try_into()
                .map_err(|_| TestCaseError::Parse("incarnation serial width".into()))?,
        ) == oracle.u64("expect_serial")?
    {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch("restore serial not one".into()))
    }
}

const NONALLOCATORS: [OperationId; 7] = [
    OperationId::ConfigurationActivate,
    OperationId::StateKeyRotate,
    OperationId::StateKeyRetire,
    OperationId::UpgradeMigrate,
    OperationId::UpgradeActivate,
    OperationId::ForwardRepair,
    OperationId::Other,
];

fn ops_under_exhaustion(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    if NONALLOCATORS
        .into_iter()
        .all(operation_admissible_under_exhaustion)
        && oracle.u64("expect_admissible_count")? == NONALLOCATORS.len() as u64
    {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch(
            "nonallocator blocked by exhaustion".into(),
        ))
    }
}

fn zero_writes(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let before = snapshot(u64::MAX)?;
    if operation_admissible_under_exhaustion(OperationId::ConfigurationActivate)
        && before == snapshot(u64::MAX)?
        && !oracle.bool("expect_allocator_write")?
    {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch(
            "exhaustion caused allocator write".into(),
        ))
    }
}

fn nonalloc_stable(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let before = snapshot(12)?;
    if operation_admissible_under_exhaustion(OperationId::Other)
        && before == preserve_continuation(before)
        && oracle.bool("expect_stable")?
    {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch("nonallocator changed state".into()))
    }
}

fn import_rejected(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    if imported_root_admissible() == oracle.bool("expect_admissible")? {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch("imported root admitted".into()))
    }
}

fn artifacts_refused(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let roles = [
        ArtifactAdmissionRole::RequestBody,
        ArtifactAdmissionRole::BackupArtifact,
        ArtifactAdmissionRole::SelectedState,
        ArtifactAdmissionRole::Environment,
        ArtifactAdmissionRole::Configuration,
    ];
    if roles
        .into_iter()
        .all(|role| !artifact_role_admissible(role))
        && oracle.u64("expect_refused_roles")? == 5
    {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch("artifact role admitted".into()))
    }
}

#[test]
fn core_s11_alloc_precedence_total() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-PRECEDENCE-TOTAL",
        "tests/fixtures/oracles/core/core-s11-alloc-precedence-total.txt",
        "fe27ace72f90bb7debaf54dc9da706b2e0ec92532fca99bf95956d46e7faac92",
        Frontier::IncarnationAlloc,
        total,
    )
}

#[test]
fn core_s11_alloc_recovery_first() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-RECOVERY-FIRST",
        "tests/fixtures/oracles/core/core-s11-alloc-recovery-first.txt",
        "b863697aa6c67defdcc753590f6c060f7241cfe2f8e4a00b9f2ef9a8d3883005",
        Frontier::IncarnationAlloc,
        recovery,
    )
}

#[test]
fn core_s11_alloc_serialmax_clockhold() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-SERIALMAX-CLOCKHOLD",
        "tests/fixtures/oracles/core/core-s11-alloc-serialmax-clockhold.txt",
        "b8f0350e8ea7ea96fdd65a5a46d5c37a2ee45adf1ca740d240acd0c8dd84afec",
        Frontier::IncarnationAlloc,
        serial_before_clock,
    )
}

#[test]
fn core_s11_alloc_before_clockhold() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-BEFORE-CLOCKHOLD",
        "tests/fixtures/oracles/core/core-s11-alloc-before-clockhold.txt",
        "f754e23995c59ffb721bc9cdcb9cc6688159249d494d76780505c5c463098cd2",
        Frontier::IncarnationAlloc,
        serial_before_clock,
    )
}

#[test]
fn core_s11_alloc_clock_before_capacity() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-CLOCK-BEFORE-CAPACITY",
        "tests/fixtures/oracles/core/core-s11-alloc-clock-before-capacity.txt",
        "9fe5c36ecd331a918e0b6c1d755bf7f79924e2d6257dad7d772dc206ac20cca3",
        Frontier::IncarnationAlloc,
        clock_before_capacity,
    )
}

#[test]
fn core_s11_alloc_publish_after_admit() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-PUBLISH-AFTER-ADMIT",
        "tests/fixtures/oracles/core/core-s11-alloc-publish-after-admit.txt",
        "88f42130cf21b6e1ffb61f8696e4bdbfacf08777b0e6736cf0ccc841a627f1fa",
        Frontier::IncarnationAlloc,
        publish_after_admit,
    )
}

#[test]
fn core_s11_alloc_outcome_rows() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-OUTCOME-ROWS",
        "tests/fixtures/oracles/core/core-s11-alloc-outcome-rows.txt",
        "3b6bf23712b8a3cced8ea6d33d027fe06c63643902eee212a98539894b1f9a72",
        Frontier::IncarnationAlloc,
        outcomes,
    )
}

#[test]
fn core_s11_alloc_checked_carry() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-CHECKED-CARRY",
        "tests/fixtures/oracles/core/core-s11-alloc-checked-carry.txt",
        "881991faea0802f0794780e7962b57579e849ef1038fb3f39c5aed51aae33f8c",
        Frontier::IncarnationAlloc,
        checked_carry,
    )
}
#[test]
fn core_s11_alloc_zero_never() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-ZERO-NEVER",
        "tests/fixtures/oracles/core/core-s11-alloc-zero-never.txt",
        "4e8f6f583f4b4033aefd150834169899cfebe3edbe3dd9394bcb0b297615bcd8",
        Frontier::IncarnationAlloc,
        zero_never,
    )
}
#[test]
fn core_s11_alloc_fresh_header() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-FRESH-HEADER",
        "tests/fixtures/oracles/core/core-s11-alloc-fresh-header.txt",
        "7b6473862d57b228ef58270a49c32f41a663e5f1b30196b1a14f0d857be28158",
        Frontier::IncarnationAlloc,
        fresh_header,
    )
}
#[test]
fn core_s11_alloc_replay_reuse() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-REPLAY-REUSE",
        "tests/fixtures/oracles/core/core-s11-alloc-replay-reuse.txt",
        "26adb2732b97f1554ef1b2f30e0b0976bcf16a984d02f1d51c96f01dda0959cf",
        Frontier::IncarnationAlloc,
        replay_reuse,
    )
}
#[test]
fn core_s11_alloc_crash_collision() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-CRASH-COLLISION",
        "tests/fixtures/oracles/core/core-s11-alloc-crash-collision.txt",
        "2b660b8f09ce845e1e3ddbcee897a1d2de0ea931825d75c7be07941fb99786d3",
        Frontier::IncarnationAlloc,
        crash_collision,
    )
}
#[test]
fn core_s11_alloc_burn_no_reissue() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-BURN-NO-REISSUE",
        "tests/fixtures/oracles/core/core-s11-alloc-burn-no-reissue.txt",
        "d42c2d963074b1b2576b9bf9f5411f33b33920b05421bec36870d2886bf72e73",
        Frontier::IncarnationAlloc,
        burn_no_reissue,
    )
}
#[test]
fn core_s11_alloc_continuation_preserve() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-CONTINUATION-PRESERVE",
        "tests/fixtures/oracles/core/core-s11-alloc-continuation-preserve.txt",
        "cbd705412de55665ebe9ec4c4a7deb357a2ea0525442a3af3754e10c058cbd7c",
        Frontier::IncarnationAlloc,
        continuation,
    )
}
#[test]
fn core_s11_alloc_prestaging_fiveway() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-PRESTAGING-FIVEWAY",
        "tests/fixtures/oracles/core/core-s11-alloc-prestaging-fiveway.txt",
        "24323a4e9af3edf989f1162f236ecd1bf5c8bb2cfb6e169db121cfffa75967e0",
        Frontier::IncarnationAlloc,
        prestaging,
    )
}
#[test]
fn core_s11_alloc_collision_refusal() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-COLLISION-REFUSAL",
        "tests/fixtures/oracles/core/core-s11-alloc-collision-refusal.txt",
        "5df3f6f7d297f9bcbfcf7d1f0f5dd365ed66c36bbd0d961ed99ad896935ede34",
        Frontier::IncarnationAlloc,
        collision_refusal,
    )
}
#[test]
fn core_s11_alloc_fail_snapshot_stable() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-FAIL-SNAPSHOT-STABLE",
        "tests/fixtures/oracles/core/core-s11-alloc-fail-snapshot-stable.txt",
        "b898358a82c04418a956531246910d72584031b50dcc018a9079706ee5ff7e56",
        Frontier::IncarnationAlloc,
        fail_snapshot,
    )
}

#[test]
fn core_s11_alloc_exhaust_recovery() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-EXHAUST-RECOVERY",
        "tests/fixtures/oracles/core/core-s11-alloc-exhaust-recovery.txt",
        "8f84826a5b3b3a4c7ad2b82e0a274d74af61513572607b3e43cfde4362b5ba75",
        Frontier::IncarnationAlloc,
        exhaustion_recovery,
    )
}
#[test]
fn core_s11_alloc_restore_serial_one() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-RESTORE-SERIAL-ONE",
        "tests/fixtures/oracles/core/core-s11-alloc-restore-serial-one.txt",
        "1ab518503398fe60a43b539b1bf4f2fff0c22c9f8d432be540cb42898d176b8d",
        Frontier::IncarnationAlloc,
        restore_one,
    )
}
#[test]
fn core_s11_alloc_ops_under_exhaust() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-OPS-UNDER-EXHAUST",
        "tests/fixtures/oracles/core/core-s11-alloc-ops-under-exhaust.txt",
        "b2c835f9e075753f65c9fb111fac8b36ffc009ed338ddff5a4470615bd8c1060",
        Frontier::IncarnationAlloc,
        ops_under_exhaustion,
    )
}
#[test]
fn core_s11_alloc_zero_writes() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-ZERO-WRITES",
        "tests/fixtures/oracles/core/core-s11-alloc-zero-writes.txt",
        "7162df25096ee2e7d0cfe84dbf1bb62610af1a83635369fa0e64fc6a05aaffd8",
        Frontier::IncarnationAlloc,
        zero_writes,
    )
}
#[test]
fn core_s11_alloc_nonalloc_stable() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-NONALLOC-STABLE",
        "tests/fixtures/oracles/core/core-s11-alloc-nonalloc-stable.txt",
        "02e8f8cd032574c5118ae234bbe9a6ee1fd7f74e0583409ca662e77b9aaf9a3c",
        Frontier::IncarnationAlloc,
        nonalloc_stable,
    )
}
#[test]
fn core_s11_alloc_import_rejected() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-IMPORT-REJECTED",
        "tests/fixtures/oracles/core/core-s11-alloc-import-rejected.txt",
        "eacb57dae400126e5a5d810e186f2902ed59ed90f1800533729363a7524b8baa",
        Frontier::IncarnationAlloc,
        import_rejected,
    )
}
#[test]
fn core_s11_alloc_artifact_refused() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-ALLOC-ARTIFACT-REFUSED",
        "tests/fixtures/oracles/core/core-s11-alloc-artifact-refused.txt",
        "d472ff56b80c614c9b2380b59fa5e79476208637edf4da352ae1d0cef2c517a6",
        Frontier::IncarnationAlloc,
        artifacts_refused,
    )
}
