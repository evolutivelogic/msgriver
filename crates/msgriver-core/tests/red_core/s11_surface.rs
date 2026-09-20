use super::harness::{CompareResult, Oracle, TestCaseError, case};
use msgriver_core::Frontier;
use msgriver_core::generation::{
    BranchSerial, JournalNamespaceProvider, OwnerNamespace, ResourceIncarnation,
    compose_incarnation, decode_incarnation_hex, derive_owner_namespace, encode_incarnation_hex,
    next_branch_serial,
};
use msgriver_core::incarnation::{
    AllocatorDecision, AllocatorEvaluation, AllocatorWitness, ReadinessReason, TargetValidation,
    TargetWitnessSet, TransitionClass, allocator_hold_precedence, classify_transition,
    classify_witness, readiness_reason, validate_target,
};

fn inventory(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let _derive: fn(&dyn JournalNamespaceProvider) -> OwnerNamespace = derive_owner_namespace;
    let _compose: fn(OwnerNamespace, BranchSerial) -> ResourceIncarnation = compose_incarnation;
    let _encode: fn(ResourceIncarnation) -> String = encode_incarnation_hex;
    let _decode: fn(&str) -> Result<ResourceIncarnation, msgriver_core::CoreError> =
        decode_incarnation_hex;
    let _next: fn(u64) -> Result<BranchSerial, msgriver_core::CoreError> = next_branch_serial;
    let _transition: fn(msgriver_core::incarnation::OperationId) -> TransitionClass =
        classify_transition;
    let _witness: fn(
        AllocatorWitness,
        OwnerNamespace,
        u64,
    ) -> msgriver_core::incarnation::WitnessClassification = classify_witness;
    let _target: fn(TargetWitnessSet) -> TargetValidation = validate_target;
    let _precedence: fn(AllocatorEvaluation) -> AllocatorDecision = allocator_hold_precedence;
    let _readiness: fn(u64, &[u64]) -> Option<ReadinessReason> = readiness_reason;
    if oracle.expect_is("ok") && oracle.u64("expect_functions")? == 10 {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch("pure inventory mismatch".into()))
    }
}

fn injection(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    const CORE: &str = concat!(
        include_str!("../../src/lib.rs"),
        include_str!("../../src/generation.rs"),
        include_str!("../../src/incarnation.rs"),
    );
    let forbidden = ["std::fs", "std::net", "std::process", "SystemTime::now"];
    if forbidden.into_iter().all(|needle| !CORE.contains(needle))
        && oracle.expect_is("ok")
        && oracle.u64("expect_forbidden_channels")? == 4
    {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch(
            "forbidden core injection surface".into(),
        ))
    }
}

#[test]
fn core_s11_surface_pure_inventory() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-SURFACE-PURE-INVENTORY",
        "tests/fixtures/oracles/core/core-s11-surface-pure-inventory.txt",
        "4180e8a250af68c64ccbaee1ba06279a52e9252bf5cc1acca732664162b34ed9",
        Frontier::MacDomainSeparate,
        inventory,
    )
}
#[test]
fn core_s11_surface_injection_matrix() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-SURFACE-INJECTION-MATRIX",
        "tests/fixtures/oracles/core/core-s11-surface-injection-matrix.txt",
        "2906cba60d6200698f72a8a303c7168c3c977d017911329b2b5276d735207947",
        Frontier::IncarnationAlloc,
        injection,
    )
}
