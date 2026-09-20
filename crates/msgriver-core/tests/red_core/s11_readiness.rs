use super::harness::{CompareResult, Oracle, TestCaseError, case};
use msgriver_core::Frontier;
use msgriver_core::incarnation::{ReadinessReason, readiness_reason};

fn reasons(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    if readiness_reason(u64::MAX, &[u64::MAX]) == Some(ReadinessReason::IncarnationExhausted)
        && oracle.expect_is("ok")
        && oracle.req("expect_precedence")? == "incarnation_exhausted"
    {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch(
            "readiness precedence mismatch".into(),
        ))
    }
}

fn incarn(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    if readiness_reason(u64::MAX, &[]) == Some(ReadinessReason::IncarnationExhausted)
        && oracle.req("expect_reason")? == "incarnation_exhausted"
    {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch(
            "incarnation exhaustion missing".into(),
        ))
    }
}

fn matrix(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let rows = [
        (12, vec![3, 7], None),
        (
            12,
            vec![3, u64::MAX],
            Some(ReadinessReason::GenerationExhausted),
        ),
        (
            u64::MAX,
            vec![3, u64::MAX],
            Some(ReadinessReason::IncarnationExhausted),
        ),
    ];
    if rows
        .into_iter()
        .all(|(high, guarded, expected)| readiness_reason(high, &guarded) == expected)
        && oracle.expect_is("ok")
        && oracle.list("expect_rows")?.len() == 3
    {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch("readiness matrix mismatch".into()))
    }
}

fn purity(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let _ = readiness_reason(1, &[u64::MAX]);
    if oracle.expect_is("ok") && oracle.req("expect_presentation")? == "absent" {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch(
            "readiness rendered presentation".into(),
        ))
    }
}

#[test]
fn core_s11_ready_exhaust_reasons() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-READY-EXHAUST-REASONS",
        "tests/fixtures/oracles/core/core-s11-ready-exhaust-reasons.txt",
        "19bff493ca17bdffb39b91cb59f33399a7db446dc8c595da45e19b9189c9cb71",
        Frontier::ReadinessReason,
        reasons,
    )
}
#[test]
fn core_s11_ready_incarn_exhausted() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-READY-INCARN-EXHAUSTED",
        "tests/fixtures/oracles/core/core-s11-ready-incarn-exhausted.txt",
        "f18c5f625e917b2d8bac7bcfa53a0973f01230bc2657ad2564bae9f849a7eb9f",
        Frontier::ReadinessReason,
        incarn,
    )
}
#[test]
fn core_s11_ready_exhaustive_matrix() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-READY-EXHAUSTIVE-MATRIX",
        "tests/fixtures/oracles/core/core-s11-ready-exhaustive-matrix.txt",
        "7b95840cc16fd4ed86dd964c9c2a2f216958e291b446516dbc50625dd5f8029c",
        Frontier::ReadinessReason,
        matrix,
    )
}
#[test]
fn core_s11_ready_purity() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-READY-PURITY",
        "tests/fixtures/oracles/core/core-s11-ready-purity.txt",
        "035c50c28983b7a4f48f0527eab93f9cee282adcaef2738d62ee3878456d3286",
        Frontier::ReadinessReason,
        purity,
    )
}
