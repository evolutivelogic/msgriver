use super::harness::{CompareResult, Oracle, TestCaseError, case, outcome};
use msgriver_core::math::{DEFAULT_DOWNTIME_CEILING_MILLIS, validate_downtime_ceiling};
use msgriver_core::safetime::carry_forward_high_water;
use msgriver_core::{Frontier, RejectClass};

fn max_carry(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    for (markers, expected) in [
        (&[100, 950, 600, 300][..], 950),
        (&[100, 600, 300][..], 600),
        (&[100, 950][..], 950),
    ] {
        match outcome(carry_forward_high_water(markers), oracle, |value| {
            *value == expected
        })? {
            CompareResult::Pass => {}
            other => return Ok(other),
        }
    }
    Ok(CompareResult::Pass)
}

fn downtime_ceiling(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let interval = 60_000;
    let threshold = 30_000;
    let settle = 60_000;
    match outcome(
        validate_downtime_ceiling(None, interval, threshold, settle),
        oracle,
        |value| *value == DEFAULT_DOWNTIME_CEILING_MILLIS,
    )? {
        CompareResult::Pass => {}
        other => return Ok(other),
    }
    match outcome(
        validate_downtime_ceiling(Some(150_001), interval, threshold, settle),
        oracle,
        |value| *value == 150_001,
    )? {
        CompareResult::Pass => {}
        other => return Ok(other),
    }
    for ceiling in [150_000, 149_999] {
        match validate_downtime_ceiling(Some(ceiling), interval, threshold, settle) {
            Err(error) if error.reject_class() == Some(RejectClass::DowntimeCeilingInvalid) => {}
            Err(error) => match error.scaffold_frontier() {
                Some(frontier) => return Ok(CompareResult::Red(frontier)),
                None => return Ok(CompareResult::Mismatch("wrong downtime rejection".into())),
            },
            Ok(_) => {
                return Ok(CompareResult::Mismatch(
                    "invalid downtime ceiling accepted".into(),
                ));
            }
        }
    }
    Ok(CompareResult::Pass)
}

#[test]
fn core_s11_safetime_max_carry() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-SAFETIME-MAX-CARRY",
        "tests/fixtures/oracles/core/core-s11-safetime-max-carry.txt",
        "6868e666af25cae9da4c858ac37f877846143b69cb9aad4db7ce5833f50fcce5",
        Frontier::SafeTimeHighWater,
        max_carry,
    )
}

#[test]
fn core_s11_safetime_downtime_ceiling() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-SAFETIME-DOWNTIME-CEILING",
        "tests/fixtures/oracles/core/core-s11-safetime-downtime-ceiling.txt",
        "34cbccc13142080a50d601c4136e1b96abc7665a2dc40e145e5ed864841a35d0",
        Frontier::CheckedArithmetic,
        downtime_ceiling,
    )
}
