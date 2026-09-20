use super::harness::{CompareResult, Oracle, TestCaseError, case, outcome};
use msgriver_core::safetime::{
    advance_high_water, carry_forward_high_water, clock_step_holds, effective_high_water,
    proven_expired,
};
use msgriver_core::{CoreError, Frontier};

const FRONTIER: Frontier = Frontier::SafeTimeHighWater;

fn pass_or_red<T>(
    result: Result<T, CoreError>,
    oracle: &Oracle,
    matches: impl FnOnce(&T) -> bool,
) -> Result<Option<CompareResult>, TestCaseError> {
    match outcome(result, oracle, matches)? {
        CompareResult::Pass => Ok(None),
        other => Ok(Some(other)),
    }
}

fn full_domain(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    for (fixed, selected, expected) in [
        (1_000, None, 1_000),
        (1_000, Some(999), 1_000),
        (1_000, Some(1_000), 1_000),
        (1_000, Some(1_001), 1_001),
        (-20, Some(-10), -10),
        (i64::MIN, Some(i64::MAX), i64::MAX),
    ] {
        if let Some(result) = pass_or_red(effective_high_water(fixed, selected), oracle, |value| {
            *value == expected
        })? {
            return Ok(result);
        }
    }

    for (markers, expected) in [
        (&[100, 950, 600, 300][..], 950),
        (&[-9, -3, -7][..], -3),
        (&[i64::MIN, i64::MAX][..], i64::MAX),
    ] {
        if let Some(result) = pass_or_red(carry_forward_high_water(markers), oracle, |value| {
            *value == expected
        })? {
            return Ok(result);
        }
    }

    match carry_forward_high_water(&[]) {
        Err(error)
            if error
                .reject_class()
                .is_some_and(|class| class.label() == "safe_time_authority_empty") => {}
        Err(error) => match error.scaffold_frontier() {
            Some(frontier) => return Ok(CompareResult::Red(frontier)),
            None => {
                return Ok(CompareResult::Mismatch(
                    "wrong empty-authority rejection".into(),
                ));
            }
        },
        Ok(_) => {
            return Ok(CompareResult::Mismatch(
                "empty authority set accepted".into(),
            ));
        }
    }

    for (current, candidate, expected) in [
        (5_000, 3_000, 5_000),
        (5_000, 5_000, 5_000),
        (5_000, 7_000, 7_000),
        (-5, -9, -5),
        (i64::MIN, i64::MAX, i64::MAX),
    ] {
        if let Some(result) =
            pass_or_red(advance_high_water(current, candidate), oracle, |value| {
                *value == expected
            })?
        {
            return Ok(result);
        }
    }

    for (boundary, high_water, expected) in [
        (1_000, 1_000, true),
        (999, 1_000, true),
        (1_001, 1_000, false),
        (i64::MIN, i64::MIN, true),
        (i64::MAX, i64::MIN, false),
    ] {
        if let Some(result) = pass_or_red(proven_expired(boundary, high_water), oracle, |value| {
            *value == expected
        })? {
            return Ok(result);
        }
    }

    for (wall_delta, monotonic_delta, expected) in [
        (30_000, 0, false),
        (30_001, 0, true),
        (-30_000, 0, false),
        (-30_001, 0, true),
        (i64::MIN, i64::MIN, false),
        (i64::MIN, 0, true),
        (i64::MAX, -1, true),
        (i64::MIN, 1, true),
    ] {
        if let Some(result) = pass_or_red(
            clock_step_holds(wall_delta, monotonic_delta),
            oracle,
            |value| *value == expected,
        )? {
            return Ok(result);
        }
    }

    Ok(CompareResult::Pass)
}

#[test]
fn core_s11_safetime_high_water_full_domain() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-SAFETIME-HIGH-WATER-FULL-DOMAIN",
        "tests/fixtures/oracles/core/core-s11-safetime-high-water-full-domain.txt",
        "21677d2aef3708d90bdedb7aa4eed420375380cfa7850512ad01d16fcab7c22b",
        FRONTIER,
        full_domain,
    )
}
