//! Safe-time successor contract for the four frozen PR-149 observations.

#[path = "red_core/harness.rs"]
mod harness;

use harness::{Oracle, TestCaseError, case, outcome};
use msgriver_core::Frontier;

const FRONTIER: Frontier = Frontier::SafeTimeHighWater;

fn selected(oracle: &Oracle) -> Result<Option<i64>, TestCaseError> {
    oracle
        .opt("selected")
        .map(|value| {
            value
                .parse::<i64>()
                .map_err(|error| TestCaseError::Parse(format!("selected: {error}")))
        })
        .transpose()
}

#[test]
fn core_safetime_max() -> Result<(), TestCaseError> {
    case(
        "CORE-SAFETIME-MAX",
        "tests/fixtures/oracles/core/core-safetime-max.txt",
        "f125a15f4d8975736b00acc615787a7dcd3e2452052a2cedb031ae57267dc644",
        FRONTIER,
        |oracle| {
            outcome(
                msgriver_core::safetime::effective_high_water(
                    oracle.i64("fixed")?,
                    selected(oracle)?,
                ),
                oracle,
                |value| *value == oracle.i64("expect_value").unwrap_or_default(),
            )
        },
    )
}

#[test]
fn core_safetime_monotonic() -> Result<(), TestCaseError> {
    case(
        "CORE-SAFETIME-MONOTONIC",
        "tests/fixtures/oracles/core/core-safetime-monotonic.txt",
        "ee1c30fdbaaf776fe97976ca9fe01f3c1494e798460e3c4749a1e854d24b140d",
        FRONTIER,
        |oracle| {
            outcome(
                msgriver_core::safetime::advance_high_water(
                    oracle.i64("current")?,
                    oracle.i64("candidate")?,
                ),
                oracle,
                |value| *value == oracle.i64("expect_value").unwrap_or_default(),
            )
        },
    )
}

#[test]
fn core_safetime_proven_expired() -> Result<(), TestCaseError> {
    case(
        "CORE-SAFETIME-PROVEN-EXPIRED",
        "tests/fixtures/oracles/core/core-safetime-proven-expired.txt",
        "762b3fe6f4eb8cb23ea3ccd0ce823328fef4fe623159cb40109ccbdaf0d65769",
        FRONTIER,
        |oracle| {
            outcome(
                msgriver_core::safetime::proven_expired(
                    oracle.i64("boundary")?,
                    oracle.i64("high_water")?,
                ),
                oracle,
                |value| *value == oracle.bool("expect_value").unwrap_or(false),
            )
        },
    )
}

#[test]
fn core_safetime_clock_threshold() -> Result<(), TestCaseError> {
    case(
        "CORE-SAFETIME-CLOCK-THRESHOLD",
        "tests/fixtures/oracles/core/core-safetime-clock-threshold.txt",
        "def176935a21d1718b6dc46ce26362c6064c67bae77a315884cca7bb2bb5390f",
        FRONTIER,
        |oracle| {
            outcome(
                msgriver_core::safetime::clock_step_holds(
                    oracle.i64("wall_delta")?,
                    oracle.i64("monotonic_delta")?,
                ),
                oracle,
                |value| *value == oracle.bool("expect_value").unwrap_or(false),
            )
        },
    )
}
