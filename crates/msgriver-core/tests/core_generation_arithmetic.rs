//! Guarded-generation arithmetic transition contract.
//!
//! The historical red-core vectors remain immutable. This additive target
//! replays only the three closed PR-109 arithmetic observations, leaving
//! resource-incarnation allocation at its separate scaffold frontier.

#[path = "red_core/harness.rs"]
mod harness;

use harness::{CompareResult, Oracle, TestCaseError, case, outcome};
use msgriver_core::Frontier;

const FRONTIER: Frontier = Frontier::GenerationArithmetic;

#[test]
fn core_generation_arithmetic_increment() -> Result<(), TestCaseError> {
    case(
        "CORE-GEN-INCREMENT",
        "tests/fixtures/oracles/core/core-gen-increment.txt",
        "7012907203594f539d333d52463aa4c5751b7d0631f6981c64bec137c4fd684f",
        FRONTIER,
        |oracle: &Oracle| -> Result<CompareResult, TestCaseError> {
            outcome(
                msgriver_core::generation::increment_generation(oracle.u64("current")?),
                oracle,
                |value| *value == oracle.u64("expect_value").unwrap_or(0),
            )
        },
    )
}

#[test]
fn core_generation_arithmetic_exhaust() -> Result<(), TestCaseError> {
    case(
        "CORE-GEN-EXHAUST",
        "tests/fixtures/oracles/core/core-gen-exhaust.txt",
        "8972152eca2d8ca7c063774ec870ed75c011dcc824acd124bac1c96490d38c2d",
        FRONTIER,
        |oracle: &Oracle| -> Result<CompareResult, TestCaseError> {
            outcome(
                msgriver_core::generation::increment_generation(oracle.u64("current")?),
                oracle,
                |value| *value == oracle.u64("expect_value").unwrap_or(0),
            )
        },
    )
}

#[test]
fn core_generation_arithmetic_limbs() -> Result<(), TestCaseError> {
    case(
        "CORE-GEN-LIMBS",
        "tests/fixtures/oracles/core/core-gen-limbs.txt",
        "1128f722c9c8e8437e857ab65332ff4438f42992a99883108741c7bbfe0bd681",
        FRONTIER,
        |oracle: &Oracle| -> Result<CompareResult, TestCaseError> {
            outcome(
                msgriver_core::generation::split_limbs(oracle.u64("generation")?),
                oracle,
                |(high, low)| {
                    *high == oracle.u32("expect_hi").unwrap_or(0)
                        && *low == oracle.u32("expect_lo").unwrap_or(0)
                },
            )
        },
    )
}
