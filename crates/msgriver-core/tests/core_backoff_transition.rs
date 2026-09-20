//! Deterministic retry/backoff transition contract.
//!
//! The historical red-core vectors remain immutable. This additive target
//! replays their four PR-084 observables through a separate test binary so a
//! successor gate can promote this domain without redefining the v1 inventory.

#[path = "red_core/harness.rs"]
mod harness;

use harness::{CompareResult, Oracle, TestCaseError, case, outcome};
use msgriver_core::Frontier;

const FRONTIER: Frontier = Frontier::ComputeBackoff;

#[test]
fn core_backoff_transition_attempt1() -> Result<(), TestCaseError> {
    case(
        "CORE-BACKOFF-ATTEMPT1",
        "tests/fixtures/oracles/core/core-backoff-attempt1.txt",
        "ab2ea915e5f6ca4e3726a777a77fb3f152aeecd0751806c24cc23b1054aa5e4a",
        FRONTIER,
        |oracle: &Oracle| -> Result<CompareResult, TestCaseError> {
            outcome(
                msgriver_core::retry::backoff(
                    oracle.u64("base")?,
                    oracle.u32("factor")?,
                    oracle.u64("max")?,
                    oracle.u32("attempt")?,
                    oracle.u32("jitter")?,
                ),
                oracle,
                |value| *value == oracle.u64("expect_value").unwrap_or(0),
            )
        },
    )
}

#[test]
fn core_backoff_transition_saturate() -> Result<(), TestCaseError> {
    case(
        "CORE-BACKOFF-SATURATE",
        "tests/fixtures/oracles/core/core-backoff-saturate.txt",
        "9963017becb2b4f334ee65a2edf8746c18e9d3ac120dfd6e3474470f57077d49",
        FRONTIER,
        |oracle: &Oracle| -> Result<CompareResult, TestCaseError> {
            outcome(
                msgriver_core::retry::backoff(
                    oracle.u64("base")?,
                    oracle.u32("factor")?,
                    oracle.u64("max")?,
                    oracle.u32("attempt")?,
                    oracle.u32("jitter")?,
                ),
                oracle,
                |value| *value == oracle.u64("expect_value").unwrap_or(0),
            )
        },
    )
}

#[test]
fn core_backoff_transition_retry_after_max() -> Result<(), TestCaseError> {
    case(
        "CORE-BACKOFF-RETRYAFTER-MAX",
        "tests/fixtures/oracles/core/core-backoff-retryafter-max.txt",
        "7218358c37c643cadbab3c56196b431af37d3228f70c231bfbef2f9a49e114be",
        FRONTIER,
        |oracle: &Oracle| -> Result<CompareResult, TestCaseError> {
            outcome(
                msgriver_core::retry::combine_retry_after(
                    oracle.u64("backoff")?,
                    oracle.u64("retry_after")?,
                ),
                oracle,
                |value| *value == oracle.u64("expect_value").unwrap_or(0),
            )
        },
    )
}

#[test]
fn core_backoff_transition_retry_after_clamp() -> Result<(), TestCaseError> {
    case(
        "CORE-BACKOFF-RETRYAFTER-CLAMP",
        "tests/fixtures/oracles/core/core-backoff-retryafter-clamp.txt",
        "b56d319171dd4e2d4b4e16501e1093b1681d81d58e39f43bd9d0ce16704c1c28",
        FRONTIER,
        |oracle: &Oracle| -> Result<CompareResult, TestCaseError> {
            outcome(
                msgriver_core::retry::combine_retry_after(
                    oracle.u64("backoff")?,
                    oracle.u64("retry_after")?,
                ),
                oracle,
                |value| *value == oracle.u64("expect_value").unwrap_or(0),
            )
        },
    )
}
