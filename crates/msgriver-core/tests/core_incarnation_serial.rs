//! Branch-serial terminal transition contract.
//!
//! This additive target replays only two immutable PR-109 observations. The
//! durable allocator and every unfrozen high-water remain outside this slice.

#[path = "red_core/harness.rs"]
mod harness;

use harness::{CompareResult, Oracle, TestCaseError, case, outcome};
use msgriver_core::Frontier;

const FRONTIER: Frontier = Frontier::IncarnationAlloc;

#[test]
fn core_incarnation_serial_exhaust() -> Result<(), TestCaseError> {
    case(
        "CORE-INCARN-SERIAL-EXHAUST",
        "tests/fixtures/oracles/core/core-incarn-serial-exhaust.txt",
        "a30326aaac0665fd7c95fdd816b74bf32fdea31bd8eeb20eab27ed00ae5d1314",
        FRONTIER,
        |oracle: &Oracle| -> Result<CompareResult, TestCaseError> {
            outcome(
                msgriver_core::generation::branch_serial_exhausted(oracle.u64("high_water")?),
                oracle,
                |value| *value == oracle.bool("expect_value").unwrap_or(false),
            )
        },
    )
}

#[test]
fn core_incarnation_serial_burn() -> Result<(), TestCaseError> {
    case(
        "CORE-INCARN-SERIAL-BURN",
        "tests/fixtures/oracles/core/core-incarn-serial-burn.txt",
        "07952e95761df086f1552b85b34e7612301a48eae53b2605b8140b4e30f99757",
        FRONTIER,
        |oracle: &Oracle| -> Result<CompareResult, TestCaseError> {
            outcome(
                msgriver_core::generation::allocate_branch_serial(oracle.u64("high_water")?),
                oracle,
                |value| *value == oracle.u64("expect_value").unwrap_or(0),
            )
        },
    )
}
