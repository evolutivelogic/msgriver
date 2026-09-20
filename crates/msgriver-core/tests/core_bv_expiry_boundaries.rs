//! Additive bounded-value expiry-boundary contract.
//!
//! This target preserves both predecessor inventories and freezes only the
//! equality and strictly-future expiry observations.

#[path = "red_core/harness.rs"]
mod harness;

use harness::{CompareResult, Oracle, TestCaseError, case, outcome};
use msgriver_core::Frontier;

const FRONTIER: Frontier = Frontier::ValidateBoundedGrammar;

const EXPIRY_EQUAL: &str = "7ebac5e4bd45c5206d3e4e17cbf9217ec01d3d79cdb0352e1502e386e1a03c46";
const EXPIRY_FUTURE: &str = "cd3869179c8747dcd7d2cf734d39a264efaa52dce75d7ab60913787eb0e77ac3";

fn expiry_case(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    outcome(
        msgriver_core::bounded::check_expiry_boundary(oracle.i64("now")?, oracle.i64("expires")?),
        oracle,
        |()| true,
    )
}

#[test]
fn core_bv_expiry_equal() -> Result<(), TestCaseError> {
    case(
        "CORE-BV-EXPIRY-EQUAL",
        "tests/fixtures/oracles/core-bv-expiry-boundaries/expiry-equal.txt",
        EXPIRY_EQUAL,
        FRONTIER,
        expiry_case,
    )
}

#[test]
fn core_bv_expiry_future() -> Result<(), TestCaseError> {
    case(
        "CORE-BV-EXPIRY-FUTURE",
        "tests/fixtures/oracles/core-bv-expiry-boundaries/expiry-future.txt",
        EXPIRY_FUTURE,
        FRONTIER,
        expiry_case,
    )
}
