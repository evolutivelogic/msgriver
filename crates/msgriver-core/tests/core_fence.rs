//! Fence-arbitration successor contract for the frozen PR-081 observations.

#[path = "red_core/harness.rs"]
mod harness;

use harness::{CompareResult, Oracle, TestCaseError, case, outcome};
use msgriver_core::{
    Frontier,
    fence::{FenceArbitration, FenceOutcome},
};

const FRONTIER: Frontier = Frontier::FenceArbitrate;

fn fence_outcome(value: &str) -> Result<FenceOutcome, TestCaseError> {
    match value {
        "accepted" => Ok(FenceOutcome::Accepted),
        "transient" => Ok(FenceOutcome::Transient),
        "ambiguous" => Ok(FenceOutcome::Ambiguous),
        other => Err(TestCaseError::Parse(format!("outcome {other:?}"))),
    }
}

fn matches_arbitration(value: &FenceArbitration, oracle: &Oracle) -> bool {
    match (value, oracle.req("expect_arbitration").unwrap_or("")) {
        (
            FenceArbitration::Applied {
                outcome: FenceOutcome::Accepted,
            },
            "applied",
        ) => oracle.req("expect_outcome").ok() == Some("accepted"),
        (
            FenceArbitration::Stale {
                ambiguity_orred,
                attempt_delta,
            },
            "stale",
        ) => {
            *ambiguity_orred == oracle.bool("expect_ambiguity_orred").unwrap_or(false)
                && *attempt_delta == oracle.u32("expect_attempt_delta").unwrap_or_default()
        }
        _ => false,
    }
}

fn arbitrate(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    outcome(
        msgriver_core::fence::arbitrate_outcome(
            oracle.u64("cur_lease")?,
            oracle.u128("cur_fence")?,
            oracle.u64("upd_lease")?,
            oracle.u128("upd_fence")?,
            fence_outcome(oracle.req("outcome")?)?,
        ),
        oracle,
        |value| matches_arbitration(value, oracle),
    )
}

#[test]
fn core_fence_match() -> Result<(), TestCaseError> {
    case(
        "CORE-FENCE-MATCH",
        "tests/fixtures/oracles/core/core-fence-match.txt",
        "adcade366c70c802dbb0aaae843ef8f142bd791e880e504509f458ac2f58adfa",
        FRONTIER,
        arbitrate,
    )
}

#[test]
fn core_fence_stale() -> Result<(), TestCaseError> {
    case(
        "CORE-FENCE-STALE",
        "tests/fixtures/oracles/core/core-fence-stale.txt",
        "0506f19a7c1531327abd138893aae3c07cd52c644795e6ea3ad47bc38b0933fe",
        FRONTIER,
        arbitrate,
    )
}

#[test]
fn core_fence_ambiguity_or() -> Result<(), TestCaseError> {
    case(
        "CORE-FENCE-AMBIGUITY-OR",
        "tests/fixtures/oracles/core/core-fence-ambiguity-or.txt",
        "fc63c12b6f07fb6ec116c12eb56b0ae6eadb10ee99632d1be91335796b618f30",
        FRONTIER,
        arbitrate,
    )
}

#[test]
fn core_fence_lease_config() -> Result<(), TestCaseError> {
    case(
        "CORE-FENCE-LEASE-CONFIG",
        "tests/fixtures/oracles/core/core-fence-lease-config.txt",
        "b7820ed9c3281deff342dcc1736f7c3d300d17f478b435425332f90ed538e706",
        FRONTIER,
        |oracle| {
            outcome(
                msgriver_core::fence::validate_lease_config(
                    oracle.u64("ttl")?,
                    oracle.u64("timeout")?,
                    oracle.u64("margin")?,
                ),
                oracle,
                |_| true,
            )
        },
    )
}
