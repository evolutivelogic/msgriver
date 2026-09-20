//! Terminal-precedence successor contract.
//!
//! The immutable `red_core` vectors remain the historical authority. This
//! target replays the six bounded PR-087 observations without rewriting that
//! inventory.

#[path = "red_core/harness.rs"]
mod harness;

use harness::{CompareResult, Oracle, TestCaseError, case, outcome};
use msgriver_core::{
    Frontier,
    state::{TerminalGuards, TerminalWinner},
};

const FRONTIER: Frontier = Frontier::TerminalPrecedence;

fn winner(value: &str) -> Option<TerminalWinner> {
    match value {
        "provider_accepted" => Some(TerminalWinner::ProviderAccepted),
        "cancelled" => Some(TerminalWinner::Cancelled),
        "expired" => Some(TerminalWinner::Expired),
        "failed" => Some(TerminalWinner::Failed),
        _ => None,
    }
}

fn evaluate(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let guards = TerminalGuards {
        known_provider_acceptance: oracle.bool("known_acceptance")?,
        cancel_committed: oracle.bool("cancel_committed")?,
        expiry_eligible: oracle.bool("expiry_eligible")?,
        attempt_exhausted: oracle.bool("attempt_exhausted")?,
        late_verifiable_ack: oracle.bool("late_verifiable_ack")?,
    };
    outcome(
        msgriver_core::state::terminal_precedence(guards),
        oracle,
        |actual| oracle.req("expect_winner").ok().and_then(winner) == Some(*actual),
    )
}

#[test]
fn core_prec_accept_wins() -> Result<(), TestCaseError> {
    case(
        "CORE-PREC-ACCEPT-WINS",
        "tests/fixtures/oracles/core/core-prec-accept-wins.txt",
        "5ba9ac68222b2f93d095219399c5617a2fb205e4a8140c85d5feca27dd87b8ef",
        FRONTIER,
        evaluate,
    )
}

#[test]
fn core_prec_cancel_over_expiry() -> Result<(), TestCaseError> {
    case(
        "CORE-PREC-CANCEL-OVER-EXPIRY",
        "tests/fixtures/oracles/core/core-prec-cancel-over-expiry.txt",
        "6e0e6f69200a45a6773370ca2d6bbe1ac049efa6f7ee3f41153bd6d19ca20e24",
        FRONTIER,
        evaluate,
    )
}

#[test]
fn core_prec_expiry_over_exhaust() -> Result<(), TestCaseError> {
    case(
        "CORE-PREC-EXPIRY-OVER-EXHAUST",
        "tests/fixtures/oracles/core/core-prec-expiry-over-exhaust.txt",
        "d9eefa8a28e6b62706ab7673e1e32f692b0a59fc3861cebf97f61cdedeb16f58",
        FRONTIER,
        evaluate,
    )
}

#[test]
fn core_prec_exhaust_failed() -> Result<(), TestCaseError> {
    case(
        "CORE-PREC-EXHAUST-FAILED",
        "tests/fixtures/oracles/core/core-prec-exhaust-failed.txt",
        "bb1efb07779ae8fb255730d2d8e31e7652041c0f55c4f2f4ceb5277b9db18858",
        FRONTIER,
        evaluate,
    )
}

#[test]
fn core_prec_terminal_noop() -> Result<(), TestCaseError> {
    case(
        "CORE-PREC-TERMINAL-NOOP",
        "tests/fixtures/oracles/core/core-prec-terminal-noop.txt",
        "8bc13ef95d6dbafacb10967216d44a654e8d61b9ecd6c7db0b81294b83803e43",
        FRONTIER,
        evaluate,
    )
}

#[test]
fn core_prec_late_ack_promote() -> Result<(), TestCaseError> {
    case(
        "CORE-PREC-LATE-ACK-PROMOTE",
        "tests/fixtures/oracles/core/core-prec-late-ack-promote.txt",
        "9dc2cab7f770f6965d513807d5d5547880ea2d3a44eb15f609b582b426441a62",
        FRONTIER,
        evaluate,
    )
}
