//! State-transition successor contract.
//!
//! The immutable `red_core` vectors remain the historical authority. This
//! target replays the four bounded PR-080/PR-087 observations through its own
//! binary, so their promotion does not rewrite the original RED inventory.

#[path = "red_core/harness.rs"]
mod harness;

use harness::{CompareResult, Oracle, TestCaseError, case, outcome};
use msgriver_core::{
    Frontier,
    state::{MessageState, StickyFlags, TransitionEvent, TransitionResult},
};

const FRONTIER: Frontier = Frontier::StateTransition;

fn state(value: &str) -> Result<MessageState, TestCaseError> {
    match value {
        "queued" => Ok(MessageState::Queued),
        "delivering" => Ok(MessageState::Delivering),
        "retry_scheduled" => Ok(MessageState::RetryScheduled),
        "provider_accepted" => Ok(MessageState::ProviderAccepted),
        other => Err(TestCaseError::Parse(format!("state {other:?}"))),
    }
}

fn event(value: &str) -> Result<TransitionEvent, TestCaseError> {
    match value {
        "fair_claim" => Ok(TransitionEvent::FairClaim),
        "transient_outcome" => Ok(TransitionEvent::TransientOutcome),
        "cancel" => Ok(TransitionEvent::Cancel),
        other => Err(TestCaseError::Parse(format!("event {other:?}"))),
    }
}

fn flags(oracle: &Oracle) -> Result<StickyFlags, TestCaseError> {
    Ok(StickyFlags {
        cancel_requested: oracle.bool("cancel_requested")?,
        effect_may_have_occurred: oracle.bool("effect")?,
        duplicate_effect_possible: oracle.bool("duplicate")?,
    })
}

fn state_matches(transition: &TransitionResult, oracle: &Oracle) -> bool {
    let expected_state = match oracle.req("expect_state").unwrap_or("") {
        "delivering" => MessageState::Delivering,
        "retry_scheduled" => MessageState::RetryScheduled,
        _ => return false,
    };
    transition.state == expected_state
        && transition.flags.cancel_requested
            == oracle.bool("expect_cancel_requested").unwrap_or(false)
        && transition.flags.effect_may_have_occurred
            == oracle.bool("expect_effect").unwrap_or(false)
        && transition.flags.duplicate_effect_possible
            == oracle.bool("expect_duplicate").unwrap_or(false)
}

fn evaluate(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let from = state(oracle.req("from")?)?;
    let event = event(oracle.req("event")?)?;
    let flags = flags(oracle)?;
    outcome(
        msgriver_core::state::transition(from, flags, event),
        oracle,
        |result| state_matches(result, oracle),
    )
}

#[test]
fn core_state_transition_valid() -> Result<(), TestCaseError> {
    case(
        "CORE-STATE-TRANSITION-VALID",
        "tests/fixtures/oracles/core/core-state-transition-valid.txt",
        "359c11ffaa82fcccaf88ce647256567f2ecacae79ebcdbe3aae253c9b3f6504c",
        FRONTIER,
        evaluate,
    )
}

#[test]
fn core_state_transition_invalid() -> Result<(), TestCaseError> {
    case(
        "CORE-STATE-TRANSITION-INVALID",
        "tests/fixtures/oracles/core/core-state-transition-invalid.txt",
        "699b71d5da70815596bf07f37c38b26ec037a0a459f906957eff88ac1d41b14e",
        FRONTIER,
        evaluate,
    )
}

#[test]
fn core_state_sticky_effect() -> Result<(), TestCaseError> {
    case(
        "CORE-STATE-STICKY-EFFECT",
        "tests/fixtures/oracles/core/core-state-sticky-effect.txt",
        "ace3cfdcffb99d4b148490fb1d7dc2a31b71700a349c55d8d5850d6348a3fd66",
        FRONTIER,
        evaluate,
    )
}

#[test]
fn core_state_cancel_delivering() -> Result<(), TestCaseError> {
    case(
        "CORE-STATE-CANCEL-DELIVERING",
        "tests/fixtures/oracles/core/core-state-cancel-delivering.txt",
        "9f83252ae91789049b408c34b9261fe00478258f2a3eb0faa4a3a8a8b2525591",
        FRONTIER,
        evaluate,
    )
}
