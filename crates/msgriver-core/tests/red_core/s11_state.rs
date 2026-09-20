use super::harness::{CompareResult, Oracle, TestCaseError, case, outcome};
use msgriver_core::generation::{GuardedWriterSnapshot, advance_writer};
use msgriver_core::state::{LateAckRow, MessageState, TerminalWinner, resolve_late_ack};
use msgriver_core::{Frontier, RejectClass};

const DIGEST: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

fn promotion(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    for prior in [
        MessageState::Queued,
        MessageState::Held,
        MessageState::Delivering,
        MessageState::RetryScheduled,
        MessageState::Failed,
        MessageState::Cancelled,
        MessageState::Expired,
    ] {
        match outcome(
            resolve_late_ack(LateAckRow {
                prior,
                late_verifiable_ack: true,
                attempt_history_digest: DIGEST,
            }),
            oracle,
            |value| {
                value.winner == TerminalWinner::ProviderAccepted
                    && value.attempt_history_digest == DIGEST
            },
        )? {
            CompareResult::Pass => {}
            other => return Ok(other),
        }
    }
    match outcome(
        resolve_late_ack(LateAckRow {
            prior: MessageState::ProviderAccepted,
            late_verifiable_ack: true,
            attempt_history_digest: DIGEST,
        }),
        oracle,
        |value| {
            value.winner == TerminalWinner::ProviderAccepted
                && value.attempt_history_digest == DIGEST
        },
    )? {
        CompareResult::Pass => Ok(CompareResult::Pass),
        other => Ok(other),
    }
}

fn writer(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let normal = GuardedWriterSnapshot {
        generation: 7,
        resource_digest: DIGEST,
        command_digest: [
            31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
            9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
        ],
    };
    match outcome(advance_writer(normal), oracle, |value| {
        value.generation == 8
            && value.resource_digest == normal.resource_digest
            && value.command_digest == normal.command_digest
    })? {
        CompareResult::Pass => {}
        other => return Ok(other),
    }
    match advance_writer(GuardedWriterSnapshot {
        generation: u64::MAX,
        ..normal
    }) {
        Err(error) if error.reject_class() == Some(RejectClass::StateGenerationExhausted) => {
            Ok(CompareResult::Pass)
        }
        Err(error) => match error.scaffold_frontier() {
            Some(frontier) => Ok(CompareResult::Red(frontier)),
            None => Ok(CompareResult::Mismatch("wrong generation failure".into())),
        },
        Ok(_) => Ok(CompareResult::Mismatch("exhaustion advanced".into())),
    }
}

#[test]
fn core_s11_state_promotion_matrix() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-STATE-PROMOTION-MATRIX",
        "tests/fixtures/oracles/core/core-s11-state-promotion-matrix.txt",
        "ccb2fd6982634a8a984cd385de94b62e1a1e26dd85a952f21ef2a2d2b795343a",
        Frontier::TerminalPrecedence,
        promotion,
    )
}

#[test]
fn core_s11_gen_advance_or_fail() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-GEN-ADVANCE-OR-FAIL",
        "tests/fixtures/oracles/core/core-s11-gen-advance-or-fail.txt",
        "e29c9699331ded8fec4b9a66c9736c5b4d9e45ff0c68d84eb272f89da68a4d18",
        Frontier::GenerationArithmetic,
        writer,
    )
}
