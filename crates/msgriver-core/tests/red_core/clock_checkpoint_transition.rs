use super::harness::{CompareResult, Oracle, TestCaseError, case, outcome};
use msgriver_core::Frontier;
use msgriver_core::clock_checkpoint::{CheckpointReason, validate_transition};

const FRONTIER: Frontier = Frontier::SafeTimeHighWater;

fn pass_or_red(
    prior_safe_time: i64,
    new_safe_time: i64,
    reason: CheckpointReason,
    oracle: &Oracle,
) -> Result<Option<CompareResult>, TestCaseError> {
    match outcome(
        validate_transition(prior_safe_time, new_safe_time, reason),
        oracle,
        |transition| {
            transition.prior_safe_time() == prior_safe_time
                && transition.new_safe_time() == new_safe_time
                && transition.reason() == reason
        },
    )? {
        CompareResult::Pass => Ok(None),
        other => Ok(Some(other)),
    }
}

fn transition_contract(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    for reason in [
        CheckpointReason::Periodic,
        CheckpointReason::AutomaticSettlement,
        CheckpointReason::CleanShutdown,
        CheckpointReason::ExpiryProof,
    ] {
        for (prior_safe_time, new_safe_time) in [
            (10, 10),
            (10, 11),
            (i64::MIN, i64::MIN),
            (i64::MIN, i64::MAX),
            (i64::MAX, i64::MAX),
        ] {
            if let Some(result) = pass_or_red(prior_safe_time, new_safe_time, reason, oracle)? {
                return Ok(result);
            }
        }

        for (prior_safe_time, new_safe_time) in
            [(41, 40), (i64::MAX, i64::MAX - 1), (i64::MIN + 1, i64::MIN)]
        {
            match validate_transition(prior_safe_time, new_safe_time, reason) {
                Err(error)
                    if error
                        .reject_class()
                        .is_some_and(|class| class.label() == "safe_time_regression") => {}
                Err(error) => match error.scaffold_frontier() {
                    Some(frontier) => return Ok(CompareResult::Red(frontier)),
                    None => {
                        return Ok(CompareResult::Mismatch("wrong regression rejection".into()));
                    }
                },
                Ok(_) => {
                    return Ok(CompareResult::Mismatch(
                        "safe-time regression accepted".into(),
                    ));
                }
            }
        }
    }

    Ok(CompareResult::Pass)
}

#[test]
fn core_s11_clock_checkpoint_transition() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-CLOCK-CHECKPOINT-TRANSITION",
        "tests/fixtures/oracles/core/core-s11-clock-checkpoint-transition.txt",
        "855ffcad1d764134ca4b500adaffb750a7d9cf4ec3efc8d7fd00bbd9e426e304",
        FRONTIER,
        transition_contract,
    )
}
