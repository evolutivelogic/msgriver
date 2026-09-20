//! Duplicate-evidence transient outcome contract, frozen before Task 0301 GREEN.

use msgriver_core::state::{
    MessageState, StickyFlags, TransitionEvent, TransitionResult, transition,
};

const fn flags(cancel_requested: bool, effect: bool, duplicate: bool) -> StickyFlags {
    StickyFlags {
        cancel_requested,
        effect_may_have_occurred: effect,
        duplicate_effect_possible: duplicate,
    }
}

fn result(state: MessageState, flags: StickyFlags) -> TransitionResult {
    TransitionResult { state, flags }
}

fn schedules_retry(result: &Result<TransitionResult, msgriver_core::CoreError>) -> bool {
    matches!(
        result,
        Ok(TransitionResult {
            state: MessageState::RetryScheduled,
            ..
        })
    )
}

#[test]
fn duplicate_evidence_transient_outcome_is_preserved() {
    assert_eq!(
        transition(
            MessageState::Delivering,
            flags(false, true, true),
            TransitionEvent::TransientOutcome,
        ),
        Ok(result(
            MessageState::RetryScheduled,
            flags(false, true, true)
        ))
    );
}

#[test]
fn transient_and_ambiguous_outcomes_retain_distinct_evidence() {
    assert_eq!(
        transition(
            MessageState::Delivering,
            flags(false, true, false),
            TransitionEvent::TransientOutcome,
        ),
        Ok(result(
            MessageState::RetryScheduled,
            flags(false, true, false)
        ))
    );
    assert_eq!(
        transition(
            MessageState::Delivering,
            flags(false, true, true),
            TransitionEvent::AmbiguousOutcome,
        ),
        Ok(result(
            MessageState::RetryScheduled,
            flags(false, true, true)
        ))
    );
}

#[test]
fn non_delivering_states_never_schedule_transient_retry() {
    for state in [
        MessageState::Queued,
        MessageState::Held,
        MessageState::RetryScheduled,
        MessageState::ProviderAccepted,
        MessageState::Failed,
        MessageState::Cancelled,
        MessageState::Expired,
    ] {
        for cancel_requested in [false, true] {
            for effect in [false, true] {
                for duplicate in [false, true] {
                    let current = flags(cancel_requested, effect, duplicate);
                    let actual = transition(state, current, TransitionEvent::TransientOutcome);
                    assert!(
                        !schedules_retry(&actual),
                        "transient outcome must not schedule from {state:?} with {current:?}: {actual:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn cancelled_or_effect_false_transient_outcome_never_schedules_retry() {
    for cancel_requested in [false, true] {
        for effect in [false, true] {
            for duplicate in [false, true] {
                let current = flags(cancel_requested, effect, duplicate);
                let actual = transition(
                    MessageState::Delivering,
                    current,
                    TransitionEvent::TransientOutcome,
                );

                if cancel_requested || !effect {
                    assert!(
                        !schedules_retry(&actual),
                        "cancelled or effect-false transient outcome must not schedule retry: {current:?} -> {actual:?}"
                    );
                }
                if cancel_requested && let Ok(next) = actual {
                    assert!(next.flags.cancel_requested);
                    assert!(next.flags.effect_may_have_occurred);
                    assert!(
                        !current.duplicate_effect_possible || next.flags.duplicate_effect_possible,
                        "cancellation path must not clear duplicate evidence: {current:?} -> {next:?}"
                    );
                }
            }
        }
    }
}
