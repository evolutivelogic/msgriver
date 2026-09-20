//! Current-fence ambiguous outcome contract, frozen before Task 0299 GREEN.

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
fn current_fence_ambiguous_outcome_marks_duplicate_risk() {
    assert_eq!(
        transition(
            MessageState::Delivering,
            flags(false, true, false),
            TransitionEvent::AmbiguousOutcome,
        ),
        Ok(result(
            MessageState::RetryScheduled,
            flags(false, true, true)
        ))
    );
}

#[test]
fn ambiguity_remains_distinct_from_effect_true_transient_outcome() {
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
}

#[test]
fn cancelled_effect_true_row_cannot_schedule_ambiguous_retry() {
    let cancelled = transition(
        MessageState::Delivering,
        flags(false, true, false),
        TransitionEvent::Cancel,
    );
    assert_eq!(
        cancelled,
        Ok(result(MessageState::Delivering, flags(true, true, false)))
    );

    let ambiguous = transition(
        MessageState::Delivering,
        flags(true, true, false),
        TransitionEvent::AmbiguousOutcome,
    );
    assert!(
        !schedules_retry(&ambiguous),
        "committed cancellation must outrank ambiguous retry: {ambiguous:?}"
    );
    if let Ok(next) = ambiguous {
        assert!(next.flags.cancel_requested);
        assert!(next.flags.effect_may_have_occurred);
    }
}

#[test]
fn non_delivering_states_never_schedule_ambiguous_retry() {
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
                    let actual = transition(state, current, TransitionEvent::AmbiguousOutcome);
                    assert!(
                        !schedules_retry(&actual),
                        "ambiguous outcome must not schedule from {state:?} with {current:?}: {actual:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn ambiguous_outcome_preserves_the_deferred_delivering_boundaries() {
    for cancel_requested in [false, true] {
        for effect in [false, true] {
            for duplicate in [false, true] {
                let current = flags(cancel_requested, effect, duplicate);
                let actual = transition(
                    MessageState::Delivering,
                    current,
                    TransitionEvent::AmbiguousOutcome,
                );

                if cancel_requested || !effect {
                    assert!(
                        !schedules_retry(&actual),
                        "cancelled or effect-false ambiguity must not schedule retry: {current:?} -> {actual:?}"
                    );
                }

                if cancel_requested && let Ok(next) = actual {
                    assert!(next.flags.cancel_requested);
                    assert!(next.flags.effect_may_have_occurred);
                    assert!(
                        !current.duplicate_effect_possible || next.flags.duplicate_effect_possible,
                        "cancellation path must not clear duplicate evidence: {current:?} -> {next:?}"
                    );
                } else if effect {
                    assert!(
                        actual.is_err()
                            || actual
                                == Ok(result(
                                    MessageState::RetryScheduled,
                                    flags(false, true, true)
                                )),
                        "effect-true ordinary ambiguity must be exact or deferred: {current:?} -> {actual:?}"
                    );
                }
            }
        }
    }
}
