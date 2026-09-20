//! Effect-true delivering cancellation contract, frozen before Task 0298 GREEN.

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

#[test]
fn effect_true_delivering_cancel_sets_only_the_request() {
    assert_eq!(
        transition(
            MessageState::Delivering,
            flags(false, true, false),
            TransitionEvent::Cancel,
        ),
        Ok(result(MessageState::Delivering, flags(true, true, false)))
    );
}

#[test]
fn delivering_cancel_never_clears_or_creates_uncertainty() {
    for cancel_requested in [false, true] {
        for effect in [false, true] {
            for duplicate in [false, true] {
                let current = flags(cancel_requested, effect, duplicate);
                let actual = transition(MessageState::Delivering, current, TransitionEvent::Cancel);
                assert!(
                    actual.is_err()
                        || actual
                            == Ok(result(
                                MessageState::Delivering,
                                flags(true, effect, duplicate)
                            )),
                    "cancel must preserve effect and duplicate evidence: {current:?} -> {actual:?}"
                );
            }
        }
    }
}

#[test]
fn cancel_from_non_delivering_state_never_claims_work() {
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
                    assert!(
                        !matches!(
                            transition(state, current, TransitionEvent::Cancel),
                            Ok(TransitionResult {
                                state: MessageState::Delivering,
                                ..
                            })
                        ),
                        "cancel must not claim work from {state:?} with {current:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn cancellation_composes_with_mark_and_outcome_boundaries() {
    assert_eq!(
        transition(
            MessageState::Delivering,
            flags(false, false, false),
            TransitionEvent::DispatchMark,
        ),
        Ok(result(MessageState::Delivering, flags(false, true, false)))
    );
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
    assert!(
        !matches!(
            transition(
                MessageState::Delivering,
                flags(true, true, false),
                TransitionEvent::TransientOutcome,
            ),
            Ok(TransitionResult {
                state: MessageState::RetryScheduled,
                ..
            })
        ),
        "committed cancellation must not schedule retry after possible effect"
    );
}
