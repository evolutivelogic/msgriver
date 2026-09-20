//! Repeated duplicate-evidence cancellation contract, frozen before Task 0303 GREEN.

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
fn repeated_duplicate_evidence_cancel_is_a_no_new_fact_projection() {
    assert_eq!(
        transition(
            MessageState::Delivering,
            flags(true, true, true),
            TransitionEvent::Cancel,
        ),
        Ok(result(MessageState::Delivering, flags(true, true, true)))
    );
}

#[test]
fn first_cancel_and_duplicate_distinction_remain_intact() {
    assert_eq!(
        transition(
            MessageState::Delivering,
            flags(false, true, true),
            TransitionEvent::Cancel,
        ),
        Ok(result(MessageState::Delivering, flags(true, true, true)))
    );
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
fn delivering_cancel_only_preserves_state_and_sticky_evidence() {
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
                    "cancel must retain delivery and evidence: {current:?} -> {actual:?}"
                );
                assert!(
                    !matches!(
                        actual,
                        Ok(TransitionResult {
                            state: MessageState::RetryScheduled
                                | MessageState::ProviderAccepted
                                | MessageState::Failed
                                | MessageState::Cancelled
                                | MessageState::Expired,
                            ..
                        })
                    ),
                    "cancel must not project an outcome: {current:?} -> {actual:?}"
                );
            }
        }
    }
}
