//! Prepared dispatch-mark effect contract, frozen before Task 0297 GREEN.

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
fn clean_prepared_dispatch_mark_starts_effect_evidence() {
    assert_eq!(
        transition(
            MessageState::Delivering,
            flags(false, false, false),
            TransitionEvent::DispatchMark,
        ),
        Ok(result(MessageState::Delivering, flags(false, true, false)))
    );
}

#[test]
fn cancelled_and_impossible_lineages_never_dispatch() {
    for current in [
        flags(true, false, false),
        flags(true, true, false),
        flags(true, false, true),
        flags(true, true, true),
        flags(false, false, true),
    ] {
        assert!(
            !matches!(
                transition(
                    MessageState::Delivering,
                    current,
                    TransitionEvent::DispatchMark
                ),
                Ok(TransitionResult {
                    state: MessageState::Delivering,
                    ..
                })
            ),
            "cancelled or impossible lineage must not dispatch: {current:?}"
        );
    }
}

#[test]
fn dispatch_mark_never_bypasses_the_delivering_state() {
    for state in [
        MessageState::Queued,
        MessageState::Held,
        MessageState::RetryScheduled,
        MessageState::ProviderAccepted,
        MessageState::Failed,
        MessageState::Cancelled,
        MessageState::Expired,
    ] {
        assert!(
            transition(
                state,
                flags(false, false, false),
                TransitionEvent::DispatchMark
            )
            .is_err(),
            "dispatch mark must not bypass fair claim from {state:?}"
        );
    }
}

#[test]
fn dispatch_mark_composes_with_existing_independent_projections() {
    assert!(
        !matches!(
            transition(
                MessageState::Delivering,
                flags(false, false, false),
                TransitionEvent::TransientOutcome,
            ),
            Ok(TransitionResult {
                state: MessageState::RetryScheduled,
                ..
            })
        ),
        "a transient outcome cannot schedule retry before a dispatch mark"
    );
    assert_eq!(
        transition(
            MessageState::Queued,
            flags(false, false, false),
            TransitionEvent::FairClaim,
        ),
        Ok(result(MessageState::Delivering, flags(false, false, false)))
    );
    assert_eq!(
        transition(
            MessageState::RetryScheduled,
            flags(false, true, false),
            TransitionEvent::FairClaim,
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
    assert_eq!(
        transition(
            MessageState::Delivering,
            flags(false, false, false),
            TransitionEvent::Cancel,
        ),
        Ok(result(MessageState::Delivering, flags(true, false, false)))
    );
}
