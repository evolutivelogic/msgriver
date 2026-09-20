//! Retry-scheduled fair-claim contract, frozen before Task 0296 GREEN.

use msgriver_core::{
    RejectClass,
    state::{MessageState, StickyFlags, TransitionEvent, TransitionResult, transition},
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
fn retry_scheduled_fair_claim_preserves_each_reachable_sticky_lineage() {
    let cases = [flags(false, true, false), flags(false, true, true)];
    let mismatches: Vec<_> = cases
        .into_iter()
        .filter_map(|current| {
            let actual = transition(
                MessageState::RetryScheduled,
                current,
                TransitionEvent::FairClaim,
            );
            (actual != Ok(result(MessageState::Delivering, current))).then_some((current, actual))
        })
        .collect();
    assert!(
        mismatches.is_empty(),
        "retry fair-claim must resolve both effect-true lineages: {mismatches:#?}"
    );
}

#[test]
fn historical_state_controls_remain_exact() {
    assert_eq!(
        transition(
            MessageState::Queued,
            flags(false, false, false),
            TransitionEvent::FairClaim,
        ),
        Ok(result(MessageState::Delivering, flags(false, false, false)))
    );
    let error = transition(
        MessageState::ProviderAccepted,
        flags(false, true, false),
        TransitionEvent::FairClaim,
    )
    .expect_err("accepted state must reject a fair claim");
    assert_eq!(error.reject_class(), Some(RejectClass::InvalidTransition));
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
fn retry_scheduled_invalid_flags_and_events_never_claim_work() {
    for current in [
        flags(true, true, false),
        flags(true, true, true),
        flags(false, false, false),
        flags(false, false, true),
    ] {
        assert!(
            !matches!(
                transition(
                    MessageState::RetryScheduled,
                    current,
                    TransitionEvent::FairClaim
                ),
                Ok(TransitionResult {
                    state: MessageState::Delivering,
                    ..
                })
            ),
            "invalid retry lineage must not claim work: {current:?}"
        );
    }
    for event in [
        TransitionEvent::DispatchMark,
        TransitionEvent::TransientOutcome,
        TransitionEvent::AmbiguousOutcome,
        TransitionEvent::Cancel,
    ] {
        assert!(
            !matches!(
                transition(
                    MessageState::RetryScheduled,
                    flags(false, true, false),
                    event
                ),
                Ok(TransitionResult {
                    state: MessageState::Delivering,
                    ..
                })
            ),
            "only fair claim may claim retry-scheduled work: {event:?}"
        );
    }
}
