//! Message state machine, sticky uncertainty, and terminal precedence
//! (P-08.1, A-09.1/A-09.2, PR-080/PR-087).
//!
//! Transition operations terminate at the [`StateTransition`](crate::Frontier)
//! gap; precedence operations terminate at
//! [`TerminalPrecedence`](crate::Frontier), until the state slice lands.

use crate::{CoreError, Frontier, RejectClass};

/// The closed durable message-state enum (A-09.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageState {
    Queued,
    Held,
    Delivering,
    RetryScheduled,
    ProviderAccepted,
    Failed,
    Cancelled,
    Expired,
}

/// Orthogonal sticky flags carried alongside a state (A-09.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StickyFlags {
    pub cancel_requested: bool,
    pub effect_may_have_occurred: bool,
    pub duplicate_effect_possible: bool,
}

/// A guarded event applied to a state (subset of A-09.2 driving atomic cases).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionEvent {
    /// Fair claim of eligible work (queued/retry_scheduled -> delivering).
    FairClaim,
    /// Dispatch mark begins conservatively (effect_may_have_occurred = true).
    DispatchMark,
    /// A transient outcome while the message holds the current fence.
    TransientOutcome,
    /// An ambiguous outcome (effect + duplicate become sticky).
    AmbiguousOutcome,
    /// An operator cancellation request.
    Cancel,
}

/// The full transition result: next state plus recomputed sticky flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionResult {
    pub state: MessageState,
    pub flags: StickyFlags,
}

/// Apply a guarded event to `from` with its current flags, returning the next
/// state and recomputed sticky flags (A-09.2). Sticky uncertainty, once true,
/// is never cleared by a transition.
pub fn transition(
    from: MessageState,
    current_flags: StickyFlags,
    event: TransitionEvent,
) -> Result<TransitionResult, CoreError> {
    match (from, current_flags, event) {
        (
            MessageState::Queued,
            StickyFlags {
                cancel_requested: false,
                effect_may_have_occurred: false,
                duplicate_effect_possible: false,
            },
            TransitionEvent::FairClaim,
        ) => Ok(TransitionResult {
            state: MessageState::Delivering,
            flags: current_flags,
        }),
        (
            MessageState::RetryScheduled,
            StickyFlags {
                cancel_requested: false,
                effect_may_have_occurred: true,
                ..
            },
            TransitionEvent::FairClaim,
        ) => Ok(TransitionResult {
            state: MessageState::Delivering,
            flags: current_flags,
        }),
        (
            MessageState::Delivering,
            StickyFlags {
                cancel_requested: false,
                effect_may_have_occurred: false,
                duplicate_effect_possible: false,
            },
            TransitionEvent::DispatchMark,
        ) => Ok(TransitionResult {
            state: MessageState::Delivering,
            flags: StickyFlags {
                cancel_requested: false,
                effect_may_have_occurred: true,
                duplicate_effect_possible: false,
            },
        }),
        (
            MessageState::ProviderAccepted,
            StickyFlags {
                cancel_requested: false,
                effect_may_have_occurred: true,
                duplicate_effect_possible: false,
            },
            TransitionEvent::FairClaim,
        ) => Err(CoreError::reject(RejectClass::InvalidTransition)),
        (
            MessageState::Delivering,
            StickyFlags {
                cancel_requested: false,
                effect_may_have_occurred: true,
                duplicate_effect_possible: false,
            },
            TransitionEvent::TransientOutcome,
        ) => Ok(TransitionResult {
            state: MessageState::RetryScheduled,
            flags: current_flags,
        }),
        (
            MessageState::Delivering,
            StickyFlags {
                cancel_requested: false,
                effect_may_have_occurred: true,
                duplicate_effect_possible: true,
            },
            TransitionEvent::TransientOutcome,
        ) => Ok(TransitionResult {
            state: MessageState::RetryScheduled,
            flags: StickyFlags {
                cancel_requested: false,
                effect_may_have_occurred: true,
                duplicate_effect_possible: true,
            },
        }),
        (
            MessageState::Delivering,
            StickyFlags {
                cancel_requested: false,
                effect_may_have_occurred: true,
                duplicate_effect_possible: false,
            },
            TransitionEvent::AmbiguousOutcome,
        ) => Ok(TransitionResult {
            state: MessageState::RetryScheduled,
            flags: StickyFlags {
                cancel_requested: false,
                effect_may_have_occurred: true,
                duplicate_effect_possible: true,
            },
        }),
        (
            MessageState::Delivering,
            StickyFlags {
                cancel_requested: false,
                effect_may_have_occurred: true,
                duplicate_effect_possible: true,
            },
            TransitionEvent::AmbiguousOutcome,
        ) => Ok(TransitionResult {
            state: MessageState::RetryScheduled,
            flags: StickyFlags {
                cancel_requested: false,
                effect_may_have_occurred: true,
                duplicate_effect_possible: true,
            },
        }),
        (
            MessageState::Delivering,
            StickyFlags {
                cancel_requested: false,
                effect_may_have_occurred: true,
                duplicate_effect_possible: false,
            },
            TransitionEvent::Cancel,
        ) => Ok(TransitionResult {
            state: MessageState::Delivering,
            flags: StickyFlags {
                cancel_requested: true,
                effect_may_have_occurred: true,
                duplicate_effect_possible: false,
            },
        }),
        (
            MessageState::Delivering,
            StickyFlags {
                cancel_requested: false,
                effect_may_have_occurred: true,
                duplicate_effect_possible: true,
            },
            TransitionEvent::Cancel,
        ) => Ok(TransitionResult {
            state: MessageState::Delivering,
            flags: StickyFlags {
                cancel_requested: true,
                effect_may_have_occurred: true,
                duplicate_effect_possible: true,
            },
        }),
        (
            MessageState::Delivering,
            StickyFlags {
                cancel_requested: true,
                effect_may_have_occurred: true,
                duplicate_effect_possible: true,
            },
            TransitionEvent::Cancel,
        ) => Ok(TransitionResult {
            state: MessageState::Delivering,
            flags: StickyFlags {
                cancel_requested: true,
                effect_may_have_occurred: true,
                duplicate_effect_possible: true,
            },
        }),
        (
            MessageState::Delivering,
            StickyFlags {
                cancel_requested: false,
                effect_may_have_occurred: false,
                duplicate_effect_possible: false,
            },
            TransitionEvent::Cancel,
        ) => Ok(TransitionResult {
            state: MessageState::Delivering,
            flags: StickyFlags {
                cancel_requested: true,
                ..current_flags
            },
        }),
        _ => Err(CoreError::scaffold(Frontier::StateTransition)),
    }
}

/// Decisive terminal guards present when an outcome commits (PR-087).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TerminalGuards {
    pub known_provider_acceptance: bool,
    pub cancel_committed: bool,
    pub expiry_eligible: bool,
    pub attempt_exhausted: bool,
    /// A late verifiable acknowledgement of matching retained evidence
    /// (PR-081/A-09.1): the sole terminal-to-terminal promotion path.
    pub late_verifiable_ack: bool,
}

/// The total-precedence winner over a set of terminal guards (PR-087/A-09.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalWinner {
    ProviderAccepted,
    Cancelled,
    Expired,
    Failed,
    /// No decisive guard: the row is not terminalized by precedence alone.
    NoTerminal,
}

/// Pure row input for the sole late-acknowledgement promotion path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LateAckRow {
    pub prior: MessageState,
    pub late_verifiable_ack: bool,
    pub attempt_history_digest: [u8; 32],
}

/// Pure late-acknowledgement resolution, retaining the history identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LateAckResolution {
    pub winner: TerminalWinner,
    pub attempt_history_digest: [u8; 32],
}

pub fn resolve_late_ack(row: LateAckRow) -> Result<LateAckResolution, CoreError> {
    if !row.late_verifiable_ack {
        return Err(CoreError::scaffold(Frontier::TerminalPrecedence));
    }
    Ok(LateAckResolution {
        winner: TerminalWinner::ProviderAccepted,
        attempt_history_digest: row.attempt_history_digest,
    })
}

/// Resolve the total terminal precedence for `guards` (PR-087/A-09.1): known
/// provider acceptance wins; otherwise a committed cancel wins over newly
/// eligible expiry; expiry wins over attempt exhaustion; exhaustion yields
/// `Failed`. A late verifiable acknowledgement of matching evidence promotes an
/// otherwise terminal row to `ProviderAccepted`.
pub fn terminal_precedence(guards: TerminalGuards) -> Result<TerminalWinner, CoreError> {
    if guards.known_provider_acceptance || guards.late_verifiable_ack {
        Ok(TerminalWinner::ProviderAccepted)
    } else if guards.cancel_committed {
        Ok(TerminalWinner::Cancelled)
    } else if guards.expiry_eligible {
        Ok(TerminalWinner::Expired)
    } else if guards.attempt_exhausted {
        Ok(TerminalWinner::Failed)
    } else {
        Ok(TerminalWinner::NoTerminal)
    }
}
