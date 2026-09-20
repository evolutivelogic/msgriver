//! Typed private boundary for the Phase 0B hermetic fixture.

use std::fmt;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CandidateKind {
    InboundMessage,
    OutboundStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Receipt {
    pub(crate) callback_key: [u8; 32],
    pub(crate) sender_generation: u64,
    pub(crate) kind: CandidateKind,
    pub(crate) received_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProviderBinding {
    pub(crate) sender_generation: u64,
    pub(crate) provider_message_id: SafeReference,
}

/// Non-sensitive provider/event reference accepted by the hermetic fixture.
/// It intentionally rejects bodies, destinations, whitespace and control data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SafeReference(String);

impl SafeReference {
    pub(crate) fn parse(value: &str) -> Result<Self, RuntimeError> {
        ["event-", "inbound-", "provider-message-"]
            .iter()
            .any(|prefix| {
                value.strip_prefix(prefix).is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
                })
            })
            .then(|| Self(value.to_owned()))
            .ok_or(RuntimeError::InvalidFixture)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RegisteredTemplate {
    Phase0Notice,
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EventKind {
    MatchedReply,
    UnmatchedReply,
    StatusSent,
    StatusDelivered,
    StatusRead,
    StatusFailed,
    RetentionDisposition,
    ServiceWindowDisposition,
    OutboundOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EvidenceEvent {
    pub(crate) kind: EventKind,
    pub(crate) reference: SafeReference,
    pub(crate) sender_generation: u64,
    pub(crate) provider_occurred_at: Option<i64>,
    pub(crate) receipt_order: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AlertIntent {
    pub(crate) event_reference: SafeReference,
    pub(crate) matched: bool,
    pub(crate) safe_timestamp: i64,
    pub(crate) leased: bool,
    /// Monotonic durable token: a stale dispatcher cannot settle a later lease.
    pub(crate) lease_fence: u64,
    /// The lease is recoverable only once this safe local deadline has passed.
    pub(crate) lease_expires_at: Option<i64>,
    pub(crate) dispatch_attempts: u32,
    pub(crate) delivered: bool,
    pub(crate) ambiguous_dispatch: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Tombstone {
    pub(crate) callback_key: [u8; 32],
    pub(crate) sender_generation: u64,
    pub(crate) key_generation: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DurableState {
    pub(crate) receipts: Vec<Receipt>,
    pub(crate) bindings: Vec<ProviderBinding>,
    pub(crate) outbound_pins: Vec<OutboundPin>,
    pub(crate) events: Vec<EvidenceEvent>,
    pub(crate) outbox: Vec<AlertIntent>,
    pub(crate) tombstones: Vec<Tombstone>,
    pub(crate) v1_history: Vec<V1Fact>,
    pub(crate) sensitive_reply: Option<SensitiveReplyState>,
    pub(crate) service_window_dispositions: Vec<ServiceWindowDisposition>,
    pub(crate) revision: u64,
}

/// Non-secret configuration generations retained with an accepted outbound
/// request. They prevent a queued command from silently moving between an
/// operator's sender, endpoint, credential or template policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OutboundPin {
    pub(crate) attempt_reference: SafeReference,
    pub(crate) sender_generation: u64,
    pub(crate) endpoint_generation: u64,
    pub(crate) credential_generation: u64,
    pub(crate) template_allowlist_generation: u64,
}

/// Presence-only retention witness: it never carries reply text, context,
/// destination or provider payload into the fixture's inspectable state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SensitiveReplyState {
    /// The verified receipt time anchors the 0--7 day retention ceiling.
    pub(crate) retained_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) local_only: bool,
}

/// Advisory provider evidence only. No variant is an authorization capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ServiceWindowState {
    Active,
    Unknown,
    Expired,
}

/// A correction names its prior safe event and appends a new observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServiceWindowDisposition {
    pub(crate) event_reference: SafeReference,
    pub(crate) prior_event_reference: Option<SafeReference>,
    pub(crate) state: ServiceWindowState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderOutcomeClass {
    Permanent,
    AuthOrConfig,
    RateLimited,
    Transient,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum V1Fact {
    ProviderAccepted {
        attempts: u32,
        uncertain: bool,
    },
    ProviderOutcome {
        class: ProviderOutcomeClass,
        attempts: u32,
        uncertain: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransactionCheckpoint {
    BeforeCommit,
    AfterReceiptInsert,
    AfterCommitBeforeAck,
    BeforeDispatchLease,
    AfterDispatchSend,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RuntimeStop {
    BeforeCommit,
    AfterReceiptInsert,
    AfterCommitBeforeAck,
    BeforeDispatchLease,
    AfterDispatchSend,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RuntimeError {
    Stop(RuntimeStop),
    RevisionConflict,
    AlertUnavailable,
    InvalidFixture,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Stop(_) => "fixture stopped at an injected checkpoint",
            Self::RevisionConflict => "fixture durable revision changed",
            Self::AlertUnavailable => "fixture alert sink is unavailable",
            Self::InvalidFixture => "fixture operation was invalid",
        })
    }
}

impl std::error::Error for RuntimeError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProviderCapture {
    template: RegisteredTemplate,
    sender_generation: u64,
    provider_message_id: Option<SafeReference>,
}

impl ProviderCapture {
    pub(crate) fn new(
        template: RegisteredTemplate,
        sender_generation: u64,
        provider_message_id: Option<SafeReference>,
    ) -> Self {
        Self {
            template,
            sender_generation,
            provider_message_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AlertCapture {
    event_reference: SafeReference,
    matched: bool,
    safe_timestamp: i64,
}

impl AlertCapture {
    pub(crate) fn new(event_reference: SafeReference, matched: bool, safe_timestamp: i64) -> Self {
        Self {
            event_reference,
            matched,
            safe_timestamp,
        }
    }

    pub(crate) fn event_reference(&self) -> &SafeReference {
        &self.event_reference
    }

    #[cfg(test)]
    pub(crate) fn fixture_record(&self) -> String {
        format!(
            "{}:{}:{}",
            self.event_reference.as_str(),
            self.matched,
            self.safe_timestamp
        )
    }
}

/// The behavior port has no access to test labels, files, sockets, process
/// spawning, secrets, endpoints or arbitrary capture text.  It can read one
/// typed durable snapshot, atomically propose a replacement, and request a
/// typed fixture capture.
pub(crate) trait ReferenceLoopRuntime {
    fn durable_state(&self) -> DurableState;
    fn replace_durable_state(
        &mut self,
        expected_revision: u64,
        replacement: DurableState,
    ) -> Result<(), RuntimeError>;
    fn capture_provider(&mut self, capture: ProviderCapture) -> Result<(), RuntimeError>;
    fn stage_callback_candidates(&mut self, candidates: &[Receipt]) -> Result<(), RuntimeError>;
    fn capture_alert(
        &mut self,
        capture: AlertCapture,
        lease_fence: u64,
        observed_at: i64,
    ) -> Result<(), RuntimeError>;
    fn lease_alert(
        &mut self,
        event_reference: &SafeReference,
        leased_at: i64,
    ) -> Result<AlertIntent, RuntimeError>;
    fn settle_alert(
        &mut self,
        event_reference: &SafeReference,
        lease_fence: u64,
    ) -> Result<(), RuntimeError>;
}
