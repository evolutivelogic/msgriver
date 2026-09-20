//! MsgRiver core domain.
//!
//! This crate holds MsgRiver's pure domain layer: bounded values and grammar
//! validation, checked time/fixed-point/capacity math, semantic canonicalization
//! and fingerprint/MAC domains, deterministic retry and jitter, message state
//! transitions and sticky uncertainty, total terminal precedence, fence
//! arbitration, safe-time high-water arithmetic, and incarnation/guarded-
//! generation allocation. It is the root of the one-way dependency graph and
//! must never depend on Tokio, HTTP, SQLite, the filesystem, processes, clocks,
//! entropy, or any platform code.
//!
//! The first bounded-value slice has replaced its scaffold gap for twelve
//! frozen CORE-BV observables. All other domains remain at their private,
//! statically enumerated scaffold gap ([`Frontier`]), which is neither a stable
//! protocol/CLI error code nor an acceptance result. The promotion gate records
//! the twelve contract passes while requiring the remaining thirty-eight atomic
//! cases to stay causally RED; broader bounded-value coverage requires another
//! frozen slice.

#![forbid(unsafe_code)]

pub mod bounded;
pub mod canon;
pub mod clock_checkpoint;
pub mod fence;
pub mod generation;
pub mod incarnation;
pub mod math;
pub mod retry;
pub mod ring;
pub mod safetime;
pub mod state;

/// Statically enumerated scaffold frontier vocabulary.
///
/// Each variant names one ordered production seam an atomic case must cross.
/// This is the readable identity the harness uses to prove a behavior case
/// terminated at its *registered* initial frontier (honest RED) rather than at a
/// setup, fixture, or capability failure. It is intentionally `#[doc(hidden)]`:
/// it is a scaffold descriptor that disappears as behavior lands, never a stable
/// API/CLI error code and never an acceptance result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub enum Frontier {
    /// Bounded-value and grammar validation (PR-061/PR-062/PR-063, P-06.1/P-06.3).
    ValidateBoundedGrammar,
    /// Checked time, fixed-point, and capacity arithmetic (A-04.1, PR-149/PR-150).
    CheckedArithmetic,
    /// Fixed-order length-prefixed semantic canonicalization (PR-074, A-04.2).
    CanonicalEncode,
    /// Domain-separated keyed MAC fingerprint/lookup (PR-074, A-04.2).
    MacDomainSeparate,
    /// Bounded exponential backoff with deterministic jitter (PR-084, A-11.3).
    ComputeBackoff,
    /// Message state transition and sticky uncertainty (P-08.1, A-09.2, PR-080).
    StateTransition,
    /// Total terminal precedence (PR-087, A-09.1).
    TerminalPrecedence,
    /// Fence/lease outcome arbitration (PR-081, A-09.4).
    FenceArbitrate,
    /// Authenticated safe-time high-water arithmetic (PR-149, A-11.5).
    SafeTimeHighWater,
    /// Guarded-generation checked arithmetic (PR-109, A-04.1).
    GenerationArithmetic,
    /// Resource-incarnation and branch-serial allocation (PR-109, PR-150).
    IncarnationAlloc,
    /// Retained MAC-key ring state and identity integrity (A-13.2).
    KeyRingState,
    /// Pure allocator-derived readiness exhaustion subset (A-02.1/A-15.3).
    ReadinessReason,
}

impl Frontier {
    /// Stable wire label, used by the harness ledger and sidecar protocol.
    #[doc(hidden)]
    pub fn label(self) -> &'static str {
        match self {
            Frontier::ValidateBoundedGrammar => "validate_bounded_grammar",
            Frontier::CheckedArithmetic => "checked_arithmetic",
            Frontier::CanonicalEncode => "canonical_encode",
            Frontier::MacDomainSeparate => "mac_domain_separate",
            Frontier::ComputeBackoff => "compute_backoff",
            Frontier::StateTransition => "state_transition",
            Frontier::TerminalPrecedence => "terminal_precedence",
            Frontier::FenceArbitrate => "fence_arbitrate",
            Frontier::SafeTimeHighWater => "safe_time_high_water",
            Frontier::GenerationArithmetic => "generation_arithmetic",
            Frontier::IncarnationAlloc => "incarnation_alloc",
            Frontier::KeyRingState => "key_ring_state",
            Frontier::ReadinessReason => "readiness_reason",
        }
    }
}

/// Stable reject-class vocabulary for the bounded/grammar and arithmetic paths.
///
/// A behavior slice uses this enumeration only after its frozen oracle reaches
/// a real rejection. Unimplemented paths continue to return their scaffold
/// gap rather than inventing a stable protocol/CLI error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum RejectClass {
    InvalidIdentifier,
    InvalidTopic,
    TooManyTags,
    InvalidTag,
    InvalidUtf8,
    EmptyText,
    InvalidTextControl,
    InvalidTitleControl,
    TitleTooLong,
    TextTooLong,
    ExpiryInPast,
    ArithmeticOverflow,
    ControlCapacity,
    InvalidTransition,
    LeaseConfigInvalid,
    RetryDelayInputInvalid,
    StateGenerationExhausted,
    IncarnationExhausted,
    DowntimeCeilingInvalid,
    SafeTimeAuthorityEmpty,
    SafeTimeRegression,
    MacKeySerialExhausted,
    IncarnationSerialZero,
    IncarnationHexWidth,
    IncarnationHexCase,
    IncarnationHexCharacter,
}

impl RejectClass {
    #[doc(hidden)]
    pub fn label(self) -> &'static str {
        match self {
            RejectClass::InvalidIdentifier => "invalid_identifier",
            RejectClass::InvalidTopic => "invalid_topic",
            RejectClass::TooManyTags => "too_many_tags",
            RejectClass::InvalidTag => "invalid_tag",
            RejectClass::InvalidUtf8 => "invalid_utf8",
            RejectClass::EmptyText => "empty_text",
            RejectClass::InvalidTextControl => "invalid_text_control",
            RejectClass::InvalidTitleControl => "invalid_title_control",
            RejectClass::TitleTooLong => "title_too_long",
            RejectClass::TextTooLong => "text_too_long",
            RejectClass::ExpiryInPast => "expiry_in_past",
            RejectClass::ArithmeticOverflow => "arithmetic_overflow",
            RejectClass::ControlCapacity => "control_capacity",
            RejectClass::InvalidTransition => "invalid_transition",
            RejectClass::LeaseConfigInvalid => "lease_config_invalid",
            RejectClass::RetryDelayInputInvalid => "retry_delay_input_invalid",
            RejectClass::StateGenerationExhausted => "state_generation_exhausted",
            RejectClass::IncarnationExhausted => "incarnation_exhausted",
            RejectClass::DowntimeCeilingInvalid => "downtime_ceiling_invalid",
            RejectClass::SafeTimeAuthorityEmpty => "safe_time_authority_empty",
            RejectClass::SafeTimeRegression => "safe_time_regression",
            RejectClass::MacKeySerialExhausted => "mac_key_serial_exhausted",
            RejectClass::IncarnationSerialZero => "incarnation_serial_zero",
            RejectClass::IncarnationHexWidth => "incarnation_hex_width",
            RejectClass::IncarnationHexCase => "incarnation_hex_case",
            RejectClass::IncarnationHexCharacter => "incarnation_hex_character",
        }
    }
}

/// Production-shaped core error.
///
/// Stable protocol/CLI error mapping belongs to the protocol layer and is
/// never satisfied by this type. The accessors below are `#[doc(hidden)]` test
/// seams; they carry no protocol acceptance meaning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreError {
    inner: CoreErrorInner,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CoreErrorInner {
    /// Private, statically enumerated scaffold gap. Removed as behavior lands.
    ScaffoldGap(Frontier),
    /// A real, stable core rejection after a behavior slice replaces its
    /// scaffold gap. Protocol mapping remains outside this crate.
    Reject(RejectClass),
}

impl CoreError {
    /// Construct a scaffold-gap error at `frontier` (crate-private: only the
    /// scaffold function bodies below call this).
    pub(crate) const fn scaffold(frontier: Frontier) -> Self {
        Self {
            inner: CoreErrorInner::ScaffoldGap(frontier),
        }
    }

    /// Construct a real core rejection for a behavior slice.
    pub(crate) const fn reject(class: RejectClass) -> Self {
        Self {
            inner: CoreErrorInner::Reject(class),
        }
    }

    /// The scaffold frontier at which the SUT currently terminates, or `None`
    /// once real behavior has replaced the gap.
    #[doc(hidden)]
    pub fn scaffold_frontier(&self) -> Option<Frontier> {
        match self.inner {
            CoreErrorInner::ScaffoldGap(frontier) => Some(frontier),
            CoreErrorInner::Reject(_) => None,
        }
    }

    /// The stable reject class, when the error is a real validation/arithmetic
    /// rejection. `None` for the scaffold gap and before reject variants exist.
    #[doc(hidden)]
    pub fn reject_class(&self) -> Option<RejectClass> {
        match self.inner {
            CoreErrorInner::ScaffoldGap(_) => None,
            CoreErrorInner::Reject(class) => Some(class),
        }
    }
}
