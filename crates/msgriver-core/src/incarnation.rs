//! Pure fixed-root incarnation allocator decisions (A-10.2).
//!
//! Durable journal scans, intent publication, pointer selection, and hold
//! precedence remain at the coordinator boundary.

use crate::generation::{
    BranchSerial, JournalNamespaceProvider, OwnerNamespace, ResourceIncarnation,
    derive_owner_namespace, next_branch_serial,
};
use crate::{CoreError, Frontier};

/// Closed operation vocabulary relevant to branch-incarnation allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationId {
    BootstrapCreate,
    RestoreCreate,
    UpgradeRollback,
    ConfigurationActivate,
    StateKeyRotate,
    StateKeyRetire,
    UpgradeMigrate,
    UpgradeActivate,
    ForwardRepair,
    Other,
}

/// Whether an operation allocates, continues, or is outside the allocator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionClass {
    Allocating,
    Continuation,
    NonAllocator,
}

/// Classify the closed allocator operation registry (A-10.2 rules 3 and 10).
pub const fn classify_transition(operation: OperationId) -> TransitionClass {
    match operation {
        OperationId::BootstrapCreate
        | OperationId::RestoreCreate
        | OperationId::UpgradeRollback => TransitionClass::Allocating,
        OperationId::ConfigurationActivate
        | OperationId::StateKeyRotate
        | OperationId::StateKeyRetire
        | OperationId::UpgradeMigrate
        | OperationId::UpgradeActivate
        | OperationId::ForwardRepair => TransitionClass::Continuation,
        OperationId::Other => TransitionClass::NonAllocator,
    }
}

/// The five permitted sources of a local allocator witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalWitnessKind {
    SelectedPointer,
    CurrentGuardedResource,
    AllocatingIntentTarget,
    LocallyStagedTarget,
    HistoryOrProvenanceEpoch,
}

/// The claimed ownership source for an incarnation witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessSource {
    Local(LocalWitnessKind),
    ForeignAuthenticatedAncestry,
    ImportedKeyOrigin,
    Unknown,
}

/// A bounded value representation of a candidate allocator witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocatorWitness {
    pub source: WitnessSource,
    pub namespace: OwnerNamespace,
    pub serial: u64,
}

/// The result of classifying a witness against one current owner root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessClassification {
    LocalWitness,
    ForeignAncestry,
    Corrupt,
}

/// Classify local versus foreign evidence without reading or mutating storage.
pub fn classify_witness(
    witness: AllocatorWitness,
    recomputed_namespace: OwnerNamespace,
    high_water: u64,
) -> WitnessClassification {
    match witness.source {
        WitnessSource::ForeignAuthenticatedAncestry | WitnessSource::ImportedKeyOrigin => {
            WitnessClassification::ForeignAncestry
        }
        WitnessSource::Local(_) => {
            if witness.namespace == recomputed_namespace
                && witness.serial != 0
                && witness.serial <= high_water
            {
                WitnessClassification::LocalWitness
            } else {
                WitnessClassification::Corrupt
            }
        }
        WitnessSource::Unknown => WitnessClassification::Corrupt,
    }
}

/// Bounded evidence required to validate an allocator target before staging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetWitnessSet {
    pub collision: bool,
    pub source_matches: bool,
    pub target_serial_matches: bool,
}

/// Stable pure target-validation outcome; the coordinator maps it to protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetValidation {
    Ok,
    Collision,
    SourceMismatch,
    TargetSerialMismatch,
}

/// Validate a fully collected bounded target witness set without mutation.
pub const fn validate_target(witnesses: TargetWitnessSet) -> TargetValidation {
    if witnesses.collision {
        TargetValidation::Collision
    } else if !witnesses.source_matches {
        TargetValidation::SourceMismatch
    } else if !witnesses.target_serial_matches {
        TargetValidation::TargetSerialMismatch
    } else {
        TargetValidation::Ok
    }
}

/// Deterministically derive the next same-root serial from high-water alone.
pub fn derive_nonreused_serial(high_water: u64) -> Result<BranchSerial, CoreError> {
    next_branch_serial(high_water)
}

/// Already-authenticated facts needed for the allocator's pure precedence
/// decision. This carries no durable state and does not authorize I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocatorEvaluation {
    pub exact_same_command_recovery: bool,
    pub forbidding_restore_or_upgrade_hold: bool,
    pub serial_exhausted: bool,
    pub clock_hold: bool,
    pub capacity_available: bool,
    pub admission_or_drain_or_coordinator_conflict: bool,
}

/// The closed result of allocator evaluation before the coordinator performs
/// any durable publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocatorDecision {
    ExactRecovery,
    ForbiddenHold,
    IncarnationUnavailable,
    ClockHold,
    ControlCapacity,
    AdmissionDrainOrCoordinatorConflict,
    PublishAndBurnAuthorized,
}

/// Apply A-10.2 rules 16–17 total precedence without publishing an intent.
pub const fn allocator_hold_precedence(input: AllocatorEvaluation) -> AllocatorDecision {
    if input.exact_same_command_recovery {
        AllocatorDecision::ExactRecovery
    } else if input.forbidding_restore_or_upgrade_hold {
        AllocatorDecision::ForbiddenHold
    } else if input.serial_exhausted {
        AllocatorDecision::IncarnationUnavailable
    } else if input.clock_hold {
        AllocatorDecision::ClockHold
    } else if !input.capacity_available {
        AllocatorDecision::ControlCapacity
    } else if input.admission_or_drain_or_coordinator_conflict {
        AllocatorDecision::AdmissionDrainOrCoordinatorConflict
    } else {
        AllocatorDecision::PublishAndBurnAuthorized
    }
}

/// Fresh fixed-root allocator header values before any intent exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocatorHeader {
    pub owner_namespace: OwnerNamespace,
    pub branch_serial_high_water: u64,
}

/// Initialize the authenticated header's pure values from its sole provider.
pub fn initialize_allocator_header(provider: &dyn JournalNamespaceProvider) -> AllocatorHeader {
    AllocatorHeader {
        owner_namespace: derive_owner_namespace(provider),
        branch_serial_high_water: 0,
    }
}

/// A caller-supplied, already-authenticated allocation intent identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationIntent {
    pub command_digest: [u8; 32],
    pub serial: BranchSerial,
    pub target: ResourceIncarnation,
}

/// Pure same-intent recovery decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDecision {
    Reuse(AllocationIntent),
    CommandCollision,
    Fresh(BranchSerial),
}

/// Reuse an exact retained intent; otherwise derive at most one fresh serial.
pub fn replay_allocation(
    retained: Option<AllocationIntent>,
    command_digest: [u8; 32],
    high_water: u64,
) -> Result<ReplayDecision, CoreError> {
    match retained {
        Some(intent) if intent.command_digest == command_digest => {
            Ok(ReplayDecision::Reuse(intent))
        }
        Some(_) => Ok(ReplayDecision::CommandCollision),
        None => next_branch_serial(high_water).map(ReplayDecision::Fresh),
    }
}

/// A pure image used to prove an allocator decision did not mutate persisted
/// inputs. Its digest stands in for caller-owned authenticated bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocatorSnapshot {
    pub header: AllocatorHeader,
    pub selected_incarnation: ResourceIncarnation,
    pub image_digest: [u8; 32],
}

/// Advance/burn one serial in a replacement value; the input itself is copied.
pub fn burn_next_serial(snapshot: AllocatorSnapshot) -> Result<AllocatorSnapshot, CoreError> {
    let serial = next_branch_serial(snapshot.header.branch_serial_high_water)?;
    Ok(AllocatorSnapshot {
        header: AllocatorHeader {
            branch_serial_high_water: serial.get(),
            ..snapshot.header
        },
        ..snapshot
    })
}

/// Continuation operations preserve the complete allocator image.
pub const fn preserve_continuation(snapshot: AllocatorSnapshot) -> AllocatorSnapshot {
    snapshot
}

/// Bounded pre-staging views collected by the coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreStagingViews {
    pub active_pointer_collision: bool,
    pub retained_history_collision: bool,
    pub retained_provenance_collision: bool,
    pub nonterminal_intent_collision: bool,
    pub staged_metadata_collision: bool,
}

/// Whether any bounded pre-staging view names the candidate target.
pub const fn pre_staging_collision(views: PreStagingViews) -> bool {
    views.active_pointer_collision
        || views.retained_history_collision
        || views.retained_provenance_collision
        || views.nonterminal_intent_collision
        || views.staged_metadata_collision
}

/// Facts that make the only supported recovery from branch-serial exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExhaustionRecovery {
    pub independently_keyed_blank_root: bool,
    pub authenticated_disaster_artifact: bool,
    pub rekeys_exhausted_root_in_place: bool,
}

/// Pure admissibility result for exhaustion recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExhaustionRecoveryDecision {
    Supported,
    Unsupported,
}

/// Admit only a new independently keyed blank root plus authenticated restore.
pub const fn exhaustion_recovery_admissibility(
    recovery: ExhaustionRecovery,
) -> ExhaustionRecoveryDecision {
    if recovery.independently_keyed_blank_root
        && recovery.authenticated_disaster_artifact
        && !recovery.rekeys_exhausted_root_in_place
    {
        ExhaustionRecoveryDecision::Supported
    } else {
        ExhaustionRecoveryDecision::Unsupported
    }
}

/// Compose the first serial under a fresh independently keyed owner root.
pub fn restore_serial_one(namespace: OwnerNamespace) -> ResourceIncarnation {
    crate::generation::compose_incarnation(namespace, BranchSerial::ONE)
}

/// Operations that do not allocate remain allocator-admissible at exhaustion.
pub const fn operation_admissible_under_exhaustion(operation: OperationId) -> bool {
    !matches!(classify_transition(operation), TransitionClass::Allocating)
}

/// An imported fixed owner root cannot be admitted as a concurrent local root.
pub const fn imported_root_admissible() -> bool {
    false
}

/// Artifact roles that must not override allocator-origin admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactAdmissionRole {
    RequestBody,
    BackupArtifact,
    SelectedState,
    Environment,
    Configuration,
}

/// Referenced artifacts never supply or override allocator-origin facts.
pub const fn artifact_role_admissible(_role: ArtifactAdmissionRole) -> bool {
    false
}

/// The complete pure readiness subset owned by the allocator core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessReason {
    GenerationExhausted,
    IncarnationExhausted,
}

/// Derive allocator readiness exhaustion without I/O or presentation. Fixed
/// root incarnation exhaustion takes precedence over guarded generations.
pub fn readiness_reason(high_water: u64, guarded_generations: &[u64]) -> Option<ReadinessReason> {
    if high_water == u64::MAX {
        Some(ReadinessReason::IncarnationExhausted)
    } else if guarded_generations.contains(&u64::MAX) {
        Some(ReadinessReason::GenerationExhausted)
    } else {
        None
    }
}

/// Report allocator readiness when the fixed-root incarnation space and a
/// guarded generation are exhausted together (PR-109): the ordered pair
/// reports the precedence winner `incarnation_exhausted` first and the
/// guarded `generation_exhausted` second, and yields exactly that pair only
/// when both inputs are exhausted. Every partial or non-exhausted input
/// retains the [`ReadinessReason`](crate::Frontier) scaffold frontier; this
/// is the frozen both-exhausted pair only and does not implement or promote
/// a public product readiness surface.
pub fn readiness_exhaustion_both(
    high_water: u64,
    guarded_generations: &[u64],
) -> Result<(ReadinessReason, ReadinessReason), CoreError> {
    if high_water == u64::MAX && guarded_generations.contains(&u64::MAX) {
        Ok((
            ReadinessReason::IncarnationExhausted,
            ReadinessReason::GenerationExhausted,
        ))
    } else {
        Err(CoreError::scaffold(Frontier::ReadinessReason))
    }
}
