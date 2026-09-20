//! Complete fixed-root image ownership: authenticate before exposing a projection,
//! and publish one bounded replacement through a retained owner directory.
//!
//! Unsupported semantic members fail construction; their tagged absence is
//! still mandatory. A summary of a lifecycle observation is not its wire body.

use super::JournalIntegrityKey;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;

const CHECKPOINT_AUTH_LABEL: &[u8] = b"msgriver/control-journal-checkpoint/v1";
const TAIL_AUTH_LABEL: &[u8] = b"msgriver/control-journal-tail/v1";
const AUTH_TAG_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct JournalHead {
    sequence: u64,
    digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AuthenticatedControlJournalHeader {
    owner_namespace: [u8; 24],
    branch_serial_high_water: u64,
}

use super::active_state_pointer::ActiveStatePointer as ActiveStatePointerCertificate;
#[cfg(test)]
use super::clock_authority_projection::ClockAuthorityHold as ClockHold;
use super::clock_authority_projection::ClockAuthorityProjection as ClockAuthority;
use super::{
    active_state_pointer, clock_authority_projection, clock_checkpoint_body,
    control_journal_record, recovery_key_generate_profile, recovery_ring_manifest,
};
use msgriver_core::bounded::check_identifier;
use msgriver_core::canon::{MacKeyId, MacKeyRef, MacPurpose};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RecoveryRingEntry {
    generation: u64,
    phase: RecoveryRingPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryRingPhase {
    Retained,
    Active,
    PendingEscrow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FixedRootCommandProjection {
    operation: FixedRootOperation,
    actor: StableActorNamespace,
    lookup: CommandTag,
    semantic_fingerprint: CommandTag,
    phase_fingerprint: CommandTag,
    portable_reservation: CommandTag,
    runtime: CommandRuntime,
    process_instance: [u8; 16],
    original_deadline: Option<i64>,
    phase: u16,
    retention: CommandRetention,
    safe_result: Option<CommandSafeResult>,
    target_binding: Option<CommandTargetBinding>,
    profile: RecoveryKeyGenerateProfile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommandTag {
    key: msgriver_core::canon::MacKeyRef,
    tag: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommandRuntime {
    Normal,
    Maintenance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommandRetention {
    Continuation,
    Terminal { terminal_time: i64, expires_at: i64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommandSafeResult {
    codec: u16,
    version: u16,
    digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommandTargetBinding {
    source: [u8; 32],
    target: [u8; 32],
    source_generation: Option<u64>,
    target_generation: Option<u64>,
    parent_witness: Option<CommandParentWitness>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommandParentWitness {
    origin: [u8; 32],
    head: JournalHead,
    certificate_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixedRootOperation {
    ConfigurationActivate,
    StateKeyRotate,
    StateKeyRetire,
    RecoveryKeyGenerate,
    RecoveryKeyImport,
    RecoveryKeyRetire,
    BootstrapCreate,
    RestoreCreate,
    StateGenerationDelete,
    UpgradePrepare,
    UpgradeMigrate,
    UpgradeActivate,
    UpgradeRollback,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum StableActorNamespace {
    Principal(Vec<u8>),
    StateOwner,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RecoveryKeyGenerateProfile(recovery_key_generate_profile::RecoveryKeyGenerateProfile);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AddressedOperation {
    ClockAcknowledge,
    SystemShutdown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AddressedState {
    Absent,
    Present(Box<AddressedStateValue>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AddressedStateValue {
    actor: AddressedActor,
    address: AddressedOperationAddress,
    desired_transition: DesiredMonotonicTransition,
    evidence: AddressedEvidence,
    phase: u8,
    safe_result: AddressedResult,
    application_head: JournalHead,
    publication_head: JournalHead,
    mirror: AddressedMirror,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AddressedActor {
    StateOwner,
    Principal(Vec<u8>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AddressedOperationAddress {
    ClockHold {
        generation: u64,
        observation_digest: [u8; 32],
    },
    ProcessInstance([u8; 16]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DesiredMonotonicTransition {
    SettleHold { risk_acknowledged: bool },
    StopProcess { grace_ms: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AddressedEvidence {
    Acknowledge {
        accepted_wall_time: i64,
        accepted_monotonic_tick: i64,
        prior_fixed_safe_time: i64,
        prior_selected_safe_time: Option<i64>,
        target_safe_time: i64,
    },
    Shutdown {
        accepted_monotonic_tick: i64,
        grace_deadline_tick: i64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AddressedResult {
    Acknowledge {
        settled_safe_time: i64,
        settled: bool,
    },
    Shutdown {
        ungraceful_reason: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AddressedMirror {
    NotApplicable,
    Pending {
        origin: [u8; 32],
        pre: JournalHead,
        policy: u8,
    },
    Committed {
        origin: [u8; 32],
        pre: JournalHead,
        policy: u8,
        post: JournalHead,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AddressedAction {
    PublishRequest(Box<AddressedStateValue>),
    PublishPhase { phase: u8, result: AddressedResult },
    CommitMirror(JournalHead),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AddressedCell {
    operation: AddressedOperation,
    current: bool,
    state: AddressedState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UpgradeDivergedProvenance {
    upgrade_id: [u8; 32],
    source_generation: u64,
    target_generation: u64,
    detecting_phase: u16,
    expected: ProvenanceHeads,
    observed: ProvenanceHeads,
    authenticated_record_digest: [u8; 32],
    resolution: Option<UpgradeDivergedResolution>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProvenanceHeads {
    journal: JournalHead,
    store_digest: [u8; 32],
    certificate_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UpgradeDivergedResolution {
    poison_digest: [u8; 32],
    repair_command_digest: [u8; 32],
    resolved_safe_time: i64,
    audit_supported_until: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FixedRootCoordinator {
    upgrade_id: [u8; 32],
    source_generation: u64,
    target_generation: u64,
    phase: CoordinatorPhase,
    safe_deadline: i64,
    monotonic_deadline: u64,
    prepared_heads: CoordinatorPreparedHeads,
    lifecycle_commitment: [u8; 32],
    source_schema: u32,
    target_schema: u32,
    certificate_digest: [u8; 32],
    rollback_eligible: bool,
    divergence_digest: Option<[u8; 32]>,
    activation_or_repair: CoordinatorOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoordinatorPhase {
    Quiescing,
    Prepared,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CoordinatorPreparedHeads {
    source: JournalHead,
    store: JournalHead,
    effect: JournalHead,
    comparison: JournalHead,
    checkpoint: JournalHead,
    tail: JournalHead,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoordinatorOutcome {
    Pending,
    Activated,
    RepairRequired,
    Repaired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OpenUpgradeProjection {
    source_head: JournalHead,
    target_head: JournalHead,
    certificate_head: JournalHead,
    phase: CoordinatorPhase,
    interval_start_head: JournalHead,
    allowed_lifecycle_count: u64,
    rolling_transcript_digest: [u8; 32],
    last_covered_head: JournalHead,
    capacity_binding: [u8; 32],
    mirror: UpgradeAuthorityMirror,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UpgradeAuthorityMirror {
    clock: ClockAuthority,
    clock_acknowledge: AddressedState,
    system_shutdown: AddressedState,
    local_command_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthenticatedTailFrame {
    prior_head: JournalHead,
    resulting_head: JournalHead,
    record: TailRecord,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TailRecord {
    ClockCheckpointEvent(clock_checkpoint_body::ClockCheckpointBody),
    ClockAcknowledge(AddressedAction),
    SystemShutdown(AddressedAction),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompleteCheckpoint {
    generation: u64,
    covered_head: JournalHead,
    clock_authority: ClockAuthority,
    active_pointer: Option<ActiveStatePointerCertificate>,
    recovery_ring: Vec<RecoveryRingEntry>,
    local_commands: Vec<FixedRootCommandProjection>,
    addressed: [AddressedCell; 4],
    provenance: Vec<UpgradeDivergedProvenance>,
    coordinator: Option<FixedRootCoordinator>,
    open_upgrade: Option<OpenUpgradeProjection>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompleteControlJournalImage {
    header: AuthenticatedControlJournalHeader,
    checkpoint: CompleteCheckpoint,
    tail: Vec<AuthenticatedTailFrame>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationFault {
    UniqueTemporaryCreate,
    TemporaryWrite,
    FileSync,
    ReplacementRename,
    DirectorySync,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ImageMutation {
    ReorderedCheckpointMember,
    ReorderedTailFrame,
    NoncontiguousTailSequence,
    CoveredHeadMismatch,
    CommandOnlyArtifact,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FoldTrigger {
    TailFrameLimit,
    TailByteLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlJournalImageError {
    MissingControlJournalImage,
    InvalidControlJournalImage,
    UnsupportedConstruction,
    WriteFailed,
    PublishUncertain,
}

impl fmt::Display for ControlJournalImageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingControlJournalImage => "control journal image is not implemented",
            Self::InvalidControlJournalImage => "control journal image is invalid",
            Self::UnsupportedConstruction => "control journal member construction is unavailable",
            Self::WriteFailed => "control journal image publication failed",
            Self::PublishUncertain => "control journal image publication is uncertain",
        })
    }
}

impl std::error::Error for ControlJournalImageError {}

/// Reuse the reviewed header authority rather than reimplementing its domain
/// tag or namespace derivation in the complete-image owner.
fn encode_image_header(
    key: &JournalIntegrityKey,
    header: AuthenticatedControlJournalHeader,
) -> Result<[u8; 120], ControlJournalImageError> {
    let component = key
        .control_journal_header_with_branch_high_water(header.branch_serial_high_water)
        .map_err(|_| ControlJournalImageError::InvalidControlJournalImage)?;
    if component.owner_namespace.as_bytes() != header.owner_namespace {
        return Err(ControlJournalImageError::InvalidControlJournalImage);
    }
    key.encode_control_journal_header(component)
        .map_err(|_| ControlJournalImageError::InvalidControlJournalImage)
}

/// The image owns exactly these two additional authentication domains. Their
/// callers pass already-canonical region bytes and exact predecessor digests;
/// no general-purpose MAC capability escapes this sibling.
fn region_tag(
    key: &JournalIntegrityKey,
    region: ImageRegion,
    bytes: &[u8],
) -> Result<[u8; AUTH_TAG_BYTES], ControlJournalImageError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&key.0[..])
        .map_err(|_| ControlJournalImageError::InvalidControlJournalImage)?;
    mac.update(region.label());
    mac.update(bytes);
    Ok(mac.finalize().into_bytes().into())
}

fn verify_region_tag(
    key: &JournalIntegrityKey,
    region: ImageRegion,
    bytes: &[u8],
    tag: &[u8],
) -> Result<(), ControlJournalImageError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&key.0[..])
        .map_err(|_| ControlJournalImageError::InvalidControlJournalImage)?;
    mac.update(region.label());
    mac.update(bytes);
    mac.verify_slice(tag)
        .map_err(|_| ControlJournalImageError::InvalidControlJournalImage)
}

fn region_digest(bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest.finalize().into()
}

/// Bounded canonical writer for image-owned framing. Lengths are emitted only
/// after their source has fit the region cap; callers never borrow a reserve.
struct ImageWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl ImageWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    fn extend(&mut self, value: &[u8]) -> Result<(), ControlJournalImageError> {
        let next = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(ControlJournalImageError::InvalidControlJournalImage)?;
        if next > self.limit {
            return Err(ControlJournalImageError::InvalidControlJournalImage);
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), ControlJournalImageError> {
        self.extend(&[value])
    }
    fn u16(&mut self, value: u16) -> Result<(), ControlJournalImageError> {
        self.extend(&value.to_be_bytes())
    }
    fn u32(&mut self, value: u32) -> Result<(), ControlJournalImageError> {
        self.extend(&value.to_be_bytes())
    }
    fn u64(&mut self, value: u64) -> Result<(), ControlJournalImageError> {
        self.extend(&value.to_be_bytes())
    }
    fn i64(&mut self, value: i64) -> Result<(), ControlJournalImageError> {
        self.extend(&value.to_be_bytes())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// Reader counterpart: every slice is checked before exposure, and callers
/// must consume the entire authenticated region before projection exposure.
struct ImageReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ImageReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ControlJournalImageError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ControlJournalImageError::InvalidControlJournalImage)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ControlJournalImageError::InvalidControlJournalImage)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ControlJournalImageError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ControlJournalImageError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| ControlJournalImageError::InvalidControlJournalImage,
        )?))
    }
    fn u32(&mut self) -> Result<u32, ControlJournalImageError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(
            |_| ControlJournalImageError::InvalidControlJournalImage,
        )?))
    }
    fn u64(&mut self) -> Result<u64, ControlJournalImageError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(
            |_| ControlJournalImageError::InvalidControlJournalImage,
        )?))
    }
    fn i64(&mut self) -> Result<i64, ControlJournalImageError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().map_err(
            |_| ControlJournalImageError::InvalidControlJournalImage,
        )?))
    }
    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn encode_head(
    writer: &mut ImageWriter,
    head: JournalHead,
) -> Result<(), ControlJournalImageError> {
    writer.u64(head.sequence)?;
    writer.extend(&head.digest)
}

fn decode_head(reader: &mut ImageReader<'_>) -> Result<JournalHead, ControlJournalImageError> {
    Ok(JournalHead {
        sequence: reader.u64()?,
        digest: reader
            .take(32)?
            .try_into()
            .map_err(|_| ControlJournalImageError::InvalidControlJournalImage)?,
    })
}

const IMAGE_LIMIT: usize = 8 * 1024 * 1024;
const CHECKPOINT_LIMIT: usize = 6 * 1024 * 1024 - 16 * 1024;
const ORDINARY_LIMIT: usize = 4 * 1024 * 1024 - 16 * 1024;
const RECONCILIATION_LIMIT: usize = 2 * 1024 * 1024;
const TAIL_LIMIT: usize = 2 * 1024 * 1024;
const FRAME_LIMIT: usize = 16 * 1024;
const TAIL_COUNT_LIMIT: usize = 128;
const CHECKPOINT_MEMBERS: u16 = 13;
const ORDINARY_COMMAND_ENTRY_LIMIT: usize = 4_032;
const STATE_OWNER_ACTOR: &[u8] = b"msgriver/state-owner/v1";
const INVALID: ControlJournalImageError = ControlJournalImageError::InvalidControlJournalImage;
const UNSUPPORTED: ControlJournalImageError = ControlJournalImageError::UnsupportedConstruction;

#[derive(Clone, Copy)]
enum ImageRegion {
    Checkpoint,
    Tail,
}

impl ImageRegion {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Checkpoint => CHECKPOINT_AUTH_LABEL,
            Self::Tail => TAIL_AUTH_LABEL,
        }
    }
}

impl ImageWriter {
    fn member(&mut self, tag: u16, bytes: &[u8]) -> Result<(), ControlJournalImageError> {
        self.u16(tag)?;
        self.u32(u32::try_from(bytes.len()).map_err(|_| INVALID)?)?;
        self.extend(bytes)
    }
}

impl<'a> ImageReader<'a> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ControlJournalImageError> {
        self.take(N)?.try_into().map_err(|_| INVALID)
    }

    fn member(&mut self, expected: u16) -> Result<&'a [u8], ControlJournalImageError> {
        if self.u16()? != expected {
            return Err(INVALID);
        }
        let length = usize::try_from(self.u32()?).map_err(|_| INVALID)?;
        self.take(length)
    }

    fn end(self) -> Result<(), ControlJournalImageError> {
        if self.finished() {
            Ok(())
        } else {
            Err(INVALID)
        }
    }
}

fn validate_head(head: JournalHead) -> Result<(), ControlJournalImageError> {
    if (head.sequence == 0) != (head.digest == [0; 32]) {
        return Err(INVALID);
    }
    Ok(())
}

impl AddressedOperation {
    fn code(self) -> u16 {
        match self {
            Self::ClockAcknowledge => 2,
            Self::SystemShutdown => 3,
        }
    }

    fn slot(self) -> usize {
        match self {
            Self::ClockAcknowledge => 0,
            Self::SystemShutdown => 2,
        }
    }

    fn kind(self) -> control_journal_record::ControlJournalRecordKind {
        match self {
            Self::ClockAcknowledge => {
                control_journal_record::ControlJournalRecordKind::ClockAcknowledge
            }
            Self::SystemShutdown => {
                control_journal_record::ControlJournalRecordKind::SystemShutdown
            }
        }
    }
}

fn addressed_complete(value: &AddressedStateValue) -> bool {
    value.phase >= 3 && !matches!(value.mirror, AddressedMirror::Pending { .. })
}

fn addressed_hold_matches(clock: ClockAuthority, address: AddressedOperationAddress) -> bool {
    clock.hold.is_some_and(|hold| {
        address
            == AddressedOperationAddress::ClockHold {
                generation: hold.generation,
                observation_digest: hold.observation_digest,
            }
    })
}

fn validate_addressed_actor(actor: &AddressedActor) -> Result<(), ControlJournalImageError> {
    if let AddressedActor::Principal(bytes) = actor
        && (bytes.is_empty()
            || bytes.len() > 128
            || !bytes[0].is_ascii_alphanumeric()
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(byte)))
    {
        return Err(INVALID);
    }
    Ok(())
}

fn validate_addressed_value(
    operation: AddressedOperation,
    value: &AddressedStateValue,
) -> Result<(), ControlJournalImageError> {
    validate_addressed_actor(&value.actor)?;
    match (
        operation,
        value.address,
        value.desired_transition,
        value.evidence,
        value.safe_result,
    ) {
        (
            AddressedOperation::ClockAcknowledge,
            AddressedOperationAddress::ClockHold {
                generation,
                observation_digest,
            },
            DesiredMonotonicTransition::SettleHold {
                risk_acknowledged: true,
            },
            AddressedEvidence::Acknowledge {
                accepted_wall_time,
                accepted_monotonic_tick,
                prior_fixed_safe_time,
                prior_selected_safe_time,
                target_safe_time,
            },
            AddressedResult::Acknowledge {
                settled_safe_time,
                settled,
            },
        ) => {
            let target = prior_fixed_safe_time
                .max(accepted_wall_time)
                .max(prior_selected_safe_time.unwrap_or(prior_fixed_safe_time));
            if generation == 0
                || observation_digest == [0; 32]
                || accepted_monotonic_tick < 0
                || target_safe_time != target
                || settled_safe_time != target
                || !(1..=3).contains(&value.phase)
                || settled != (value.phase == 3)
                || prior_selected_safe_time.is_none()
                    != matches!(value.mirror, AddressedMirror::NotApplicable)
            {
                return Err(INVALID);
            }
        }
        (
            AddressedOperation::SystemShutdown,
            AddressedOperationAddress::ProcessInstance(process),
            DesiredMonotonicTransition::StopProcess { grace_ms },
            AddressedEvidence::Shutdown {
                accepted_monotonic_tick,
                grace_deadline_tick,
            },
            AddressedResult::Shutdown { ungraceful_reason },
        ) => {
            if process == [0; 16]
                || grace_ms == 0
                || accepted_monotonic_tick < 0
                || accepted_monotonic_tick.checked_add(i64::from(grace_ms))
                    != Some(grace_deadline_tick)
                || !(1..=4).contains(&value.phase)
                || if value.phase == 4 {
                    !(1..=4).contains(&ungraceful_reason)
                } else {
                    ungraceful_reason != 0
                }
            {
                return Err(INVALID);
            }
        }
        _ => return Err(INVALID),
    }
    match value.mirror {
        AddressedMirror::NotApplicable => {}
        AddressedMirror::Pending {
            origin,
            pre,
            policy,
        }
        | AddressedMirror::Committed {
            origin,
            pre,
            policy,
            ..
        } => {
            if origin[24..] == [0; 8]
                || pre.digest == [0; 32]
                || !(match operation {
                    AddressedOperation::ClockAcknowledge => matches!(policy, 1 | 2),
                    AddressedOperation::SystemShutdown => policy == 3,
                })
            {
                return Err(INVALID);
            }
            match value.mirror {
                AddressedMirror::Committed { post, .. }
                    if value.phase < 3
                        || post.sequence <= pre.sequence
                        || post.digest == [0; 32] =>
                {
                    return Err(INVALID);
                }
                AddressedMirror::Pending { .. }
                    if operation == AddressedOperation::ClockAcknowledge && value.phase == 3 =>
                {
                    return Err(INVALID);
                }
                _ => {}
            }
        }
    }
    let application = value.application_head;
    let publication = value.publication_head;
    if application.sequence == 0
        || application.digest == [0; 32]
        || publication.sequence == 0
        || publication.digest == [0; 32]
        || application.sequence > publication.sequence
        || (application.sequence == publication.sequence
            && application.digest != publication.digest)
    {
        return Err(INVALID);
    }
    let receipt = operation == AddressedOperation::SystemShutdown
        && matches!(value.mirror, AddressedMirror::Committed { .. });
    if (receipt && application.sequence >= publication.sequence)
        || (!receipt && application != publication)
    {
        return Err(INVALID);
    }
    Ok(())
}

fn validate_addressed_cells(
    checkpoint: &CompleteCheckpoint,
) -> Result<(), ControlJournalImageError> {
    for (index, cell) in checkpoint.addressed.iter().enumerate() {
        let AddressedState::Present(value) = &cell.state else {
            continue;
        };
        validate_addressed_value(cell.operation, value)?;
        if cell.current == addressed_complete(value) {
            return Err(INVALID);
        }
        for head in [value.application_head, value.publication_head] {
            if head.sequence > checkpoint.covered_head.sequence
                || (head.sequence == checkpoint.covered_head.sequence
                    && head.digest != checkpoint.covered_head.digest)
            {
                return Err(INVALID);
            }
        }
        // One fixed-root record cannot produce or publish two operations.
        // A sequence identifies one record even if supplied digests differ.
        for other in &checkpoint.addressed[index + 1..] {
            if let AddressedState::Present(other_value) = &other.state
                && cell.operation != other.operation
                && [value.application_head, value.publication_head]
                    .iter()
                    .any(|head| {
                        head.sequence == other_value.application_head.sequence
                            || head.sequence == other_value.publication_head.sequence
                    })
            {
                return Err(INVALID);
            }
        }
        if let AddressedEvidence::Acknowledge {
            target_safe_time, ..
        } = value.evidence
        {
            if value.phase >= 2 && checkpoint.clock_authority.safe_time < target_safe_time {
                return Err(INVALID);
            }
            if let Some(hold) = checkpoint.clock_authority.hold {
                let AddressedOperationAddress::ClockHold { generation, .. } = value.address else {
                    return Err(INVALID);
                };
                if generation > hold.generation
                    || ((!cell.current || generation == hold.generation)
                        && !addressed_hold_matches(checkpoint.clock_authority, value.address))
                {
                    return Err(INVALID);
                }
            }
        }
    }
    for slot in [0, 2] {
        if let (AddressedState::Present(_), AddressedState::Present(_)) = (
            &checkpoint.addressed[slot].state,
            &checkpoint.addressed[slot + 1].state,
        ) {
            return Err(INVALID);
        }
    }
    Ok(())
}

fn encode_addressed_result(
    writer: &mut ImageWriter,
    result: AddressedResult,
) -> Result<(), ControlJournalImageError> {
    match result {
        AddressedResult::Acknowledge {
            settled_safe_time,
            settled,
        } => {
            writer.u16(0x77)?;
            writer.u16(1)?;
            writer.u16(9)?;
            writer.i64(settled_safe_time)?;
            writer.u8(u8::from(settled))
        }
        AddressedResult::Shutdown { ungraceful_reason } => {
            writer.u16(0x78)?;
            writer.u16(1)?;
            writer.u16(1)?;
            writer.u8(ungraceful_reason)
        }
    }
}

fn decode_addressed_result(
    reader: &mut ImageReader<'_>,
    operation: AddressedOperation,
) -> Result<AddressedResult, ControlJournalImageError> {
    let (codec, width) = match operation {
        AddressedOperation::ClockAcknowledge => (0x77, 9),
        AddressedOperation::SystemShutdown => (0x78, 1),
    };
    if reader.u16()? != codec || reader.u16()? != 1 || reader.u16()? != width {
        return Err(INVALID);
    }
    Ok(match operation {
        AddressedOperation::ClockAcknowledge => AddressedResult::Acknowledge {
            settled_safe_time: reader.i64()?,
            settled: match reader.u8()? {
                0 => false,
                1 => true,
                _ => return Err(INVALID),
            },
        },
        AddressedOperation::SystemShutdown => AddressedResult::Shutdown {
            ungraceful_reason: reader.u8()?,
        },
    })
}

fn encode_addressed_value(
    operation: AddressedOperation,
    value: &AddressedStateValue,
    with_heads: bool,
) -> Result<Vec<u8>, ControlJournalImageError> {
    validate_addressed_value(operation, value)?;
    let mut writer = ImageWriter::new(426);
    writer.u8(1)?;
    writer.u16(operation.code())?;
    let (kind, actor) = match &value.actor {
        AddressedActor::StateOwner => (2, STATE_OWNER_ACTOR),
        AddressedActor::Principal(bytes) => (1, bytes.as_slice()),
    };
    writer.u8(kind)?;
    writer.u8(u8::try_from(actor.len()).map_err(|_| INVALID)?)?;
    writer.extend(actor)?;
    match value.address {
        AddressedOperationAddress::ClockHold {
            generation,
            observation_digest,
        } => {
            writer.u64(generation)?;
            writer.extend(&observation_digest)?;
        }
        AddressedOperationAddress::ProcessInstance(process) => writer.extend(&process)?,
    }
    writer.u8(1)?;
    match value.desired_transition {
        DesiredMonotonicTransition::SettleHold { risk_acknowledged } => {
            writer.u8(u8::from(risk_acknowledged))?
        }
        DesiredMonotonicTransition::StopProcess { grace_ms } => writer.u32(grace_ms)?,
    }
    match value.evidence {
        AddressedEvidence::Acknowledge {
            accepted_wall_time,
            accepted_monotonic_tick,
            prior_fixed_safe_time,
            prior_selected_safe_time,
            target_safe_time,
        } => {
            writer.i64(accepted_wall_time)?;
            writer.i64(accepted_monotonic_tick)?;
            writer.i64(prior_fixed_safe_time)?;
            writer.u8(u8::from(prior_selected_safe_time.is_some()))?;
            if let Some(time) = prior_selected_safe_time {
                writer.i64(time)?;
            }
            writer.i64(target_safe_time)?;
        }
        AddressedEvidence::Shutdown {
            accepted_monotonic_tick,
            grace_deadline_tick,
        } => {
            writer.i64(accepted_monotonic_tick)?;
            writer.i64(grace_deadline_tick)?;
        }
    }
    writer.u8(value.phase)?;
    encode_addressed_result(&mut writer, value.safe_result)?;
    if with_heads {
        encode_head(&mut writer, value.application_head)?;
        encode_head(&mut writer, value.publication_head)?;
    }
    match value.mirror {
        AddressedMirror::NotApplicable => writer.u8(0)?,
        AddressedMirror::Pending {
            origin,
            pre,
            policy,
        }
        | AddressedMirror::Committed {
            origin,
            pre,
            policy,
            ..
        } => {
            writer.u8(if matches!(value.mirror, AddressedMirror::Pending { .. }) {
                1
            } else {
                2
            })?;
            writer.extend(&origin)?;
            encode_head(&mut writer, pre)?;
            writer.u8(policy)?;
            if let AddressedMirror::Committed { post, .. } = value.mirror {
                encode_head(&mut writer, post)?;
            }
        }
    }
    Ok(writer.finish())
}

/// Requests omit heads; authenticated replay supplies the envelope head for both.
fn decode_addressed_value(
    operation: AddressedOperation,
    bytes: &[u8],
    request_head: Option<JournalHead>,
) -> Result<AddressedStateValue, ControlJournalImageError> {
    if bytes.len() > 426 {
        return Err(INVALID);
    }
    let mut reader = ImageReader::new(bytes);
    if reader.u8()? != 1 || reader.u16()? != operation.code() {
        return Err(INVALID);
    }
    let kind = reader.u8()?;
    let length = usize::from(reader.u8()?);
    if !(1..=128).contains(&length) {
        return Err(INVALID);
    }
    let actor_bytes = reader.take(length)?;
    let actor = match kind {
        1 => AddressedActor::Principal(actor_bytes.to_vec()),
        2 if actor_bytes == STATE_OWNER_ACTOR => AddressedActor::StateOwner,
        _ => return Err(INVALID),
    };
    validate_addressed_actor(&actor)?;
    let address = match operation {
        AddressedOperation::ClockAcknowledge => AddressedOperationAddress::ClockHold {
            generation: reader.u64()?,
            observation_digest: reader.array()?,
        },
        AddressedOperation::SystemShutdown => {
            AddressedOperationAddress::ProcessInstance(reader.array()?)
        }
    };
    if reader.u8()? != 1 {
        return Err(INVALID);
    }
    let desired_transition = match operation {
        AddressedOperation::ClockAcknowledge => {
            if reader.u8()? != 1 {
                return Err(INVALID);
            }
            DesiredMonotonicTransition::SettleHold {
                risk_acknowledged: true,
            }
        }
        AddressedOperation::SystemShutdown => DesiredMonotonicTransition::StopProcess {
            grace_ms: reader.u32()?,
        },
    };
    let evidence = match operation {
        AddressedOperation::ClockAcknowledge => AddressedEvidence::Acknowledge {
            accepted_wall_time: reader.i64()?,
            accepted_monotonic_tick: reader.i64()?,
            prior_fixed_safe_time: reader.i64()?,
            prior_selected_safe_time: match reader.u8()? {
                0 => None,
                1 => Some(reader.i64()?),
                _ => return Err(INVALID),
            },
            target_safe_time: reader.i64()?,
        },
        AddressedOperation::SystemShutdown => AddressedEvidence::Shutdown {
            accepted_monotonic_tick: reader.i64()?,
            grace_deadline_tick: reader.i64()?,
        },
    };
    let phase = reader.u8()?;
    let safe_result = decode_addressed_result(&mut reader, operation)?;
    let (application_head, publication_head) = match request_head {
        Some(head) => (head, head),
        None => (decode_head(&mut reader)?, decode_head(&mut reader)?),
    };
    let mirror = match reader.u8()? {
        0 => AddressedMirror::NotApplicable,
        tag @ (1 | 2) => {
            let origin = reader.array()?;
            let pre = decode_head(&mut reader)?;
            let policy = reader.u8()?;
            if tag == 1 {
                AddressedMirror::Pending {
                    origin,
                    pre,
                    policy,
                }
            } else {
                AddressedMirror::Committed {
                    origin,
                    pre,
                    policy,
                    post: decode_head(&mut reader)?,
                }
            }
        }
        _ => return Err(INVALID),
    };
    reader.end()?;
    let value = AddressedStateValue {
        actor,
        address,
        desired_transition,
        evidence,
        phase,
        safe_result,
        application_head,
        publication_head,
        mirror,
    };
    validate_addressed_value(operation, &value)?;
    Ok(value)
}

fn encode_addressed_action(
    operation: AddressedOperation,
    action: &AddressedAction,
) -> Result<Vec<u8>, ControlJournalImageError> {
    let mut payload = ImageWriter::new(306);
    let tag = match action {
        AddressedAction::PublishRequest(value) => {
            if value.phase != 1 || matches!(value.mirror, AddressedMirror::Committed { .. }) {
                return Err(INVALID);
            }
            payload.extend(&encode_addressed_value(operation, value, false)?)?;
            1
        }
        AddressedAction::PublishPhase { phase, result } => {
            payload.u8(*phase)?;
            encode_addressed_result(&mut payload, *result)?;
            2
        }
        AddressedAction::CommitMirror(post) => {
            encode_head(&mut payload, *post)?;
            3
        }
    };
    let payload = payload.finish();
    let mut writer = ImageWriter::new(310);
    writer.u8(1)?;
    writer.u8(tag)?;
    writer.u16(u16::try_from(payload.len()).map_err(|_| INVALID)?)?;
    writer.extend(&payload)?;
    Ok(writer.finish())
}

fn decode_addressed_action(
    operation: AddressedOperation,
    bytes: &[u8],
    head: JournalHead,
) -> Result<AddressedAction, ControlJournalImageError> {
    let mut reader = ImageReader::new(bytes);
    if reader.u8()? != 1 {
        return Err(INVALID);
    }
    let tag = reader.u8()?;
    let length = usize::from(reader.u16()?);
    let payload = reader.take(length)?;
    reader.end()?;
    let mut reader = ImageReader::new(payload);
    let action = match tag {
        1 => AddressedAction::PublishRequest(Box::new(decode_addressed_value(
            operation,
            reader.take(length)?,
            Some(head),
        )?)),
        2 => AddressedAction::PublishPhase {
            phase: reader.u8()?,
            result: decode_addressed_result(&mut reader, operation)?,
        },
        3 => AddressedAction::CommitMirror(decode_head(&mut reader)?),
        _ => return Err(INVALID),
    };
    reader.end()?;
    if encode_addressed_action(operation, &action)? != bytes {
        return Err(INVALID);
    }
    Ok(action)
}

/// Retention reads the old hold before clearing it, so a superseded obligation
/// can never regain disclosure eligibility after a newer hold clears.
fn complete_acknowledge(checkpoint: &mut CompleteCheckpoint, value: Box<AddressedStateValue>) {
    checkpoint.addressed[0].state = AddressedState::Absent;
    if addressed_hold_matches(checkpoint.clock_authority, value.address) {
        checkpoint.clock_authority.hold = None;
        checkpoint.addressed[1].state = AddressedState::Present(value);
    }
}

fn replay_addressed(
    checkpoint: &mut CompleteCheckpoint,
    operation: AddressedOperation,
    action: &AddressedAction,
    head: JournalHead,
) -> Result<(), ControlJournalImageError> {
    let slot = operation.slot();
    let mut value = match action {
        AddressedAction::PublishRequest(request) => {
            if checkpoint.addressed[slot].state != AddressedState::Absent
                || request.phase != 1
                || request.application_head != head
                || request.publication_head != head
            {
                return Err(INVALID);
            }
            match (&checkpoint.active_pointer, request.mirror) {
                (None, AddressedMirror::NotApplicable) => {}
                (Some(pointer), AddressedMirror::Pending { origin, .. })
                    if origin == pointer.target_history_epoch => {}
                _ => return Err(INVALID),
            }
            if let AddressedEvidence::Acknowledge {
                prior_fixed_safe_time,
                ..
            } = request.evidence
                && (!addressed_hold_matches(checkpoint.clock_authority, request.address)
                    || prior_fixed_safe_time != checkpoint.clock_authority.safe_time)
            {
                return Err(INVALID);
            }
            if let AddressedState::Present(last) = &checkpoint.addressed[slot + 1].state
                && last.address == request.address
            {
                return Err(INVALID);
            }
            request.clone()
        }
        _ => {
            let AddressedState::Present(value) = &checkpoint.addressed[slot].state else {
                return Err(INVALID);
            };
            value.clone()
        }
    };
    match action {
        AddressedAction::PublishRequest(_) => {
            if operation == AddressedOperation::SystemShutdown {
                // Last contains only resolved completion; a new process makes
                // that completion ineligible in replay as well as after folding.
                checkpoint.addressed[slot + 1].state = AddressedState::Absent;
            }
        }
        AddressedAction::PublishPhase { phase, result } => {
            let legal = match operation {
                AddressedOperation::ClockAcknowledge => {
                    (value.phase == 1 && *phase == 2)
                        || (value.phase == 2
                            && *phase == 3
                            && matches!(value.mirror, AddressedMirror::NotApplicable))
                }
                // The append seam authorizes recovery. Reopening authenticated
                // history replays its already-authorized recovery edge.
                AddressedOperation::SystemShutdown => {
                    matches!((value.phase, *phase), (1, 2 | 4) | (2, 3 | 4))
                }
            };
            if !legal || matches!(value.mirror, AddressedMirror::Committed { .. }) {
                return Err(INVALID);
            }
            if operation == AddressedOperation::ClockAcknowledge && *phase == 2 {
                let AddressedEvidence::Acknowledge {
                    target_safe_time, ..
                } = value.evidence
                else {
                    return Err(INVALID);
                };
                if !addressed_hold_matches(checkpoint.clock_authority, value.address)
                    || target_safe_time < checkpoint.clock_authority.safe_time
                {
                    return Err(INVALID);
                }
                checkpoint.clock_authority.safe_time = target_safe_time;
            }
            value.phase = *phase;
            value.safe_result = *result;
            value.application_head = head;
            value.publication_head = head;
        }
        AddressedAction::CommitMirror(post) => {
            let AddressedMirror::Pending {
                origin,
                pre,
                policy,
            } = value.mirror
            else {
                return Err(INVALID);
            };
            if (operation == AddressedOperation::ClockAcknowledge && value.phase != 2)
                || (operation == AddressedOperation::SystemShutdown
                    && !matches!(value.phase, 3 | 4))
                || post.sequence <= pre.sequence
                || post.digest == [0; 32]
            {
                return Err(INVALID);
            }
            value.mirror = AddressedMirror::Committed {
                origin,
                pre,
                policy,
                post: *post,
            };
            value.publication_head = head;
            if operation == AddressedOperation::ClockAcknowledge {
                let AddressedEvidence::Acknowledge {
                    target_safe_time, ..
                } = value.evidence
                else {
                    return Err(INVALID);
                };
                value.phase = 3;
                value.safe_result = AddressedResult::Acknowledge {
                    settled_safe_time: target_safe_time,
                    settled: true,
                };
                value.application_head = head;
            }
        }
    }
    validate_addressed_value(operation, &value)?;
    if addressed_complete(&value) {
        if operation == AddressedOperation::ClockAcknowledge {
            complete_acknowledge(checkpoint, value);
        } else {
            checkpoint.addressed[slot].state = AddressedState::Absent;
            checkpoint.addressed[slot + 1].state = AddressedState::Present(value);
        }
    } else {
        checkpoint.addressed[slot].state = AddressedState::Present(value);
    }
    Ok(())
}

/// Process authority and recovery mode come from lifecycle reconstruction;
/// neither becomes another encoded cell field.
fn append_addressed_action(
    key: &JournalIntegrityKey,
    image: &CompleteControlJournalImage,
    operation: AddressedOperation,
    action: AddressedAction,
    current_process: [u8; 16],
    recovery: bool,
) -> Result<CompleteControlJournalImage, ControlJournalImageError> {
    encode_control_journal_image(key, image)?;
    let projection = replay_tail(image)?;
    if current_process == [0; 16] {
        return Err(INVALID);
    }
    if operation == AddressedOperation::SystemShutdown {
        let value = match &action {
            AddressedAction::PublishRequest(value) => value,
            _ => match &projection.addressed[2].state {
                AddressedState::Present(value) => value,
                AddressedState::Absent => return Err(INVALID),
            },
        };
        let active = value.address == AddressedOperationAddress::ProcessInstance(current_process);
        match &action {
            AddressedAction::PublishRequest(_) if !active => return Err(INVALID),
            AddressedAction::PublishPhase { phase, .. } => {
                if !(active || recovery && *phase == 4)
                    || (value.phase == 1 && *phase == 4 && !recovery)
                {
                    return Err(INVALID);
                }
            }
            AddressedAction::CommitMirror(_) if !active && !recovery => return Err(INVALID),
            _ => {}
        }
    }
    let body = encode_addressed_action(operation, &action)?;
    let prior = projection.covered_head;
    let wire = key
        .encode_control_journal_record(operation.kind(), &body, component_head(prior))
        .map_err(|_| INVALID)?;
    let record = key
        .decode_control_journal_record(&wire, component_head(prior))
        .map_err(|_| INVALID)?;
    let head = JournalHead {
        sequence: record.sequence,
        digest: record.record_digest,
    };
    // Normalize the omitted request heads to their sole canonical source.
    let action = decode_addressed_action(operation, &body, head)?;
    let mut checkpoint = projection;
    replay_addressed(&mut checkpoint, operation, &action, head)?;
    checkpoint.covered_head = head;
    let tail_bytes = image.tail.iter().try_fold(104_usize, |total, frame| {
        total
            .checked_add(encode_tail_frame(key, frame.prior_head, frame)?.len())
            .ok_or(INVALID)
    })?;
    let superseded = operation == AddressedOperation::SystemShutdown
        && matches!(&checkpoint.addressed[3].state, AddressedState::Present(value)
            if value.address != AddressedOperationAddress::ProcessInstance(current_process));
    let mut next = image.clone();
    if superseded || image.tail.len() == TAIL_COUNT_LIMIT || tail_bytes + wire.len() > TAIL_LIMIT {
        if superseded {
            checkpoint.addressed[3].state = AddressedState::Absent;
        }
        checkpoint.generation = checkpoint.generation.checked_add(1).ok_or(INVALID)?;
        next.checkpoint = checkpoint;
        next.tail.clear();
    } else {
        next.tail.push(AuthenticatedTailFrame {
            prior_head: prior,
            resulting_head: head,
            record: match operation {
                AddressedOperation::ClockAcknowledge => TailRecord::ClockAcknowledge(action),
                AddressedOperation::SystemShutdown => TailRecord::SystemShutdown(action),
            },
        });
    }
    encode_control_journal_image(key, &next)?;
    Ok(next)
}

/// Full-image hold entry/startup publication. Pending obligations remain exact;
/// only completed results lose eligibility when external authority advances.
fn publish_addressed_authority(
    key: &JournalIntegrityKey,
    image: &CompleteControlJournalImage,
    clock: ClockAuthority,
    current_process: [u8; 16],
) -> Result<CompleteControlJournalImage, ControlJournalImageError> {
    encode_control_journal_image(key, image)?;
    let mut next = fold_control_journal_image(image, FoldTrigger::TailFrameLimit)?;
    let prior = next.checkpoint.clock_authority;
    if current_process == [0; 16] || clock.safe_time < prior.safe_time {
        return Err(INVALID);
    }
    // Hold clearance needs the settlement publication and its barrier.
    if let Some(old) = prior.hold {
        let Some(new) = clock.hold else {
            return Err(INVALID);
        };
        if new.generation < old.generation || (new.generation == old.generation && new != old) {
            return Err(INVALID);
        }
    }
    if let AddressedState::Present(last) = &next.checkpoint.addressed[1].state
        && clock.hold.is_some()
        && !addressed_hold_matches(clock, last.address)
    {
        let AddressedOperationAddress::ClockHold { generation, .. } = last.address else {
            return Err(INVALID);
        };
        if clock.hold.is_some_and(|hold| hold.generation <= generation) {
            return Err(INVALID);
        }
        next.checkpoint.addressed[1].state = AddressedState::Absent;
    }
    if let AddressedState::Present(last) = &next.checkpoint.addressed[3].state
        && last.address != AddressedOperationAddress::ProcessInstance(current_process)
    {
        next.checkpoint.addressed[3].state = AddressedState::Absent;
    }
    next.checkpoint.clock_authority = clock;
    encode_control_journal_image(key, &next)?;
    Ok(next)
}

/// Authentication/authorization belong to the caller. This private query grants
/// neither, and pending obligations never disclose a completed result.
fn addressed_completion(
    image: &CompleteControlJournalImage,
    operation: AddressedOperation,
    address: AddressedOperationAddress,
    current_process: [u8; 16],
) -> Result<Option<AddressedResult>, ControlJournalImageError> {
    let checkpoint = replay_tail(image)?;
    let eligible = match (operation, address) {
        (AddressedOperation::ClockAcknowledge, AddressedOperationAddress::ClockHold { .. }) => {
            checkpoint.clock_authority.hold.is_none()
                || addressed_hold_matches(checkpoint.clock_authority, address)
        }
        (
            AddressedOperation::SystemShutdown,
            AddressedOperationAddress::ProcessInstance(process),
        ) => process != [0; 16] && process == current_process,
        _ => false,
    };
    if eligible
        && let AddressedState::Present(value) = &checkpoint.addressed[operation.slot() + 1].state
        && value.address == address
        && addressed_complete(value)
    {
        return Ok(Some(value.safe_result));
    }
    Ok(None)
}

fn validate_checkpoint(checkpoint: &CompleteCheckpoint) -> Result<(), ControlJournalImageError> {
    if checkpoint.generation == 0 {
        return Err(INVALID);
    }
    validate_head(checkpoint.covered_head)?;
    clock_authority_projection::encode_clock_authority_projection(checkpoint.clock_authority)
        .map_err(|_| INVALID)?;
    for (index, cell) in checkpoint.addressed.iter().enumerate() {
        let operation = if index < 2 {
            AddressedOperation::ClockAcknowledge
        } else {
            AddressedOperation::SystemShutdown
        };
        if cell.operation != operation || cell.current != (index % 2 == 0) {
            return Err(INVALID);
        }
    }
    validate_addressed_cells(checkpoint)?;
    // Upgrade groups still lack complete profile codecs.
    if !checkpoint.provenance.is_empty()
        || checkpoint.coordinator.is_some()
        || checkpoint.open_upgrade.is_some()
    {
        return Err(UNSUPPORTED);
    }
    if checkpoint.local_commands.len() > ORDINARY_COMMAND_ENTRY_LIMIT {
        return Err(INVALID);
    }
    let mut previous_key = None;
    for command in &checkpoint.local_commands {
        if command.operation != FixedRootOperation::RecoveryKeyGenerate
            || command.target_binding.is_some()
            || !matches!(
                (command.phase, command.retention),
                (1 | 2, CommandRetention::Continuation)
                    | (3 | 4, CommandRetention::Terminal { .. })
            )
        {
            return Err(UNSUPPORTED);
        }
        if let Some(result) = command.safe_result
            && (result.codec != 0x0076 || result.version != 1)
        {
            return Err(INVALID);
        }
        if command.process_instance == [0; 16] {
            return Err(INVALID);
        }
        recovery_key_generate_profile::decode_recovery_key_generate_profile(
            &recovery_key_generate_profile::encode_recovery_key_generate_profile(command.profile.0),
        )
        .map_err(|_| INVALID)?;
        let key = command_projection_key(command)?;
        if previous_key
            .as_ref()
            .is_some_and(|previous| previous >= &key)
        {
            return Err(INVALID);
        }
        previous_key = Some(key);
    }
    Ok(())
}

fn command_projection_key(
    command: &FixedRootCommandProjection,
) -> Result<Vec<u8>, ControlJournalImageError> {
    let mut key = vec![4];
    match &command.actor {
        StableActorNamespace::Principal(value) => {
            check_identifier(value).map_err(|_| INVALID)?;
            key.push(1);
            key.push(u8::try_from(value.len()).map_err(|_| INVALID)?);
            key.extend_from_slice(value);
        }
        StableActorNamespace::StateOwner => {
            key.push(2);
            key.push(u8::try_from(STATE_OWNER_ACTOR.len()).map_err(|_| INVALID)?);
            key.extend_from_slice(STATE_OWNER_ACTOR);
        }
    }
    if command.lookup.key.purpose() != MacPurpose::CommandLookupV1 {
        return Err(INVALID);
    }
    key.extend_from_slice(command.lookup.key.key_id().as_bytes());
    key.extend_from_slice(&command.lookup.tag);
    Ok(key)
}

fn expected_prebootstrap_origin(owner_namespace: [u8; 24]) -> [u8; 32] {
    let mut origin = [0; 32];
    origin[..24].copy_from_slice(&owner_namespace);
    origin
}

fn validate_command_tag(
    tag: CommandTag,
    expected_purpose: MacPurpose,
    expected_prebootstrap_origin: [u8; 32],
) -> Result<(), ControlJournalImageError> {
    if tag.key.purpose() != expected_purpose {
        return Err(INVALID);
    }
    let key_id = tag.key.key_id();
    let key = key_id.as_bytes();
    if key[32..].iter().all(|byte| *byte == 0) {
        return Err(INVALID);
    }
    let origin_serial_is_zero = key[24..32].iter().all(|byte| *byte == 0);
    if origin_serial_is_zero
        && (expected_purpose != MacPurpose::PortableReservationV1
            || key[..32] != expected_prebootstrap_origin)
    {
        return Err(INVALID);
    }
    Ok(())
}

fn encode_command_projection(
    owner_namespace: [u8; 24],
    projection: &FixedRootCommandProjection,
) -> Result<Vec<u8>, ControlJournalImageError> {
    if projection.operation != FixedRootOperation::RecoveryKeyGenerate
        || projection.target_binding.is_some()
    {
        return Err(UNSUPPORTED);
    }
    let mut wire = Vec::new();
    wire.extend_from_slice(&[1, 4]);
    match &projection.actor {
        StableActorNamespace::Principal(value) => {
            check_identifier(value).map_err(|_| INVALID)?;
            wire.extend_from_slice(&[1, u8::try_from(value.len()).map_err(|_| INVALID)?]);
            wire.extend_from_slice(value);
        }
        StableActorNamespace::StateOwner => {
            wire.push(2);
            wire.push(u8::try_from(STATE_OWNER_ACTOR.len()).map_err(|_| INVALID)?);
            wire.extend_from_slice(STATE_OWNER_ACTOR);
        }
    }
    for (tag, purpose) in [
        (projection.lookup, MacPurpose::CommandLookupV1),
        (
            projection.semantic_fingerprint,
            MacPurpose::CommandSemanticFingerprintV1,
        ),
        (
            projection.phase_fingerprint,
            MacPurpose::CommandPhaseFingerprintV1,
        ),
        (
            projection.portable_reservation,
            MacPurpose::PortableReservationV1,
        ),
    ] {
        validate_command_tag(tag, purpose, expected_prebootstrap_origin(owner_namespace))?;
        wire.extend_from_slice(tag.key.key_id().as_bytes());
        wire.extend_from_slice(&tag.tag);
    }
    wire.push(match projection.runtime {
        CommandRuntime::Normal => 1,
        CommandRuntime::Maintenance => 2,
    });
    wire.extend_from_slice(&projection.process_instance);
    match projection.original_deadline {
        None => wire.push(0),
        Some(value) => {
            wire.push(1);
            wire.extend_from_slice(&value.to_be_bytes());
        }
    }
    wire.extend_from_slice(&projection.phase.to_be_bytes());
    match projection.retention {
        CommandRetention::Continuation => wire.extend_from_slice(&[1, 0, 0]),
        CommandRetention::Terminal {
            terminal_time,
            expires_at,
        } if expires_at > terminal_time && projection.safe_result.is_some() => {
            wire.extend_from_slice(&[2, 1]);
            wire.extend_from_slice(&terminal_time.to_be_bytes());
            wire.push(1);
            wire.extend_from_slice(&expires_at.to_be_bytes());
        }
        CommandRetention::Terminal { .. } => return Err(INVALID),
    }
    match projection.safe_result {
        None => wire.push(0),
        Some(result) => {
            wire.push(1);
            wire.extend_from_slice(&result.codec.to_be_bytes());
            wire.extend_from_slice(&result.version.to_be_bytes());
            wire.extend_from_slice(&result.digest);
        }
    }
    wire.push(0);
    let profile =
        recovery_key_generate_profile::encode_recovery_key_generate_profile(projection.profile.0);
    wire.extend_from_slice(
        &u16::try_from(profile.len())
            .map_err(|_| INVALID)?
            .to_be_bytes(),
    );
    wire.extend_from_slice(&profile);
    if wire.len() > 16_274 {
        return Err(INVALID);
    }
    Ok(wire)
}

fn decode_command_projection(
    owner_namespace: [u8; 24],
    wire: &[u8],
) -> Result<FixedRootCommandProjection, ControlJournalImageError> {
    let mut reader = ImageReader::new(wire);
    if reader.u8()? != 1 || reader.u8()? != 4 {
        return Err(UNSUPPORTED);
    }
    let actor = match reader.u8()? {
        1 => {
            let length = usize::from(reader.u8()?);
            let value = reader.take(length)?.to_vec();
            check_identifier(&value).map_err(|_| INVALID)?;
            StableActorNamespace::Principal(value)
        }
        2 => {
            let length = usize::from(reader.u8()?);
            let value = reader.take(length)?;
            if value != STATE_OWNER_ACTOR {
                return Err(INVALID);
            }
            StableActorNamespace::StateOwner
        }
        _ => return Err(INVALID),
    };
    let mut tag = |purpose| -> Result<CommandTag, ControlJournalImageError> {
        Ok(CommandTag {
            key: MacKeyRef::new(purpose, MacKeyId::from_bytes(reader.array()?)),
            tag: reader.array()?,
        })
    };
    let lookup = tag(MacPurpose::CommandLookupV1)?;
    let semantic_fingerprint = tag(MacPurpose::CommandSemanticFingerprintV1)?;
    let phase_fingerprint = tag(MacPurpose::CommandPhaseFingerprintV1)?;
    let portable_reservation = tag(MacPurpose::PortableReservationV1)?;
    for (tag, purpose) in [
        (lookup, MacPurpose::CommandLookupV1),
        (
            semantic_fingerprint,
            MacPurpose::CommandSemanticFingerprintV1,
        ),
        (phase_fingerprint, MacPurpose::CommandPhaseFingerprintV1),
        (portable_reservation, MacPurpose::PortableReservationV1),
    ] {
        validate_command_tag(tag, purpose, expected_prebootstrap_origin(owner_namespace))?;
    }
    let runtime = match reader.u8()? {
        1 => CommandRuntime::Normal,
        2 => CommandRuntime::Maintenance,
        _ => return Err(INVALID),
    };
    let process_instance = reader.array()?;
    let original_deadline = match reader.u8()? {
        0 => None,
        1 => Some(reader.i64()?),
        _ => return Err(INVALID),
    };
    let phase = reader.u16()?;
    let retention = match (reader.u8()?, reader.u8()?) {
        (1, 0) if reader.u8()? == 0 => CommandRetention::Continuation,
        (2, 1) => {
            let terminal_time = reader.i64()?;
            if reader.u8()? != 1 {
                return Err(INVALID);
            }
            let expires_at = reader.i64()?;
            CommandRetention::Terminal {
                terminal_time,
                expires_at,
            }
        }
        _ => return Err(INVALID),
    };
    let safe_result = match reader.u8()? {
        0 => None,
        1 => Some(CommandSafeResult {
            codec: reader.u16()?,
            version: reader.u16()?,
            digest: reader.array()?,
        }),
        _ => return Err(INVALID),
    };
    if reader.u8()? != 0 {
        return Err(UNSUPPORTED);
    }
    let profile_length = usize::from(reader.u16()?);
    let profile = recovery_key_generate_profile::decode_recovery_key_generate_profile(
        reader.take(profile_length)?,
    )
    .map_err(|_| INVALID)?;
    reader.end()?;
    let projection = FixedRootCommandProjection {
        operation: FixedRootOperation::RecoveryKeyGenerate,
        actor,
        lookup,
        semantic_fingerprint,
        phase_fingerprint,
        portable_reservation,
        runtime,
        process_instance,
        original_deadline,
        phase,
        retention,
        safe_result,
        target_binding: None,
        profile: RecoveryKeyGenerateProfile(profile),
    };
    validate_checkpoint(&CompleteCheckpoint {
        generation: 1,
        covered_head: JournalHead {
            sequence: 0,
            digest: [0; 32],
        },
        clock_authority: ClockAuthority {
            safe_time: 0,
            hold: None,
            last_shutdown_observation: None,
        },
        active_pointer: None,
        recovery_ring: vec![],
        local_commands: vec![projection.clone()],
        addressed: std::array::from_fn(|index| AddressedCell {
            operation: if index < 2 {
                AddressedOperation::ClockAcknowledge
            } else {
                AddressedOperation::SystemShutdown
            },
            current: index % 2 == 0,
            state: AddressedState::Absent,
        }),
        provenance: vec![],
        coordinator: None,
        open_upgrade: None,
    })?;
    Ok(projection)
}

fn encode_command_member(
    owner_namespace: [u8; 24],
    commands: &[FixedRootCommandProjection],
) -> Result<Vec<u8>, ControlJournalImageError> {
    if commands.len() > ORDINARY_COMMAND_ENTRY_LIMIT {
        return Err(INVALID);
    }
    let mut writer = ImageWriter::new(ORDINARY_LIMIT - 72);
    writer.u32(u32::try_from(commands.len()).map_err(|_| INVALID)?)?;
    for command in commands {
        let wire = encode_command_projection(owner_namespace, command)?;
        writer.u16(u16::try_from(wire.len()).map_err(|_| INVALID)?)?;
        writer.extend(&wire)?;
    }
    Ok(writer.finish())
}

fn decode_command_member(
    owner_namespace: [u8; 24],
    bytes: &[u8],
) -> Result<Vec<FixedRootCommandProjection>, ControlJournalImageError> {
    let mut reader = ImageReader::new(bytes);
    let count = usize::try_from(reader.u32()?).map_err(|_| INVALID)?;
    if count > ORDINARY_COMMAND_ENTRY_LIMIT || count > bytes.len().saturating_sub(4) / 2 {
        return Err(INVALID);
    }
    let mut commands = Vec::with_capacity(count);
    for _ in 0..count {
        let length = usize::from(reader.u16()?);
        let wire = reader.take(length)?;
        commands.push(decode_command_projection(owner_namespace, wire)?);
    }
    reader.end()?;
    Ok(commands)
}

fn validate_image_bindings(
    image: &CompleteControlJournalImage,
) -> Result<(), ControlJournalImageError> {
    let pointer_origins = image
        .checkpoint
        .active_pointer
        .iter()
        .map(|pointer| pointer.target_history_epoch);
    let mirror_origins = image.checkpoint.addressed.iter().filter_map(|cell| {
        let AddressedState::Present(value) = &cell.state else {
            return None;
        };
        match value.mirror {
            AddressedMirror::NotApplicable => None,
            AddressedMirror::Pending { origin, .. } | AddressedMirror::Committed { origin, .. } => {
                Some(origin)
            }
        }
    });
    // Retention survives selection changes, but never grants foreign or
    // unallocated origins local authority.
    for epoch in pointer_origins.chain(mirror_origins) {
        let serial = u64::from_be_bytes(epoch[24..].try_into().map_err(|_| INVALID)?);
        if epoch[..24] != image.header.owner_namespace
            || serial == 0
            || serial > image.header.branch_serial_high_water
        {
            return Err(INVALID);
        }
    }
    // Generation one is the initialized checkpoint, not a way to mint a
    // non-genesis covered head or synthesize an existing hold/shutdown result.
    if image.checkpoint.generation == 1
        && (image.checkpoint.covered_head.sequence != 0
            || image.checkpoint.clock_authority.hold.is_some()
            || image
                .checkpoint
                .clock_authority
                .last_shutdown_observation
                .is_some()
            || image.checkpoint.active_pointer.is_some()
            || !image.checkpoint.recovery_ring.is_empty())
    {
        return Err(INVALID);
    }
    Ok(())
}

fn encode_ring(
    key: &JournalIntegrityKey,
    entries: &[RecoveryRingEntry],
) -> Result<Vec<u8>, ControlJournalImageError> {
    use recovery_ring_manifest as component;
    // Bound before copying even a trusted construction input.
    if entries.len() > 16 {
        return Err(INVALID);
    }
    let manifest = component::RecoveryRingManifest {
        entries: entries
            .iter()
            .map(|entry| component::RecoveryRingEntry {
                generation: component::RecoveryGeneration(entry.generation),
                phase: match entry.phase {
                    RecoveryRingPhase::Retained => component::RecoveryRingPhase::Retained,
                    RecoveryRingPhase::Active => component::RecoveryRingPhase::Active,
                    RecoveryRingPhase::PendingEscrow => component::RecoveryRingPhase::PendingEscrow,
                },
            })
            .collect(),
    };
    component::encode_recovery_ring_manifest(key, &manifest).map_err(|_| INVALID)
}

fn decode_ring(
    key: &JournalIntegrityKey,
    bytes: &[u8],
) -> Result<Vec<RecoveryRingEntry>, ControlJournalImageError> {
    use recovery_ring_manifest as component;
    let manifest = component::decode_recovery_ring_manifest(key, bytes).map_err(|_| INVALID)?;
    Ok(manifest
        .entries
        .into_iter()
        .map(|entry| RecoveryRingEntry {
            generation: entry.generation.0,
            phase: match entry.phase {
                component::RecoveryRingPhase::Retained => RecoveryRingPhase::Retained,
                component::RecoveryRingPhase::Active => RecoveryRingPhase::Active,
                component::RecoveryRingPhase::PendingEscrow => RecoveryRingPhase::PendingEscrow,
            },
        })
        .collect())
}

fn encode_checkpoint(
    key: &JournalIntegrityKey,
    owner_namespace: [u8; 24],
    checkpoint: &CompleteCheckpoint,
) -> Result<Vec<u8>, ControlJournalImageError> {
    validate_checkpoint(checkpoint)?;
    // All supported variable entries are ordinary. The four addressed cells
    // occupy only reconciliation space; no ordinary entry borrows that reserve.
    let mut ordinary = ImageWriter::new(ORDINARY_LIMIT - 72);
    ordinary.member(1, &checkpoint.generation.to_be_bytes())?;
    let mut head = ImageWriter::new(40);
    encode_head(&mut head, checkpoint.covered_head)?;
    ordinary.member(2, &head.finish())?;
    ordinary.member(
        3,
        &clock_authority_projection::encode_clock_authority_projection(checkpoint.clock_authority)
            .map_err(|_| INVALID)?,
    )?;
    let mut pointer = ImageWriter::new(625);
    match &checkpoint.active_pointer {
        None => pointer.u8(0)?,
        Some(value) => {
            pointer.u8(1)?;
            pointer.extend(
                &active_state_pointer::encode_active_state_pointer(key, value)
                    .map_err(|_| INVALID)?,
            )?;
        }
    }
    ordinary.member(4, &pointer.finish())?;
    ordinary.member(5, &encode_ring(key, &checkpoint.recovery_ring)?)?;
    ordinary.member(
        6,
        &encode_command_member(owner_namespace, &checkpoint.local_commands)?,
    )?;
    let mut reconciliation = ImageWriter::new(RECONCILIATION_LIMIT);
    for (tag, cell) in (7..=10).zip(&checkpoint.addressed) {
        let body = match &cell.state {
            AddressedState::Absent => vec![0],
            AddressedState::Present(value) => encode_addressed_value(cell.operation, value, true)?,
        };
        reconciliation.member(tag, &body)?;
    }
    let mut suffix = ImageWriter::new(ORDINARY_LIMIT);
    suffix.member(11, &0_u32.to_be_bytes())?;
    suffix.member(12, &[0])?;
    suffix.member(13, &[0])?;
    if ordinary.bytes.len() + suffix.bytes.len() + 72 > ORDINARY_LIMIT {
        return Err(INVALID);
    }
    let mut payload = ImageWriter::new(CHECKPOINT_LIMIT - 72);
    payload.extend(&ordinary.finish())?;
    payload.extend(&reconciliation.finish())?;
    payload.extend(&suffix.finish())?;
    Ok(payload.finish())
}

fn decode_checkpoint(
    key: &JournalIntegrityKey,
    owner_namespace: [u8; 24],
    bytes: &[u8],
) -> Result<CompleteCheckpoint, ControlJournalImageError> {
    let mut reader = ImageReader::new(bytes);
    let mut generation = ImageReader::new(reader.member(1)?);
    let generation_value = generation.u64()?;
    generation.end()?;
    let mut head = ImageReader::new(reader.member(2)?);
    let covered_head = decode_head(&mut head)?;
    head.end()?;
    let clock_authority =
        clock_authority_projection::decode_clock_authority_projection(reader.member(3)?)
            .map_err(|_| INVALID)?;
    let mut pointer = ImageReader::new(reader.member(4)?);
    let active_pointer = match pointer.u8()? {
        0 => {
            pointer.end()?;
            None
        }
        1 => Some(
            active_state_pointer::decode_active_state_pointer(
                key,
                pointer.take(pointer.bytes.len() - pointer.offset)?,
            )
            .map_err(|_| INVALID)?,
        ),
        _ => return Err(INVALID),
    };
    let recovery_ring = decode_ring(key, reader.member(5)?)?;
    let local_commands = decode_command_member(owner_namespace, reader.member(6)?)?;
    let mut addressed = std::array::from_fn(|index| AddressedCell {
        operation: if index < 2 {
            AddressedOperation::ClockAcknowledge
        } else {
            AddressedOperation::SystemShutdown
        },
        current: index % 2 == 0,
        state: AddressedState::Absent,
    });
    for (tag, cell) in (7..=10).zip(&mut addressed) {
        let body = reader.member(tag)?;
        if body != [0] {
            cell.state = AddressedState::Present(Box::new(decode_addressed_value(
                cell.operation,
                body,
                None,
            )?));
        }
    }
    if reader.member(11)? != 0_u32.to_be_bytes()
        || reader.member(12)? != [0]
        || reader.member(13)? != [0]
    {
        return Err(INVALID);
    }
    reader.end()?;
    let checkpoint = CompleteCheckpoint {
        generation: generation_value,
        covered_head,
        clock_authority,
        active_pointer,
        recovery_ring,
        local_commands,
        addressed,
        provenance: Vec::new(),
        coordinator: None,
        open_upgrade: None,
    };
    // Re-encoding applies the same component and partition checks and proves
    // canonical equality, including explicit absence and all required slots.
    if encode_checkpoint(key, owner_namespace, &checkpoint).map_err(|_| INVALID)? != bytes {
        return Err(INVALID);
    }
    Ok(checkpoint)
}

fn seal_region(
    key: &JournalIntegrityKey,
    region: ImageRegion,
    count: u16,
    header_digest: [u8; 32],
    checkpoint_digest: Option<[u8; 32]>,
    payload: &[u8],
) -> Result<Vec<u8>, ControlJournalImageError> {
    let (limit, overhead) = match region {
        ImageRegion::Checkpoint if checkpoint_digest.is_none() => (CHECKPOINT_LIMIT, 72),
        ImageRegion::Tail if checkpoint_digest.is_some() => (TAIL_LIMIT, 104),
        _ => return Err(INVALID),
    };
    let mut writer = ImageWriter::new(limit);
    let length = payload.len().checked_add(overhead).ok_or(INVALID)?;
    writer.u32(u32::try_from(length).map_err(|_| INVALID)?)?;
    writer.u16(1)?;
    writer.u16(count)?;
    writer.extend(&header_digest)?;
    if let Some(digest) = checkpoint_digest {
        writer.extend(&digest)?;
    }
    writer.extend(payload)?;
    writer.extend(&region_tag(key, region, &writer.bytes)?)?;
    Ok(writer.finish())
}

struct OpenRegion<'a> {
    exact_wire: &'a [u8],
    payload: &'a [u8],
    count: u16,
}

fn open_region<'a>(
    key: &JournalIntegrityKey,
    reader: &mut ImageReader<'a>,
    region: ImageRegion,
    header_digest: [u8; 32],
    checkpoint_digest: Option<[u8; 32]>,
) -> Result<OpenRegion<'a>, ControlJournalImageError> {
    let (limit, minimum) = match region {
        ImageRegion::Checkpoint if checkpoint_digest.is_none() => (CHECKPOINT_LIMIT, 72),
        ImageRegion::Tail if checkpoint_digest.is_some() => (TAIL_LIMIT, 104),
        _ => return Err(INVALID),
    };
    let start = reader.offset;
    let length = usize::try_from(reader.u32()?).map_err(|_| INVALID)?;
    if !(minimum..=limit).contains(&length) {
        return Err(INVALID);
    }
    reader.take(length - 4)?;
    let exact_wire = &reader.bytes[start..reader.offset];
    let tag_start = length - AUTH_TAG_BYTES;
    verify_region_tag(
        key,
        region,
        &exact_wire[..tag_start],
        &exact_wire[tag_start..],
    )?;
    let mut region_reader = ImageReader::new(&exact_wire[4..tag_start]);
    if region_reader.u16()? != 1 {
        return Err(INVALID);
    }
    let count = region_reader.u16()?;
    if region_reader.array::<32>()? != header_digest {
        return Err(INVALID);
    }
    if let Some(digest) = checkpoint_digest
        && region_reader.array::<32>()? != digest
    {
        return Err(INVALID);
    }
    Ok(OpenRegion {
        exact_wire,
        payload: region_reader.take(region_reader.bytes.len() - region_reader.offset)?,
        count,
    })
}

fn component_head(head: JournalHead) -> control_journal_record::JournalHead {
    control_journal_record::JournalHead {
        sequence: head.sequence,
        record_digest: head.digest,
    }
}

fn encode_tail_frame(
    key: &JournalIntegrityKey,
    prior: JournalHead,
    frame: &AuthenticatedTailFrame,
) -> Result<Vec<u8>, ControlJournalImageError> {
    if frame.prior_head != prior
        || Some(frame.resulting_head.sequence) != prior.sequence.checked_add(1)
    {
        return Err(INVALID);
    }
    let (kind, body) = encode_tail_record(&frame.record)?;
    let wire = key
        .encode_control_journal_record(kind, &body, component_head(prior))
        .map_err(|_| INVALID)?;
    let authenticated = key
        .decode_control_journal_record(&wire, component_head(prior))
        .map_err(|_| INVALID)?;
    if authenticated.record_digest != frame.resulting_head.digest {
        return Err(INVALID);
    }
    Ok(wire)
}

fn encode_tail_record(
    record: &TailRecord,
) -> Result<(control_journal_record::ControlJournalRecordKind, Vec<u8>), ControlJournalImageError> {
    Ok(match record {
        TailRecord::ClockCheckpointEvent(body) => (
            control_journal_record::ControlJournalRecordKind::ClockCheckpoint,
            clock_checkpoint_body::encode_clock_checkpoint_body(*body).map_err(|_| INVALID)?,
        ),
        TailRecord::ClockAcknowledge(action) => (
            AddressedOperation::ClockAcknowledge.kind(),
            encode_addressed_action(AddressedOperation::ClockAcknowledge, action)?,
        ),
        TailRecord::SystemShutdown(action) => (
            AddressedOperation::SystemShutdown.kind(),
            encode_addressed_action(AddressedOperation::SystemShutdown, action)?,
        ),
    })
}

fn replay_clock_at(
    checkpoint: &mut CompleteCheckpoint,
    body: clock_checkpoint_body::ClockCheckpointBody,
    head: JournalHead,
) -> Result<(), ControlJournalImageError> {
    let prior = checkpoint.clock_authority;
    replay_clock(checkpoint, body)?;
    if body.reason == clock_checkpoint_body::CheckpointReason::AutomaticSettlement
        && let AddressedState::Present(value) = &checkpoint.addressed[0].state
        && addressed_hold_matches(prior, value.address)
    {
        // A clock frame carries no selected commit receipt. Fail closed if
        // finalization would discard a pending selected-mirror obligation.
        if !matches!(value.mirror, AddressedMirror::NotApplicable) || value.phase != 2 {
            return Err(INVALID);
        }
        let mut value = value.clone();
        let AddressedEvidence::Acknowledge {
            target_safe_time, ..
        } = value.evidence
        else {
            return Err(INVALID);
        };
        if checkpoint.clock_authority.safe_time < target_safe_time {
            return Err(INVALID);
        }
        value.phase = 3;
        value.safe_result = AddressedResult::Acknowledge {
            settled_safe_time: target_safe_time,
            settled: true,
        };
        value.application_head = head;
        value.publication_head = head;
        checkpoint.addressed[0].state = AddressedState::Absent;
        checkpoint.addressed[1].state = AddressedState::Present(value);
    }
    Ok(())
}

fn replay_clock(
    checkpoint: &mut CompleteCheckpoint,
    body: clock_checkpoint_body::ClockCheckpointBody,
) -> Result<(), ControlJournalImageError> {
    use clock_checkpoint_body::CheckpointReason;
    clock_checkpoint_body::encode_clock_checkpoint_body(body).map_err(|_| INVALID)?;
    if body.prior_safe_time != checkpoint.clock_authority.safe_time {
        return Err(INVALID);
    }
    match (body.reason, checkpoint.clock_authority.hold, body.hold) {
        (CheckpointReason::AutomaticSettlement, Some(current), Some(named))
            if current.generation == named.generation
                && current.observation_digest == named.observation_digest => {}
        (CheckpointReason::AutomaticSettlement, _, _) => return Err(INVALID),
        (_, None, None) => {}
        _ => return Err(INVALID),
    }
    // A pre-mirror witness is optional even with selected state. When present,
    // it must name that selected origin; it does not prove a completed mirror.
    match (&checkpoint.active_pointer, body.pre_mirror) {
        (_, None) => {}
        (Some(pointer), Some(mirror)) if pointer.target_history_epoch == mirror.selected_origin => {
        }
        _ => return Err(INVALID),
    }
    checkpoint.clock_authority.safe_time = body.new_safe_time;
    if body.reason == CheckpointReason::AutomaticSettlement {
        checkpoint.clock_authority.hold = None;
    }
    if body.reason == CheckpointReason::CleanShutdown {
        checkpoint.clock_authority.last_shutdown_observation = Some(body.accepted_wall_time);
    }
    Ok(())
}

fn replay_tail(
    image: &CompleteControlJournalImage,
) -> Result<CompleteCheckpoint, ControlJournalImageError> {
    validate_image_bindings(image)?;
    validate_checkpoint(&image.checkpoint)?;
    if image.tail.len() > TAIL_COUNT_LIMIT {
        return Err(INVALID);
    }
    let mut checkpoint = image.checkpoint.clone();
    let mut prior = checkpoint.covered_head;
    let mut bytes = 104_usize;
    for frame in &image.tail {
        if frame.prior_head != prior
            || Some(frame.resulting_head.sequence) != prior.sequence.checked_add(1)
        {
            return Err(INVALID);
        }
        validate_head(frame.resulting_head)?;
        let (kind, body_bytes) = encode_tail_record(&frame.record)?;
        let expected = match kind {
            control_journal_record::ControlJournalRecordKind::ClockCheckpoint => {
                JournalIntegrityKey::control_journal_clock_checkpoint_head(
                    &body_bytes,
                    component_head(prior),
                )
                .map_err(|_| INVALID)?
                .record_digest
            }
            _ => {
                let mut digest = Sha256::new();
                digest.update(b"msgriver/control-journal-record/v1");
                let operation = if kind == AddressedOperation::ClockAcknowledge.kind() {
                    AddressedOperation::ClockAcknowledge
                } else {
                    AddressedOperation::SystemShutdown
                };
                digest.update(operation.code().to_be_bytes());
                digest.update(frame.resulting_head.sequence.to_be_bytes());
                digest.update(prior.digest);
                digest.update(&body_bytes);
                digest.finalize().into()
            }
        };
        if expected != frame.resulting_head.digest {
            return Err(INVALID);
        }
        let frame_bytes = body_bytes.len().checked_add(110).ok_or(INVALID)?;
        bytes = bytes.checked_add(frame_bytes).ok_or(INVALID)?;
        if frame_bytes > FRAME_LIMIT || bytes > TAIL_LIMIT {
            return Err(INVALID);
        }
        match &frame.record {
            TailRecord::ClockCheckpointEvent(body) => {
                replay_clock_at(&mut checkpoint, *body, frame.resulting_head)?
            }
            TailRecord::ClockAcknowledge(action) => replay_addressed(
                &mut checkpoint,
                AddressedOperation::ClockAcknowledge,
                action,
                frame.resulting_head,
            )?,
            TailRecord::SystemShutdown(action) => replay_addressed(
                &mut checkpoint,
                AddressedOperation::SystemShutdown,
                action,
                frame.resulting_head,
            )?,
        }
        prior = frame.resulting_head;
        checkpoint.covered_head = prior;
        validate_checkpoint(&checkpoint)?;
    }
    checkpoint.covered_head = prior;
    validate_checkpoint(&checkpoint)?;
    Ok(checkpoint)
}

fn encode_control_journal_image(
    key: &JournalIntegrityKey,
    image: &CompleteControlJournalImage,
) -> Result<Vec<u8>, ControlJournalImageError> {
    let header = encode_image_header(key, image.header)?;
    let checkpoint_payload =
        encode_checkpoint(key, image.header.owner_namespace, &image.checkpoint)?;
    replay_tail(image)?;
    let header_digest = region_digest(&header);
    let checkpoint = seal_region(
        key,
        ImageRegion::Checkpoint,
        CHECKPOINT_MEMBERS,
        header_digest,
        None,
        &checkpoint_payload,
    )?;
    let mut payload = ImageWriter::new(TAIL_LIMIT - 104);
    let mut prior = image.checkpoint.covered_head;
    for frame in &image.tail {
        payload.extend(&encode_tail_frame(key, prior, frame)?)?;
        prior = frame.resulting_head;
    }
    let tail = seal_region(
        key,
        ImageRegion::Tail,
        u16::try_from(image.tail.len()).map_err(|_| INVALID)?,
        header_digest,
        Some(region_digest(&checkpoint)),
        &payload.finish(),
    )?;
    let mut wire = ImageWriter::new(IMAGE_LIMIT);
    wire.extend(&header)?;
    wire.extend(&checkpoint)?;
    wire.extend(&tail)?;
    Ok(wire.finish())
}

fn decode_control_journal_image(
    key: &JournalIntegrityKey,
    wire: &[u8],
) -> Result<CompleteControlJournalImage, ControlJournalImageError> {
    if wire.len() > IMAGE_LIMIT {
        return Err(INVALID);
    }
    let mut reader = ImageReader::new(wire);
    let header_wire = reader.take(120)?;
    let header = key
        .decode_control_journal_header(header_wire)
        .map_err(|_| INVALID)?;
    let header_digest = region_digest(header_wire);
    let checkpoint_region = open_region(
        key,
        &mut reader,
        ImageRegion::Checkpoint,
        header_digest,
        None,
    )?;
    if checkpoint_region.count != CHECKPOINT_MEMBERS {
        return Err(INVALID);
    }
    let checkpoint = decode_checkpoint(
        key,
        header.owner_namespace.as_bytes(),
        checkpoint_region.payload,
    )?;
    let tail_region = open_region(
        key,
        &mut reader,
        ImageRegion::Tail,
        header_digest,
        Some(region_digest(checkpoint_region.exact_wire)),
    )?;
    reader.end()?;
    let count = usize::from(tail_region.count);
    if count > TAIL_COUNT_LIMIT || count > tail_region.payload.len() / 110 {
        return Err(INVALID);
    }
    let mut reader = ImageReader::new(tail_region.payload);
    let mut tail = Vec::with_capacity(count);
    let mut prior = checkpoint.covered_head;
    for _ in 0..count {
        let start = reader.offset;
        let length = usize::try_from(reader.u32()?).map_err(|_| INVALID)?;
        if !(110..=FRAME_LIMIT).contains(&length) {
            return Err(INVALID);
        }
        reader.take(length - 4)?;
        let frame = key
            .decode_control_journal_record(
                &reader.bytes[start..reader.offset],
                component_head(prior),
            )
            .map_err(|_| INVALID)?;
        let resulting_head = JournalHead {
            sequence: frame.sequence,
            digest: frame.record_digest,
        };
        let record = match frame.kind {
            control_journal_record::ControlJournalRecordKind::ClockCheckpoint => {
                TailRecord::ClockCheckpointEvent(
                    clock_checkpoint_body::decode_clock_checkpoint_body(frame.body)
                        .map_err(|_| INVALID)?,
                )
            }
            control_journal_record::ControlJournalRecordKind::ClockAcknowledge => {
                TailRecord::ClockAcknowledge(decode_addressed_action(
                    AddressedOperation::ClockAcknowledge,
                    frame.body,
                    resulting_head,
                )?)
            }
            control_journal_record::ControlJournalRecordKind::SystemShutdown => {
                TailRecord::SystemShutdown(decode_addressed_action(
                    AddressedOperation::SystemShutdown,
                    frame.body,
                    resulting_head,
                )?)
            }
        };
        tail.push(AuthenticatedTailFrame {
            prior_head: prior,
            resulting_head,
            record,
        });
        prior = resulting_head;
    }
    reader.end()?;
    let image = CompleteControlJournalImage {
        header: AuthenticatedControlJournalHeader {
            owner_namespace: header.owner_namespace.as_bytes(),
            branch_serial_high_water: header.branch_serial_high_water,
        },
        checkpoint,
        tail,
    };
    replay_tail(&image).map_err(|_| INVALID)?;
    Ok(image)
}

/// Pure folding accepts only the complete typed automata. It neither invents
/// clock observations nor resolves a digest-only command profile. Wire heads
/// must have been authenticated before handing a recovered image to this seam.
fn fold_control_journal_image(
    image: &CompleteControlJournalImage,
    _trigger: FoldTrigger,
) -> Result<CompleteControlJournalImage, ControlJournalImageError> {
    let mut checkpoint = replay_tail(image)?;
    checkpoint.generation = checkpoint.generation.checked_add(1).ok_or(INVALID)?;
    Ok(CompleteControlJournalImage {
        header: image.header,
        checkpoint,
        tail: Vec::new(),
    })
}

/// Build a frame from a complete observation, using the component's actual
/// digest. Callers cannot choose a resulting digest or omit body witnesses.
fn append_clock_checkpoint(
    key: &JournalIntegrityKey,
    image: &CompleteControlJournalImage,
    body: clock_checkpoint_body::ClockCheckpointBody,
) -> Result<CompleteControlJournalImage, ControlJournalImageError> {
    // Check the old image, including existing frame digests, before extending it.
    encode_control_journal_image(key, image)?;
    let mut next = image.clone();
    let encoded_body =
        clock_checkpoint_body::encode_clock_checkpoint_body(body).map_err(|_| INVALID)?;
    let frame_size = 110 + encoded_body.len();
    let tail_bytes = 104
        + image.tail.iter().try_fold(0_usize, |sum, frame| {
            let bytes = encode_tail_frame(key, frame.prior_head, frame)?;
            sum.checked_add(bytes.len()).ok_or(INVALID)
        })?;
    let must_fold = next.tail.len() == TAIL_COUNT_LIMIT || tail_bytes + frame_size > TAIL_LIMIT;
    let prior = next
        .tail
        .last()
        .map_or(next.checkpoint.covered_head, |frame| frame.resulting_head);
    let wire = key
        .encode_control_journal_record(
            control_journal_record::ControlJournalRecordKind::ClockCheckpoint,
            &encoded_body,
            component_head(prior),
        )
        .map_err(|_| INVALID)?;
    let record = key
        .decode_control_journal_record(&wire, component_head(prior))
        .map_err(|_| INVALID)?;
    let resulting_head = JournalHead {
        sequence: record.sequence,
        digest: record.record_digest,
    };
    if must_fold {
        // Absorb the pending publication too, without constructing an over-cap tail.
        let mut checkpoint = replay_tail(&next)?;
        replay_clock_at(&mut checkpoint, body, resulting_head)?;
        checkpoint.covered_head = resulting_head;
        checkpoint.generation = checkpoint.generation.checked_add(1).ok_or(INVALID)?;
        next.checkpoint = checkpoint;
        next.tail.clear();
    } else {
        next.tail.push(AuthenticatedTailFrame {
            prior_head: prior,
            resulting_head,
            record: TailRecord::ClockCheckpointEvent(body),
        });
    }
    encode_control_journal_image(key, &next)?;
    Ok(next)
}

/// Produce authenticated structural counterexamples, never publication input.
/// On an empty tail the reorder/sequence probes first seed two synthetic,
/// fully encoded observations so the named mutation remains nontrivial.
fn mutate_control_journal_image(
    key: &JournalIntegrityKey,
    wire: &[u8],
    mutation: ImageMutation,
) -> Result<Vec<u8>, ControlJournalImageError> {
    let image = decode_control_journal_image(key, wire)?;
    let header = encode_image_header(key, image.header)?;
    let header_digest = region_digest(&header);
    let mut checkpoint_payload =
        encode_checkpoint(key, image.header.owner_namespace, &image.checkpoint)?;
    let mut member_count = CHECKPOINT_MEMBERS;
    let mut frames = Vec::new();
    for frame in &image.tail {
        frames.push(encode_tail_frame(key, frame.prior_head, frame)?);
    }
    match mutation {
        ImageMutation::ReorderedCheckpointMember => {
            let mut reader = ImageReader::new(&checkpoint_payload);
            reader.member(1)?;
            let first_end = reader.offset;
            reader.member(2)?;
            let second_end = reader.offset;
            checkpoint_payload[..second_end].rotate_left(first_end);
        }
        ImageMutation::CoveredHeadMismatch => {
            let mut reader = ImageReader::new(&checkpoint_payload);
            reader.member(1)?;
            reader.member(2)?;
            let end = reader.offset;
            checkpoint_payload[end - 40..end - 32].fill(0);
            checkpoint_payload[end - 32..end].fill(1);
        }
        ImageMutation::CommandOnlyArtifact => {
            let mut reader = ImageReader::new(&checkpoint_payload);
            for tag in 1..6 {
                reader.member(tag)?;
            }
            let start = reader.offset;
            reader.member(6)?;
            checkpoint_payload = checkpoint_payload[start..reader.offset].to_vec();
            member_count = 1;
            frames.clear();
        }
        ImageMutation::ReorderedTailFrame | ImageMutation::NoncontiguousTailSequence => {
            if frames.len() < 2 {
                frames.clear();
                let safe_time = image.checkpoint.clock_authority.safe_time;
                let body = clock_checkpoint_body::encode_clock_checkpoint_body(
                    clock_checkpoint_body::ClockCheckpointBody {
                        runtime_mode: clock_checkpoint_body::RuntimeMode::Maintenance,
                        process_instance: [1; 16],
                        accepted_wall_time: safe_time,
                        accepted_monotonic_tick: 0,
                        prior_safe_time: safe_time,
                        new_safe_time: safe_time,
                        reason: clock_checkpoint_body::CheckpointReason::Periodic,
                        hold: None,
                        pre_mirror: None,
                    },
                )
                .map_err(|_| INVALID)?;
                let mut prior = component_head(image.checkpoint.covered_head);
                for _ in 0..2 {
                    let frame = key
                        .encode_control_journal_record(
                            control_journal_record::ControlJournalRecordKind::ClockCheckpoint,
                            &body,
                            prior,
                        )
                        .map_err(|_| INVALID)?;
                    let record = key
                        .decode_control_journal_record(&frame, prior)
                        .map_err(|_| INVALID)?;
                    prior = control_journal_record::JournalHead {
                        sequence: record.sequence,
                        record_digest: record.record_digest,
                    };
                    frames.push(frame);
                }
            }
            if mutation == ImageMutation::ReorderedTailFrame {
                frames.swap(0, 1);
            } else {
                // Drop the first authenticated frame: the tail now starts at a gap.
                frames.remove(0);
            }
        }
    }
    let checkpoint = seal_region(
        key,
        ImageRegion::Checkpoint,
        member_count,
        header_digest,
        None,
        &checkpoint_payload,
    )?;
    let mut payload = ImageWriter::new(TAIL_LIMIT - 104);
    for frame in &frames {
        payload.extend(frame)?;
    }
    let tail = seal_region(
        key,
        ImageRegion::Tail,
        u16::try_from(frames.len()).map_err(|_| INVALID)?,
        header_digest,
        Some(region_digest(&checkpoint)),
        &payload.finish(),
    )?;
    let mut output = ImageWriter::new(IMAGE_LIMIT);
    output.extend(&header)?;
    output.extend(&checkpoint)?;
    output.extend(&tail)?;
    Ok(output.finish())
}

const JOURNAL_NAME: &str = "control-journal";

struct ImageOwner {
    _lock: crate::StateOwnerLock,
    directory: rustix::fd::OwnedFd,
}

impl ImageOwner {
    fn acquire(root: &Path) -> Result<Self, ControlJournalImageError> {
        use rustix::fs::{FileType, Mode, OFlags};
        use std::os::unix::ffi::OsStrExt;
        let (lock, reference) = crate::StateOwnerLock::acquire_with_private_root_reference(root)
            .map_err(|_| ControlJournalImageError::WriteFailed)?;
        let root = std::ffi::CString::new(root.as_os_str().as_bytes())
            .map_err(|_| ControlJournalImageError::WriteFailed)?;
        let directory = rustix::fs::openat(
            rustix::fs::CWD,
            root.as_c_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ControlJournalImageError::WriteFailed)?;
        let actual =
            rustix::fs::fstat(&directory).map_err(|_| ControlJournalImageError::WriteFailed)?;
        let expected =
            rustix::fs::fstat(&reference).map_err(|_| ControlJournalImageError::WriteFailed)?;
        if FileType::from_raw_mode(actual.st_mode) != FileType::Directory
            || actual.st_mode & 0o7777 != 0o700
            || actual.st_uid != rustix::process::geteuid().as_raw()
            || actual.st_ino != expected.st_ino
            || actual.st_dev != expected.st_dev
        {
            return Err(ControlJournalImageError::WriteFailed);
        }
        Ok(Self {
            _lock: lock,
            directory,
        })
    }

    fn read(
        &self,
        key: &JournalIntegrityKey,
    ) -> Result<Option<CompleteControlJournalImage>, ControlJournalImageError> {
        use rustix::fs::{FileType, Mode, OFlags};
        let file = match rustix::fs::openat(
            &self.directory,
            JOURNAL_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(file) => file,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err(INVALID),
        };
        let metadata = rustix::fs::fstat(&file).map_err(|_| INVALID)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_mode & 0o7777 != 0o600
            || metadata.st_uid != rustix::process::geteuid().as_raw()
            || metadata.st_nlink != 1
            || metadata.st_size < 0
            || metadata.st_size > IMAGE_LIMIT as i64
        {
            return Err(INVALID);
        }
        let mut bytes = Vec::new();
        let mut buffer = [0; 8192];
        loop {
            let count = match rustix::io::read(&file, &mut buffer) {
                Ok(count) => count,
                Err(rustix::io::Errno::INTR) => continue,
                Err(_) => return Err(INVALID),
            };
            if count == 0 {
                break;
            }
            if bytes.len().checked_add(count).ok_or(INVALID)? > IMAGE_LIMIT {
                return Err(INVALID);
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
        if bytes.len() != usize::try_from(metadata.st_size).map_err(|_| INVALID)? {
            return Err(INVALID);
        }
        decode_control_journal_image(key, &bytes).map(Some)
    }
}

fn publish_control_journal_image(
    key: &JournalIntegrityKey,
    root: &Path,
    image: &CompleteControlJournalImage,
) -> Result<(), ControlJournalImageError> {
    publish_image(key, root, image, None)
}

fn publish_control_journal_image_with_fault(
    key: &JournalIntegrityKey,
    root: &Path,
    image: &CompleteControlJournalImage,
    fault: PublicationFault,
) -> Result<(), ControlJournalImageError> {
    publish_image(key, root, image, Some(fault))
}

fn publication_barrier(
    injected: Option<PublicationFault>,
    barrier: PublicationFault,
) -> Result<(), ControlJournalImageError> {
    if injected == Some(barrier) {
        Err(if barrier == PublicationFault::DirectorySync {
            ControlJournalImageError::PublishUncertain
        } else {
            ControlJournalImageError::WriteFailed
        })
    } else {
        Ok(())
    }
}

fn publish_image(
    key: &JournalIntegrityKey,
    root: &Path,
    image: &CompleteControlJournalImage,
    fault: Option<PublicationFault>,
) -> Result<(), ControlJournalImageError> {
    use rustix::fs::{AtFlags, Mode, OFlags};
    use std::sync::atomic::{AtomicU64, Ordering};
    static TEMPORARY_SERIAL: AtomicU64 = AtomicU64::new(0);
    let bytes = encode_control_journal_image(key, image)?;
    let owner = ImageOwner::acquire(root)?;
    if let Some(previous) = owner.read(key)? {
        let old = replay_tail(&previous)?;
        let new = replay_tail(image)?;
        if image.header.branch_serial_high_water < previous.header.branch_serial_high_water
            || image.checkpoint.generation < previous.checkpoint.generation
            || new.covered_head.sequence < old.covered_head.sequence
            || (new.covered_head.sequence == old.covered_head.sequence
                && new.covered_head.digest != old.covered_head.digest)
            || new.clock_authority.safe_time < old.clock_authority.safe_time
        {
            return Err(INVALID);
        }
    } else if image.header.branch_serial_high_water != 0
        || image.checkpoint.generation != 1
        || image.checkpoint.covered_head.sequence != 0
        || !image.tail.is_empty()
    {
        // A missing journal can only be initialized, never adopted from an
        // arbitrary later snapshot in place of authenticated fixed-root truth.
        return Err(INVALID);
    }
    publication_barrier(fault, PublicationFault::UniqueTemporaryCreate)?;
    let serial = TEMPORARY_SERIAL
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| ControlJournalImageError::WriteFailed)?;
    let name = format!(".control-journal-{}-{serial}.tmp", std::process::id());
    // EXCL and NOFOLLOW make stale or hostile temporary entries inert. All
    // operations after acquisition remain relative to the retained directory.
    let file = rustix::fs::openat(
        &owner.directory,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| ControlJournalImageError::WriteFailed)?;
    let before_rename = (|| {
        // Inject an actual short prefix; the old selected name is untouched.
        if fault == Some(PublicationFault::TemporaryWrite) {
            write_image_bytes(&file, &bytes[..bytes.len() / 2])?;
        }
        publication_barrier(fault, PublicationFault::TemporaryWrite)?;
        write_image_bytes(&file, &bytes)?;
        publication_barrier(fault, PublicationFault::FileSync)?;
        rustix::fs::fsync(&file).map_err(|_| ControlJournalImageError::WriteFailed)?;
        publication_barrier(fault, PublicationFault::ReplacementRename)?;
        rustix::fs::renameat(
            &owner.directory,
            name.as_str(),
            &owner.directory,
            JOURNAL_NAME,
        )
        .map_err(|_| ControlJournalImageError::WriteFailed)
    })();
    if let Err(error) = before_rename {
        // A leftover temporary is inert even if cleanup fails. Never unlink
        // the selected pathname or rewrite it to compensate for an error.
        let _ = rustix::fs::unlinkat(&owner.directory, name.as_str(), AtFlags::empty());
        return Err(error);
    }
    publication_barrier(fault, PublicationFault::DirectorySync)?;
    rustix::fs::fsync(&owner.directory).map_err(|_| ControlJournalImageError::PublishUncertain)?;
    let selected = owner
        .read(key)
        .map_err(|_| ControlJournalImageError::PublishUncertain)?;
    if selected.as_ref() != Some(image) {
        return Err(ControlJournalImageError::PublishUncertain);
    }
    Ok(())
}

fn write_image_bytes(
    file: &rustix::fd::OwnedFd,
    mut bytes: &[u8],
) -> Result<(), ControlJournalImageError> {
    while !bytes.is_empty() {
        match rustix::io::write(file, bytes) {
            Ok(0) => return Err(ControlJournalImageError::WriteFailed),
            Ok(count) => bytes = &bytes[count..],
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return Err(ControlJournalImageError::WriteFailed),
        }
    }
    Ok(())
}

fn reopen_control_journal_image(
    key: &JournalIntegrityKey,
    root: &Path,
) -> Result<CompleteControlJournalImage, ControlJournalImageError> {
    ImageOwner::acquire(root)?.read(key)?.ok_or(INVALID)
}

#[cfg(test)]
#[path = "red_control_journal_image.rs"]
mod red_control_journal_image;
