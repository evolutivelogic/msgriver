//! Task 0067 private authenticated common-prefix codec.
//!
//! The enclosing journal record authenticates these body bytes. Operation
//! profile semantics, key resolution, persistence, and envelope integration
//! deliberately remain outside this in-memory boundary.

use msgriver_core::bounded::check_identifier;
use msgriver_core::canon::{MacKeyId, MacKeyRef, MacPurpose};
use std::fmt;

const FORMAT: u8 = 1;
const MAX_COMMAND_BODY_BYTES: usize = 16_274;
const MAX_PROFILE_BODY_BYTES: usize = 15_580;
const STATE_OWNER: &[u8] = b"msgriver/state-owner/v1";

type ParentWitness = ([u8; 32], u64, [u8; 32], [u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq)]
enum FixedRootCommandOperation {
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

impl FixedRootCommandOperation {
    fn code(&self) -> u8 {
        match self {
            Self::ConfigurationActivate => 0x01,
            Self::StateKeyRotate => 0x02,
            Self::StateKeyRetire => 0x03,
            Self::RecoveryKeyGenerate => 0x04,
            Self::RecoveryKeyImport => 0x05,
            Self::RecoveryKeyRetire => 0x06,
            Self::BootstrapCreate => 0x07,
            Self::RestoreCreate => 0x08,
            Self::StateGenerationDelete => 0x09,
            Self::UpgradePrepare => 0x0a,
            Self::UpgradeMigrate => 0x0b,
            Self::UpgradeActivate => 0x0c,
            Self::UpgradeRollback => 0x0d,
        }
    }

    fn from_code(code: u8) -> Result<Self, FixedRootCommandError> {
        match code {
            0x01 => Ok(Self::ConfigurationActivate),
            0x02 => Ok(Self::StateKeyRotate),
            0x03 => Ok(Self::StateKeyRetire),
            0x04 => Ok(Self::RecoveryKeyGenerate),
            0x05 => Ok(Self::RecoveryKeyImport),
            0x06 => Ok(Self::RecoveryKeyRetire),
            0x07 => Ok(Self::BootstrapCreate),
            0x08 => Ok(Self::RestoreCreate),
            0x09 => Ok(Self::StateGenerationDelete),
            0x0a => Ok(Self::UpgradePrepare),
            0x0b => Ok(Self::UpgradeMigrate),
            0x0c => Ok(Self::UpgradeActivate),
            0x0d => Ok(Self::UpgradeRollback),
            _ => Err(FixedRootCommandError::InvalidFixedRootCommand),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum FixedRootCommandActor {
    Principal(Vec<u8>),
    StateOwner,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixedRootCommandRuntime {
    Normal,
    Maintenance,
}

impl FixedRootCommandRuntime {
    fn code(self) -> u8 {
        match self {
            Self::Normal => 1,
            Self::Maintenance => 2,
        }
    }

    fn from_code(code: u8) -> Result<Self, FixedRootCommandError> {
        match code {
            1 => Ok(Self::Normal),
            2 => Ok(Self::Maintenance),
            _ => Err(FixedRootCommandError::InvalidFixedRootCommand),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FixedRootCommandTag {
    key: MacKeyRef,
    tag: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixedRootCommandRetention {
    Continuation,
    Terminal { terminal_time: i64, expires_at: i64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FixedRootCommandSafeResult {
    codec: u16,
    version: u16,
    digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FixedRootCommandTargetBinding {
    source: [u8; 32],
    target: [u8; 32],
    source_generation: Option<u64>,
    target_generation: Option<u64>,
    parent_witness: Option<ParentWitness>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FixedRootCommand {
    operation: FixedRootCommandOperation,
    actor: FixedRootCommandActor,
    tags: [FixedRootCommandTag; 4],
    runtime: FixedRootCommandRuntime,
    process_instance: [u8; 16],
    original_deadline: Option<i64>,
    phase: u16,
    retention: FixedRootCommandRetention,
    safe_result: Option<FixedRootCommandSafeResult>,
    target_binding: Option<FixedRootCommandTargetBinding>,
    profile_body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FixedRootCommandCodec {
    expected_prebootstrap_origin: [u8; 32],
}

impl FixedRootCommandCodec {
    fn new(expected_prebootstrap_origin: [u8; 32]) -> Self {
        Self {
            expected_prebootstrap_origin,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FixedRootCommandError {
    InvalidFixedRootCommand,
}

impl fmt::Display for FixedRootCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fixed-root command is invalid")
    }
}

impl std::error::Error for FixedRootCommandError {}

pub(super) fn encode_fixed_root_command(
    codec: &FixedRootCommandCodec,
    command: FixedRootCommand,
) -> Result<Vec<u8>, FixedRootCommandError> {
    validate_command(codec, &command)?;
    let actor = actor_bytes(&command.actor)?;
    let mut wire = Vec::with_capacity(MAX_COMMAND_BODY_BYTES);
    wire.extend_from_slice(&[
        FORMAT,
        command.operation.code(),
        actor.0,
        actor.1.len() as u8,
    ]);
    wire.extend_from_slice(&actor.1);
    for tag in command.tags {
        wire.extend_from_slice(tag.key.key_id().as_bytes());
        wire.extend_from_slice(&tag.tag);
    }
    wire.push(command.runtime.code());
    wire.extend_from_slice(&command.process_instance);
    write_optional_i64(&mut wire, command.original_deadline);
    wire.extend_from_slice(&command.phase.to_be_bytes());
    write_retention(&mut wire, command.retention);
    write_safe_result(&mut wire, command.safe_result);
    write_target_binding(&mut wire, command.target_binding);
    let profile_body_length = u16::try_from(command.profile_body.len())
        .map_err(|_| FixedRootCommandError::InvalidFixedRootCommand)?;
    wire.extend_from_slice(&profile_body_length.to_be_bytes());
    wire.extend_from_slice(&command.profile_body);
    if wire.len() > MAX_COMMAND_BODY_BYTES {
        return Err(FixedRootCommandError::InvalidFixedRootCommand);
    }
    Ok(wire)
}

pub(super) fn decode_fixed_root_command(
    codec: &FixedRootCommandCodec,
    wire: &[u8],
) -> Result<FixedRootCommand, FixedRootCommandError> {
    if wire.len() > MAX_COMMAND_BODY_BYTES {
        return Err(FixedRootCommandError::InvalidFixedRootCommand);
    }
    let mut reader = Reader::new(wire);
    if reader.byte()? != FORMAT {
        return Err(FixedRootCommandError::InvalidFixedRootCommand);
    }
    let operation = FixedRootCommandOperation::from_code(reader.byte()?)?;
    let actor = read_actor(&mut reader)?;
    let tags = [
        read_tag(&mut reader, MacPurpose::CommandLookupV1)?,
        read_tag(&mut reader, MacPurpose::CommandSemanticFingerprintV1)?,
        read_tag(&mut reader, MacPurpose::CommandPhaseFingerprintV1)?,
        read_tag(&mut reader, MacPurpose::PortableReservationV1)?,
    ];
    let runtime = FixedRootCommandRuntime::from_code(reader.byte()?)?;
    let process_instance = reader.array()?;
    let original_deadline = reader.optional_i64()?;
    let phase = reader.u16()?;
    let retention = read_retention(&mut reader)?;
    let safe_result = read_safe_result(&mut reader)?;
    let target_binding = read_target_binding(&mut reader)?;
    let profile_length = usize::from(reader.u16()?);
    if profile_length > MAX_PROFILE_BODY_BYTES {
        return Err(FixedRootCommandError::InvalidFixedRootCommand);
    }
    let profile_body = reader.bytes(profile_length)?.to_vec();
    if !reader.finished() {
        return Err(FixedRootCommandError::InvalidFixedRootCommand);
    }
    let command = FixedRootCommand {
        operation,
        actor,
        tags,
        runtime,
        process_instance,
        original_deadline,
        phase,
        retention,
        safe_result,
        target_binding,
        profile_body,
    };
    validate_command(codec, &command)?;
    Ok(command)
}

fn validate_command(
    codec: &FixedRootCommandCodec,
    command: &FixedRootCommand,
) -> Result<(), FixedRootCommandError> {
    if !origin_serial_is_zero(&codec.expected_prebootstrap_origin) {
        return Err(FixedRootCommandError::InvalidFixedRootCommand);
    }
    let _ = actor_bytes(&command.actor)?;
    if command.process_instance.iter().all(|byte| *byte == 0)
        || command.phase == 0
        || command.profile_body.len() > MAX_PROFILE_BODY_BYTES
    {
        return Err(FixedRootCommandError::InvalidFixedRootCommand);
    }
    for (tag, purpose) in command.tags.iter().zip([
        MacPurpose::CommandLookupV1,
        MacPurpose::CommandSemanticFingerprintV1,
        MacPurpose::CommandPhaseFingerprintV1,
        MacPurpose::PortableReservationV1,
    ]) {
        validate_tag(codec, *tag, purpose)?;
    }
    match command.retention {
        FixedRootCommandRetention::Continuation => {}
        FixedRootCommandRetention::Terminal {
            terminal_time,
            expires_at,
        } if expires_at > terminal_time && command.safe_result.is_some() => {}
        FixedRootCommandRetention::Terminal { .. } => {
            return Err(FixedRootCommandError::InvalidFixedRootCommand);
        }
    }
    if let Some(binding) = command.target_binding {
        validate_target_binding(codec, command.operation.clone(), command.retention, binding)?;
    }
    Ok(())
}

fn actor_bytes(actor: &FixedRootCommandActor) -> Result<(u8, Vec<u8>), FixedRootCommandError> {
    match actor {
        FixedRootCommandActor::Principal(value) => {
            check_identifier(value).map_err(|_| FixedRootCommandError::InvalidFixedRootCommand)?;
            Ok((1, value.clone()))
        }
        FixedRootCommandActor::StateOwner => Ok((2, STATE_OWNER.to_vec())),
    }
}

fn validate_tag(
    codec: &FixedRootCommandCodec,
    tag: FixedRootCommandTag,
    expected_purpose: MacPurpose,
) -> Result<(), FixedRootCommandError> {
    if tag.key.purpose() != expected_purpose {
        return Err(FixedRootCommandError::InvalidFixedRootCommand);
    }
    let key_id = tag.key.key_id();
    let key = key_id.as_bytes();
    if key[32..].iter().all(|byte| *byte == 0) {
        return Err(FixedRootCommandError::InvalidFixedRootCommand);
    }
    let origin_serial_is_zero = key[24..32].iter().all(|byte| *byte == 0);
    if origin_serial_is_zero
        && (expected_purpose != MacPurpose::PortableReservationV1
            || key[..32] != codec.expected_prebootstrap_origin)
    {
        return Err(FixedRootCommandError::InvalidFixedRootCommand);
    }
    Ok(())
}

fn validate_target_binding(
    codec: &FixedRootCommandCodec,
    operation: FixedRootCommandOperation,
    retention: FixedRootCommandRetention,
    binding: FixedRootCommandTargetBinding,
) -> Result<(), FixedRootCommandError> {
    if origin_serial_is_zero(&binding.target) {
        return Err(FixedRootCommandError::InvalidFixedRootCommand);
    }
    match operation {
        FixedRootCommandOperation::BootstrapCreate
            if binding.source == codec.expected_prebootstrap_origin => {}
        FixedRootCommandOperation::BootstrapCreate => {
            return Err(FixedRootCommandError::InvalidFixedRootCommand);
        }
        _ if origin_serial_is_zero(&binding.source) => {
            return Err(FixedRootCommandError::InvalidFixedRootCommand);
        }
        _ => {}
    }
    if retention == FixedRootCommandRetention::Continuation && binding.source != binding.target {
        return Err(FixedRootCommandError::InvalidFixedRootCommand);
    }
    Ok(())
}

fn origin_serial_is_zero(origin: &[u8; 32]) -> bool {
    origin[24..].iter().all(|byte| *byte == 0)
}

fn write_optional_i64(wire: &mut Vec<u8>, value: Option<i64>) {
    match value {
        None => wire.push(0),
        Some(value) => {
            wire.push(1);
            wire.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn write_retention(wire: &mut Vec<u8>, retention: FixedRootCommandRetention) {
    match retention {
        FixedRootCommandRetention::Continuation => wire.extend_from_slice(&[1, 0, 0]),
        FixedRootCommandRetention::Terminal {
            terminal_time,
            expires_at,
        } => {
            wire.extend_from_slice(&[2, 1]);
            wire.extend_from_slice(&terminal_time.to_be_bytes());
            wire.push(1);
            wire.extend_from_slice(&expires_at.to_be_bytes());
        }
    }
}

fn write_safe_result(wire: &mut Vec<u8>, safe_result: Option<FixedRootCommandSafeResult>) {
    match safe_result {
        None => wire.push(0),
        Some(result) => {
            wire.push(1);
            wire.extend_from_slice(&result.codec.to_be_bytes());
            wire.extend_from_slice(&result.version.to_be_bytes());
            wire.extend_from_slice(&result.digest);
        }
    }
}

fn write_target_binding(wire: &mut Vec<u8>, binding: Option<FixedRootCommandTargetBinding>) {
    match binding {
        None => wire.push(0),
        Some(binding) => {
            wire.push(1);
            wire.extend_from_slice(&binding.source);
            wire.extend_from_slice(&binding.target);
            write_optional_u64(wire, binding.source_generation);
            write_optional_u64(wire, binding.target_generation);
            match binding.parent_witness {
                None => wire.push(0),
                Some((origin, head, head_digest, certificate_digest)) => {
                    wire.push(1);
                    wire.extend_from_slice(&origin);
                    wire.extend_from_slice(&head.to_be_bytes());
                    wire.extend_from_slice(&head_digest);
                    wire.extend_from_slice(&certificate_digest);
                }
            }
        }
    }
}

fn write_optional_u64(wire: &mut Vec<u8>, value: Option<u64>) {
    match value {
        None => wire.push(0),
        Some(value) => {
            wire.push(1);
            wire.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn read_actor(reader: &mut Reader<'_>) -> Result<FixedRootCommandActor, FixedRootCommandError> {
    let kind = reader.byte()?;
    let length = usize::from(reader.byte()?);
    if length == 0 {
        return Err(FixedRootCommandError::InvalidFixedRootCommand);
    }
    let value = reader.bytes(length)?.to_vec();
    match kind {
        1 => {
            check_identifier(&value).map_err(|_| FixedRootCommandError::InvalidFixedRootCommand)?;
            Ok(FixedRootCommandActor::Principal(value))
        }
        2 if value == STATE_OWNER => Ok(FixedRootCommandActor::StateOwner),
        _ => Err(FixedRootCommandError::InvalidFixedRootCommand),
    }
}

fn read_tag(
    reader: &mut Reader<'_>,
    purpose: MacPurpose,
) -> Result<FixedRootCommandTag, FixedRootCommandError> {
    Ok(FixedRootCommandTag {
        key: MacKeyRef::new(purpose, MacKeyId::from_bytes(reader.array()?)),
        tag: reader.array()?,
    })
}

fn read_retention(
    reader: &mut Reader<'_>,
) -> Result<FixedRootCommandRetention, FixedRootCommandError> {
    let tag = reader.byte()?;
    let terminal_time = reader.optional_i64()?;
    let expiry = reader.optional_i64()?;
    match (tag, terminal_time, expiry) {
        (1, None, None) => Ok(FixedRootCommandRetention::Continuation),
        (2, Some(terminal_time), Some(expires_at)) => Ok(FixedRootCommandRetention::Terminal {
            terminal_time,
            expires_at,
        }),
        _ => Err(FixedRootCommandError::InvalidFixedRootCommand),
    }
}

fn read_safe_result(
    reader: &mut Reader<'_>,
) -> Result<Option<FixedRootCommandSafeResult>, FixedRootCommandError> {
    match reader.byte()? {
        0 => Ok(None),
        1 => Ok(Some(FixedRootCommandSafeResult {
            codec: reader.u16()?,
            version: reader.u16()?,
            digest: reader.array()?,
        })),
        _ => Err(FixedRootCommandError::InvalidFixedRootCommand),
    }
}

fn read_target_binding(
    reader: &mut Reader<'_>,
) -> Result<Option<FixedRootCommandTargetBinding>, FixedRootCommandError> {
    match reader.byte()? {
        0 => Ok(None),
        1 => {
            let source = reader.array()?;
            let target = reader.array()?;
            let source_generation = reader.optional_u64()?;
            let target_generation = reader.optional_u64()?;
            let parent_witness = match reader.byte()? {
                0 => None,
                1 => Some((
                    reader.array()?,
                    reader.u64()?,
                    reader.array()?,
                    reader.array()?,
                )),
                _ => return Err(FixedRootCommandError::InvalidFixedRootCommand),
            };
            Ok(Some(FixedRootCommandTargetBinding {
                source,
                target,
                source_generation,
                target_generation,
                parent_witness,
            }))
        }
        _ => Err(FixedRootCommandError::InvalidFixedRootCommand),
    }
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }

    fn finished(&self) -> bool {
        self.remaining.is_empty()
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], FixedRootCommandError> {
        let (head, tail) = self
            .remaining
            .split_at_checked(length)
            .ok_or(FixedRootCommandError::InvalidFixedRootCommand)?;
        self.remaining = tail;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, FixedRootCommandError> {
        Ok(self.bytes(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FixedRootCommandError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| FixedRootCommandError::InvalidFixedRootCommand)
    }

    fn u16(&mut self) -> Result<u16, FixedRootCommandError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, FixedRootCommandError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn optional_i64(&mut self) -> Result<Option<i64>, FixedRootCommandError> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(i64::from_be_bytes(self.array()?))),
            _ => Err(FixedRootCommandError::InvalidFixedRootCommand),
        }
    }

    fn optional_u64(&mut self) -> Result<Option<u64>, FixedRootCommandError> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(u64::from_be_bytes(self.array()?))),
            _ => Err(FixedRootCommandError::InvalidFixedRootCommand),
        }
    }
}

#[cfg(test)]
#[path = "red_fixed_root_command.rs"]
mod red_fixed_root_command;

#[cfg(test)]
#[path = "red_fixed_root_command_common_invariants.rs"]
mod red_fixed_root_command_common_invariants;

#[cfg(test)]
#[path = "red_fixed_root_command_codec_input.rs"]
mod red_fixed_root_command_codec_input;

#[cfg(test)]
#[path = "red_fixed_root_command_authenticated.rs"]
mod red_fixed_root_command_authenticated;
