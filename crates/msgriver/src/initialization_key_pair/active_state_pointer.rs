//! Task 0028 private active-state pointer certificate frontier.
//!
//! A-14.3 owns the eventual file publication. This child owns only the
//! authenticated in-memory certificate value and has no I/O capability.

use super::JournalIntegrityKey;
use hmac::{Hmac, Mac};
use sha2::Sha256;

const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"msgriver/active-state-pointer/v1";
const TAG_BYTES: usize = 32;
const MINIMUM_BYTES: usize = 116;
const MAXIMUM_BYTES: usize = 624;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PointerOrigin {
    Bootstrap,
    Restore,
    Rollback,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ActiveStatePointer {
    pub(super) protocol_version: u32,
    pub(super) transition_id: String,
    pub(super) final_generation: u64,
    pub(super) lineage_id: String,
    pub(super) target_history_epoch: [u8; 32],
    pub(super) origin: PointerOrigin,
    pub(super) database_certificate_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ActiveStatePointerError {
    MissingActiveStatePointer,
    InvalidActiveStatePointer,
}

pub(super) fn encode_active_state_pointer(
    key: &JournalIntegrityKey,
    pointer: &ActiveStatePointer,
) -> Result<Vec<u8>, ActiveStatePointerError> {
    // FRONTIER: active_state_pointer
    validate_pointer(pointer)?;
    let transition = pointer.transition_id.as_bytes();
    let lineage = pointer.lineage_id.as_bytes();
    let mut wire = Vec::with_capacity(expected_length(transition.len(), lineage.len())?);
    wire.push(VERSION);
    wire.extend_from_slice(&pointer.protocol_version.to_be_bytes());
    wire.extend_from_slice(&(transition.len() as u16).to_be_bytes());
    wire.extend_from_slice(transition);
    wire.extend_from_slice(&pointer.final_generation.to_be_bytes());
    wire.extend_from_slice(&(lineage.len() as u16).to_be_bytes());
    wire.extend_from_slice(lineage);
    wire.extend_from_slice(&pointer.target_history_epoch);
    wire.push(pointer.origin.code());
    wire.extend_from_slice(&pointer.database_certificate_digest);
    wire.extend_from_slice(&key.active_state_pointer_tag(&wire)?);
    Ok(wire)
}

pub(super) fn decode_active_state_pointer(
    key: &JournalIntegrityKey,
    wire: &[u8],
) -> Result<ActiveStatePointer, ActiveStatePointerError> {
    // FRONTIER: active_state_pointer
    if !(MINIMUM_BYTES..=MAXIMUM_BYTES).contains(&wire.len()) || wire.len() < 7 {
        return Err(ActiveStatePointerError::InvalidActiveStatePointer);
    }
    let transition_length = read_length(&wire[5..7])?;
    if wire.len() < 17 + transition_length {
        return Err(ActiveStatePointerError::InvalidActiveStatePointer);
    }
    let lineage_length_start = 15 + transition_length;
    let lineage_length = read_length(&wire[lineage_length_start..lineage_length_start + 2])?;
    let total_length = expected_length(transition_length, lineage_length)?;
    if wire.len() != total_length {
        return Err(ActiveStatePointerError::InvalidActiveStatePointer);
    }

    let tag_start = wire.len() - TAG_BYTES;
    key.verify_active_state_pointer_tag(&wire[..tag_start], &wire[tag_start..])?;

    if wire[0] != VERSION {
        return Err(ActiveStatePointerError::InvalidActiveStatePointer);
    }
    let transition_start = 7;
    let generation_start = transition_start + transition_length;
    let lineage_start = lineage_length_start + 2;
    let epoch_start = lineage_start + lineage_length;
    let origin_start = epoch_start + 32;
    let digest_start = origin_start + 1;
    let pointer = ActiveStatePointer {
        protocol_version: u32::from_be_bytes(
            wire[1..5]
                .try_into()
                .map_err(|_| ActiveStatePointerError::InvalidActiveStatePointer)?,
        ),
        transition_id: validated_identifier(&wire[transition_start..generation_start])?,
        final_generation: u64::from_be_bytes(
            wire[generation_start..lineage_length_start]
                .try_into()
                .map_err(|_| ActiveStatePointerError::InvalidActiveStatePointer)?,
        ),
        lineage_id: validated_identifier(&wire[lineage_start..epoch_start])?,
        target_history_epoch: wire[epoch_start..origin_start]
            .try_into()
            .map_err(|_| ActiveStatePointerError::InvalidActiveStatePointer)?,
        origin: PointerOrigin::from_code(wire[origin_start])?,
        database_certificate_digest: wire[digest_start..tag_start]
            .try_into()
            .map_err(|_| ActiveStatePointerError::InvalidActiveStatePointer)?,
    };
    validate_pointer(&pointer)?;
    Ok(pointer)
}

impl PointerOrigin {
    fn code(self) -> u8 {
        match self {
            Self::Bootstrap => 1,
            Self::Restore => 2,
            Self::Rollback => 3,
        }
    }

    fn from_code(code: u8) -> Result<Self, ActiveStatePointerError> {
        match code {
            1 => Ok(Self::Bootstrap),
            2 => Ok(Self::Restore),
            3 => Ok(Self::Rollback),
            _ => Err(ActiveStatePointerError::InvalidActiveStatePointer),
        }
    }
}

impl JournalIntegrityKey {
    fn active_state_pointer_tag(
        &self,
        pointer_without_tag: &[u8],
    ) -> Result<[u8; TAG_BYTES], ActiveStatePointerError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0[..])
            .map_err(|_| ActiveStatePointerError::InvalidActiveStatePointer)?;
        mac.update(DOMAIN);
        mac.update(pointer_without_tag);
        Ok(mac.finalize().into_bytes().into())
    }

    fn verify_active_state_pointer_tag(
        &self,
        pointer_without_tag: &[u8],
        tag: &[u8],
    ) -> Result<(), ActiveStatePointerError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0[..])
            .map_err(|_| ActiveStatePointerError::InvalidActiveStatePointer)?;
        mac.update(DOMAIN);
        mac.update(pointer_without_tag);
        mac.verify_slice(tag)
            .map_err(|_| ActiveStatePointerError::InvalidActiveStatePointer)
    }
}

fn read_length(bytes: &[u8]) -> Result<usize, ActiveStatePointerError> {
    let length = u16::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| ActiveStatePointerError::InvalidActiveStatePointer)?,
    ) as usize;
    if !(1..=255).contains(&length) {
        return Err(ActiveStatePointerError::InvalidActiveStatePointer);
    }
    Ok(length)
}

fn expected_length(
    transition_length: usize,
    lineage_length: usize,
) -> Result<usize, ActiveStatePointerError> {
    if !(1..=255).contains(&transition_length) || !(1..=255).contains(&lineage_length) {
        return Err(ActiveStatePointerError::InvalidActiveStatePointer);
    }
    Ok(114 + transition_length + lineage_length)
}

fn validated_identifier(bytes: &[u8]) -> Result<String, ActiveStatePointerError> {
    let identifier = std::str::from_utf8(bytes)
        .map_err(|_| ActiveStatePointerError::InvalidActiveStatePointer)?;
    if identifier.contains('\0') {
        return Err(ActiveStatePointerError::InvalidActiveStatePointer);
    }
    Ok(identifier.to_owned())
}

fn validate_pointer(pointer: &ActiveStatePointer) -> Result<(), ActiveStatePointerError> {
    expected_length(pointer.transition_id.len(), pointer.lineage_id.len())?;
    if pointer.transition_id.contains('\0')
        || pointer.lineage_id.contains('\0')
        || pointer.final_generation == 0
        || pointer
            .database_certificate_digest
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(ActiveStatePointerError::InvalidActiveStatePointer);
    }
    Ok(())
}

#[cfg(test)]
#[path = "red_active_state_pointer.rs"]
mod red_active_state_pointer;
