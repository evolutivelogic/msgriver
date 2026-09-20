//! Task 0033 private recovery-ring/v1 manifest codec frontier.
//!
//! This child owns only the authenticated in-memory representation. It has no
//! allocation authority, storage, publication, replay, or public API surface.

use super::JournalIntegrityKey;
use hmac::{Hmac, Mac};
use sha2::Sha256;

const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"msgriver/recovery-ring/v1";
const TAG_BYTES: usize = 32;
const MAXIMUM_ENTRIES: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct RecoveryGeneration(pub(super) u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecoveryRingPhase {
    Retained,
    Active,
    PendingEscrow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RecoveryRingEntry {
    pub(super) generation: RecoveryGeneration,
    pub(super) phase: RecoveryRingPhase,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RecoveryRingManifest {
    pub(super) entries: Vec<RecoveryRingEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecoveryRingManifestError {
    MissingRecoveryRingManifest,
    InvalidRecoveryRingManifest,
}

pub(super) fn encode_recovery_ring_manifest(
    key: &JournalIntegrityKey,
    manifest: &RecoveryRingManifest,
) -> Result<Vec<u8>, RecoveryRingManifestError> {
    // FRONTIER: recovery_ring_manifest
    validate_manifest(manifest)?;
    let mut wire = Vec::with_capacity(expected_length(manifest.entries.len())?);
    wire.push(VERSION);
    wire.push(manifest.entries.len() as u8);
    for entry in &manifest.entries {
        wire.extend_from_slice(&entry.generation.0.to_be_bytes());
        wire.push(entry.phase.code());
    }
    wire.extend_from_slice(&key.recovery_ring_manifest_tag(&wire)?);
    Ok(wire)
}

pub(super) fn decode_recovery_ring_manifest(
    key: &JournalIntegrityKey,
    wire: &[u8],
) -> Result<RecoveryRingManifest, RecoveryRingManifestError> {
    // FRONTIER: recovery_ring_manifest
    if wire.len() < 2 {
        return Err(RecoveryRingManifestError::InvalidRecoveryRingManifest);
    }
    let entry_count = wire[1] as usize;
    let total_length = expected_length(entry_count)?;
    if wire.len() != total_length {
        return Err(RecoveryRingManifestError::InvalidRecoveryRingManifest);
    }

    let tag_start = wire.len() - TAG_BYTES;
    key.verify_recovery_ring_manifest_tag(&wire[..tag_start], &wire[tag_start..])?;
    if wire[0] != VERSION {
        return Err(RecoveryRingManifestError::InvalidRecoveryRingManifest);
    }

    let mut entries = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
        let offset = 2 + index * 9;
        let generation = u64::from_be_bytes(
            wire[offset..offset + 8]
                .try_into()
                .map_err(|_| RecoveryRingManifestError::InvalidRecoveryRingManifest)?,
        );
        let phase = RecoveryRingPhase::from_code(wire[offset + 8])?;
        entries.push(RecoveryRingEntry {
            generation: RecoveryGeneration(generation),
            phase,
        });
    }
    let manifest = RecoveryRingManifest { entries };
    validate_manifest(&manifest)?;
    Ok(manifest)
}

impl RecoveryRingPhase {
    fn code(self) -> u8 {
        match self {
            Self::Retained => 1,
            Self::Active => 2,
            Self::PendingEscrow => 3,
        }
    }

    fn from_code(code: u8) -> Result<Self, RecoveryRingManifestError> {
        match code {
            1 => Ok(Self::Retained),
            2 => Ok(Self::Active),
            3 => Ok(Self::PendingEscrow),
            _ => Err(RecoveryRingManifestError::InvalidRecoveryRingManifest),
        }
    }
}

impl JournalIntegrityKey {
    fn recovery_ring_manifest_tag(
        &self,
        manifest_without_tag: &[u8],
    ) -> Result<[u8; TAG_BYTES], RecoveryRingManifestError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0[..])
            .map_err(|_| RecoveryRingManifestError::InvalidRecoveryRingManifest)?;
        mac.update(DOMAIN);
        mac.update(manifest_without_tag);
        Ok(mac.finalize().into_bytes().into())
    }

    fn verify_recovery_ring_manifest_tag(
        &self,
        manifest_without_tag: &[u8],
        tag: &[u8],
    ) -> Result<(), RecoveryRingManifestError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0[..])
            .map_err(|_| RecoveryRingManifestError::InvalidRecoveryRingManifest)?;
        mac.update(DOMAIN);
        mac.update(manifest_without_tag);
        mac.verify_slice(tag)
            .map_err(|_| RecoveryRingManifestError::InvalidRecoveryRingManifest)
    }
}

fn expected_length(entry_count: usize) -> Result<usize, RecoveryRingManifestError> {
    if entry_count > MAXIMUM_ENTRIES {
        return Err(RecoveryRingManifestError::InvalidRecoveryRingManifest);
    }
    Ok(34 + 9 * entry_count)
}

fn validate_manifest(manifest: &RecoveryRingManifest) -> Result<(), RecoveryRingManifestError> {
    expected_length(manifest.entries.len())?;
    let mut previous_generation = None;
    let mut active_entries = 0;
    let mut pending_entries = 0;
    for entry in &manifest.entries {
        if entry.generation.0 == 0
            || previous_generation.is_some_and(|previous| previous >= entry.generation)
        {
            return Err(RecoveryRingManifestError::InvalidRecoveryRingManifest);
        }
        previous_generation = Some(entry.generation);
        match entry.phase {
            RecoveryRingPhase::Retained => {}
            RecoveryRingPhase::Active => active_entries += 1,
            RecoveryRingPhase::PendingEscrow => pending_entries += 1,
        }
    }
    if active_entries > 1 || pending_entries > 1 {
        return Err(RecoveryRingManifestError::InvalidRecoveryRingManifest);
    }
    Ok(())
}

#[cfg(test)]
#[path = "red_recovery_ring_manifest.rs"]
mod red_recovery_ring_manifest;
