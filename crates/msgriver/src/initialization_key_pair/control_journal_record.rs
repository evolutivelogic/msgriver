//! Task 0020 private control-journal lifecycle-envelope boundary.
//!
//! It owns only A-13.2.1 frame integrity and chain position. Record bodies,
//! checkpoint/image authority, and publication remain outside this child.

use super::JournalIntegrityKey;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fmt;

const MIN_FRAME_BYTES: usize = 110;
const MAX_FRAME_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = MAX_FRAME_BYTES - MIN_FRAME_BYTES;
const RECORD_LABEL: &[u8] = b"msgriver/control-journal-record/v1";
const AUTH_LABEL: &[u8] = b"msgriver/control-journal-record-auth/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ControlJournalRecordKind {
    ClockCheckpoint,
    ClockAcknowledge,
    SystemShutdown,
}

impl ControlJournalRecordKind {
    fn code(self) -> u16 {
        match self {
            Self::ClockCheckpoint => 1,
            Self::ClockAcknowledge => 2,
            Self::SystemShutdown => 3,
        }
    }

    fn from_code(code: u16) -> Result<Self, ControlJournalRecordError> {
        match code {
            1 => Ok(Self::ClockCheckpoint),
            2 => Ok(Self::ClockAcknowledge),
            3 => Ok(Self::SystemShutdown),
            _ => Err(ControlJournalRecordError::InvalidRecord),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct JournalHead {
    pub(super) sequence: u64,
    pub(super) record_digest: [u8; 32],
}

impl JournalHead {
    fn genesis() -> Self {
        Self {
            sequence: 0,
            record_digest: [0; 32],
        }
    }
}

#[derive(PartialEq, Eq)]
pub(super) struct ControlJournalRecord<'a> {
    pub(super) kind: ControlJournalRecordKind,
    pub(super) sequence: u64,
    pub(super) record_digest: [u8; 32],
    pub(super) body: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ControlJournalRecordError {
    MissingControlJournalRecord,
    InvalidRecord,
    SequenceExhausted,
}

impl fmt::Display for ControlJournalRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingControlJournalRecord => "control journal record is not implemented",
            Self::InvalidRecord => "control journal record is invalid",
            Self::SequenceExhausted => "control journal record sequence is exhausted",
        })
    }
}

impl std::error::Error for ControlJournalRecordError {}

impl JournalIntegrityKey {
    pub(super) fn encode_control_journal_record(
        &self,
        kind: ControlJournalRecordKind,
        body: &[u8],
        prior: JournalHead,
    ) -> Result<Vec<u8>, ControlJournalRecordError> {
        let mut frame = Self::record_prefix(kind, body, prior)?;
        frame.extend_from_slice(&Self::record_digest(&frame));
        frame.extend_from_slice(&self.record_tag(&frame)?);
        Ok(frame)
    }

    /// Pure image-fold bridge. It computes only the canonical clock record's
    /// head; it grants no authentication, key access, or publication authority.
    pub(super) fn control_journal_clock_checkpoint_head(
        body: &[u8],
        prior: JournalHead,
    ) -> Result<JournalHead, ControlJournalRecordError> {
        let prefix = Self::record_prefix(ControlJournalRecordKind::ClockCheckpoint, body, prior)?;
        Ok(JournalHead {
            sequence: prior
                .sequence
                .checked_add(1)
                .ok_or(ControlJournalRecordError::SequenceExhausted)?,
            record_digest: Self::record_digest(&prefix),
        })
    }

    fn record_prefix(
        kind: ControlJournalRecordKind,
        body: &[u8],
        prior: JournalHead,
    ) -> Result<Vec<u8>, ControlJournalRecordError> {
        if body.len() > MAX_BODY_BYTES {
            return Err(ControlJournalRecordError::InvalidRecord);
        }
        let sequence = prior
            .sequence
            .checked_add(1)
            .ok_or(ControlJournalRecordError::SequenceExhausted)?;
        let length = MIN_FRAME_BYTES + body.len();
        let length = u32::try_from(length).map_err(|_| ControlJournalRecordError::InvalidRecord)?;
        let mut frame = Vec::with_capacity(length as usize);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&kind.code().to_be_bytes());
        frame.extend_from_slice(&sequence.to_be_bytes());
        frame.extend_from_slice(&prior.record_digest);
        frame.extend_from_slice(body);
        Ok(frame)
    }

    pub(super) fn decode_control_journal_record<'a>(
        &self,
        frame: &'a [u8],
        prior: JournalHead,
    ) -> Result<ControlJournalRecord<'a>, ControlJournalRecordError> {
        if frame.len() < 4 {
            return Err(ControlJournalRecordError::InvalidRecord);
        }
        let length = u32::from_be_bytes(
            frame[..4]
                .try_into()
                .map_err(|_| ControlJournalRecordError::InvalidRecord)?,
        );
        let length =
            usize::try_from(length).map_err(|_| ControlJournalRecordError::InvalidRecord)?;
        if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&length) || frame.len() != length {
            return Err(ControlJournalRecordError::InvalidRecord);
        }
        let tag_start = length - 32;
        self.verify_record_tag(&frame[..tag_start], &frame[tag_start..])?;
        let digest_start = length - 64;
        let expected_digest = Self::record_digest(&frame[..digest_start]);
        if frame[digest_start..tag_start] != expected_digest {
            return Err(ControlJournalRecordError::InvalidRecord);
        }
        let kind = ControlJournalRecordKind::from_code(u16::from_be_bytes(
            frame[4..6]
                .try_into()
                .map_err(|_| ControlJournalRecordError::InvalidRecord)?,
        ))?;
        let sequence = u64::from_be_bytes(
            frame[6..14]
                .try_into()
                .map_err(|_| ControlJournalRecordError::InvalidRecord)?,
        );
        let expected_sequence = prior
            .sequence
            .checked_add(1)
            .ok_or(ControlJournalRecordError::SequenceExhausted)?;
        if sequence != expected_sequence || frame[14..46] != prior.record_digest {
            return Err(ControlJournalRecordError::InvalidRecord);
        }
        Ok(ControlJournalRecord {
            kind,
            sequence,
            record_digest: expected_digest,
            body: &frame[46..digest_start],
        })
    }

    fn record_digest(frame_prefix: &[u8]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(RECORD_LABEL);
        digest.update(&frame_prefix[4..]);
        digest.finalize().into()
    }

    fn record_tag(&self, frame_without_tag: &[u8]) -> Result<[u8; 32], ControlJournalRecordError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0[..])
            .map_err(|_| ControlJournalRecordError::InvalidRecord)?;
        mac.update(AUTH_LABEL);
        mac.update(frame_without_tag);
        Ok(mac.finalize().into_bytes().into())
    }

    fn verify_record_tag(
        &self,
        frame_without_tag: &[u8],
        tag: &[u8],
    ) -> Result<(), ControlJournalRecordError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0[..])
            .map_err(|_| ControlJournalRecordError::InvalidRecord)?;
        mac.update(AUTH_LABEL);
        mac.update(frame_without_tag);
        mac.verify_slice(tag)
            .map_err(|_| ControlJournalRecordError::InvalidRecord)
    }
}

#[cfg(test)]
#[path = "red_control_journal_record.rs"]
mod red_control_journal_record;
