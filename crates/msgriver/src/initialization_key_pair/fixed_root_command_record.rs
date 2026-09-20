//! Task 0069 private `0x0020` A-13.2.1 envelope boundary.
//!
//! This child authenticates opaque fixed-root command bytes only. It owns no
//! body semantics, journal image, I/O, or durable intent.

use super::JournalIntegrityKey;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fmt;

const FIXED_ROOT_COMMAND_KIND: u16 = 0x0020;
const MIN_FRAME_BYTES: usize = 110;
const MAX_FRAME_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = MAX_FRAME_BYTES - MIN_FRAME_BYTES;
const RECORD_LABEL: &[u8] = b"msgriver/control-journal-record/v1";
const AUTH_LABEL: &[u8] = b"msgriver/control-journal-record-auth/v1";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct FixedRootCommandJournalHead {
    pub(super) sequence: u64,
    pub(super) record_digest: [u8; 32],
}

impl FixedRootCommandJournalHead {
    pub(super) fn genesis() -> Self {
        Self {
            sequence: 0,
            record_digest: [0; 32],
        }
    }
}

#[derive(PartialEq, Eq)]
pub(super) struct FixedRootCommandRecord<'a> {
    pub(super) sequence: u64,
    pub(super) record_digest: [u8; 32],
    pub(super) body: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FixedRootCommandRecordError {
    InvalidRecord,
    SequenceExhausted,
}

impl fmt::Display for FixedRootCommandRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRecord => "fixed-root command record is invalid",
            Self::SequenceExhausted => "fixed-root command record sequence is exhausted",
        })
    }
}

impl std::error::Error for FixedRootCommandRecordError {}

impl JournalIntegrityKey {
    pub(super) fn encode_fixed_root_command_record(
        &self,
        body: &[u8],
        prior: FixedRootCommandJournalHead,
    ) -> Result<Vec<u8>, FixedRootCommandRecordError> {
        if body.len() > MAX_BODY_BYTES {
            return Err(FixedRootCommandRecordError::InvalidRecord);
        }
        let sequence = prior
            .sequence
            .checked_add(1)
            .ok_or(FixedRootCommandRecordError::SequenceExhausted)?;
        let length = MIN_FRAME_BYTES + body.len();
        let length =
            u32::try_from(length).map_err(|_| FixedRootCommandRecordError::InvalidRecord)?;
        let mut frame = Vec::with_capacity(length as usize);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&FIXED_ROOT_COMMAND_KIND.to_be_bytes());
        frame.extend_from_slice(&sequence.to_be_bytes());
        frame.extend_from_slice(&prior.record_digest);
        frame.extend_from_slice(body);
        frame.extend_from_slice(&fixed_root_command_record_digest(&frame));
        frame.extend_from_slice(&fixed_root_command_record_tag(self, &frame)?);
        Ok(frame)
    }

    pub(super) fn decode_fixed_root_command_record<'a>(
        &self,
        frame: &'a [u8],
        prior: FixedRootCommandJournalHead,
    ) -> Result<FixedRootCommandRecord<'a>, FixedRootCommandRecordError> {
        if frame.len() < 4 {
            return Err(FixedRootCommandRecordError::InvalidRecord);
        }
        let length = u32::from_be_bytes(
            frame[..4]
                .try_into()
                .map_err(|_| FixedRootCommandRecordError::InvalidRecord)?,
        );
        let length =
            usize::try_from(length).map_err(|_| FixedRootCommandRecordError::InvalidRecord)?;
        if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&length) || frame.len() != length {
            return Err(FixedRootCommandRecordError::InvalidRecord);
        }
        let tag_start = length - 32;
        verify_fixed_root_command_record_tag(self, &frame[..tag_start], &frame[tag_start..])?;
        let digest_start = length - 64;
        let expected_digest = fixed_root_command_record_digest(&frame[..digest_start]);
        if frame[digest_start..tag_start] != expected_digest {
            return Err(FixedRootCommandRecordError::InvalidRecord);
        }
        let kind = u16::from_be_bytes(
            frame[4..6]
                .try_into()
                .map_err(|_| FixedRootCommandRecordError::InvalidRecord)?,
        );
        if kind != FIXED_ROOT_COMMAND_KIND {
            return Err(FixedRootCommandRecordError::InvalidRecord);
        }
        let sequence = u64::from_be_bytes(
            frame[6..14]
                .try_into()
                .map_err(|_| FixedRootCommandRecordError::InvalidRecord)?,
        );
        let expected_sequence = prior
            .sequence
            .checked_add(1)
            .ok_or(FixedRootCommandRecordError::SequenceExhausted)?;
        if sequence != expected_sequence || frame[14..46] != prior.record_digest {
            return Err(FixedRootCommandRecordError::InvalidRecord);
        }
        Ok(FixedRootCommandRecord {
            sequence,
            record_digest: expected_digest,
            body: &frame[46..digest_start],
        })
    }
}

fn fixed_root_command_record_digest(frame_prefix: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(RECORD_LABEL);
    digest.update(&frame_prefix[4..]);
    digest.finalize().into()
}

fn fixed_root_command_record_tag(
    journal_integrity_key: &JournalIntegrityKey,
    frame_without_tag: &[u8],
) -> Result<[u8; 32], FixedRootCommandRecordError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&journal_integrity_key.0[..])
        .map_err(|_| FixedRootCommandRecordError::InvalidRecord)?;
    mac.update(AUTH_LABEL);
    mac.update(frame_without_tag);
    Ok(mac.finalize().into_bytes().into())
}

fn verify_fixed_root_command_record_tag(
    journal_integrity_key: &JournalIntegrityKey,
    frame_without_tag: &[u8],
    tag: &[u8],
) -> Result<(), FixedRootCommandRecordError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&journal_integrity_key.0[..])
        .map_err(|_| FixedRootCommandRecordError::InvalidRecord)?;
    mac.update(AUTH_LABEL);
    mac.update(frame_without_tag);
    mac.verify_slice(tag)
        .map_err(|_| FixedRootCommandRecordError::InvalidRecord)
}

#[cfg(test)]
#[path = "red_fixed_root_command_record.rs"]
mod red_fixed_root_command_record;
