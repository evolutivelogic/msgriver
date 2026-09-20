//! Task 0071 private composition of the `0x0020` envelope and common body.
//!
//! The body remains opaque until the preceding record codec has authenticated
//! it. This boundary returns an in-memory value only; it cannot publish, apply,
//! or otherwise mutate a journal head.

use super::JournalIntegrityKey;
use super::fixed_root_command::{
    FixedRootCommand, FixedRootCommandCodec, decode_fixed_root_command, encode_fixed_root_command,
};
use super::fixed_root_command_record::{FixedRootCommandJournalHead, FixedRootCommandRecordError};
use std::fmt;

#[derive(PartialEq, Eq)]
pub(super) struct FixedRootCommandAuthenticatedRecord {
    pub(super) sequence: u64,
    pub(super) record_digest: [u8; 32],
    pub(super) command: FixedRootCommand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FixedRootCommandAuthenticatedError {
    InvalidCommand,
    SequenceExhausted,
}

impl fmt::Display for FixedRootCommandAuthenticatedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCommand => "authenticated fixed-root command is invalid",
            Self::SequenceExhausted => "authenticated fixed-root command sequence is exhausted",
        })
    }
}

impl std::error::Error for FixedRootCommandAuthenticatedError {}

pub(super) fn encode_fixed_root_command_authenticated(
    journal_integrity_key: &JournalIntegrityKey,
    body_codec: &FixedRootCommandCodec,
    command: FixedRootCommand,
    prior: FixedRootCommandJournalHead,
) -> Result<Vec<u8>, FixedRootCommandAuthenticatedError> {
    let body = encode_fixed_root_command(body_codec, command)
        .map_err(|_| FixedRootCommandAuthenticatedError::InvalidCommand)?;
    journal_integrity_key
        .encode_fixed_root_command_record(&body, prior)
        .map_err(map_record_error)
}

pub(super) fn decode_fixed_root_command_authenticated(
    journal_integrity_key: &JournalIntegrityKey,
    body_codec: &FixedRootCommandCodec,
    frame: &[u8],
    prior: FixedRootCommandJournalHead,
) -> Result<FixedRootCommandAuthenticatedRecord, FixedRootCommandAuthenticatedError> {
    let record = journal_integrity_key
        .decode_fixed_root_command_record(frame, prior)
        .map_err(map_record_error)?;
    let command = decode_fixed_root_command(body_codec, record.body)
        .map_err(|_| FixedRootCommandAuthenticatedError::InvalidCommand)?;
    Ok(FixedRootCommandAuthenticatedRecord {
        sequence: record.sequence,
        record_digest: record.record_digest,
        command,
    })
}

fn map_record_error(error: FixedRootCommandRecordError) -> FixedRootCommandAuthenticatedError {
    match error {
        FixedRootCommandRecordError::InvalidRecord => {
            FixedRootCommandAuthenticatedError::InvalidCommand
        }
        FixedRootCommandRecordError::SequenceExhausted => {
            FixedRootCommandAuthenticatedError::SequenceExhausted
        }
    }
}
