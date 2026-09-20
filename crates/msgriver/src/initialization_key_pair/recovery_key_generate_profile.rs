//! Private lossless body codec for operation-`04` `recovery_key.generate`.
//!
//! It owns only the literal profile body defined by A-13.2.3.  Common command
//! authority, request/phase preimages, envelope framing, and safe-result
//! contents remain owned by their existing boundaries.

use std::fmt;

const FORMAT: u8 = 1;
const GENERATE: u8 = 1;
const ACKNOWLEDGE: u8 = 2;
const ISSUANCE: u8 = 1;
const CONFIRMATION: u8 = 2;
const ENTRY_BYTES: usize = 33;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecoveryKeyGenerateVariant {
    Generate,
    Acknowledge,
}

impl RecoveryKeyGenerateVariant {
    fn code(self) -> u8 {
        match self {
            Self::Generate => GENERATE,
            Self::Acknowledge => ACKNOWLEDGE,
        }
    }

    fn decode(code: u8) -> Result<Self, RecoveryKeyGenerateProfileError> {
        match code {
            GENERATE => Ok(Self::Generate),
            ACKNOWLEDGE => Ok(Self::Acknowledge),
            _ => Err(RecoveryKeyGenerateProfileError::InvalidProfile),
        }
    }
}

/// The two digest kinds have distinct slots and therefore cannot alias.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RecoveryKeyGenerateProfile {
    pub(super) variant: RecoveryKeyGenerateVariant,
    pub(super) issuance_digest: Option<[u8; 32]>,
    pub(super) confirmation_digest: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecoveryKeyGenerateProfileError {
    InvalidProfile,
}

impl fmt::Display for RecoveryKeyGenerateProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("recovery-key generate profile is invalid")
    }
}

impl std::error::Error for RecoveryKeyGenerateProfileError {}

pub(super) fn encode_recovery_key_generate_profile(profile: RecoveryKeyGenerateProfile) -> Vec<u8> {
    let count = u8::from(profile.issuance_digest.is_some())
        + u8::from(profile.confirmation_digest.is_some());
    let mut wire = Vec::with_capacity(3 + ENTRY_BYTES * usize::from(count));
    wire.extend_from_slice(&[FORMAT, profile.variant.code(), count]);
    if let Some(digest) = profile.issuance_digest {
        wire.push(ISSUANCE);
        wire.extend_from_slice(&digest);
    }
    if let Some(digest) = profile.confirmation_digest {
        wire.push(CONFIRMATION);
        wire.extend_from_slice(&digest);
    }
    wire
}

pub(super) fn decode_recovery_key_generate_profile(
    wire: &[u8],
) -> Result<RecoveryKeyGenerateProfile, RecoveryKeyGenerateProfileError> {
    if wire.len() < 3 || wire[0] != FORMAT {
        return Err(RecoveryKeyGenerateProfileError::InvalidProfile);
    }
    let variant = RecoveryKeyGenerateVariant::decode(wire[1])?;
    let count = wire[2];
    if count > 2 || wire.len() != 3 + ENTRY_BYTES * usize::from(count) {
        return Err(RecoveryKeyGenerateProfileError::InvalidProfile);
    }
    let mut issuance_digest = None;
    let mut confirmation_digest = None;
    let mut previous_kind = 0;
    for entry in wire[3..].chunks_exact(ENTRY_BYTES) {
        let kind = entry[0];
        if kind <= previous_kind {
            return Err(RecoveryKeyGenerateProfileError::InvalidProfile);
        }
        let digest = entry[1..]
            .try_into()
            .map_err(|_| RecoveryKeyGenerateProfileError::InvalidProfile)?;
        match kind {
            ISSUANCE => issuance_digest = Some(digest),
            CONFIRMATION => confirmation_digest = Some(digest),
            _ => return Err(RecoveryKeyGenerateProfileError::InvalidProfile),
        }
        previous_kind = kind;
    }
    Ok(RecoveryKeyGenerateProfile {
        variant,
        issuance_digest,
        confirmation_digest,
    })
}

#[cfg(test)]
#[path = "red_recovery_key_generate_profile.rs"]
mod red_recovery_key_generate_profile;
