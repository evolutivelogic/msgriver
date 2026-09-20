//! Task 0083 private state-mac-key/v1 codec frontier.
//!
//! This child owns only one authenticated in-memory value. It has no manifest,
//! path, filesystem, provider, allocation, or publication capability.

use super::JournalIntegrityKey;
use hmac::{Hmac, Mac};
use msgriver_core::canon::{MacKeyId, MacKeyRef, MacPurpose};
use sha2::Sha256;
use zeroize::Zeroizing;

const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"msgriver/state-mac-key/v1";
const PRECEDING_BYTES: usize = 74;
const TAG_BYTES: usize = 32;
const WIRE_BYTES: usize = PRECEDING_BYTES + TAG_BYTES;

pub(crate) struct StateMacKeySecret(pub(super) Zeroizing<[u8; 32]>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StateMacKeyFileError {
    MissingStateMacKeyFile,
    InvalidStateMacKeyFile,
}

pub(super) fn encode_state_mac_key_file(
    key: &JournalIntegrityKey,
    expected: MacKeyRef,
    secret: &StateMacKeySecret,
) -> Result<[u8; 106], StateMacKeyFileError> {
    // FRONTIER: state_mac_key_file
    validate_reference(expected)?;
    if secret.0.iter().all(|byte| *byte == 0) {
        return Err(StateMacKeyFileError::InvalidStateMacKeyFile);
    }

    let mut wire = [0; WIRE_BYTES];
    wire[0] = VERSION;
    wire[1] = expected.purpose() as u8;
    wire[2..42].copy_from_slice(expected.key_id().as_bytes());
    wire[42..PRECEDING_BYTES].copy_from_slice(&secret.0[..]);
    let tag = key.state_mac_key_file_tag(&wire[..PRECEDING_BYTES])?;
    wire[PRECEDING_BYTES..].copy_from_slice(&tag);
    Ok(wire)
}

pub(crate) fn decode_state_mac_key_file(
    key: &JournalIntegrityKey,
    expected: MacKeyRef,
    wire: &[u8],
) -> Result<StateMacKeySecret, StateMacKeyFileError> {
    // FRONTIER: state_mac_key_file
    validate_reference(expected)?;
    if wire.len() != WIRE_BYTES {
        return Err(StateMacKeyFileError::InvalidStateMacKeyFile);
    }
    key.verify_state_mac_key_file_tag(&wire[..PRECEDING_BYTES], &wire[PRECEDING_BYTES..])?;
    if wire[0] != VERSION {
        return Err(StateMacKeyFileError::InvalidStateMacKeyFile);
    }

    let actual = MacKeyRef::new(
        purpose_from_byte(wire[1])?,
        MacKeyId::from_bytes(
            wire[2..42]
                .try_into()
                .map_err(|_| StateMacKeyFileError::InvalidStateMacKeyFile)?,
        ),
    );
    validate_reference(actual)?;
    if actual != expected {
        return Err(StateMacKeyFileError::InvalidStateMacKeyFile);
    }

    let raw: [u8; 32] = wire[42..PRECEDING_BYTES]
        .try_into()
        .map_err(|_| StateMacKeyFileError::InvalidStateMacKeyFile)?;
    if raw.iter().all(|byte| *byte == 0) {
        return Err(StateMacKeyFileError::InvalidStateMacKeyFile);
    }
    Ok(StateMacKeySecret(Zeroizing::new(raw)))
}

impl JournalIntegrityKey {
    fn state_mac_key_file_tag(
        &self,
        preceding: &[u8],
    ) -> Result<[u8; TAG_BYTES], StateMacKeyFileError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0[..])
            .map_err(|_| StateMacKeyFileError::InvalidStateMacKeyFile)?;
        mac.update(DOMAIN);
        mac.update(preceding);
        Ok(mac.finalize().into_bytes().into())
    }

    fn verify_state_mac_key_file_tag(
        &self,
        preceding: &[u8],
        tag: &[u8],
    ) -> Result<(), StateMacKeyFileError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0[..])
            .map_err(|_| StateMacKeyFileError::InvalidStateMacKeyFile)?;
        mac.update(DOMAIN);
        mac.update(preceding);
        mac.verify_slice(tag)
            .map_err(|_| StateMacKeyFileError::InvalidStateMacKeyFile)
    }
}

fn validate_reference(reference: MacKeyRef) -> Result<(), StateMacKeyFileError> {
    if reference.key_id().as_bytes()[32..]
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(StateMacKeyFileError::InvalidStateMacKeyFile);
    }
    Ok(())
}

fn purpose_from_byte(byte: u8) -> Result<MacPurpose, StateMacKeyFileError> {
    match byte {
        0x01 => Ok(MacPurpose::ApiKeyVerifyV1),
        0x02 => Ok(MacPurpose::IdempotencyLookupV1),
        0x03 => Ok(MacPurpose::IdempotencyFingerprintV1),
        0x04 => Ok(MacPurpose::ReplayLookupV1),
        0x05 => Ok(MacPurpose::ReplayFingerprintV1),
        0x06 => Ok(MacPurpose::CommandLookupV1),
        0x07 => Ok(MacPurpose::CommandSemanticFingerprintV1),
        0x08 => Ok(MacPurpose::CommandPhaseFingerprintV1),
        0x09 => Ok(MacPurpose::RetryJitterV1),
        0x0a => Ok(MacPurpose::ArtifactInternalAuthV1),
        0x0b => Ok(MacPurpose::PortableReservationV1),
        _ => Err(StateMacKeyFileError::InvalidStateMacKeyFile),
    }
}

#[cfg(test)]
#[path = "red_state_mac_key_file.rs"]
mod red_state_mac_key_file;
