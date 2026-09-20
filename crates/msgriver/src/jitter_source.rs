//! Host-owned retry-jitter source seam (A-11.3, PR-084).
//!
//! This source owns the provider boundary and never exposes key material to
//! the core consumer of its closed result vocabulary.

use msgriver_core::canon::{MacKeyRef, MacProvider, MacPurpose};

const RETRY_JITTER_DOMAIN: &[u8] = b"msgriver/retry-jitter/v1\0";
const REJECTION_LIMIT: u32 = 0xffff_fd94;

/// The complete public context a host-side retry-jitter derivation may receive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JitterSourceRequest {
    pub derivation_version: u8,
    pub key_reference: MacKeyRef,
    pub message_id: [u8; 16],
    pub completed_attempt_ordinal: u16,
}

/// Closed result vocabulary consumed by the core after host-side derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitterSourceOutcome {
    MultiplierMilli(u16),
    InvalidDerivation,
    Unavailable,
}

/// Private host-side scaffold state; never a protocol or core error.
///
/// Version one completes without this error. It remains in the port signature
/// to preserve the compile-seam API while later derivation versions are
/// separately specified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitterSourceError {
    MissingImplementation,
}

/// Derive the retry multiplier from a host-owned key reference.
///
/// Invalid construction and unavailable/exhausted source outcomes are closed,
/// typed results. Core observes no key, tag, counter, or provider capability.
pub fn derive_retry_jitter(
    provider: &dyn MacProvider,
    request: JitterSourceRequest,
) -> Result<JitterSourceOutcome, JitterSourceError> {
    if request.derivation_version != 1
        || !(1..=1023).contains(&request.completed_attempt_ordinal)
        || request.key_reference.purpose() != MacPurpose::RetryJitterV1
        || !is_uuid_v7(request.message_id)
    {
        return Ok(JitterSourceOutcome::InvalidDerivation);
    }

    for counter in 0..=u8::MAX {
        let input = framed_input(request, counter);
        let tag = match provider.authenticate(request.key_reference, &input) {
            Ok(tag) if tag.key() == request.key_reference => tag,
            Ok(_) | Err(_) => return Ok(JitterSourceOutcome::Unavailable),
        };
        let bytes = tag.tag().0;
        let candidate = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if candidate < REJECTION_LIMIT {
            return Ok(JitterSourceOutcome::MultiplierMilli(
                (500 + candidate % 1001) as u16,
            ));
        }
    }

    Ok(JitterSourceOutcome::Unavailable)
}

fn is_uuid_v7(message_id: [u8; 16]) -> bool {
    message_id[6] >> 4 == 7 && message_id[8] >> 6 == 2
}

fn framed_input(request: JitterSourceRequest, counter: u8) -> Vec<u8> {
    let mut input = Vec::with_capacity(RETRY_JITTER_DOMAIN.len() + 40 + 16 + 2 + 1);
    input.extend_from_slice(RETRY_JITTER_DOMAIN);
    input.extend_from_slice(request.key_reference.key_id().as_bytes());
    input.extend_from_slice(&request.message_id);
    input.extend_from_slice(&request.completed_attempt_ordinal.to_be_bytes());
    input.push(counter);
    input
}

#[cfg(test)]
#[path = "red_jitter_source.rs"]
mod red_jitter_source;
