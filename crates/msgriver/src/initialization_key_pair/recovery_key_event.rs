//! Task 0039 private recovery-key event body codec frontier.
//!
//! The enclosing journal envelope authenticates these bytes. This child only
//! owns the canonical in-memory body, with no command ingress or side effects.

const VERSION: u8 = 1;
const RECOVERY_KEY_GENERATE_OPERATION: u8 = 1;
const FIXED_STATE_OWNER_ACTOR: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RecoveryKeyEventGeneration(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryKeyEventPhase {
    IntentGenerate,
    KeyDurable,
    SecretConsumed,
    PendingEscrow,
    Activated,
    TerminalFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryKeyEventRetention {
    Null,
    Terminal { expires_at: i64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RecoveryKeyEvent {
    generation: RecoveryKeyEventGeneration,
    command_digest: [u8; 32],
    semantic_fingerprint: [u8; 32],
    phase_fingerprint: [u8; 32],
    portable_reservation_digest: [u8; 32],
    key_confirmation_digest: Option<[u8; 32]>,
    phase: RecoveryKeyEventPhase,
    retention: RecoveryKeyEventRetention,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryKeyEventError {
    MissingRecoveryKeyEvent,
    InvalidRecoveryKeyEvent,
}

fn encode_recovery_key_event(event: RecoveryKeyEvent) -> Result<Vec<u8>, RecoveryKeyEventError> {
    // FRONTIER: recovery_key_event
    validate_event(event)?;
    let mut wire = Vec::with_capacity(event.encoded_length());
    wire.extend_from_slice(&[
        VERSION,
        RECOVERY_KEY_GENERATE_OPERATION,
        FIXED_STATE_OWNER_ACTOR,
        event.phase.code(),
    ]);
    wire.extend_from_slice(&event.generation.0.to_be_bytes());
    wire.extend_from_slice(&event.command_digest);
    wire.extend_from_slice(&event.semantic_fingerprint);
    wire.extend_from_slice(&event.phase_fingerprint);
    wire.extend_from_slice(&event.portable_reservation_digest);
    match event.key_confirmation_digest {
        None => wire.push(0),
        Some(digest) => {
            wire.push(1);
            wire.extend_from_slice(&digest);
        }
    }
    match event.retention {
        RecoveryKeyEventRetention::Null => wire.push(0),
        RecoveryKeyEventRetention::Terminal { expires_at } => {
            wire.push(1);
            wire.extend_from_slice(&expires_at.to_be_bytes());
        }
    }
    Ok(wire)
}

fn decode_recovery_key_event(wire: &[u8]) -> Result<RecoveryKeyEvent, RecoveryKeyEventError> {
    // FRONTIER: recovery_key_event
    if wire.len() < 141 {
        return Err(RecoveryKeyEventError::InvalidRecoveryKeyEvent);
    }
    let key_confirmation_present = wire[140];
    let confirmation_length = match key_confirmation_present {
        0 => 0,
        1 => 32,
        _ => return Err(RecoveryKeyEventError::InvalidRecoveryKeyEvent),
    };
    let retention_offset = 141 + confirmation_length;
    if wire.len() <= retention_offset {
        return Err(RecoveryKeyEventError::InvalidRecoveryKeyEvent);
    }
    let retention = match wire[retention_offset] {
        0 => RecoveryKeyEventRetention::Null,
        1 => RecoveryKeyEventRetention::Terminal {
            expires_at: i64::from_be_bytes(
                wire.get(retention_offset + 1..retention_offset + 9)
                    .ok_or(RecoveryKeyEventError::InvalidRecoveryKeyEvent)?
                    .try_into()
                    .map_err(|_| RecoveryKeyEventError::InvalidRecoveryKeyEvent)?,
            ),
        },
        _ => return Err(RecoveryKeyEventError::InvalidRecoveryKeyEvent),
    };
    let expected_length = match (key_confirmation_present, retention) {
        (0, RecoveryKeyEventRetention::Null) => 142,
        (0, RecoveryKeyEventRetention::Terminal { .. }) => 150,
        (1, RecoveryKeyEventRetention::Null) => 174,
        (1, RecoveryKeyEventRetention::Terminal { .. }) => 182,
        _ => return Err(RecoveryKeyEventError::InvalidRecoveryKeyEvent),
    };
    if wire.len() != expected_length {
        return Err(RecoveryKeyEventError::InvalidRecoveryKeyEvent);
    }

    let event = RecoveryKeyEvent {
        generation: RecoveryKeyEventGeneration(u64::from_be_bytes(
            wire.get(4..12)
                .ok_or(RecoveryKeyEventError::InvalidRecoveryKeyEvent)?
                .try_into()
                .map_err(|_| RecoveryKeyEventError::InvalidRecoveryKeyEvent)?,
        )),
        command_digest: digest_at(wire, 12)?,
        semantic_fingerprint: digest_at(wire, 44)?,
        phase_fingerprint: digest_at(wire, 76)?,
        portable_reservation_digest: digest_at(wire, 108)?,
        key_confirmation_digest: match key_confirmation_present {
            0 => None,
            1 => Some(digest_at(wire, 141)?),
            _ => return Err(RecoveryKeyEventError::InvalidRecoveryKeyEvent),
        },
        phase: RecoveryKeyEventPhase::from_code(wire[3])?,
        retention,
    };
    if wire[0] != VERSION
        || wire[1] != RECOVERY_KEY_GENERATE_OPERATION
        || wire[2] != FIXED_STATE_OWNER_ACTOR
    {
        return Err(RecoveryKeyEventError::InvalidRecoveryKeyEvent);
    }
    validate_event(event)?;
    Ok(event)
}

impl RecoveryKeyEvent {
    fn encoded_length(self) -> usize {
        142 + usize::from(self.key_confirmation_digest.is_some()) * 32
            + match self.retention {
                RecoveryKeyEventRetention::Null => 0,
                RecoveryKeyEventRetention::Terminal { .. } => 8,
            }
    }
}

impl RecoveryKeyEventPhase {
    fn code(self) -> u8 {
        match self {
            Self::IntentGenerate => 1,
            Self::KeyDurable => 2,
            Self::SecretConsumed => 3,
            Self::PendingEscrow => 4,
            Self::Activated => 5,
            Self::TerminalFailed => 6,
        }
    }

    fn from_code(code: u8) -> Result<Self, RecoveryKeyEventError> {
        match code {
            1 => Ok(Self::IntentGenerate),
            2 => Ok(Self::KeyDurable),
            3 => Ok(Self::SecretConsumed),
            4 => Ok(Self::PendingEscrow),
            5 => Ok(Self::Activated),
            6 => Ok(Self::TerminalFailed),
            _ => Err(RecoveryKeyEventError::InvalidRecoveryKeyEvent),
        }
    }
}

fn digest_at(wire: &[u8], offset: usize) -> Result<[u8; 32], RecoveryKeyEventError> {
    wire.get(offset..offset + 32)
        .ok_or(RecoveryKeyEventError::InvalidRecoveryKeyEvent)?
        .try_into()
        .map_err(|_| RecoveryKeyEventError::InvalidRecoveryKeyEvent)
}

fn validate_event(event: RecoveryKeyEvent) -> Result<(), RecoveryKeyEventError> {
    if event.generation.0 == 0
        || digest_is_zero(&event.command_digest)
        || digest_is_zero(&event.semantic_fingerprint)
        || digest_is_zero(&event.phase_fingerprint)
        || digest_is_zero(&event.portable_reservation_digest)
        || event
            .key_confirmation_digest
            .is_some_and(|digest| digest_is_zero(&digest))
    {
        return Err(RecoveryKeyEventError::InvalidRecoveryKeyEvent);
    }
    match event.phase {
        RecoveryKeyEventPhase::IntentGenerate => {
            if event.key_confirmation_digest.is_none()
                && event.retention == RecoveryKeyEventRetention::Null
            {
                Ok(())
            } else {
                Err(RecoveryKeyEventError::InvalidRecoveryKeyEvent)
            }
        }
        RecoveryKeyEventPhase::TerminalFailed => {
            if event.key_confirmation_digest.is_none()
                && matches!(event.retention, RecoveryKeyEventRetention::Terminal { .. })
            {
                Ok(())
            } else {
                Err(RecoveryKeyEventError::InvalidRecoveryKeyEvent)
            }
        }
        RecoveryKeyEventPhase::KeyDurable
        | RecoveryKeyEventPhase::SecretConsumed
        | RecoveryKeyEventPhase::PendingEscrow
        | RecoveryKeyEventPhase::Activated => {
            if event.key_confirmation_digest.is_some()
                && event.retention == RecoveryKeyEventRetention::Null
            {
                Ok(())
            } else {
                Err(RecoveryKeyEventError::InvalidRecoveryKeyEvent)
            }
        }
    }
}

fn digest_is_zero(digest: &[u8; 32]) -> bool {
    digest.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
#[path = "red_recovery_key_event.rs"]
mod red_recovery_key_event;
