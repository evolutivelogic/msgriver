//! Task 0022 private A-13.2.2 clock-checkpoint body frontier.
//!
//! The envelope authenticates these bytes elsewhere. This child will later
//! validate only canonical body meaning, never clock collection or publication.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RuntimeMode {
    Normal,
    Maintenance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CheckpointReason {
    Periodic,
    AutomaticSettlement,
    CleanShutdown,
    ExpiryProof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NamedHold {
    pub(super) generation: u64,
    pub(super) observation_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PreMirrorWitness {
    pub(super) selected_origin: [u8; 32],
    pub(super) transaction_sequence: u64,
    pub(super) transaction_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ClockCheckpointBody {
    pub(super) runtime_mode: RuntimeMode,
    pub(super) process_instance: [u8; 16],
    pub(super) accepted_wall_time: i64,
    pub(super) accepted_monotonic_tick: i64,
    pub(super) prior_safe_time: i64,
    pub(super) new_safe_time: i64,
    pub(super) reason: CheckpointReason,
    pub(super) hold: Option<NamedHold>,
    pub(super) pre_mirror: Option<PreMirrorWitness>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ClockCheckpointBodyError {
    MissingClockCheckpointBody,
    InvalidBody,
}

const FIXED_BODY_BYTES: usize = 53;
const HOLD_BYTES: usize = 40;
const MIRROR_BYTES: usize = 72;

impl RuntimeMode {
    fn code(self) -> u8 {
        match self {
            Self::Normal => 1,
            Self::Maintenance => 2,
        }
    }

    fn from_code(code: u8) -> Result<Self, ClockCheckpointBodyError> {
        match code {
            1 => Ok(Self::Normal),
            2 => Ok(Self::Maintenance),
            _ => Err(ClockCheckpointBodyError::InvalidBody),
        }
    }
}

impl CheckpointReason {
    fn code(self) -> u8 {
        match self {
            Self::Periodic => 1,
            Self::AutomaticSettlement => 2,
            Self::CleanShutdown => 3,
            Self::ExpiryProof => 4,
        }
    }

    fn from_code(code: u8) -> Result<Self, ClockCheckpointBodyError> {
        match code {
            1 => Ok(Self::Periodic),
            2 => Ok(Self::AutomaticSettlement),
            3 => Ok(Self::CleanShutdown),
            4 => Ok(Self::ExpiryProof),
            _ => Err(ClockCheckpointBodyError::InvalidBody),
        }
    }
}

pub(super) fn encode_clock_checkpoint_body(
    body: ClockCheckpointBody,
) -> Result<Vec<u8>, ClockCheckpointBodyError> {
    validate_body(body)?;
    let mut wire = Vec::with_capacity(expected_length(
        body.hold.is_some(),
        body.pre_mirror.is_some(),
    ));
    wire.extend_from_slice(&[1, body.runtime_mode.code()]);
    wire.extend_from_slice(&body.process_instance);
    wire.extend_from_slice(&body.accepted_wall_time.to_be_bytes());
    wire.extend_from_slice(&body.accepted_monotonic_tick.to_be_bytes());
    wire.extend_from_slice(&body.prior_safe_time.to_be_bytes());
    wire.extend_from_slice(&body.new_safe_time.to_be_bytes());
    wire.push(body.reason.code());
    wire.push(u8::from(body.hold.is_some()));
    wire.push(u8::from(body.pre_mirror.is_some()));
    if let Some(hold) = body.hold {
        wire.extend_from_slice(&hold.generation.to_be_bytes());
        wire.extend_from_slice(&hold.observation_digest);
    }
    if let Some(mirror) = body.pre_mirror {
        wire.extend_from_slice(&mirror.selected_origin);
        wire.extend_from_slice(&mirror.transaction_sequence.to_be_bytes());
        wire.extend_from_slice(&mirror.transaction_digest);
    }
    Ok(wire)
}

pub(super) fn decode_clock_checkpoint_body(
    wire: &[u8],
) -> Result<ClockCheckpointBody, ClockCheckpointBodyError> {
    if wire.len() < FIXED_BODY_BYTES || wire[0] != 1 {
        return Err(ClockCheckpointBodyError::InvalidBody);
    }
    let hold_present = presence_tag(wire[51])?;
    let mirror_present = presence_tag(wire[52])?;
    if wire.len() != expected_length(hold_present, mirror_present) {
        return Err(ClockCheckpointBodyError::InvalidBody);
    }
    let runtime_mode = RuntimeMode::from_code(wire[1])?;
    let process_instance = wire[2..18]
        .try_into()
        .map_err(|_| ClockCheckpointBodyError::InvalidBody)?;
    let accepted_wall_time = read_i64(&wire[18..26])?;
    let accepted_monotonic_tick = read_i64(&wire[26..34])?;
    let prior_safe_time = read_i64(&wire[34..42])?;
    let new_safe_time = read_i64(&wire[42..50])?;
    let reason = CheckpointReason::from_code(wire[50])?;
    let mut offset = FIXED_BODY_BYTES;
    let hold = if hold_present {
        let generation = read_u64(&wire[offset..offset + 8])?;
        let observation_digest = wire[offset + 8..offset + HOLD_BYTES]
            .try_into()
            .map_err(|_| ClockCheckpointBodyError::InvalidBody)?;
        offset += HOLD_BYTES;
        Some(NamedHold {
            generation,
            observation_digest,
        })
    } else {
        None
    };
    let pre_mirror = if mirror_present {
        let selected_origin = wire[offset..offset + 32]
            .try_into()
            .map_err(|_| ClockCheckpointBodyError::InvalidBody)?;
        let transaction_sequence = read_u64(&wire[offset + 32..offset + 40])?;
        let transaction_digest = wire[offset + 40..offset + MIRROR_BYTES]
            .try_into()
            .map_err(|_| ClockCheckpointBodyError::InvalidBody)?;
        Some(PreMirrorWitness {
            selected_origin,
            transaction_sequence,
            transaction_digest,
        })
    } else {
        None
    };
    let body = ClockCheckpointBody {
        runtime_mode,
        process_instance,
        accepted_wall_time,
        accepted_monotonic_tick,
        prior_safe_time,
        new_safe_time,
        reason,
        hold,
        pre_mirror,
    };
    validate_body(body)?;
    Ok(body)
}

fn expected_length(hold_present: bool, mirror_present: bool) -> usize {
    FIXED_BODY_BYTES
        + usize::from(hold_present) * HOLD_BYTES
        + usize::from(mirror_present) * MIRROR_BYTES
}

fn presence_tag(tag: u8) -> Result<bool, ClockCheckpointBodyError> {
    match tag {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ClockCheckpointBodyError::InvalidBody),
    }
}

fn read_i64(bytes: &[u8]) -> Result<i64, ClockCheckpointBodyError> {
    Ok(i64::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| ClockCheckpointBodyError::InvalidBody)?,
    ))
}

fn read_u64(bytes: &[u8]) -> Result<u64, ClockCheckpointBodyError> {
    Ok(u64::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| ClockCheckpointBodyError::InvalidBody)?,
    ))
}

fn validate_body(body: ClockCheckpointBody) -> Result<(), ClockCheckpointBodyError> {
    if body.process_instance == [0; 16]
        || body.accepted_monotonic_tick < 0
        || body.new_safe_time != body.prior_safe_time.max(body.accepted_wall_time)
    {
        return Err(ClockCheckpointBodyError::InvalidBody);
    }
    match (body.reason, body.hold) {
        (CheckpointReason::AutomaticSettlement, Some(hold)) => {
            if hold.generation == 0 || hold.observation_digest == [0; 32] {
                return Err(ClockCheckpointBodyError::InvalidBody);
            }
        }
        (CheckpointReason::AutomaticSettlement, None) | (_, Some(_)) => {
            return Err(ClockCheckpointBodyError::InvalidBody);
        }
        (_, None) => {}
    }
    if let Some(mirror) = body.pre_mirror
        && (mirror.selected_origin[24..] == 0u64.to_be_bytes()
            || mirror.transaction_digest == [0; 32])
    {
        return Err(ClockCheckpointBodyError::InvalidBody);
    }
    Ok(())
}

#[cfg(test)]
#[path = "red_clock_checkpoint_body.rs"]
mod red_clock_checkpoint_body;
