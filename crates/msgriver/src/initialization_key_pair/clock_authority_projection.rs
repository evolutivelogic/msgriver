//! Task 0025 private clock-authority projection frontier.
//!
//! The future checkpoint authenticates these bytes. This child will validate
//! only the canonical projection value, never a lifecycle or image transition.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ClockAuthorityHold {
    pub(super) generation: u64,
    pub(super) observation_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ClockAuthorityProjection {
    pub(super) safe_time: i64,
    pub(super) hold: Option<ClockAuthorityHold>,
    pub(super) last_shutdown_observation: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ClockAuthorityProjectionError {
    MissingClockAuthorityProjection,
    InvalidClockAuthorityProjection,
}

pub(super) fn encode_clock_authority_projection(
    projection: ClockAuthorityProjection,
) -> Result<Vec<u8>, ClockAuthorityProjectionError> {
    // FRONTIER: clock_authority_projection
    validate_projection(projection)?;
    let mut wire = Vec::with_capacity(expected_length(
        projection.hold.is_some(),
        projection.last_shutdown_observation.is_some(),
    ));
    wire.push(1);
    wire.extend_from_slice(&projection.safe_time.to_be_bytes());
    wire.push(u8::from(projection.hold.is_some()));
    if let Some(hold) = projection.hold {
        wire.extend_from_slice(&hold.generation.to_be_bytes());
        wire.extend_from_slice(&hold.observation_digest);
    }
    wire.push(u8::from(projection.last_shutdown_observation.is_some()));
    if let Some(observation) = projection.last_shutdown_observation {
        wire.extend_from_slice(&observation.to_be_bytes());
    }
    Ok(wire)
}

pub(super) fn decode_clock_authority_projection(
    wire: &[u8],
) -> Result<ClockAuthorityProjection, ClockAuthorityProjectionError> {
    // FRONTIER: clock_authority_projection
    if wire.len() < 11 || wire[0] != 1 {
        return Err(ClockAuthorityProjectionError::InvalidClockAuthorityProjection);
    }
    let hold_present = presence_tag(wire[9])?;
    let shutdown_tag_offset = if hold_present {
        if wire.len() < 51 {
            return Err(ClockAuthorityProjectionError::InvalidClockAuthorityProjection);
        }
        50
    } else {
        10
    };
    let shutdown_present = presence_tag(wire[shutdown_tag_offset])?;
    if wire.len() != expected_length(hold_present, shutdown_present) {
        return Err(ClockAuthorityProjectionError::InvalidClockAuthorityProjection);
    }
    let safe_time = read_i64(&wire[1..9])?;
    let hold = if hold_present {
        Some(ClockAuthorityHold {
            generation: read_u64(&wire[10..18])?,
            observation_digest: wire[18..50]
                .try_into()
                .map_err(|_| ClockAuthorityProjectionError::InvalidClockAuthorityProjection)?,
        })
    } else {
        None
    };
    let last_shutdown_observation = if shutdown_present {
        Some(read_i64(
            &wire[shutdown_tag_offset + 1..shutdown_tag_offset + 9],
        )?)
    } else {
        None
    };
    let projection = ClockAuthorityProjection {
        safe_time,
        hold,
        last_shutdown_observation,
    };
    validate_projection(projection)?;
    Ok(projection)
}

fn expected_length(hold_present: bool, shutdown_present: bool) -> usize {
    11 + usize::from(hold_present) * 40 + usize::from(shutdown_present) * 8
}

fn presence_tag(tag: u8) -> Result<bool, ClockAuthorityProjectionError> {
    match tag {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ClockAuthorityProjectionError::InvalidClockAuthorityProjection),
    }
}

fn read_i64(bytes: &[u8]) -> Result<i64, ClockAuthorityProjectionError> {
    Ok(i64::from_be_bytes(bytes.try_into().map_err(|_| {
        ClockAuthorityProjectionError::InvalidClockAuthorityProjection
    })?))
}

fn read_u64(bytes: &[u8]) -> Result<u64, ClockAuthorityProjectionError> {
    Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
        ClockAuthorityProjectionError::InvalidClockAuthorityProjection
    })?))
}

fn validate_projection(
    projection: ClockAuthorityProjection,
) -> Result<(), ClockAuthorityProjectionError> {
    if let Some(hold) = projection.hold
        && (hold.generation == 0 || hold.observation_digest.iter().all(|byte| *byte == 0))
    {
        return Err(ClockAuthorityProjectionError::InvalidClockAuthorityProjection);
    }
    Ok(())
}

#[cfg(test)]
#[path = "red_clock_authority_projection.rs"]
mod red_clock_authority_projection;
