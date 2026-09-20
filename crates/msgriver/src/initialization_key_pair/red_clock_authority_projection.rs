use super::*;

const HOLD_DIGEST: [u8; 32] = [0xA5; 32];

fn projection(hold: Option<ClockAuthorityHold>, shutdown: Option<i64>) -> ClockAuthorityProjection {
    ClockAuthorityProjection {
        safe_time: -17,
        hold,
        last_shutdown_observation: shutdown,
    }
}

fn named_hold() -> ClockAuthorityHold {
    ClockAuthorityHold {
        generation: 9,
        observation_digest: HOLD_DIGEST,
    }
}

fn encode(projection: ClockAuthorityProjection) -> Vec<u8> {
    match encode_clock_authority_projection(projection) {
        Ok(wire) => wire,
        Err(ClockAuthorityProjectionError::MissingClockAuthorityProjection) => {
            panic!("MissingClockAuthorityProjection: clock_authority_projection")
        }
        Err(error) => panic!("canonical projection rejected: {error:?}"),
    }
}

fn decode(wire: &[u8]) -> ClockAuthorityProjection {
    match decode_clock_authority_projection(wire) {
        Ok(projection) => projection,
        Err(ClockAuthorityProjectionError::MissingClockAuthorityProjection) => {
            panic!("MissingClockAuthorityProjection: clock_authority_projection")
        }
        Err(error) => panic!("canonical projection rejected: {error:?}"),
    }
}

fn reject(wire: &[u8]) {
    match decode_clock_authority_projection(wire) {
        Ok(_) => panic!("malformed projection decoded"),
        Err(error) => {
            if error == ClockAuthorityProjectionError::MissingClockAuthorityProjection {
                panic!("MissingClockAuthorityProjection: clock_authority_projection")
            }
        }
    }
}

#[test]
fn canonical_layouts_round_trip_and_distinguish_absence() {
    let cases = [
        (
            projection(None, None),
            vec![1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0, 0],
        ),
        (
            projection(None, Some(-2)),
            vec![
                1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFE,
            ],
        ),
        (projection(Some(named_hold()), None), {
            let mut wire = vec![1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 1];
            wire.extend_from_slice(&9u64.to_be_bytes());
            wire.extend_from_slice(&HOLD_DIGEST);
            wire.push(0);
            wire
        }),
        (projection(Some(named_hold()), Some(i64::MAX)), {
            let mut wire = vec![1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 1];
            wire.extend_from_slice(&9u64.to_be_bytes());
            wire.extend_from_slice(&HOLD_DIGEST);
            wire.push(1);
            wire.extend_from_slice(&i64::MAX.to_be_bytes());
            wire
        }),
    ];
    for (value, wire) in cases {
        assert!(matches!(wire.len(), 11 | 19 | 51 | 59));
        assert_eq!(encode(value), wire);
        assert_eq!(decode(&wire), value);
    }
    assert_ne!(
        encode(projection(None, None)),
        encode(projection(None, Some(0)))
    );
}

#[test]
fn malformed_lengths_tags_and_hold_address_fail_closed() {
    let canonical = [
        encode(projection(None, None)),
        encode(projection(None, Some(-2))),
        encode(projection(Some(named_hold()), None)),
        encode(projection(Some(named_hold()), Some(i64::MAX))),
    ];
    for wire in canonical {
        for length in 0..wire.len() {
            reject(&wire[..length]);
        }
        let mut trailing = wire;
        trailing.push(0);
        reject(&trailing);
    }
    let mut bad_version = encode(projection(None, None));
    bad_version[0] = 2;
    reject(&bad_version);
    let mut bad_hold_tag = encode(projection(None, None));
    bad_hold_tag[9] = 2;
    reject(&bad_hold_tag);
    let mut bad_shutdown_tag = encode(projection(None, None));
    bad_shutdown_tag[10] = 2;
    reject(&bad_shutdown_tag);
    let mut zero_generation = encode(projection(Some(named_hold()), None));
    zero_generation[10..18].fill(0);
    reject(&zero_generation);
    let mut zero_digest = encode(projection(Some(named_hold()), None));
    zero_digest[18..50].fill(0);
    reject(&zero_digest);
    let mut held_short = encode(projection(Some(named_hold()), None));
    held_short.truncate(50);
    reject(&held_short);
}

#[test]
fn boundary_is_private_and_side_effect_free() {
    let source = include_str!("clock_authority_projection.rs");
    for forbidden in [
        "pub fn encode_clock_authority_projection",
        "std::fs",
        "std::net",
        "sqlite",
        "Hmac",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }
    assert!(source.contains("FRONTIER: clock_authority_projection"));
}
