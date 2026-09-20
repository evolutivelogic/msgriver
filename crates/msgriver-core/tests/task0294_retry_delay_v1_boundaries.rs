//! Additive A-11.3 retry-delay contract, frozen before Task 0294 GREEN.

use msgriver_core::{
    RejectClass,
    retry::{RetryDelayV1Input, retry_delay_v1},
};

fn input(
    completed_attempt_ordinal: u16,
    multiplier_milli: u16,
    validated_retry_after_ms: Option<u32>,
) -> RetryDelayV1Input {
    RetryDelayV1Input {
        base_delay_ms: 1_000,
        factor_milli: 2_000,
        max_delay_ms: 900_000,
        completed_attempt_ordinal,
        multiplier_milli,
        validated_retry_after_ms,
    }
}

#[test]
fn published_a11_3_retry_delay_values_are_exact() {
    for (request, expected) in [
        (input(1, 500, None), 500),
        (input(2, 1_000, None), 2_000),
        (input(10, 1_500, None), 768_000),
        (input(11, 1_500, None), 900_000),
        (input(1, 500, Some(3_600_000)), 3_600_000),
    ] {
        assert_eq!(retry_delay_v1(request), Ok(expected));
    }
}

#[test]
fn retry_delay_is_one_based_capped_and_floor_rounded_at_both_steps() {
    let recurrence_floor = RetryDelayV1Input {
        base_delay_ms: 1_500,
        factor_milli: 1_001,
        max_delay_ms: 3_600_000,
        completed_attempt_ordinal: 2,
        multiplier_milli: 1_000,
        validated_retry_after_ms: None,
    };
    let jitter_floor = RetryDelayV1Input {
        base_delay_ms: 1_500,
        factor_milli: 2_000,
        max_delay_ms: 3_600_000,
        completed_attempt_ordinal: 1,
        multiplier_milli: 1_001,
        validated_retry_after_ms: None,
    };
    assert_eq!(retry_delay_v1(recurrence_floor), Ok(1_501));
    assert_eq!(retry_delay_v1(jitter_floor), Ok(1_501));
    assert_eq!(retry_delay_v1(input(11, 500, None)), Ok(450_000));
}

#[test]
fn retry_delay_rejects_every_closed_scalar_domain_edge() {
    let valid = input(1, 1_000, None);
    let cases = [
        RetryDelayV1Input {
            base_delay_ms: 999,
            ..valid
        },
        RetryDelayV1Input {
            base_delay_ms: 3_600_001,
            ..valid
        },
        RetryDelayV1Input {
            factor_milli: 1_000,
            ..valid
        },
        RetryDelayV1Input {
            factor_milli: 16_001,
            ..valid
        },
        RetryDelayV1Input {
            max_delay_ms: 999,
            ..valid
        },
        RetryDelayV1Input {
            max_delay_ms: 3_600_001,
            ..valid
        },
        RetryDelayV1Input {
            completed_attempt_ordinal: 0,
            ..valid
        },
        RetryDelayV1Input {
            completed_attempt_ordinal: 1_024,
            ..valid
        },
        RetryDelayV1Input {
            multiplier_milli: 499,
            ..valid
        },
        RetryDelayV1Input {
            multiplier_milli: 1_501,
            ..valid
        },
        RetryDelayV1Input {
            validated_retry_after_ms: Some(999),
            ..valid
        },
        RetryDelayV1Input {
            validated_retry_after_ms: Some(3_600_001),
            ..valid
        },
    ];
    for request in cases {
        let error = retry_delay_v1(request).expect_err("out-of-domain input must reject");
        assert_eq!(
            error.reject_class(),
            Some(RejectClass::RetryDelayInputInvalid)
        );
    }
}
