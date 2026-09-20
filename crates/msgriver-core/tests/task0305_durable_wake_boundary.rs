//! Additive A-11.3 durable wake boundary contract, frozen before Task 0305
//! GREEN.

use msgriver_core::{
    RejectClass,
    retry::{DurableWakeBoundaryV1, DurableWakeBoundaryV1Input, durable_wake_boundary_v1},
};

fn input(
    safe_now_millis: i64,
    retry_ms: u32,
    expires_at_millis: Option<i64>,
    created_at_millis: i64,
    max_delivery_age_ms: u64,
) -> DurableWakeBoundaryV1Input {
    DurableWakeBoundaryV1Input {
        safe_now_millis,
        retry_ms,
        expires_at_millis,
        created_at_millis,
        max_delivery_age_ms,
    }
}

fn boundary(selected_instant_millis: i64, earliest: bool) -> DurableWakeBoundaryV1 {
    DurableWakeBoundaryV1 {
        selected_instant_millis,
        retry_deadline_is_strictly_earliest: earliest,
    }
}

#[test]
fn strictly_earliest_retry_deadline_is_selected() {
    for (request, expected) in [
        (
            input(10_000, 30_000, Some(50_000), 1_000, 90_000),
            boundary(40_000, true),
        ),
        (
            input(10_000, 1, Some(50_000), 1_000, 90_000),
            boundary(10_001, true),
        ),
        (
            input(0, 3_600_000, Some(5_000_000), 0, 2_592_000_000),
            boundary(3_600_000, true),
        ),
    ] {
        assert_eq!(durable_wake_boundary_v1(request), Ok(expected));
    }
}

#[test]
fn terminal_boundaries_independently_win() {
    for (request, expected) in [
        (
            input(10_000, 3_600_000, Some(20_000), 1_000, 90_000),
            boundary(20_000, false),
        ),
        (
            input(10_000, 3_600_000, None, 100, 1_000),
            boundary(1_100, false),
        ),
        (
            input(10_000, 3_600_000, Some(5_000_000), 100, 1_000),
            boundary(1_100, false),
        ),
    ] {
        assert_eq!(durable_wake_boundary_v1(request), Ok(expected));
    }
}

#[test]
fn terminal_equality_is_not_strict_earliest() {
    for (request, expected) in [
        (
            input(10_000, 30_000, Some(40_000), 1_000, 90_000),
            boundary(40_000, false),
        ),
        (
            input(10_000, 30_000, None, 30_000, 10_000),
            boundary(40_000, false),
        ),
        (
            input(10_000, 30_000, Some(40_000), 30_000, 10_000),
            boundary(40_000, false),
        ),
    ] {
        assert_eq!(durable_wake_boundary_v1(request), Ok(expected));
    }
}

#[test]
fn absent_expiry_removes_only_that_boundary() {
    assert_eq!(
        durable_wake_boundary_v1(input(10_000, 30_000, None, 1_000, 90_000)),
        Ok(boundary(40_000, true)),
    );
}

#[test]
fn overflow_of_either_addition_is_a_typed_rejection() {
    for request in [
        input(i64::MAX, 1, Some(5_000), 1_000, 90_000),
        input(0, 1, None, i64::MAX, 2_592_000_000),
    ] {
        let error = durable_wake_boundary_v1(request).expect_err("checked addition overflow");
        assert_eq!(error.reject_class(), Some(RejectClass::ArithmeticOverflow));
    }
}

#[test]
fn closed_scalar_domains_reject_without_coercion() {
    for request in [
        input(10_000, 0, Some(50_000), 1_000, 90_000),
        input(10_000, 3_600_001, Some(50_000), 1_000, 90_000),
        input(10_000, 30_000, Some(50_000), 1_000, 999),
        input(10_000, 30_000, Some(50_000), 1_000, 2_592_000_001),
    ] {
        let error = durable_wake_boundary_v1(request).expect_err("out-of-domain scalar");
        assert_eq!(
            error.reject_class(),
            Some(RejectClass::RetryDelayInputInvalid)
        );
    }
}

#[test]
fn resolved_instants_receive_no_new_validation() {
    assert_eq!(
        durable_wake_boundary_v1(input(-500, 1_000, None, -1_000, 90_000)),
        Ok(boundary(500, true)),
    );
}
