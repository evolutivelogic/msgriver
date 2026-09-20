//! Task 0277 GREEN boundary observations (additive, non-contract).
//!
//! This target executes only the two Task 0277 contract boundaries that the
//! frozen RED vectors do not reach: the `u64::MAX` ceiling of
//! `ring::serial_next` and the partial-input scaffolds of
//! `incarnation::readiness_exhaustion_both`. It re-asserts the frozen
//! vectors themselves and the unchanged `readiness_reason` precedence. It
//! receives no coverage credit and never aliases the frozen RED harness.

use msgriver_core::Frontier;
use msgriver_core::incarnation::{ReadinessReason, readiness_exhaustion_both, readiness_reason};
use msgriver_core::ring;

fn scaffold_of(result: Result<impl std::fmt::Debug, msgriver_core::CoreError>) -> Frontier {
    let error = result.expect_err("expected a scaffold gap");
    error
        .scaffold_frontier()
        .unwrap_or_else(|| panic!("expected a scaffold gap, got {error:?}"))
}

#[test]
fn ring_serial_next_frozen_vector_and_representable_successors() {
    assert_eq!(ring::serial_next(41), Ok(42));
    assert_eq!(ring::serial_next(0), Ok(1));
    assert_eq!(ring::serial_next(u64::MAX - 1), Ok(u64::MAX));
}

#[test]
fn readiness_both_exhausted_yields_the_exact_ordered_pair() {
    let expected = (
        ReadinessReason::IncarnationExhausted,
        ReadinessReason::GenerationExhausted,
    );
    assert_eq!(
        readiness_exhaustion_both(u64::MAX, &[u64::MAX]),
        Ok(expected)
    );
    assert_eq!(
        readiness_exhaustion_both(u64::MAX, &[0, u64::MAX, 7]),
        Ok(expected)
    );
}

#[test]
fn readiness_both_exhausted_partial_inputs_retain_scaffold() {
    assert_eq!(
        scaffold_of(readiness_exhaustion_both(u64::MAX, &[0])),
        Frontier::ReadinessReason
    );
    assert_eq!(
        scaffold_of(readiness_exhaustion_both(7, &[u64::MAX])),
        Frontier::ReadinessReason
    );
    assert_eq!(
        scaffold_of(readiness_exhaustion_both(7, &[])),
        Frontier::ReadinessReason
    );
}

#[test]
fn readiness_reason_precedence_is_unchanged() {
    assert_eq!(
        readiness_reason(u64::MAX, &[]),
        Some(ReadinessReason::IncarnationExhausted)
    );
    assert_eq!(
        readiness_reason(0, &[u64::MAX]),
        Some(ReadinessReason::GenerationExhausted)
    );
    assert_eq!(readiness_reason(0, &[1]), None);
}
