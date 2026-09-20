//! Additive A-09.4 fence and lease contract, frozen before Task 0285 GREEN.

use msgriver_core::{
    RejectClass,
    fence::{FenceArbitration, FenceOutcome, arbitrate_outcome, validate_lease_config},
};

#[test]
fn matching_fence_applies_each_ordinary_outcome_and_stale_nonacks_are_monotonic() {
    for outcome in [
        FenceOutcome::Transient,
        FenceOutcome::Permanent,
        FenceOutcome::Ambiguous,
    ] {
        assert_eq!(
            arbitrate_outcome(9, 77, 9, 77, outcome),
            Ok(FenceArbitration::Applied { outcome })
        );
    }

    assert_eq!(
        arbitrate_outcome(9, 77, 8, 77, FenceOutcome::Permanent),
        Ok(FenceArbitration::Stale {
            ambiguity_orred: false,
            attempt_delta: 0,
        })
    );
    assert_eq!(
        arbitrate_outcome(9, 77, 9, 76, FenceOutcome::Ambiguous),
        Ok(FenceArbitration::Stale {
            ambiguity_orred: true,
            attempt_delta: 0,
        })
    );
}

#[test]
fn lease_requires_a_minimum_margin_and_strictly_exceeds_timeout_plus_margin() {
    assert_eq!(validate_lease_config(10_001, 5_000, 5_000), Ok(()));

    for (lease, timeout, margin) in [(10_000, 5_000, 5_000), (20_000, 15_001, 4_999)] {
        let error =
            validate_lease_config(lease, timeout, margin).expect_err("invalid lease config");
        assert_eq!(error.reject_class(), Some(RejectClass::LeaseConfigInvalid));
    }
}
