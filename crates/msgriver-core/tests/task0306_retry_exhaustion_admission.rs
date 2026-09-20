//! Additive A-11.3 retry-exhaustion admission contract, frozen before Task
//! 0306 GREEN.

use msgriver_core::{
    RejectClass,
    retry::{RetryAdmission, retry_admission_v1},
};

#[test]
fn completed_final_attempt_is_exhausted() {
    for (completed_attempt_ordinal, max_attempts) in [(1, 1), (128, 128), (1_024, 1_024)] {
        assert_eq!(
            retry_admission_v1(completed_attempt_ordinal, max_attempts),
            Ok(RetryAdmission::Exhausted)
        );
    }
}

#[test]
fn one_attempt_remaining_stays_eligible_with_exact_retry_index() {
    for (completed_attempt_ordinal, max_attempts, retry_index) in
        [(127, 128, 126), (1_023, 1_024, 1_022)]
    {
        assert_eq!(
            retry_admission_v1(completed_attempt_ordinal, max_attempts),
            Ok(RetryAdmission::Eligible { retry_index })
        );
    }
}

#[test]
fn first_completed_attempt_is_eligible_when_another_remains() {
    assert_eq!(
        retry_admission_v1(1, 2),
        Ok(RetryAdmission::Eligible { retry_index: 0 })
    );
}

#[test]
fn malformed_scalars_reject_without_coercion() {
    for (completed_attempt_ordinal, max_attempts) in [(1, 0), (1, 1_025), (0, 128), (129, 128)] {
        let error = retry_admission_v1(completed_attempt_ordinal, max_attempts)
            .expect_err("out-of-domain scalar");
        assert_eq!(
            error.reject_class(),
            Some(RejectClass::RetryDelayInputInvalid)
        );
    }
}
