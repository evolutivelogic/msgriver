//! Additive PR-109 arithmetic coverage beyond the immutable S11 vectors.
//!
//! These values prove the complete pure function, while the historical
//! catalog, ledger and generated RED cases remain byte-identical.

use msgriver_core::{
    RejectClass,
    generation::{increment_generation, split_limbs},
};

#[test]
fn increment_is_checked_for_ordinary_values_and_the_ceiling() {
    assert_eq!(increment_generation(0), Ok(1));
    assert_eq!(increment_generation(41), Ok(42));

    let error = increment_generation(u64::MAX).expect_err("MAX must not wrap");
    assert_eq!(
        error.reject_class(),
        Some(RejectClass::StateGenerationExhausted)
    );
}

#[test]
fn limbs_preserve_the_complete_unsigned_u64_word() {
    assert_eq!(split_limbs(0), Ok((0, 0)));
    assert_eq!(
        split_limbs(0x0123_4567_89ab_cdef),
        Ok((0x0123_4567, 0x89ab_cdef))
    );
}
