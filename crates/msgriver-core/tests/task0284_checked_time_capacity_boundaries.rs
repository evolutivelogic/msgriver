//! Additive PR-149/PR-150 boundary contract, frozen before Task 0284 GREEN.

use msgriver_core::{
    RejectClass,
    math::{checkpoint_capacity_fits, utc_add_millis},
};

#[test]
fn utc_add_is_total_for_representable_positive_and_negative_sums() {
    assert_eq!(utc_add_millis(0, -1), Ok(-1));
    assert_eq!(utc_add_millis(-500, 1_000), Ok(500));

    for (base, delta) in [(i64::MAX, 1), (i64::MIN, -1)] {
        let error = utc_add_millis(base, delta).expect_err("overflow must reject");
        assert_eq!(error.reject_class(), Some(RejectClass::ArithmeticOverflow));
    }
}

#[test]
fn control_checkpoint_accepts_every_non_exceeding_rectangle_and_rejects_each_excess() {
    assert_eq!(checkpoint_capacity_fits(0, 0), Ok(()));
    assert_eq!(checkpoint_capacity_fits(4_177_920, 4_032), Ok(()));

    for (bytes, entries) in [(4_177_921, 0), (0, 4_033)] {
        let error = checkpoint_capacity_fits(bytes, entries).expect_err("excess must reject");
        assert_eq!(error.reject_class(), Some(RejectClass::ControlCapacity));
    }
}
