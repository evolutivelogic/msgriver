//! Additive connector Retry-After parse and clamp contract, frozen before
//! Task 0307 GREEN.

use msgriver_connectors::retry_after::parse_retry_after;

/// 1994-11-06T08:49:37Z, the fixed validated instant for the frozen vectors.
const SAFE_NOW_MILLIS: i64 = 784_111_777_000;

#[test]
fn delta_zero_clamps_to_one_second() {
    assert_eq!(parse_retry_after("0", SAFE_NOW_MILLIS), Ok(Some(1_000)));
}

#[test]
fn in_range_delta_passes_through_unclamped() {
    for (header, expected) in [
        ("1", 1_000),
        ("5", 5_000),
        ("1800", 1_800_000),
        ("3600", 3_600_000),
    ] {
        assert_eq!(
            parse_retry_after(header, SAFE_NOW_MILLIS),
            Ok(Some(expected))
        );
    }
}

#[test]
fn above_ceiling_delta_clamps_to_one_hour() {
    for header in ["3601", "86400", "999999999"] {
        assert_eq!(
            parse_retry_after(header, SAFE_NOW_MILLIS),
            Ok(Some(3_600_000))
        );
    }
}

#[test]
fn checked_overflow_delta_is_ignored_not_clamped() {
    // i64::MAX seconds overflow the checked i64 millisecond conversion.
    assert_eq!(
        parse_retry_after("9223372036854775807", SAFE_NOW_MILLIS),
        Ok(None)
    );
}

#[test]
fn malformed_delta_text_is_ignored() {
    for header in ["", "+5", "-5", " 5", "5 ", "1 0", "five", "5s"] {
        assert_eq!(
            parse_retry_after(header, SAFE_NOW_MILLIS),
            Ok(None),
            "header {header:?} must be ignored"
        );
    }
}

#[test]
fn future_date_under_a_second_clamps_to_one_second() {
    // The instant carries 500 ms, so 08:49:38 is only 500 ms in the future.
    assert_eq!(
        parse_retry_after("Sun, 06 Nov 1994 08:49:38 GMT", 784_111_777_500),
        Ok(Some(1_000))
    );
}

#[test]
fn future_date_under_an_hour_is_exact() {
    for (header, expected) in [
        ("Sun, 06 Nov 1994 09:19:36 GMT", 1_799_000),
        ("Sun, 06 Nov 1994 09:19:37 GMT", 1_800_000),
    ] {
        assert_eq!(
            parse_retry_after(header, SAFE_NOW_MILLIS),
            Ok(Some(expected))
        );
    }
}

#[test]
fn future_date_at_or_over_an_hour_clamps_to_one_hour() {
    for header in [
        "Sun, 06 Nov 1994 09:49:37 GMT",
        "Sun, 06 Nov 1994 09:49:38 GMT",
        "Mon, 07 Nov 1994 08:49:37 GMT",
        "Tue, 19 Jan 2038 03:14:07 GMT",
    ] {
        assert_eq!(
            parse_retry_after(header, SAFE_NOW_MILLIS),
            Ok(Some(3_600_000))
        );
    }
}

#[test]
fn past_or_equal_dates_are_ignored() {
    assert_eq!(
        parse_retry_after("Sun, 06 Nov 1994 08:49:36 GMT", SAFE_NOW_MILLIS),
        Ok(None)
    );
    assert_eq!(
        parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", SAFE_NOW_MILLIS),
        Ok(None)
    );
}

#[test]
fn obsolete_or_non_gmt_dates_are_ignored() {
    for header in [
        "Sunday, 06-Nov-94 08:49:37 GMT",
        "Sun Nov  6 08:49:37 1994",
        "Sun, 06 Nov 1994 08:49:37 EST",
        "Sun, 06 Nov 1994 08:49:37 UTC",
    ] {
        assert_eq!(
            parse_retry_after(header, SAFE_NOW_MILLIS),
            Ok(None),
            "header {header:?} must be ignored"
        );
    }
}

#[test]
fn malformed_dates_are_ignored() {
    for header in [
        "Sun, 6 Nov 1994 08:49:37 GMT",
        "Sun, 06 Nov 1994 8:49:37 GMT",
        "Sun, 06 Nov 1994 08:49:37",
        "Sun, 06 Nov 1994 08:49:37 GMTx",
        "Sun, 06 Xyz 1994 08:49:37 GMT",
        "not-a-date",
    ] {
        assert_eq!(
            parse_retry_after(header, SAFE_NOW_MILLIS),
            Ok(None),
            "header {header:?} must be ignored"
        );
    }
}

#[test]
fn checked_date_overflow_is_ignored_not_clamped() {
    // The checked i64 millisecond subtraction from i64::MIN overflows.
    assert_eq!(
        parse_retry_after("Fri, 31 Dec 9999 23:59:59 GMT", i64::MIN),
        Ok(None)
    );
}
