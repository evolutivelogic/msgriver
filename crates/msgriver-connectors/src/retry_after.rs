//! Connector-boundary `Retry-After` parsing and clamping (PR-084, A-11.3).
//!
//! The seam accepts already-extracted header text and an already-validated UTC
//! instant in epoch milliseconds, and yields only the clamped
//! `1_000..=3_600_000` millisecond delay or `None` for ignored input. Core
//! receives the resulting scalar, never raw header bytes; no clock, network,
//! provider, driver, or metrics capability reaches this boundary.

use core::fmt;

/// The private frontier retained for frozen connectors RED provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum ConnectorsFrontier {
    ParseRetryAfter,
}

impl ConnectorsFrontier {
    #[doc(hidden)]
    pub const fn label(self) -> &'static str {
        "connectors_retry_after_parse"
    }
}

/// Non-stable crate-local connectors error; it is never an HTTP or CLI error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum ConnectorsError {
    /// Retired scaffold frontier, retained as frozen RED provenance.
    Scaffold { frontier: ConnectorsFrontier },
}

impl ConnectorsError {
    #[doc(hidden)]
    pub const fn scaffold_frontier(&self) -> Option<ConnectorsFrontier> {
        match self {
            Self::Scaffold { frontier } => Some(*frontier),
        }
    }
}

impl fmt::Display for ConnectorsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scaffold { frontier } => {
                write!(f, "connectors scaffold frontier `{}`", frontier.label())
            }
        }
    }
}

impl std::error::Error for ConnectorsError {}

/// Parse one provider `Retry-After` header value against an already-validated
/// UTC instant, returning the clamped `1_000..=3_600_000` millisecond delay or
/// `None` for ignored input (PR-084, A-11.3).
///
/// Only an ASCII decimal delta-seconds value or a strict IMF-fixdate in GMT
/// is accepted; malformed text, past or equal dates, and checked i64
/// millisecond overflow are ignored, never clamped.
pub fn parse_retry_after(
    header_value: &str,
    safe_now_millis: i64,
) -> Result<Option<u32>, ConnectorsError> {
    // Delta-seconds parse only as strict ASCII decimals; every other shape is
    // retried as a strict IMF-fixdate before being ignored.
    let millis =
        delta_millis(header_value).or_else(|| future_date_millis(header_value, safe_now_millis));
    // The clamp range fits u32, so the cast cannot truncate.
    Ok(millis.map(|delay| delay.clamp(1_000, 3_600_000) as u32))
}

/// Decimal delta-seconds under checked i64 millisecond arithmetic; an
/// unrepresentable value is ignored, not clamped.
fn delta_millis(header: &str) -> Option<i64> {
    digits_value(header.as_bytes())?.checked_mul(1_000)
}

/// Strict IMF-fixdate `day-name "," SP date1 SP time-of-day SP "GMT"` only
/// (RFC 7231): obsolete forms and non-GMT zones are malformed. The result is
/// the strictly future millisecond delta; past, equal, or overflowing inputs
/// are ignored.
fn future_date_millis(header: &str, safe_now_millis: i64) -> Option<i64> {
    let bytes = header.as_bytes();
    if bytes.len() != 29 || &bytes[3..5] != b", " {
        return None;
    }
    let weekday = weekday_index(&bytes[..3])?;
    let day = digits_value(&bytes[5..7])?;
    let month = month_number(&bytes[8..11])?;
    let year = digits_value(&bytes[12..16])?;
    let hour = digits_value(&bytes[17..19])?;
    let minute = digits_value(&bytes[20..22])?;
    let second = digits_value(&bytes[23..25])?;
    if bytes[7] != b' ' || bytes[11] != b' ' || bytes[16] != b' ' {
        return None;
    }
    if bytes[19] != b':' || bytes[22] != b':' || bytes[25] != b' ' || &bytes[26..] != b"GMT" {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 || day > days_in_month(year, month) || day == 0 {
        return None;
    }
    epoch_millis(year, month, day, hour, minute, second, weekday)?
        .checked_sub(safe_now_millis)
        .filter(|delta| *delta > 0)
}

/// Value of a non-empty run of ASCII decimal digits under checked i64
/// accumulation; any other byte or an unrepresentable value is `None`.
fn digits_value(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() || !bytes.iter().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    bytes.iter().try_fold(0_i64, |value, byte| {
        let digit = i64::from(*byte - b'0');
        value.checked_mul(10)?.checked_add(digit)
    })
}

fn weekday_index(bytes: &[u8]) -> Option<i64> {
    match bytes {
        b"Mon" => Some(0),
        b"Tue" => Some(1),
        b"Wed" => Some(2),
        b"Thu" => Some(3),
        b"Fri" => Some(4),
        b"Sat" => Some(5),
        b"Sun" => Some(6),
        _ => None,
    }
}

fn month_number(bytes: &[u8]) -> Option<i64> {
    match bytes {
        b"Jan" => Some(1),
        b"Feb" => Some(2),
        b"Mar" => Some(3),
        b"Apr" => Some(4),
        b"May" => Some(5),
        b"Jun" => Some(6),
        b"Jul" => Some(7),
        b"Aug" => Some(8),
        b"Sep" => Some(9),
        b"Oct" => Some(10),
        b"Nov" => Some(11),
        b"Dec" => Some(12),
        _ => None,
    }
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Epoch milliseconds of a proleptic Gregorian date-time under checked i64
/// arithmetic. Days from civil follow the March-based era formulation so leap
/// days fall at the end of the computational year.
fn epoch_millis(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
    expected_weekday: i64,
) -> Option<i64> {
    let y = year - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let year_of_era = y - era * 400;
    let month_from_march = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    if (days + 3).rem_euclid(7) != expected_weekday {
        return None;
    }
    days.checked_mul(86_400)?
        .checked_add(hour * 3_600 + minute * 60 + second)?
        .checked_mul(1_000)
}
