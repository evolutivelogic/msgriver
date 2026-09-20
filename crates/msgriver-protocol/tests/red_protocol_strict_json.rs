//! Frozen strict-JSON RED cases for the shared protocol decoder boundary.
//!
//! These tests describe actual A-07.1 / PR-131 / PR-132 observables.  They do
//! not emulate parsing: every case calls the real protocol seam and fails only
//! at its declared scaffold frontier until an implementation is authorized.

#![forbid(unsafe_code)]

use msgriver_protocol::{JsonFrontier, StrictJsonReject, StrictJsonResult, strict_json_value};
use std::fmt;

#[derive(Debug)]
enum JsonCaseError {
    BehaviorRed {
        case_id: &'static str,
    },
    Mismatch {
        case_id: &'static str,
        detail: String,
    },
}

impl fmt::Display for JsonCaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BehaviorRed { case_id } => write!(
                f,
                "{case_id}: behavior missing — terminated at RED frontier `protocol_strict_json_decode`"
            ),
            Self::Mismatch { case_id, detail } => {
                write!(f, "{case_id}: observable mismatch — {detail}")
            }
        }
    }
}

impl std::error::Error for JsonCaseError {}

fn case(
    case_id: &'static str,
    input: &[u8],
    allowed_fields: &[&str],
    expected: StrictJsonResult,
) -> Result<(), JsonCaseError> {
    match strict_json_value(input, allowed_fields) {
        Ok(actual) if actual == expected => Ok(()),
        Ok(actual) => Err(JsonCaseError::Mismatch {
            case_id,
            detail: format!("expected {expected:?}, got {actual:?}"),
        }),
        Err(error) if error.scaffold_frontier() == Some(JsonFrontier::StrictDecode) => {
            Err(JsonCaseError::BehaviorRed { case_id })
        }
        Err(error) => Err(JsonCaseError::Mismatch {
            case_id,
            detail: format!("unexpected decoder error: {error}"),
        }),
    }
}

fn nested_array(depth: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(depth.saturating_mul(2).saturating_add(1));
    bytes.extend(std::iter::repeat_n(b'[', depth));
    bytes.push(b'0');
    bytes.extend(std::iter::repeat_n(b']', depth));
    bytes
}

#[test]
fn proto_json_accepts_closed_object() -> Result<(), JsonCaseError> {
    case(
        "PROTO-JSON-CLOSED-OBJECT",
        br#"{"title":"backup"}"#,
        &["title"],
        StrictJsonResult::Accepted,
    )
}

#[test]
fn proto_json_rejects_duplicate_member() -> Result<(), JsonCaseError> {
    case(
        "PROTO-JSON-DUPLICATE-MEMBER",
        br#"{"title":"first","title":"second"}"#,
        &["title"],
        StrictJsonResult::Rejected(StrictJsonReject::DuplicateField),
    )
}

#[test]
fn proto_json_rejects_unknown_member() -> Result<(), JsonCaseError> {
    case(
        "PROTO-JSON-UNKNOWN-MEMBER",
        br#"{"title":"backup","extra":true}"#,
        &["title"],
        StrictJsonResult::Rejected(StrictJsonReject::UnknownField),
    )
}

#[test]
fn proto_json_rejects_body_api_version() -> Result<(), JsonCaseError> {
    case(
        "PROTO-JSON-BODY-API-VERSION",
        br#"{"title":"backup","api_version":1}"#,
        &["title"],
        StrictJsonResult::Rejected(StrictJsonReject::UnknownField),
    )
}

#[test]
fn proto_json_rejects_explicit_null() -> Result<(), JsonCaseError> {
    case(
        "PROTO-JSON-EXPLICIT-NULL",
        br#"{"title":null}"#,
        &["title"],
        StrictJsonResult::Rejected(StrictJsonReject::ExplicitNull),
    )
}

#[test]
fn proto_json_accepts_depth_64() -> Result<(), JsonCaseError> {
    let input = nested_array(64);
    case(
        "PROTO-JSON-DEPTH-64",
        &input,
        &[],
        StrictJsonResult::Accepted,
    )
}

#[test]
fn proto_json_rejects_depth_65() -> Result<(), JsonCaseError> {
    let input = nested_array(65);
    case(
        "PROTO-JSON-DEPTH-65",
        &input,
        &[],
        StrictJsonResult::Rejected(StrictJsonReject::Malformed),
    )
}

#[test]
fn proto_json_rejects_invalid_utf8() -> Result<(), JsonCaseError> {
    case(
        "PROTO-JSON-INVALID-UTF8",
        b"{\"title\":\"\xff\"}",
        &["title"],
        StrictJsonResult::Rejected(StrictJsonReject::Malformed),
    )
}
