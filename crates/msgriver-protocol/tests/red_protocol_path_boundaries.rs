//! Additive RED boundaries for source-mandated path-codec grammar.
//!
//! These cases extend the first six path vectors without changing them. They
//! remain local codec observations: no route, authorization, resource lookup,
//! HTTP status or error envelope is selected here.

#![forbid(unsafe_code)]

use msgriver_protocol::{
    CodecId, PathDecodeResult, PathFrontier, PathReject, PathSegment, decode_path_segment,
};
use std::fmt;

#[derive(Debug)]
enum PathBoundaryError {
    BehaviorRed {
        case_id: &'static str,
    },
    Mismatch {
        case_id: &'static str,
        detail: String,
    },
}

impl fmt::Display for PathBoundaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BehaviorRed { case_id } => write!(
                f,
                "{case_id}: behavior missing — terminated at RED frontier `protocol_path_decode`"
            ),
            Self::Mismatch { case_id, detail } => {
                write!(f, "{case_id}: observable mismatch — {detail}")
            }
        }
    }
}

impl std::error::Error for PathBoundaryError {}

fn case(
    case_id: &'static str,
    codec: CodecId,
    segment: &str,
    expected: PathDecodeResult,
) -> Result<(), PathBoundaryError> {
    match decode_path_segment(codec, segment) {
        Ok(actual) if actual == expected => Ok(()),
        Ok(actual) => Err(PathBoundaryError::Mismatch {
            case_id,
            detail: format!("expected {expected:?}, got {actual:?}"),
        }),
        Err(error) if error.scaffold_frontier() == Some(PathFrontier::Decode) => {
            Err(PathBoundaryError::BehaviorRed { case_id })
        }
        Err(error) => Err(PathBoundaryError::Mismatch {
            case_id,
            detail: format!("unexpected path decoder error: {error}"),
        }),
    }
}

fn provider_id_at_length(length: usize) -> String {
    let mut value = String::from("a");
    value.extend(std::iter::repeat_n('z', length.saturating_sub(1)));
    value
}

#[test]
fn proto_path_accepts_one_byte_provider_id() -> Result<(), PathBoundaryError> {
    case(
        "PROTO-PATH-PROVIDER-ID-MIN-BYTES",
        CodecId::PathProviderIdV1,
        "a",
        PathDecodeResult::Accepted(PathSegment::ProviderId("a".to_owned())),
    )
}

#[test]
fn proto_path_accepts_sixty_four_byte_provider_id() -> Result<(), PathBoundaryError> {
    let segment = provider_id_at_length(64);
    case(
        "PROTO-PATH-PROVIDER-ID-MAX-BYTES",
        CodecId::PathProviderIdV1,
        &segment,
        PathDecodeResult::Accepted(PathSegment::ProviderId(segment.clone())),
    )
}

#[test]
fn proto_path_rejects_sixty_five_byte_provider_id() -> Result<(), PathBoundaryError> {
    let segment = provider_id_at_length(65);
    case(
        "PROTO-PATH-PROVIDER-ID-OVERFLOW",
        CodecId::PathProviderIdV1,
        &segment,
        PathDecodeResult::Rejected(PathReject::InvalidProviderId),
    )
}

#[test]
fn proto_path_rejects_noncanonical_base64url_trailing_bits() -> Result<(), PathBoundaryError> {
    case(
        "PROTO-PATH-PROVIDER-SCHEMA-ID-TRAILING-BITS",
        CodecId::PathProviderSchemaIdV1,
        "YR",
        PathDecodeResult::Rejected(PathReject::NonCanonicalBase64Url),
    )
}

#[test]
fn proto_path_rejects_standard_base64_alphabet() -> Result<(), PathBoundaryError> {
    case(
        "PROTO-PATH-PROVIDER-SCHEMA-ID-STANDARD-ALPHABET",
        CodecId::PathProviderSchemaIdV1,
        "+w",
        PathDecodeResult::Rejected(PathReject::NonCanonicalBase64Url),
    )
}

#[test]
fn proto_path_rejects_non_utf8_schema_id() -> Result<(), PathBoundaryError> {
    case(
        "PROTO-PATH-PROVIDER-SCHEMA-ID-INVALID-UTF8",
        CodecId::PathProviderSchemaIdV1,
        "_w",
        PathDecodeResult::Rejected(PathReject::NonCanonicalBase64Url),
    )
}

#[test]
fn proto_path_rejects_non_v7_message_id() -> Result<(), PathBoundaryError> {
    case(
        "PROTO-PATH-MESSAGE-ID-NON-V7",
        CodecId::PathMessageIdV1,
        "0196bfe4-0000-6000-8000-000000000001",
        PathDecodeResult::Rejected(PathReject::InvalidMessageId),
    )
}

#[test]
fn proto_path_rejects_non_rfc4122_variant_message_id() -> Result<(), PathBoundaryError> {
    case(
        "PROTO-PATH-MESSAGE-ID-NON-RFC4122-VARIANT",
        CodecId::PathMessageIdV1,
        "0196bfe4-0000-7000-c000-000000000001",
        PathDecodeResult::Rejected(PathReject::InvalidMessageId),
    )
}
