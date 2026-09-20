//! Frozen RED cases for the locally complete protocol path codecs.
//!
//! These cases cover only grammar and canonical spelling from A-04.1, A-06.1
//! and A-06.2.  They deliberately do not decide routing, authorization,
//! resource existence, HTTP status or error-envelope behavior.

#![forbid(unsafe_code)]

use msgriver_protocol::{
    CodecId, PathDecodeResult, PathFrontier, PathReject, PathSegment, decode_path_segment,
};
use std::fmt;

#[derive(Debug)]
enum PathCaseError {
    BehaviorRed {
        case_id: &'static str,
    },
    Mismatch {
        case_id: &'static str,
        detail: String,
    },
}

impl fmt::Display for PathCaseError {
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

impl std::error::Error for PathCaseError {}

fn case(
    case_id: &'static str,
    codec: CodecId,
    segment: &str,
    expected: PathDecodeResult,
) -> Result<(), PathCaseError> {
    match decode_path_segment(codec, segment) {
        Ok(actual) if actual == expected => Ok(()),
        Ok(actual) => Err(PathCaseError::Mismatch {
            case_id,
            detail: format!("expected {expected:?}, got {actual:?}"),
        }),
        Err(error) if error.scaffold_frontier() == Some(PathFrontier::Decode) => {
            Err(PathCaseError::BehaviorRed { case_id })
        }
        Err(error) => Err(PathCaseError::Mismatch {
            case_id,
            detail: format!("unexpected path decoder error: {error}"),
        }),
    }
}

#[test]
fn proto_path_accepts_canonical_provider_id() -> Result<(), PathCaseError> {
    case(
        "PROTO-PATH-PROVIDER-ID-CANONICAL",
        CodecId::PathProviderIdV1,
        "ops-ntfy",
        PathDecodeResult::Accepted(PathSegment::ProviderId("ops-ntfy".to_owned())),
    )
}

#[test]
fn proto_path_rejects_noncanonical_provider_id() -> Result<(), PathCaseError> {
    case(
        "PROTO-PATH-PROVIDER-ID-UPPERCASE",
        CodecId::PathProviderIdV1,
        "Ops-ntfy",
        PathDecodeResult::Rejected(PathReject::InvalidProviderId),
    )
}

#[test]
fn proto_path_accepts_canonical_provider_schema_id() -> Result<(), PathCaseError> {
    case(
        "PROTO-PATH-PROVIDER-SCHEMA-ID-CANONICAL",
        CodecId::PathProviderSchemaIdV1,
        "bXNncml2ZXI6Ly9zY2hlbWEvdGV4dC8x",
        PathDecodeResult::Accepted(PathSegment::ProviderSchemaId(
            "msgriver://schema/text/1".to_owned(),
        )),
    )
}

#[test]
fn proto_path_rejects_padded_provider_schema_id() -> Result<(), PathCaseError> {
    case(
        "PROTO-PATH-PROVIDER-SCHEMA-ID-PADDING",
        CodecId::PathProviderSchemaIdV1,
        "bXNncml2ZXI6Ly9zY2hlbWEvdGV4dC8x=",
        PathDecodeResult::Rejected(PathReject::NonCanonicalBase64Url),
    )
}

#[test]
fn proto_path_accepts_canonical_message_id() -> Result<(), PathCaseError> {
    case(
        "PROTO-PATH-MESSAGE-ID-CANONICAL",
        CodecId::PathMessageIdV1,
        "0196bfe4-0000-7000-8000-000000000001",
        PathDecodeResult::Accepted(PathSegment::MessageId(
            "0196bfe4-0000-7000-8000-000000000001".to_owned(),
        )),
    )
}

#[test]
fn proto_path_rejects_noncanonical_message_id() -> Result<(), PathCaseError> {
    case(
        "PROTO-PATH-MESSAGE-ID-UPPERCASE",
        CodecId::PathMessageIdV1,
        "0196BFE4-0000-7000-8000-000000000001",
        PathDecodeResult::Rejected(PathReject::InvalidMessageId),
    )
}
