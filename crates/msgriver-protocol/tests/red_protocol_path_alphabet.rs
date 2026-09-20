//! Isolated valid-UTF-8 standard-base64 alphabet RED vector.
//!
//! This corrective vector is separate from the frozen boundary suite: it
//! proves that rejecting `+` is required even when decoding would yield valid
//! UTF-8, as A-06.2 requires canonical unpadded base64url.

#![forbid(unsafe_code)]

use msgriver_protocol::{CodecId, PathDecodeResult, PathFrontier, PathReject, decode_path_segment};
use std::fmt;

#[derive(Debug)]
enum PathAlphabetError {
    BehaviorRed { case_id: &'static str },
    Mismatch(String),
}

impl fmt::Display for PathAlphabetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BehaviorRed { case_id } => write!(
                f,
                "{case_id}: behavior missing — terminated at RED frontier `protocol_path_decode`"
            ),
            Self::Mismatch(detail) => write!(f, "path alphabet observable mismatch — {detail}"),
        }
    }
}

impl std::error::Error for PathAlphabetError {}

#[test]
fn proto_path_rejects_standard_alphabet_with_valid_utf8() -> Result<(), PathAlphabetError> {
    let expected = PathDecodeResult::Rejected(PathReject::NonCanonicalBase64Url);
    match decode_path_segment(CodecId::PathProviderSchemaIdV1, "4KC+") {
        Ok(actual) if actual == expected => Ok(()),
        Ok(actual) => Err(PathAlphabetError::Mismatch(format!(
            "expected {expected:?}, got {actual:?}"
        ))),
        Err(error) if error.scaffold_frontier() == Some(PathFrontier::Decode) => {
            Err(PathAlphabetError::BehaviorRed {
                case_id: "PROTO-PATH-PROVIDER-SCHEMA-ID-VALID-UTF8-STANDARD-ALPHABET",
            })
        }
        Err(error) => Err(PathAlphabetError::Mismatch(format!(
            "unexpected path decoder error: {error}"
        ))),
    }
}
