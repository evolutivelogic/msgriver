//! Typed path-segment declarations and their local grammar decoder.
//!
//! A-04.1, A-06.1 and A-06.2 fully specify the first three derivable path
//! codecs.  This module owns only their local grammar and canonical spelling;
//! route selection, authorization and resource lookup remain outside this
//! protocol seam.

use core::fmt;

use crate::CodecId;

/// A decoded path value for a path codec whose local grammar is complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSegment {
    ProviderId(String),
    ProviderSchemaId(String),
    MessageId(String),
}

/// Closed local rejection classes for the first derivable path codecs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathReject {
    InvalidProviderId,
    NonCanonicalBase64Url,
    InvalidMessageId,
}

/// Observable local result before any route or resource operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathDecodeResult {
    Accepted(PathSegment),
    Rejected(PathReject),
}

/// The private frontier retained for frozen path RED-suite provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum PathFrontier {
    Decode,
}

impl PathFrontier {
    #[doc(hidden)]
    pub const fn label(self) -> &'static str {
        "protocol_path_decode"
    }
}

/// Non-stable local path error; it is never an HTTP or CLI error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum PathError {
    Scaffold { frontier: PathFrontier },
    UnsupportedCodec { codec: CodecId },
}

impl PathError {
    const fn unsupported(codec: CodecId) -> Self {
        Self::UnsupportedCodec { codec }
    }

    #[doc(hidden)]
    pub const fn scaffold_frontier(&self) -> Option<PathFrontier> {
        match self {
            Self::Scaffold { frontier } => Some(*frontier),
            Self::UnsupportedCodec { .. } => None,
        }
    }

    #[doc(hidden)]
    pub const fn is_unsupported_codec(&self) -> bool {
        matches!(self, Self::UnsupportedCodec { .. })
    }
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scaffold { frontier } => {
                write!(f, "protocol path scaffold frontier `{}`", frontier.label())
            }
            Self::UnsupportedCodec { codec } => {
                write!(
                    f,
                    "codec `{}` is outside the path RED scope",
                    codec.as_str()
                )
            }
        }
    }
}

impl std::error::Error for PathError {}

/// Decode one locally specified path segment without selecting a route,
/// performing a resource lookup, or making an authorization decision.
pub fn decode_path_segment(codec: CodecId, segment: &str) -> Result<PathDecodeResult, PathError> {
    let result = match codec {
        CodecId::PathProviderIdV1 => provider_id(segment),
        CodecId::PathProviderSchemaIdV1 => provider_schema_id(segment),
        CodecId::PathMessageIdV1 => message_id(segment),
        _ => return Err(PathError::unsupported(codec)),
    };
    Ok(result)
}

fn provider_id(segment: &str) -> PathDecodeResult {
    let bytes = segment.as_bytes();
    let valid = (1..=64).contains(&bytes.len())
        && matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes[1..]
            .iter()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'));
    if valid {
        PathDecodeResult::Accepted(PathSegment::ProviderId(segment.to_owned()))
    } else {
        PathDecodeResult::Rejected(PathReject::InvalidProviderId)
    }
}

fn provider_schema_id(segment: &str) -> PathDecodeResult {
    // SIMPLIFICAÇÃO: A-06.2 requires encoded/decoded size bounds but does not
    // specify numeric limits. This local grammar slice therefore cannot infer
    // one; a future bounded-schema contract must add it before promotion.
    let Some(decoded) = decode_base64url(segment) else {
        return PathDecodeResult::Rejected(PathReject::NonCanonicalBase64Url);
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
        return PathDecodeResult::Rejected(PathReject::NonCanonicalBase64Url);
    };
    if encode_base64url(decoded.as_bytes()) != segment {
        return PathDecodeResult::Rejected(PathReject::NonCanonicalBase64Url);
    }
    PathDecodeResult::Accepted(PathSegment::ProviderSchemaId(decoded))
}

fn message_id(segment: &str) -> PathDecodeResult {
    let bytes = segment.as_bytes();
    let valid = bytes.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        && bytes.iter().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index) || matches!(byte, b'0'..=b'9' | b'a'..=b'f')
        })
        && bytes[14] == b'7'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b');
    if valid {
        PathDecodeResult::Accepted(PathSegment::MessageId(segment.to_owned()))
    } else {
        PathDecodeResult::Rejected(PathReject::InvalidMessageId)
    }
}

fn decode_base64url(segment: &str) -> Option<Vec<u8>> {
    let values = segment
        .bytes()
        .map(base64url_value)
        .collect::<Option<Vec<_>>>()?;
    if values.len() % 4 == 1 {
        return None;
    }
    if (values.len() % 4 == 2 && values.last()? & 0x0f != 0)
        || (values.len() % 4 == 3 && values.last()? & 0x03 != 0)
    {
        return None;
    }
    let mut output = Vec::with_capacity(values.len() * 3 / 4);
    for chunk in values.chunks(4) {
        output.push((chunk[0] << 2) | (chunk.get(1).copied().unwrap_or(0) >> 4));
        if chunk.len() > 2 {
            output.push((chunk[1] << 4) | (chunk[2] >> 2));
        }
        if chunk.len() > 3 {
            output.push((chunk[2] << 6) | chunk[3]);
        }
    }
    Some(output)
}

fn base64url_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

fn encode_base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        output.push(ALPHABET[(chunk[0] >> 2) as usize] as char);
        output.push(
            ALPHABET[((chunk[0] & 0x03) << 4 | (chunk.get(1).copied().unwrap_or(0) >> 4)) as usize]
                as char,
        );
        if chunk.len() > 1 {
            output.push(
                ALPHABET
                    [((chunk[1] & 0x0f) << 2 | (chunk.get(2).copied().unwrap_or(0) >> 6)) as usize]
                    as char,
            );
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(chunk[2] & 0x3f) as usize] as char);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_codec_is_not_classified_as_path_red() {
        assert!(matches!(
            decode_path_segment(CodecId::JsonShutdownV1, "ignored"),
            Err(error) if error.is_unsupported_codec() && error.scaffold_frontier().is_none()
        ));
    }
}
