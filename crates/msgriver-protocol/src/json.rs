//! Strict JSON lexical preflight for the protocol boundary.
//!
//! A-07.1 requires a single lexical preflight before typed decoding: UTF-8,
//! duplicate/unknown members, explicit null where absence has meaning, and the
//! 64-level structural ceiling all fail before dispatch.  The declarations
//! below reject before typed decoding, routing, dispatch, or storage.

use core::fmt;
use serde::Deserializer as _;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};

const MAX_STRUCTURAL_DEPTH: usize = 64;

/// Observable result of a strict JSON object contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictJsonResult {
    /// The payload is a valid object for the supplied closed field set.
    Accepted,
    /// The payload is rejected before any typed command or store action.
    Rejected(StrictJsonReject),
}

/// Closed pre-dispatch rejection classes for the strict JSON boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictJsonReject {
    Malformed,
    DuplicateField,
    UnknownField,
    ExplicitNull,
}

/// The private authoring seam used to make the initial RED terminal explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum JsonFrontier {
    StrictDecode,
}

impl JsonFrontier {
    #[doc(hidden)]
    pub const fn label(self) -> &'static str {
        "protocol_strict_json_decode"
    }
}

/// Non-stable scaffold error; this is never serialized as an API error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct JsonError {
    frontier: JsonFrontier,
}

impl JsonError {
    #[doc(hidden)]
    pub const fn scaffold_frontier(&self) -> Option<JsonFrontier> {
        Some(self.frontier)
    }
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "protocol JSON scaffold frontier `{}`",
            self.frontier.label()
        )
    }
}

impl std::error::Error for JsonError {}

/// Validate one JSON value before typed command deserialization.
///
/// A nonempty field slice requests closed-object field validation.  An empty
/// slice is the lexical preflight used by compound codec tests, including the
/// depth boundary, before their typed schema is selected.
///
/// This is a lexical boundary only. It validates JSON syntax and the supplied
/// root-object field set but deliberately returns no decoded value, route
/// decision, dispatch, or store action.
pub fn strict_json_value(
    input: &[u8],
    allowed_fields: &[&str],
) -> Result<StrictJsonResult, JsonError> {
    let input = match core::str::from_utf8(input) {
        Ok(input) => input,
        Err(_) => return Ok(StrictJsonResult::Rejected(StrictJsonReject::Malformed)),
    };
    if lexical_depth_is_invalid(input) {
        return Ok(StrictJsonResult::Rejected(StrictJsonReject::Malformed));
    }
    if allowed_fields.is_empty() {
        let mut decoder = serde_json::Deserializer::from_str(input);
        let mut rejection = None;
        let decoded = StrictJsonSeed {
            rejection: &mut rejection,
        }
        .deserialize(&mut decoder)
        .and_then(|_| decoder.end());
        if let Some(rejection) = rejection {
            return Ok(StrictJsonResult::Rejected(rejection));
        }
        return Ok(match decoded {
            Ok(()) => StrictJsonResult::Accepted,
            Err(_) => StrictJsonResult::Rejected(StrictJsonReject::Malformed),
        });
    }

    let mut decoder = serde_json::Deserializer::from_str(input);
    let mut rejection = None;
    let decoded = decoder
        .deserialize_map(ClosedObject {
            allowed_fields,
            rejection: &mut rejection,
        })
        .and_then(|result| decoder.end().map(|()| result));
    if let Some(rejection) = rejection {
        return Ok(StrictJsonResult::Rejected(rejection));
    }
    Ok(match decoded {
        Ok(result) => result,
        Err(_) => StrictJsonResult::Rejected(StrictJsonReject::Malformed),
    })
}

/// A-07.1 caps arrays and objects before serde constructs any typed value.
/// Syntax is still delegated to serde_json below; this pass owns only UTF-8
/// string-awareness, balanced structural delimiters, and the depth ceiling.
fn lexical_depth_is_invalid(input: &str) -> bool {
    let mut nesting = Vec::with_capacity(MAX_STRUCTURAL_DEPTH);
    let mut in_string = false;
    let mut escaped = false;

    for byte in input.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            } else if byte < 0x20 {
                return true;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                nesting.push(byte);
                if nesting.len() > MAX_STRUCTURAL_DEPTH {
                    return true;
                }
            }
            b'}' if nesting.pop() != Some(b'{') => return true,
            b']' if nesting.pop() != Some(b'[') => return true,
            b'}' | b']' => {}
            _ => {}
        }
    }
    in_string || escaped || !nesting.is_empty()
}

struct ClosedObject<'a, 'b> {
    allowed_fields: &'a [&'a str],
    rejection: &'b mut Option<StrictJsonReject>,
}

impl<'de> Visitor<'de> for ClosedObject<'_, '_> {
    type Value = StrictJsonResult;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a closed JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = Vec::new();
        while let Some(field) = map.next_key::<String>()? {
            if seen.iter().any(|previous: &String| previous == &field) {
                *self.rejection = Some(StrictJsonReject::DuplicateField);
                return Err(de::Error::custom("duplicate JSON field"));
            }
            if !self.allowed_fields.contains(&field.as_str()) {
                *self.rejection = Some(StrictJsonReject::UnknownField);
                return Err(de::Error::custom("unknown JSON field"));
            }
            seen.push(field);
            if map
                .next_value_seed(StrictJsonSeed {
                    rejection: &mut *self.rejection,
                })?
                .is_null()
            {
                *self.rejection = Some(StrictJsonReject::ExplicitNull);
                return Err(de::Error::custom("explicit null JSON field"));
            }
        }
        Ok(StrictJsonResult::Accepted)
    }
}

/// A complete JSON value whose deserializer rejects duplicate keys at every
/// object depth. It intentionally retains no parsed data after preflight.
enum StrictJson {
    Null,
    Other,
}

impl StrictJson {
    const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

struct StrictJsonSeed<'a> {
    rejection: &'a mut Option<StrictJsonReject>,
}

impl<'de> DeserializeSeed<'de> for StrictJsonSeed<'_> {
    type Value = StrictJson;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor {
            rejection: self.rejection,
        })
    }
}

struct StrictJsonVisitor<'a> {
    rejection: &'a mut Option<StrictJsonReject>,
}

impl<'de> Visitor<'de> for StrictJsonVisitor<'_> {
    type Value = StrictJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a complete JSON value")
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJson::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJson::Null)
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJson::Other)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJson::Other)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJson::Other)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJson::Other)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJson::Other)
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJson::Other)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(StrictJsonSeed {
                rejection: &mut *self.rejection,
            })?
            .is_some()
        {}
        Ok(StrictJson::Other)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = Vec::new();
        while let Some(field) = map.next_key::<String>()? {
            if seen.iter().any(|previous: &String| previous == &field) {
                *self.rejection = Some(StrictJsonReject::DuplicateField);
                return Err(de::Error::custom("duplicate JSON field"));
            }
            seen.push(field);
            map.next_value_seed(StrictJsonSeed {
                rejection: &mut *self.rejection,
            })?;
        }
        Ok(StrictJson::Other)
    }
}

#[cfg(test)]
mod tests {
    use super::{StrictJsonReject, StrictJsonResult, strict_json_value};

    #[test]
    fn rejects_duplicate_field_nested_under_closed_root() {
        assert_eq!(
            strict_json_value(br#"{"title":{"a":1,"a":2}}"#, &["title"]),
            Ok(StrictJsonResult::Rejected(StrictJsonReject::DuplicateField))
        );
    }

    #[test]
    fn rejects_duplicate_field_during_empty_field_lexical_preflight() {
        assert_eq!(
            strict_json_value(br#"{"a":1,"a":2}"#, &[]),
            Ok(StrictJsonResult::Rejected(StrictJsonReject::DuplicateField))
        );
    }
}
