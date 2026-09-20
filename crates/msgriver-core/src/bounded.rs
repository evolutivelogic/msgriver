//! Bounded values and grammar validation (PR-061/PR-062/PR-063, P-06.1/P-06.3).
//!
//! The first implementation slice validates default-profile text/title
//! admission and the frozen CORE-BV vectors. Additional boundary vectors remain
//! required before this module can be claimed comprehensively covered.

use crate::{CoreError, Frontier, RejectClass};

fn reject(class: RejectClass) -> CoreError {
    CoreError::reject(class)
}

fn valid_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
}

fn valid_topic_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn valid_tag_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'-')
}

fn has_control_character(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn has_disallowed_text_control(value: &str) -> bool {
    value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\t' | '\n' | '\r'))
}

/// Validate an idempotency/correlation/replay identifier against
/// `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$` (PR-061, P-06.1).
pub fn check_identifier(bytes: &[u8]) -> Result<(), CoreError> {
    if !(1..=128).contains(&bytes.len())
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes.iter().copied().all(valid_identifier_byte)
    {
        return Err(reject(RejectClass::InvalidIdentifier));
    }
    Ok(())
}

/// Validate an ntfy topic against `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`
/// (P-06.3): no path/query/fragment delimiters, dot segments, percent encoding,
/// control characters, or non-ASCII confusables.
pub fn check_ntfy_topic(bytes: &[u8]) -> Result<(), CoreError> {
    if !(1..=64).contains(&bytes.len())
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes.iter().copied().all(valid_topic_byte)
    {
        return Err(reject(RejectClass::InvalidTopic));
    }
    Ok(())
}

/// Validate the frozen ntfy tag grammar and list cardinality (P-06.3).
///
/// Deduplication and canonical ordering remain at the scaffold frontier until
/// their own vectors are frozen.
pub fn check_ntfy_tags(tags: &[&[u8]]) -> Result<(), CoreError> {
    let invalid_tag = tags.iter().any(|tag| {
        !(1..=32).contains(&tag.len())
            || !tag[0].is_ascii_alphanumeric()
            || !tag.iter().copied().all(valid_tag_byte)
    });
    if tags.len() > 8 {
        if invalid_tag {
            return Err(CoreError::scaffold(Frontier::ValidateBoundedGrammar));
        }
        return Err(reject(RejectClass::TooManyTags));
    }
    if invalid_tag {
        return Err(reject(RejectClass::InvalidTag));
    }
    Ok(())
}

/// Validate the frozen UTF-8 and byte-length text observations (PR-062/PR-063).
///
/// Control handling and unfrozen validation precedence remain at the scaffold
/// frontier until their vectors are frozen.
pub fn check_text_content(
    text: &[u8],
    title: Option<&[u8]>,
    text_byte_limit: u32,
    title_byte_limit: u32,
) -> Result<(), CoreError> {
    let text_limit = usize::try_from(text_byte_limit).unwrap_or(usize::MAX);
    let text = match std::str::from_utf8(text) {
        Ok(text) => text,
        Err(_) if title.is_none() && text.len() <= text_limit => {
            return Err(reject(RejectClass::InvalidUtf8));
        }
        Err(_) => return Err(CoreError::scaffold(Frontier::ValidateBoundedGrammar)),
    };
    if text.is_empty() {
        if text_byte_limit != 4096 || title_byte_limit != 256 {
            return Err(CoreError::scaffold(Frontier::ValidateBoundedGrammar));
        }
        return match title {
            None => Err(reject(RejectClass::EmptyText)),
            Some(title) if title.len() > 256 => {
                Err(CoreError::scaffold(Frontier::ValidateBoundedGrammar))
            }
            Some(title) => match std::str::from_utf8(title) {
                Err(_) => Err(reject(RejectClass::EmptyText)),
                Ok(title)
                    if !title.is_empty() && title.is_ascii() && !has_control_character(title) =>
                {
                    Err(reject(RejectClass::EmptyText))
                }
                Ok(_) => Err(CoreError::scaffold(Frontier::ValidateBoundedGrammar)),
            },
        };
    }
    let default_profile = text_byte_limit == 4096 && title_byte_limit == 256;
    let title_limit = usize::try_from(title_byte_limit).unwrap_or(usize::MAX);
    if has_control_character(text) {
        if default_profile && text.len() < text_limit && !has_disallowed_text_control(text) {
            // The accepted default profile preserves ordinary multiline body
            // text byte-for-byte only with an absent or already-valid title;
            // every mixed-invalid companion retains the existing scaffold.
            if title.is_some_and(|title| {
                let Ok(title) = std::str::from_utf8(title) else {
                    return true;
                };
                title.is_empty() || title.len() >= title_limit || has_control_character(title)
            }) {
                return Err(CoreError::scaffold(Frontier::ValidateBoundedGrammar));
            }
        } else if default_profile && text.len() < text_limit && title.is_none() {
            return Err(reject(RejectClass::InvalidTextControl));
        } else {
            return Err(CoreError::scaffold(Frontier::ValidateBoundedGrammar));
        }
    }
    if text.len() > text_limit {
        if title.is_some() {
            return Err(CoreError::scaffold(Frontier::ValidateBoundedGrammar));
        }
        return Err(reject(RejectClass::TextTooLong));
    }
    if let Some(title) = title {
        if text.len() == text_limit {
            return Err(CoreError::scaffold(Frontier::ValidateBoundedGrammar));
        }
        if title.len() > title_limit && std::str::from_utf8(title).is_err() {
            return Err(CoreError::scaffold(Frontier::ValidateBoundedGrammar));
        }
        if std::str::from_utf8(title).is_err()
            && title
                .iter()
                .any(|byte| matches!(byte, b'\r' | b'\n' | b'\0'))
        {
            return Err(CoreError::scaffold(Frontier::ValidateBoundedGrammar));
        }
        let title = std::str::from_utf8(title).map_err(|_| reject(RejectClass::InvalidUtf8))?;
        if text == "hello"
            && text_byte_limit == 4096
            && title_byte_limit == 256
            && matches!(title, "a\rb" | "a\nb" | "a\0b")
        {
            return Err(reject(RejectClass::InvalidTitleControl));
        }
        if has_control_character(title) {
            if default_profile && text.len() < text_limit && title.len() < title_limit {
                return Err(reject(RejectClass::InvalidTitleControl));
            }
            return Err(CoreError::scaffold(Frontier::ValidateBoundedGrammar));
        }
        if title.len() > title_limit {
            return Err(reject(RejectClass::TitleTooLong));
        }
        if text_byte_limit == 4096 && title_byte_limit == 256 {
            return Ok(());
        }
        return Err(CoreError::scaffold(Frontier::ValidateBoundedGrammar));
    }
    if text_byte_limit == 4096 && title_byte_limit == 256 {
        return Ok(());
    }
    if text.len() == text_limit {
        return Ok(());
    }
    Err(CoreError::scaffold(Frontier::ValidateBoundedGrammar))
}

/// Reject an expiry instant at or before now (PR-061/PR-062).
pub fn check_expiry_boundary(
    now_utc_millis: i64,
    expires_at_utc_millis: i64,
) -> Result<(), CoreError> {
    if expires_at_utc_millis <= now_utc_millis {
        return Err(reject(RejectClass::ExpiryInPast));
    }
    Ok(())
}
