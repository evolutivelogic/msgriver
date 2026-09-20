//! Additive bounded-value edge contract.
//!
//! This target deliberately leaves the original 50-case RED inventory and its
//! promotion gate unchanged. It shares the frozen sidecar protocol while
//! pinning five independently reviewable edge fixtures.

#[path = "red_core/harness.rs"]
mod harness;

use harness::{CompareResult, Oracle, TestCaseError, case, decode_hex, outcome};
use msgriver_core::Frontier;

const FRONTIER: Frontier = Frontier::ValidateBoundedGrammar;

const TAGS_VALID8_MAX32: &str = "e8150bc2c039ce21be185da33308d070792f2b595fd3ca703c854b15b3ec243b";
const TAGS_INVALID: &str = "64387341fe07491a282ec78f32ac1f56a8f26dfdfd459eb9fb4d064b057b050f";
const TEXT_VALID4096_UTF8: &str =
    "d36d6c7d52fff1220d8f8c5701e6c9b400fc396ac4920f321469af88759abd0a";
const TEXT_LIMIT4097: &str = "e7efa29c3e09e8bd71584cb1a83f8913970b51326ac280405fe4bcc8d588df31";
const TITLE_BADUTF8: &str = "cf5070c7b5baee588583f0599a568990c2b67904d9f01405c1b891a09a9acc43";

fn tags_valid(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let tags = oracle.list("tags")?;
    let refs: Vec<&[u8]> = tags.iter().map(String::as_bytes).collect();
    outcome(
        msgriver_core::bounded::check_ntfy_tags(&refs),
        oracle,
        |()| true,
    )
}

fn tags_invalid(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let tag = decode_hex(oracle.req("tag_hex")?)?;
    outcome(
        msgriver_core::bounded::check_ntfy_tags(&[&tag]),
        oracle,
        |()| true,
    )
}

fn repeated_hex(oracle: &Oracle, prefix: &str) -> Result<Vec<u8>, TestCaseError> {
    let unit = decode_hex(oracle.req(&format!("{prefix}_unit_hex"))?)?;
    let repeat = oracle.u32(&format!("{prefix}_repeat"))?;
    let mut out = Vec::with_capacity(unit.len().saturating_mul(repeat as usize));
    for _ in 0..repeat {
        out.extend_from_slice(&unit);
    }
    Ok(out)
}

fn text_input(oracle: &Oracle) -> Result<Vec<u8>, TestCaseError> {
    repeated_hex(oracle, "text")
}

fn title_input(oracle: &Oracle) -> Result<Option<Vec<u8>>, TestCaseError> {
    oracle.opt("title_hex").map(decode_hex).transpose()
}

fn text_case(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let text = text_input(oracle)?;
    let title = title_input(oracle)?;
    outcome(
        msgriver_core::bounded::check_text_content(
            &text,
            title.as_deref(),
            oracle.u32("text_limit")?,
            oracle.u32("title_limit")?,
        ),
        oracle,
        |()| true,
    )
}

#[test]
fn core_bv_edge_tags_valid8_max32() -> Result<(), TestCaseError> {
    case(
        "CORE-BV-EDGE-TAGS-VALID8-MAX32",
        "tests/fixtures/oracles/core-bv-edges/tags-valid8-max32.txt",
        TAGS_VALID8_MAX32,
        FRONTIER,
        tags_valid,
    )
}

#[test]
fn core_bv_edge_tags_invalid() -> Result<(), TestCaseError> {
    case(
        "CORE-BV-EDGE-TAGS-INVALID",
        "tests/fixtures/oracles/core-bv-edges/tags-invalid.txt",
        TAGS_INVALID,
        FRONTIER,
        tags_invalid,
    )
}

#[test]
fn core_bv_edge_text_valid4096_utf8() -> Result<(), TestCaseError> {
    case(
        "CORE-BV-EDGE-TEXT-VALID4096-UTF8",
        "tests/fixtures/oracles/core-bv-edges/text-valid4096-utf8.txt",
        TEXT_VALID4096_UTF8,
        FRONTIER,
        text_case,
    )
}

#[test]
fn core_bv_edge_text_limit4097() -> Result<(), TestCaseError> {
    case(
        "CORE-BV-EDGE-TEXT-LIMIT4097",
        "tests/fixtures/oracles/core-bv-edges/text-limit4097.txt",
        TEXT_LIMIT4097,
        FRONTIER,
        text_case,
    )
}

#[test]
fn core_bv_edge_title_badutf8() -> Result<(), TestCaseError> {
    case(
        "CORE-BV-EDGE-TITLE-BADUTF8",
        "tests/fixtures/oracles/core-bv-edges/title-badutf8.txt",
        TITLE_BADUTF8,
        FRONTIER,
        text_case,
    )
}
