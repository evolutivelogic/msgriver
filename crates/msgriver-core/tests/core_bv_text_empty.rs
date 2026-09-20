//! Additive bounded empty-text contract.
//!
//! This target freezes only the three adjudicated zero-byte text observations.
//! All other text grammar and precedence remains at the bounded-grammar
//! frontier until separately contracted.

#[path = "red_core/harness.rs"]
mod harness;

use harness::{CompareResult, Oracle, TestCaseError, case, decode_hex, outcome};
use msgriver_core::Frontier;

const FRONTIER: Frontier = Frontier::ValidateBoundedGrammar;

const TITLE_ABSENT: &str = "ca01683272e5fb7cefdcb6d8c7620fe066ccb65ff04056989275647e8823ba70";
const TITLE_ASCII: &str = "2880a7a2bcc422dfb22a90e2088364faa02a0a381c26c6158243bf805be30734";
const TITLE_BAD_UTF8: &str = "6f7b40987a7adc8975b92f8cb24aa736ba2537986416acdbdb0cf59f8faad0e3";

fn text_input(oracle: &Oracle) -> Result<Vec<u8>, TestCaseError> {
    decode_hex(oracle.req("text_hex")?)
}

fn title_input(oracle: &Oracle) -> Result<Option<Vec<u8>>, TestCaseError> {
    oracle.opt("title_hex").map(decode_hex).transpose()
}

fn empty_text_case(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
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
fn core_bv_text_empty_title_absent() -> Result<(), TestCaseError> {
    case(
        "CORE-BV-TEXT-EMPTY-TITLE-ABSENT",
        "tests/fixtures/oracles/core-bv-text-empty/title-absent.txt",
        TITLE_ABSENT,
        FRONTIER,
        empty_text_case,
    )
}

#[test]
fn core_bv_text_empty_title_ascii() -> Result<(), TestCaseError> {
    case(
        "CORE-BV-TEXT-EMPTY-TITLE-ASCII",
        "tests/fixtures/oracles/core-bv-text-empty/title-ascii.txt",
        TITLE_ASCII,
        FRONTIER,
        empty_text_case,
    )
}

#[test]
fn core_bv_text_empty_title_bad_utf8() -> Result<(), TestCaseError> {
    case(
        "CORE-BV-TEXT-EMPTY-TITLE-BADUTF8",
        "tests/fixtures/oracles/core-bv-text-empty/title-badutf8.txt",
        TITLE_BAD_UTF8,
        FRONTIER,
        empty_text_case,
    )
}
