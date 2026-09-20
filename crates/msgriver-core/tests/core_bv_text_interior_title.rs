#[path = "red_core/harness.rs"]
mod harness;

use harness::{CompareResult, Oracle, TestCaseError, case, decode_hex, outcome};
use msgriver_core::Frontier;

const FRONTIER: Frontier = Frontier::ValidateBoundedGrammar;
const TEXT_INTERIOR_TITLE: &str =
    "dd7c6abefa611c2e84fdb3da508f25e9bb9a1da5bfb8901dba54e6fc2688a597";

fn text_interior_title_case(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let text = decode_hex(oracle.req("text_hex")?)?;
    let title = decode_hex(oracle.req("title_hex")?)?;
    outcome(
        msgriver_core::bounded::check_text_content(
            &text,
            Some(&title),
            oracle.u32("text_limit")?,
            oracle.u32("title_limit")?,
        ),
        oracle,
        |()| true,
    )
}

#[test]
fn core_bv_text_interior_title_hello_note() -> Result<(), TestCaseError> {
    case(
        "CORE-BV-TEXT-INTERIOR-TITLE",
        "tests/fixtures/oracles/core-bv-text-interior-title/text-interior-title.txt",
        TEXT_INTERIOR_TITLE,
        FRONTIER,
        text_interior_title_case,
    )
}
