#[path = "red_core/harness.rs"]
mod harness;

use harness::{CompareResult, Oracle, TestCaseError, case, decode_hex, outcome};
use msgriver_core::Frontier;

const FRONTIER: Frontier = Frontier::ValidateBoundedGrammar;
const NON_ASCII_TITLE: &str = "507e2d263c2aa185a42704ee3cb30d08668272870ac0c0d0c13aaa1543f43707";

fn non_ascii_title_case(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
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
fn core_bv_non_ascii_title_cafe() -> Result<(), TestCaseError> {
    case(
        "CORE-BV-NON-ASCII-TITLE",
        "tests/fixtures/oracles/core-bv-non-ascii-title/non-ascii-title.txt",
        NON_ASCII_TITLE,
        FRONTIER,
        non_ascii_title_case,
    )
}
