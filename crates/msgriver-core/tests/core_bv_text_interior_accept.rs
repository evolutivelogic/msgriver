//! Additive bounded interior text-acceptance contract.
//!
//! This target freezes one ordinary, title-less ntfy text acceptance. All other
//! interior forms and precedence remain at the bounded-grammar frontier.

#[path = "red_core/harness.rs"]
mod harness;

use harness::{CompareResult, Oracle, TestCaseError, case, decode_hex, outcome};
use msgriver_core::Frontier;

const FRONTIER: Frontier = Frontier::ValidateBoundedGrammar;
const TEXT_INTERIOR: &str = "392c44feb78f2cf6910ebb12455bfdfb48914d940d6fe83b6b06e12031e90c43";

fn text_interior_accept_case(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let text = decode_hex(oracle.req("text_hex")?)?;
    outcome(
        msgriver_core::bounded::check_text_content(
            &text,
            None,
            oracle.u32("text_limit")?,
            oracle.u32("title_limit")?,
        ),
        oracle,
        |()| true,
    )
}

#[test]
fn core_bv_text_interior_accept_hello() -> Result<(), TestCaseError> {
    case(
        "CORE-BV-TEXT-INTERIOR-ACCEPT",
        "tests/fixtures/oracles/core-bv-text-interior-accept/text-interior.txt",
        TEXT_INTERIOR,
        FRONTIER,
        text_interior_accept_case,
    )
}
