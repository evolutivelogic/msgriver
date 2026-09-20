#[path = "red_core/harness.rs"]
mod harness;

use harness::{CompareResult, Oracle, TestCaseError, case, decode_hex, outcome};
use msgriver_core::Frontier;

const FRONTIER: Frontier = Frontier::ValidateBoundedGrammar;
const NORMATIVE_SUBMIT_TITLE: &str =
    "a6c23b8a1f0dd3db47adc9547db474fc8eff0d0ec615a7e1f96f0bfc77b2ed1f";

fn normative_submit_title_case(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
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
fn core_bv_normative_submit_title_backup() -> Result<(), TestCaseError> {
    case(
        "CORE-BV-NORMATIVE-SUBMIT-TITLE",
        "tests/fixtures/oracles/core-bv-normative-submit-title/normative-submit-title.txt",
        NORMATIVE_SUBMIT_TITLE,
        FRONTIER,
        normative_submit_title_case,
    )
}
