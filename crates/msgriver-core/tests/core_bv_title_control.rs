//! Additive bounded title-control contract.
//!
//! This target freezes only the three adjudicated CR, LF, and NUL title controls
//! over valid non-empty text. All other text grammar and precedence remains at the bounded-grammar
//! frontier until separately contracted.

#[path = "red_core/harness.rs"]
mod harness;

use harness::{CompareResult, Oracle, TestCaseError, case, decode_hex, outcome};
use msgriver_core::Frontier;

const FRONTIER: Frontier = Frontier::ValidateBoundedGrammar;

const TITLE_CR: &str = "29bb9c627daa1a330b90f6799a775b8eb315d6dcdc91177f0f8bbc72a8c045f7";
const TITLE_LF: &str = "90c1636609fec0aa75a6b887974032844b4de76848630cdba49ef010bbf4da4a";
const TITLE_NUL: &str = "d2273dadac33773770e1a5efa10e9b4823b31a765e7533da1a661d50f2bd2083";

fn text_input(oracle: &Oracle) -> Result<Vec<u8>, TestCaseError> {
    decode_hex(oracle.req("text_hex")?)
}

fn title_input(oracle: &Oracle) -> Result<Option<Vec<u8>>, TestCaseError> {
    oracle.opt("title_hex").map(decode_hex).transpose()
}

fn title_control_case(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
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
fn core_bv_title_control_cr() -> Result<(), TestCaseError> {
    case(
        "CORE-BV-TITLE-CONTROL-CR",
        "tests/fixtures/oracles/core-bv-title-control/title-cr.txt",
        TITLE_CR,
        FRONTIER,
        title_control_case,
    )
}

#[test]
fn core_bv_title_control_lf() -> Result<(), TestCaseError> {
    case(
        "CORE-BV-TITLE-CONTROL-LF",
        "tests/fixtures/oracles/core-bv-title-control/title-lf.txt",
        TITLE_LF,
        FRONTIER,
        title_control_case,
    )
}

#[test]
fn core_bv_title_control_nul() -> Result<(), TestCaseError> {
    case(
        "CORE-BV-TITLE-CONTROL-NUL",
        "tests/fixtures/oracles/core-bv-title-control/title-nul.txt",
        TITLE_NUL,
        FRONTIER,
        title_control_case,
    )
}
