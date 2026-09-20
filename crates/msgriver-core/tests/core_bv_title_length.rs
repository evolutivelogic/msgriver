//! Additive bounded title-length boundary contract.
//!
//! This target freezes only the inclusive 256-byte default ntfy title boundary
//! over a present ASCII title and valid non-empty text. Other title validity and
//! precedence remains at the bounded-grammar frontier until separately contracted.

#[path = "red_core/harness.rs"]
mod harness;

use harness::{CompareResult, Oracle, TestCaseError, case, decode_hex, outcome};
use msgriver_core::Frontier;

const FRONTIER: Frontier = Frontier::ValidateBoundedGrammar;

const TITLE_256: &str = "df52d78809cf6a2d1d30e16fb967748778d852023986946a421c97ec7134962d";
const TITLE_257: &str = "c07beaf6792dff777e3f1ad942801f2a84a501d1dbee0dd2cac147e1034bafec";

fn text_input(oracle: &Oracle) -> Result<Vec<u8>, TestCaseError> {
    decode_hex(oracle.req("text_hex")?)
}

fn title_input(oracle: &Oracle) -> Result<Option<Vec<u8>>, TestCaseError> {
    oracle.opt("title_hex").map(decode_hex).transpose()
}

fn title_length_case(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
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
fn core_bv_title_length_256() -> Result<(), TestCaseError> {
    case(
        "CORE-BV-TITLE-LENGTH-256",
        "tests/fixtures/oracles/core-bv-title-length/title-256.txt",
        TITLE_256,
        FRONTIER,
        title_length_case,
    )
}

#[test]
fn core_bv_title_length_257() -> Result<(), TestCaseError> {
    case(
        "CORE-BV-TITLE-LENGTH-257",
        "tests/fixtures/oracles/core-bv-title-length/title-257.txt",
        TITLE_257,
        FRONTIER,
        title_length_case,
    )
}
