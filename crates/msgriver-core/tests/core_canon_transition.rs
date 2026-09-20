//! Canonical-encoding transition contract.
//!
//! Historical canonical RED vectors retain their original framing. This
//! successor freezes the A-04.2 E1 known answer and the ntfy default/tag
//! normalization observation without changing that historical inventory.

#[path = "red_core/harness.rs"]
mod harness;

use harness::{CompareResult, Oracle, TestCaseError, case, hex, outcome};
use msgriver_core::{Frontier, canon::CanonicalInput};

const FRONTIER: Frontier = Frontier::CanonicalEncode;

const REQUEST_V1_KAT: &str = "00077d9abef2c6045cb412b5a21d5acd6cc19623bdaf8267eacf7c9520db4e2e";
const DEFAULTED_TAGS: &str = "4e28d5d643f678278172a2271c81848deef8e23a40ae6f971ddcaab93da4b1d6";

fn base_input() -> CanonicalInput {
    CanonicalInput {
        provider: b"ntfy".to_vec(),
        destination_kind: b"ntfy_topic".to_vec(),
        destination_schema_version: 1,
        destination_fields: vec![b"alerts".to_vec()],
        content_kind: b"text".to_vec(),
        content_schema_version: 1,
        // A single content field is the schema's omitted-title form.
        content_fields: vec![b"hello".to_vec()],
        ..CanonicalInput::default()
    }
}

fn defaulted_tags(fields: &[&[u8]]) -> CanonicalInput {
    CanonicalInput {
        options_kind: Some(b"ntfy".to_vec()),
        options_schema_version: Some(1),
        // The immutable v1 priority default is explicit only in its effective
        // canonical payload. The remaining entries are set-like ntfy tags.
        options_fields: std::iter::once(b"default".as_slice())
            .chain(fields.iter().copied())
            .map(ToOwned::to_owned)
            .collect(),
        options_set_like: true,
        ..base_input()
    }
}

#[test]
fn core_canon_transition_request_v1_kat() -> Result<(), TestCaseError> {
    case(
        "CORE-CANON-TRANSITION-REQUEST-V1-KAT",
        "tests/fixtures/oracles/core-canon-transition/request-v1-kat.txt",
        REQUEST_V1_KAT,
        FRONTIER,
        |oracle: &Oracle| -> Result<CompareResult, TestCaseError> {
            outcome(
                msgriver_core::canon::canonical_request_v1(&base_input()),
                oracle,
                |bytes| {
                    bytes.len() == oracle.u64("expect_len").unwrap_or(0) as usize
                        && hex(bytes) == oracle.req("expect_canonical_hex").unwrap_or("")
                },
            )
        },
    )
}

#[test]
fn core_canon_transition_defaulted_tags() -> Result<(), TestCaseError> {
    case(
        "CORE-CANON-TRANSITION-DEFAULTED-TAGS",
        "tests/fixtures/oracles/core-canon-transition/defaulted-tags.txt",
        DEFAULTED_TAGS,
        FRONTIER,
        |oracle: &Oracle| -> Result<CompareResult, TestCaseError> {
            let permuted = defaulted_tags(&[b"zebra", b"apple", b"mango", b"apple"]);
            let normalized = defaulted_tags(&[b"apple", b"mango", b"zebra"]);
            let pair = msgriver_core::canon::canonical_request_v1(&permuted).and_then(|first| {
                msgriver_core::canon::canonical_request_v1(&normalized)
                    .map(|second| (first, second))
            });
            outcome(pair, oracle, |(first, second)| {
                first == second
                    && second.len() == oracle.u64("expect_len").unwrap_or(0) as usize
                    && hex(second) == oracle.req("expect_canonical_hex").unwrap_or("")
            })
        },
    )
}
