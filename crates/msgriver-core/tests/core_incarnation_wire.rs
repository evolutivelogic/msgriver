//! Resource-incarnation wire transition contract.
//!
//! The historical red-core vector remains immutable. This additive target
//! replays only its one PR-109 serialization observable without promoting
//! allocation, validation, or any other incarnation behavior.

#[path = "red_core/harness.rs"]
mod harness;

use harness::{CompareResult, Oracle, TestCaseError, case, outcome};
use msgriver_core::Frontier;

const FRONTIER: Frontier = Frontier::IncarnationAlloc;

#[test]
fn core_incarnation_wire() -> Result<(), TestCaseError> {
    case(
        "CORE-INCARN-WIRE",
        "tests/fixtures/oracles/core/core-incarn-wire.txt",
        "25b579b983fc0e0cd93794def20993f17ad35c6a689f2fdad8d0bf4a4066da5d",
        FRONTIER,
        |oracle: &Oracle| -> Result<CompareResult, TestCaseError> {
            let namespace = oracle.hex_bytes("namespace_hex")?;
            let mut root = [0_u8; 24];
            root.copy_from_slice(&namespace);
            outcome(
                msgriver_core::generation::incarnation_wire(&root, oracle.u64("serial")?),
                oracle,
                |wire| wire.as_str() == oracle.req("expect_wire").unwrap_or(""),
            )
        },
    )
}
