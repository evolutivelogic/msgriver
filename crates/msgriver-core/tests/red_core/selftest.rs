//! Structural self-tests for the core RED harness.
//!
//! These PASS at RED (unlike the behavior cases). They prove the harness
//! substrate is correct and independent of MsgRiver production code: the
//! hand-rolled SHA-256 matches published known-answer vectors, the `CaseProbe`
//! sidecar protocol enforces its ordered sequence and rejects out-of-order or
//! duplicate events and unregistered frontiers, and the harness digest of a
//! frozen oracle matches an independently computed value.

use crate::harness::{Probe, hex, read_workspace_relative, sha256, sidecar_path};
use msgriver_core::Frontier;
use std::fs;

const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const BV_ID_EMPTY_DIGEST: &str = "cfa78ebea7ae777e9abc2f3592c4146342796978b81ab189e50d5d314021a598";

#[test]
fn harness_sha256_empty_known_answer() {
    assert_eq!(hex(&sha256(b"")), SHA256_EMPTY);
}

#[test]
fn harness_sha256_abc_known_answer() {
    assert_eq!(hex(&sha256(b"abc")), SHA256_ABC);
}

#[test]
fn harness_oracle_digest_independent() {
    let bytes = read_workspace_relative("tests/fixtures/oracles/core/core-bv-id-empty.txt")
        .expect("oracle readable");
    assert_eq!(hex(&sha256(&bytes)), BV_ID_EMPTY_DIGEST);
}

#[test]
fn harness_probe_valid_sequence() {
    let case_id = "SELFTEST-VALID-SEQUENCE";
    let mut probe = Probe::open(case_id, Frontier::ValidateBoundedGrammar).expect("probe open");
    probe.fixture_validated("d0d0", "d0d0");
    probe.action_started();
    probe.frontier_reached(Frontier::ValidateBoundedGrammar);
    probe.behavior_red(Frontier::ValidateBoundedGrammar, "synthetic");
    drop(probe);
    let sidecar = fs::read_to_string(sidecar_path(case_id)).expect("sidecar readable");
    let events: Vec<&str> = sidecar
        .lines()
        .filter_map(|line| line.split('"').nth(3))
        .collect();
    assert_eq!(
        events,
        vec![
            "case_opened",
            "fixture_validated",
            "action_started",
            "frontier_reached",
            "behavior_red",
            "cleanup",
        ]
    );
    assert!(sidecar.contains("\"opened_paths\":1"));
    assert!(sidecar.contains("\"opened_sockets\":0"));
    assert!(sidecar.contains("\"cleanup_ok\":true"));
}

#[test]
fn harness_probe_rejects_duplicate_fixture() {
    let case_id = "SELFTEST-DUP-FIXTURE";
    let mut probe = Probe::open(case_id, Frontier::CheckedArithmetic).expect("probe open");
    probe.fixture_validated("d1d1", "d1d1");
    probe.fixture_validated("d1d1", "d1d1");
    drop(probe);
    let sidecar = fs::read_to_string(sidecar_path(case_id)).expect("sidecar readable");
    assert!(
        sidecar.contains("\"event\":\"protocol_violation\""),
        "duplicate fixture_validated must record a protocol violation: {sidecar}"
    );
}

#[test]
fn harness_probe_rejects_unknown_frontier() {
    let case_id = "SELFTEST-UNKNOWN-FRONTIER";
    let mut probe = Probe::open(case_id, Frontier::CheckedArithmetic).expect("probe open");
    probe.fixture_validated("d2d2", "d2d2");
    probe.action_started();
    probe.frontier_reached(Frontier::CanonicalEncode);
    drop(probe);
    let sidecar = fs::read_to_string(sidecar_path(case_id)).expect("sidecar readable");
    assert!(
        sidecar.contains("\"event\":\"protocol_violation\""),
        "unregistered frontier must record a protocol violation: {sidecar}"
    );
}
