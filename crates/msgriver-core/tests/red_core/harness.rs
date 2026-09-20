//! Test-only `CaseProbe` substrate for the core RED suite.
//!
//! This module lives outside production code (`src/`) and is compiled only for
//! integration tests. It is stdlib-only: it hand-rolls SHA-256, minimal JSON
//! emission, and a line-oriented oracle parser, and never touches Tokio, HTTP,
//! SQLite, the network, or entropy. Production code never emits or consumes the
//! sidecar protocol.
//!
//! Each atomic case writes exactly one JSONL sidecar enforcing this sequence:
//! exactly one `fixture_validated`, exactly one `action_started`, zero or more
//! declared `frontier_reached`, and exactly one terminal `behavior_red` or
//! `contract_pass`. The [`case`] driver is RED-aware: when the SUT returns a
//! private scaffold gap at the case's registered initial frontier it records the
//! frontier and a `behavior_red` terminal and returns a fallible error; once a
//! later implementation slice removes the gap, the same unchanged case compares
//! the real observable against the frozen oracle and records `contract_pass`.
//!
// This is a shared test-support module: its typed oracle accessors and helpers
// form an intentional API surface used across many generated case kinds, not
// all of which any single case exercises. The freeze gate still denies every
// real lint; this only permits the broad helper inventory test infra exposes.
#![allow(dead_code)]

use msgriver_core::{CoreError, Frontier, RejectClass};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process;

// ---------------------------------------------------------------------------
// SHA-256 (hand-rolled, stdlib only — test evidence, not production code).
// ---------------------------------------------------------------------------

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Compute SHA-256 over `data` and return the 32-byte digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for (i, &k) in SHA256_K.iter().enumerate() {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex encoding of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_DIGITS[(b >> 4) as usize] as char);
        out.push(HEX_DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decode a lowercase/uppercase hex string into bytes.
pub fn decode_hex(s: &str) -> Result<Vec<u8>, TestCaseError> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(TestCaseError::Parse("odd-length hex".into()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi =
            hex_value(bytes[i]).ok_or_else(|| TestCaseError::Parse("invalid hex digit".into()))?;
        let lo = hex_value(bytes[i + 1])
            .ok_or_else(|| TestCaseError::Parse("invalid hex digit".into()))?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Fallible error type (no panic/assert/unwrap in case bodies).
// ---------------------------------------------------------------------------

/// Fallible error returned by every case body. A test returns this to fail; it
/// never panics as a substitute for evidence.
#[derive(Debug)]
pub enum TestCaseError {
    OracleDigestMismatch {
        case_id: String,
        expected: String,
        actual: String,
    },
    Parse(String),
    MissingField(String),
    BehaviorRed {
        case_id: String,
        frontier: &'static str,
    },
    Mismatch {
        case_id: String,
        detail: String,
    },
}

impl fmt::Display for TestCaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OracleDigestMismatch {
                case_id,
                expected,
                actual,
            } => write!(
                f,
                "oracle digest mismatch for {case_id}: expected {expected}, got {actual}"
            ),
            Self::Parse(msg) => write!(f, "oracle parse error: {msg}"),
            Self::MissingField(field) => write!(f, "oracle missing required field `{field}`"),
            Self::BehaviorRed { case_id, frontier } => write!(
                f,
                "{case_id}: behavior missing — terminated at RED frontier `{frontier}`"
            ),
            Self::Mismatch { case_id, detail } => {
                write!(f, "{case_id}: observable mismatch — {detail}")
            }
        }
    }
}

impl std::error::Error for TestCaseError {}

/// The result of comparing the SUT output against the frozen oracle.
#[derive(Debug, Clone)]
pub enum CompareResult {
    /// The real observable matched the oracle exactly (`contract_pass`).
    Pass,
    /// The SUT returned a scaffold gap at `frontier` (`behavior_red`).
    Red(Frontier),
    /// The real observable was present but disagreed with the oracle.
    Mismatch(String),
}

/// Map a typed SUT `Result` into a `CompareResult` uniformly:
///
/// * a scaffold gap becomes [`CompareResult::Red`] (the intended RED terminal);
/// * an inhabited value is handed to `value_matches`, which returns `true` for
///   an exact oracle match (`Pass`); and
/// * a real (gap-free) error is a `Pass` only when the oracle expects a reject
///   whose stable class matches.
///
/// Every case body routes through this so the gap→RED rule is uniform and no
/// path hides a missing behavior. When a later slice removes the gap, the same
/// unchanged case compares the real observable and records `contract_pass`.
pub fn outcome<T>(
    res: Result<T, CoreError>,
    oracle: &Oracle,
    value_matches: impl FnOnce(&T) -> bool,
) -> Result<CompareResult, TestCaseError> {
    match res {
        Ok(value) => {
            if oracle.expect_is("ok") && value_matches(&value) {
                Ok(CompareResult::Pass)
            } else {
                Ok(CompareResult::Mismatch(
                    "observable did not match the oracle".into(),
                ))
            }
        }
        Err(err) => match err.scaffold_frontier() {
            Some(frontier) => Ok(CompareResult::Red(frontier)),
            None => {
                let class_match = oracle
                    .expect_class()
                    .zip(err.reject_class().map(RejectClass::label))
                    .is_some_and(|(expected, actual)| expected == actual);
                if oracle.expect_is("reject") && class_match {
                    Ok(CompareResult::Pass)
                } else {
                    Ok(CompareResult::Mismatch(
                        "real error did not match the expected reject class".into(),
                    ))
                }
            }
        },
    }
}

// ---------------------------------------------------------------------------
// Frozen oracle (line-oriented key/value text, reviewable and bounded).
// ---------------------------------------------------------------------------

/// Parsed frozen oracle: a map from key to raw string value.
pub struct Oracle {
    fields: BTreeMap<String, String>,
}

impl Oracle {
    fn parse(case_id: &str, text: &str) -> Result<Self, TestCaseError> {
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        for raw in text.lines() {
            let line = raw.trim_end_matches('\r').trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once(':')
                .ok_or_else(|| TestCaseError::Parse(format!("malformed oracle line: {line:?}")))?;
            let key = key.trim();
            if key.is_empty() {
                continue;
            }
            fields.insert(key.to_string(), value.trim().to_string());
        }
        let parsed_id = fields
            .get("case_id")
            .ok_or_else(|| TestCaseError::MissingField("case_id".into()))?;
        if parsed_id != case_id {
            return Err(TestCaseError::Parse(format!(
                "oracle case_id `{parsed_id}` does not match expected `{case_id}`"
            )));
        }
        Ok(Self { fields })
    }

    pub fn req(&self, key: &str) -> Result<&str, TestCaseError> {
        self.fields
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| TestCaseError::MissingField(key.to_string()))
    }

    pub fn opt(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }

    pub fn expect_is(&self, value: &str) -> bool {
        self.req("expect").map(|e| e == value).unwrap_or(false)
    }

    pub fn expect_class(&self) -> Option<&str> {
        self.opt("expect_class")
    }

    pub fn i64(&self, key: &str) -> Result<i64, TestCaseError> {
        self.req(key)?
            .parse::<i64>()
            .map_err(|e| TestCaseError::Parse(format!("field `{key}` not i64: {e}")))
    }

    pub fn u64(&self, key: &str) -> Result<u64, TestCaseError> {
        self.req(key)?
            .parse::<u64>()
            .map_err(|e| TestCaseError::Parse(format!("field `{key}` not u64: {e}")))
    }

    pub fn u32(&self, key: &str) -> Result<u32, TestCaseError> {
        self.req(key)?
            .parse::<u32>()
            .map_err(|e| TestCaseError::Parse(format!("field `{key}` not u32: {e}")))
    }

    pub fn u128(&self, key: &str) -> Result<u128, TestCaseError> {
        self.req(key)?
            .parse::<u128>()
            .map_err(|e| TestCaseError::Parse(format!("field `{key}` not u128: {e}")))
    }

    pub fn bool(&self, key: &str) -> Result<bool, TestCaseError> {
        match self.req(key)? {
            "true" => Ok(true),
            "false" => Ok(false),
            other => Err(TestCaseError::Parse(format!(
                "field `{key}` not bool: {other}"
            ))),
        }
    }

    /// Bytes encoded directly as the value's UTF-8.
    pub fn raw_bytes(&self, key: &str) -> Result<&[u8], TestCaseError> {
        Ok(self.req(key)?.as_bytes())
    }

    /// Bytes encoded as hex in the value.
    pub fn hex_bytes(&self, key: &str) -> Result<Vec<u8>, TestCaseError> {
        decode_hex(self.req(key)?)
    }

    /// Comma-separated list of values.
    pub fn list(&self, key: &str) -> Result<Vec<String>, TestCaseError> {
        Ok(self
            .req(key)?
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::trim)
            .map(str::to_string)
            .collect())
    }
}

// ---------------------------------------------------------------------------
// CaseProbe: one JSONL sidecar per case enforcing the ordered protocol.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeState {
    Init,
    FixtureValidated,
    ActionStarted,
    FrontierReached,
    Terminal,
    Violated,
}

/// The harness probe owning one JSONL sidecar and the sequence state machine.
pub struct Probe {
    case_id: String,
    file: Option<File>,
    state: ProbeState,
    seq: u64,
    opened_paths: u32,
    opened_sockets: u32,
    initial_frontier: Frontier,
}

impl Probe {
    /// Open the sidecar for `case_id`. Records the registered initial frontier
    /// so a reached frontier can be checked against it before the terminal.
    pub fn open(case_id: &str, initial_frontier: Frontier) -> Result<Self, TestCaseError> {
        let sidecar = sidecar_path(case_id);
        if let Some(parent) = sidecar.parent() {
            std::fs::create_dir_all(parent).map_err(|e| TestCaseError::Parse(e.to_string()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&sidecar)
            .map_err(|e| TestCaseError::Parse(e.to_string()))?;
        let mut probe = Self {
            case_id: case_id.to_string(),
            file: Some(file),
            state: ProbeState::Init,
            seq: 0,
            opened_paths: 1, // the sidecar itself
            opened_sockets: 0,
            initial_frontier,
        };
        probe.emit_obj(|o| {
            o.push_str("\"event\":\"case_opened\"");
            push_str(o, "case_id", case_id);
            push_str(o, "frontier", initial_frontier.label());
            push_num(o, "pid", process::id() as u64);
        });
        Ok(probe)
    }

    fn emit_obj<F: FnOnce(&mut String)>(&mut self, build: F) {
        let mut obj = String::from("{");
        build(&mut obj);
        obj.push_str(",\"seq\":");
        obj.push_str(&self.seq.to_string());
        self.seq = self.seq.wrapping_add(1);
        obj.push('}');
        obj.push('\n');
        if let Some(file) = self.file.as_mut() {
            let _ = file.write_all(obj.as_bytes());
            let _ = file.flush();
        }
    }

    fn violate(&mut self, detail: &str) {
        self.state = ProbeState::Violated;
        let case_id = self.case_id.clone();
        self.emit_obj(|o| {
            o.push_str("\"event\":\"protocol_violation\"");
            push_str(o, "case_id", &case_id);
            push_str(o, "detail", detail);
        });
    }

    /// Record `fixture_validated`. Exactly once, before any action.
    pub fn fixture_validated(&mut self, oracle_digest: &str, fixture_digest: &str) {
        if self.state != ProbeState::Init {
            self.violate("fixture_validated out of order or duplicate");
            return;
        }
        let case_id = self.case_id.clone();
        self.emit_obj(|o| {
            o.push_str("\"event\":\"fixture_validated\"");
            push_str(o, "case_id", &case_id);
            push_str(o, "oracle_digest", oracle_digest);
            push_str(o, "fixture_digest", fixture_digest);
        });
        self.state = ProbeState::FixtureValidated;
    }

    /// Record a non-fixture validation failure terminal (invalid RED).
    pub fn fixture_failed(&mut self, detail: &str) {
        let case_id = self.case_id.clone();
        self.emit_obj(|o| {
            o.push_str("\"event\":\"fixture_failed\"");
            push_str(o, "case_id", &case_id);
            push_str(o, "detail", detail);
        });
        self.finish_terminal();
    }

    /// Record `action_started`. Exactly once, after fixture validation.
    pub fn action_started(&mut self) {
        if self.state != ProbeState::FixtureValidated {
            self.violate("action_started out of order or duplicate");
            return;
        }
        let case_id = self.case_id.clone();
        self.emit_obj(|o| {
            o.push_str("\"event\":\"action_started\"");
            push_str(o, "case_id", &case_id);
            push_num(o, "pid", process::id() as u64);
        });
        self.state = ProbeState::ActionStarted;
    }

    /// Record a reached `frontier`. Zero or more, after the action and before a
    /// terminal; the frontier must be the case's registered initial frontier.
    pub fn frontier_reached(&mut self, frontier: Frontier) {
        if self.state != ProbeState::ActionStarted && self.state != ProbeState::FrontierReached {
            self.violate("frontier_reached out of order");
            return;
        }
        if frontier != self.initial_frontier {
            self.violate("frontier_reached for an unregistered/unknown frontier");
            return;
        }
        let case_id = self.case_id.clone();
        self.emit_obj(|o| {
            o.push_str("\"event\":\"frontier_reached\"");
            push_str(o, "case_id", &case_id);
            push_str(o, "frontier", frontier.label());
        });
        self.state = ProbeState::FrontierReached;
    }

    /// Record the `behavior_red` terminal (intended missing behavior).
    pub fn behavior_red(&mut self, frontier: Frontier, detail: &str) {
        if self.state == ProbeState::Terminal || self.state == ProbeState::Violated {
            self.violate("duplicate/nonterminal terminal");
            return;
        }
        if self.state != ProbeState::ActionStarted && self.state != ProbeState::FrontierReached {
            self.violate("behavior_red before action_started");
            return;
        }
        let case_id = self.case_id.clone();
        self.emit_obj(|o| {
            o.push_str("\"event\":\"behavior_red\"");
            push_str(o, "case_id", &case_id);
            push_str(o, "frontier", frontier.label());
            push_str(o, "detail", detail);
        });
        self.finish_terminal();
    }

    /// Record the `contract_pass` terminal (observable matched oracle).
    pub fn contract_pass(&mut self) {
        if self.state == ProbeState::Terminal || self.state == ProbeState::Violated {
            self.violate("duplicate/nonterminal terminal");
            return;
        }
        if self.state != ProbeState::ActionStarted && self.state != ProbeState::FrontierReached {
            self.violate("contract_pass before action_started");
            return;
        }
        let case_id = self.case_id.clone();
        self.emit_obj(|o| {
            o.push_str("\"event\":\"contract_pass\"");
            push_str(o, "case_id", &case_id);
        });
        self.finish_terminal();
    }

    fn finish_terminal(&mut self) {
        self.state = ProbeState::Terminal;
        let (paths, sockets, cleanup_ok) = (self.opened_paths, self.opened_sockets, true);
        let case_id = self.case_id.clone();
        self.emit_obj(|o| {
            o.push_str("\"event\":\"cleanup\"");
            push_str(o, "case_id", &case_id);
            push_num(o, "opened_paths", paths as u64);
            push_num(o, "opened_sockets", sockets as u64);
            o.push_str(",\"child_status\":null");
            push_bool(o, "cleanup_ok", cleanup_ok);
        });
        self.file = None; // dropped/closed here
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        if self.state != ProbeState::Terminal && self.state != ProbeState::Violated {
            // The driver always writes a terminal; reaching here means a panic
            // or early abort, which is recorded as invalid evidence.
            self.violate("probe dropped without a terminal event");
            let case_id = self.case_id.clone();
            let (paths, sockets) = (self.opened_paths, self.opened_sockets);
            self.emit_obj(|o| {
                o.push_str("\"event\":\"cleanup\"");
                push_str(o, "case_id", &case_id);
                push_num(o, "opened_paths", paths as u64);
                push_num(o, "opened_sockets", sockets as u64);
                o.push_str(",\"child_status\":null");
                push_bool(o, "cleanup_ok", false);
            });
        }
    }
}

fn push_str(out: &mut String, key: &str, value: &str) {
    out.push_str(",\"");
    out.push_str(key);
    out.push_str("\":\"");
    json_escape_into(out, value);
    out.push('"');
}

fn push_num(out: &mut String, key: &str, value: u64) {
    out.push_str(",\"");
    out.push_str(key);
    out.push_str("\":");
    out.push_str(&value.to_string());
}

fn push_bool(out: &mut String, key: &str, value: bool) {
    out.push_str(",\"");
    out.push_str(key);
    out.push_str("\":");
    out.push_str(if value { "true" } else { "false" });
}

fn json_escape_into(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // crates/msgriver-core -> crates -> workspace root.
    manifest
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn sidecar_path(case_id: &str) -> PathBuf {
    let dir = match std::env::var("MSGRIVER_RED_SIDECAR_DIR") {
        Ok(value) => PathBuf::from(value),
        Err(_) => workspace_root().join("target").join("red-sidecars"),
    };
    dir.join(format!("{}.jsonl", case_id.to_ascii_lowercase()))
}

// ---------------------------------------------------------------------------
// The RED-aware case driver.
// ---------------------------------------------------------------------------

/// Load + validate the oracle, run the case body, and write the terminal.
///
/// `oracle_rel` is relative to the workspace root. `oracle_digest_hex` is the
/// frozen SHA-256 of the oracle file. `initial_frontier` is the case's
/// registered initial scaffold frontier. `body` parses the oracle, calls the
/// typed SUT path, and returns the comparison result.
pub fn case<F>(
    case_id: &str,
    oracle_rel: &str,
    oracle_digest_hex: &str,
    initial_frontier: Frontier,
    body: F,
) -> Result<(), TestCaseError>
where
    F: FnOnce(&Oracle) -> Result<CompareResult, TestCaseError>,
{
    let mut probe = Probe::open(case_id, initial_frontier)?;
    let oracle_path = workspace_root().join(oracle_rel);
    let oracle_bytes = match std::fs::read(&oracle_path) {
        Ok(bytes) => {
            probe.opened_paths = probe.opened_paths.wrapping_add(1);
            bytes
        }
        Err(err) => {
            probe.fixture_failed(&format!("oracle read error: {err}"));
            return Err(TestCaseError::Parse(format!(
                "oracle read error for {case_id}: {err}"
            )));
        }
    };
    let actual_digest = hex(&sha256(&oracle_bytes));
    if actual_digest != oracle_digest_hex {
        probe.fixture_failed("oracle digest mismatch");
        return Err(TestCaseError::OracleDigestMismatch {
            case_id: case_id.to_string(),
            expected: oracle_digest_hex.to_string(),
            actual: actual_digest,
        });
    }
    let oracle = match Oracle::parse(
        case_id,
        std::str::from_utf8(&oracle_bytes)
            .map_err(|e| TestCaseError::Parse(format!("oracle not utf-8: {e}")))?,
    ) {
        Ok(oracle) => oracle,
        Err(err) => {
            probe.fixture_failed(&err.to_string());
            return Err(err);
        }
    };
    probe.fixture_validated(&actual_digest, &actual_digest);
    probe.action_started();
    let result = body(&oracle);
    match result {
        Ok(CompareResult::Pass) => {
            probe.contract_pass();
            Ok(())
        }
        Ok(CompareResult::Red(frontier)) => {
            probe.frontier_reached(frontier);
            probe.behavior_red(frontier, "scaffold gap: behavior not implemented");
            Err(TestCaseError::BehaviorRed {
                case_id: case_id.to_string(),
                frontier: frontier.label(),
            })
        }
        Ok(CompareResult::Mismatch(detail)) => {
            probe.behavior_red(initial_frontier, &format!("observable mismatch: {detail}"));
            Err(TestCaseError::Mismatch {
                case_id: case_id.to_string(),
                detail,
            })
        }
        Err(err) => {
            probe.behavior_red(initial_frontier, &format!("case body error: {err}"));
            Err(err)
        }
    }
}

/// Read a file's bytes relative to the workspace root (used by structural
/// self-tests that compare frozen oracle digests without invoking the SUT).
pub fn read_workspace_relative(rel: &str) -> Result<Vec<u8>, TestCaseError> {
    std::fs::read(workspace_root().join(rel))
        .map_err(|e| TestCaseError::Parse(format!("read {rel}: {e}")))
}
