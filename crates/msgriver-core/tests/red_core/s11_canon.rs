use super::harness::{CompareResult, Oracle, TestCaseError, case, hex, outcome, sha256};
use msgriver_core::Frontier;
use msgriver_core::canon::{
    self, CanonicalInput, MacKeyId, MacKeyRef, MacProvider, MacProviderError, MacPurpose, MacTag,
    VersionedTag,
};

const KEY: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
const KEY_ID: [u8; 40] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
];

struct FixedMac;
impl MacProvider for FixedMac {
    fn authenticate(
        &self,
        key: MacKeyRef,
        message: &[u8],
    ) -> Result<VersionedTag, MacProviderError> {
        let mut block = [0u8; 64];
        block[..KEY.len()].copy_from_slice(&KEY);
        let mut inner = Vec::with_capacity(64 + message.len());
        for byte in block {
            inner.push(byte ^ 0x36);
        }
        inner.extend_from_slice(message);
        let inner_hash = sha256(&inner);
        let mut outer = Vec::with_capacity(96);
        for byte in block {
            outer.push(byte ^ 0x5c);
        }
        outer.extend_from_slice(&inner_hash);
        Ok(VersionedTag::new(key, MacTag(sha256(&outer))))
    }
}

fn input(o: &Oracle) -> Result<CanonicalInput, TestCaseError> {
    Ok(CanonicalInput {
        provider: o.req("provider")?.as_bytes().to_vec(),
        destination_kind: o.req("dest_kind")?.as_bytes().to_vec(),
        destination_schema_version: o.u32("dest_schema")?,
        destination_fields: o
            .list("dest_fields")?
            .into_iter()
            .map(String::into_bytes)
            .collect(),
        content_kind: o.req("content_kind")?.as_bytes().to_vec(),
        content_schema_version: o.u32("content_schema")?,
        content_fields: o
            .list("content_fields")?
            .into_iter()
            .map(String::into_bytes)
            .collect(),
        options_kind: Some(o.req("options_kind")?.as_bytes().to_vec()),
        options_schema_version: Some(o.u32("options_schema")?),
        options_fields: o
            .list("options_fields")?
            .into_iter()
            .map(String::into_bytes)
            .collect(),
        options_set_like: o.bool("options_set_like")?,
        expires_at_millis: Some(o.i64("expires")?),
        correlation_id: Some(o.req("correlation")?.as_bytes().to_vec()),
    })
}

fn vectors(o: &Oracle) -> Result<Vec<(&'static str, CanonicalInput)>, TestCaseError> {
    let base = input(o)?;
    let mut topic = base.clone();
    topic.destination_fields = vec![b"alerts2".to_vec()];
    let mut title = base.clone();
    title.content_fields[0] = b"Hi2".to_vec();
    let mut text = base.clone();
    text.content_fields[1] = b"hello2".to_vec();
    let mut priority = base.clone();
    priority.options_fields[0] = b"high".to_vec();
    let mut tags = base.clone();
    tags.options_fields = vec![b"default".to_vec(), b"apple".to_vec(), b"zebra".to_vec()];
    let mut expires = base.clone();
    expires.expires_at_millis = Some(1_700_000_000_001);
    let mut correlation = base.clone();
    correlation.correlation_id = Some(b"corr-2".to_vec());
    let mut equivalent = base;
    equivalent.options_fields = vec![
        b"default".to_vec(),
        b"mango".to_vec(),
        b"apple".to_vec(),
        b"apple".to_vec(),
    ];
    Ok(vec![
        ("base", input(o)?),
        ("topic", topic),
        ("title", title),
        ("text", text),
        ("priority", priority),
        ("tags", tags),
        ("expires", expires),
        ("correlation", correlation),
        ("tags_permuted_duplicate_equivalent", equivalent),
    ])
}

fn canonical_result(o: &Oracle) -> Result<CompareResult, TestCaseError> {
    for (name, candidate) in vectors(o)? {
        let expected = o.req(&format!("{name}_canonical_hex"))?.to_string();
        match outcome(canon::canonical_request_v1(&candidate), o, |bytes| {
            hex(bytes) == expected
        })? {
            CompareResult::Pass => {}
            other => return Ok(other),
        }
    }
    Ok(CompareResult::Pass)
}

fn field_sensitivity(o: &Oracle) -> Result<CompareResult, TestCaseError> {
    match canonical_result(o)? {
        CompareResult::Pass => {}
        other => return Ok(other),
    }
    let key = MacKeyRef::new(
        MacPurpose::IdempotencyFingerprintV1,
        MacKeyId::from_bytes(KEY_ID),
    );
    let provider = FixedMac;
    for (name, candidate) in vectors(o)? {
        let canonical =
            canon::canonical_request_v1(&candidate).map_err(|error| TestCaseError::Mismatch {
                case_id: "CORE-S11-CANON-FIELD-SENSITIVITY".into(),
                detail: format!("canonical result changed after comparison: {error:?}"),
            })?;
        let versioned = canon::semantic_fingerprint_v1_with_provider(&provider, key, &canonical)
            .map_err(|error| TestCaseError::Mismatch {
                case_id: "CORE-S11-CANON-FIELD-SENSITIVITY".into(),
                detail: format!("provider MAC failed: {error:?}"),
            })?;
        if versioned.key() != key
            || hex(&versioned.tag().0) != o.req(&format!("{name}_fingerprint_tag_hex"))?
        {
            return Ok(CompareResult::Mismatch(format!(
                "fingerprint mismatch for {name}"
            )));
        }
    }
    Ok(CompareResult::Pass)
}

fn run(
    id: &str,
    path: &str,
    digest: &str,
    compare: fn(&Oracle) -> Result<CompareResult, TestCaseError>,
) -> Result<(), TestCaseError> {
    case(id, path, digest, Frontier::CanonicalEncode, compare)
}

#[test]
fn core_s11_canon_fidelity() -> Result<(), TestCaseError> {
    run(
        "CORE-S11-CANON-FIDELITY",
        "tests/fixtures/oracles/core/core-s11-canon-fidelity.txt",
        "680abc9d1b90a516a5928d89c28a0e61fdf6dfa531e155296cae8278344ba26b",
        canonical_result,
    )
}

#[test]
fn core_s11_canon_field_sensitivity() -> Result<(), TestCaseError> {
    run(
        "CORE-S11-CANON-FIELD-SENSITIVITY",
        "tests/fixtures/oracles/core/core-s11-canon-field-sensitivity.txt",
        "b88920dce686538440926217ed6bebdb81011b6cc0b78d99757c3c8d750bb309",
        field_sensitivity,
    )
}
