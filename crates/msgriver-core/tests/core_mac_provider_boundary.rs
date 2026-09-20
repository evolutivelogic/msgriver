//! MAC-provider boundary transition contract.
//!
//! Historical red-core MAC vectors deliberately retain their old raw-key
//! scaffold signatures. This successor exercises the A-04.2 provider boundary:
//! core frames public inputs and the provider receives only a purpose-qualified
//! key reference plus that framed message.

use std::cell::RefCell;

use msgriver_core::canon::{
    MacKeyId, MacKeyRef, MacProvider, MacProviderError, MacPurpose, MacTag, VersionedTag,
    lookup_digest_v1_with_provider, semantic_fingerprint_v1_with_provider,
};

#[path = "red_core/harness.rs"]
mod harness;

const FINGERPRINT_DOMAIN: &[u8] = b"msgriver-idempotency-fingerprint-v1\0";
const LOOKUP_DOMAIN: &[u8] = b"msgriver-idempotency-lookup-v1\0";

#[derive(Default)]
struct RecordingProvider {
    calls: RefCell<Vec<(MacKeyRef, Vec<u8>)>>,
}

impl MacProvider for RecordingProvider {
    fn authenticate(&self, key: MacKeyRef, input: &[u8]) -> Result<VersionedTag, MacProviderError> {
        self.calls.borrow_mut().push((key, input.to_vec()));
        Ok(VersionedTag::new(key, MacTag([0x5a; 32])))
    }
}

struct MismatchedKeyProvider;

impl MacProvider for MismatchedKeyProvider {
    fn authenticate(
        &self,
        _key: MacKeyRef,
        _input: &[u8],
    ) -> Result<VersionedTag, MacProviderError> {
        Ok(VersionedTag::new(
            MacKeyRef::new(MacPurpose::IdempotencyLookupV1, key_id()),
            MacTag([0; 32]),
        ))
    }
}

/// A test-only provider is the sole place this successor contains the public
/// KAT secrets. Production core sees only its public key reference and input.
struct KatProvider {
    expected: MacKeyRef,
    key: [u8; 32],
}

impl MacProvider for KatProvider {
    fn authenticate(&self, key: MacKeyRef, input: &[u8]) -> Result<VersionedTag, MacProviderError> {
        if key != self.expected {
            return Err(MacProviderError::Unavailable);
        }
        Ok(VersionedTag::new(
            key,
            MacTag(hmac_sha256(&self.key, input)),
        ))
    }
}

fn hmac_sha256(key: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = inner_pad.to_vec();
    inner.extend_from_slice(input);
    let inner_hash = harness::sha256(&inner);
    let mut outer = outer_pad.to_vec();
    outer.extend_from_slice(&inner_hash);
    harness::sha256(&outer)
}

fn key_id() -> MacKeyId {
    MacKeyId::from_bytes([
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 0,
        0, 0, 0, 7,
    ])
}

fn canonical_request_v1_kat() -> Vec<u8> {
    msgriver_core::canon::canonical_request_v1(&msgriver_core::canon::CanonicalInput {
        provider: b"ntfy".to_vec(),
        destination_kind: b"ntfy_topic".to_vec(),
        destination_schema_version: 1,
        destination_fields: vec![b"alerts".to_vec()],
        content_kind: b"text".to_vec(),
        content_schema_version: 1,
        content_fields: vec![b"hello".to_vec()],
        ..Default::default()
    })
    .unwrap()
}

#[test]
fn core_mac_provider_frames_fingerprint_without_key_material() {
    let provider = RecordingProvider::default();
    let key = MacKeyRef::new(MacPurpose::IdempotencyFingerprintV1, key_id());
    let canonical = [0xde, 0xad, 0xbe, 0xef];

    let result = semantic_fingerprint_v1_with_provider(&provider, key, &canonical).unwrap();

    assert_eq!(result.key(), key);
    assert_eq!(result.tag(), MacTag([0x5a; 32]));
    let calls = provider.calls.into_inner();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, key);
    let mut expected = FINGERPRINT_DOMAIN.to_vec();
    expected.extend_from_slice(key.key_id().as_bytes());
    expected.extend_from_slice(&(canonical.len() as u32).to_be_bytes());
    expected.extend_from_slice(&canonical);
    assert_eq!(calls[0].1, expected);
}

#[test]
fn core_mac_provider_frames_lookup_under_its_distinct_purpose() {
    let provider = RecordingProvider::default();
    let key = MacKeyRef::new(MacPurpose::IdempotencyLookupV1, key_id());

    let result =
        lookup_digest_v1_with_provider(&provider, key, b"principal-1", b"request-1").unwrap();

    assert_eq!(result.key(), key);
    let calls = provider.calls.into_inner();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, key);
    let mut expected = LOOKUP_DOMAIN.to_vec();
    expected.extend_from_slice(key.key_id().as_bytes());
    for value in [b"principal-1".as_slice(), b"request-1"] {
        expected.extend_from_slice(&(value.len() as u32).to_be_bytes());
        expected.extend_from_slice(value);
    }
    assert_eq!(calls[0].1, expected);
}

#[test]
fn core_mac_provider_rejects_cross_purpose_calls_before_provider_resolution() {
    let provider = RecordingProvider::default();
    let key = MacKeyRef::new(MacPurpose::IdempotencyLookupV1, key_id());

    let error = semantic_fingerprint_v1_with_provider(&provider, key, b"canonical").unwrap_err();

    assert_eq!(error, MacProviderError::PurposeMismatch);
    assert!(provider.calls.into_inner().is_empty());
}

#[test]
fn core_mac_provider_rejects_a_provider_tag_for_a_different_public_key() {
    let key = MacKeyRef::new(MacPurpose::IdempotencyFingerprintV1, key_id());

    let error = semantic_fingerprint_v1_with_provider(&MismatchedKeyProvider, key, b"canonical")
        .unwrap_err();

    assert_eq!(error, MacProviderError::ReturnedMismatchedKey);
}

#[test]
fn core_mac_provider_reproduces_the_published_a042_known_answers() {
    let fingerprint_key = MacKeyRef::new(MacPurpose::IdempotencyFingerprintV1, key_id());
    let fingerprint_provider = KatProvider {
        expected: fingerprint_key,
        key: std::array::from_fn(|index| index as u8),
    };
    let canonical = canonical_request_v1_kat();
    assert_eq!(canonical.len(), 222);
    let fingerprint =
        semantic_fingerprint_v1_with_provider(&fingerprint_provider, fingerprint_key, &canonical)
            .unwrap();
    assert_eq!(
        harness::hex(&fingerprint.tag().0),
        "0f53ea3942cc0a3844cfcb6d1c6e70a67332dbca1681369ec38fa867d4a43988"
    );

    let lookup_key = MacKeyRef::new(MacPurpose::IdempotencyLookupV1, key_id());
    let lookup_provider = KatProvider {
        expected: lookup_key,
        key: std::array::from_fn(|index| 0x20 + index as u8),
    };
    let lookup =
        lookup_digest_v1_with_provider(&lookup_provider, lookup_key, b"principal-1", b"request-1")
            .unwrap();
    assert_eq!(
        harness::hex(&lookup.tag().0),
        "0a81d319e0d706a7ac0f0db3aa062f3f4e81f4ab18e577f144d1d153215eb989"
    );
}
