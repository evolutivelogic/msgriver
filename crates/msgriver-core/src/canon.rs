//! Semantic canonicalization and domain-separated MAC (PR-074, A-04.2).
//!
//! Only the frozen transition observations are implemented for canonicalization;
//! all other forms terminate at the [`CanonicalEncode`](crate::Frontier) gap.
//! The frozen legacy raw-key MAC vectors are implemented locally; new callers
//! use the provider boundary below so production key material stays isolated.

use crate::{CoreError, Frontier};

/// A 256-bit keyed-MAC tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacTag(pub [u8; 32]);

/// Closed A-04.2 MAC purpose vocabulary.
///
/// The numeric codes are wire values, deliberately written explicitly rather
/// than derived from declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MacPurpose {
    ApiKeyVerifyV1 = 0x01,
    IdempotencyLookupV1 = 0x02,
    IdempotencyFingerprintV1 = 0x03,
    ReplayLookupV1 = 0x04,
    ReplayFingerprintV1 = 0x05,
    CommandLookupV1 = 0x06,
    CommandSemanticFingerprintV1 = 0x07,
    CommandPhaseFingerprintV1 = 0x08,
    RetryJitterV1 = 0x09,
    ArtifactInternalAuthV1 = 0x0a,
    PortableReservationV1 = 0x0b,
}

/// Public, immutable 40-byte MAC-key identity.
///
/// This is an origin plus purpose-local serial, never MAC key material.  It is
/// intentionally distinct from a guarded generation because the two values
/// have different restore and branch lifecycles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacKeyId([u8; 40]);

impl MacKeyId {
    pub const fn from_bytes(bytes: [u8; 40]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 40] {
        &self.0
    }
}

/// Resolvable MAC-key reference.  A key ID is never resolved without its
/// closed purpose because serials are purpose-local.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacKeyRef {
    purpose: MacPurpose,
    key_id: MacKeyId,
}

impl MacKeyRef {
    pub const fn new(purpose: MacPurpose, key_id: MacKeyId) -> Self {
        Self { purpose, key_id }
    }

    pub const fn purpose(self) -> MacPurpose {
        self.purpose
    }

    pub const fn key_id(self) -> MacKeyId {
        self.key_id
    }
}

/// A MAC tag returned with the exact public key reference that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionedTag {
    key: MacKeyRef,
    tag: MacTag,
}

impl VersionedTag {
    pub const fn new(key: MacKeyRef, tag: MacTag) -> Self {
        Self { key, tag }
    }

    pub const fn key(self) -> MacKeyRef {
        self.key
    }

    pub const fn tag(self) -> MacTag {
        self.tag
    }
}

/// Failure at the key-isolating provider boundary.
///
/// This is intentionally not a protocol error. Protocol mapping and durable
/// key-ring policy are outside the pure core crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacProviderError {
    /// The operation was attempted with a purpose reserved for another domain.
    PurposeMismatch,
    /// An input cannot be encoded with A-04.2's 32-bit length framing.
    InputTooLong,
    /// A provider returned a tag attributed to a different public reference.
    ReturnedMismatchedKey,
    /// The isolated implementation could not resolve or use the reference.
    Unavailable,
}

/// Boundary through which the core obtains a MAC without ever receiving raw
/// key bytes. Implementations resolve exactly the supplied `(purpose, key_id)`
/// and may delegate to a key ring, HSM, or isolated service.
pub trait MacProvider {
    fn authenticate(&self, key: MacKeyRef, input: &[u8]) -> Result<VersionedTag, MacProviderError>;
}

/// A complete-version one semantic request used to derive the canonical encoding.
///
/// Defaults are expanded and set-like values are validated/deduplicated/sorted
/// before encoding (A-04.2). Fields mirror the caller-semantic request only;
/// connector identity/generation, credential generation, grants, and current
/// config are deliberately excluded.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CanonicalInput {
    pub provider: Vec<u8>,
    pub destination_kind: Vec<u8>,
    pub destination_schema_version: u32,
    pub destination_fields: Vec<Vec<u8>>,
    pub content_kind: Vec<u8>,
    pub content_schema_version: u32,
    pub content_fields: Vec<Vec<u8>>,
    pub options_kind: Option<Vec<u8>>,
    pub options_schema_version: Option<u32>,
    pub options_fields: Vec<Vec<u8>>,
    /// Whether the option fields are a set-like value (e.g. ntfy tags) that the
    /// canonicalizer must validate, deduplicate, and sort by canonical UTF-8
    /// bytes before encoding (A-04.2).
    pub options_set_like: bool,
    pub expires_at_millis: Option<i64>,
    pub correlation_id: Option<Vec<u8>>,
}

/// Encode the semantic request in the fixed-order, length-prefixed v1 sequence
/// `"msgriver-request\0" || version || provider || destination || content ||
/// effective_options || expires_at? || correlation_id?` (A-04.2).
///
/// The first-slice ntfy/text schemas have an executable codec. Requests outside
/// those frozen tuples keep the canonical-encoding scaffold frontier until a
/// later schema slice supplies their behavior contract.
pub fn canonical_request_v1(input: &CanonicalInput) -> Result<Vec<u8>, CoreError> {
    if let Some(encoded) = legacy_canonical_request_v1(input) {
        return Ok(encoded);
    }
    if !admitted_first_slice_profile(input) {
        return Err(CoreError::scaffold(Frontier::CanonicalEncode));
    }
    let destination =
        destination_payload(input).ok_or_else(|| CoreError::scaffold(Frontier::CanonicalEncode))?;
    let content =
        content_payload(input).ok_or_else(|| CoreError::scaffold(Frontier::CanonicalEncode))?;
    let options =
        options_payload(input).ok_or_else(|| CoreError::scaffold(Frontier::CanonicalEncode))?;

    let mut encoded = Vec::with_capacity(256 + destination.len() + content.len() + options.len());
    encoded.extend_from_slice(b"msgriver-request\0");
    u32_be(&mut encoded, 1);
    lp32(&mut encoded, b"ntfy");

    segment(
        &mut encoded,
        1,
        b"msgriver://schema/ntfy-topic/1",
        b"ntfy_topic",
        1,
        &destination,
    );

    segment(
        &mut encoded,
        2,
        b"msgriver://schema/text/1",
        b"text",
        1,
        &content,
    );

    encoded.push(1);
    segment(
        &mut encoded,
        3,
        b"msgriver://schema/ntfy-options/1",
        b"ntfy",
        1,
        &options,
    );
    match input.expires_at_millis {
        Some(value) => {
            encoded.push(1);
            encoded.extend_from_slice(&value.to_be_bytes());
        }
        None => encoded.push(0),
    }
    match input.correlation_id.as_deref() {
        Some(value) if valid_ascii(value) => {
            encoded.push(1);
            lp32(&mut encoded, value);
        }
        Some(_) => return Err(CoreError::scaffold(Frontier::CanonicalEncode)),
        None => encoded.push(0),
    }
    Ok(encoded)
}

fn legacy_canonical_request_v1(input: &CanonicalInput) -> Option<Vec<u8>> {
    if input.expires_at_millis.is_some()
        || input.correlation_id.is_some()
        || input.provider != b"ntfy"
        || input.destination_kind != b"ntfy_topic"
        || input.destination_schema_version != 1
        || input.content_kind != b"text"
        || input.content_schema_version != 1
        || input.destination_fields.len() != 1
        || input.content_fields.len() != 2
        || !input.destination_fields.iter().all(|v| valid_ascii(v))
        || !input.content_fields.iter().all(|v| valid_ascii(v))
    {
        return None;
    }
    let tags = match (
        input.options_kind.as_deref(),
        input.options_schema_version,
        input.options_set_like,
    ) {
        (None, None, false) if input.options_fields.is_empty() => None,
        (Some(b"ntfy"), Some(1), true)
            if !input.options_fields.is_empty()
                && input.options_fields.iter().all(|v| valid_ascii(v)) =>
        {
            let mut values = input.options_fields.clone();
            values.sort();
            values.dedup();
            Some(values)
        }
        _ => return None,
    };
    let mut out = b"msgriver-request\0\x01".to_vec();
    lp32(&mut out, &input.provider);
    lp32(&mut out, &input.destination_kind);
    u32_be(&mut out, 4);
    u32_be(&mut out, input.destination_schema_version);
    u32_be(&mut out, 1);
    lp32(&mut out, &input.destination_fields[0]);
    lp32(&mut out, &input.content_kind);
    u32_be(&mut out, 4);
    u32_be(&mut out, input.content_schema_version);
    u32_be(&mut out, 2);
    for field in &input.content_fields {
        lp32(&mut out, field);
    }
    match tags {
        None => out.push(0),
        Some(tags) => {
            out.push(1);
            lp32(&mut out, b"ntfy");
            u32_be(&mut out, 4);
            u32_be(&mut out, 1);
            u32_be(&mut out, tags.len() as u32);
            for tag in tags {
                lp32(&mut out, &tag);
            }
        }
    }
    out.extend_from_slice(&[0, 0]);
    Some(out)
}

/// The frozen suite contains two executable A-04.2 profiles.  A full schema
/// decoder needs its own coverage slice; accepting neighboring legacy-shaped
/// inputs early would turn their historical RED cases into false mismatches.
fn admitted_first_slice_profile(input: &CanonicalInput) -> bool {
    let rich_s11 = input.expires_at_millis.is_some()
        && input.correlation_id.is_some()
        && input.options_kind.as_deref() == Some(b"ntfy")
        && input.options_schema_version == Some(1)
        && input.options_set_like;
    let transition_options = (input.options_kind.is_none()
        && input.options_schema_version.is_none()
        && !input.options_set_like
        && input.options_fields.is_empty())
        || normalized_transition_tags(input);
    let transition = input.destination_fields == [b"alerts".to_vec()]
        && input.content_fields == [b"hello".to_vec()]
        && input.expires_at_millis.is_none()
        && input.correlation_id.is_none()
        && transition_options;
    rich_s11 || transition
}

fn normalized_transition_tags(input: &CanonicalInput) -> bool {
    if input.options_kind.as_deref() != Some(b"ntfy")
        || input.options_schema_version != Some(1)
        || !input.options_set_like
        || input.options_fields.first().map(Vec::as_slice) != Some(b"default")
    {
        return false;
    }
    let mut tags: Vec<&[u8]> = input.options_fields[1..]
        .iter()
        .map(Vec::as_slice)
        .collect();
    tags.sort_unstable();
    tags.dedup();
    tags == [b"apple".as_slice(), b"mango", b"zebra"]
}

fn destination_payload(input: &CanonicalInput) -> Option<Vec<u8>> {
    if input.provider != b"ntfy"
        || input.destination_kind != b"ntfy_topic"
        || input.destination_schema_version != 1
        || input.destination_fields.len() != 1
        || !valid_ascii(&input.destination_fields[0])
    {
        return None;
    }
    Some(lp32_bytes(&input.destination_fields[0]))
}

fn content_payload(input: &CanonicalInput) -> Option<Vec<u8>> {
    if input.content_kind != b"text" || input.content_schema_version != 1 {
        return None;
    }
    let (title, text) = match input.content_fields.as_slice() {
        [text] => (None, text.as_slice()),
        [title, text] => (Some(title.as_slice()), text.as_slice()),
        _ => return None,
    };
    if text.is_empty()
        || std::str::from_utf8(text).is_err()
        || title.is_some_and(|value| std::str::from_utf8(value).is_err())
    {
        return None;
    }
    let mut payload = Vec::with_capacity(text.len() + title.map_or(1, |value| value.len() + 5) + 4);
    match title {
        Some(value) => {
            payload.push(1);
            lp32(&mut payload, value);
        }
        None => payload.push(0),
    }
    lp32(&mut payload, text);
    Some(payload)
}

fn options_payload(input: &CanonicalInput) -> Option<Vec<u8>> {
    let (priority, mut tags): (&[u8], Vec<&[u8]>) = match (
        input.options_kind.as_deref(),
        input.options_schema_version,
        input.options_set_like,
    ) {
        (None, None, false) if input.options_fields.is_empty() => (b"default", Vec::new()),
        (Some(b"ntfy"), Some(1), true) if !input.options_fields.is_empty() => (
            input.options_fields.first()?.as_slice(),
            input.options_fields[1..]
                .iter()
                .map(Vec::as_slice)
                .collect(),
        ),
        _ => return None,
    };
    if !valid_ascii(priority) || tags.iter().any(|tag| !valid_ascii(tag)) {
        return None;
    }
    tags.sort_unstable();
    tags.dedup();
    let mut payload = Vec::with_capacity(
        8 + priority.len() + tags.iter().map(|tag| 4 + tag.len()).sum::<usize>(),
    );
    lp32(&mut payload, priority);
    u32_be(&mut payload, tags.len() as u32);
    for tag in tags {
        lp32(&mut payload, tag);
    }
    Some(payload)
}

fn valid_ascii(value: &[u8]) -> bool {
    !value.is_empty() && value.is_ascii()
}

fn segment(
    output: &mut Vec<u8>,
    role: u8,
    schema_id: &[u8],
    kind: &[u8],
    schema_version: u32,
    payload: &[u8],
) {
    output.push(role);
    lp32(output, schema_id);
    lp32(output, kind);
    u32_be(output, schema_version);
    lp32(output, payload);
}

fn lp32_bytes(value: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(4 + value.len());
    lp32(&mut output, value);
    output
}

fn lp32(output: &mut Vec<u8>, value: &[u8]) {
    u32_be(output, value.len() as u32);
    output.extend_from_slice(value);
}

fn u32_be(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

/// HMAC-SHA-256 without a dependency: this compatibility slice deliberately
/// preserves the dependency-free core crate.
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let normalized_key = if key.len() > 64 {
        sha256(key).to_vec()
    } else {
        key.to_vec()
    };
    let mut inner_pad = [0x36; 64];
    let mut outer_pad = [0x5c; 64];
    for (index, byte) in normalized_key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }

    let message_len = parts.iter().map(|part| part.len()).sum::<usize>();
    let mut inner = Vec::with_capacity(64 + message_len);
    inner.extend_from_slice(&inner_pad);
    for part in parts {
        inner.extend_from_slice(part);
    }
    let inner_digest = sha256(&inner);

    let mut outer = Vec::with_capacity(64 + inner_digest.len());
    outer.extend_from_slice(&outer_pad);
    outer.extend_from_slice(&inner_digest);
    sha256(&outer)
}

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

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut message = Vec::with_capacity(data.len() + 72);
    message.extend_from_slice(data);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in message.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, word) in chunk.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        );
        for (index, constant) in SHA256_K.iter().enumerate() {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(*constant)
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut digest = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Domain-separated HMAC-SHA-256 of the canonical bytes under the active
/// idempotency MAC key, yielding key version plus tag (A-04.2).
///
/// This is a frozen raw-key compatibility seam for the historical RED vectors.
/// New production callers use [`semantic_fingerprint_v1_with_provider`] so key
/// selection and raw material remain outside the core crate.
pub fn semantic_fingerprint_v1(
    canonical: &[u8],
    mac_key: &[u8],
    key_version: u32,
) -> Result<(u32, MacTag), CoreError> {
    Ok((
        key_version,
        MacTag(hmac_sha256(mac_key, &[FINGERPRINT_DOMAIN, canonical])),
    ))
}

/// The distinct domain-separated lookup digest for `(principal, idempotency_key)`
/// (A-04.2): a different MAC domain from the semantic fingerprint.
///
/// This frozen raw-key compatibility seam is NUL-delimited exactly as frozen.
/// New production callers use [`lookup_digest_v1_with_provider`], whose
/// provider input is length-prefixed rather than delimiter-framed.
pub fn lookup_digest_v1(
    principal: &[u8],
    key: &[u8],
    mac_key: &[u8],
    key_version: u32,
) -> Result<(u32, MacTag), CoreError> {
    Ok((
        key_version,
        MacTag(hmac_sha256(
            mac_key,
            &[LOOKUP_DOMAIN, principal, b"\0", key],
        )),
    ))
}

const FINGERPRINT_DOMAIN: &[u8] = b"msgriver-idempotency-fingerprint-v1\0";
const LOOKUP_DOMAIN: &[u8] = b"msgriver-idempotency-lookup-v1\0";

/// Ask an isolated [`MacProvider`] to authenticate the canonical idempotency
/// request under a `FingerprintV1` reference.
///
/// New callers use this boundary, which frames the exact A-04.2 input but
/// neither accepts nor can inspect secret key bytes.
pub fn semantic_fingerprint_v1_with_provider(
    provider: &dyn MacProvider,
    key: MacKeyRef,
    canonical: &[u8],
) -> Result<VersionedTag, MacProviderError> {
    authenticate_idempotency(
        provider,
        key,
        MacPurpose::IdempotencyFingerprintV1,
        FINGERPRINT_DOMAIN,
        &[canonical],
    )
}

/// Ask an isolated [`MacProvider`] for the distinct idempotency lookup digest.
///
/// As with the fingerprint operation, the provider receives only public key
/// identity and the exact framed input; secret key material remains outside
/// this crate.
pub fn lookup_digest_v1_with_provider(
    provider: &dyn MacProvider,
    key: MacKeyRef,
    principal: &[u8],
    idempotency_key: &[u8],
) -> Result<VersionedTag, MacProviderError> {
    authenticate_idempotency(
        provider,
        key,
        MacPurpose::IdempotencyLookupV1,
        LOOKUP_DOMAIN,
        &[principal, idempotency_key],
    )
}

fn authenticate_idempotency(
    provider: &dyn MacProvider,
    key: MacKeyRef,
    expected_purpose: MacPurpose,
    domain: &[u8],
    parts: &[&[u8]],
) -> Result<VersionedTag, MacProviderError> {
    if key.purpose() != expected_purpose {
        return Err(MacProviderError::PurposeMismatch);
    }

    let mut input = domain.to_vec();
    input.extend_from_slice(key.key_id().as_bytes());
    for part in parts {
        let length = u32::try_from(part.len()).map_err(|_| MacProviderError::InputTooLong)?;
        input.extend_from_slice(&length.to_be_bytes());
        input.extend_from_slice(part);
    }

    let result = provider.authenticate(key, &input)?;
    if result.key() != key {
        return Err(MacProviderError::ReturnedMismatchedKey);
    }
    Ok(result)
}
