use super::{JitterSourceOutcome, JitterSourceRequest, derive_retry_jitter};
use hmac::{Hmac, Mac};
use msgriver_core::canon::{
    MacKeyId, MacKeyRef, MacProvider, MacProviderError, MacPurpose, MacTag, VersionedTag,
};
use sha2::Sha256;
use std::cell::{Cell, RefCell};

const K1: [u8; 32] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
];
const K2: [u8; 32] = [
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
];

struct HmacProvider([u8; 32]);

struct RecordingHmacProvider {
    key: [u8; 32],
    counters: RefCell<Vec<u8>>,
}

struct UnavailableProvider;

struct CountingUnavailableProvider {
    calls: Cell<u16>,
}

struct RejectingProvider {
    counters: RefCell<Vec<u8>>,
}

impl MacProvider for HmacProvider {
    fn authenticate(&self, key: MacKeyRef, input: &[u8]) -> Result<VersionedTag, MacProviderError> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.0).map_err(|_| MacProviderError::Unavailable)?;
        mac.update(input);
        let tag: [u8; 32] = mac.finalize().into_bytes().into();
        Ok(VersionedTag::new(key, MacTag(tag)))
    }
}

impl MacProvider for RecordingHmacProvider {
    fn authenticate(&self, key: MacKeyRef, input: &[u8]) -> Result<VersionedTag, MacProviderError> {
        self.counters
            .borrow_mut()
            .push(*input.last().expect("jitter frame always has a counter"));
        HmacProvider(self.key).authenticate(key, input)
    }
}

impl MacProvider for UnavailableProvider {
    fn authenticate(
        &self,
        _key: MacKeyRef,
        _input: &[u8],
    ) -> Result<VersionedTag, MacProviderError> {
        Err(MacProviderError::Unavailable)
    }
}

impl MacProvider for CountingUnavailableProvider {
    fn authenticate(
        &self,
        _key: MacKeyRef,
        _input: &[u8],
    ) -> Result<VersionedTag, MacProviderError> {
        self.calls.set(self.calls.get() + 1);
        Err(MacProviderError::Unavailable)
    }
}

impl MacProvider for RejectingProvider {
    fn authenticate(&self, key: MacKeyRef, input: &[u8]) -> Result<VersionedTag, MacProviderError> {
        self.counters
            .borrow_mut()
            .push(*input.last().expect("jitter frame always has a counter"));
        Ok(VersionedTag::new(key, MacTag([0xff; 32])))
    }
}

fn request(serial: u64, message_id: [u8; 16], ordinal: u16) -> JitterSourceRequest {
    let mut key_id = [0u8; 40];
    key_id[..24].copy_from_slice(&[
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    ]);
    key_id[24..32].copy_from_slice(&42u64.to_be_bytes());
    key_id[32..].copy_from_slice(&serial.to_be_bytes());
    JitterSourceRequest {
        derivation_version: 1,
        key_reference: MacKeyRef::new(MacPurpose::RetryJitterV1, MacKeyId::from_bytes(key_id)),
        message_id,
        completed_attempt_ordinal: ordinal,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn framed_input(request: JitterSourceRequest, counter: u8) -> Vec<u8> {
    let mut input = b"msgriver/retry-jitter/v1\0".to_vec();
    input.extend_from_slice(request.key_reference.key_id().as_bytes());
    input.extend_from_slice(&request.message_id);
    input.extend_from_slice(&request.completed_attempt_ordinal.to_be_bytes());
    input.push(counter);
    input
}

#[test]
fn retry_jitter_kat_one_is_frozen_before_port_implementation() {
    let request = request(
        7,
        [0x01, 0x90, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1],
        1,
    );
    let input = framed_input(request, 0);
    let tag = HmacProvider(K1)
        .authenticate(request.key_reference, &input)
        .expect("fixture HMAC provider is available");
    assert_eq!(
        tag.tag().0,
        [
            0x50, 0x93, 0x14, 0x8a, 0x0e, 0xb5, 0xe7, 0x35, 0x3a, 0xcb, 0xb6, 0x85, 0x9c, 0x9c,
            0xb7, 0x98, 0xfd, 0x71, 0xda, 0x15, 0xda, 0x91, 0x48, 0x96, 0xbf, 0x6c, 0xe8, 0xc4,
            0xf1, 0x0d, 0x73, 0x1f,
        ]
    );
    assert_ne!(
        HmacProvider(K2)
            .authenticate(request.key_reference, &input)
            .expect("second fixture HMAC provider is available")
            .tag()
            .0,
        tag.tag().0,
        "distinct fixture keys must not collapse under the same framed input"
    );
    assert_eq!(
        derive_retry_jitter(&HmacProvider(K1), request),
        Ok(JitterSourceOutcome::MultiplierMilli(1365))
    );
}

#[test]
fn retry_jitter_remaining_published_kats_are_frozen() {
    for (key, serial, message_id, ordinal, expected, multiplier) in [
        (
            K1,
            7,
            [0x01, 0x90, 0, 0, 0, 2, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 3],
            1023,
            "d3880aebf1690b8b202a007d6ce80a4ed8799e6e7098341ecf57ef79ea108562",
            1405,
        ),
        (
            K2,
            8,
            [0x01, 0x90, 0, 0, 0, 3, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 4],
            2,
            "6c246cda865baef045b8d070ebeb4f67b1a2d005e5cb619eba479c8fcd7959cb",
            1477,
        ),
        (
            K1,
            8,
            [0x01, 0x90, 0, 0, 0, 4, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 5],
            2,
            "5c4490d2c25f99ea630b88a65ba58c14b26c89870fb33fd345f0344ce5d752f2",
            1444,
        ),
    ] {
        let request = request(serial, message_id, ordinal);
        let input = framed_input(request, 0);
        let provider = HmacProvider(key);
        let tag = provider
            .authenticate(request.key_reference, &input)
            .expect("fixture HMAC provider is available");
        assert_eq!(hex(&tag.tag().0), expected);
        assert_eq!(
            derive_retry_jitter(&provider, request),
            Ok(JitterSourceOutcome::MultiplierMilli(multiplier))
        );
    }
}

#[test]
fn retry_jitter_rejection_sequence_freezes_counter_zero_then_one() {
    let request = request(
        7,
        [
            0x01, 0x90, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0x02, 0xfd, 0x1a, 0x63,
        ],
        1,
    );
    let fixture_provider = HmacProvider(K1);
    let zero = fixture_provider
        .authenticate(request.key_reference, &framed_input(request, 0))
        .expect("fixture HMAC provider is available");
    let one = fixture_provider
        .authenticate(request.key_reference, &framed_input(request, 1))
        .expect("fixture HMAC provider is available");
    assert_eq!(
        hex(&zero.tag().0),
        "ffffff100c8540ac168988ff13a791471f00bfe0fa8a1cc1c0182f7dcd6a1db3"
    );
    assert_eq!(
        hex(&one.tag().0),
        "2d122372a06ab9a8ff3eb7b3e96e81cc23e6a50f8a1c1705c487c72281fc0bc9"
    );
    assert!(u32::from_be_bytes(zero.tag().0[..4].try_into().expect("tag prefix")) >= 0xffff_fd94);
    assert_eq!(
        u32::from_be_bytes(one.tag().0[..4].try_into().expect("tag prefix")) % 1001 + 500,
        534
    );
    let source_provider = RecordingHmacProvider {
        key: K1,
        counters: RefCell::new(Vec::new()),
    };
    assert_eq!(
        derive_retry_jitter(&source_provider, request),
        Ok(JitterSourceOutcome::MultiplierMilli(534))
    );
    assert_eq!(
        source_provider.counters.into_inner(),
        vec![0, 1],
        "the rejected counter-zero candidate must be followed by counter one"
    );
}

#[test]
fn retry_jitter_invalid_inputs_fail_before_the_provider() {
    let provider = CountingUnavailableProvider {
        calls: Cell::new(0),
    };
    let valid = request(
        7,
        [0x01, 0x90, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1],
        1,
    );
    let mut invalid_version = valid;
    invalid_version.derivation_version = 2;
    let mut zero_ordinal = valid;
    zero_ordinal.completed_attempt_ordinal = 0;
    let mut ceiling_ordinal = valid;
    ceiling_ordinal.completed_attempt_ordinal = 1024;
    let wrong_purpose = JitterSourceRequest {
        key_reference: MacKeyRef::new(MacPurpose::ReplayLookupV1, valid.key_reference.key_id()),
        ..valid
    };
    let mut non_v7_message = valid;
    non_v7_message.message_id[6] = 0x60;
    for request in [
        invalid_version,
        zero_ordinal,
        ceiling_ordinal,
        wrong_purpose,
        non_v7_message,
    ] {
        assert_eq!(
            derive_retry_jitter(&provider, request),
            Ok(JitterSourceOutcome::InvalidDerivation)
        );
    }
    assert_eq!(
        provider.calls.get(),
        0,
        "invalid requests must not reach the provider"
    );
}

#[test]
fn retry_jitter_provider_unavailable_has_no_fallback() {
    let request = request(
        7,
        [0x01, 0x90, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1],
        1,
    );
    assert_eq!(
        derive_retry_jitter(&UnavailableProvider, request),
        Ok(JitterSourceOutcome::Unavailable)
    );
}

#[test]
fn retry_jitter_rejection_exhaustion_is_bounded_and_ordered() {
    let provider = RejectingProvider {
        counters: RefCell::new(Vec::new()),
    };
    let request = request(
        7,
        [0x01, 0x90, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1],
        1,
    );
    assert_eq!(
        derive_retry_jitter(&provider, request),
        Ok(JitterSourceOutcome::Unavailable)
    );
    assert_eq!(
        provider.counters.into_inner(),
        (0..=u8::MAX).collect::<Vec<_>>(),
        "the bounded source must make every candidate exactly once, in order"
    );
}

#[test]
fn retry_jitter_port_returns_the_closed_typed_result() {
    assert_eq!(
        derive_retry_jitter(
            &HmacProvider(K1),
            request(
                7,
                [0x01, 0x90, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1],
                1,
            ),
        ),
        Ok(JitterSourceOutcome::MultiplierMilli(1365))
    );
}

#[test]
fn retry_jitter_outcome_stays_closed_and_keyless() {
    let source = include_str!("jitter_source.rs");
    let _ = JitterSourceOutcome::InvalidDerivation;
    let _ = JitterSourceOutcome::Unavailable;
    for forbidden in ["[u8; 32]", "Hmac<", "hmac::", "sha2::"] {
        assert!(
            !source.contains(forbidden),
            "forbidden source capability: {forbidden}"
        );
    }
}
