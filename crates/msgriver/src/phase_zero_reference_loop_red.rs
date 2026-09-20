//! Frozen behavior-first RED for the private Phase 0B reference loop.
//!
//! Every case owns raw fixture bytes, typed initial state and a complete safe
//! expected observation. The port receives no case identifier. Its current
//! missing result is deliberately the only RED frontier; replacing it later
//! must make these exact fixtures, not a case lookup, reach their assertions.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::path::{Path, PathBuf};

use crate::phase_zero::reference_loop::{
    AlertCapture, AlertIntent, CandidateKind, DurableState, EventKind, EvidenceEvent, OutboundPin,
    ProviderBinding, ProviderCapture, ProviderOutcomeClass, Receipt, RegisteredTemplate,
    RuntimeError, RuntimeStop, SafeReference, SensitiveReplyState, ServiceWindowDisposition,
    ServiceWindowState, Tombstone, TransactionCheckpoint, V1Fact,
};
use crate::phase_zero::reference_loop_port::{
    CallbackIngress, CallerSuppliedAuthority, DedupKeyGeneration, Header,
    PhaseZeroReferenceLoopError, ProviderFixtureOutcome, QueryParameter,
    ReferenceLoopConfiguration, ReferenceLoopOperation, ReferenceLoopPort, ReferenceLoopRequest,
    ReferenceLoopResponse, RegisteredOutbound, RetentionControl, TemplateSelection, reference_loop,
};
use crate::phase_zero_reference_loop_fixture::FixtureKernel;

const R09_CHILD_TEST: &str =
    "phase_zero_reference_loop_red::phase_zero_reference_loop_r09_child_reopens_durable_checkpoint";
const R09_SNAPSHOT_NAME: &str = "r09-durable-state.bin";
const DISPATCH_CHILD_TEST: &str =
    "phase_zero_reference_loop_red::phase_zero_reference_loop_dispatch_child_reopens_durable_lease";
const DISPATCH_SNAPSHOT_NAME: &str = "dispatch-durable-state.bin";

const MESSAGE_BODY: &[u8] = br#"{"object":"whatsapp_business_account","entry":[{"id":"123","changes":[{"field":"messages","value":{"messaging_product":"whatsapp","metadata":{"phone_number_id":"456"},"messages":[{"id":"inbound-1","from":"5511","timestamp":"1710000000","type":"text","text":{"body":"hello"},"context":{"id":"provider-message-1"}}]}}]}]}"#;
const STATUS_BODY: &[u8] = br#"{"object":"whatsapp_business_account","entry":[{"id":"123","changes":[{"field":"messages","value":{"messaging_product":"whatsapp","metadata":{"phone_number_id":"456"},"statuses":[{"id":"provider-message-1","recipient_id":"5511","status":"delivered","timestamp":"1710000000"}]}}]}]}"#;
const READ_STATUS_BODY: &[u8] = br#"{"object":"whatsapp_business_account","entry":[{"id":"123","changes":[{"field":"messages","value":{"messaging_product":"whatsapp","metadata":{"phone_number_id":"456"},"statuses":[{"id":"provider-message-1","recipient_id":"5511","status":"read","timestamp":"1709999000"}]}}]}]}"#;
const FAILED_STATUS_BODY: &[u8] = br#"{"object":"whatsapp_business_account","entry":[{"id":"123","changes":[{"field":"messages","value":{"messaging_product":"whatsapp","metadata":{"phone_number_id":"456"},"statuses":[{"id":"provider-message-1","recipient_id":"5511","status":"failed","timestamp":"1710001000"}]}}]}]}"#;
const NO_CONTEXT_BODY: &[u8] = br#"{"object":"whatsapp_business_account","entry":[{"id":"123","changes":[{"field":"messages","value":{"messaging_product":"whatsapp","metadata":{"phone_number_id":"456"},"messages":[{"id":"inbound-2","from":"5511","timestamp":"1710000000","type":"text","text":{"body":"hello"}}]}}]}]}"#;
const UNKNOWN_CONTEXT_BODY: &[u8] = br#"{"object":"whatsapp_business_account","entry":[{"id":"123","changes":[{"field":"messages","value":{"messaging_product":"whatsapp","metadata":{"phone_number_id":"456"},"messages":[{"id":"inbound-3","from":"5511","timestamp":"1710000000","type":"text","text":{"body":"hello"},"context":{"id":"provider-message-9"}}]}}]}]}"#;
const DIFFERENT_TEXT_CONTEXT_BODY: &[u8] = br#"{"object":"whatsapp_business_account","entry":[{"id":"123","changes":[{"field":"messages","value":{"messaging_product":"whatsapp","metadata":{"phone_number_id":"456"},"messages":[{"id":"inbound-4","from":"5511","timestamp":"1710000000","type":"text","text":{"body":"different"},"context":{"id":"provider-message-1"}}]}}]}]}"#;
const BATCH_DUPLICATE_NEW_BODY: &[u8] = br#"{"object":"whatsapp_business_account","entry":[{"id":"123","changes":[{"field":"messages","value":{"messaging_product":"whatsapp","metadata":{"phone_number_id":"456"},"messages":[{"id":"inbound-1","from":"5511","timestamp":"1710000000","type":"text","text":{"body":"hello"},"context":{"id":"provider-message-1"}},{"id":"inbound-2","from":"5511","timestamp":"1710000000","type":"text","text":{"body":"hello"}}]}}]}]}"#;
const BATCH_VALID_INVALID_BODY: &[u8] = br#"{"object":"whatsapp_business_account","entry":[{"id":"123","changes":[{"field":"messages","value":{"messaging_product":"whatsapp","metadata":{"phone_number_id":"456"},"messages":[{"id":"inbound-1","from":"5511","timestamp":"1710000000","type":"text","text":{"body":"hello"},"context":{"id":"provider-message-1"}},{"id":"inbound-99","from":"5511","timestamp":"1710000000","type":"text"}]}}]}]}"#;
const BATCH_REPLY_UNBOUND_STATUS_BODY: &[u8] = br#"{"object":"whatsapp_business_account","entry":[{"id":"123","changes":[{"field":"messages","value":{"messaging_product":"whatsapp","metadata":{"phone_number_id":"456"},"messages":[{"id":"inbound-1","from":"5511","timestamp":"1710000000","type":"text","text":{"body":"hello"},"context":{"id":"provider-message-1"}}]}},{"field":"messages","value":{"messaging_product":"whatsapp","metadata":{"phone_number_id":"456"},"statuses":[{"id":"provider-message-2","recipient_id":"5511","status":"delivered","timestamp":"1710000000"}]}}]}]}"#;
const MALFORMED_BODY: &[u8] = b"{";
const UNKNOWN_SCHEMA_BODY: &[u8] = b"[]";
const MESSAGE_SIGNATURE: &str =
    "sha256=767d16c05776c8c54c55210ab0d6e81963cef18156994c7b4fb1c69b4f62e309";
const STATUS_SIGNATURE: &str =
    "sha256=12de152db349f50dfe5cb57c7f28543d6e624c54b374207161334a33734c6827";
const READ_STATUS_SIGNATURE: &str =
    "sha256=787a655928aafd88ab53b99237a38806817b30c7f9562f8c1a310dc4082ee2a5";
const FAILED_STATUS_SIGNATURE: &str =
    "sha256=8abda843eb823986b835ba759f229e21c15a35e204282c0e62dc252717eecd25";
const NO_CONTEXT_SIGNATURE: &str =
    "sha256=debfeb68013f5be19484721fb4f87c37839898af2403c8e257a3785a03f2b3e7";
const UNKNOWN_CONTEXT_SIGNATURE: &str =
    "sha256=2b2c27ef882029d05fe8b89f6c9f0599d0ab1a19cf3460c91dc79d48e46020ec";
const MALFORMED_SIGNATURE: &str =
    "sha256=ebf93fd7e80c03dd675a6386b6b9ac4ba71de7e3f6986639d07b2913db284c19";
const UNKNOWN_SCHEMA_SIGNATURE: &str =
    "sha256=b3a8b5b652a464b31fb18751ccc4c9507d132dd8b0f9a633ff07ebacc86af616";

#[derive(Clone, Debug)]
struct ExpectedObservation {
    response: ReferenceLoopResponse,
    before: DurableState,
    after: DurableState,
    providers: Vec<ProviderCapture>,
    alerts: Vec<AlertCapture>,
    attempted_alerts: Vec<AlertCapture>,
}

fn safe(value: &str) -> SafeReference {
    SafeReference::parse(value).expect("fixed non-sensitive reference")
}

fn configuration() -> ReferenceLoopConfiguration {
    ReferenceLoopConfiguration {
        verification_token: b"phase-zero-verify".to_vec(),
        app_secret: [0x5a; 32],
        active_dedup_key_generation: 4,
        retained_dedup_keys: vec![DedupKeyGeneration {
            generation: 4,
            material: [0xa4; 32],
        }],
        sender_generation: 7,
        endpoint_generation: 1,
        credential_generation: 1,
        template_allowlist_generation: 1,
        service_window: ServiceWindowState::Unknown,
        waba_id: b"123".to_vec(),
        phone_number_id: b"456".to_vec(),
        fake_provider_outcome: ProviderFixtureOutcome::Accepted(safe("provider-message-13")),
    }
}

fn configuration_with_provider_outcome(
    outcome: ProviderFixtureOutcome,
) -> ReferenceLoopConfiguration {
    let mut configuration = configuration();
    configuration.fake_provider_outcome = outcome;
    configuration
}

fn configuration_after_key_rotation() -> ReferenceLoopConfiguration {
    let mut configuration = configuration();
    configuration.retained_dedup_keys.insert(
        0,
        DedupKeyGeneration {
            generation: 3,
            material: [0xa3; 32],
        },
    );
    configuration
}

fn header(name: &[u8], value: &[u8]) -> Header {
    Header {
        name: name.to_vec(),
        value: value.to_vec(),
    }
}

fn callback(body: &[u8], signature: &str) -> ReferenceLoopRequest {
    callback_with_configuration_and_elapsed(body, signature, configuration(), 12)
}

fn signed_callback(body: Vec<u8>) -> ReferenceLoopRequest {
    let signature = signature_for(&body);
    callback(&body, &signature)
}

fn no_context_message_with_json_text(text_json: &str) -> Vec<u8> {
    let body = std::str::from_utf8(NO_CONTEXT_BODY).expect("fixed UTF-8 callback fixture");
    let changed = body.replacen(r#""body":"hello""#, &format!(r#""body":{text_json}"#), 1);
    assert_ne!(
        changed, body,
        "text boundary fixture must mutate the signed bytes"
    );
    changed.into_bytes()
}

fn no_context_message_with_ignored_nesting(array_depth: usize) -> Vec<u8> {
    let body = std::str::from_utf8(NO_CONTEXT_BODY).expect("fixed UTF-8 callback fixture");
    let nested = format!("{}0{}", "[".repeat(array_depth), "]".repeat(array_depth));
    let changed = body.replacen(
        r#""messages":["#,
        &format!(r#""ignored":{nested},"messages":["#),
        1,
    );
    assert_ne!(
        changed, body,
        "depth boundary fixture must mutate the signed bytes"
    );
    changed.into_bytes()
}

fn signature_for(body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(&[0x5a; 32]).expect("fixed HMAC key");
    mac.update(body);
    format!("sha256={}", hex_lower(&mac.finalize().into_bytes()))
}

fn callback_with_configuration(
    body: &[u8],
    signature: &str,
    configuration: ReferenceLoopConfiguration,
) -> ReferenceLoopRequest {
    callback_with_configuration_and_elapsed(body, signature, configuration, 12)
}

fn callback_with_configuration_and_elapsed(
    body: &[u8],
    signature: &str,
    configuration: ReferenceLoopConfiguration,
    elapsed_millis: u64,
) -> ReferenceLoopRequest {
    ReferenceLoopRequest {
        operation: ReferenceLoopOperation::Callback(CallbackIngress {
            method: b"POST".to_vec(),
            query: Vec::new(),
            headers: vec![
                header(b"content-type", b"application/json; charset=utf-8"),
                header(b"x-hub-signature-256", signature.as_bytes()),
            ],
            raw_body: body.to_vec(),
            elapsed_millis,
        }),
        configuration,
        received_at: 1_710_000_001,
    }
}

fn callback_without_signature(body: &[u8]) -> ReferenceLoopRequest {
    let mut request = callback(body, MESSAGE_SIGNATURE);
    let ReferenceLoopOperation::Callback(ingress) = &mut request.operation else {
        unreachable!("callback helper constructs callback operation");
    };
    ingress
        .headers
        .retain(|header| header.name != b"x-hub-signature-256");
    request
}

fn challenge(token: &[u8]) -> ReferenceLoopRequest {
    ReferenceLoopRequest {
        operation: ReferenceLoopOperation::Callback(CallbackIngress {
            method: b"GET".to_vec(),
            query: vec![
                QueryParameter {
                    name: b"hub.mode".to_vec(),
                    value: b"subscribe".to_vec(),
                },
                QueryParameter {
                    name: b"hub.verify_token".to_vec(),
                    value: token.to_vec(),
                },
                QueryParameter {
                    name: b"hub.challenge".to_vec(),
                    value: b"bounded-challenge".to_vec(),
                },
            ],
            headers: Vec::new(),
            raw_body: Vec::new(),
            elapsed_millis: 4,
        }),
        configuration: configuration(),
        received_at: 1_710_000_001,
    }
}

fn registered_outbound(configuration: ReferenceLoopConfiguration) -> ReferenceLoopRequest {
    ReferenceLoopRequest {
        operation: ReferenceLoopOperation::RegisteredOutbound(RegisteredOutbound {
            attempt_reference: safe("event-13"),
            sender_generation: 7,
            template: TemplateSelection::Registered(RegisteredTemplate::Phase0Notice),
            destination: b"+5511999999999".to_vec(),
            locale: b"pt_BR".to_vec(),
            parameters: vec![b"bounded".to_vec()],
            caller_supplied_authority: None,
        }),
        configuration,
        received_at: 1_710_000_001,
    }
}

fn retention_control(
    local_operator: bool,
    requested_raw_hours: Option<u16>,
    extension_hours: Option<u16>,
    purge: bool,
) -> ReferenceLoopRequest {
    ReferenceLoopRequest {
        operation: ReferenceLoopOperation::Retention(RetentionControl {
            local_operator,
            requested_raw_hours,
            extension_hours,
            purge,
        }),
        configuration: configuration(),
        received_at: 1_710_000_001,
    }
}

fn dispatch_alert(event_reference: SafeReference) -> ReferenceLoopRequest {
    dispatch_alert_at(event_reference, 1_710_000_001)
}

fn dispatch_alert_at(event_reference: SafeReference, received_at: i64) -> ReferenceLoopRequest {
    ReferenceLoopRequest {
        operation: ReferenceLoopOperation::DispatchAlert { event_reference },
        configuration: configuration(),
        received_at,
    }
}

fn correct_service_window(
    event_reference: SafeReference,
    prior_event_reference: SafeReference,
    state: ServiceWindowState,
) -> ReferenceLoopRequest {
    ReferenceLoopRequest {
        operation: ReferenceLoopOperation::CorrectServiceWindow {
            event_reference,
            prior_event_reference,
            state,
        },
        configuration: configuration(),
        received_at: 1_710_000_001,
    }
}

fn accepted(
    status: u16,
    body: &[u8],
    before: DurableState,
    after: DurableState,
) -> ExpectedObservation {
    ExpectedObservation {
        response: ReferenceLoopResponse {
            status,
            headers: Vec::new(),
            body: body.to_vec(),
        },
        before,
        after,
        providers: Vec::new(),
        alerts: Vec::new(),
        attempted_alerts: Vec::new(),
    }
}

fn accepted_with_headers(
    status: u16,
    headers: Vec<Header>,
    body: &[u8],
    before: DurableState,
    after: DurableState,
) -> ExpectedObservation {
    ExpectedObservation {
        response: ReferenceLoopResponse {
            status,
            headers,
            body: body.to_vec(),
        },
        before,
        after,
        providers: Vec::new(),
        alerts: Vec::new(),
        attempted_alerts: Vec::new(),
    }
}

fn receipt(kind: CandidateKind, callback_key: [u8; 32]) -> Receipt {
    Receipt {
        callback_key,
        sender_generation: 7,
        kind,
        received_at: 1_710_000_001,
    }
}

fn callback_key(fields: &[&[u8]], key: [u8; 32]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("fixed HMAC key");
    mac.update(&wac1(fields));
    mac.finalize().into_bytes().into()
}

fn message_key(message_id: &[u8], key: [u8; 32]) -> [u8; 32] {
    callback_key(&[b"message", b"7", b"123", b"456", message_id], key)
}

fn status_key(status: &[u8], timestamp: &[u8], key: [u8; 32]) -> [u8; 32] {
    status_key_for(b"provider-message-1", status, timestamp, key)
}

fn status_key_for(
    provider_message_id: &[u8],
    status: &[u8],
    timestamp: &[u8],
    key: [u8; 32],
) -> [u8; 32] {
    callback_key(
        &[
            b"status",
            b"7",
            b"123",
            b"456",
            provider_message_id,
            status,
            timestamp,
            b"5511",
        ],
        key,
    )
}

fn status_state() -> DurableState {
    DurableState {
        receipts: vec![receipt(
            CandidateKind::OutboundStatus,
            status_key(b"delivered", b"1710000000", [0xa4; 32]),
        )],
        bindings: vec![ProviderBinding {
            sender_generation: 7,
            provider_message_id: safe("provider-message-1"),
        }],
        events: vec![EvidenceEvent {
            kind: EventKind::StatusDelivered,
            reference: safe("event-5"),
            sender_generation: 7,
            provider_occurred_at: Some(1_710_000_000),
            receipt_order: 1,
        }],
        tombstones: vec![Tombstone {
            callback_key: status_key(b"delivered", b"1710000000", [0xa4; 32]),
            sender_generation: 7,
            key_generation: 4,
        }],
        revision: 1,
        ..DurableState::default()
    }
}

fn matched_reply_state(matched: bool) -> DurableState {
    DurableState {
        receipts: vec![receipt(
            CandidateKind::InboundMessage,
            if matched {
                message_key(b"inbound-1", [0xa4; 32])
            } else {
                message_key(b"inbound-2", [0xa4; 32])
            },
        )],
        events: vec![EvidenceEvent {
            kind: if matched {
                EventKind::MatchedReply
            } else {
                EventKind::UnmatchedReply
            },
            reference: safe(if matched { "event-6" } else { "event-7" }),
            sender_generation: 7,
            provider_occurred_at: Some(1_710_000_000),
            receipt_order: 1,
        }],
        outbox: vec![AlertIntent {
            event_reference: safe(if matched { "event-6" } else { "event-7" }),
            matched,
            safe_timestamp: 1_710_000_000,
            leased: false,
            lease_fence: 0,
            lease_expires_at: None,
            dispatch_attempts: 0,
            delivered: false,
            ambiguous_dispatch: false,
        }],
        tombstones: vec![Tombstone {
            callback_key: if matched {
                message_key(b"inbound-1", [0xa4; 32])
            } else {
                message_key(b"inbound-2", [0xa4; 32])
            },
            sender_generation: 7,
            key_generation: 4,
        }],
        revision: 1,
        ..DurableState::default()
    }
}

fn require_missing(case: &str, request: ReferenceLoopRequest, expected: ExpectedObservation) {
    let mut runtime = FixtureKernel::with_durable(expected.before.clone());
    let result = reference_loop().handle(&request, &mut runtime);
    match result {
        Err(PhaseZeroReferenceLoopError::MissingPhaseZeroReferenceLoop) => {
            panic!("{case}: PhaseZeroReferenceLoop frontier is intentionally RED")
        }
        Err(other) => panic!("{case}: wrong frontier: {other:?}"),
        Ok(response) => {
            assert_eq!(response, expected.response, "{case}: safe response");
            assert_eq!(runtime.durable(), &expected.after, "{case}: durable state");
            assert_eq!(
                runtime.provider_captures(),
                expected.providers,
                "{case}: provider capture"
            );
            assert_eq!(
                runtime.alert_captures(),
                expected.alerts,
                "{case}: alert capture"
            );
            assert_eq!(
                runtime.attempted_alert_captures(),
                expected.attempted_alerts,
                "{case}: attempted alert capture"
            );
        }
    }
}

fn require_alert_outage_restart_and_retry(
    case: &str,
    outage_request: ReferenceLoopRequest,
    outage_expected: ExpectedObservation,
    retry_request: ReferenceLoopRequest,
    retry_expected: ExpectedObservation,
) {
    let store_root = r09_store_root();
    let snapshot = store_root.join("alert-outage-durable-state.bin");
    let mut runtime = FixtureKernel::with_store(outage_expected.before.clone(), &snapshot)
        .expect("initialize alert-outage durable fixture");
    runtime.inject_alert_unavailable();
    match reference_loop().handle(&outage_request, &mut runtime) {
        Err(PhaseZeroReferenceLoopError::MissingPhaseZeroReferenceLoop) => {
            let _ = std::fs::remove_file(&snapshot);
            panic!("{case}: PhaseZeroReferenceLoop frontier is intentionally RED")
        }
        Ok(response) => {
            assert_eq!(
                response, outage_expected.response,
                "{case}: outage response remains safe"
            );
            assert_eq!(
                runtime.durable(),
                &outage_expected.after,
                "{case}: retryable durable lease"
            );
            assert!(
                runtime.provider_captures().is_empty() && runtime.alert_captures().is_empty(),
                "{case}: unavailable alert sink produces no successful external capture"
            );
            assert_eq!(
                runtime.attempted_alert_captures(),
                outage_expected.attempted_alerts,
                "{case}: unavailable alert sink still has one independently observed attempt"
            );
            drop(runtime);
            let mut restarted = FixtureKernel::reopen_store(&snapshot)
                .expect("restart reopens the failed-send durable lease");
            assert_eq!(
                restarted.durable(),
                &outage_expected.after,
                "{case}: restart retains only retryable durable state"
            );
            match reference_loop().handle(&retry_request, &mut restarted) {
                Ok(retry_response) => {
                    assert_eq!(
                        retry_response, retry_expected.response,
                        "{case}: retry response"
                    );
                    assert_eq!(
                        restarted.durable(),
                        &retry_expected.after,
                        "{case}: retry settles only under a new fence"
                    );
                    assert_eq!(
                        restarted.alert_captures(),
                        retry_expected.alerts,
                        "{case}: successful retry has one safe alert capture"
                    );
                    assert_eq!(
                        restarted.provider_captures(),
                        retry_expected.providers,
                        "{case}: alert retry has no provider capture"
                    );
                    assert_eq!(
                        restarted.attempted_alert_captures(),
                        retry_expected.attempted_alerts,
                        "{case}: successful retry has the exact attempted alert list"
                    );
                }
                Err(error) => panic!("{case}: retry must recover after sink outage: {error:?}"),
            }
        }
        Err(error) => panic!("{case}: alert outage must retain a retryable intent: {error:?}"),
    }
}

fn require_checkpoint_stop(
    case: &str,
    request: ReferenceLoopRequest,
    expected: ExpectedObservation,
    checkpoint: TransactionCheckpoint,
    stop: RuntimeStop,
) {
    let mut runtime = FixtureKernel::with_durable(expected.before.clone());
    runtime.inject_stop(checkpoint);
    let result = reference_loop().handle(&request, &mut runtime);
    match result {
        Err(PhaseZeroReferenceLoopError::MissingPhaseZeroReferenceLoop) => {
            panic!("{case}: PhaseZeroReferenceLoop frontier is intentionally RED")
        }
        Err(PhaseZeroReferenceLoopError::Runtime(RuntimeError::Stop(actual))) => {
            assert_eq!(actual, stop, "{case}: exact injected checkpoint");
            assert_eq!(
                runtime.durable(),
                &expected.after,
                "{case}: durable recovery state"
            );
            assert_eq!(
                runtime.provider_captures(),
                expected.providers,
                "{case}: provider capture"
            );
            assert_eq!(
                runtime.alert_captures(),
                expected.alerts,
                "{case}: alert capture"
            );
            assert_eq!(
                runtime.attempted_alert_captures(),
                expected.attempted_alerts,
                "{case}: attempted alert capture"
            );
            let reconstructed = runtime.restart();
            assert_eq!(
                reconstructed.durable(),
                &expected.after,
                "{case}: restart retains only the durable result"
            );
            assert!(
                reconstructed.provider_captures().is_empty()
                    && reconstructed.alert_captures().is_empty(),
                "{case}: restart clears volatile fixture captures"
            );
        }
        Err(other) => panic!("{case}: wrong frontier: {other:?}"),
        Ok(response) => panic!("{case}: expected checkpoint {stop:?}, got {response:?}"),
    }
}

fn r09_store_root() -> PathBuf {
    if let Some(root) = std::env::var_os("MSGRIVER_PHASE0_STORE_ROOT") {
        return PathBuf::from(root);
    }
    for attempt in 0..32_u32 {
        // nosemgrep: rust.lang.security.temp-dir.temp-dir -- test-owned 0700 store is made unique below.
        let root = std::env::temp_dir().join(format!(
            "msgriver-phase0-r09-{}-{}",
            std::process::id(),
            attempt
        ));
        match std::fs::create_dir(&root) {
            Ok(()) => {
                #[cfg(unix)]
                std::fs::set_permissions(
                    &root,
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                )
                .expect("restrict isolated R09 store");
                return root;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create isolated R09 store: {error}"),
        }
    }
    panic!("allocate isolated R09 store")
}

fn run_r09_worker_child(
    store_root: &Path,
    checkpoint: TransactionCheckpoint,
    input: &str,
) -> std::process::Output {
    // nosemgrep: rust.lang.security.current-exe.current-exe -- invokes this test binary's ignored child only.
    let executable = std::env::current_exe().expect("locate test executable");
    std::process::Command::new(executable)
        .arg("--exact")
        .arg(R09_CHILD_TEST)
        .arg("--ignored")
        .arg("--nocapture")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("inherit test path"))
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("MSGRIVER_PHASE0_STORE_ROOT", store_root)
        .env("MSGRIVER_PHASE0_CHILD_EFFECT_LOG", "1")
        .env("MSGRIVER_PHASE0_TERMINATE_AT_CHECKPOINT", "1")
        .env(
            "MSGRIVER_PHASE0_R09_CHECKPOINT",
            match checkpoint {
                TransactionCheckpoint::BeforeCommit => "before-commit",
                TransactionCheckpoint::AfterReceiptInsert => "after-receipt-insert",
                TransactionCheckpoint::AfterCommitBeforeAck => "after-commit",
                TransactionCheckpoint::BeforeDispatchLease
                | TransactionCheckpoint::AfterDispatchSend => {
                    panic!("R09 uses callback transaction checkpoints only")
                }
            },
        )
        .env("MSGRIVER_PHASE0_R09_INPUT", input)
        .output()
        .expect("launch R09 child")
}

fn r09_child_input(request: &ReferenceLoopRequest) -> &'static str {
    match &request.operation {
        ReferenceLoopOperation::Callback(ingress)
            if ingress.raw_body == BATCH_DUPLICATE_NEW_BODY =>
        {
            "two-new"
        }
        ReferenceLoopOperation::Callback(_) => "single",
        _ => panic!("R09 child accepts only callback inputs"),
    }
}

fn run_dispatch_worker_child(store_root: &Path) -> std::process::Output {
    // nosemgrep: rust.lang.security.current-exe.current-exe -- invokes this test binary's ignored child only.
    let executable = std::env::current_exe().expect("locate test executable");
    std::process::Command::new(executable)
        .arg("--exact")
        .arg(DISPATCH_CHILD_TEST)
        .arg("--ignored")
        .arg("--nocapture")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("inherit test path"))
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("MSGRIVER_PHASE0_STORE_ROOT", store_root)
        .env("MSGRIVER_PHASE0_CHILD_EFFECT_LOG", "1")
        .env("MSGRIVER_PHASE0_TERMINATE_AT_CHECKPOINT", "1")
        .output()
        .expect("launch dispatch child")
}

fn require_checkpoint_stop_and_replay(
    case: &str,
    request: ReferenceLoopRequest,
    stopped_expected: ExpectedObservation,
    replay_expected: ExpectedObservation,
    checkpoint: TransactionCheckpoint,
    stop: RuntimeStop,
) {
    let store_root = r09_store_root();
    let snapshot = store_root.join(R09_SNAPSHOT_NAME);
    let runtime = FixtureKernel::with_store(stopped_expected.before.clone(), &snapshot)
        .expect("initialize R09 durable fixture");
    drop(runtime);
    let child = run_r09_worker_child(&store_root, checkpoint, r09_child_input(&request));
    match child.status.code().expect("R09 child is not signaled") {
        94 => {
            let _ = std::fs::remove_file(&snapshot);
            panic!("{case}: PhaseZeroReferenceLoop frontier is intentionally RED")
        }
        93 => {
            let child_stdout = String::from_utf8(child.stdout)
                .expect("R09 child emits only safe ASCII effect records");
            assert!(
                !child_stdout.contains("MSGRIVER_PHASE0_PROVIDER_CAPTURE")
                    && !child_stdout.contains("MSGRIVER_PHASE0_ALERT_"),
                "{case}: callback worker termination has no external effect"
            );
            let mut restarted = FixtureKernel::reopen_store(&snapshot)
                .expect("R09 parent reopens child-validated durable checkpoint");
            assert_eq!(
                restarted.durable(),
                &stopped_expected.after,
                "{case}: child-validated snapshot is complete before replay"
            );
            assert!(
                restarted.provider_captures().is_empty() && restarted.alert_captures().is_empty(),
                "{case}: process restart has no volatile capture state"
            );
            match reference_loop().handle(&request, &mut restarted) {
                Ok(response) => {
                    assert_eq!(
                        response, replay_expected.response,
                        "{case}: replay response"
                    );
                    assert_eq!(
                        restarted.durable(),
                        &replay_expected.after,
                        "{case}: replay durable state"
                    );
                    assert_eq!(
                        restarted.provider_captures(),
                        replay_expected.providers,
                        "{case}: replay provider capture"
                    );
                    assert_eq!(
                        restarted.alert_captures(),
                        replay_expected.alerts,
                        "{case}: replay alert capture"
                    );
                    assert_eq!(
                        restarted.attempted_alert_captures(),
                        replay_expected.attempted_alerts,
                        "{case}: replay attempted alert capture"
                    );
                }
                Err(error) => panic!("{case}: replay must acknowledge after restart: {error:?}"),
            }
        }
        status => panic!("{case}: R09 child exit={status}; expected injected {stop:?}"),
    }
}

fn require_dispatch_checkpoint_stop_and_replay(
    case: &str,
    stopped_request: ReferenceLoopRequest,
    stopped_expected: ExpectedObservation,
    replay_request: ReferenceLoopRequest,
    replay_expected: ExpectedObservation,
) {
    assert_eq!(
        stopped_request,
        dispatch_alert(safe("event-6")),
        "{case}: child dispatch input is closed and independently reconstructed"
    );
    let store_root = r09_store_root();
    let snapshot = store_root.join(DISPATCH_SNAPSHOT_NAME);
    let runtime = FixtureKernel::with_store(stopped_expected.before.clone(), &snapshot)
        .expect("initialize dispatch durable fixture");
    drop(runtime);
    let child = run_dispatch_worker_child(&store_root);
    match child.status.code().expect("dispatch child is not signaled") {
        94 => {
            let _ = std::fs::remove_file(&snapshot);
            panic!("{case}: PhaseZeroReferenceLoop frontier is intentionally RED")
        }
        93 => {
            let child_stdout = String::from_utf8(child.stdout)
                .expect("dispatch child emits only safe ASCII effect records");
            let expected_records = vec![
                "MSGRIVER_PHASE0_ALERT_ATTEMPT:event-6:true:1710000000",
                "MSGRIVER_PHASE0_ALERT_CAPTURE:event-6:true:1710000000",
            ];
            let observed_records: Vec<&str> = child_stdout
                .lines()
                .filter(|line| line.starts_with("MSGRIVER_PHASE0_"))
                .collect();
            assert_eq!(
                observed_records, expected_records,
                "{case}: terminated child has one and only one attempted and completed safe effect"
            );
            let mut restarted = FixtureKernel::reopen_store(&snapshot)
                .expect("dispatch parent reopens child-validated durable lease");
            assert_eq!(
                restarted.durable(),
                &stopped_expected.after,
                "{case}: child-validated lease survives process termination"
            );
            assert!(
                restarted.alert_captures().is_empty(),
                "{case}: a restarted worker cannot inherit an old external capture"
            );
            match reference_loop().handle(&replay_request, &mut restarted) {
                Ok(response) => {
                    assert_eq!(response, replay_expected.response, "{case}: retry response");
                    assert_eq!(
                        restarted.durable(),
                        &replay_expected.after,
                        "{case}: expired lease recovery is fenced and durable"
                    );
                    assert_eq!(
                        restarted.alert_captures(),
                        replay_expected.alerts,
                        "{case}: retry has exactly one independently observed safe capture"
                    );
                    assert_eq!(
                        restarted.provider_captures(),
                        replay_expected.providers,
                        "{case}: retry has no provider capture"
                    );
                    assert_eq!(
                        restarted.attempted_alert_captures(),
                        replay_expected.attempted_alerts,
                        "{case}: retry has the exact attempted alert list"
                    );
                }
                Err(error) => panic!("{case}: replay must recover the expired lease: {error:?}"),
            }
        }
        status => panic!("{case}: dispatch child exit={status}; expected post-send interruption"),
    }
}

/// This is intentionally ignored in the ordinary RED run. It reconstructs the
/// store and executes the callback itself; `93` means the named barrier ended
/// the worker and `94` preserves the current missing-factory RED frontier.
#[test]
#[ignore]
fn phase_zero_reference_loop_r09_child_reopens_durable_checkpoint() {
    let root =
        std::env::var_os("MSGRIVER_PHASE0_STORE_ROOT").expect("R09 child store root is explicit");
    let snapshot = PathBuf::from(root).join(R09_SNAPSHOT_NAME);
    let checkpoint = match std::env::var("MSGRIVER_PHASE0_R09_CHECKPOINT")
        .expect("R09 child checkpoint is explicit")
        .as_str()
    {
        "before-commit" => TransactionCheckpoint::BeforeCommit,
        "after-receipt-insert" => TransactionCheckpoint::AfterReceiptInsert,
        "after-commit" => TransactionCheckpoint::AfterCommitBeforeAck,
        other => panic!("unknown R09 child checkpoint: {other}"),
    };
    let mut runtime = FixtureKernel::reopen_store(&snapshot)
        .expect("R09 child opens only a complete durable checkpoint");
    runtime.inject_stop(checkpoint);
    let request = match std::env::var("MSGRIVER_PHASE0_R09_INPUT")
        .expect("R09 child input is explicit")
        .as_str()
    {
        "single" => callback(MESSAGE_BODY, MESSAGE_SIGNATURE),
        "two-new" => callback(
            BATCH_DUPLICATE_NEW_BODY,
            &signature_for(BATCH_DUPLICATE_NEW_BODY),
        ),
        other => panic!("unknown R09 child input: {other}"),
    };
    match reference_loop().handle(&request, &mut runtime) {
        Err(PhaseZeroReferenceLoopError::MissingPhaseZeroReferenceLoop) => std::process::exit(94),
        Err(PhaseZeroReferenceLoopError::Runtime(RuntimeError::Stop(actual))) => panic!(
            "R09 child returned {actual:?}; it must terminate inside checkpoint {checkpoint:?}"
        ),
        result => panic!("R09 child must terminate at its barrier: {result:?}"),
    }
}

/// This separate child runs the dispatcher against disk-reopened state and
/// terminates only after the fake dispatch barrier.
#[test]
#[ignore]
fn phase_zero_reference_loop_dispatch_child_reopens_durable_lease() {
    let root = std::env::var_os("MSGRIVER_PHASE0_STORE_ROOT")
        .expect("dispatch child store root is explicit");
    let snapshot = PathBuf::from(root).join(DISPATCH_SNAPSHOT_NAME);
    let mut runtime = FixtureKernel::reopen_store(&snapshot)
        .expect("dispatch child opens only a complete durable lease checkpoint");
    runtime.inject_stop(TransactionCheckpoint::AfterDispatchSend);
    match reference_loop().handle(&dispatch_alert(safe("event-6")), &mut runtime) {
        Err(PhaseZeroReferenceLoopError::MissingPhaseZeroReferenceLoop) => std::process::exit(94),
        Err(PhaseZeroReferenceLoopError::Runtime(RuntimeError::Stop(actual))) => {
            panic!("dispatch child returned {actual:?}; it must terminate inside its checkpoint")
        }
        result => panic!("dispatch child must terminate after the fake send: {result:?}"),
    }
}

#[test]
fn phase_zero_reference_loop_fixed_hmac_and_wac1_vectors() {
    assert_fixed_signature(MESSAGE_BODY, MESSAGE_SIGNATURE);
    assert_fixed_signature(STATUS_BODY, STATUS_SIGNATURE);
    assert_fixed_signature(READ_STATUS_BODY, READ_STATUS_SIGNATURE);
    assert_fixed_signature(FAILED_STATUS_BODY, FAILED_STATUS_SIGNATURE);
    assert_fixed_signature(NO_CONTEXT_BODY, NO_CONTEXT_SIGNATURE);
    assert_fixed_signature(UNKNOWN_CONTEXT_BODY, UNKNOWN_CONTEXT_SIGNATURE);
    assert_fixed_signature(MALFORMED_BODY, MALFORMED_SIGNATURE);
    assert_fixed_signature(UNKNOWN_SCHEMA_BODY, UNKNOWN_SCHEMA_SIGNATURE);
    assert_eq!(
        wac1(&[b"message", b"7", b"123", b"456", b"inbound-1"]),
        b"WAC17:message1:73:1233:4569:inbound-1",
        "canonical callback fields are length-prefixed without JSON ordering"
    );
    assert_fixed_hmac(
        b"WAC17:message1:73:1233:4569:inbound-1",
        [0xa3; 32],
        "4759b011363878d90866308ab60467d5492e249ba5fefff9bdb5fd92cf517730",
    );
    assert_fixed_hmac(
        b"WAC17:message1:73:1233:4569:inbound-1",
        [0xa4; 32],
        "ee6d70e076a2ef245e96933ff7fbfdadd612752ffe73e0095ef1116375b22e15",
    );
    let status_fields = [
        b"status".as_slice(),
        b"7".as_slice(),
        b"123".as_slice(),
        b"456".as_slice(),
        b"provider-message-1".as_slice(),
        b"delivered".as_slice(),
        b"1710000000".as_slice(),
        b"5511".as_slice(),
    ];
    assert_eq!(
        wac1(&status_fields),
        b"WAC16:status1:73:1233:45618:provider-message-19:delivered10:17100000004:5511"
    );
    assert_fixed_hmac(
        b"WAC16:status1:73:1233:45618:provider-message-19:delivered10:17100000004:5511",
        [0xa4; 32],
        "6a4629645be714ae4d0d2db05a4b53ae3b23cc025bac6608af108778e6aefcce",
    );
}

fn assert_fixed_signature(body: &[u8], expected: &str) {
    assert_fixed_hmac(body, [0x5a; 32], &expected[7..]);
}

fn assert_fixed_hmac(body: &[u8], key: [u8; 32], expected: &str) {
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("fixed HMAC key");
    mac.update(body);
    assert_eq!(hex_lower(&mac.finalize().into_bytes()), expected);
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn wac1(fields: &[&[u8]]) -> Vec<u8> {
    let mut encoded = b"WAC1".to_vec();
    for field in fields {
        encoded.extend_from_slice(field.len().to_string().as_bytes());
        encoded.push(b':');
        encoded.extend_from_slice(field);
    }
    encoded
}

#[test]
fn p0b_r01_valid_challenge_has_exact_echo_and_no_durable_mutation() {
    require_missing(
        "P0B-R01",
        challenge(b"phase-zero-verify"),
        accepted_with_headers(
            200,
            vec![header(b"content-type", b"text/plain; charset=utf-8")],
            b"bounded-challenge",
            DurableState::default(),
            DurableState::default(),
        ),
    );
    let mut duplicate_challenge = challenge(b"phase-zero-verify");
    let ReferenceLoopOperation::Callback(ingress) = &mut duplicate_challenge.operation else {
        unreachable!("challenge helper constructs callback ingress");
    };
    ingress.query.push(QueryParameter {
        name: b"hub.challenge".to_vec(),
        value: b"second".to_vec(),
    });
    require_missing(
        "P0B-R01 duplicate challenge parameter is not an alternate success",
        duplicate_challenge,
        accepted(401, b"", DurableState::default(), DurableState::default()),
    );
    let mut unknown_query = challenge(b"phase-zero-verify");
    let ReferenceLoopOperation::Callback(ingress) = &mut unknown_query.operation else {
        unreachable!("challenge helper constructs callback ingress");
    };
    ingress.query.push(QueryParameter {
        name: b"unexpected".to_vec(),
        value: b"value".to_vec(),
    });
    require_missing(
        "P0B-R01 unknown challenge parameter is rejected",
        unknown_query,
        accepted(401, b"", DurableState::default(), DurableState::default()),
    );
}

#[test]
fn p0b_r02_invalid_challenge_is_safe_and_stateless() {
    require_missing(
        "P0B-R02",
        challenge(b"wrong-token"),
        accepted(401, b"", DurableState::default(), DurableState::default()),
    );
    require_missing(
        "P0B-R02 empty verification token",
        challenge(b""),
        accepted(401, b"", DurableState::default(), DurableState::default()),
    );
}

#[test]
fn p0b_r03_signature_grammar_failure_precedes_parse_and_mutation() {
    let before = DurableState {
        bindings: vec![ProviderBinding {
            sender_generation: 7,
            provider_message_id: safe("provider-message-1"),
        }],
        ..DurableState::default()
    };
    let mut case_insensitive_after = matched_reply_state(true);
    case_insensitive_after.bindings = before.bindings.clone();
    let mut case_insensitive_header = callback(MESSAGE_BODY, MESSAGE_SIGNATURE);
    let ReferenceLoopOperation::Callback(ingress) = &mut case_insensitive_header.operation else {
        unreachable!("callback helper constructs callback operation");
    };
    ingress.headers[1].name = b"X-Hub-Signature-256".to_vec();
    require_missing(
        "P0B-R03 signature header name is ASCII case-insensitive",
        case_insensitive_header,
        accepted(200, b"", before, case_insensitive_after),
    );
    require_missing(
        "P0B-R03 unsupported algorithm",
        callback(MESSAGE_BODY, "sha1=not-accepted"),
        accepted(401, b"", DurableState::default(), DurableState::default()),
    );
    require_missing(
        "P0B-R03 missing signature",
        callback_without_signature(MESSAGE_BODY),
        accepted(401, b"", DurableState::default(), DurableState::default()),
    );
    require_missing(
        "P0B-R03 wrong fixed-width digest",
        callback(
            MESSAGE_BODY,
            "sha256=0000000000000000000000000000000000000000000000000000000000000000",
        ),
        accepted(401, b"", DurableState::default(), DurableState::default()),
    );
    let mut duplicate_signature = callback(MESSAGE_BODY, MESSAGE_SIGNATURE);
    let ReferenceLoopOperation::Callback(ingress) = &mut duplicate_signature.operation else {
        unreachable!("callback helper constructs callback operation");
    };
    ingress.headers.push(header(
        b"x-hub-signature-256",
        b"sha256=767d16c05776c8c54c55210ab0d6e81963cef18156994c7b4fb1c69b4f62e309",
    ));
    require_missing(
        "P0B-R03 duplicate signature header",
        duplicate_signature,
        accepted(401, b"", DurableState::default(), DurableState::default()),
    );
    require_missing(
        "P0B-R03 upper-case digest grammar is rejected",
        callback(
            MESSAGE_BODY,
            "sha256=767D16C05776C8C54C55210AB0D6E81963CEF18156994C7B4FB1C69B4F62E309",
        ),
        accepted(401, b"", DurableState::default(), DurableState::default()),
    );
}

#[test]
fn p0b_r04_transport_and_authenticated_schema_failures_are_empty_and_stateless() {
    require_missing(
        "P0B-R04 body ceiling",
        callback(&vec![b'x'; 262_145], MESSAGE_SIGNATURE),
        accepted(413, b"", DurableState::default(), DurableState::default()),
    );
    require_missing(
        "P0B-R04 deadline",
        callback_with_configuration_and_elapsed(
            MESSAGE_BODY,
            MESSAGE_SIGNATURE,
            configuration(),
            5_001,
        ),
        accepted(408, b"", DurableState::default(), DurableState::default()),
    );
    require_missing(
        "P0B-R04 exact deadline remains eligible for authenticated parsing",
        callback_with_configuration_and_elapsed(
            MALFORMED_BODY,
            MALFORMED_SIGNATURE,
            configuration(),
            5_000,
        ),
        accepted(400, b"", DurableState::default(), DurableState::default()),
    );
    let exact_limit = vec![b'x'; 262_144];
    require_missing(
        "P0B-R04 exact body limit remains eligible for authenticated parsing",
        callback(&exact_limit, &signature_for(&exact_limit)),
        accepted(400, b"", DurableState::default(), DurableState::default()),
    );
    require_missing(
        "P0B-R04 authenticated malformed JSON",
        callback(MALFORMED_BODY, MALFORMED_SIGNATURE),
        accepted(400, b"", DurableState::default(), DurableState::default()),
    );
    require_missing(
        "P0B-R04 authenticated unsupported schema",
        callback(UNKNOWN_SCHEMA_BODY, UNKNOWN_SCHEMA_SIGNATURE),
        accepted(400, b"", DurableState::default(), DurableState::default()),
    );
    let depth_sixteen = no_context_message_with_ignored_nesting(10);
    require_missing(
        "P0B-R04 maximum JSON depth is eligible",
        signed_callback(depth_sixteen),
        accepted(
            200,
            b"",
            DurableState::default(),
            matched_reply_state(false),
        ),
    );
    let depth_seventeen = no_context_message_with_ignored_nesting(11);
    require_missing(
        "P0B-R04 JSON depth over the profile is stateless",
        signed_callback(depth_seventeen),
        accepted(400, b"", DurableState::default(), DurableState::default()),
    );
    for length in [512_usize, 513, 4_096] {
        let text = format!("\"{}\"", "x".repeat(length));
        require_missing(
            &format!("P0B-R04 text body {length} bytes remains eligible"),
            signed_callback(no_context_message_with_json_text(&text)),
            accepted(
                200,
                b"",
                DurableState::default(),
                matched_reply_state(false),
            ),
        );
    }
    let overlong_text = format!("\"{}\"", "x".repeat(4_097));
    require_missing(
        "P0B-R04 text body over 4096 bytes is stateless",
        signed_callback(no_context_message_with_json_text(&overlong_text)),
        accepted(400, b"", DurableState::default(), DurableState::default()),
    );
    require_missing(
        "P0B-R04 text LF escape is eligible",
        signed_callback(no_context_message_with_json_text(r#""line\nnext""#)),
        accepted(
            200,
            b"",
            DurableState::default(),
            matched_reply_state(false),
        ),
    );
    require_missing(
        "P0B-R04 text C0 control is stateless",
        signed_callback(no_context_message_with_json_text(r#""line\u0001next""#)),
        accepted(400, b"", DurableState::default(), DurableState::default()),
    );
    let mut duplicate_content_type = callback(MESSAGE_BODY, MESSAGE_SIGNATURE);
    let ReferenceLoopOperation::Callback(ingress) = &mut duplicate_content_type.operation else {
        unreachable!("callback helper constructs callback operation");
    };
    ingress
        .headers
        .push(header(b"content-type", b"application/json"));
    require_missing(
        "P0B-R04 duplicate content type",
        duplicate_content_type,
        accepted(400, b"", DurableState::default(), DurableState::default()),
    );
}

#[test]
fn p0b_r05_status_requires_exact_same_generation_binding() {
    let mut foreign_sender = configuration();
    foreign_sender.waba_id = b"999".to_vec();
    require_missing(
        "P0B-R05 foreign ingress authority",
        callback_with_configuration(STATUS_BODY, STATUS_SIGNATURE, foreign_sender),
        accepted(400, b"", DurableState::default(), DurableState::default()),
    );
    require_missing(
        "P0B-R05 absent binding rolls back",
        callback(STATUS_BODY, STATUS_SIGNATURE),
        accepted(503, b"", DurableState::default(), DurableState::default()),
    );
    let before = DurableState {
        bindings: vec![ProviderBinding {
            sender_generation: 7,
            provider_message_id: safe("provider-message-1"),
        }],
        ..DurableState::default()
    };
    let mut after = status_state();
    after.bindings = before.bindings.clone();
    require_missing(
        "P0B-R05 exact same-generation binding",
        callback(STATUS_BODY, STATUS_SIGNATURE),
        accepted(200, b"", before, after),
    );
    let stale_before = DurableState {
        bindings: vec![ProviderBinding {
            sender_generation: 8,
            provider_message_id: safe("provider-message-1"),
        }],
        ..DurableState::default()
    };
    require_missing(
        "P0B-R05 stale-generation binding rolls back",
        callback(STATUS_BODY, STATUS_SIGNATURE),
        accepted(503, b"", stale_before.clone(), stale_before),
    );
}

#[test]
fn p0b_r06_exact_context_creates_one_matched_event_and_safe_alert() {
    let before = DurableState {
        bindings: vec![ProviderBinding {
            sender_generation: 7,
            provider_message_id: safe("provider-message-1"),
        }],
        ..DurableState::default()
    };
    let mut after = matched_reply_state(true);
    after.bindings = before.bindings.clone();
    require_missing(
        "P0B-R06",
        callback(MESSAGE_BODY, MESSAGE_SIGNATURE),
        accepted(200, b"", before, after),
    );
}

#[test]
fn p0b_r07_missing_context_is_unmatched_without_heuristic() {
    require_missing(
        "P0B-R07",
        callback(NO_CONTEXT_BODY, NO_CONTEXT_SIGNATURE),
        accepted(
            200,
            b"",
            DurableState::default(),
            matched_reply_state(false),
        ),
    );
}

#[test]
fn p0b_r08_replay_after_rotation_is_acknowledged_without_duplicate_effect() {
    let mut state = matched_reply_state(true);
    state.tombstones[0].key_generation = 3;
    state.receipts[0].callback_key = message_key(b"inbound-1", [0xa3; 32]);
    state.tombstones[0].callback_key = message_key(b"inbound-1", [0xa3; 32]);
    require_missing(
        "P0B-R08",
        callback_with_configuration(
            MESSAGE_BODY,
            MESSAGE_SIGNATURE,
            configuration_after_key_rotation(),
        ),
        accepted(200, b"", state.clone(), state),
    );
    let mut rotated_status = status_state();
    rotated_status.receipts[0].callback_key = status_key(b"delivered", b"1710000000", [0xa3; 32]);
    rotated_status.tombstones[0].callback_key = status_key(b"delivered", b"1710000000", [0xa3; 32]);
    rotated_status.tombstones[0].key_generation = 3;
    require_missing(
        "P0B-R08 retained generation deduplicates status replay",
        callback_with_configuration(
            STATUS_BODY,
            STATUS_SIGNATURE,
            configuration_after_key_rotation(),
        ),
        accepted(200, b"", rotated_status.clone(), rotated_status),
    );
    require_missing(
        "P0B-R08 new callback under rotation uses the active generation",
        callback_with_configuration(
            NO_CONTEXT_BODY,
            NO_CONTEXT_SIGNATURE,
            configuration_after_key_rotation(),
        ),
        accepted(
            200,
            b"",
            DurableState::default(),
            matched_reply_state(false),
        ),
    );
}

#[test]
fn p0b_r09_pre_and_post_commit_crashes_have_distinct_recovery_state() {
    let before = DurableState {
        bindings: vec![ProviderBinding {
            sender_generation: 7,
            provider_message_id: safe("provider-message-1"),
        }],
        ..DurableState::default()
    };
    let mut committed = matched_reply_state(true);
    committed.bindings = before.bindings.clone();
    require_checkpoint_stop_and_replay(
        "P0B-R09 pre-commit",
        callback(MESSAGE_BODY, MESSAGE_SIGNATURE),
        accepted(200, b"", before.clone(), before.clone()),
        accepted(200, b"", before.clone(), committed.clone()),
        TransactionCheckpoint::BeforeCommit,
        RuntimeStop::BeforeCommit,
    );
    require_checkpoint_stop_and_replay(
        "P0B-R09 post-commit",
        callback(MESSAGE_BODY, MESSAGE_SIGNATURE),
        accepted(200, b"", before.clone(), committed.clone()),
        accepted(200, b"", committed.clone(), committed),
        TransactionCheckpoint::AfterCommitBeforeAck,
        RuntimeStop::AfterCommitBeforeAck,
    );

    require_missing(
        "P0B-R09 valid reply plus unbound valid status rolls back as one callback",
        callback(
            BATCH_REPLY_UNBOUND_STATUS_BODY,
            &signature_for(BATCH_REPLY_UNBOUND_STATUS_BODY),
        ),
        accepted(503, b"", before.clone(), before.clone()),
    );
    let mut bound_before = before.clone();
    bound_before.bindings.push(ProviderBinding {
        sender_generation: 7,
        provider_message_id: safe("provider-message-2"),
    });
    let mut bound_after = matched_reply_state(true);
    bound_after.bindings = bound_before.bindings.clone();
    bound_after.receipts.push(receipt(
        CandidateKind::OutboundStatus,
        status_key_for(
            b"provider-message-2",
            b"delivered",
            b"1710000000",
            [0xa4; 32],
        ),
    ));
    bound_after.events.push(EvidenceEvent {
        kind: EventKind::StatusDelivered,
        reference: safe("event-7"),
        sender_generation: 7,
        provider_occurred_at: Some(1_710_000_000),
        receipt_order: 2,
    });
    bound_after.tombstones.push(Tombstone {
        callback_key: status_key_for(
            b"provider-message-2",
            b"delivered",
            b"1710000000",
            [0xa4; 32],
        ),
        sender_generation: 7,
        key_generation: 4,
    });
    require_missing(
        "P0B-R09 exact new binding permits the previously rolled-back batch",
        callback(
            BATCH_REPLY_UNBOUND_STATUS_BODY,
            &signature_for(BATCH_REPLY_UNBOUND_STATUS_BODY),
        ),
        accepted(200, b"", bound_before, bound_after),
    );

    let mut one_before = matched_reply_state(true);
    one_before.bindings = before.bindings.clone();
    let mut duplicate_new_after = one_before.clone();
    duplicate_new_after.receipts.push(receipt(
        CandidateKind::InboundMessage,
        message_key(b"inbound-2", [0xa4; 32]),
    ));
    duplicate_new_after.events.push(EvidenceEvent {
        kind: EventKind::UnmatchedReply,
        reference: safe("event-7"),
        sender_generation: 7,
        provider_occurred_at: Some(1_710_000_000),
        receipt_order: 2,
    });
    duplicate_new_after.outbox.push(AlertIntent {
        event_reference: safe("event-7"),
        matched: false,
        safe_timestamp: 1_710_000_000,
        leased: false,
        lease_fence: 0,
        lease_expires_at: None,
        dispatch_attempts: 0,
        delivered: false,
        ambiguous_dispatch: false,
    });
    duplicate_new_after.tombstones.push(Tombstone {
        callback_key: message_key(b"inbound-2", [0xa4; 32]),
        sender_generation: 7,
        key_generation: 4,
    });
    duplicate_new_after.revision = 2;
    let mut two_new_after = duplicate_new_after.clone();
    two_new_after.revision = 1;
    require_missing(
        "P0B-R09 valid plus invalid candidate rejects the entire batch",
        callback(
            BATCH_VALID_INVALID_BODY,
            &signature_for(BATCH_VALID_INVALID_BODY),
        ),
        accepted(400, b"", before.clone(), before.clone()),
    );
    require_missing(
        "P0B-R09 duplicate plus new candidate commits only the new candidate",
        callback(
            BATCH_DUPLICATE_NEW_BODY,
            &signature_for(BATCH_DUPLICATE_NEW_BODY),
        ),
        accepted(200, b"", one_before.clone(), duplicate_new_after.clone()),
    );
    require_checkpoint_stop_and_replay(
        "P0B-R09 failure after receipt insertion rolls back every new batch member",
        callback(
            BATCH_DUPLICATE_NEW_BODY,
            &signature_for(BATCH_DUPLICATE_NEW_BODY),
        ),
        accepted(503, b"", before.clone(), before.clone()),
        accepted(200, b"", before.clone(), two_new_after.clone()),
        TransactionCheckpoint::AfterReceiptInsert,
        RuntimeStop::AfterReceiptInsert,
    );
    require_checkpoint_stop_and_replay(
        "P0B-R09 post-commit termination preserves the complete two-new-candidate batch",
        callback(
            BATCH_DUPLICATE_NEW_BODY,
            &signature_for(BATCH_DUPLICATE_NEW_BODY),
        ),
        accepted(200, b"", before, two_new_after.clone()),
        accepted(200, b"", two_new_after.clone(), two_new_after),
        TransactionCheckpoint::AfterCommitBeforeAck,
        RuntimeStop::AfterCommitBeforeAck,
    );
}

#[test]
fn p0b_r10_dispatch_failure_retains_one_durable_intent() {
    let before = matched_reply_state(true);
    require_missing(
        "P0B-R10 callback replay does not synchronously dispatch ntfy",
        callback(MESSAGE_BODY, MESSAGE_SIGNATURE),
        accepted(200, b"", before.clone(), before.clone()),
    );
    require_checkpoint_stop(
        "P0B-R10 dispatcher outage retains the one unleased durable intent",
        dispatch_alert(safe("event-6")),
        accepted(202, b"", before.clone(), before.clone()),
        TransactionCheckpoint::BeforeDispatchLease,
        RuntimeStop::BeforeDispatchLease,
    );

    let mut active_lease = before.clone();
    active_lease.outbox[0].leased = true;
    active_lease.outbox[0].lease_fence = 1;
    active_lease.outbox[0].lease_expires_at = Some(1_710_000_061);
    active_lease.outbox[0].dispatch_attempts = 1;
    active_lease.revision = 2;
    require_missing(
        "P0B-R10 competing dispatcher cannot capture an unexpired lease",
        dispatch_alert_at(safe("event-6"), 1_710_000_060),
        accepted(202, b"", active_lease.clone(), active_lease.clone()),
    );

    let mut recovered = active_lease.clone();
    recovered.outbox[0].leased = false;
    recovered.outbox[0].lease_fence = 2;
    recovered.outbox[0].lease_expires_at = None;
    recovered.outbox[0].dispatch_attempts = 2;
    recovered.outbox[0].delivered = true;
    recovered.outbox[0].ambiguous_dispatch = true;
    recovered.revision = 4;
    let mut recovered_expected = accepted(202, b"", active_lease, recovered);
    recovered_expected.alerts = vec![AlertCapture::new(safe("event-6"), true, 1_710_000_000)];
    recovered_expected.attempted_alerts =
        vec![AlertCapture::new(safe("event-6"), true, 1_710_000_000)];
    let mut outage_expected = accepted(202, b"", before, recovered_expected.before.clone());
    outage_expected.attempted_alerts =
        vec![AlertCapture::new(safe("event-6"), true, 1_710_000_000)];
    require_alert_outage_restart_and_retry(
        "P0B-R10 failed alert send restarts and retries once under a new fence",
        dispatch_alert(safe("event-6")),
        outage_expected,
        dispatch_alert_at(safe("event-6"), 1_710_000_061),
        recovered_expected,
    );
}

#[test]
fn p0b_r11_privacy_expiry_and_purge_leave_only_safe_evidence() {
    let before = DurableState {
        sensitive_reply: Some(SensitiveReplyState {
            retained_at: 1_710_000_001,
            expires_at: 1_710_086_401,
            local_only: true,
        }),
        ..DurableState::default()
    };
    require_missing(
        "P0B-R11 default safe view has no raw response body",
        retention_control(true, None, None, false),
        accepted(200, b"", before.clone(), before.clone()),
    );
    let expired_before = DurableState {
        sensitive_reply: Some(SensitiveReplyState {
            retained_at: 1_709_900_000,
            expires_at: 1_709_999_999,
            local_only: true,
        }),
        ..DurableState::default()
    };
    let mut expired_after = DurableState::default();
    expired_after.events.push(EvidenceEvent {
        kind: EventKind::RetentionDisposition,
        reference: safe("event-11"),
        sender_generation: 7,
        provider_occurred_at: None,
        receipt_order: 1,
    });
    expired_after.revision = 1;
    require_missing(
        "P0B-R11 expiry purges sensitive state but keeps safe disposition",
        retention_control(true, Some(24), None, false),
        accepted(200, b"", expired_before, expired_after),
    );
}

#[test]
fn p0b_r12_late_evidence_does_not_rewrite_v1_history() {
    let before = DurableState {
        bindings: vec![ProviderBinding {
            sender_generation: 7,
            provider_message_id: safe("provider-message-1"),
        }],
        v1_history: vec![V1Fact::ProviderAccepted {
            attempts: 1,
            uncertain: false,
        }],
        revision: 1,
        ..DurableState::default()
    };
    let mut after = before.clone();
    after.receipts.push(receipt(
        CandidateKind::OutboundStatus,
        status_key(b"delivered", b"1710000000", [0xa4; 32]),
    ));
    after.tombstones.push(Tombstone {
        callback_key: status_key(b"delivered", b"1710000000", [0xa4; 32]),
        sender_generation: 7,
        key_generation: 4,
    });
    after.events.push(EvidenceEvent {
        kind: EventKind::StatusDelivered,
        reference: safe("event-12"),
        sender_generation: 7,
        provider_occurred_at: Some(1_710_000_000),
        receipt_order: 1,
    });
    after.revision = 2;
    require_missing(
        "P0B-R12",
        callback(STATUS_BODY, STATUS_SIGNATURE),
        accepted(200, b"", before, after),
    );
}

#[test]
fn p0b_r13_registered_template_rejects_free_form_and_binds_known_acceptance() {
    let unknown = ReferenceLoopRequest {
        operation: ReferenceLoopOperation::RegisteredOutbound(RegisteredOutbound {
            attempt_reference: safe("event-13"),
            sender_generation: 7,
            template: TemplateSelection::Unknown(b"unregistered-template".to_vec()),
            destination: b"+5511999999999".to_vec(),
            locale: b"pt_BR".to_vec(),
            parameters: vec![b"bounded".to_vec()],
            caller_supplied_authority: None,
        }),
        configuration: configuration(),
        received_at: 1_710_000_001,
    };
    require_missing(
        "P0B-R13 unknown template",
        unknown,
        accepted(400, b"", DurableState::default(), DurableState::default()),
    );
    for (label, destination, locale, parameters) in [
        (
            "P0B-R13 non-E164 destination",
            b"5511999999999".to_vec(),
            b"pt_BR".to_vec(),
            vec![b"bounded".to_vec()],
        ),
        (
            "P0B-R13 unapproved locale",
            b"+5511999999999".to_vec(),
            b"en_US".to_vec(),
            vec![b"bounded".to_vec()],
        ),
        (
            "P0B-R13 wrong parameter cardinality",
            b"+5511999999999".to_vec(),
            b"pt_BR".to_vec(),
            vec![b"one".to_vec(), b"two".to_vec()],
        ),
        (
            "P0B-R13 missing required parameter",
            b"+5511999999999".to_vec(),
            b"pt_BR".to_vec(),
            Vec::new(),
        ),
        (
            "P0B-R13 unbounded parameter",
            b"+5511999999999".to_vec(),
            b"pt_BR".to_vec(),
            vec![vec![b'x'; 4_097]],
        ),
    ] {
        let mut malformed = registered_outbound(configuration());
        let ReferenceLoopOperation::RegisteredOutbound(outbound) = &mut malformed.operation else {
            unreachable!("registered outbound helper constructs that operation");
        };
        outbound.destination = destination;
        outbound.locale = locale;
        outbound.parameters = parameters;
        require_missing(
            label,
            malformed,
            accepted(400, b"", DurableState::default(), DurableState::default()),
        );
    }
    let request = ReferenceLoopRequest {
        operation: ReferenceLoopOperation::RegisteredOutbound(RegisteredOutbound {
            attempt_reference: safe("event-13"),
            sender_generation: 7,
            template: TemplateSelection::Registered(RegisteredTemplate::Phase0Notice),
            destination: b"+5511999999999".to_vec(),
            locale: b"pt_BR".to_vec(),
            parameters: vec![b"bounded".to_vec()],
            caller_supplied_authority: None,
        }),
        configuration: configuration(),
        received_at: 1_710_000_001,
    };
    let after = DurableState {
        bindings: vec![ProviderBinding {
            sender_generation: 7,
            provider_message_id: safe("provider-message-13"),
        }],
        outbound_pins: vec![OutboundPin {
            attempt_reference: safe("event-13"),
            sender_generation: 7,
            endpoint_generation: 1,
            credential_generation: 1,
            template_allowlist_generation: 1,
        }],
        events: vec![EvidenceEvent {
            kind: EventKind::OutboundOutcome,
            reference: safe("event-13"),
            sender_generation: 7,
            provider_occurred_at: None,
            receipt_order: 1,
        }],
        revision: 1,
        ..DurableState::default()
    };
    require_missing(
        "P0B-R13",
        request,
        ExpectedObservation {
            response: ReferenceLoopResponse {
                status: 202,
                headers: Vec::new(),
                body: Vec::new(),
            },
            before: DurableState::default(),
            after,
            providers: vec![ProviderCapture::new(
                RegisteredTemplate::Phase0Notice,
                7,
                Some(safe("provider-message-13")),
            )],
            alerts: Vec::new(),
            attempted_alerts: Vec::new(),
        },
    );
}

#[test]
fn p0b_r14_only_known_provider_acceptance_may_create_a_binding() {
    for (class, uncertain) in [
        (ProviderOutcomeClass::Permanent, false),
        (ProviderOutcomeClass::AuthOrConfig, false),
        (ProviderOutcomeClass::RateLimited, false),
        (ProviderOutcomeClass::Transient, false),
        (ProviderOutcomeClass::Ambiguous, true),
    ] {
        let after = DurableState {
            events: vec![EvidenceEvent {
                kind: EventKind::OutboundOutcome,
                reference: safe("event-14"),
                sender_generation: 7,
                provider_occurred_at: None,
                receipt_order: 1,
            }],
            v1_history: vec![V1Fact::ProviderOutcome {
                class,
                attempts: 1,
                uncertain,
            }],
            revision: 1,
            ..DurableState::default()
        };
        let mut expected = accepted(202, b"", DurableState::default(), after);
        expected.providers = vec![ProviderCapture::new(
            RegisteredTemplate::Phase0Notice,
            7,
            None,
        )];
        require_missing(
            "P0B-R14 classified non-acceptance",
            registered_outbound(configuration_with_provider_outcome(
                ProviderFixtureOutcome::Classified(class),
            )),
            expected,
        );
    }
}

#[test]
fn p0b_r15_status_facts_are_append_only_and_keep_provider_time() {
    let before = status_state();
    let mut after_read = before.clone();
    after_read.receipts.push(receipt(
        CandidateKind::OutboundStatus,
        status_key(b"read", b"1709999000", [0xa4; 32]),
    ));
    after_read.tombstones.push(Tombstone {
        callback_key: status_key(b"read", b"1709999000", [0xa4; 32]),
        sender_generation: 7,
        key_generation: 4,
    });
    after_read.events.push(EvidenceEvent {
        kind: EventKind::StatusRead,
        reference: safe("event-15"),
        sender_generation: 7,
        provider_occurred_at: Some(1_709_999_000),
        receipt_order: 2,
    });
    after_read.revision = 2;
    require_missing(
        "P0B-R15 earlier read appends without rewriting delivery",
        callback(READ_STATUS_BODY, READ_STATUS_SIGNATURE),
        accepted(200, b"", before, after_read.clone()),
    );
    let mut after_failed = after_read.clone();
    after_failed.receipts.push(receipt(
        CandidateKind::OutboundStatus,
        status_key(b"failed", b"1710001000", [0xa4; 32]),
    ));
    after_failed.tombstones.push(Tombstone {
        callback_key: status_key(b"failed", b"1710001000", [0xa4; 32]),
        sender_generation: 7,
        key_generation: 4,
    });
    after_failed.events.push(EvidenceEvent {
        kind: EventKind::StatusFailed,
        reference: safe("event-16"),
        sender_generation: 7,
        provider_occurred_at: Some(1_710_001_000),
        receipt_order: 3,
    });
    after_failed.revision = 3;
    require_missing(
        "P0B-R15 later failed appends without rewriting read",
        callback(FAILED_STATUS_BODY, FAILED_STATUS_SIGNATURE),
        accepted(200, b"", after_read, after_failed),
    );
}

#[test]
fn p0b_r16_correlation_adversaries_stay_unmatched() {
    let before = DurableState {
        bindings: vec![ProviderBinding {
            sender_generation: 7,
            provider_message_id: safe("provider-message-1"),
        }],
        ..DurableState::default()
    };
    let mut exact_context_after = matched_reply_state(true);
    exact_context_after.bindings = before.bindings.clone();
    exact_context_after.receipts[0].callback_key = message_key(b"inbound-4", [0xa4; 32]);
    exact_context_after.tombstones[0].callback_key = message_key(b"inbound-4", [0xa4; 32]);
    require_missing(
        "P0B-R16 text cannot alter an exact context match",
        callback(
            DIFFERENT_TEXT_CONTEXT_BODY,
            &signature_for(DIFFERENT_TEXT_CONTEXT_BODY),
        ),
        accepted(200, b"", before, exact_context_after),
    );
    let mut unknown_context_after = matched_reply_state(false);
    unknown_context_after.receipts[0].callback_key = message_key(b"inbound-3", [0xa4; 32]);
    unknown_context_after.tombstones[0].callback_key = message_key(b"inbound-3", [0xa4; 32]);
    require_missing(
        "P0B-R16 unknown context",
        callback(UNKNOWN_CONTEXT_BODY, UNKNOWN_CONTEXT_SIGNATURE),
        accepted(200, b"", DurableState::default(), unknown_context_after),
    );
    let stale_before = DurableState {
        bindings: vec![ProviderBinding {
            sender_generation: 8,
            provider_message_id: safe("provider-message-1"),
        }],
        ..DurableState::default()
    };
    let mut stale_after = matched_reply_state(false);
    stale_after.bindings = stale_before.bindings.clone();
    stale_after.receipts[0].callback_key = message_key(b"inbound-1", [0xa4; 32]);
    stale_after.tombstones[0].callback_key = message_key(b"inbound-1", [0xa4; 32]);
    require_missing(
        "P0B-R16 stale sender generation",
        callback(MESSAGE_BODY, MESSAGE_SIGNATURE),
        accepted(200, b"", stale_before, stale_after),
    );
    let ambiguous_before = DurableState {
        bindings: vec![
            ProviderBinding {
                sender_generation: 7,
                provider_message_id: safe("provider-message-1"),
            },
            ProviderBinding {
                sender_generation: 7,
                provider_message_id: safe("provider-message-1"),
            },
        ],
        ..DurableState::default()
    };
    let mut ambiguous_after = matched_reply_state(false);
    ambiguous_after.bindings = ambiguous_before.bindings.clone();
    ambiguous_after.receipts[0].callback_key = message_key(b"inbound-1", [0xa4; 32]);
    ambiguous_after.tombstones[0].callback_key = message_key(b"inbound-1", [0xa4; 32]);
    require_missing(
        "P0B-R16 ambiguous exact binding",
        callback(MESSAGE_BODY, MESSAGE_SIGNATURE),
        accepted(200, b"", ambiguous_before, ambiguous_after),
    );
}

#[test]
fn p0b_r17_tombstone_survives_callback_key_rotation() {
    let before = DurableState {
        tombstones: vec![Tombstone {
            callback_key: message_key(b"inbound-1", [0xa3; 32]),
            sender_generation: 7,
            key_generation: 3,
        }],
        ..DurableState::default()
    };
    require_missing(
        "P0B-R17",
        callback_with_configuration(
            MESSAGE_BODY,
            MESSAGE_SIGNATURE,
            configuration_after_key_rotation(),
        ),
        accepted(200, b"", before.clone(), before),
    );
}

#[test]
fn p0b_r18_service_window_is_advisory_and_cannot_authorize_send() {
    for service_window in [
        ServiceWindowState::Active,
        ServiceWindowState::Unknown,
        ServiceWindowState::Expired,
    ] {
        let mut callback_configuration = configuration();
        callback_configuration.service_window = service_window;
        require_missing(
            "P0B-R18 every service-window state remains receive-and-alert only",
            callback_with_configuration(
                NO_CONTEXT_BODY,
                NO_CONTEXT_SIGNATURE,
                callback_configuration,
            ),
            accepted(
                200,
                b"",
                DurableState::default(),
                matched_reply_state(false),
            ),
        );
    }
    let before = DurableState {
        events: vec![EvidenceEvent {
            kind: EventKind::ServiceWindowDisposition,
            reference: safe("event-18"),
            sender_generation: 7,
            provider_occurred_at: Some(1_710_000_000),
            receipt_order: 1,
        }],
        service_window_dispositions: vec![ServiceWindowDisposition {
            event_reference: safe("event-18"),
            prior_event_reference: None,
            state: ServiceWindowState::Active,
        }],
        revision: 1,
        ..DurableState::default()
    };
    let mut after = before.clone();
    after.events.push(EvidenceEvent {
        kind: EventKind::ServiceWindowDisposition,
        reference: safe("event-19"),
        sender_generation: 7,
        provider_occurred_at: Some(1_710_000_001),
        receipt_order: 2,
    });
    after
        .service_window_dispositions
        .push(ServiceWindowDisposition {
            event_reference: safe("event-19"),
            prior_event_reference: Some(safe("event-18")),
            state: ServiceWindowState::Expired,
        });
    after.revision = 2;
    require_missing(
        "P0B-R18 correction appends a disposition without rewrite",
        correct_service_window(
            safe("event-19"),
            safe("event-18"),
            ServiceWindowState::Expired,
        ),
        accepted(200, b"", before, after),
    );
}

#[test]
fn p0b_r19_retention_extension_is_bounded_and_audited() {
    require_missing(
        "P0B-R19 remote inspection is denied",
        retention_control(false, Some(24), None, false),
        accepted(403, b"", DurableState::default(), DurableState::default()),
    );
    let opt_out_before = DurableState {
        sensitive_reply: Some(SensitiveReplyState {
            retained_at: 1_710_000_001,
            expires_at: 1_710_086_401,
            local_only: true,
        }),
        ..DurableState::default()
    };
    let opt_out_after = DurableState {
        events: vec![EvidenceEvent {
            kind: EventKind::RetentionDisposition,
            reference: safe("event-21"),
            sender_generation: 7,
            provider_occurred_at: None,
            receipt_order: 1,
        }],
        revision: 1,
        ..DurableState::default()
    };
    require_missing(
        "P0B-R19 zero retention opt-out purges content but keeps safe evidence",
        retention_control(true, Some(0), None, false),
        accepted(200, b"", opt_out_before, opt_out_after),
    );
    let before = DurableState {
        sensitive_reply: Some(SensitiveReplyState {
            retained_at: 1_710_000_001,
            expires_at: 1_710_086_401,
            local_only: true,
        }),
        ..DurableState::default()
    };
    require_missing(
        "P0B-R19 retention beyond seven-day ceiling is denied from receipt time",
        retention_control(true, Some(169), None, false),
        accepted(400, b"", before.clone(), before.clone()),
    );
    let mut extended = before.clone();
    extended.sensitive_reply = Some(SensitiveReplyState {
        retained_at: 1_710_000_001,
        expires_at: 1_710_604_801,
        local_only: true,
    });
    extended.events.push(EvidenceEvent {
        kind: EventKind::RetentionDisposition,
        reference: safe("event-19"),
        sender_generation: 7,
        provider_occurred_at: None,
        receipt_order: 2,
    });
    extended.revision = 1;
    require_missing(
        "P0B-R19 audited extension within seven-day ceiling",
        retention_control(true, Some(24), Some(168), false),
        accepted(200, b"", before, extended.clone()),
    );
    let mut purged = extended.clone();
    purged.sensitive_reply = None;
    purged.events.push(EvidenceEvent {
        kind: EventKind::RetentionDisposition,
        reference: safe("event-20"),
        sender_generation: 7,
        provider_occurred_at: None,
        receipt_order: 3,
    });
    purged.revision = 2;
    require_missing(
        "P0B-R19 purge removes sensitive state but retains safe evidence",
        retention_control(true, None, None, true),
        accepted(200, b"", extended, purged),
    );
}

#[test]
fn p0b_r20_alert_capture_has_only_safe_fields_and_records_ambiguity() {
    let duplicate_before = matched_reply_state(true);
    require_missing(
        "P0B-R20 replay creates no second alert intent or capture",
        callback(MESSAGE_BODY, MESSAGE_SIGNATURE),
        accepted(200, b"", duplicate_before.clone(), duplicate_before),
    );

    let before = matched_reply_state(true);
    let mut stopped_after = before.clone();
    stopped_after.outbox[0].leased = true;
    stopped_after.outbox[0].lease_fence = 1;
    stopped_after.outbox[0].lease_expires_at = Some(1_710_000_061);
    stopped_after.outbox[0].dispatch_attempts = 1;
    stopped_after.revision = 2;
    let stopped_expected = ExpectedObservation {
        response: ReferenceLoopResponse {
            status: 202,
            headers: Vec::new(),
            body: Vec::new(),
        },
        before: before.clone(),
        after: stopped_after.clone(),
        providers: Vec::new(),
        alerts: vec![AlertCapture::new(safe("event-6"), true, 1_710_000_000)],
        attempted_alerts: vec![AlertCapture::new(safe("event-6"), true, 1_710_000_000)],
    };
    let mut replay_after = stopped_after.clone();
    replay_after.outbox[0].leased = false;
    replay_after.outbox[0].lease_fence = 2;
    replay_after.outbox[0].lease_expires_at = None;
    replay_after.outbox[0].dispatch_attempts = 2;
    replay_after.outbox[0].delivered = true;
    replay_after.outbox[0].ambiguous_dispatch = true;
    replay_after.revision = 4;
    let replay_expected = ExpectedObservation {
        response: ReferenceLoopResponse {
            status: 202,
            headers: Vec::new(),
            body: Vec::new(),
        },
        before: stopped_after,
        after: replay_after,
        providers: Vec::new(),
        alerts: vec![AlertCapture::new(safe("event-6"), true, 1_710_000_000)],
        attempted_alerts: vec![AlertCapture::new(safe("event-6"), true, 1_710_000_000)],
    };
    require_dispatch_checkpoint_stop_and_replay(
        "P0B-R20 post-send termination persists a fenced recovery lease",
        dispatch_alert(safe("event-6")),
        stopped_expected,
        dispatch_alert_at(safe("event-6"), 1_710_000_061),
        replay_expected,
    );
}

#[test]
fn p0b_r21_caller_authority_cannot_drift_a_queued_template() {
    let forbidden_authorities = vec![
        CallerSuppliedAuthority::Endpoint(b"https://caller.invalid/webhook".to_vec()),
        CallerSuppliedAuthority::Token(b"caller-token".to_vec()),
        CallerSuppliedAuthority::SenderId(b"caller-sender".to_vec()),
        CallerSuppliedAuthority::Webhook(b"https://caller.invalid/callback".to_vec()),
        CallerSuppliedAuthority::Header(header(b"x-caller-header", b"caller-value")),
        CallerSuppliedAuthority::ArbitraryBody(br#"{"free":"form"}"#.to_vec()),
    ];
    for authority in forbidden_authorities {
        let mut request = registered_outbound(configuration());
        let ReferenceLoopOperation::RegisteredOutbound(outbound) = &mut request.operation else {
            unreachable!("registered outbound helper constructs that operation");
        };
        outbound.caller_supplied_authority = Some(authority);
        require_missing(
            "P0B-R21 caller authority is rejected before acceptance",
            request,
            accepted(400, b"", DurableState::default(), DurableState::default()),
        );
    }

    let pin = OutboundPin {
        attempt_reference: safe("event-21"),
        sender_generation: 7,
        endpoint_generation: 1,
        credential_generation: 1,
        template_allowlist_generation: 1,
    };
    for drifted_configuration in [
        {
            let mut value = configuration();
            value.sender_generation = 8;
            value
        },
        {
            let mut value = configuration();
            value.endpoint_generation = 2;
            value
        },
        {
            let mut value = configuration();
            value.credential_generation = 2;
            value
        },
        {
            let mut value = configuration();
            value.template_allowlist_generation = 2;
            value
        },
    ] {
        let before = DurableState {
            outbound_pins: vec![pin.clone()],
            ..DurableState::default()
        };
        let mut request = registered_outbound(drifted_configuration);
        let ReferenceLoopOperation::RegisteredOutbound(outbound) = &mut request.operation else {
            unreachable!("registered outbound helper constructs that operation");
        };
        outbound.attempt_reference = pin.attempt_reference.clone();
        require_missing(
            "P0B-R21 queued command generation drift is rejected",
            request,
            accepted(409, b"", before.clone(), before),
        );
    }
}

#[test]
fn p0b_r22_only_private_provider_ingress_reaches_the_callback_seam() {
    let client_api = ReferenceLoopRequest {
        operation: ReferenceLoopOperation::ClientApi,
        configuration: configuration(),
        received_at: 1_710_000_001,
    };
    require_missing(
        "P0B-R22 client API",
        client_api,
        accepted(404, b"", DurableState::default(), DurableState::default()),
    );
    let client_api_key = ReferenceLoopRequest {
        operation: ReferenceLoopOperation::ClientApiKey,
        configuration: configuration(),
        received_at: 1_710_000_001,
    };
    require_missing(
        "P0B-R22 client API key",
        client_api_key,
        accepted(404, b"", DurableState::default(), DurableState::default()),
    );
    let cli_catalog = ReferenceLoopRequest {
        operation: ReferenceLoopOperation::CliCatalog,
        configuration: configuration(),
        received_at: 1_710_000_001,
    };
    require_missing(
        "P0B-R22 CLI catalog",
        cli_catalog,
        accepted(404, b"", DurableState::default(), DurableState::default()),
    );
    let provider_ingress = callback(MESSAGE_BODY, MESSAGE_SIGNATURE);
    let ReferenceLoopOperation::Callback(ingress) = provider_ingress.operation else {
        unreachable!("callback helper constructs provider ingress");
    };
    let client_callback = ReferenceLoopRequest {
        operation: ReferenceLoopOperation::ClientCallback(ingress),
        configuration: configuration(),
        received_at: 1_710_000_001,
    };
    require_missing(
        "P0B-R22 client cannot invoke signed provider callback behavior",
        client_callback,
        accepted(404, b"", DurableState::default(), DurableState::default()),
    );
}
