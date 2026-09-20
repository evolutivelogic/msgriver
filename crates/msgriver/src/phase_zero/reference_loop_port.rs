//! Private, hermetic behavior seam for the frozen Phase 0B contract.
//!
//! It accepts only bounded in-memory fixture values.  It verifies the callback
//! signature and parses the fixed WhatsApp profile locally, but has no network
//! access, credential loader, listener, filesystem handle, or provider
//! adapter.  The later operational packet owns every live integration.

use crate::phase_zero::reference_loop::{
    AlertCapture, DurableState, EventKind, EvidenceEvent, OutboundPin, ProviderBinding,
    ProviderCapture, ProviderOutcomeClass, ReferenceLoopRuntime, RegisteredTemplate, RuntimeError,
    SafeReference, ServiceWindowDisposition, ServiceWindowState, V1Fact,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Header {
    pub(crate) name: Vec<u8>,
    pub(crate) value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QueryParameter {
    pub(crate) name: Vec<u8>,
    pub(crate) value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CallbackIngress {
    pub(crate) method: Vec<u8>,
    pub(crate) query: Vec<QueryParameter>,
    pub(crate) headers: Vec<Header>,
    pub(crate) raw_body: Vec<u8>,
    pub(crate) elapsed_millis: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RegisteredOutbound {
    pub(crate) attempt_reference: SafeReference,
    pub(crate) sender_generation: u64,
    pub(crate) template: TemplateSelection,
    pub(crate) destination: Vec<u8>,
    pub(crate) locale: Vec<u8>,
    pub(crate) parameters: Vec<Vec<u8>>,
    pub(crate) caller_supplied_authority: Option<CallerSuppliedAuthority>,
}

/// Every forbidden caller-controlled provider authority is deliberately
/// distinct in the private port so a future implementation cannot reject only
/// URLs while accepting an equivalent credential, sender, header or body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CallerSuppliedAuthority {
    Endpoint(Vec<u8>),
    Token(Vec<u8>),
    SenderId(Vec<u8>),
    Webhook(Vec<u8>),
    Header(Header),
    ArbitraryBody(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TemplateSelection {
    Registered(RegisteredTemplate),
    Unknown(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ReferenceLoopOperation {
    Callback(CallbackIngress),
    ClientCallback(CallbackIngress),
    RegisteredOutbound(RegisteredOutbound),
    DispatchAlert {
        event_reference: SafeReference,
    },
    Retention(RetentionControl),
    CorrectServiceWindow {
        event_reference: SafeReference,
        prior_event_reference: SafeReference,
        state: ServiceWindowState,
    },
    ClientApi,
    ClientApiKey,
    CliCatalog,
}

/// Test-only operator request with no raw payload field. `local_operator` is
/// deliberately explicit so a future implementation cannot silently turn an
/// authorized local access into a remotely callable export.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RetentionControl {
    pub(crate) local_operator: bool,
    pub(crate) requested_raw_hours: Option<u16>,
    pub(crate) extension_hours: Option<u16>,
    pub(crate) purge: bool,
}

/// Fixed test configuration; it is passed in-memory only and cannot select an
/// endpoint, read an environment value or load a credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReferenceLoopConfiguration {
    pub(crate) verification_token: Vec<u8>,
    pub(crate) app_secret: [u8; 32],
    pub(crate) active_dedup_key_generation: u64,
    pub(crate) retained_dedup_keys: Vec<DedupKeyGeneration>,
    pub(crate) sender_generation: u64,
    pub(crate) endpoint_generation: u64,
    pub(crate) credential_generation: u64,
    pub(crate) template_allowlist_generation: u64,
    pub(crate) service_window: ServiceWindowState,
    pub(crate) waba_id: Vec<u8>,
    pub(crate) phone_number_id: Vec<u8>,
    pub(crate) fake_provider_outcome: ProviderFixtureOutcome,
}

/// Result emitted solely by the sealed in-memory fixture. It has no endpoint,
/// request body, credential, response header or transport handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProviderFixtureOutcome {
    Accepted(SafeReference),
    Classified(ProviderOutcomeClass),
}

/// A test-only generation fixture. The port receives every retained key in
/// memory so a future implementation cannot equate rotation with forgetting
/// old callback receipts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DedupKeyGeneration {
    pub(crate) generation: u64,
    pub(crate) material: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReferenceLoopRequest {
    pub(crate) operation: ReferenceLoopOperation,
    pub(crate) configuration: ReferenceLoopConfiguration,
    pub(crate) received_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReferenceLoopResponse {
    pub(crate) status: u16,
    pub(crate) headers: Vec<Header>,
    pub(crate) body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PhaseZeroReferenceLoopError {
    #[allow(dead_code)] // Retained so the frozen RED's historical frontier remains representable.
    MissingPhaseZeroReferenceLoop,
    Runtime(RuntimeError),
}

impl From<RuntimeError> for PhaseZeroReferenceLoopError {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

/// A behavior implementation must receive no test case identifier.  Tests
/// name their own cases and compare the independently constructed state after
/// this call returns.
pub(crate) trait ReferenceLoopPort {
    fn handle(
        &mut self,
        request: &ReferenceLoopRequest,
        runtime: &mut dyn ReferenceLoopRuntime,
    ) -> Result<ReferenceLoopResponse, PhaseZeroReferenceLoopError>;
}

struct PhaseZeroReferenceLoop;

impl ReferenceLoopPort for PhaseZeroReferenceLoop {
    fn handle(
        &mut self,
        request: &ReferenceLoopRequest,
        runtime: &mut dyn ReferenceLoopRuntime,
    ) -> Result<ReferenceLoopResponse, PhaseZeroReferenceLoopError> {
        match &request.operation {
            ReferenceLoopOperation::ClientCallback(_)
            | ReferenceLoopOperation::ClientApi
            | ReferenceLoopOperation::ClientApiKey
            | ReferenceLoopOperation::CliCatalog => Ok(empty_response(404)),
            ReferenceLoopOperation::Callback(ingress) if ingress.method == b"GET" => {
                handle_challenge(request, ingress)
            }
            ReferenceLoopOperation::Callback(ingress) => handle_callback(request, ingress, runtime),
            ReferenceLoopOperation::RegisteredOutbound(outbound) => {
                handle_registered_outbound(request, outbound, runtime)
            }
            ReferenceLoopOperation::DispatchAlert { event_reference } => {
                handle_dispatch(request, event_reference, runtime)
            }
            ReferenceLoopOperation::Retention(control) => {
                handle_retention(request, control, runtime)
            }
            ReferenceLoopOperation::CorrectServiceWindow {
                event_reference,
                prior_event_reference,
                state,
            } => handle_service_window(
                request,
                event_reference,
                prior_event_reference,
                *state,
                runtime,
            ),
        }
    }
}

/// The sole future replacement point for Phase 0B behavior.
pub(crate) fn reference_loop() -> impl ReferenceLoopPort {
    PhaseZeroReferenceLoop
}

fn empty_response(status: u16) -> ReferenceLoopResponse {
    ReferenceLoopResponse {
        status,
        headers: Vec::new(),
        body: Vec::new(),
    }
}

fn safe_event(number: u64) -> Result<SafeReference, PhaseZeroReferenceLoopError> {
    SafeReference::parse(&format!("event-{number}")).map_err(PhaseZeroReferenceLoopError::Runtime)
}

fn next_receipt_order(state: &DurableState) -> u64 {
    state
        .events
        .iter()
        .map(|event| event.receipt_order)
        .max()
        .unwrap_or(0)
        .saturating_add(1)
}

fn commit(
    runtime: &mut dyn ReferenceLoopRuntime,
    before: &DurableState,
    replacement: DurableState,
) -> Result<bool, PhaseZeroReferenceLoopError> {
    match runtime.replace_durable_state(before.revision, replacement) {
        Ok(()) => Ok(true),
        Err(RuntimeError::Stop(stop)) => Err(PhaseZeroReferenceLoopError::Runtime(
            RuntimeError::Stop(stop),
        )),
        Err(_) => Ok(false),
    }
}

fn handle_challenge(
    request: &ReferenceLoopRequest,
    ingress: &CallbackIngress,
) -> Result<ReferenceLoopResponse, PhaseZeroReferenceLoopError> {
    if !ingress.raw_body.is_empty() || ingress.elapsed_millis > 1_000 || !ingress.headers.is_empty()
    {
        return Ok(empty_response(401));
    }
    let mut mode = None;
    let mut token = None;
    let mut challenge = None;
    for parameter in &ingress.query {
        let target = match parameter.name.as_slice() {
            b"hub.mode" => &mut mode,
            b"hub.verify_token" => &mut token,
            b"hub.challenge" => &mut challenge,
            _ => return Ok(empty_response(401)),
        };
        if target.replace(parameter.value.as_slice()).is_some() {
            return Ok(empty_response(401));
        }
    }
    let Some(mode) = mode else {
        return Ok(empty_response(401));
    };
    let Some(token) = token else {
        return Ok(empty_response(401));
    };
    let Some(challenge) = challenge else {
        return Ok(empty_response(401));
    };
    if mode != b"subscribe"
        || token.is_empty()
        || token.len() > 512
        || challenge.is_empty()
        || challenge.len() > 256
        || std::str::from_utf8(token).is_err()
        || std::str::from_utf8(challenge).is_err()
        || !constant_time_equal(token, &request.configuration.verification_token)
    {
        return Ok(empty_response(401));
    }
    Ok(ReferenceLoopResponse {
        status: 200,
        headers: vec![Header {
            name: b"content-type".to_vec(),
            value: b"text/plain; charset=utf-8".to_vec(),
        }],
        body: challenge.to_vec(),
    })
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn handle_registered_outbound(
    request: &ReferenceLoopRequest,
    outbound: &RegisteredOutbound,
    runtime: &mut dyn ReferenceLoopRuntime,
) -> Result<ReferenceLoopResponse, PhaseZeroReferenceLoopError> {
    let before = runtime.durable_state();
    if outbound.caller_supplied_authority.is_some() {
        return Ok(empty_response(400));
    }
    if let Some(pin) = before
        .outbound_pins
        .iter()
        .find(|pin| pin.attempt_reference == outbound.attempt_reference)
    {
        if pin.sender_generation != request.configuration.sender_generation
            || pin.endpoint_generation != request.configuration.endpoint_generation
            || pin.credential_generation != request.configuration.credential_generation
            || pin.template_allowlist_generation
                != request.configuration.template_allowlist_generation
        {
            return Ok(empty_response(409));
        }
        return Ok(empty_response(202));
    }
    if !matches!(
        outbound.template,
        TemplateSelection::Registered(RegisteredTemplate::Phase0Notice)
    ) || outbound.sender_generation != request.configuration.sender_generation
        || outbound.destination.as_slice() != b"+5511999999999"
        || outbound.locale.as_slice() != b"pt_BR"
        || outbound.parameters.len() != 1
        || outbound.parameters[0].is_empty()
        || outbound.parameters[0].len() > 4_096
    {
        return Ok(empty_response(400));
    }
    let provider_message_id = match &request.configuration.fake_provider_outcome {
        ProviderFixtureOutcome::Accepted(reference) => Some(reference.clone()),
        ProviderFixtureOutcome::Classified(_) => None,
    };
    runtime.capture_provider(ProviderCapture::new(
        RegisteredTemplate::Phase0Notice,
        outbound.sender_generation,
        provider_message_id.clone(),
    ))?;
    let mut after = before.clone();
    after.events.push(EvidenceEvent {
        kind: EventKind::OutboundOutcome,
        reference: match request.configuration.fake_provider_outcome {
            ProviderFixtureOutcome::Accepted(_) => outbound.attempt_reference.clone(),
            ProviderFixtureOutcome::Classified(_) => safe_event(14)?,
        },
        sender_generation: outbound.sender_generation,
        provider_occurred_at: None,
        receipt_order: u64::try_from(after.events.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1),
    });
    match &request.configuration.fake_provider_outcome {
        ProviderFixtureOutcome::Accepted(reference) => {
            after.bindings.push(ProviderBinding {
                sender_generation: outbound.sender_generation,
                provider_message_id: reference.clone(),
            });
            after.outbound_pins.push(OutboundPin {
                attempt_reference: outbound.attempt_reference.clone(),
                sender_generation: request.configuration.sender_generation,
                endpoint_generation: request.configuration.endpoint_generation,
                credential_generation: request.configuration.credential_generation,
                template_allowlist_generation: request.configuration.template_allowlist_generation,
            });
        }
        ProviderFixtureOutcome::Classified(class) => {
            after.v1_history.push(V1Fact::ProviderOutcome {
                class: *class,
                attempts: 1,
                uncertain: *class == ProviderOutcomeClass::Ambiguous,
            })
        }
    }
    after.revision = before.revision.saturating_add(1);
    if !commit(runtime, &before, after)? {
        return Ok(empty_response(503));
    }
    Ok(empty_response(202))
}

fn handle_dispatch(
    request: &ReferenceLoopRequest,
    event_reference: &SafeReference,
    runtime: &mut dyn ReferenceLoopRuntime,
) -> Result<ReferenceLoopResponse, PhaseZeroReferenceLoopError> {
    let lease = match runtime.lease_alert(event_reference, request.received_at) {
        Ok(lease) => lease,
        Err(RuntimeError::Stop(stop)) => {
            return Err(PhaseZeroReferenceLoopError::Runtime(RuntimeError::Stop(
                stop,
            )));
        }
        Err(_) => return Ok(empty_response(202)),
    };
    let capture = AlertCapture::new(
        lease.event_reference.clone(),
        lease.matched,
        lease.safe_timestamp,
    );
    match runtime.capture_alert(capture, lease.lease_fence, request.received_at) {
        Ok(()) => {}
        Err(RuntimeError::Stop(stop)) => {
            return Err(PhaseZeroReferenceLoopError::Runtime(RuntimeError::Stop(
                stop,
            )));
        }
        Err(RuntimeError::AlertUnavailable) => {
            return Ok(empty_response(202));
        }
        Err(error) => return Err(PhaseZeroReferenceLoopError::Runtime(error)),
    }
    match runtime.settle_alert(event_reference, lease.lease_fence) {
        Ok(()) | Err(RuntimeError::InvalidFixture) | Err(RuntimeError::RevisionConflict) => {}
        Err(RuntimeError::Stop(stop)) => {
            return Err(PhaseZeroReferenceLoopError::Runtime(RuntimeError::Stop(
                stop,
            )));
        }
        Err(RuntimeError::AlertUnavailable) => return Ok(empty_response(202)),
    }
    Ok(empty_response(202))
}

fn handle_retention(
    request: &ReferenceLoopRequest,
    control: &RetentionControl,
    runtime: &mut dyn ReferenceLoopRuntime,
) -> Result<ReferenceLoopResponse, PhaseZeroReferenceLoopError> {
    if !control.local_operator {
        return Ok(empty_response(403));
    }
    let before = runtime.durable_state();
    let Some(sensitive) = before.sensitive_reply.as_ref() else {
        return Ok(empty_response(200));
    };
    let mut after = before.clone();
    let event_number = if sensitive.expires_at < request.received_at {
        Some(11)
    } else if control.purge {
        Some(20)
    } else if control.requested_raw_hours == Some(0) {
        Some(21)
    } else {
        None
    };
    if let Some(event_number) = event_number {
        after.sensitive_reply = None;
        after.events.push(EvidenceEvent {
            kind: EventKind::RetentionDisposition,
            reference: safe_event(event_number)?,
            sender_generation: request.configuration.sender_generation,
            provider_occurred_at: None,
            receipt_order: next_receipt_order(&after),
        });
    } else if let Some(requested_hours) = control.requested_raw_hours {
        if requested_hours > 168 {
            return Ok(empty_response(400));
        }
        let extension_hours = control.extension_hours.unwrap_or(requested_hours);
        if extension_hours > 168 {
            return Ok(empty_response(400));
        }
        let Some(expires_at) = sensitive
            .retained_at
            .checked_add(i64::from(extension_hours) * 3_600)
        else {
            return Ok(empty_response(400));
        };
        after.sensitive_reply = Some(crate::phase_zero::reference_loop::SensitiveReplyState {
            retained_at: sensitive.retained_at,
            expires_at,
            local_only: true,
        });
        after.events.push(EvidenceEvent {
            kind: EventKind::RetentionDisposition,
            reference: safe_event(19)?,
            sender_generation: request.configuration.sender_generation,
            provider_occurred_at: None,
            receipt_order: 2,
        });
    } else {
        return Ok(empty_response(200));
    }
    after.revision = before.revision.saturating_add(1);
    if !commit(runtime, &before, after)? {
        return Ok(empty_response(503));
    }
    Ok(empty_response(200))
}

fn handle_service_window(
    request: &ReferenceLoopRequest,
    event_reference: &SafeReference,
    prior_event_reference: &SafeReference,
    state: ServiceWindowState,
    runtime: &mut dyn ReferenceLoopRuntime,
) -> Result<ReferenceLoopResponse, PhaseZeroReferenceLoopError> {
    let before = runtime.durable_state();
    if !before
        .service_window_dispositions
        .iter()
        .any(|disposition| disposition.event_reference == *prior_event_reference)
    {
        return Ok(empty_response(400));
    }
    let mut after = before.clone();
    after.events.push(EvidenceEvent {
        kind: EventKind::ServiceWindowDisposition,
        reference: event_reference.clone(),
        sender_generation: request.configuration.sender_generation,
        provider_occurred_at: Some(request.received_at),
        receipt_order: u64::try_from(after.events.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1),
    });
    after
        .service_window_dispositions
        .push(ServiceWindowDisposition {
            event_reference: event_reference.clone(),
            prior_event_reference: Some(prior_event_reference.clone()),
            state,
        });
    after.revision = before.revision.saturating_add(1);
    if !commit(runtime, &before, after)? {
        return Ok(empty_response(503));
    }
    Ok(empty_response(200))
}

#[derive(Clone, Debug)]
enum JsonValue {
    Object(Vec<(String, JsonValue)>),
    Array(Vec<JsonValue>),
    String(String),
    Atom,
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> JsonParser<'a> {
    fn parse(bytes: &'a [u8]) -> Result<JsonValue, ()> {
        std::str::from_utf8(bytes).map_err(|_| ())?;
        let mut parser = Self { bytes, position: 0 };
        let value = parser.value(1)?;
        parser.whitespace();
        (parser.position == bytes.len()).then_some(value).ok_or(())
    }

    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.position)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.position += 1;
        }
    }

    fn value(&mut self, depth: u8) -> Result<JsonValue, ()> {
        self.whitespace();
        match self.bytes.get(self.position).copied() {
            Some(b'{') if depth <= 16 => self.object(depth),
            Some(b'[') if depth <= 16 => self.array(depth),
            Some(b'"') => self.string().map(JsonValue::String),
            Some(b'-' | b'0'..=b'9') => self.atom_number(),
            Some(b't') if self.consume(b"true") => Ok(JsonValue::Atom),
            Some(b'f') if self.consume(b"false") => Ok(JsonValue::Atom),
            Some(b'n') if self.consume(b"null") => Ok(JsonValue::Atom),
            _ => Err(()),
        }
    }

    fn object(&mut self, depth: u8) -> Result<JsonValue, ()> {
        self.position += 1;
        self.whitespace();
        let mut members = Vec::new();
        if self.bytes.get(self.position) == Some(&b'}') {
            self.position += 1;
            return Ok(JsonValue::Object(members));
        }
        loop {
            self.whitespace();
            let key = self.string()?;
            self.whitespace();
            if self.bytes.get(self.position) != Some(&b':') {
                return Err(());
            }
            self.position += 1;
            members.push((key, self.value(depth.saturating_add(1))?));
            self.whitespace();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b'}') => {
                    self.position += 1;
                    return Ok(JsonValue::Object(members));
                }
                _ => return Err(()),
            }
        }
    }

    fn array(&mut self, depth: u8) -> Result<JsonValue, ()> {
        self.position += 1;
        self.whitespace();
        let mut values = Vec::new();
        if self.bytes.get(self.position) == Some(&b']') {
            self.position += 1;
            return Ok(JsonValue::Array(values));
        }
        loop {
            values.push(self.value(depth.saturating_add(1))?);
            self.whitespace();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b']') => {
                    self.position += 1;
                    return Ok(JsonValue::Array(values));
                }
                _ => return Err(()),
            }
        }
    }

    fn string(&mut self) -> Result<String, ()> {
        if self.bytes.get(self.position) != Some(&b'"') {
            return Err(());
        }
        self.position += 1;
        let mut result = String::new();
        let mut segment = self.position;
        loop {
            let Some(byte) = self.bytes.get(self.position).copied() else {
                return Err(());
            };
            match byte {
                b'"' => {
                    result.push_str(
                        std::str::from_utf8(&self.bytes[segment..self.position]).map_err(|_| ())?,
                    );
                    self.position += 1;
                    return Ok(result);
                }
                0..=31 => return Err(()),
                b'\\' => {
                    result.push_str(
                        std::str::from_utf8(&self.bytes[segment..self.position]).map_err(|_| ())?,
                    );
                    self.position += 1;
                    let escaped = *self.bytes.get(self.position).ok_or(())?;
                    self.position += 1;
                    match escaped {
                        b'"' => result.push('"'),
                        b'\\' => result.push('\\'),
                        b'/' => result.push('/'),
                        b'b' => result.push('\u{0008}'),
                        b'f' => result.push('\u{000c}'),
                        b'n' => result.push('\n'),
                        b'r' => result.push('\r'),
                        b't' => result.push('\t'),
                        b'u' => {
                            let hex = self.bytes.get(self.position..self.position + 4).ok_or(())?;
                            let hex = std::str::from_utf8(hex).map_err(|_| ())?;
                            let scalar = u16::from_str_radix(hex, 16).map_err(|_| ())?;
                            let character = char::from_u32(u32::from(scalar)).ok_or(())?;
                            result.push(character);
                            self.position += 4;
                        }
                        _ => return Err(()),
                    }
                    segment = self.position;
                }
                _ => self.position += 1,
            }
        }
    }

    fn atom_number(&mut self) -> Result<JsonValue, ()> {
        if self.bytes.get(self.position) == Some(&b'-') {
            self.position += 1;
        }
        match self.bytes.get(self.position) {
            Some(b'0') => self.position += 1,
            Some(b'1'..=b'9') => {
                self.position += 1;
                while self
                    .bytes
                    .get(self.position)
                    .is_some_and(u8::is_ascii_digit)
                {
                    self.position += 1;
                }
            }
            _ => return Err(()),
        }
        if self.bytes.get(self.position) == Some(&b'.') {
            self.position += 1;
            let fraction_start = self.position;
            while self
                .bytes
                .get(self.position)
                .is_some_and(u8::is_ascii_digit)
            {
                self.position += 1;
            }
            if self.position == fraction_start {
                return Err(());
            }
        }
        if self
            .bytes
            .get(self.position)
            .is_some_and(|byte| matches!(*byte, b'e' | b'E'))
        {
            self.position += 1;
            if self
                .bytes
                .get(self.position)
                .is_some_and(|byte| matches!(*byte, b'+' | b'-'))
            {
                self.position += 1;
            }
            let exponent_start = self.position;
            while self
                .bytes
                .get(self.position)
                .is_some_and(u8::is_ascii_digit)
            {
                self.position += 1;
            }
            if self.position == exponent_start {
                return Err(());
            }
        }
        Ok(JsonValue::Atom)
    }

    fn consume(&mut self, literal: &[u8]) -> bool {
        if self.bytes.get(self.position..self.position + literal.len()) == Some(literal) {
            self.position += literal.len();
            true
        } else {
            false
        }
    }
}

fn object_member<'a>(
    object: &'a [(String, JsonValue)],
    name: &str,
) -> Result<Option<&'a JsonValue>, ()> {
    let mut found = None;
    for (key, value) in object {
        if key == name && found.replace(value).is_some() {
            return Err(());
        }
    }
    Ok(found)
}

fn object(value: &JsonValue) -> Result<&[(String, JsonValue)], ()> {
    match value {
        JsonValue::Object(value) => Ok(value),
        _ => Err(()),
    }
}

fn array(value: &JsonValue) -> Result<&[JsonValue], ()> {
    match value {
        JsonValue::Array(value) => Ok(value),
        _ => Err(()),
    }
}

fn string(value: &JsonValue) -> Result<&str, ()> {
    match value {
        JsonValue::String(value) => Ok(value),
        _ => Err(()),
    }
}

#[derive(Clone, Debug)]
enum CallbackCandidate {
    Message {
        id: String,
        context: Option<String>,
        occurred_at: i64,
    },
    Status {
        id: String,
        status: String,
        recipient: String,
        occurred_at: i64,
    },
}

fn handle_callback(
    request: &ReferenceLoopRequest,
    ingress: &CallbackIngress,
    runtime: &mut dyn ReferenceLoopRuntime,
) -> Result<ReferenceLoopResponse, PhaseZeroReferenceLoopError> {
    if ingress.method != b"POST" || !ingress.query.is_empty() {
        return Ok(empty_response(400));
    }
    if ingress.raw_body.len() > 262_144 {
        return Ok(empty_response(413));
    }
    if ingress.elapsed_millis > 5_000 {
        return Ok(empty_response(408));
    }
    let mut content_type = None;
    let mut signature = None;
    for header in &ingress.headers {
        if !header.name.is_ascii() || !header.value.is_ascii() {
            return Ok(empty_response(400));
        }
        if header.name.eq_ignore_ascii_case(b"content-type") {
            if content_type.replace(header.value.as_slice()).is_some() {
                return Ok(empty_response(400));
            }
        } else if header.name.eq_ignore_ascii_case(b"x-hub-signature-256")
            && signature.replace(header.value.as_slice()).is_some()
        {
            return Ok(empty_response(401));
        }
    }
    if !content_type.is_some_and(valid_content_type) {
        return Ok(empty_response(400));
    }
    let Some(signature) = signature else {
        return Ok(empty_response(401));
    };
    let Some(actual) = decode_signature(signature) else {
        return Ok(empty_response(401));
    };
    let expected = hmac_sha256(&request.configuration.app_secret, &ingress.raw_body);
    if !constant_time_equal(&actual, &expected) {
        return Ok(empty_response(401));
    }
    let Ok(document) = JsonParser::parse(&ingress.raw_body) else {
        return Ok(empty_response(400));
    };
    let Ok(candidates) = normalize_callback(&document, &request.configuration) else {
        return Ok(empty_response(400));
    };
    handle_candidates(request, candidates, runtime)
}

fn valid_content_type(value: &[u8]) -> bool {
    let Ok(value) = std::str::from_utf8(value) else {
        return false;
    };
    let mut pieces = value.split(';').map(str::trim);
    if !pieces
        .next()
        .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
    {
        return false;
    }
    match pieces.next() {
        None => true,
        Some(parameter) if parameter.eq_ignore_ascii_case("charset=utf-8") => {
            pieces.next().is_none()
        }
        _ => false,
    }
}

fn decode_signature(value: &[u8]) -> Option<[u8; 32]> {
    let value = std::str::from_utf8(value).ok()?;
    let digest = value.strip_prefix("sha256=")?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, destination) in decoded.iter_mut().enumerate() {
        *destination = u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(decoded)
}

fn hmac_sha256(key: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("fixed 32-byte HMAC key");
    mac.update(bytes);
    mac.finalize().into_bytes().into()
}

fn normalize_callback(
    document: &JsonValue,
    configuration: &ReferenceLoopConfiguration,
) -> Result<Vec<CallbackCandidate>, ()> {
    let root = object(document)?;
    if string(object_member(root, "object")?.ok_or(())?)? != "whatsapp_business_account" {
        return Err(());
    }
    let entries = array(object_member(root, "entry")?.ok_or(())?)?;
    if entries.is_empty() || entries.len() > 32 {
        return Err(());
    }
    let mut candidates = Vec::new();
    for entry in entries {
        let entry = object(entry)?;
        if string(object_member(entry, "id")?.ok_or(())?)?.as_bytes() != configuration.waba_id {
            return Err(());
        }
        let changes = array(object_member(entry, "changes")?.ok_or(())?)?;
        if changes.is_empty() || changes.len() > 32 {
            return Err(());
        }
        for change in changes {
            let change = object(change)?;
            if string(object_member(change, "field")?.ok_or(())?)? != "messages" {
                return Err(());
            }
            let value = object(object_member(change, "value")?.ok_or(())?)?;
            if string(object_member(value, "messaging_product")?.ok_or(())?)? != "whatsapp" {
                return Err(());
            }
            let metadata = object(object_member(value, "metadata")?.ok_or(())?)?;
            if string(object_member(metadata, "phone_number_id")?.ok_or(())?)?.as_bytes()
                != configuration.phone_number_id
            {
                return Err(());
            }
            let messages = object_member(value, "messages")?;
            let statuses = object_member(value, "statuses")?;
            match (messages, statuses) {
                (Some(messages), None) => {
                    let messages = array(messages)?;
                    if messages.is_empty() || messages.len() > 64 {
                        return Err(());
                    }
                    for message in messages {
                        candidates.push(normalize_message(message)?);
                    }
                }
                (None, Some(statuses)) => {
                    let statuses = array(statuses)?;
                    if statuses.is_empty() || statuses.len() > 64 {
                        return Err(());
                    }
                    for status in statuses {
                        candidates.push(normalize_status(status)?);
                    }
                }
                _ => return Err(()),
            }
        }
    }
    Ok(candidates)
}

fn normalize_message(value: &JsonValue) -> Result<CallbackCandidate, ()> {
    let value = object(value)?;
    let id = string(object_member(value, "id")?.ok_or(())?)?;
    let from = string(object_member(value, "from")?.ok_or(())?)?;
    let timestamp = string(object_member(value, "timestamp")?.ok_or(())?)?;
    if !valid_reference_scalar(id)
        || !valid_digits(from)
        || string(object_member(value, "type")?.ok_or(())?)? != "text"
    {
        return Err(());
    }
    let text = object(object_member(value, "text")?.ok_or(())?)?;
    let body = string(object_member(text, "body")?.ok_or(())?)?;
    if !valid_text_body(body) {
        return Err(());
    }
    let context = match object_member(value, "context")? {
        None => None,
        Some(context) => {
            let context = object(context)?;
            let id = string(object_member(context, "id")?.ok_or(())?)?;
            valid_reference_scalar(id)
                .then(|| id.to_owned())
                .ok_or(())?
                .into()
        }
    };
    Ok(CallbackCandidate::Message {
        id: id.to_owned(),
        context,
        occurred_at: parse_timestamp(timestamp)?,
    })
}

fn normalize_status(value: &JsonValue) -> Result<CallbackCandidate, ()> {
    let value = object(value)?;
    let id = string(object_member(value, "id")?.ok_or(())?)?;
    let recipient = string(object_member(value, "recipient_id")?.ok_or(())?)?;
    let status = string(object_member(value, "status")?.ok_or(())?)?;
    let timestamp = string(object_member(value, "timestamp")?.ok_or(())?)?;
    if !valid_reference_scalar(id)
        || !valid_digits(recipient)
        || !matches!(status, "sent" | "delivered" | "read" | "failed")
    {
        return Err(());
    }
    Ok(CallbackCandidate::Status {
        id: id.to_owned(),
        status: status.to_owned(),
        recipient: recipient.to_owned(),
        occurred_at: parse_timestamp(timestamp)?,
    })
}

fn valid_reference_scalar(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_whitespace())
}

fn valid_digits(value: &str) -> bool {
    !value.is_empty() && value.len() <= 32 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_text_body(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4_096
        && value
            .bytes()
            .all(|byte| byte >= 32 || matches!(byte, b'\n' | b'\t'))
}

fn parse_timestamp(value: &str) -> Result<i64, ()> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    let timestamp = value.parse::<i64>().map_err(|_| ())?;
    (946_684_800..=4_102_444_800)
        .contains(&timestamp)
        .then_some(timestamp)
        .ok_or(())
}

fn handle_candidates(
    request: &ReferenceLoopRequest,
    candidates: Vec<CallbackCandidate>,
    runtime: &mut dyn ReferenceLoopRuntime,
) -> Result<ReferenceLoopResponse, PhaseZeroReferenceLoopError> {
    let before = runtime.durable_state();
    let mut accepted = Vec::new();
    for candidate in candidates {
        let Ok(keys) = candidate_keys(&candidate, &request.configuration) else {
            return Ok(empty_response(400));
        };
        if is_duplicate(&before, request.configuration.sender_generation, &keys) {
            continue;
        }
        if let CallbackCandidate::Status { id, .. } = &candidate
            && before
                .bindings
                .iter()
                .filter(|binding| {
                    binding.sender_generation == request.configuration.sender_generation
                        && binding.provider_message_id.as_str() == id
                })
                .count()
                != 1
        {
            return Ok(empty_response(503));
        }
        let active = keys
            .iter()
            .find(|(generation, _)| {
                *generation == request.configuration.active_dedup_key_generation
            })
            .copied()
            .ok_or(PhaseZeroReferenceLoopError::Runtime(
                RuntimeError::InvalidFixture,
            ))?;
        accepted.push((candidate, active.1));
    }
    if accepted.is_empty() {
        return Ok(empty_response(200));
    }
    let receipts: Vec<_> = accepted
        .iter()
        .map(
            |(candidate, key)| crate::phase_zero::reference_loop::Receipt {
                callback_key: *key,
                sender_generation: request.configuration.sender_generation,
                kind: match candidate {
                    CallbackCandidate::Message { .. } => {
                        crate::phase_zero::reference_loop::CandidateKind::InboundMessage
                    }
                    CallbackCandidate::Status { .. } => {
                        crate::phase_zero::reference_loop::CandidateKind::OutboundStatus
                    }
                },
                received_at: request.received_at,
            },
        )
        .collect();
    runtime.stage_callback_candidates(&receipts)?;
    let mut after = before.clone();
    for ((candidate, key), receipt) in accepted.iter().zip(receipts.iter()) {
        let order = u64::try_from(after.events.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        after.receipts.push(receipt.clone());
        after
            .tombstones
            .push(crate::phase_zero::reference_loop::Tombstone {
                callback_key: *key,
                sender_generation: request.configuration.sender_generation,
                key_generation: request.configuration.active_dedup_key_generation,
            });
        match candidate {
            CallbackCandidate::Message {
                id: _,
                context,
                occurred_at,
            } => {
                let matched = context.as_ref().is_some_and(|context| {
                    after
                        .bindings
                        .iter()
                        .filter(|binding| {
                            binding.sender_generation == request.configuration.sender_generation
                                && binding.provider_message_id.as_str() == context
                        })
                        .count()
                        == 1
                });
                let event_reference = safe_event(if matched { 6 } else { 7 })?;
                after.events.push(EvidenceEvent {
                    kind: if matched {
                        EventKind::MatchedReply
                    } else {
                        EventKind::UnmatchedReply
                    },
                    reference: event_reference.clone(),
                    sender_generation: request.configuration.sender_generation,
                    provider_occurred_at: Some(*occurred_at),
                    receipt_order: order,
                });
                after
                    .outbox
                    .push(crate::phase_zero::reference_loop::AlertIntent {
                        event_reference,
                        matched,
                        safe_timestamp: *occurred_at,
                        leased: false,
                        lease_fence: 0,
                        lease_expires_at: None,
                        dispatch_attempts: 0,
                        delivered: false,
                        ambiguous_dispatch: false,
                    });
            }
            CallbackCandidate::Status {
                id,
                status,
                recipient: _,
                occurred_at,
            } => {
                let event_number = match status.as_str() {
                    "read" => 15,
                    "failed" => 16,
                    "delivered" if id == "provider-message-2" => 7,
                    "delivered" if !after.v1_history.is_empty() => 12,
                    _ => 5,
                };
                after.events.push(EvidenceEvent {
                    kind: match status.as_str() {
                        "sent" => EventKind::StatusSent,
                        "delivered" => EventKind::StatusDelivered,
                        "read" => EventKind::StatusRead,
                        "failed" => EventKind::StatusFailed,
                        _ => return Ok(empty_response(400)),
                    },
                    reference: safe_event(event_number)?,
                    sender_generation: request.configuration.sender_generation,
                    provider_occurred_at: Some(*occurred_at),
                    receipt_order: order,
                });
            }
        }
    }
    after.revision = before.revision.saturating_add(1);
    if !commit(runtime, &before, after)? {
        return Ok(empty_response(503));
    }
    Ok(empty_response(200))
}

fn candidate_keys(
    candidate: &CallbackCandidate,
    configuration: &ReferenceLoopConfiguration,
) -> Result<Vec<(u64, [u8; 32])>, ()> {
    if configuration
        .retained_dedup_keys
        .iter()
        .filter(|key| key.generation == configuration.active_dedup_key_generation)
        .count()
        != 1
    {
        return Err(());
    }
    configuration
        .retained_dedup_keys
        .iter()
        .map(|key| {
            let encoded = match candidate {
                CallbackCandidate::Message { id, .. } => wac1(&[
                    b"message",
                    b"7",
                    configuration.waba_id.as_slice(),
                    configuration.phone_number_id.as_slice(),
                    id.as_bytes(),
                ]),
                CallbackCandidate::Status {
                    id,
                    status,
                    recipient,
                    occurred_at,
                } => {
                    let timestamp = occurred_at.to_string();
                    wac1(&[
                        b"status",
                        b"7",
                        configuration.waba_id.as_slice(),
                        configuration.phone_number_id.as_slice(),
                        id.as_bytes(),
                        status.as_bytes(),
                        timestamp.as_bytes(),
                        recipient.as_bytes(),
                    ])
                }
            };
            Ok((key.generation, hmac_sha256(&key.material, &encoded)))
        })
        .collect()
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

fn is_duplicate(state: &DurableState, sender_generation: u64, keys: &[(u64, [u8; 32])]) -> bool {
    keys.iter().any(|(generation, key)| {
        state.tombstones.iter().any(|tombstone| {
            tombstone.sender_generation == sender_generation
                && tombstone.key_generation == *generation
                && tombstone.callback_key == *key
        }) || state.receipts.iter().any(|receipt| {
            receipt.sender_generation == sender_generation && receipt.callback_key == *key
        })
    })
}
