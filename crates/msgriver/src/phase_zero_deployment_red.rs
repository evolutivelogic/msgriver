//! Frozen RED for the private Phase 0B deployment boundary.
//!
//! Entry points select authority: tests cannot assert a role through a generic
//! request and the missing implementation sees only one role facade at once.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::phase_zero::deployment::{
    AlertIntentState, CredentialStartRequest, DeniedResourceAttempt, DeploymentBoundaryError,
    DeploymentBoundaryPort, DeploymentObservation, DeploymentResponse, DeploymentState,
    DiagnosticArtifact, DispatchOperation, DispatchTransportResult, DispatcherRequest,
    DispatcherRuntime, Header, IngressDeniedAttempt, IngressEvent, IngressRequest, IngressRuntime,
    LeaseResult, LifecycleEvent, LifecycleOperation, LifecycleRequest, LifecycleRuntime, Method,
    NetworkAttempt, NtfyAclRequest, NtfyAclRules, NtfyAclRuntime, NtfyAction, NtfyPrincipal,
    OutboundOperation, OutboundRequest, OutboundRuntime, QueryParameter, RestoreEnvironment,
    RestoreRequest, SafeDisposition, SettlementResult, TopicScope, deployment_boundary,
};

#[derive(Clone, Debug)]
struct FixtureRuntime {
    state: DeploymentState,
    publisher_outcome: DispatchTransportResult,
    publisher_ledger: PublisherLedger,
    resource_ledger: ResourceLedger,
    ingress_ledger: IngressLedger,
    lifecycle_ledger: LifecycleLedger,
    restore_environment: RestoreEnvironment,
}

/// Transport-owned evidence: a boundary can request a publish but cannot
/// replace these counters through the dispatcher state facade.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct PublisherLedger {
    attempts: u32,
    acceptances: u32,
}

/// Separate typed resource witnesses. The fixture stores only counts, not
/// evidence bytes or topic content, and no role state replacement can alter
/// them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ResourceLedger {
    evidence_reads: u32,
    configured_topic_reads: u32,
    denied_attempts: Vec<DeniedResourceAttempt>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct IngressLedger {
    events: Vec<IngressEvent>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct LifecycleLedger {
    events: Vec<LifecycleEvent>,
}

impl FixtureRuntime {
    fn snapshot(&self) -> DeploymentState {
        self.state.clone()
    }
}
impl IngressRuntime for FixtureRuntime {
    fn verify_raw_callback_hmac(&mut self, request: &IngressRequest) -> bool {
        self.ingress_ledger.events.push(IngressEvent::MacChecked);
        self.state.ingress.verification_attempts += 1;
        let mut mac = Hmac::<Sha256>::new_from_slice(&request.app_secret)
            .expect("fixed-width fixture HMAC key");
        mac.update(&request.raw_body);
        let expected = format!(
            "sha256={}",
            mac.finalize()
                .into_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let verified = request.headers.iter().any(|header| {
            header.name == b"x-hub-signature-256" && header.value == expected.as_bytes()
        });
        if verified {
            self.ingress_ledger.events.push(IngressEvent::MacVerified);
        }
        verified
    }
    fn parse_verified_callback(&mut self) -> bool {
        if self.ingress_ledger.events.last() != Some(&IngressEvent::MacVerified) {
            return false;
        }
        self.ingress_ledger.events.push(IngressEvent::Parsed);
        self.state.ingress.parser_attempts += 1;
        true
    }
    fn propose_verified_transaction(&mut self) -> bool {
        if self.ingress_ledger.events.last() != Some(&IngressEvent::Parsed) {
            return false;
        }
        self.ingress_ledger
            .events
            .push(IngressEvent::TransactionProposed);
        self.state.ingress.transaction_attempts += 1;
        self.state.ingress.safe_events += 1;
        self.state.ingress.alert_intents += 1;
        true
    }
    fn record_denied_ingress_resource(&mut self, attempt: DeniedResourceAttempt) {
        assert!(matches!(
            attempt,
            DeniedResourceAttempt::IngressAlertIntentPublish
                | DeniedResourceAttempt::IngressSharedStoreBypass
                | DeniedResourceAttempt::IngressDeserializedHandleBypass
        ));
        self.resource_ledger.denied_attempts.push(attempt);
    }
}
impl OutboundRuntime for FixtureRuntime {
    fn accept_exact_registered_command(&mut self, request: &OutboundRequest) -> bool {
        if request.operation != OutboundOperation::ReadExactRegisteredCommand
            || request.credential_in_wrong_role
            || self.state.outbound.registered_commands == 0
        {
            return false;
        }
        self.state.outbound.provider_attempt_records += 1;
        true
    }
    fn read_evidence_sentinel(&mut self) {
        self.resource_ledger.evidence_reads += 1;
    }
    fn record_denied_outbound_resource(&mut self, attempt: DeniedResourceAttempt) {
        assert!(matches!(
            attempt,
            DeniedResourceAttempt::OutboundEvidenceRead
                | DeniedResourceAttempt::OutboundEvidenceMutate
                | DeniedResourceAttempt::OutboundAlertIntentRead
                | DeniedResourceAttempt::OutboundAlertIntentWrite
                | DeniedResourceAttempt::OutboundSharedStoreBypass
                | DeniedResourceAttempt::OutboundDeserializedHandleBypass
        ));
        self.resource_ledger.denied_attempts.push(attempt);
    }
}
impl DispatcherRuntime for FixtureRuntime {
    fn acquire_safe_intent_lease(&mut self, requested_fence: u64) -> LeaseResult {
        let Some(intent) = self.state.dispatcher.alert_intent.as_mut() else {
            return LeaseResult::Denied;
        };
        if intent.leased
            || intent.delivered
            || intent.ambiguous
            || intent.attempts >= intent.retry_limit
            || requested_fence <= intent.lease_fence
        {
            return LeaseResult::Denied;
        }
        intent.lease_fence = requested_fence;
        intent.leased = true;
        LeaseResult::Acquired
    }
    fn settle_safe_intent(&mut self, requested_fence: u64) -> SettlementResult {
        let Some(intent) = self.state.dispatcher.alert_intent.as_ref() else {
            return SettlementResult::Denied;
        };
        if intent.delivered {
            return SettlementResult::Delivered;
        }
        if intent.ambiguous {
            return SettlementResult::Ambiguous;
        }
        if intent.attempts >= intent.retry_limit {
            return SettlementResult::Exhausted;
        }
        let permitted = if intent.leased {
            requested_fence == intent.lease_fence
        } else {
            intent
                .lease_fence
                .checked_add(1)
                .is_some_and(|next_fence| requested_fence == next_fence)
        };
        if !permitted {
            return SettlementResult::Denied;
        }
        if self.publisher_outcome == DispatchTransportResult::CrashBeforeAttempt {
            return SettlementResult::Retryable;
        }

        let intent = self
            .state
            .dispatcher
            .alert_intent
            .as_mut()
            .expect("intent checked above");
        intent.lease_fence = requested_fence;
        intent.leased = true;
        match self.publisher_outcome {
            DispatchTransportResult::DefiniteRefusal => {
                self.publisher_ledger.attempts += 1;
                intent.attempts += 1;
                intent.leased = false;
                if intent.attempts >= intent.retry_limit {
                    SettlementResult::Exhausted
                } else {
                    SettlementResult::Retryable
                }
            }
            DispatchTransportResult::Accepted => {
                self.publisher_ledger.attempts += 1;
                self.publisher_ledger.acceptances += 1;
                intent.attempts += 1;
                intent.delivered = true;
                intent.leased = false;
                self.state.dispatcher.published_alerts += 1;
                SettlementResult::Delivered
            }
            DispatchTransportResult::CrashAfterAcceptedPublish => {
                self.publisher_ledger.attempts += 1;
                self.publisher_ledger.acceptances += 1;
                intent.attempts += 1;
                intent.ambiguous = true;
                SettlementResult::Ambiguous
            }
            DispatchTransportResult::CrashBeforeAttempt => unreachable!("returned above"),
        }
    }
    fn is_stale_lease_fence(&self, requested_fence: u64) -> bool {
        self.state
            .dispatcher
            .alert_intent
            .as_ref()
            .filter(|intent| intent.leased)
            .is_some_and(|intent| requested_fence < intent.lease_fence)
    }
    fn attempt_safe_publish(&mut self) -> DispatchTransportResult {
        match self.publisher_outcome {
            DispatchTransportResult::CrashBeforeAttempt => {}
            DispatchTransportResult::DefiniteRefusal => {
                self.publisher_ledger.attempts += 1;
            }
            DispatchTransportResult::Accepted
            | DispatchTransportResult::CrashAfterAcceptedPublish => {
                self.publisher_ledger.attempts += 1;
                self.publisher_ledger.acceptances += 1;
            }
        }
        self.publisher_outcome
    }
    fn record_denied_dispatcher_resource(&mut self, attempt: DeniedResourceAttempt) {
        assert!(matches!(
            attempt,
            DeniedResourceAttempt::DispatcherRegisteredCommandRead
                | DeniedResourceAttempt::DispatcherRegisteredCommandMutate
                | DeniedResourceAttempt::DispatcherProviderCredentialRead
                | DeniedResourceAttempt::DispatcherEvidenceMutate
                | DeniedResourceAttempt::DispatcherSharedStoreBypass
                | DeniedResourceAttempt::DispatcherDeserializedHandleBypass
        ));
        self.resource_ledger.denied_attempts.push(attempt);
    }
}
impl NtfyAclRuntime for FixtureRuntime {
    fn evaluate_private_acl(&mut self, request: NtfyAclRequest) -> bool {
        if request.rules != NtfyAclRules::exact_private() {
            return false;
        }
        match (request.principal, request.action, request.topic) {
            (NtfyPrincipal::ConfiguredPublisher, NtfyAction::Publish, TopicScope::Configured) => {
                self.state.ntfy_acl.configured_publish_observations += 1;
                true
            }
            (NtfyPrincipal::ConfiguredReader, NtfyAction::Read, TopicScope::Configured) => {
                self.state.ntfy_acl.configured_read_observations += 1;
                true
            }
            _ => false,
        }
    }
    fn read_configured_topic_sentinel(&mut self) {
        self.resource_ledger.configured_topic_reads += 1;
    }
}
impl LifecycleRuntime for FixtureRuntime {
    fn start_current_credential(&mut self, request: CredentialStartRequest) -> bool {
        if request.in_arguments
            || request.in_environment
            || request.broad_file_access
            || request.mounted_file_access
            || request.wrong_role_mount
            || request.presented_generation != self.state.lifecycle.credential_generation
            || self
                .state
                .lifecycle
                .revoked_credential_generations
                .contains(&request.presented_generation)
        {
            return false;
        }
        self.state.lifecycle.credential_start_records += 1;
        true
    }
    fn restore_activation_is_inactive(&self) -> bool {
        let lifecycle = &self.state.lifecycle;
        !lifecycle.route_enabled
            && !lifecycle.service_unit_enabled
            && !lifecycle.scheduler_enabled
            && !lifecycle.sender_generation_active
            && !lifecycle.credential_generation_active
            && !lifecycle.alert_publisher_active
    }
    fn enter_restore_quarantine(&mut self) -> bool {
        if self.state.lifecycle.restore_state_opened {
            return false;
        }
        self.state.lifecycle.restore_quarantined = true;
        self.lifecycle_ledger
            .events
            .push(LifecycleEvent::RestoreQuarantined);
        true
    }
    fn quarantine_raw_restore_copy(&mut self) -> bool {
        if !self.restore_environment.raw_record_expired
            && !self.restore_environment.raw_record_opted_out
        {
            return false;
        }
        self.state.lifecycle.restore_quarantined = true;
        self.state.lifecycle.raw_restore_copies = 0;
        self.state.lifecycle.safe_restore_dispositions += 1;
        self.lifecycle_ledger
            .events
            .push(LifecycleEvent::RestoreQuarantined);
        self.lifecycle_ledger
            .events
            .push(LifecycleEvent::RawCopyWithheld);
        true
    }
    fn contain_secret_artifact(&mut self) -> bool {
        if !self.state.lifecycle.secret_diagnostic_artifact_present {
            return false;
        }
        let generation = self.state.lifecycle.credential_generation;
        self.state.lifecycle.secret_diagnostic_artifact_present = false;
        self.state.lifecycle.safe_incidents += 1;
        self.state.lifecycle.credential_generation += 1;
        self.state
            .lifecycle
            .revoked_credential_generations
            .push(generation);
        self.lifecycle_ledger.events.extend([
            LifecycleEvent::SecretArtifactDetected,
            LifecycleEvent::SecretArtifactDeleted,
            LifecycleEvent::CredentialGenerationRevoked,
        ]);
        true
    }
    fn open_quarantined_restore(&mut self) -> bool {
        if !self.state.lifecycle.restore_quarantined
            || self.restore_environment.network_available
            || self.restore_environment.credential_mounted
            || self.restore_environment.scheduler_enabled
        {
            return false;
        }
        self.state.lifecycle.restore_state_opened = true;
        self.lifecycle_ledger
            .events
            .push(LifecycleEvent::RestoreStateOpened);
        true
    }
    fn complete_rollback(&mut self) -> bool {
        let lifecycle = &self.state.lifecycle;
        if lifecycle.route_enabled
            || lifecycle.service_unit_enabled
            || lifecycle.scheduler_enabled
            || lifecycle.sender_generation_active
            || lifecycle.credential_generation_active
            || lifecycle.alert_publisher_active
        {
            return false;
        }
        self.lifecycle_ledger
            .events
            .push(LifecycleEvent::RollbackCompleted);
        true
    }
    fn fault_accept_revoked_credential_start(&mut self) -> bool {
        let generation = self.state.lifecycle.credential_generation;
        if !self
            .state
            .lifecycle
            .revoked_credential_generations
            .contains(&generation)
        {
            return false;
        }
        self.state.lifecycle.credential_start_records += 1;
        true
    }
    fn fault_open_quarantined_restore(&mut self) -> bool {
        if !self.state.lifecycle.restore_quarantined || self.state.lifecycle.restore_state_opened {
            return false;
        }
        self.state.lifecycle.restore_state_opened = true;
        true
    }
    fn fault_disable_route_without_rollback(&mut self) -> bool {
        if !self.state.lifecycle.route_enabled {
            return false;
        }
        self.state.lifecycle.route_enabled = false;
        true
    }
    fn fault_store_sensitive_diagnostic(&mut self) -> bool {
        if self.state.lifecycle.secret_diagnostic_artifact_present {
            return false;
        }
        self.state.lifecycle.secret_diagnostic_artifact_present = true;
        true
    }
    fn restore_environment(&self) -> RestoreEnvironment {
        self.restore_environment
    }
}

fn state() -> DeploymentState {
    DeploymentState {
        lifecycle: crate::phase_zero::deployment::LifecycleState {
            credential_generation: 1,
            secret_diagnostic_artifact_present: false,
            safe_incidents: 0,
            revoked_credential_generations: Vec::new(),
            restore_quarantined: false,
            restore_state_opened: false,
            raw_restore_copies: 0,
            safe_restore_dispositions: 0,
            retention_anchor: 17,
            sender_generation: 7,
            route_enabled: true,
            service_unit_enabled: true,
            scheduler_enabled: true,
            sender_generation_active: true,
            credential_generation_active: true,
            credential_start_records: 0,
            alert_publisher_active: true,
        },
        ..DeploymentState::default()
    }
}
fn alert_intent() -> AlertIntentState {
    AlertIntentState {
        lease_fence: 0,
        leased: false,
        attempts: 0,
        delivered: false,
        ambiguous: false,
        retry_limit: 3,
    }
}
fn state_with_intent() -> DeploymentState {
    let mut value = state();
    value.dispatcher.alert_intent = Some(alert_intent());
    value
}
fn rollback_ready_state() -> DeploymentState {
    let mut value = state();
    value.lifecycle.route_enabled = false;
    value.lifecycle.service_unit_enabled = false;
    value.lifecycle.scheduler_enabled = false;
    value.lifecycle.sender_generation_active = false;
    value.lifecycle.credential_generation_active = false;
    value.lifecycle.alert_publisher_active = false;
    value
}
fn observation(disposition: SafeDisposition) -> DeploymentObservation {
    let status = match disposition {
        SafeDisposition::ChallengeAccepted | SafeDisposition::CallbackAccepted => 200,
        SafeDisposition::RegisteredCommandAccepted
        | SafeDisposition::NtfyAllowed
        | SafeDisposition::IntentRetryable
        | SafeDisposition::IntentAmbiguous
        | SafeDisposition::CredentialStartAccepted
        | SafeDisposition::RestoreOpened
        | SafeDisposition::RollbackComplete => 202,
        SafeDisposition::RoleDenied | SafeDisposition::NtfyDenied => 403,
        SafeDisposition::IntentExhausted
        | SafeDisposition::Rejected
        | SafeDisposition::RestoreQuarantined
        | SafeDisposition::FaultDetected => 400,
    };
    DeploymentObservation {
        disposition,
        response: DeploymentResponse {
            status,
            body: Vec::new(),
        },
    }
}
fn challenge() -> DeploymentObservation {
    DeploymentObservation {
        disposition: SafeDisposition::ChallengeAccepted,
        response: DeploymentResponse {
            status: 200,
            body: b"fixture-challenge".to_vec(),
        },
    }
}
fn ingress(mutator: impl FnOnce(&mut IngressRequest)) -> IngressRequest {
    let mut value = IngressRequest::challenge();
    mutator(&mut value);
    value
}
fn outbound(operation: OutboundOperation) -> OutboundRequest {
    OutboundRequest {
        operation,
        credential_in_wrong_role: false,
    }
}
fn dispatcher(operation: DispatchOperation) -> DispatcherRequest {
    DispatcherRequest {
        operation,
        requested_fence: 0,
    }
}
fn acl(principal: NtfyPrincipal, action: NtfyAction, topic: TopicScope) -> NtfyAclRequest {
    NtfyAclRequest {
        principal,
        action,
        topic,
        rules: NtfyAclRules::exact_private(),
    }
}
fn lifecycle(operation: LifecycleOperation) -> LifecycleRequest {
    LifecycleRequest { operation }
}
fn credential(mutator: impl FnOnce(&mut CredentialStartRequest)) -> CredentialStartRequest {
    let mut request = CredentialStartRequest {
        presented_generation: 1,
        ..CredentialStartRequest::default()
    };
    mutator(&mut request);
    request
}
fn restore(mutator: impl FnOnce(&mut RestoreRequest)) -> RestoreRequest {
    let mut request = RestoreRequest {
        requested_generation: 7,
        ..RestoreRequest::default()
    };
    mutator(&mut request);
    request
}
fn restore_environment(mutator: impl FnOnce(&mut RestoreEnvironment)) -> RestoreEnvironment {
    let mut environment = RestoreEnvironment {
        snapshot_generation: 7,
        ..RestoreEnvironment::default()
    };
    mutator(&mut environment);
    environment
}

fn signature(body: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&[0x6b; 32]).expect("fixed fixture key");
    mac.update(body);
    let encoded: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("sha256={encoded}").into_bytes()
}
fn signed_post() -> IngressRequest {
    let body = br#"{"object":"whatsapp_business_account","entry":[{"id":"fixture-waba-7","changes":[{"field":"messages","value":{"messaging_product":"whatsapp","metadata":{"phone_number_id":"fixture-phone-8"},"messages":[{"id":"inbound-1","from":"5511","timestamp":"1710000000","type":"text","text":{"body":"hello"}}]}}]}]}"#.to_vec();
    ingress(|value| {
        value.method = Method::Post;
        value.raw_body = body.clone();
        value.query_parameters.clear();
        value.headers = vec![
            Header {
                name: b"content-type".to_vec(),
                value: b"application/json; charset=utf-8".to_vec(),
            },
            Header {
                name: b"x-hub-signature-256".to_vec(),
                value: signature(&body),
            },
        ];
    })
}
fn post(mutator: impl FnOnce(&mut IngressRequest)) -> IngressRequest {
    let mut value = signed_post();
    mutator(&mut value);
    value
}

#[derive(Clone)]
enum BoundaryCall {
    Ingress(IngressRequest),
    Outbound(OutboundRequest),
    Dispatcher(DispatcherRequest),
    Acl(NtfyAclRequest),
    Lifecycle(LifecycleRequest),
}
#[derive(Clone)]
struct Contract {
    call: BoundaryCall,
    before: DeploymentState,
    expected: DeploymentObservation,
    expected_state: DeploymentState,
    publisher_outcome: DispatchTransportResult,
    expected_publisher: PublisherLedger,
    expected_resources: ResourceLedger,
    expected_ingress: IngressLedger,
    expected_lifecycle: LifecycleLedger,
    restore_environment: RestoreEnvironment,
}
fn contract(
    call: BoundaryCall,
    before: DeploymentState,
    expected: DeploymentObservation,
    expected_state: DeploymentState,
) -> Contract {
    Contract {
        call,
        before,
        expected,
        expected_state,
        publisher_outcome: DispatchTransportResult::Accepted,
        expected_publisher: PublisherLedger::default(),
        expected_resources: ResourceLedger::default(),
        expected_ingress: IngressLedger::default(),
        expected_lifecycle: LifecycleLedger::default(),
        restore_environment: restore_environment(|_| {}),
    }
}
impl Contract {
    fn with_publisher_outcome(mut self, publisher_outcome: DispatchTransportResult) -> Self {
        self.publisher_outcome = publisher_outcome;
        self
    }
    fn with_expected_publisher(mut self, expected_publisher: PublisherLedger) -> Self {
        self.expected_publisher = expected_publisher;
        self
    }
    fn with_expected_ingress(mut self, expected_ingress: IngressLedger) -> Self {
        self.expected_ingress = expected_ingress;
        self
    }
    fn with_expected_lifecycle(mut self, expected_lifecycle: LifecycleLedger) -> Self {
        self.expected_lifecycle = expected_lifecycle;
        self
    }
    fn with_restore_environment(mut self, restore_environment: RestoreEnvironment) -> Self {
        self.restore_environment = restore_environment;
        self
    }
}

fn run(
    boundary: &mut dyn DeploymentBoundaryPort,
    call: &BoundaryCall,
    runtime: &mut FixtureRuntime,
) -> Result<DeploymentObservation, DeploymentBoundaryError> {
    match call {
        BoundaryCall::Ingress(request) => boundary.evaluate_ingress(request, runtime),
        BoundaryCall::Outbound(request) => boundary.evaluate_outbound(request, runtime),
        BoundaryCall::Dispatcher(request) => boundary.evaluate_dispatcher(request, runtime),
        BoundaryCall::Acl(request) => boundary.evaluate_ntfy_acl(*request, runtime),
        BoundaryCall::Lifecycle(request) => boundary.evaluate_lifecycle(*request, runtime),
    }
}
fn require_missing_contracts(contracts: impl IntoIterator<Item = Contract>) {
    let mut saw_missing_frontier = false;
    for Contract {
        call,
        before,
        expected,
        expected_state,
        publisher_outcome,
        expected_publisher,
        expected_resources,
        expected_ingress,
        expected_lifecycle,
        restore_environment,
    } in contracts
    {
        let mut runtime = FixtureRuntime {
            state: before.clone(),
            publisher_outcome,
            publisher_ledger: PublisherLedger::default(),
            resource_ledger: ResourceLedger::default(),
            ingress_ledger: IngressLedger::default(),
            lifecycle_ledger: LifecycleLedger::default(),
            restore_environment,
        };
        match run(&mut deployment_boundary(), &call, &mut runtime) {
            Err(DeploymentBoundaryError::MissingDeploymentBoundary) => {
                assert_eq!(
                    runtime.snapshot(),
                    before,
                    "missing boundary must not mutate fixture state"
                );
                assert_eq!(runtime.publisher_ledger, PublisherLedger::default());
                assert_eq!(runtime.resource_ledger, ResourceLedger::default());
                assert_eq!(runtime.ingress_ledger, IngressLedger::default());
                assert_eq!(runtime.lifecycle_ledger, LifecycleLedger::default());
                assert_eq!(runtime.restore_environment, restore_environment);
                saw_missing_frontier = true;
            }
            Ok(actual) => {
                assert_eq!(actual, expected, "independent deployment observation");
                assert_eq!(
                    runtime.snapshot(),
                    expected_state,
                    "only the selected role facade may mutate state"
                );
                assert_eq!(runtime.publisher_ledger, expected_publisher);
                assert_eq!(runtime.resource_ledger, expected_resources);
                assert_eq!(runtime.ingress_ledger, expected_ingress);
                assert_eq!(runtime.lifecycle_ledger, expected_lifecycle);
                assert_eq!(runtime.restore_environment, restore_environment);
            }
        }
    }
    assert!(
        !saw_missing_frontier,
        "MissingDeploymentBoundary: deployment boundary is intentionally RED"
    );
}

/// A future GREEN boundary must carry state and publisher evidence through all
/// steps. In the current RED, the first missing entrypoint is the only
/// permitted frontier and must leave that shared fixture untouched.
fn require_missing_sequence(steps: impl IntoIterator<Item = Contract>) {
    let mut runtime: Option<FixtureRuntime> = None;
    let mut expected_publisher_before = PublisherLedger::default();
    let mut expected_resources_before = ResourceLedger::default();
    let mut expected_ingress_before = IngressLedger::default();
    let mut expected_lifecycle_before = LifecycleLedger::default();
    let mut saw_missing_frontier = false;
    for Contract {
        call,
        before,
        expected,
        expected_state,
        publisher_outcome,
        expected_publisher,
        expected_resources,
        expected_ingress,
        expected_lifecycle,
        restore_environment,
    } in steps
    {
        let fixture = runtime.get_or_insert_with(|| FixtureRuntime {
            state: before.clone(),
            publisher_outcome,
            publisher_ledger: PublisherLedger::default(),
            resource_ledger: ResourceLedger::default(),
            ingress_ledger: IngressLedger::default(),
            lifecycle_ledger: LifecycleLedger::default(),
            restore_environment,
        });
        fixture.restore_environment = restore_environment;
        assert_eq!(
            fixture.snapshot(),
            before,
            "durable dispatcher state before step"
        );
        assert_eq!(
            fixture.publisher_ledger, expected_publisher_before,
            "transport-owned ledger before step"
        );
        assert_eq!(
            fixture.resource_ledger, expected_resources_before,
            "typed resource ledger before step"
        );
        assert_eq!(fixture.ingress_ledger, expected_ingress_before);
        assert_eq!(fixture.lifecycle_ledger, expected_lifecycle_before);
        assert_eq!(fixture.restore_environment, restore_environment);
        fixture.publisher_outcome = publisher_outcome;
        match run(&mut deployment_boundary(), &call, fixture) {
            Err(DeploymentBoundaryError::MissingDeploymentBoundary) => {
                assert_eq!(fixture.snapshot(), before);
                assert_eq!(fixture.publisher_ledger, expected_publisher_before);
                assert_eq!(fixture.resource_ledger, expected_resources_before);
                assert_eq!(fixture.ingress_ledger, expected_ingress_before);
                assert_eq!(fixture.lifecycle_ledger, expected_lifecycle_before);
                assert_eq!(fixture.restore_environment, restore_environment);
                saw_missing_frontier = true;
                break;
            }
            Ok(actual) => {
                assert_eq!(actual, expected);
                assert_eq!(fixture.snapshot(), expected_state);
                assert_eq!(fixture.publisher_ledger, expected_publisher);
                assert_eq!(fixture.resource_ledger, expected_resources);
                assert_eq!(fixture.ingress_ledger, expected_ingress);
                assert_eq!(fixture.lifecycle_ledger, expected_lifecycle);
                assert_eq!(fixture.restore_environment, restore_environment);
                expected_publisher_before = expected_publisher;
                expected_resources_before = expected_resources;
                expected_ingress_before = expected_ingress;
                expected_lifecycle_before = expected_lifecycle;
            }
        }
    }
    assert!(
        !saw_missing_frontier,
        "MissingDeploymentBoundary: deployment boundary is intentionally RED"
    );
}

/// Complete observable result for a single boundary call. Mutant controls use
/// this rather than a generic "some assertion failed" predicate: each control
/// names the one observable it expects its mutation to disturb.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FixtureOutcome {
    observation: DeploymentObservation,
    state: DeploymentState,
    publisher: PublisherLedger,
    resources: ResourceLedger,
    ingress: IngressLedger,
    lifecycle: LifecycleLedger,
    restore_environment: RestoreEnvironment,
}

impl FixtureOutcome {
    fn expected(contract: &Contract) -> Self {
        Self {
            observation: contract.expected.clone(),
            state: contract.expected_state.clone(),
            publisher: contract.expected_publisher.clone(),
            resources: contract.expected_resources.clone(),
            ingress: contract.expected_ingress.clone(),
            lifecycle: contract.expected_lifecycle.clone(),
            restore_environment: contract.restore_environment,
        }
    }

    fn from_runtime(observation: DeploymentObservation, runtime: &FixtureRuntime) -> Self {
        Self {
            observation,
            state: runtime.snapshot(),
            publisher: runtime.publisher_ledger.clone(),
            resources: runtime.resource_ledger.clone(),
            ingress: runtime.ingress_ledger.clone(),
            lifecycle: runtime.lifecycle_ledger.clone(),
            restore_environment: runtime.restore_environment,
        }
    }
}

fn run_contract(
    boundary: &mut dyn DeploymentBoundaryPort,
    contract: &Contract,
    actor: &str,
) -> FixtureOutcome {
    let mut runtime = FixtureRuntime {
        state: contract.before.clone(),
        publisher_outcome: contract.publisher_outcome,
        publisher_ledger: PublisherLedger::default(),
        resource_ledger: ResourceLedger::default(),
        ingress_ledger: IngressLedger::default(),
        lifecycle_ledger: LifecycleLedger::default(),
        restore_environment: contract.restore_environment,
    };
    let observation = run(boundary, &contract.call, &mut runtime)
        .unwrap_or_else(|error| panic!("{actor} must return an observation: {error:?}"));
    FixtureOutcome::from_runtime(observation, &runtime)
}

/// Runs an intentionally narrow GREEN reference behavior against one RED
/// contract. This proves fixture transitions without making the production
/// boundary implementation available to the normal D01--D24 matrix.
fn require_corrected_contract(
    corrected: &mut dyn DeploymentBoundaryPort,
    contract: Contract,
    diagnostic: &str,
) {
    let expected = FixtureOutcome::expected(&contract);
    assert_eq!(
        run_contract(corrected, &contract, "corrected lifecycle control"),
        expected,
        "corrected lifecycle control must satisfy the same contract: {diagnostic}"
    );
}

fn require_fault_control<F>(
    corrected: &mut dyn DeploymentBoundaryPort,
    faulty: &mut dyn DeploymentBoundaryPort,
    contract: Contract,
    diagnostic: &str,
    assert_named_witness: F,
) where
    F: FnOnce(&FixtureOutcome, &FixtureOutcome),
{
    let expected = FixtureOutcome::expected(&contract);
    assert_eq!(
        run_contract(corrected, &contract, "corrected control"),
        expected,
        "corrected control must satisfy the same contract: {diagnostic}"
    );
    let actual = run_contract(faulty, &contract, "targeted faulty port");
    assert_named_witness(&actual, &expected);
}

fn assert_observation_witness(
    actual: &FixtureOutcome,
    expected: &FixtureOutcome,
    witness: DeploymentObservation,
    diagnostic: &str,
) {
    assert_ne!(
        witness, expected.observation,
        "observation witness must differ from the contract: {diagnostic}"
    );
    assert_eq!(
        actual.observation, witness,
        "named observation witness: {diagnostic}"
    );
    assert_eq!(
        actual.state, expected.state,
        "unrelated state: {diagnostic}"
    );
    assert_eq!(
        actual.publisher, expected.publisher,
        "unrelated publisher: {diagnostic}"
    );
    assert_eq!(
        actual.resources, expected.resources,
        "unrelated resources: {diagnostic}"
    );
    assert_eq!(
        actual.ingress, expected.ingress,
        "unrelated ingress: {diagnostic}"
    );
    assert_eq!(
        actual.lifecycle, expected.lifecycle,
        "unrelated lifecycle: {diagnostic}"
    );
    assert_eq!(
        actual.restore_environment, expected.restore_environment,
        "unrelated restore environment: {diagnostic}"
    );
}

fn assert_state_witness(
    actual: &FixtureOutcome,
    expected: &FixtureOutcome,
    witness: DeploymentState,
    diagnostic: &str,
) {
    assert_ne!(
        witness, expected.state,
        "state witness must differ from the contract: {diagnostic}"
    );
    assert_eq!(
        actual.observation, expected.observation,
        "unrelated observation: {diagnostic}"
    );
    assert_eq!(actual.state, witness, "named state witness: {diagnostic}");
    assert_eq!(
        actual.publisher, expected.publisher,
        "unrelated publisher: {diagnostic}"
    );
    assert_eq!(
        actual.resources, expected.resources,
        "unrelated resources: {diagnostic}"
    );
    assert_eq!(
        actual.ingress, expected.ingress,
        "unrelated ingress: {diagnostic}"
    );
    assert_eq!(
        actual.lifecycle, expected.lifecycle,
        "unrelated lifecycle: {diagnostic}"
    );
    assert_eq!(
        actual.restore_environment, expected.restore_environment,
        "unrelated restore environment: {diagnostic}"
    );
}

fn assert_publisher_witness(
    actual: &FixtureOutcome,
    expected: &FixtureOutcome,
    witness: PublisherLedger,
    diagnostic: &str,
) {
    assert_ne!(
        witness, expected.publisher,
        "publisher witness must differ from the contract: {diagnostic}"
    );
    assert_eq!(
        actual.observation, expected.observation,
        "unrelated observation: {diagnostic}"
    );
    assert_eq!(
        actual.state, expected.state,
        "unrelated state: {diagnostic}"
    );
    assert_eq!(
        actual.publisher, witness,
        "named publisher witness: {diagnostic}"
    );
    assert_eq!(
        actual.resources, expected.resources,
        "unrelated resources: {diagnostic}"
    );
    assert_eq!(
        actual.ingress, expected.ingress,
        "unrelated ingress: {diagnostic}"
    );
    assert_eq!(
        actual.lifecycle, expected.lifecycle,
        "unrelated lifecycle: {diagnostic}"
    );
    assert_eq!(
        actual.restore_environment, expected.restore_environment,
        "unrelated restore environment: {diagnostic}"
    );
}

fn assert_resource_witness(
    actual: &FixtureOutcome,
    expected: &FixtureOutcome,
    witness: ResourceLedger,
    diagnostic: &str,
) {
    assert_ne!(
        witness, expected.resources,
        "resource witness must differ from the contract: {diagnostic}"
    );
    assert_eq!(
        actual.observation, expected.observation,
        "unrelated observation: {diagnostic}"
    );
    assert_eq!(
        actual.state, expected.state,
        "unrelated state: {diagnostic}"
    );
    assert_eq!(
        actual.publisher, expected.publisher,
        "unrelated publisher: {diagnostic}"
    );
    assert_eq!(
        actual.resources, witness,
        "named resource witness: {diagnostic}"
    );
    assert_eq!(
        actual.ingress, expected.ingress,
        "unrelated ingress: {diagnostic}"
    );
    assert_eq!(
        actual.lifecycle, expected.lifecycle,
        "unrelated lifecycle: {diagnostic}"
    );
    assert_eq!(
        actual.restore_environment, expected.restore_environment,
        "unrelated restore environment: {diagnostic}"
    );
}

fn denied_ingress(attempt: IngressDeniedAttempt, before: DeploymentState) -> Contract {
    contract(
        BoundaryCall::Ingress(ingress(|value| value.denied_attempt = Some(attempt))),
        before.clone(),
        observation(SafeDisposition::RoleDenied),
        before,
    )
}

fn denied_ingress_resource(attempt: DeniedResourceAttempt, before: DeploymentState) -> Contract {
    let request_attempt = match attempt {
        DeniedResourceAttempt::IngressAlertIntentPublish => {
            IngressDeniedAttempt::AlertIntentPublish
        }
        DeniedResourceAttempt::IngressSharedStoreBypass => IngressDeniedAttempt::SharedStoreBypass,
        DeniedResourceAttempt::IngressDeserializedHandleBypass => {
            IngressDeniedAttempt::DeserializedHandleBypass
        }
        _ => panic!("fixture ingress resource must have ingress authority"),
    };
    denied_ingress(request_attempt, before)
}

fn denied_outbound_resource(attempt: DeniedResourceAttempt, before: DeploymentState) -> Contract {
    let operation = match attempt {
        DeniedResourceAttempt::OutboundEvidenceRead => OutboundOperation::EvidenceRead,
        DeniedResourceAttempt::OutboundEvidenceMutate => OutboundOperation::EvidenceMutate,
        DeniedResourceAttempt::OutboundAlertIntentRead => OutboundOperation::AlertIntentRead,
        DeniedResourceAttempt::OutboundAlertIntentWrite => OutboundOperation::AlertIntentWrite,
        DeniedResourceAttempt::OutboundSharedStoreBypass => OutboundOperation::SharedStoreBypass,
        DeniedResourceAttempt::OutboundDeserializedHandleBypass => {
            OutboundOperation::DeserializedHandleBypass
        }
        _ => panic!("fixture outbound resource must have outbound authority"),
    };
    contract(
        BoundaryCall::Outbound(outbound(operation)),
        before.clone(),
        observation(SafeDisposition::RoleDenied),
        before,
    )
}

fn denied_dispatcher_resource(attempt: DeniedResourceAttempt, before: DeploymentState) -> Contract {
    let operation = match attempt {
        DeniedResourceAttempt::DispatcherRegisteredCommandRead => {
            DispatchOperation::RegisteredCommandRead
        }
        DeniedResourceAttempt::DispatcherRegisteredCommandMutate => {
            DispatchOperation::RegisteredCommandMutate
        }
        DeniedResourceAttempt::DispatcherProviderCredentialRead => {
            DispatchOperation::ProviderCredentialRead
        }
        DeniedResourceAttempt::DispatcherEvidenceMutate => DispatchOperation::EvidenceMutate,
        DeniedResourceAttempt::DispatcherSharedStoreBypass => DispatchOperation::SharedStoreBypass,
        DeniedResourceAttempt::DispatcherDeserializedHandleBypass => {
            DispatchOperation::DeserializedHandleBypass
        }
        _ => panic!("fixture dispatcher resource must have dispatcher authority"),
    };
    contract(
        BoundaryCall::Dispatcher(dispatcher(operation)),
        before.clone(),
        observation(SafeDisposition::RoleDenied),
        before,
    )
}

#[test]
fn p0b_d01_exact_get_challenge_is_bounded_and_stateless() {
    let before = state();
    require_missing_contracts([contract(
        BoundaryCall::Ingress(ingress(|_| {})),
        before.clone(),
        challenge(),
        before,
    )]);
}
#[test]
fn p0b_d02_invalid_get_shape_rejects_before_verifier() {
    let before = state();
    require_missing_contracts(
        [
            ingress(|v| v.path = b"/webhooks/whatsapp/extra".to_vec()),
            ingress(|v| {
                v.query_parameters.pop();
            }),
            ingress(|v| {
                v.query_parameters.push(QueryParameter {
                    name: b"hub.mode".to_vec(),
                    value: b"subscribe".to_vec(),
                });
            }),
            ingress(|v| {
                v.query_parameters[0].name = b"unexpected".to_vec();
            }),
            ingress(|v| v.method = Method::Other),
            ingress(|v| v.raw_body = b"x".to_vec()),
        ]
        .map(|request| {
            contract(
                BoundaryCall::Ingress(request),
                before.clone(),
                observation(SafeDisposition::Rejected),
                before.clone(),
            )
        }),
    );
}
#[test]
fn p0b_d03_post_transport_bounds_reject_without_mutation() {
    let before = state();
    require_missing_contracts(
        [
            post(|v| {
                v.query_parameters = vec![QueryParameter {
                    name: b"x".to_vec(),
                    value: b"y".to_vec(),
                }];
            }),
            post(|v| {
                v.method = Method::Other;
            }),
            post(|v| {
                v.raw_body = vec![0_u8; 262_145];
            }),
            post(|v| {
                v.elapsed_millis = 5_001;
            }),
            post(|v| {
                v.headers.push(v.headers[1].clone());
            }),
            post(|v| {
                v.headers.push(v.headers[0].clone());
            }),
            post(|v| {
                v.headers
                    .retain(|header| header.name != b"x-hub-signature-256");
            }),
            post(|v| {
                v.headers[1].value = b"sha256=invalid".to_vec();
            }),
            post(|v| {
                v.headers[1].value =
                    b"sha256=0000000000000000000000000000000000000000000000000000000000000000"
                        .to_vec();
            }),
        ]
        .map(|request| {
            contract(
                BoundaryCall::Ingress(request),
                before.clone(),
                observation(SafeDisposition::Rejected),
                before.clone(),
            )
        }),
    );
}
#[test]
fn p0b_d04_public_management_surfaces_are_not_deployment_options() {
    let before = state();
    require_missing_contracts([contract(
        BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::PublicManagementSurface)),
        before.clone(),
        observation(SafeDisposition::Rejected),
        before,
    )]);
}
#[test]
fn p0b_d05_ingress_has_no_external_network_capability() {
    let before = state();
    require_missing_contracts(
        [
            NetworkAttempt::Connect,
            NetworkAttempt::Bind,
            NetworkAttempt::Resolve,
        ]
        .map(|attempt| {
            denied_ingress(
                IngressDeniedAttempt::ExternalNetwork(attempt),
                before.clone(),
            )
        }),
    );
}
#[test]
fn p0b_d06_ingress_cannot_read_credentials_or_change_commands() {
    let before = state();
    require_missing_contracts(
        [
            IngressDeniedAttempt::ProviderCredentialRead,
            IngressDeniedAttempt::NtfyCredentialRead,
            IngressDeniedAttempt::RegisteredCommandRead,
            IngressDeniedAttempt::RegisteredCommandWrite,
            IngressDeniedAttempt::RegisteredCommandMutate,
        ]
        .map(|attempt| denied_ingress(attempt, before.clone())),
    );
}
#[test]
fn p0b_d07_outbound_rejects_caller_provider_authority() {
    let before = state();
    let mut wrong = OutboundRequest::registered_command();
    wrong.credential_in_wrong_role = true;
    require_missing_contracts([
        contract(
            BoundaryCall::Outbound(outbound(OutboundOperation::CallerSuppliedProviderAuthority)),
            before.clone(),
            observation(SafeDisposition::Rejected),
            before.clone(),
        ),
        contract(
            BoundaryCall::Outbound(wrong),
            before.clone(),
            observation(SafeDisposition::Rejected),
            before,
        ),
    ]);
}
#[test]
fn p0b_d08_dispatcher_accepts_only_safe_configured_alert_intents() {
    let before = state();
    require_missing_contracts(
        [
            DispatchOperation::ReadRawCallbackBody,
            DispatchOperation::ReadTopic,
            DispatchOperation::PublishForeignTopic,
        ]
        .map(|operation| {
            contract(
                BoundaryCall::Dispatcher(dispatcher(operation)),
                before.clone(),
                observation(SafeDisposition::RoleDenied),
                before.clone(),
            )
        }),
    );
}
#[test]
fn p0b_d09_ntfy_plan_requires_private_least_privilege_acl() {
    let before = state();
    let mut anonymous_read = NtfyAclRules::exact_private();
    anonymous_read.anonymous.configured_read = true;
    let mut anonymous_publish = NtfyAclRules::exact_private();
    anonymous_publish.anonymous.configured_publish = true;
    let mut anonymous_foreign_read = NtfyAclRules::exact_private();
    anonymous_foreign_read.anonymous.foreign_read = true;
    let mut anonymous_foreign_publish = NtfyAclRules::exact_private();
    anonymous_foreign_publish.anonymous.foreign_publish = true;
    let mut publisher_wildcard = NtfyAclRules::exact_private();
    publisher_wildcard.publisher.foreign_publish = true;
    let mut publisher_read = NtfyAclRules::exact_private();
    publisher_read.publisher.configured_read = true;
    let mut publisher_foreign_read = NtfyAclRules::exact_private();
    publisher_foreign_read.publisher.foreign_read = true;
    let mut reader_publish = NtfyAclRules::exact_private();
    reader_publish.reader.configured_publish = true;
    let mut reader_foreign_read = NtfyAclRules::exact_private();
    reader_foreign_read.reader.foreign_read = true;
    let mut reader_foreign_publish = NtfyAclRules::exact_private();
    reader_foreign_publish.reader.foreign_publish = true;
    let mut missing_required_publish = NtfyAclRules::exact_private();
    missing_required_publish.publisher.configured_publish = false;
    let mut missing_required_read = NtfyAclRules::exact_private();
    missing_required_read.reader.configured_read = false;
    require_missing_contracts(
        [
            anonymous_read,
            anonymous_publish,
            anonymous_foreign_read,
            anonymous_foreign_publish,
            publisher_wildcard,
            publisher_read,
            publisher_foreign_read,
            reader_publish,
            reader_foreign_read,
            reader_foreign_publish,
            missing_required_publish,
            missing_required_read,
        ]
        .map(|rules| {
            let mut request = acl(
                NtfyPrincipal::ConfiguredPublisher,
                NtfyAction::Publish,
                TopicScope::Configured,
            );
            request.rules = rules;
            contract(
                BoundaryCall::Acl(request),
                before.clone(),
                observation(SafeDisposition::NtfyDenied),
                before.clone(),
            )
        }),
    );
}
#[test]
fn p0b_d10_dispatch_failure_keeps_a_fenced_safe_intent() {
    let before = state_with_intent();
    let mut after_first_refusal = before.clone();
    after_first_refusal.dispatcher.alert_intent = Some(AlertIntentState {
        lease_fence: 1,
        leased: false,
        attempts: 1,
        delivered: false,
        ambiguous: false,
        retry_limit: 3,
    });
    let mut after_second_refusal = after_first_refusal.clone();
    after_second_refusal.dispatcher.alert_intent = Some(AlertIntentState {
        lease_fence: 2,
        leased: false,
        attempts: 2,
        delivered: false,
        ambiguous: false,
        retry_limit: 3,
    });
    let mut exhausted_after = after_second_refusal.clone();
    exhausted_after.dispatcher.alert_intent = Some(AlertIntentState {
        lease_fence: 3,
        leased: false,
        attempts: 3,
        delivered: false,
        ambiguous: false,
        retry_limit: 3,
    });
    let mut first = dispatcher(DispatchOperation::SettleIntent);
    first.requested_fence = 1;
    let mut second = dispatcher(DispatchOperation::SettleIntent);
    second.requested_fence = 2;
    let mut third = dispatcher(DispatchOperation::SettleIntent);
    third.requested_fence = 3;
    let mut exhausted_replay = dispatcher(DispatchOperation::SettleIntent);
    exhausted_replay.requested_fence = 3;
    require_missing_sequence([
        contract(
            BoundaryCall::Dispatcher(first),
            before.clone(),
            observation(SafeDisposition::IntentRetryable),
            after_first_refusal.clone(),
        )
        .with_publisher_outcome(DispatchTransportResult::DefiniteRefusal)
        .with_expected_publisher(PublisherLedger {
            attempts: 1,
            acceptances: 0,
        }),
        contract(
            BoundaryCall::Dispatcher(second),
            after_first_refusal,
            observation(SafeDisposition::IntentRetryable),
            after_second_refusal.clone(),
        )
        .with_publisher_outcome(DispatchTransportResult::DefiniteRefusal)
        .with_expected_publisher(PublisherLedger {
            attempts: 2,
            acceptances: 0,
        }),
        contract(
            BoundaryCall::Dispatcher(third),
            after_second_refusal,
            observation(SafeDisposition::IntentExhausted),
            exhausted_after.clone(),
        )
        .with_publisher_outcome(DispatchTransportResult::DefiniteRefusal)
        .with_expected_publisher(PublisherLedger {
            attempts: 3,
            acceptances: 0,
        }),
        contract(
            BoundaryCall::Dispatcher(exhausted_replay),
            exhausted_after.clone(),
            observation(SafeDisposition::IntentExhausted),
            exhausted_after,
        )
        .with_publisher_outcome(DispatchTransportResult::Accepted)
        .with_expected_publisher(PublisherLedger {
            attempts: 3,
            acceptances: 0,
        }),
    ]);
}
#[test]
fn p0b_d11_sensitive_diagnostics_fail_closed() {
    let before = state();
    require_missing_contracts(
        [
            DiagnosticArtifact::RawBody,
            DiagnosticArtifact::RawQuery,
            DiagnosticArtifact::SecretMarker,
            DiagnosticArtifact::AuthorizationHeader,
            DiagnosticArtifact::ContentField,
        ]
        .map(|artifact| {
            contract(
                BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::SensitiveDiagnostic(
                    artifact,
                ))),
                before.clone(),
                observation(SafeDisposition::Rejected),
                before.clone(),
            )
        }),
    );
}
#[test]
fn p0b_d12_secret_artifact_requires_containment_and_revocation() {
    let mut before = state();
    before.lifecycle.secret_diagnostic_artifact_present = true;
    let mut after = before.clone();
    after.lifecycle.secret_diagnostic_artifact_present = false;
    after.lifecycle.safe_incidents = 1;
    after.lifecycle.credential_generation = 2;
    after.lifecycle.revoked_credential_generations = vec![1];
    require_missing_contracts([contract(
        BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::SecretArtifact)),
        before,
        observation(SafeDisposition::FaultDetected),
        after,
    )
    .with_expected_lifecycle(LifecycleLedger {
        events: vec![
            LifecycleEvent::SecretArtifactDetected,
            LifecycleEvent::SecretArtifactDeleted,
            LifecycleEvent::CredentialGenerationRevoked,
        ],
    })]);
}
#[test]
fn p0b_d13_restore_requires_offline_quarantine_before_state_open() {
    let before = rollback_ready_state();
    let mut quarantined = before.clone();
    quarantined.lifecycle.restore_quarantined = true;
    let mut restored = quarantined.clone();
    restored.lifecycle.restore_state_opened = true;
    let mut contracts = vec![
        contract(
            BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::Restore(restore(|_| {})))),
            before.clone(),
            observation(SafeDisposition::RestoreOpened),
            restored,
        )
        .with_expected_lifecycle(LifecycleLedger {
            events: vec![
                LifecycleEvent::RestoreQuarantined,
                LifecycleEvent::RestoreStateOpened,
            ],
        }),
    ];
    contracts.extend(
        [
            restore_environment(|environment| environment.network_available = true),
            restore_environment(|environment| environment.credential_mounted = true),
            restore_environment(|environment| environment.scheduler_enabled = true),
        ]
        .map(|environment| {
            contract(
                BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::Restore(restore(|_| {})))),
                before.clone(),
                observation(SafeDisposition::RestoreQuarantined),
                quarantined.clone(),
            )
            .with_expected_lifecycle(LifecycleLedger {
                events: vec![LifecycleEvent::RestoreQuarantined],
            })
            .with_restore_environment(environment)
        }),
    );
    let mut route_active = before.clone();
    route_active.lifecycle.route_enabled = true;
    let mut service_active = before.clone();
    service_active.lifecycle.service_unit_enabled = true;
    let mut sender_active = before.clone();
    sender_active.lifecycle.sender_generation_active = true;
    let mut credential_active = before.clone();
    credential_active.lifecycle.credential_generation_active = true;
    let mut publisher_active = before.clone();
    publisher_active.lifecycle.alert_publisher_active = true;
    for active_before in [
        route_active,
        service_active,
        sender_active,
        credential_active,
        publisher_active,
    ] {
        let mut active_quarantined = active_before.clone();
        active_quarantined.lifecycle.restore_quarantined = true;
        contracts.push(
            contract(
                BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::Restore(restore(|_| {})))),
                active_before,
                observation(SafeDisposition::RestoreQuarantined),
                active_quarantined,
            )
            .with_expected_lifecycle(LifecycleLedger {
                events: vec![LifecycleEvent::RestoreQuarantined],
            }),
        );
    }
    require_missing_contracts(contracts);
}
#[test]
fn p0b_d14_restore_cannot_resurrect_expired_or_opted_out_raw_data() {
    let mut before = state();
    before.lifecycle.raw_restore_copies = 1;
    let mut after = before.clone();
    after.lifecycle.restore_quarantined = true;
    after.lifecycle.raw_restore_copies = 0;
    after.lifecycle.safe_restore_dispositions = 1;
    require_missing_contracts(
        [
            restore_environment(|environment| environment.raw_record_expired = true),
            restore_environment(|environment| environment.raw_record_opted_out = true),
        ]
        .map(|environment| {
            contract(
                BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::Restore(restore(|_| {})))),
                before.clone(),
                observation(SafeDisposition::RestoreQuarantined),
                after.clone(),
            )
            .with_expected_lifecycle(LifecycleLedger {
                events: vec![
                    LifecycleEvent::RestoreQuarantined,
                    LifecycleEvent::RawCopyWithheld,
                ],
            })
            .with_restore_environment(environment)
        }),
    );
}
#[test]
fn p0b_d15_rollback_requires_all_authority_to_be_disabled() {
    let mut route = rollback_ready_state();
    route.lifecycle.route_enabled = true;
    let mut service = rollback_ready_state();
    service.lifecycle.service_unit_enabled = true;
    let mut scheduler = rollback_ready_state();
    scheduler.lifecycle.scheduler_enabled = true;
    let mut sender = rollback_ready_state();
    sender.lifecycle.sender_generation_active = true;
    let mut credential_generation = rollback_ready_state();
    credential_generation.lifecycle.credential_generation_active = true;
    let mut publisher = rollback_ready_state();
    publisher.lifecycle.alert_publisher_active = true;
    require_missing_contracts(
        [
            route,
            service,
            scheduler,
            sender,
            credential_generation,
            publisher,
        ]
        .map(|before| {
            contract(
                BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::Rollback)),
                before.clone(),
                observation(SafeDisposition::Rejected),
                before.clone(),
            )
        }),
    );
}
#[test]
fn p0b_d16_signed_post_uses_unchanged_raw_bytes_before_mutation() {
    let before = state();
    let mut after = before.clone();
    after.ingress.verification_attempts = 1;
    after.ingress.parser_attempts = 1;
    after.ingress.transaction_attempts = 1;
    after.ingress.safe_events = 1;
    after.ingress.alert_intents = 1;
    let mut mac_rejected = before.clone();
    mac_rejected.ingress.verification_attempts = 1;
    require_missing_contracts([
        contract(
            BoundaryCall::Ingress(signed_post()),
            before.clone(),
            observation(SafeDisposition::CallbackAccepted),
            after,
        )
        .with_expected_ingress(IngressLedger {
            events: vec![
                IngressEvent::MacChecked,
                IngressEvent::MacVerified,
                IngressEvent::Parsed,
                IngressEvent::TransactionProposed,
            ],
        }),
        contract(
            BoundaryCall::Ingress(post(|request| request.raw_body.push(b' '))),
            before.clone(),
            observation(SafeDisposition::Rejected),
            mac_rejected,
        )
        .with_expected_ingress(IngressLedger {
            events: vec![IngressEvent::MacChecked],
        }),
    ]);
}
#[test]
fn p0b_d17_get_normalization_and_token_mismatch_are_not_equivalent_routes() {
    let before = state();
    require_missing_contracts(
        [
            ingress(|v| v.path = b"/webhooks%2fwhatsapp".to_vec()),
            ingress(|v| v.path = b"/webhooks//whatsapp".to_vec()),
            ingress(|v| v.path = b"/webhooks/whatsapp/".to_vec()),
            ingress(|v| {
                v.verification_token = b"wrong-deployment-verify".to_vec();
            }),
        ]
        .map(|request| {
            contract(
                BoundaryCall::Ingress(request),
                before.clone(),
                observation(SafeDisposition::Rejected),
                before.clone(),
            )
        }),
    );
}
#[test]
fn p0b_d18_all_cross_role_resource_bypasses_are_denied_before_effect() {
    let before = state();
    require_missing_contracts(
        [
            DeniedResourceAttempt::IngressAlertIntentPublish,
            DeniedResourceAttempt::IngressSharedStoreBypass,
            DeniedResourceAttempt::IngressDeserializedHandleBypass,
        ]
        .map(|attempt| denied_ingress_resource(attempt, before.clone())),
    );
    require_missing_contracts(
        [
            DeniedResourceAttempt::OutboundEvidenceRead,
            DeniedResourceAttempt::OutboundEvidenceMutate,
            DeniedResourceAttempt::OutboundAlertIntentRead,
            DeniedResourceAttempt::OutboundAlertIntentWrite,
            DeniedResourceAttempt::OutboundSharedStoreBypass,
            DeniedResourceAttempt::OutboundDeserializedHandleBypass,
        ]
        .map(|attempt| denied_outbound_resource(attempt, before.clone())),
    );
    require_missing_contracts(
        [
            DeniedResourceAttempt::DispatcherRegisteredCommandRead,
            DeniedResourceAttempt::DispatcherRegisteredCommandMutate,
            DeniedResourceAttempt::DispatcherProviderCredentialRead,
            DeniedResourceAttempt::DispatcherEvidenceMutate,
            DeniedResourceAttempt::DispatcherSharedStoreBypass,
            DeniedResourceAttempt::DispatcherDeserializedHandleBypass,
        ]
        .map(|attempt| denied_dispatcher_resource(attempt, before.clone())),
    );
}
#[test]
fn p0b_d19_secret_placement_and_revoked_generation_cannot_start_a_role() {
    let before = state();
    let mut allowed_after = before.clone();
    allowed_after.lifecycle.credential_start_records = 1;
    let mut current_revoked = before.clone();
    current_revoked.lifecycle.revoked_credential_generations = vec![1];
    let mut legacy_generation = before.clone();
    legacy_generation.lifecycle.credential_generation = 2;
    let mut contracts = vec![contract(
        BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::StartWithCredential(
            credential(|_| {}),
        ))),
        before.clone(),
        observation(SafeDisposition::CredentialStartAccepted),
        allowed_after,
    )];
    contracts.extend(
        [
            (
                credential(|request| request.in_arguments = true),
                before.clone(),
            ),
            (
                credential(|request| request.in_environment = true),
                before.clone(),
            ),
            (
                credential(|request| request.broad_file_access = true),
                before.clone(),
            ),
            (
                credential(|request| request.mounted_file_access = true),
                before.clone(),
            ),
            (
                credential(|request| request.wrong_role_mount = true),
                before.clone(),
            ),
            (
                credential(|request| request.presented_generation = 1),
                legacy_generation,
            ),
        ]
        .map(|(request, placement_before)| {
            contract(
                BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::StartWithCredential(
                    request,
                ))),
                placement_before.clone(),
                observation(SafeDisposition::Rejected),
                placement_before,
            )
        }),
    );
    contracts.push(contract(
        BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::StartWithCredential(
            credential(|_| {}),
        ))),
        current_revoked.clone(),
        observation(SafeDisposition::Rejected),
        current_revoked,
    ));
    require_missing_contracts(contracts);
}
#[test]
fn p0b_d20_ntfy_effective_acl_has_exact_allowed_and_denied_principals() {
    let before = state();
    let mut publisher_after = before.clone();
    publisher_after.ntfy_acl.configured_publish_observations = 1;
    let mut reader_after = before.clone();
    reader_after.ntfy_acl.configured_read_observations = 1;
    require_missing_contracts([
        contract(
            BoundaryCall::Acl(acl(
                NtfyPrincipal::ConfiguredPublisher,
                NtfyAction::Publish,
                TopicScope::Configured,
            )),
            before.clone(),
            observation(SafeDisposition::NtfyAllowed),
            publisher_after,
        ),
        contract(
            BoundaryCall::Acl(acl(
                NtfyPrincipal::ConfiguredReader,
                NtfyAction::Read,
                TopicScope::Configured,
            )),
            before.clone(),
            observation(SafeDisposition::NtfyAllowed),
            reader_after,
        ),
        contract(
            BoundaryCall::Acl(acl(
                NtfyPrincipal::Anonymous,
                NtfyAction::Read,
                TopicScope::Configured,
            )),
            before.clone(),
            observation(SafeDisposition::NtfyDenied),
            before.clone(),
        ),
        contract(
            BoundaryCall::Acl(acl(
                NtfyPrincipal::Anonymous,
                NtfyAction::Publish,
                TopicScope::Configured,
            )),
            before.clone(),
            observation(SafeDisposition::NtfyDenied),
            before.clone(),
        ),
        contract(
            BoundaryCall::Acl(acl(
                NtfyPrincipal::Anonymous,
                NtfyAction::Read,
                TopicScope::Foreign,
            )),
            before.clone(),
            observation(SafeDisposition::NtfyDenied),
            before.clone(),
        ),
        contract(
            BoundaryCall::Acl(acl(
                NtfyPrincipal::Anonymous,
                NtfyAction::Publish,
                TopicScope::Foreign,
            )),
            before.clone(),
            observation(SafeDisposition::NtfyDenied),
            before.clone(),
        ),
        contract(
            BoundaryCall::Acl(acl(
                NtfyPrincipal::ConfiguredPublisher,
                NtfyAction::Read,
                TopicScope::Configured,
            )),
            before.clone(),
            observation(SafeDisposition::NtfyDenied),
            before.clone(),
        ),
        contract(
            BoundaryCall::Acl(acl(
                NtfyPrincipal::ConfiguredPublisher,
                NtfyAction::Read,
                TopicScope::Foreign,
            )),
            before.clone(),
            observation(SafeDisposition::NtfyDenied),
            before.clone(),
        ),
        contract(
            BoundaryCall::Acl(acl(
                NtfyPrincipal::ConfiguredReader,
                NtfyAction::Publish,
                TopicScope::Configured,
            )),
            before.clone(),
            observation(SafeDisposition::NtfyDenied),
            before.clone(),
        ),
        contract(
            BoundaryCall::Acl(acl(
                NtfyPrincipal::ConfiguredPublisher,
                NtfyAction::Publish,
                TopicScope::Foreign,
            )),
            before.clone(),
            observation(SafeDisposition::NtfyDenied),
            before,
        ),
        contract(
            BoundaryCall::Acl(acl(
                NtfyPrincipal::ConfiguredReader,
                NtfyAction::Read,
                TopicScope::Foreign,
            )),
            state(),
            observation(SafeDisposition::NtfyDenied),
            state(),
        ),
        contract(
            BoundaryCall::Acl(acl(
                NtfyPrincipal::ConfiguredReader,
                NtfyAction::Publish,
                TopicScope::Foreign,
            )),
            state(),
            observation(SafeDisposition::NtfyDenied),
            state(),
        ),
    ]);
}
#[test]
fn p0b_d21_dispatch_crash_restart_and_competition_keep_fences_honest() {
    let ready = state_with_intent();
    let mut competing_lease = ready.clone();
    competing_lease.dispatcher.alert_intent = Some(AlertIntentState {
        lease_fence: 2,
        leased: true,
        attempts: 0,
        delivered: false,
        ambiguous: false,
        retry_limit: 3,
    });
    let mut ambiguous = competing_lease.clone();
    ambiguous.dispatcher.alert_intent = Some(AlertIntentState {
        lease_fence: 2,
        leased: true,
        attempts: 1,
        delivered: false,
        ambiguous: true,
        retry_limit: 3,
    });
    let mut before_attempt = dispatcher(DispatchOperation::SettleIntent);
    before_attempt.requested_fence = 1;
    let mut acquire_competing = dispatcher(DispatchOperation::AcquireLease);
    acquire_competing.requested_fence = 2;
    let mut stale_settle = dispatcher(DispatchOperation::SettleIntent);
    stale_settle.requested_fence = 1;
    let mut accepted_then_crash = dispatcher(DispatchOperation::SettleIntent);
    accepted_then_crash.requested_fence = 2;
    let mut ambiguous_replay = dispatcher(DispatchOperation::SettleIntent);
    ambiguous_replay.requested_fence = 2;
    require_missing_sequence([
        contract(
            BoundaryCall::Dispatcher(before_attempt),
            ready.clone(),
            observation(SafeDisposition::IntentRetryable),
            ready.clone(),
        )
        .with_publisher_outcome(DispatchTransportResult::CrashBeforeAttempt),
        contract(
            BoundaryCall::Dispatcher(acquire_competing),
            ready,
            observation(SafeDisposition::NtfyAllowed),
            competing_lease.clone(),
        ),
        contract(
            BoundaryCall::Dispatcher(stale_settle),
            competing_lease.clone(),
            observation(SafeDisposition::RoleDenied),
            competing_lease.clone(),
        ),
        contract(
            BoundaryCall::Dispatcher(accepted_then_crash),
            competing_lease,
            observation(SafeDisposition::IntentAmbiguous),
            ambiguous.clone(),
        )
        .with_publisher_outcome(DispatchTransportResult::CrashAfterAcceptedPublish)
        .with_expected_publisher(PublisherLedger {
            attempts: 1,
            acceptances: 1,
        }),
        contract(
            BoundaryCall::Dispatcher(ambiguous_replay),
            ambiguous.clone(),
            observation(SafeDisposition::IntentAmbiguous),
            ambiguous,
        )
        .with_publisher_outcome(DispatchTransportResult::Accepted)
        .with_expected_publisher(PublisherLedger {
            attempts: 1,
            acceptances: 1,
        }),
    ]);
}
#[test]
fn p0b_d22_restore_and_interrupted_rollback_reject_stale_reactivation() {
    let rollback_ready = rollback_ready_state();
    let mut quarantined = rollback_ready.clone();
    quarantined.lifecycle.restore_quarantined = true;
    let interrupted_before = state();
    let mut interrupted_quarantined = interrupted_before.clone();
    interrupted_quarantined.lifecycle.restore_quarantined = true;
    require_missing_contracts([contract(
        BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::Restore(restore(|_| {})))),
        interrupted_before,
        observation(SafeDisposition::RestoreQuarantined),
        interrupted_quarantined,
    )
    .with_expected_lifecycle(LifecycleLedger {
        events: vec![LifecycleEvent::RestoreQuarantined],
    })
    .with_restore_environment(restore_environment(|environment| {
        environment.rollback_interrupted = true
    }))]);
    require_missing_sequence([
        contract(
            BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::Rollback)),
            rollback_ready.clone(),
            observation(SafeDisposition::RollbackComplete),
            rollback_ready.clone(),
        )
        .with_expected_lifecycle(LifecycleLedger {
            events: vec![LifecycleEvent::RollbackCompleted],
        }),
        contract(
            BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::Restore(restore(|_| {})))),
            rollback_ready.clone(),
            observation(SafeDisposition::RestoreQuarantined),
            quarantined.clone(),
        )
        .with_expected_lifecycle(LifecycleLedger {
            events: vec![
                LifecycleEvent::RollbackCompleted,
                LifecycleEvent::RestoreQuarantined,
            ],
        })
        .with_restore_environment(restore_environment(|environment| {
            environment.snapshot_generation = 6
        })),
        contract(
            BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::Restore(restore(|request| {
                request.reactivation_requested = true
            })))),
            quarantined.clone(),
            observation(SafeDisposition::RestoreQuarantined),
            quarantined.clone(),
        )
        .with_expected_lifecycle(LifecycleLedger {
            events: vec![
                LifecycleEvent::RollbackCompleted,
                LifecycleEvent::RestoreQuarantined,
                LifecycleEvent::RestoreQuarantined,
            ],
        }),
        contract(
            BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::Restore(restore(|_| {})))),
            quarantined.clone(),
            observation(SafeDisposition::RestoreQuarantined),
            quarantined,
        )
        .with_expected_lifecycle(LifecycleLedger {
            events: vec![
                LifecycleEvent::RollbackCompleted,
                LifecycleEvent::RestoreQuarantined,
                LifecycleEvent::RestoreQuarantined,
                LifecycleEvent::RestoreQuarantined,
            ],
        })
        .with_restore_environment(restore_environment(|environment| {
            environment.rollback_interrupted = true
        })),
    ]);
}
#[test]
fn p0b_d23_authorized_controls_prove_the_boundary_is_not_reject_all() {
    let mut before = state();
    before.outbound.registered_commands = 1;
    before.dispatcher.alert_intent = Some(alert_intent());
    let mut callback_after = before.clone();
    callback_after.ingress.verification_attempts = 1;
    callback_after.ingress.parser_attempts = 1;
    callback_after.ingress.transaction_attempts = 1;
    callback_after.ingress.safe_events = 1;
    callback_after.ingress.alert_intents = 1;
    let mut outbound_after = before.clone();
    outbound_after.outbound.provider_attempt_records = 1;
    let mut dispatch_after = before.clone();
    dispatch_after.dispatcher.published_alerts = 1;
    dispatch_after.dispatcher.alert_intent = Some(AlertIntentState {
        lease_fence: 1,
        leased: false,
        attempts: 1,
        delivered: true,
        ambiguous: false,
        retry_limit: 3,
    });
    require_missing_contracts([
        contract(
            BoundaryCall::Ingress(ingress(|_| {})),
            before.clone(),
            challenge(),
            before.clone(),
        ),
        contract(
            BoundaryCall::Ingress(signed_post()),
            before.clone(),
            observation(SafeDisposition::CallbackAccepted),
            callback_after,
        )
        .with_expected_ingress(IngressLedger {
            events: vec![
                IngressEvent::MacChecked,
                IngressEvent::MacVerified,
                IngressEvent::Parsed,
                IngressEvent::TransactionProposed,
            ],
        }),
        contract(
            BoundaryCall::Outbound(OutboundRequest::registered_command()),
            before.clone(),
            observation(SafeDisposition::RegisteredCommandAccepted),
            outbound_after,
        ),
        contract(
            BoundaryCall::Dispatcher(DispatcherRequest::configured_safe_intent()),
            before.clone(),
            observation(SafeDisposition::NtfyAllowed),
            dispatch_after,
        )
        .with_expected_publisher(PublisherLedger {
            attempts: 1,
            acceptances: 1,
        }),
    ]);
}
#[test]
fn p0b_d24_targeted_faults_are_detected_by_their_own_controls() {
    trait Fault {
        fn ingress(
            _: &IngressRequest,
            _: &mut dyn IngressRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            Err(DeploymentBoundaryError::MissingDeploymentBoundary)
        }
        fn outbound(
            _: &OutboundRequest,
            _: &mut dyn OutboundRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            Err(DeploymentBoundaryError::MissingDeploymentBoundary)
        }
        fn dispatcher(
            _: &DispatcherRequest,
            _: &mut dyn DispatcherRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            Err(DeploymentBoundaryError::MissingDeploymentBoundary)
        }
        fn acl(
            _: NtfyAclRequest,
            _: &mut dyn NtfyAclRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            Err(DeploymentBoundaryError::MissingDeploymentBoundary)
        }
        fn lifecycle(
            _: LifecycleRequest,
            _: &mut dyn LifecycleRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            Err(DeploymentBoundaryError::MissingDeploymentBoundary)
        }
    }
    struct FaultyPort<F>(std::marker::PhantomData<F>);
    impl<F> FaultyPort<F> {
        fn new() -> Self {
            Self(std::marker::PhantomData)
        }
    }
    impl<F: Fault> DeploymentBoundaryPort for FaultyPort<F> {
        fn evaluate_ingress(
            &mut self,
            request: &IngressRequest,
            runtime: &mut dyn IngressRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            F::ingress(request, runtime)
        }
        fn evaluate_outbound(
            &mut self,
            request: &OutboundRequest,
            runtime: &mut dyn OutboundRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            F::outbound(request, runtime)
        }
        fn evaluate_dispatcher(
            &mut self,
            request: &DispatcherRequest,
            runtime: &mut dyn DispatcherRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            F::dispatcher(request, runtime)
        }
        fn evaluate_ntfy_acl(
            &mut self,
            request: NtfyAclRequest,
            runtime: &mut dyn NtfyAclRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            F::acl(request, runtime)
        }
        fn evaluate_lifecycle(
            &mut self,
            request: LifecycleRequest,
            runtime: &mut dyn LifecycleRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            F::lifecycle(request, runtime)
        }
    }
    #[derive(Clone, Copy)]
    enum CorrectedCase {
        ValidGet,
        MacRejection,
        RoleDenial,
        CrossRoleResourceDenial,
        Containment,
        RestoreOpen,
        RollbackCompletion,
        InterruptedRestore,
        AclCheck,
        Fence,
        Revocation,
        Expiry,
        Rollback,
        Redaction,
    }
    /// The paired controls are deliberately narrow reference behaviors. They
    /// prove each mutant witness is attached to the very contract it claims
    /// to violate, without making the still-RED deployment boundary GREEN.
    struct CorrectedPort(CorrectedCase);
    impl CorrectedPort {
        fn new(case: CorrectedCase) -> Self {
            Self(case)
        }
    }
    impl DeploymentBoundaryPort for CorrectedPort {
        fn evaluate_ingress(
            &mut self,
            request: &IngressRequest,
            runtime: &mut dyn IngressRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            match self.0 {
                CorrectedCase::ValidGet => {
                    assert_eq!(request.method, Method::Get);
                    Ok(challenge())
                }
                CorrectedCase::MacRejection => {
                    assert_eq!(request.method, Method::Post);
                    assert!(!runtime.verify_raw_callback_hmac(request));
                    Ok(observation(SafeDisposition::Rejected))
                }
                CorrectedCase::CrossRoleResourceDenial => {
                    assert!(matches!(
                        request.denied_attempt,
                        Some(
                            IngressDeniedAttempt::AlertIntentPublish
                                | IngressDeniedAttempt::SharedStoreBypass
                                | IngressDeniedAttempt::DeserializedHandleBypass
                        )
                    ));
                    Ok(observation(SafeDisposition::RoleDenied))
                }
                _ => Err(DeploymentBoundaryError::MissingDeploymentBoundary),
            }
        }
        fn evaluate_outbound(
            &mut self,
            request: &OutboundRequest,
            _: &mut dyn OutboundRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            match self.0 {
                CorrectedCase::RoleDenial => {
                    assert_eq!(request.operation, OutboundOperation::EvidenceRead);
                    Ok(observation(SafeDisposition::RoleDenied))
                }
                CorrectedCase::CrossRoleResourceDenial => {
                    assert!(matches!(
                        request.operation,
                        OutboundOperation::EvidenceRead
                            | OutboundOperation::EvidenceMutate
                            | OutboundOperation::AlertIntentRead
                            | OutboundOperation::AlertIntentWrite
                            | OutboundOperation::SharedStoreBypass
                            | OutboundOperation::DeserializedHandleBypass
                    ));
                    Ok(observation(SafeDisposition::RoleDenied))
                }
                _ => Err(DeploymentBoundaryError::MissingDeploymentBoundary),
            }
        }
        fn evaluate_dispatcher(
            &mut self,
            request: &DispatcherRequest,
            _: &mut dyn DispatcherRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            match self.0 {
                CorrectedCase::Fence => {
                    assert_eq!(request.operation, DispatchOperation::SettleIntent);
                    Ok(observation(SafeDisposition::RoleDenied))
                }
                CorrectedCase::CrossRoleResourceDenial => {
                    assert!(matches!(
                        request.operation,
                        DispatchOperation::RegisteredCommandRead
                            | DispatchOperation::RegisteredCommandMutate
                            | DispatchOperation::ProviderCredentialRead
                            | DispatchOperation::EvidenceMutate
                            | DispatchOperation::SharedStoreBypass
                            | DispatchOperation::DeserializedHandleBypass
                    ));
                    Ok(observation(SafeDisposition::RoleDenied))
                }
                _ => Err(DeploymentBoundaryError::MissingDeploymentBoundary),
            }
        }
        fn evaluate_ntfy_acl(
            &mut self,
            request: NtfyAclRequest,
            _: &mut dyn NtfyAclRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            match self.0 {
                CorrectedCase::AclCheck => {
                    assert_eq!(request.principal, NtfyPrincipal::Anonymous);
                    assert_eq!(request.action, NtfyAction::Read);
                    Ok(observation(SafeDisposition::NtfyDenied))
                }
                _ => Err(DeploymentBoundaryError::MissingDeploymentBoundary),
            }
        }
        fn evaluate_lifecycle(
            &mut self,
            request: LifecycleRequest,
            runtime: &mut dyn LifecycleRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            match self.0 {
                CorrectedCase::Containment => {
                    assert!(matches!(
                        request.operation,
                        LifecycleOperation::SecretArtifact
                    ));
                    assert!(runtime.contain_secret_artifact());
                    Ok(observation(SafeDisposition::FaultDetected))
                }
                CorrectedCase::RestoreOpen => {
                    assert!(matches!(request.operation, LifecycleOperation::Restore(_)));
                    assert!(runtime.enter_restore_quarantine());
                    assert!(runtime.open_quarantined_restore());
                    Ok(observation(SafeDisposition::RestoreOpened))
                }
                CorrectedCase::RollbackCompletion => {
                    assert!(matches!(request.operation, LifecycleOperation::Rollback));
                    assert!(runtime.complete_rollback());
                    Ok(observation(SafeDisposition::RollbackComplete))
                }
                CorrectedCase::InterruptedRestore => {
                    let LifecycleOperation::Restore(restore) = request.operation else {
                        panic!("fixture requires restore request");
                    };
                    assert!(restore.reactivation_requested);
                    assert!(runtime.restore_environment().rollback_interrupted);
                    assert!(runtime.enter_restore_quarantine());
                    Ok(observation(SafeDisposition::RestoreQuarantined))
                }
                CorrectedCase::Revocation => {
                    assert!(matches!(
                        request.operation,
                        LifecycleOperation::StartWithCredential(_)
                    ));
                    Ok(observation(SafeDisposition::Rejected))
                }
                CorrectedCase::Expiry => {
                    assert!(matches!(request.operation, LifecycleOperation::Restore(_)));
                    assert!(runtime.quarantine_raw_restore_copy());
                    Ok(observation(SafeDisposition::RestoreQuarantined))
                }
                CorrectedCase::Rollback => {
                    assert!(matches!(request.operation, LifecycleOperation::Rollback));
                    Ok(observation(SafeDisposition::Rejected))
                }
                CorrectedCase::Redaction => {
                    assert!(matches!(
                        request.operation,
                        LifecycleOperation::SensitiveDiagnostic(DiagnosticArtifact::RawBody)
                    ));
                    Ok(observation(SafeDisposition::Rejected))
                }
                _ => Err(DeploymentBoundaryError::MissingDeploymentBoundary),
            }
        }
    }
    struct OmitValidGet;
    impl Fault for OmitValidGet {
        fn ingress(
            request: &IngressRequest,
            _: &mut dyn IngressRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            assert_eq!(request.method, Method::Get);
            Ok(observation(SafeDisposition::Rejected))
        }
    }
    struct OmitMacRejection;
    impl Fault for OmitMacRejection {
        fn ingress(
            request: &IngressRequest,
            runtime: &mut dyn IngressRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            assert_eq!(request.method, Method::Post);
            assert!(!runtime.verify_raw_callback_hmac(request));
            Ok(observation(SafeDisposition::CallbackAccepted))
        }
    }
    struct OmitRoleDenial;
    impl Fault for OmitRoleDenial {
        fn outbound(
            request: &OutboundRequest,
            runtime: &mut dyn OutboundRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            assert_eq!(request.operation, OutboundOperation::EvidenceRead);
            runtime.read_evidence_sentinel();
            Ok(observation(SafeDisposition::RoleDenied))
        }
    }
    /// A role boundary that acknowledges a prohibited request while touching
    /// the role-confined resource witness. Each match is deliberately closed:
    /// an ingress port cannot manufacture an outbound/dispatcher witness.
    struct OmitCrossRoleResourceDenial;
    impl Fault for OmitCrossRoleResourceDenial {
        fn ingress(
            request: &IngressRequest,
            runtime: &mut dyn IngressRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            let attempt = match request.denied_attempt {
                Some(IngressDeniedAttempt::AlertIntentPublish) => {
                    DeniedResourceAttempt::IngressAlertIntentPublish
                }
                Some(IngressDeniedAttempt::SharedStoreBypass) => {
                    DeniedResourceAttempt::IngressSharedStoreBypass
                }
                Some(IngressDeniedAttempt::DeserializedHandleBypass) => {
                    DeniedResourceAttempt::IngressDeserializedHandleBypass
                }
                _ => return Err(DeploymentBoundaryError::MissingDeploymentBoundary),
            };
            runtime.record_denied_ingress_resource(attempt);
            Ok(observation(SafeDisposition::RoleDenied))
        }
        fn outbound(
            request: &OutboundRequest,
            runtime: &mut dyn OutboundRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            let attempt = match request.operation {
                OutboundOperation::EvidenceRead => DeniedResourceAttempt::OutboundEvidenceRead,
                OutboundOperation::EvidenceMutate => DeniedResourceAttempt::OutboundEvidenceMutate,
                OutboundOperation::AlertIntentRead => {
                    DeniedResourceAttempt::OutboundAlertIntentRead
                }
                OutboundOperation::AlertIntentWrite => {
                    DeniedResourceAttempt::OutboundAlertIntentWrite
                }
                OutboundOperation::SharedStoreBypass => {
                    DeniedResourceAttempt::OutboundSharedStoreBypass
                }
                OutboundOperation::DeserializedHandleBypass => {
                    DeniedResourceAttempt::OutboundDeserializedHandleBypass
                }
                _ => return Err(DeploymentBoundaryError::MissingDeploymentBoundary),
            };
            runtime.record_denied_outbound_resource(attempt);
            Ok(observation(SafeDisposition::RoleDenied))
        }
        fn dispatcher(
            request: &DispatcherRequest,
            runtime: &mut dyn DispatcherRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            let attempt = match request.operation {
                DispatchOperation::RegisteredCommandRead => {
                    DeniedResourceAttempt::DispatcherRegisteredCommandRead
                }
                DispatchOperation::RegisteredCommandMutate => {
                    DeniedResourceAttempt::DispatcherRegisteredCommandMutate
                }
                DispatchOperation::ProviderCredentialRead => {
                    DeniedResourceAttempt::DispatcherProviderCredentialRead
                }
                DispatchOperation::EvidenceMutate => {
                    DeniedResourceAttempt::DispatcherEvidenceMutate
                }
                DispatchOperation::SharedStoreBypass => {
                    DeniedResourceAttempt::DispatcherSharedStoreBypass
                }
                DispatchOperation::DeserializedHandleBypass => {
                    DeniedResourceAttempt::DispatcherDeserializedHandleBypass
                }
                _ => return Err(DeploymentBoundaryError::MissingDeploymentBoundary),
            };
            runtime.record_denied_dispatcher_resource(attempt);
            Ok(observation(SafeDisposition::RoleDenied))
        }
    }
    struct OmitAclCheck;
    impl Fault for OmitAclCheck {
        fn acl(
            request: NtfyAclRequest,
            runtime: &mut dyn NtfyAclRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            assert_eq!(request.principal, NtfyPrincipal::Anonymous);
            assert_eq!(request.action, NtfyAction::Read);
            runtime.read_configured_topic_sentinel();
            Ok(observation(SafeDisposition::NtfyDenied))
        }
    }
    struct OmitFence;
    impl Fault for OmitFence {
        fn dispatcher(
            request: &DispatcherRequest,
            runtime: &mut dyn DispatcherRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            assert_eq!(
                runtime.attempt_safe_publish(),
                DispatchTransportResult::DefiniteRefusal
            );
            assert!(runtime.is_stale_lease_fence(request.requested_fence));
            Ok(observation(SafeDisposition::RoleDenied))
        }
    }
    struct OmitRevocation;
    impl Fault for OmitRevocation {
        fn lifecycle(
            request: LifecycleRequest,
            runtime: &mut dyn LifecycleRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            let LifecycleOperation::StartWithCredential(start) = request.operation else {
                panic!("fixture requires credential-start mutation");
            };
            assert_eq!(start.presented_generation, 1);
            assert!(runtime.fault_accept_revoked_credential_start());
            Ok(observation(SafeDisposition::Rejected))
        }
    }
    struct OmitExpiry;
    impl Fault for OmitExpiry {
        fn lifecycle(
            request: LifecycleRequest,
            runtime: &mut dyn LifecycleRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            let LifecycleOperation::Restore(_) = request.operation else {
                panic!("fixture requires restore mutation");
            };
            assert!(runtime.restore_environment().raw_record_expired);
            assert!(runtime.quarantine_raw_restore_copy());
            assert!(runtime.fault_open_quarantined_restore());
            Ok(observation(SafeDisposition::RestoreQuarantined))
        }
    }
    struct OmitRollback;
    impl Fault for OmitRollback {
        fn lifecycle(
            request: LifecycleRequest,
            runtime: &mut dyn LifecycleRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            assert!(matches!(request.operation, LifecycleOperation::Rollback));
            assert!(runtime.fault_disable_route_without_rollback());
            Ok(observation(SafeDisposition::Rejected))
        }
    }
    struct OmitRedaction;
    impl Fault for OmitRedaction {
        fn lifecycle(
            request: LifecycleRequest,
            runtime: &mut dyn LifecycleRuntime,
        ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
            assert_eq!(
                request.operation,
                LifecycleOperation::SensitiveDiagnostic(DiagnosticArtifact::RawBody)
            );
            assert!(runtime.fault_store_sensitive_diagnostic());
            Ok(observation(SafeDisposition::Rejected))
        }
    }
    let mut valid_get_fault = FaultyPort::<OmitValidGet>::new();
    let mut mac_fault = FaultyPort::<OmitMacRejection>::new();
    let mut role_fault = FaultyPort::<OmitRoleDenial>::new();
    let mut cross_role_resource_fault = FaultyPort::<OmitCrossRoleResourceDenial>::new();
    let mut acl_fault = FaultyPort::<OmitAclCheck>::new();
    let mut fence_fault = FaultyPort::<OmitFence>::new();
    let mut revocation_fault = FaultyPort::<OmitRevocation>::new();
    let mut expiry_fault = FaultyPort::<OmitExpiry>::new();
    let mut rollback_fault = FaultyPort::<OmitRollback>::new();
    let mut redaction_fault = FaultyPort::<OmitRedaction>::new();
    let before = state();
    let mut containment_before = state();
    containment_before
        .lifecycle
        .secret_diagnostic_artifact_present = true;
    let mut containment_after = containment_before.clone();
    containment_after
        .lifecycle
        .secret_diagnostic_artifact_present = false;
    containment_after.lifecycle.safe_incidents = 1;
    containment_after.lifecycle.credential_generation = 2;
    containment_after.lifecycle.revoked_credential_generations = vec![1];
    let mut containment_control = CorrectedPort::new(CorrectedCase::Containment);
    require_corrected_contract(
        &mut containment_control,
        contract(
            BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::SecretArtifact)),
            containment_before,
            observation(SafeDisposition::FaultDetected),
            containment_after,
        )
        .with_expected_lifecycle(LifecycleLedger {
            events: vec![
                LifecycleEvent::SecretArtifactDetected,
                LifecycleEvent::SecretArtifactDeleted,
                LifecycleEvent::CredentialGenerationRevoked,
            ],
        }),
        "D12 containment and revocation",
    );
    let restore_before = rollback_ready_state();
    let mut restore_after = restore_before.clone();
    restore_after.lifecycle.restore_quarantined = true;
    restore_after.lifecycle.restore_state_opened = true;
    let mut restore_control = CorrectedPort::new(CorrectedCase::RestoreOpen);
    require_corrected_contract(
        &mut restore_control,
        contract(
            BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::Restore(restore(|_| {})))),
            restore_before,
            observation(SafeDisposition::RestoreOpened),
            restore_after,
        )
        .with_expected_lifecycle(LifecycleLedger {
            events: vec![
                LifecycleEvent::RestoreQuarantined,
                LifecycleEvent::RestoreStateOpened,
            ],
        }),
        "D13 quarantine before state-open",
    );
    let rollback_before = rollback_ready_state();
    let mut rollback_completion_control = CorrectedPort::new(CorrectedCase::RollbackCompletion);
    require_corrected_contract(
        &mut rollback_completion_control,
        contract(
            BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::Rollback)),
            rollback_before.clone(),
            observation(SafeDisposition::RollbackComplete),
            rollback_before,
        )
        .with_expected_lifecycle(LifecycleLedger {
            events: vec![LifecycleEvent::RollbackCompleted],
        }),
        "D15 all authority disabled before rollback completion",
    );
    let interrupted_before = rollback_ready_state();
    let mut interrupted_after = interrupted_before.clone();
    interrupted_after.lifecycle.restore_quarantined = true;
    let mut interrupted_restore_control = CorrectedPort::new(CorrectedCase::InterruptedRestore);
    require_corrected_contract(
        &mut interrupted_restore_control,
        contract(
            BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::Restore(restore(|request| {
                request.reactivation_requested = true
            })))),
            interrupted_before,
            observation(SafeDisposition::RestoreQuarantined),
            interrupted_after,
        )
        .with_expected_lifecycle(LifecycleLedger {
            events: vec![LifecycleEvent::RestoreQuarantined],
        })
        .with_restore_environment(restore_environment(|environment| {
            environment.rollback_interrupted = true
        })),
        "D22 interrupted rollback remains quarantined",
    );
    let mut valid_get_control = CorrectedPort::new(CorrectedCase::ValidGet);
    require_fault_control(
        &mut valid_get_control,
        &mut valid_get_fault,
        contract(
            BoundaryCall::Ingress(ingress(|_| {})),
            before.clone(),
            challenge(),
            before.clone(),
        ),
        "valid-GET response",
        |actual, expected| {
            assert_observation_witness(
                actual,
                expected,
                observation(SafeDisposition::Rejected),
                "valid-GET response",
            );
        },
    );
    let mut mac_rejected = before.clone();
    mac_rejected.ingress.verification_attempts = 1;
    let mut mac_control = CorrectedPort::new(CorrectedCase::MacRejection);
    require_fault_control(
        &mut mac_control,
        &mut mac_fault,
        contract(
            BoundaryCall::Ingress(post(|request| request.raw_body.push(b' '))),
            before.clone(),
            observation(SafeDisposition::Rejected),
            mac_rejected,
        )
        .with_expected_ingress(IngressLedger {
            events: vec![IngressEvent::MacChecked],
        }),
        "MAC rejection",
        |actual, expected| {
            assert_observation_witness(
                actual,
                expected,
                observation(SafeDisposition::CallbackAccepted),
                "MAC rejection",
            );
        },
    );
    let mut role_control = CorrectedPort::new(CorrectedCase::RoleDenial);
    require_fault_control(
        &mut role_control,
        &mut role_fault,
        contract(
            BoundaryCall::Outbound(outbound(OutboundOperation::EvidenceRead)),
            before.clone(),
            observation(SafeDisposition::RoleDenied),
            before.clone(),
        ),
        "role denial",
        |actual, expected| {
            assert_resource_witness(
                actual,
                expected,
                ResourceLedger {
                    evidence_reads: 1,
                    ..ResourceLedger::default()
                },
                "role denial",
            );
        },
    );
    let mut cross_role_resource_control =
        CorrectedPort::new(CorrectedCase::CrossRoleResourceDenial);
    for attempt in [
        DeniedResourceAttempt::IngressAlertIntentPublish,
        DeniedResourceAttempt::IngressSharedStoreBypass,
        DeniedResourceAttempt::IngressDeserializedHandleBypass,
    ] {
        require_fault_control(
            &mut cross_role_resource_control,
            &mut cross_role_resource_fault,
            denied_ingress_resource(attempt, before.clone()),
            "ingress cross-role resource denial",
            |actual, expected| {
                assert_resource_witness(
                    actual,
                    expected,
                    ResourceLedger {
                        denied_attempts: vec![attempt],
                        ..ResourceLedger::default()
                    },
                    "ingress cross-role resource denial",
                );
            },
        );
    }
    for attempt in [
        DeniedResourceAttempt::OutboundEvidenceRead,
        DeniedResourceAttempt::OutboundEvidenceMutate,
        DeniedResourceAttempt::OutboundAlertIntentRead,
        DeniedResourceAttempt::OutboundAlertIntentWrite,
        DeniedResourceAttempt::OutboundSharedStoreBypass,
        DeniedResourceAttempt::OutboundDeserializedHandleBypass,
    ] {
        require_fault_control(
            &mut cross_role_resource_control,
            &mut cross_role_resource_fault,
            denied_outbound_resource(attempt, before.clone()),
            "outbound cross-role resource denial",
            |actual, expected| {
                assert_resource_witness(
                    actual,
                    expected,
                    ResourceLedger {
                        denied_attempts: vec![attempt],
                        ..ResourceLedger::default()
                    },
                    "outbound cross-role resource denial",
                );
            },
        );
    }
    for attempt in [
        DeniedResourceAttempt::DispatcherRegisteredCommandRead,
        DeniedResourceAttempt::DispatcherRegisteredCommandMutate,
        DeniedResourceAttempt::DispatcherProviderCredentialRead,
        DeniedResourceAttempt::DispatcherEvidenceMutate,
        DeniedResourceAttempt::DispatcherSharedStoreBypass,
        DeniedResourceAttempt::DispatcherDeserializedHandleBypass,
    ] {
        require_fault_control(
            &mut cross_role_resource_control,
            &mut cross_role_resource_fault,
            denied_dispatcher_resource(attempt, before.clone()),
            "dispatcher cross-role resource denial",
            |actual, expected| {
                assert_resource_witness(
                    actual,
                    expected,
                    ResourceLedger {
                        denied_attempts: vec![attempt],
                        ..ResourceLedger::default()
                    },
                    "dispatcher cross-role resource denial",
                );
            },
        );
    }
    let mut acl_control = CorrectedPort::new(CorrectedCase::AclCheck);
    require_fault_control(
        &mut acl_control,
        &mut acl_fault,
        contract(
            BoundaryCall::Acl(acl(
                NtfyPrincipal::Anonymous,
                NtfyAction::Read,
                TopicScope::Configured,
            )),
            before.clone(),
            observation(SafeDisposition::NtfyDenied),
            before.clone(),
        ),
        "ACL check",
        |actual, expected| {
            assert_resource_witness(
                actual,
                expected,
                ResourceLedger {
                    configured_topic_reads: 1,
                    ..ResourceLedger::default()
                },
                "ACL check",
            );
        },
    );
    let mut dispatcher_before = state_with_intent();
    dispatcher_before.dispatcher.alert_intent = Some(AlertIntentState {
        lease_fence: 2,
        leased: true,
        attempts: 1,
        delivered: false,
        ambiguous: false,
        retry_limit: 3,
    });
    let mut settle = dispatcher(DispatchOperation::SettleIntent);
    settle.requested_fence = 1;
    let mut fence_control = CorrectedPort::new(CorrectedCase::Fence);
    require_fault_control(
        &mut fence_control,
        &mut fence_fault,
        contract(
            BoundaryCall::Dispatcher(settle),
            dispatcher_before.clone(),
            observation(SafeDisposition::RoleDenied),
            dispatcher_before,
        )
        .with_publisher_outcome(DispatchTransportResult::DefiniteRefusal),
        "fence",
        |actual, expected| {
            assert_publisher_witness(
                actual,
                expected,
                PublisherLedger {
                    attempts: 1,
                    acceptances: 0,
                },
                "fence",
            );
        },
    );
    let mut revoked_before = before.clone();
    revoked_before
        .lifecycle
        .revoked_credential_generations
        .push(1);
    let mut revocation_control = CorrectedPort::new(CorrectedCase::Revocation);
    require_fault_control(
        &mut revocation_control,
        &mut revocation_fault,
        contract(
            BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::StartWithCredential(
                credential(|request| request.presented_generation = 1),
            ))),
            revoked_before.clone(),
            observation(SafeDisposition::Rejected),
            revoked_before,
        ),
        "revocation",
        |actual, expected| {
            let mut witness = expected.state.clone();
            witness.lifecycle.credential_start_records += 1;
            assert_state_witness(actual, expected, witness, "revocation");
        },
    );
    let mut expired_before = before.clone();
    expired_before.lifecycle.raw_restore_copies = 1;
    let mut expired_after = expired_before.clone();
    expired_after.lifecycle.restore_quarantined = true;
    expired_after.lifecycle.raw_restore_copies = 0;
    expired_after.lifecycle.safe_restore_dispositions = 1;
    let mut expiry_control = CorrectedPort::new(CorrectedCase::Expiry);
    require_fault_control(
        &mut expiry_control,
        &mut expiry_fault,
        contract(
            BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::Restore(restore(|_| {})))),
            expired_before,
            observation(SafeDisposition::RestoreQuarantined),
            expired_after,
        )
        .with_expected_lifecycle(LifecycleLedger {
            events: vec![
                LifecycleEvent::RestoreQuarantined,
                LifecycleEvent::RawCopyWithheld,
            ],
        })
        .with_restore_environment(restore_environment(|environment| {
            environment.raw_record_expired = true
        })),
        "expiry",
        |actual, expected| {
            let mut witness = expected.state.clone();
            witness.lifecycle.restore_state_opened = true;
            assert_state_witness(actual, expected, witness, "expiry");
        },
    );
    let mut rollback_control = CorrectedPort::new(CorrectedCase::Rollback);
    require_fault_control(
        &mut rollback_control,
        &mut rollback_fault,
        contract(
            BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::Rollback)),
            before.clone(),
            observation(SafeDisposition::Rejected),
            before.clone(),
        ),
        "rollback",
        |actual, expected| {
            let mut witness = expected.state.clone();
            witness.lifecycle.route_enabled = false;
            assert_state_witness(actual, expected, witness, "rollback");
        },
    );
    let mut redaction_control = CorrectedPort::new(CorrectedCase::Redaction);
    require_fault_control(
        &mut redaction_control,
        &mut redaction_fault,
        contract(
            BoundaryCall::Lifecycle(lifecycle(LifecycleOperation::SensitiveDiagnostic(
                DiagnosticArtifact::RawBody,
            ))),
            before.clone(),
            observation(SafeDisposition::Rejected),
            before,
        ),
        "redaction",
        |actual, expected| {
            let mut witness = expected.state.clone();
            witness.lifecycle.secret_diagnostic_artifact_present = true;
            assert_state_witness(actual, expected, witness, "redaction");
        },
    );
}
