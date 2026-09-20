//! Private typed boundary for the Phase 0B deployment-plan RED.
//!
//! This module models only in-memory fixture authority. The operation that
//! reaches a port method selects its role: there is deliberately no caller
//! supplied role field and no composite mutable state handle.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Method {
    Get,
    Post,
    Other,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CredentialStartRequest {
    pub(crate) in_arguments: bool,
    pub(crate) in_environment: bool,
    pub(crate) broad_file_access: bool,
    pub(crate) mounted_file_access: bool,
    pub(crate) wrong_role_mount: bool,
    pub(crate) presented_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NetworkAttempt {
    Connect,
    Bind,
    Resolve,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IngressDeniedAttempt {
    ExternalNetwork(NetworkAttempt),
    ProviderCredentialRead,
    NtfyCredentialRead,
    RegisteredCommandRead,
    RegisteredCommandWrite,
    RegisteredCommandMutate,
    AlertIntentPublish,
    SharedStoreBypass,
    DeserializedHandleBypass,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutboundOperation {
    ReadExactRegisteredCommand,
    CallerSuppliedProviderAuthority,
    EvidenceRead,
    EvidenceMutate,
    AlertIntentRead,
    AlertIntentWrite,
    SharedStoreBypass,
    DeserializedHandleBypass,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DispatchOperation {
    AcquireLease,
    PublishConfiguredSafeIntent,
    ReadRawCallbackBody,
    ReadTopic,
    PublishForeignTopic,
    RegisteredCommandRead,
    RegisteredCommandMutate,
    EvidenceMutate,
    ProviderCredentialRead,
    SharedStoreBypass,
    DeserializedHandleBypass,
    SettleIntent,
}

/// Closed, safe witnesses for cross-role access attempts. They retain neither
/// resource data nor an authority token, only the exact prohibited capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // Variants become reachable when the frozen RED turns GREEN.
pub(crate) enum DeniedResourceAttempt {
    IngressAlertIntentPublish,
    IngressSharedStoreBypass,
    IngressDeserializedHandleBypass,
    OutboundEvidenceRead,
    OutboundEvidenceMutate,
    OutboundAlertIntentRead,
    OutboundAlertIntentWrite,
    OutboundSharedStoreBypass,
    OutboundDeserializedHandleBypass,
    DispatcherRegisteredCommandRead,
    DispatcherRegisteredCommandMutate,
    DispatcherProviderCredentialRead,
    DispatcherEvidenceMutate,
    DispatcherSharedStoreBypass,
    DispatcherDeserializedHandleBypass,
}

/// Result supplied by the dispatcher-owned fixture transport, never by the
/// caller's request. A future boundary must react to the observed transport
/// result rather than trust a test-selected fault label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DispatchTransportResult {
    Accepted,
    DefiniteRefusal,
    CrashBeforeAttempt,
    CrashAfterAcceptedPublish,
}

/// Closed results for the dispatcher-owned lease transition.  The boundary
/// chooses a safe disposition from these witnesses; callers cannot supply a
/// transport or lease outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeaseResult {
    Acquired,
    Denied,
}

/// Closed results for settlement of a dispatcher-owned safe alert intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SettlementResult {
    Delivered,
    Retryable,
    Exhausted,
    Ambiguous,
    Denied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NtfyPrincipal {
    Anonymous,
    ConfiguredPublisher,
    ConfiguredReader,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NtfyAction {
    Read,
    Publish,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TopicScope {
    Configured,
    Foreign,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NtfyPermissions {
    pub(crate) configured_read: bool,
    pub(crate) configured_publish: bool,
    pub(crate) foreign_read: bool,
    pub(crate) foreign_publish: bool,
}

/// Concrete effective fixture ACL. It deliberately carries permissions for
/// every principal/topic operation instead of one scenario label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NtfyAclRules {
    pub(crate) anonymous: NtfyPermissions,
    pub(crate) publisher: NtfyPermissions,
    pub(crate) reader: NtfyPermissions,
}

impl NtfyAclRules {
    pub(crate) fn exact_private() -> Self {
        Self {
            anonymous: NtfyPermissions::default(),
            publisher: NtfyPermissions {
                configured_publish: true,
                ..NtfyPermissions::default()
            },
            reader: NtfyPermissions {
                configured_read: true,
                ..NtfyPermissions::default()
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LifecycleOperation {
    PublicManagementSurface,
    SensitiveDiagnostic(DiagnosticArtifact),
    SecretArtifact,
    Restore(RestoreRequest),
    Rollback,
    StartWithCredential(CredentialStartRequest),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DiagnosticArtifact {
    RawBody,
    RawQuery,
    SecretMarker,
    AuthorizationHeader,
    ContentField,
}

/// Concrete restore preconditions and snapshot attributes. Values are safe
/// booleans/generations only; the fixture never contains raw backup content.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RestoreRequest {
    pub(crate) requested_generation: u64,
    pub(crate) reactivation_requested: bool,
}

/// Effective restore environment supplied by the fixture runtime rather than
/// the request sender. It contains only safe operational booleans/generation
/// metadata; raw records and credentials are never represented.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RestoreEnvironment {
    pub(crate) network_available: bool,
    pub(crate) credential_mounted: bool,
    pub(crate) scheduler_enabled: bool,
    pub(crate) snapshot_generation: u64,
    pub(crate) rollback_interrupted: bool,
    pub(crate) raw_record_expired: bool,
    pub(crate) raw_record_opted_out: bool,
}

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

/// Raw callback transport belongs only to the ingress entrypoint. A future
/// verifier must decide over these original bytes before parsing or mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IngressRequest {
    pub(crate) method: Method,
    /// Unnormalized request-target bytes. The boundary must accept only its
    /// exact configured callback path, not an enum classification supplied by
    /// the caller.
    pub(crate) path: Vec<u8>,
    pub(crate) elapsed_millis: u64,
    pub(crate) denied_attempt: Option<IngressDeniedAttempt>,
    pub(crate) raw_body: Vec<u8>,
    pub(crate) headers: Vec<Header>,
    pub(crate) query_parameters: Vec<QueryParameter>,
    pub(crate) verification_token: Vec<u8>,
    pub(crate) app_secret: [u8; 32],
    pub(crate) active_waba_id: Vec<u8>,
    pub(crate) active_phone_number_id: Vec<u8>,
}

impl IngressRequest {
    pub(crate) fn challenge() -> Self {
        Self {
            method: Method::Get,
            path: b"/webhooks/whatsapp".to_vec(),
            elapsed_millis: 4,
            denied_attempt: None,
            raw_body: Vec::new(),
            headers: Vec::new(),
            query_parameters: vec![
                QueryParameter {
                    name: b"hub.mode".to_vec(),
                    value: b"subscribe".to_vec(),
                },
                QueryParameter {
                    name: b"hub.verify_token".to_vec(),
                    value: b"deployment-verify".to_vec(),
                },
                QueryParameter {
                    name: b"hub.challenge".to_vec(),
                    value: b"fixture-challenge".to_vec(),
                },
            ],
            verification_token: b"deployment-verify".to_vec(),
            app_secret: [0x6b; 32],
            active_waba_id: b"fixture-waba-7".to_vec(),
            active_phone_number_id: b"fixture-phone-8".to_vec(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OutboundRequest {
    pub(crate) operation: OutboundOperation,
    pub(crate) credential_in_wrong_role: bool,
}
impl OutboundRequest {
    pub(crate) fn registered_command() -> Self {
        Self {
            operation: OutboundOperation::ReadExactRegisteredCommand,
            credential_in_wrong_role: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DispatcherRequest {
    pub(crate) operation: DispatchOperation,
    pub(crate) requested_fence: u64,
}
impl DispatcherRequest {
    pub(crate) fn configured_safe_intent() -> Self {
        Self {
            operation: DispatchOperation::PublishConfiguredSafeIntent,
            requested_fence: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NtfyAclRequest {
    pub(crate) principal: NtfyPrincipal,
    pub(crate) action: NtfyAction,
    pub(crate) topic: TopicScope,
    pub(crate) rules: NtfyAclRules,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LifecycleRequest {
    pub(crate) operation: LifecycleOperation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SafeDisposition {
    ChallengeAccepted,
    Rejected,
    CallbackAccepted,
    RegisteredCommandAccepted,
    RoleDenied,
    NtfyAllowed,
    NtfyDenied,
    IntentRetryable,
    IntentExhausted,
    IntentAmbiguous,
    CredentialStartAccepted,
    RestoreOpened,
    RestoreQuarantined,
    RollbackComplete,
    FaultDetected,
}

/// Safe causal order witnesses for callback handling. They retain no request
/// bytes or parsed content and are deliberately distinct from mutable ingress
/// record counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IngressEvent {
    MacChecked,
    MacVerified,
    Parsed,
    TransactionProposed,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct IngressState {
    /// Ordering witnesses: parser/transaction may advance only after a raw
    /// signature verification. They carry counts, never payload content.
    pub(crate) verification_attempts: u32,
    pub(crate) parser_attempts: u32,
    pub(crate) transaction_attempts: u32,
    pub(crate) safe_events: u32,
    pub(crate) alert_intents: u32,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct OutboundState {
    pub(crate) registered_commands: u32,
    /// Safe count only: no destination, body, provider identifier or credential
    /// enters the deployment fixture. D23 requires this evidence to change
    /// after the exact registered command is accepted.
    pub(crate) provider_attempt_records: u32,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DispatcherState {
    pub(crate) published_alerts: u32,
    pub(crate) alert_intent: Option<AlertIntentState>,
}
/// Safe authorization evidence for the private ntfy fixture. It records only
/// a configured-topic read/publish decision, never topic text or content.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct NtfyAclState {
    pub(crate) configured_read_observations: u32,
    pub(crate) configured_publish_observations: u32,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct LifecycleState {
    pub(crate) credential_generation: u64,
    /// Fixture-only presence bit for a deliberately created secret-bearing
    /// diagnostic artifact. It never stores the marker or a credential value.
    pub(crate) secret_diagnostic_artifact_present: bool,
    /// Safe containment evidence: count only, never raw incident content.
    pub(crate) safe_incidents: u32,
    /// Generations that were explicitly revoked during containment. A later
    /// role-start request must reject these rather than treating rotation as
    /// sufficient authorization.
    pub(crate) revoked_credential_generations: Vec<u64>,
    /// Restore must enter quarantine before any snapshot state is opened.
    pub(crate) restore_quarantined: bool,
    pub(crate) restore_state_opened: bool,
    /// Presence-only counters for isolated raw copies and their surviving safe
    /// disposition. No raw record is represented in this fixture.
    pub(crate) raw_restore_copies: u32,
    pub(crate) safe_restore_dispositions: u32,
    /// Existing retention anchor; restore must never reset it.
    pub(crate) retention_anchor: u64,
    pub(crate) sender_generation: u64,
    pub(crate) route_enabled: bool,
    pub(crate) service_unit_enabled: bool,
    pub(crate) scheduler_enabled: bool,
    pub(crate) sender_generation_active: bool,
    pub(crate) credential_generation_active: bool,
    pub(crate) credential_start_records: u32,
    pub(crate) alert_publisher_active: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LifecycleEvent {
    SecretArtifactDetected,
    SecretArtifactDeleted,
    CredentialGenerationRevoked,
    RestoreQuarantined,
    RawCopyWithheld,
    RestoreStateOpened,
    RollbackCompleted,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DeploymentState {
    pub(crate) ingress: IngressState,
    pub(crate) outbound: OutboundState,
    pub(crate) dispatcher: DispatcherState,
    pub(crate) ntfy_acl: NtfyAclState,
    pub(crate) lifecycle: LifecycleState,
}

/// Safe dispatcher state: no destination, body, provider identity or credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AlertIntentState {
    pub(crate) lease_fence: u64,
    pub(crate) leased: bool,
    pub(crate) attempts: u32,
    pub(crate) delivered: bool,
    pub(crate) ambiguous: bool,
    pub(crate) retry_limit: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeploymentObservation {
    pub(crate) disposition: SafeDisposition,
    pub(crate) response: DeploymentResponse,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeploymentResponse {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
}

#[allow(dead_code)]
pub(crate) trait IngressRuntime {
    /// Performs verification over the original callback bytes and records the
    /// check (and only a successful verification) itself.
    fn verify_raw_callback_hmac(&mut self, request: &IngressRequest) -> bool;
    /// Records parsing only after the runtime observed a verified MAC.
    fn parse_verified_callback(&mut self) -> bool;
    /// Records proposal only after the runtime observed parsing.
    fn propose_verified_transaction(&mut self) -> bool;
    fn record_denied_ingress_resource(&mut self, attempt: DeniedResourceAttempt);
}
#[allow(dead_code)]
pub(crate) trait OutboundRuntime {
    /// Accepts the single pre-registered command without exposing a provider
    /// credential or command contents to the boundary.
    fn accept_exact_registered_command(&mut self, request: &OutboundRequest) -> bool;
    /// Test-only typed evidence resource. Correct outbound behavior has no
    /// reason to call it; a mutant that reads evidence leaves independent
    /// sentinel evidence outside replaceable outbound state.
    fn read_evidence_sentinel(&mut self);
    fn record_denied_outbound_resource(&mut self, attempt: DeniedResourceAttempt);
}
#[allow(dead_code)]
pub(crate) trait DispatcherRuntime {
    /// Acquires the next fenced lease for the sole safe alert intent.
    fn acquire_safe_intent_lease(&mut self, requested_fence: u64) -> LeaseResult;
    /// Settles a fenced intent through the dispatcher-owned publisher.
    fn settle_safe_intent(&mut self, requested_fence: u64) -> SettlementResult;
    /// Answers the only fence question a caller may ask. It exposes neither
    /// the current fence value nor the intent object/state.
    fn is_stale_lease_fence(&self, requested_fence: u64) -> bool;
    /// Performs one fake-publisher attempt. The runtime must record attempt
    /// and acceptance evidence before returning the injected transport point;
    /// a boundary cannot receive a result label from its caller.
    fn attempt_safe_publish(&mut self) -> DispatchTransportResult;
    fn record_denied_dispatcher_resource(&mut self, attempt: DeniedResourceAttempt);
}
#[allow(dead_code)]
pub(crate) trait NtfyAclRuntime {
    /// Evaluates an exact private ACL and records only a safe authorization
    /// observation for its configured topic.
    fn evaluate_private_acl(&mut self, request: NtfyAclRequest) -> bool;
    /// Test-only typed configured-topic resource witness for ACL mutants.
    fn read_configured_topic_sentinel(&mut self);
}
#[allow(dead_code)]
pub(crate) trait LifecycleRuntime {
    /// Starts only the current, correctly placed and non-revoked credential.
    fn start_current_credential(&mut self, request: CredentialStartRequest) -> bool;
    /// Reports whether every persisted authority is inactive before a
    /// quarantined restore may open state.
    fn restore_activation_is_inactive(&self) -> bool;
    /// Enters a safe restore quarantine before any restored state can open.
    /// Unlike raw-copy disposition, this records no raw-data decision.
    fn enter_restore_quarantine(&mut self) -> bool;
    /// Performs the expired/opted-out raw-copy disposition and emits its
    /// ordered quarantine/withheld evidence as one causal operation.
    fn quarantine_raw_restore_copy(&mut self) -> bool;
    /// Contains a present secret artifact and records detection, deletion and
    /// revocation as one irreversible fixture transition.
    fn contain_secret_artifact(&mut self) -> bool;
    /// Opens restored state only after the runtime has recorded quarantine and
    /// the effective environment remains offline and inactive.
    fn open_quarantined_restore(&mut self) -> bool;
    /// Records completion only when every authority was already disabled.
    fn complete_rollback(&mut self) -> bool;
    /// D24-only fault witnesses. These model one narrowly named forbidden
    /// effect each; they deliberately do not expose arbitrary lifecycle state.
    fn fault_accept_revoked_credential_start(&mut self) -> bool;
    fn fault_open_quarantined_restore(&mut self) -> bool;
    fn fault_disable_route_without_rollback(&mut self) -> bool;
    fn fault_store_sensitive_diagnostic(&mut self) -> bool;
    fn restore_environment(&self) -> RestoreEnvironment;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeploymentBoundaryError {
    MissingDeploymentBoundary,
}

/// Separate methods make authority selection an entrypoint property. No method
/// receives full deployment state or another role facade.
pub(crate) trait DeploymentBoundaryPort {
    fn evaluate_ingress(
        &mut self,
        request: &IngressRequest,
        runtime: &mut dyn IngressRuntime,
    ) -> Result<DeploymentObservation, DeploymentBoundaryError>;
    fn evaluate_outbound(
        &mut self,
        request: &OutboundRequest,
        runtime: &mut dyn OutboundRuntime,
    ) -> Result<DeploymentObservation, DeploymentBoundaryError>;
    fn evaluate_dispatcher(
        &mut self,
        request: &DispatcherRequest,
        runtime: &mut dyn DispatcherRuntime,
    ) -> Result<DeploymentObservation, DeploymentBoundaryError>;
    fn evaluate_ntfy_acl(
        &mut self,
        request: NtfyAclRequest,
        runtime: &mut dyn NtfyAclRuntime,
    ) -> Result<DeploymentObservation, DeploymentBoundaryError>;
    fn evaluate_lifecycle(
        &mut self,
        request: LifecycleRequest,
        runtime: &mut dyn LifecycleRuntime,
    ) -> Result<DeploymentObservation, DeploymentBoundaryError>;
}

struct GreenDeploymentBoundary;

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

fn challenge_observation() -> DeploymentObservation {
    DeploymentObservation {
        disposition: SafeDisposition::ChallengeAccepted,
        response: DeploymentResponse {
            status: 200,
            body: b"fixture-challenge".to_vec(),
        },
    }
}

fn is_exact_challenge(request: &IngressRequest) -> bool {
    request.method == Method::Get
        && request.path == b"/webhooks/whatsapp"
        && request.elapsed_millis <= 5_000
        && request.denied_attempt.is_none()
        && request.raw_body.is_empty()
        && request.headers.is_empty()
        && request.verification_token == b"deployment-verify"
        && request.query_parameters
            == [
                QueryParameter {
                    name: b"hub.mode".to_vec(),
                    value: b"subscribe".to_vec(),
                },
                QueryParameter {
                    name: b"hub.verify_token".to_vec(),
                    value: b"deployment-verify".to_vec(),
                },
                QueryParameter {
                    name: b"hub.challenge".to_vec(),
                    value: b"fixture-challenge".to_vec(),
                },
            ]
}

fn has_exact_post_transport(request: &IngressRequest) -> bool {
    request.method == Method::Post
        && request.path == b"/webhooks/whatsapp"
        && request.elapsed_millis <= 5_000
        && request.denied_attempt.is_none()
        && !request.raw_body.is_empty()
        && request.raw_body.len() <= 262_144
        && request.query_parameters.is_empty()
        && request.headers.len() == 2
        && request.headers[0].name == b"content-type"
        && request.headers[0].value == b"application/json; charset=utf-8"
        && request.headers[1].name == b"x-hub-signature-256"
        && request.headers[1].value.len() == 71
        && request.headers[1].value.starts_with(b"sha256=")
        && request.headers[1].value[7..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        && request.headers[1].value[7..]
            .iter()
            .any(|byte| *byte != b'0')
}

impl DeploymentBoundaryPort for GreenDeploymentBoundary {
    fn evaluate_ingress(
        &mut self,
        request: &IngressRequest,
        runtime: &mut dyn IngressRuntime,
    ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
        if request.denied_attempt.is_some() {
            return Ok(observation(SafeDisposition::RoleDenied));
        }
        if is_exact_challenge(request) {
            return Ok(challenge_observation());
        }
        if !has_exact_post_transport(request) {
            return Ok(observation(SafeDisposition::Rejected));
        }
        if !runtime.verify_raw_callback_hmac(request)
            || !runtime.parse_verified_callback()
            || !runtime.propose_verified_transaction()
        {
            return Ok(observation(SafeDisposition::Rejected));
        }
        Ok(observation(SafeDisposition::CallbackAccepted))
    }
    fn evaluate_outbound(
        &mut self,
        request: &OutboundRequest,
        runtime: &mut dyn OutboundRuntime,
    ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
        if request.operation == OutboundOperation::ReadExactRegisteredCommand
            && !request.credential_in_wrong_role
            && runtime.accept_exact_registered_command(request)
        {
            return Ok(observation(SafeDisposition::RegisteredCommandAccepted));
        }
        Ok(observation(
            if request.operation == OutboundOperation::CallerSuppliedProviderAuthority
                || request.credential_in_wrong_role
            {
                SafeDisposition::Rejected
            } else {
                SafeDisposition::RoleDenied
            },
        ))
    }
    fn evaluate_dispatcher(
        &mut self,
        request: &DispatcherRequest,
        runtime: &mut dyn DispatcherRuntime,
    ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
        let settlement = match request.operation {
            DispatchOperation::AcquireLease => {
                match runtime.acquire_safe_intent_lease(request.requested_fence) {
                    LeaseResult::Acquired => return Ok(observation(SafeDisposition::NtfyAllowed)),
                    LeaseResult::Denied => return Ok(observation(SafeDisposition::RoleDenied)),
                }
            }
            DispatchOperation::SettleIntent => runtime.settle_safe_intent(request.requested_fence),
            DispatchOperation::PublishConfiguredSafeIntent => {
                match runtime.acquire_safe_intent_lease(1) {
                    LeaseResult::Acquired => runtime.settle_safe_intent(1),
                    LeaseResult::Denied => SettlementResult::Denied,
                }
            }
            _ => return Ok(observation(SafeDisposition::RoleDenied)),
        };
        Ok(observation(match settlement {
            SettlementResult::Delivered => SafeDisposition::NtfyAllowed,
            SettlementResult::Retryable => SafeDisposition::IntentRetryable,
            SettlementResult::Exhausted => SafeDisposition::IntentExhausted,
            SettlementResult::Ambiguous => SafeDisposition::IntentAmbiguous,
            SettlementResult::Denied => SafeDisposition::RoleDenied,
        }))
    }
    fn evaluate_ntfy_acl(
        &mut self,
        request: NtfyAclRequest,
        runtime: &mut dyn NtfyAclRuntime,
    ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
        Ok(observation(if runtime.evaluate_private_acl(request) {
            SafeDisposition::NtfyAllowed
        } else {
            SafeDisposition::NtfyDenied
        }))
    }
    fn evaluate_lifecycle(
        &mut self,
        request: LifecycleRequest,
        runtime: &mut dyn LifecycleRuntime,
    ) -> Result<DeploymentObservation, DeploymentBoundaryError> {
        let disposition = match request.operation {
            LifecycleOperation::PublicManagementSurface
            | LifecycleOperation::SensitiveDiagnostic(_) => SafeDisposition::Rejected,
            LifecycleOperation::SecretArtifact => {
                if runtime.contain_secret_artifact() {
                    SafeDisposition::FaultDetected
                } else {
                    SafeDisposition::Rejected
                }
            }
            LifecycleOperation::StartWithCredential(credential) => {
                if runtime.start_current_credential(credential) {
                    SafeDisposition::CredentialStartAccepted
                } else {
                    SafeDisposition::Rejected
                }
            }
            LifecycleOperation::Rollback => {
                if runtime.complete_rollback() {
                    SafeDisposition::RollbackComplete
                } else {
                    SafeDisposition::Rejected
                }
            }
            LifecycleOperation::Restore(restore) => {
                let environment = runtime.restore_environment();
                if environment.rollback_interrupted
                    || restore.reactivation_requested
                    || restore.requested_generation != environment.snapshot_generation
                {
                    let _ = runtime.enter_restore_quarantine();
                    SafeDisposition::RestoreQuarantined
                } else if environment.raw_record_expired || environment.raw_record_opted_out {
                    let _ = runtime.quarantine_raw_restore_copy();
                    SafeDisposition::RestoreQuarantined
                } else if !runtime.restore_activation_is_inactive() {
                    let _ = runtime.enter_restore_quarantine();
                    SafeDisposition::RestoreQuarantined
                } else if runtime.enter_restore_quarantine() && runtime.open_quarantined_restore() {
                    SafeDisposition::RestoreOpened
                } else {
                    SafeDisposition::RestoreQuarantined
                }
            }
        };
        Ok(observation(disposition))
    }
}

/// The only future behavior replacement point for the frozen deployment RED.
pub(crate) fn deployment_boundary() -> impl DeploymentBoundaryPort {
    GreenDeploymentBoundary
}
