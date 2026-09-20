//! Generated protocol/catalog RED cases. DO NOT EDIT.
//!
//! The expectations are generated from the frozen catalog, never from a Rust
//! descriptor.  Every case calls the real protocol seam.  Until materialization
//! is implemented, that seam reports the registered scaffold frontier and the
//! test fails intentionally as `behavior_red`.

use msgriver_protocol::{
    Authorization, Binding, CodecId, HttpMethod, Idempotency, OneTimeMode, OperationDescriptor,
    OperationId, ProtocolFrontier, Risk, operation_catalog,
};
use std::fmt;

const SOURCE_DIGEST: &str = "ec509cfe81b6f07ba1cf1917b22b41a4e22e68a675f3ba40c5a91d46280229ec";
const FIXTURE_DIGEST: &str = "a162d76019494662eafce439082112fc9fd977f4daa2e2d8b391225d8424b23a";

#[derive(Debug)]
enum CatalogCaseError {
    BehaviorRed {
        case_id: &'static str,
    },
    Mismatch {
        case_id: &'static str,
        detail: String,
    },
}

impl fmt::Display for CatalogCaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BehaviorRed { case_id } => write!(
                f,
                "{case_id}: behavior missing — terminated at RED frontier `protocol_catalog_materialize`"
            ),
            Self::Mismatch { case_id, detail } => {
                write!(f, "{case_id}: observable mismatch — {detail}")
            }
        }
    }
}

impl std::error::Error for CatalogCaseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CodecReference {
    operation_id: OperationId,
    direction: &'static str,
    codec_id: CodecId,
}

fn live_catalog(case_id: &'static str) -> Result<&'static [OperationDescriptor], CatalogCaseError> {
    match operation_catalog() {
        Ok(catalog) => Ok(catalog),
        Err(error) if error.scaffold_frontier() == Some(ProtocolFrontier::CatalogMaterialize) => {
            Err(CatalogCaseError::BehaviorRed { case_id })
        }
        Err(error) => Err(CatalogCaseError::Mismatch {
            case_id,
            detail: format!("unexpected protocol error: {error}"),
        }),
    }
}

fn operation_case(
    case_id: &'static str,
    expected: OperationDescriptor,
) -> Result<(), CatalogCaseError> {
    let catalog = live_catalog(case_id)?;
    let Some(actual) = catalog.iter().find(|item| item.id == expected.id) else {
        return Err(CatalogCaseError::Mismatch {
            case_id,
            detail: format!("missing operation {}", expected.id.as_str()),
        });
    };
    if actual != &expected {
        return Err(CatalogCaseError::Mismatch {
            case_id,
            detail: format!("descriptor mismatch for {}", expected.id.as_str()),
        });
    }
    Ok(())
}

fn catalog_references(catalog: &[OperationDescriptor]) -> Vec<CodecReference> {
    let mut refs = Vec::new();
    for descriptor in catalog {
        if descriptor.request_codec != CodecId::None {
            refs.push(CodecReference {
                operation_id: descriptor.id,
                direction: "request",
                codec_id: descriptor.request_codec,
            });
        }
        if let Some(codec_id) = descriptor.response_codec {
            refs.push(CodecReference {
                operation_id: descriptor.id,
                direction: "response",
                codec_id,
            });
        }
    }
    refs.sort();
    refs
}

#[test]
fn proto_catalog_op_provider_list() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-PROVIDER.LIST",
        OperationDescriptor {
            id: OperationId::ProviderList,
            method: HttpMethod::Get,
            path: "/v1/providers",
            bindings: &[Binding::NormalUds, Binding::NormalTcp],
            authorization: Authorization::AuthenticatedCatalog,
            request_codec: CodecId::QueryProviderListV1,
            response_codec: Some(CodecId::JsonProviderPageV1),
            idempotency: Idempotency::Safe,
            risk: Risk::Read,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_provider_show() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-PROVIDER.SHOW",
        OperationDescriptor {
            id: OperationId::ProviderShow,
            method: HttpMethod::Get,
            path: "/v1/providers/{provider_id}",
            bindings: &[Binding::NormalUds, Binding::NormalTcp],
            authorization: Authorization::AuthenticatedCatalog,
            request_codec: CodecId::PathProviderIdV1,
            response_codec: Some(CodecId::JsonProviderV1),
            idempotency: Idempotency::Safe,
            risk: Risk::Read,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_provider_schema() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-PROVIDER.SCHEMA",
        OperationDescriptor {
            id: OperationId::ProviderSchema,
            method: HttpMethod::Get,
            path: "/v1/providers/{provider_id}/schemas/{schema_id}",
            bindings: &[Binding::NormalUds, Binding::NormalTcp],
            authorization: Authorization::AuthenticatedCatalog,
            request_codec: CodecId::PathProviderSchemaIdV1,
            response_codec: Some(CodecId::JsonProviderSchemaV1),
            idempotency: Idempotency::Safe,
            risk: Risk::Read,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_message_submit() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-MESSAGE.SUBMIT",
        OperationDescriptor {
            id: OperationId::MessageSubmit,
            method: HttpMethod::Post,
            path: "/v1/messages",
            bindings: &[Binding::NormalUds, Binding::NormalTcp],
            authorization: Authorization::Submit,
            request_codec: CodecId::JsonMessageSubmitV1,
            response_codec: Some(CodecId::JsonMessageAcceptanceV1),
            idempotency: Idempotency::DomainKey,
            risk: Risk::ExternalEffect,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_message_list() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-MESSAGE.LIST",
        OperationDescriptor {
            id: OperationId::MessageList,
            method: HttpMethod::Get,
            path: "/v1/messages",
            bindings: &[Binding::NormalUds, Binding::NormalTcp],
            authorization: Authorization::StatusOwnOrOperator,
            request_codec: CodecId::QueryMessageListV1,
            response_codec: Some(CodecId::JsonMessagePageV1),
            idempotency: Idempotency::Safe,
            risk: Risk::Read,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_message_show() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-MESSAGE.SHOW",
        OperationDescriptor {
            id: OperationId::MessageShow,
            method: HttpMethod::Get,
            path: "/v1/messages/{message_id}",
            bindings: &[Binding::NormalUds, Binding::NormalTcp],
            authorization: Authorization::StatusOwnOrOperator,
            request_codec: CodecId::PathMessageIdV1,
            response_codec: Some(CodecId::JsonMessageStatusV1),
            idempotency: Idempotency::Safe,
            risk: Risk::Read,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_message_attempt_list() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-MESSAGE.ATTEMPT.LIST",
        OperationDescriptor {
            id: OperationId::MessageAttemptList,
            method: HttpMethod::Get,
            path: "/v1/messages/{message_id}/attempts",
            bindings: &[Binding::NormalUds, Binding::NormalTcp],
            authorization: Authorization::StatusOwnOrOperator,
            request_codec: CodecId::QueryMessageAttemptListV1,
            response_codec: Some(CodecId::JsonAttemptPageV1),
            idempotency: Idempotency::Safe,
            risk: Risk::Read,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_message_cancel() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-MESSAGE.CANCEL",
        OperationDescriptor {
            id: OperationId::MessageCancel,
            method: HttpMethod::Post,
            path: "/v1/messages/{message_id}/cancel",
            bindings: &[Binding::NormalUds, Binding::NormalTcp],
            authorization: Authorization::CancelOwnOrOperator,
            request_codec: CodecId::JsonMessageCancelV1,
            response_codec: Some(CodecId::JsonMessageStatusV1),
            idempotency: Idempotency::IdempotentAction,
            risk: Risk::Mutation,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_dead_letter_list() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-DEAD_LETTER.LIST",
        OperationDescriptor {
            id: OperationId::DeadLetterList,
            method: HttpMethod::Get,
            path: "/v1/dead-letters",
            bindings: &[Binding::NormalUds, Binding::NormalTcp],
            authorization: Authorization::Operator,
            request_codec: CodecId::QueryDeadLetterListV1,
            response_codec: Some(CodecId::JsonDeadLetterPageV1),
            idempotency: Idempotency::Safe,
            risk: Risk::Read,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_dead_letter_replay() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-DEAD_LETTER.REPLAY",
        OperationDescriptor {
            id: OperationId::DeadLetterReplay,
            method: HttpMethod::Post,
            path: "/v1/dead-letters/{message_id}/replays",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::JsonDeadLetterReplayV1,
            response_codec: Some(CodecId::JsonMessageAcceptanceV1),
            idempotency: Idempotency::DomainKey,
            risk: Risk::ExternalEffect,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_payload_purge() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-PAYLOAD.PURGE",
        OperationDescriptor {
            id: OperationId::PayloadPurge,
            method: HttpMethod::Delete,
            path: "/v1/messages/{message_id}/payload",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::JsonPayloadPurgeV1,
            response_codec: Some(CodecId::JsonPayloadPurgeResultV1),
            idempotency: Idempotency::IdempotentAction,
            risk: Risk::Destructive,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_queue_list() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-QUEUE.LIST",
        OperationDescriptor {
            id: OperationId::QueueList,
            method: HttpMethod::Get,
            path: "/v1/admin/queue",
            bindings: &[Binding::NormalUds, Binding::NormalTcp],
            authorization: Authorization::Operator,
            request_codec: CodecId::QueryQueueListV1,
            response_codec: Some(CodecId::JsonQueuePageV1),
            idempotency: Idempotency::Safe,
            risk: Risk::Read,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_connector_list() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-CONNECTOR.LIST",
        OperationDescriptor {
            id: OperationId::ConnectorList,
            method: HttpMethod::Get,
            path: "/v1/admin/connectors",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::QueryConnectorListV1,
            response_codec: Some(CodecId::JsonConnectorPageV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_connector_show() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-CONNECTOR.SHOW",
        OperationDescriptor {
            id: OperationId::ConnectorShow,
            method: HttpMethod::Get,
            path: "/v1/admin/connectors/{connector_id}",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::PathConnectorIdV1,
            response_codec: Some(CodecId::JsonConnectorStatusV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_audit_list() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-AUDIT.LIST",
        OperationDescriptor {
            id: OperationId::AuditList,
            method: HttpMethod::Get,
            path: "/v1/admin/audit-events",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::QueryAuditListV1,
            response_codec: Some(CodecId::JsonAuditPageV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_admission_show() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-ADMISSION.SHOW",
        OperationDescriptor {
            id: OperationId::AdmissionShow,
            method: HttpMethod::Get,
            path: "/v1/admin/admission",
            bindings: &[Binding::NormalUds, Binding::NormalTcp],
            authorization: Authorization::Operator,
            request_codec: CodecId::None,
            response_codec: Some(CodecId::JsonAdmissionV1),
            idempotency: Idempotency::Safe,
            risk: Risk::Read,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_admission_set() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-ADMISSION.SET",
        OperationDescriptor {
            id: OperationId::AdmissionSet,
            method: HttpMethod::Put,
            path: "/v1/admin/admission",
            bindings: &[Binding::NormalUds, Binding::NormalTcp],
            authorization: Authorization::Operator,
            request_codec: CodecId::JsonAdmissionSetV1,
            response_codec: Some(CodecId::JsonAdmissionV1),
            idempotency: Idempotency::GenerationGuarded,
            risk: Risk::ReversibleControl,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_drain_start() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-DRAIN.START",
        OperationDescriptor {
            id: OperationId::DrainStart,
            method: HttpMethod::Post,
            path: "/v1/admin/drains",
            bindings: &[Binding::NormalUds, Binding::NormalTcp],
            authorization: Authorization::Operator,
            request_codec: CodecId::JsonDrainV1,
            response_codec: Some(CodecId::JsonDrainResultV1),
            idempotency: Idempotency::CommandKey,
            risk: Risk::ReversibleControl,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_clock_show() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-CLOCK.SHOW",
        OperationDescriptor {
            id: OperationId::ClockShow,
            method: HttpMethod::Get,
            path: "/v1/admin/clock",
            bindings: &[Binding::NormalUds, Binding::MaintenanceUds],
            authorization: Authorization::LocalOperatorOrStateOwnerPeer,
            request_codec: CodecId::None,
            response_codec: Some(CodecId::JsonClockStatusV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_clock_acknowledge() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-CLOCK.ACKNOWLEDGE",
        OperationDescriptor {
            id: OperationId::ClockAcknowledge,
            method: HttpMethod::Post,
            path: "/v1/admin/clock-acknowledgements",
            bindings: &[Binding::NormalUds, Binding::MaintenanceUds],
            authorization: Authorization::LocalOperatorOrStateOwnerPeer,
            request_codec: CodecId::JsonClockAcknowledgementV1,
            response_codec: Some(CodecId::JsonClockStatusV1),
            idempotency: Idempotency::AddressedState,
            risk: Risk::SafetyOverride,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_principal_list() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-PRINCIPAL.LIST",
        OperationDescriptor {
            id: OperationId::PrincipalList,
            method: HttpMethod::Get,
            path: "/v1/admin/principals",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::QueryPrincipalListV1,
            response_codec: Some(CodecId::JsonPrincipalPageV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_principal_create() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-PRINCIPAL.CREATE",
        OperationDescriptor {
            id: OperationId::PrincipalCreate,
            method: HttpMethod::Post,
            path: "/v1/admin/principals",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::JsonPrincipalCreateV1,
            response_codec: Some(CodecId::JsonPrincipalV1),
            idempotency: Idempotency::CommandKey,
            risk: Risk::AuthorizationChange,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_principal_show() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-PRINCIPAL.SHOW",
        OperationDescriptor {
            id: OperationId::PrincipalShow,
            method: HttpMethod::Get,
            path: "/v1/admin/principals/{principal_id}",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::PathPrincipalIdV1,
            response_codec: Some(CodecId::JsonPrincipalV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_principal_update() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-PRINCIPAL.UPDATE",
        OperationDescriptor {
            id: OperationId::PrincipalUpdate,
            method: HttpMethod::Patch,
            path: "/v1/admin/principals/{principal_id}",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::JsonPrincipalUpdateV1,
            response_codec: Some(CodecId::JsonPrincipalV1),
            idempotency: Idempotency::CommandKey,
            risk: Risk::AuthorizationChange,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_principal_enable() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-PRINCIPAL.ENABLE",
        OperationDescriptor {
            id: OperationId::PrincipalEnable,
            method: HttpMethod::Post,
            path: "/v1/admin/principals/{principal_id}/enable",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::JsonGenerationGuardedActionV1,
            response_codec: Some(CodecId::JsonPrincipalV1),
            idempotency: Idempotency::GenerationGuarded,
            risk: Risk::AuthorizationChange,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_principal_disable() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-PRINCIPAL.DISABLE",
        OperationDescriptor {
            id: OperationId::PrincipalDisable,
            method: HttpMethod::Post,
            path: "/v1/admin/principals/{principal_id}/disable",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::JsonGenerationGuardedActionV1,
            response_codec: Some(CodecId::JsonPrincipalV1),
            idempotency: Idempotency::GenerationGuarded,
            risk: Risk::AuthorizationChange,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_grant_list() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-GRANT.LIST",
        OperationDescriptor {
            id: OperationId::GrantList,
            method: HttpMethod::Get,
            path: "/v1/admin/principals/{principal_id}/provider-grants",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::QueryGrantListV1,
            response_codec: Some(CodecId::JsonGrantPageV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_grant_put() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-GRANT.PUT",
        OperationDescriptor {
            id: OperationId::GrantPut,
            method: HttpMethod::Put,
            path: "/v1/admin/principals/{principal_id}/provider-grants/{provider_id}",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::JsonGrantSetV1,
            response_codec: Some(CodecId::JsonGrantV1),
            idempotency: Idempotency::GenerationGuarded,
            risk: Risk::AuthorizationChange,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_grant_delete() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-GRANT.DELETE",
        OperationDescriptor {
            id: OperationId::GrantDelete,
            method: HttpMethod::Delete,
            path: "/v1/admin/principals/{principal_id}/provider-grants/{provider_id}",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::JsonGenerationGuardedActionV1,
            response_codec: Some(CodecId::JsonGrantDeleteResultV1),
            idempotency: Idempotency::GenerationGuarded,
            risk: Risk::AuthorizationChange,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_api_key_list() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-API_KEY.LIST",
        OperationDescriptor {
            id: OperationId::ApiKeyList,
            method: HttpMethod::Get,
            path: "/v1/admin/api-keys",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::QueryApiKeyListV1,
            response_codec: Some(CodecId::JsonApiKeyPageV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_api_key_issue() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-API_KEY.ISSUE",
        OperationDescriptor {
            id: OperationId::ApiKeyIssue,
            method: HttpMethod::Post,
            path: "/v1/admin/api-keys",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::JsonApiKeyIssueV1,
            response_codec: Some(CodecId::JsonApiKeySecretOnceV1),
            idempotency: Idempotency::OneTimeSecret,
            risk: Risk::CredentialIssue,
            one_time_mode: Some(OneTimeMode::SinglePhase),
        },
    )
}

#[test]
fn proto_catalog_op_api_key_rotate() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-API_KEY.ROTATE",
        OperationDescriptor {
            id: OperationId::ApiKeyRotate,
            method: HttpMethod::Post,
            path: "/v1/admin/api-keys/{key_id}/rotations",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::JsonApiKeyRotateV1,
            response_codec: Some(CodecId::JsonApiKeySecretOnceV1),
            idempotency: Idempotency::OneTimeSecret,
            risk: Risk::CredentialIssue,
            one_time_mode: Some(OneTimeMode::SinglePhase),
        },
    )
}

#[test]
fn proto_catalog_op_api_key_revoke() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-API_KEY.REVOKE",
        OperationDescriptor {
            id: OperationId::ApiKeyRevoke,
            method: HttpMethod::Delete,
            path: "/v1/admin/api-keys/{key_id}",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::JsonAdminActionV1,
            response_codec: Some(CodecId::JsonApiKeyRevokeResultV1),
            idempotency: Idempotency::IdempotentAction,
            risk: Risk::AuthorizationChange,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_peer_mapping_list() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-PEER_MAPPING.LIST",
        OperationDescriptor {
            id: OperationId::PeerMappingList,
            method: HttpMethod::Get,
            path: "/v1/admin/peer-mappings",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::QueryPeerMappingListV1,
            response_codec: Some(CodecId::JsonPeerMappingPageV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_peer_mapping_create() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-PEER_MAPPING.CREATE",
        OperationDescriptor {
            id: OperationId::PeerMappingCreate,
            method: HttpMethod::Post,
            path: "/v1/admin/peer-mappings",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::JsonPeerMappingCreateV1,
            response_codec: Some(CodecId::JsonPeerMappingV1),
            idempotency: Idempotency::CommandKey,
            risk: Risk::AuthorizationChange,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_peer_mapping_show() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-PEER_MAPPING.SHOW",
        OperationDescriptor {
            id: OperationId::PeerMappingShow,
            method: HttpMethod::Get,
            path: "/v1/admin/peer-mappings/{mapping_id}",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::PathPeerMappingIdV1,
            response_codec: Some(CodecId::JsonPeerMappingV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_peer_mapping_update() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-PEER_MAPPING.UPDATE",
        OperationDescriptor {
            id: OperationId::PeerMappingUpdate,
            method: HttpMethod::Patch,
            path: "/v1/admin/peer-mappings/{mapping_id}",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::JsonPeerMappingUpdateV1,
            response_codec: Some(CodecId::JsonPeerMappingV1),
            idempotency: Idempotency::CommandKey,
            risk: Risk::AuthorizationChange,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_peer_mapping_delete() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-PEER_MAPPING.DELETE",
        OperationDescriptor {
            id: OperationId::PeerMappingDelete,
            method: HttpMethod::Delete,
            path: "/v1/admin/peer-mappings/{mapping_id}",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::JsonAdminActionV1,
            response_codec: Some(CodecId::JsonPeerMappingDeleteResultV1),
            idempotency: Idempotency::IdempotentAction,
            risk: Risk::AuthorizationChange,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_configuration_show() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-CONFIGURATION.SHOW",
        OperationDescriptor {
            id: OperationId::ConfigurationShow,
            method: HttpMethod::Get,
            path: "/v1/admin/configuration",
            bindings: &[Binding::NormalUds, Binding::MaintenanceUds],
            authorization: Authorization::LocalOperatorOrStateOwnerPeer,
            request_codec: CodecId::None,
            response_codec: Some(CodecId::JsonConfigurationV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_configuration_validate() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-CONFIGURATION.VALIDATE",
        OperationDescriptor {
            id: OperationId::ConfigurationValidate,
            method: HttpMethod::Post,
            path: "/v1/admin/config-validations",
            bindings: &[Binding::NormalUds, Binding::MaintenanceUds],
            authorization: Authorization::LocalOperatorOrStateOwnerPeer,
            request_codec: CodecId::BytesConfigurationCandidateV1,
            response_codec: Some(CodecId::JsonConfigurationValidationV1),
            idempotency: Idempotency::SafeCalculation,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_configuration_activate() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-CONFIGURATION.ACTIVATE",
        OperationDescriptor {
            id: OperationId::ConfigurationActivate,
            method: HttpMethod::Put,
            path: "/v1/admin/configuration",
            bindings: &[Binding::MaintenanceUds],
            authorization: Authorization::StateOwnerPeer,
            request_codec: CodecId::BytesConfigurationActivationV1,
            response_codec: Some(CodecId::JsonConfigurationActivationV1),
            idempotency: Idempotency::CommandKey,
            risk: Risk::ConfigurationChange,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_state_key_list() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-STATE_KEY.LIST",
        OperationDescriptor {
            id: OperationId::StateKeyList,
            method: HttpMethod::Get,
            path: "/v1/admin/state-keys",
            bindings: &[Binding::MaintenanceUds],
            authorization: Authorization::StateOwnerPeer,
            request_codec: CodecId::QueryStateKeyListV1,
            response_codec: Some(CodecId::JsonStateKeyPageV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_state_key_rotate() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-STATE_KEY.ROTATE",
        OperationDescriptor {
            id: OperationId::StateKeyRotate,
            method: HttpMethod::Post,
            path: "/v1/admin/state-keys/{purpose}/rotations",
            bindings: &[Binding::MaintenanceUds],
            authorization: Authorization::StateOwnerPeer,
            request_codec: CodecId::JsonStateKeyRotateV1,
            response_codec: Some(CodecId::JsonStateKeyRotationV1),
            idempotency: Idempotency::CommandKey,
            risk: Risk::CryptographicChange,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_state_key_retire() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-STATE_KEY.RETIRE",
        OperationDescriptor {
            id: OperationId::StateKeyRetire,
            method: HttpMethod::Delete,
            path: "/v1/admin/state-keys/{purpose}/{generation_id}",
            bindings: &[Binding::MaintenanceUds],
            authorization: Authorization::StateOwnerPeer,
            request_codec: CodecId::JsonKeyRetirementV1,
            response_codec: Some(CodecId::JsonKeyRetirementResultV1),
            idempotency: Idempotency::CommandKey,
            risk: Risk::Destructive,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_recovery_key_list() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-RECOVERY_KEY.LIST",
        OperationDescriptor {
            id: OperationId::RecoveryKeyList,
            method: HttpMethod::Get,
            path: "/v1/admin/recovery-keys",
            bindings: &[Binding::MaintenanceUds],
            authorization: Authorization::StateOwnerPeer,
            request_codec: CodecId::QueryRecoveryKeyListV1,
            response_codec: Some(CodecId::JsonRecoveryKeyPageV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_recovery_key_generate() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-RECOVERY_KEY.GENERATE",
        OperationDescriptor {
            id: OperationId::RecoveryKeyGenerate,
            method: HttpMethod::Post,
            path: "/v1/admin/recovery-keys",
            bindings: &[Binding::MaintenanceUds],
            authorization: Authorization::StateOwnerPeer,
            request_codec: CodecId::JsonRecoveryKeyGeneratePhaseV1,
            response_codec: Some(CodecId::JsonRecoveryKeyGeneratePhaseResultV1),
            idempotency: Idempotency::OneTimeSecret,
            risk: Risk::CredentialIssue,
            one_time_mode: Some(OneTimeMode::EscrowAcknowledgement),
        },
    )
}

#[test]
fn proto_catalog_op_recovery_key_import() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-RECOVERY_KEY.IMPORT",
        OperationDescriptor {
            id: OperationId::RecoveryKeyImport,
            method: HttpMethod::Post,
            path: "/v1/admin/recovery-key-imports",
            bindings: &[Binding::MaintenanceUds],
            authorization: Authorization::StateOwnerPeer,
            request_codec: CodecId::JsonRecoveryKeyImportV1,
            response_codec: Some(CodecId::JsonRecoveryKeyMetadataV1),
            idempotency: Idempotency::CommandKey,
            risk: Risk::CryptographicChange,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_recovery_key_retire() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-RECOVERY_KEY.RETIRE",
        OperationDescriptor {
            id: OperationId::RecoveryKeyRetire,
            method: HttpMethod::Delete,
            path: "/v1/admin/recovery-keys/{generation_id}",
            bindings: &[Binding::MaintenanceUds],
            authorization: Authorization::StateOwnerPeer,
            request_codec: CodecId::JsonKeyRetirementV1,
            response_codec: Some(CodecId::JsonKeyRetirementResultV1),
            idempotency: Idempotency::CommandKey,
            risk: Risk::Destructive,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_backup_list() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-BACKUP.LIST",
        OperationDescriptor {
            id: OperationId::BackupList,
            method: HttpMethod::Get,
            path: "/v1/admin/backups",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::QueryBackupListV1,
            response_codec: Some(CodecId::JsonBackupPageV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_backup_create() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-BACKUP.CREATE",
        OperationDescriptor {
            id: OperationId::BackupCreate,
            method: HttpMethod::Post,
            path: "/v1/admin/backups",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::JsonBackupCreateV1,
            response_codec: Some(CodecId::JsonBackupJobV1),
            idempotency: Idempotency::CommandKey,
            risk: Risk::ResourceIntensive,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_backup_show() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-BACKUP.SHOW",
        OperationDescriptor {
            id: OperationId::BackupShow,
            method: HttpMethod::Get,
            path: "/v1/admin/backups/{backup_id}",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::PathBackupIdV1,
            response_codec: Some(CodecId::JsonBackupJobV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_backup_manifest() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-BACKUP.MANIFEST",
        OperationDescriptor {
            id: OperationId::BackupManifest,
            method: HttpMethod::Get,
            path: "/v1/admin/backups/{backup_id}/manifest",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::PathBackupIdV1,
            response_codec: Some(CodecId::JsonBackupManifestV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_backup_download() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-BACKUP.DOWNLOAD",
        OperationDescriptor {
            id: OperationId::BackupDownload,
            method: HttpMethod::Get,
            path: "/v1/admin/backups/{backup_id}/artifact",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::PathBackupIdV1,
            response_codec: Some(CodecId::StreamBackupArtifactV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_backup_cancel() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-BACKUP.CANCEL",
        OperationDescriptor {
            id: OperationId::BackupCancel,
            method: HttpMethod::Post,
            path: "/v1/admin/backups/{backup_id}/cancel",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::JsonAdminActionV1,
            response_codec: Some(CodecId::JsonBackupJobV1),
            idempotency: Idempotency::IdempotentAction,
            risk: Risk::Mutation,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_bootstrap_create() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-BOOTSTRAP.CREATE",
        OperationDescriptor {
            id: OperationId::BootstrapCreate,
            method: HttpMethod::Post,
            path: "/v1/admin/bootstrap",
            bindings: &[Binding::MaintenanceUds],
            authorization: Authorization::StateOwnerPeer,
            request_codec: CodecId::JsonBootstrapV1,
            response_codec: Some(CodecId::JsonBootstrapResultV1),
            idempotency: Idempotency::CommandKey,
            risk: Risk::ConfigurationChange,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_restore_create() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-RESTORE.CREATE",
        OperationDescriptor {
            id: OperationId::RestoreCreate,
            method: HttpMethod::Post,
            path: "/v1/admin/restores",
            bindings: &[Binding::MaintenanceUds],
            authorization: Authorization::StateOwnerPeer,
            request_codec: CodecId::StreamRestoreArtifactV1,
            response_codec: Some(CodecId::JsonRestoreJobV1),
            idempotency: Idempotency::CommandKey,
            risk: Risk::Destructive,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_restore_show() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-RESTORE.SHOW",
        OperationDescriptor {
            id: OperationId::RestoreShow,
            method: HttpMethod::Get,
            path: "/v1/admin/restores/{restore_id}",
            bindings: &[Binding::MaintenanceUds],
            authorization: Authorization::StateOwnerPeer,
            request_codec: CodecId::PathRestoreIdV1,
            response_codec: Some(CodecId::JsonRestoreJobV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_restore_report() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-RESTORE.REPORT",
        OperationDescriptor {
            id: OperationId::RestoreReport,
            method: HttpMethod::Get,
            path: "/v1/admin/restores/current",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::QueryRestoreReportPageV1,
            response_codec: Some(CodecId::JsonRestoreReportPageV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_restore_resume() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-RESTORE.RESUME",
        OperationDescriptor {
            id: OperationId::RestoreResume,
            method: HttpMethod::Post,
            path: "/v1/admin/restores/current/resume",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalRecoveryOperator,
            request_codec: CodecId::JsonRestoreResumeV1,
            response_codec: Some(CodecId::JsonRestoreResumeResultV1),
            idempotency: Idempotency::CommandKey,
            risk: Risk::SafetyOverride,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_state_generation_list() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-STATE_GENERATION.LIST",
        OperationDescriptor {
            id: OperationId::StateGenerationList,
            method: HttpMethod::Get,
            path: "/v1/admin/state-generations",
            bindings: &[Binding::MaintenanceUds],
            authorization: Authorization::StateOwnerPeer,
            request_codec: CodecId::QueryStateGenerationListV1,
            response_codec: Some(CodecId::JsonStateGenerationPageV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_state_generation_delete() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-STATE_GENERATION.DELETE",
        OperationDescriptor {
            id: OperationId::StateGenerationDelete,
            method: HttpMethod::Delete,
            path: "/v1/admin/state-generations/{generation_id}",
            bindings: &[Binding::MaintenanceUds],
            authorization: Authorization::StateOwnerPeer,
            request_codec: CodecId::JsonStateGenerationDeleteV1,
            response_codec: Some(CodecId::JsonStateGenerationDeleteResultV1),
            idempotency: Idempotency::CommandKey,
            risk: Risk::Destructive,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_upgrade_show() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-UPGRADE.SHOW",
        OperationDescriptor {
            id: OperationId::UpgradeShow,
            method: HttpMethod::Get,
            path: "/v1/admin/upgrade",
            bindings: &[Binding::NormalUds, Binding::MaintenanceUds],
            authorization: Authorization::LocalOperatorOrStateOwnerPeer,
            request_codec: CodecId::None,
            response_codec: Some(CodecId::JsonUpgradeStatusV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_upgrade_prepare() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-UPGRADE.PREPARE",
        OperationDescriptor {
            id: OperationId::UpgradePrepare,
            method: HttpMethod::Post,
            path: "/v1/admin/upgrades",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::JsonUpgradePrepareV1,
            response_codec: Some(CodecId::JsonUpgradeStatusV1),
            idempotency: Idempotency::CommandKey,
            risk: Risk::SafetyControl,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_upgrade_migrate() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-UPGRADE.MIGRATE",
        OperationDescriptor {
            id: OperationId::UpgradeMigrate,
            method: HttpMethod::Post,
            path: "/v1/admin/upgrades/{upgrade_id}/migration",
            bindings: &[Binding::MaintenanceUds],
            authorization: Authorization::StateOwnerPeer,
            request_codec: CodecId::JsonUpgradeMigrateV1,
            response_codec: Some(CodecId::JsonUpgradeStatusV1),
            idempotency: Idempotency::CommandKey,
            risk: Risk::Destructive,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_upgrade_activate() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-UPGRADE.ACTIVATE",
        OperationDescriptor {
            id: OperationId::UpgradeActivate,
            method: HttpMethod::Post,
            path: "/v1/admin/upgrades/{upgrade_id}/activation",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::JsonUpgradeActivateV1,
            response_codec: Some(CodecId::JsonUpgradeStatusV1),
            idempotency: Idempotency::CommandKey,
            risk: Risk::SafetyOverride,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_upgrade_rollback() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-UPGRADE.ROLLBACK",
        OperationDescriptor {
            id: OperationId::UpgradeRollback,
            method: HttpMethod::Post,
            path: "/v1/admin/upgrades/{upgrade_id}/rollback",
            bindings: &[Binding::MaintenanceUds],
            authorization: Authorization::StateOwnerPeer,
            request_codec: CodecId::JsonUpgradeRollbackV1,
            response_codec: Some(CodecId::JsonUpgradeStatusV1),
            idempotency: Idempotency::CommandKey,
            risk: Risk::Destructive,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_system_health() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-SYSTEM.HEALTH",
        OperationDescriptor {
            id: OperationId::SystemHealth,
            method: HttpMethod::Get,
            path: "/v1/system/health",
            bindings: &[
                Binding::NormalUds,
                Binding::NormalTcp,
                Binding::MaintenanceUds,
            ],
            authorization: Authorization::ProbeByBinding,
            request_codec: CodecId::None,
            response_codec: Some(CodecId::JsonHealthV1),
            idempotency: Idempotency::Safe,
            risk: Risk::Read,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_system_readiness() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-SYSTEM.READINESS",
        OperationDescriptor {
            id: OperationId::SystemReadiness,
            method: HttpMethod::Get,
            path: "/v1/system/readiness",
            bindings: &[
                Binding::NormalUds,
                Binding::NormalTcp,
                Binding::MaintenanceUds,
            ],
            authorization: Authorization::ProbeByBinding,
            request_codec: CodecId::None,
            response_codec: Some(CodecId::JsonReadinessV1),
            idempotency: Idempotency::Safe,
            risk: Risk::Read,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_system_metrics() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-SYSTEM.METRICS",
        OperationDescriptor {
            id: OperationId::SystemMetrics,
            method: HttpMethod::Get,
            path: "/v1/system/metrics",
            bindings: &[Binding::NormalUds],
            authorization: Authorization::LocalOperator,
            request_codec: CodecId::None,
            response_codec: Some(CodecId::TextMetricsV1),
            idempotency: Idempotency::Safe,
            risk: Risk::SensitiveRead,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_op_system_shutdown() -> Result<(), CatalogCaseError> {
    operation_case(
        "PROTO-CATALOG-OP-SYSTEM.SHUTDOWN",
        OperationDescriptor {
            id: OperationId::SystemShutdown,
            method: HttpMethod::Post,
            path: "/v1/system/shutdown",
            bindings: &[Binding::NormalUds, Binding::MaintenanceUds],
            authorization: Authorization::LocalOperatorOrStateOwnerPeer,
            request_codec: CodecId::JsonShutdownV1,
            response_codec: Some(CodecId::JsonShutdownAcceptedV1),
            idempotency: Idempotency::AddressedState,
            risk: Risk::SafetyControl,
            one_time_mode: None,
        },
    )
}

#[test]
fn proto_catalog_operation_set() -> Result<(), CatalogCaseError> {
    let case_id = "PROTO-CATALOG-OPERATION-SET";
    let catalog = live_catalog(case_id)?;
    let actual: Vec<OperationId> = catalog.iter().map(|item| item.id).collect();
    let expected = [
        OperationId::ProviderList,
        OperationId::ProviderShow,
        OperationId::ProviderSchema,
        OperationId::MessageSubmit,
        OperationId::MessageList,
        OperationId::MessageShow,
        OperationId::MessageAttemptList,
        OperationId::MessageCancel,
        OperationId::DeadLetterList,
        OperationId::DeadLetterReplay,
        OperationId::PayloadPurge,
        OperationId::QueueList,
        OperationId::ConnectorList,
        OperationId::ConnectorShow,
        OperationId::AuditList,
        OperationId::AdmissionShow,
        OperationId::AdmissionSet,
        OperationId::DrainStart,
        OperationId::ClockShow,
        OperationId::ClockAcknowledge,
        OperationId::PrincipalList,
        OperationId::PrincipalCreate,
        OperationId::PrincipalShow,
        OperationId::PrincipalUpdate,
        OperationId::PrincipalEnable,
        OperationId::PrincipalDisable,
        OperationId::GrantList,
        OperationId::GrantPut,
        OperationId::GrantDelete,
        OperationId::ApiKeyList,
        OperationId::ApiKeyIssue,
        OperationId::ApiKeyRotate,
        OperationId::ApiKeyRevoke,
        OperationId::PeerMappingList,
        OperationId::PeerMappingCreate,
        OperationId::PeerMappingShow,
        OperationId::PeerMappingUpdate,
        OperationId::PeerMappingDelete,
        OperationId::ConfigurationShow,
        OperationId::ConfigurationValidate,
        OperationId::ConfigurationActivate,
        OperationId::StateKeyList,
        OperationId::StateKeyRotate,
        OperationId::StateKeyRetire,
        OperationId::RecoveryKeyList,
        OperationId::RecoveryKeyGenerate,
        OperationId::RecoveryKeyImport,
        OperationId::RecoveryKeyRetire,
        OperationId::BackupList,
        OperationId::BackupCreate,
        OperationId::BackupShow,
        OperationId::BackupManifest,
        OperationId::BackupDownload,
        OperationId::BackupCancel,
        OperationId::BootstrapCreate,
        OperationId::RestoreCreate,
        OperationId::RestoreShow,
        OperationId::RestoreReport,
        OperationId::RestoreResume,
        OperationId::StateGenerationList,
        OperationId::StateGenerationDelete,
        OperationId::UpgradeShow,
        OperationId::UpgradePrepare,
        OperationId::UpgradeMigrate,
        OperationId::UpgradeActivate,
        OperationId::UpgradeRollback,
        OperationId::SystemHealth,
        OperationId::SystemReadiness,
        OperationId::SystemMetrics,
        OperationId::SystemShutdown,
    ];
    if actual != expected {
        return Err(CatalogCaseError::Mismatch {
            case_id,
            detail: "operation ID set or order differs".into(),
        });
    }
    Ok(())
}

#[test]
fn proto_catalog_codec_references() -> Result<(), CatalogCaseError> {
    let case_id = "PROTO-CATALOG-CODEC-REFERENCES";
    let catalog = live_catalog(case_id)?;
    let mut expected = vec![
        CodecReference {
            operation_id: OperationId::ProviderList,
            direction: "request",
            codec_id: CodecId::QueryProviderListV1,
        },
        CodecReference {
            operation_id: OperationId::ProviderList,
            direction: "response",
            codec_id: CodecId::JsonProviderPageV1,
        },
        CodecReference {
            operation_id: OperationId::ProviderShow,
            direction: "request",
            codec_id: CodecId::PathProviderIdV1,
        },
        CodecReference {
            operation_id: OperationId::ProviderShow,
            direction: "response",
            codec_id: CodecId::JsonProviderV1,
        },
        CodecReference {
            operation_id: OperationId::ProviderSchema,
            direction: "request",
            codec_id: CodecId::PathProviderSchemaIdV1,
        },
        CodecReference {
            operation_id: OperationId::ProviderSchema,
            direction: "response",
            codec_id: CodecId::JsonProviderSchemaV1,
        },
        CodecReference {
            operation_id: OperationId::MessageSubmit,
            direction: "request",
            codec_id: CodecId::JsonMessageSubmitV1,
        },
        CodecReference {
            operation_id: OperationId::MessageSubmit,
            direction: "response",
            codec_id: CodecId::JsonMessageAcceptanceV1,
        },
        CodecReference {
            operation_id: OperationId::MessageList,
            direction: "request",
            codec_id: CodecId::QueryMessageListV1,
        },
        CodecReference {
            operation_id: OperationId::MessageList,
            direction: "response",
            codec_id: CodecId::JsonMessagePageV1,
        },
        CodecReference {
            operation_id: OperationId::MessageShow,
            direction: "request",
            codec_id: CodecId::PathMessageIdV1,
        },
        CodecReference {
            operation_id: OperationId::MessageShow,
            direction: "response",
            codec_id: CodecId::JsonMessageStatusV1,
        },
        CodecReference {
            operation_id: OperationId::MessageAttemptList,
            direction: "request",
            codec_id: CodecId::QueryMessageAttemptListV1,
        },
        CodecReference {
            operation_id: OperationId::MessageAttemptList,
            direction: "response",
            codec_id: CodecId::JsonAttemptPageV1,
        },
        CodecReference {
            operation_id: OperationId::MessageCancel,
            direction: "request",
            codec_id: CodecId::JsonMessageCancelV1,
        },
        CodecReference {
            operation_id: OperationId::MessageCancel,
            direction: "response",
            codec_id: CodecId::JsonMessageStatusV1,
        },
        CodecReference {
            operation_id: OperationId::DeadLetterList,
            direction: "request",
            codec_id: CodecId::QueryDeadLetterListV1,
        },
        CodecReference {
            operation_id: OperationId::DeadLetterList,
            direction: "response",
            codec_id: CodecId::JsonDeadLetterPageV1,
        },
        CodecReference {
            operation_id: OperationId::DeadLetterReplay,
            direction: "request",
            codec_id: CodecId::JsonDeadLetterReplayV1,
        },
        CodecReference {
            operation_id: OperationId::DeadLetterReplay,
            direction: "response",
            codec_id: CodecId::JsonMessageAcceptanceV1,
        },
        CodecReference {
            operation_id: OperationId::PayloadPurge,
            direction: "request",
            codec_id: CodecId::JsonPayloadPurgeV1,
        },
        CodecReference {
            operation_id: OperationId::PayloadPurge,
            direction: "response",
            codec_id: CodecId::JsonPayloadPurgeResultV1,
        },
        CodecReference {
            operation_id: OperationId::QueueList,
            direction: "request",
            codec_id: CodecId::QueryQueueListV1,
        },
        CodecReference {
            operation_id: OperationId::QueueList,
            direction: "response",
            codec_id: CodecId::JsonQueuePageV1,
        },
        CodecReference {
            operation_id: OperationId::ConnectorList,
            direction: "request",
            codec_id: CodecId::QueryConnectorListV1,
        },
        CodecReference {
            operation_id: OperationId::ConnectorList,
            direction: "response",
            codec_id: CodecId::JsonConnectorPageV1,
        },
        CodecReference {
            operation_id: OperationId::ConnectorShow,
            direction: "request",
            codec_id: CodecId::PathConnectorIdV1,
        },
        CodecReference {
            operation_id: OperationId::ConnectorShow,
            direction: "response",
            codec_id: CodecId::JsonConnectorStatusV1,
        },
        CodecReference {
            operation_id: OperationId::AuditList,
            direction: "request",
            codec_id: CodecId::QueryAuditListV1,
        },
        CodecReference {
            operation_id: OperationId::AuditList,
            direction: "response",
            codec_id: CodecId::JsonAuditPageV1,
        },
        CodecReference {
            operation_id: OperationId::AdmissionShow,
            direction: "response",
            codec_id: CodecId::JsonAdmissionV1,
        },
        CodecReference {
            operation_id: OperationId::AdmissionSet,
            direction: "request",
            codec_id: CodecId::JsonAdmissionSetV1,
        },
        CodecReference {
            operation_id: OperationId::AdmissionSet,
            direction: "response",
            codec_id: CodecId::JsonAdmissionV1,
        },
        CodecReference {
            operation_id: OperationId::DrainStart,
            direction: "request",
            codec_id: CodecId::JsonDrainV1,
        },
        CodecReference {
            operation_id: OperationId::DrainStart,
            direction: "response",
            codec_id: CodecId::JsonDrainResultV1,
        },
        CodecReference {
            operation_id: OperationId::ClockShow,
            direction: "response",
            codec_id: CodecId::JsonClockStatusV1,
        },
        CodecReference {
            operation_id: OperationId::ClockAcknowledge,
            direction: "request",
            codec_id: CodecId::JsonClockAcknowledgementV1,
        },
        CodecReference {
            operation_id: OperationId::ClockAcknowledge,
            direction: "response",
            codec_id: CodecId::JsonClockStatusV1,
        },
        CodecReference {
            operation_id: OperationId::PrincipalList,
            direction: "request",
            codec_id: CodecId::QueryPrincipalListV1,
        },
        CodecReference {
            operation_id: OperationId::PrincipalList,
            direction: "response",
            codec_id: CodecId::JsonPrincipalPageV1,
        },
        CodecReference {
            operation_id: OperationId::PrincipalCreate,
            direction: "request",
            codec_id: CodecId::JsonPrincipalCreateV1,
        },
        CodecReference {
            operation_id: OperationId::PrincipalCreate,
            direction: "response",
            codec_id: CodecId::JsonPrincipalV1,
        },
        CodecReference {
            operation_id: OperationId::PrincipalShow,
            direction: "request",
            codec_id: CodecId::PathPrincipalIdV1,
        },
        CodecReference {
            operation_id: OperationId::PrincipalShow,
            direction: "response",
            codec_id: CodecId::JsonPrincipalV1,
        },
        CodecReference {
            operation_id: OperationId::PrincipalUpdate,
            direction: "request",
            codec_id: CodecId::JsonPrincipalUpdateV1,
        },
        CodecReference {
            operation_id: OperationId::PrincipalUpdate,
            direction: "response",
            codec_id: CodecId::JsonPrincipalV1,
        },
        CodecReference {
            operation_id: OperationId::PrincipalEnable,
            direction: "request",
            codec_id: CodecId::JsonGenerationGuardedActionV1,
        },
        CodecReference {
            operation_id: OperationId::PrincipalEnable,
            direction: "response",
            codec_id: CodecId::JsonPrincipalV1,
        },
        CodecReference {
            operation_id: OperationId::PrincipalDisable,
            direction: "request",
            codec_id: CodecId::JsonGenerationGuardedActionV1,
        },
        CodecReference {
            operation_id: OperationId::PrincipalDisable,
            direction: "response",
            codec_id: CodecId::JsonPrincipalV1,
        },
        CodecReference {
            operation_id: OperationId::GrantList,
            direction: "request",
            codec_id: CodecId::QueryGrantListV1,
        },
        CodecReference {
            operation_id: OperationId::GrantList,
            direction: "response",
            codec_id: CodecId::JsonGrantPageV1,
        },
        CodecReference {
            operation_id: OperationId::GrantPut,
            direction: "request",
            codec_id: CodecId::JsonGrantSetV1,
        },
        CodecReference {
            operation_id: OperationId::GrantPut,
            direction: "response",
            codec_id: CodecId::JsonGrantV1,
        },
        CodecReference {
            operation_id: OperationId::GrantDelete,
            direction: "request",
            codec_id: CodecId::JsonGenerationGuardedActionV1,
        },
        CodecReference {
            operation_id: OperationId::GrantDelete,
            direction: "response",
            codec_id: CodecId::JsonGrantDeleteResultV1,
        },
        CodecReference {
            operation_id: OperationId::ApiKeyList,
            direction: "request",
            codec_id: CodecId::QueryApiKeyListV1,
        },
        CodecReference {
            operation_id: OperationId::ApiKeyList,
            direction: "response",
            codec_id: CodecId::JsonApiKeyPageV1,
        },
        CodecReference {
            operation_id: OperationId::ApiKeyIssue,
            direction: "request",
            codec_id: CodecId::JsonApiKeyIssueV1,
        },
        CodecReference {
            operation_id: OperationId::ApiKeyIssue,
            direction: "response",
            codec_id: CodecId::JsonApiKeySecretOnceV1,
        },
        CodecReference {
            operation_id: OperationId::ApiKeyRotate,
            direction: "request",
            codec_id: CodecId::JsonApiKeyRotateV1,
        },
        CodecReference {
            operation_id: OperationId::ApiKeyRotate,
            direction: "response",
            codec_id: CodecId::JsonApiKeySecretOnceV1,
        },
        CodecReference {
            operation_id: OperationId::ApiKeyRevoke,
            direction: "request",
            codec_id: CodecId::JsonAdminActionV1,
        },
        CodecReference {
            operation_id: OperationId::ApiKeyRevoke,
            direction: "response",
            codec_id: CodecId::JsonApiKeyRevokeResultV1,
        },
        CodecReference {
            operation_id: OperationId::PeerMappingList,
            direction: "request",
            codec_id: CodecId::QueryPeerMappingListV1,
        },
        CodecReference {
            operation_id: OperationId::PeerMappingList,
            direction: "response",
            codec_id: CodecId::JsonPeerMappingPageV1,
        },
        CodecReference {
            operation_id: OperationId::PeerMappingCreate,
            direction: "request",
            codec_id: CodecId::JsonPeerMappingCreateV1,
        },
        CodecReference {
            operation_id: OperationId::PeerMappingCreate,
            direction: "response",
            codec_id: CodecId::JsonPeerMappingV1,
        },
        CodecReference {
            operation_id: OperationId::PeerMappingShow,
            direction: "request",
            codec_id: CodecId::PathPeerMappingIdV1,
        },
        CodecReference {
            operation_id: OperationId::PeerMappingShow,
            direction: "response",
            codec_id: CodecId::JsonPeerMappingV1,
        },
        CodecReference {
            operation_id: OperationId::PeerMappingUpdate,
            direction: "request",
            codec_id: CodecId::JsonPeerMappingUpdateV1,
        },
        CodecReference {
            operation_id: OperationId::PeerMappingUpdate,
            direction: "response",
            codec_id: CodecId::JsonPeerMappingV1,
        },
        CodecReference {
            operation_id: OperationId::PeerMappingDelete,
            direction: "request",
            codec_id: CodecId::JsonAdminActionV1,
        },
        CodecReference {
            operation_id: OperationId::PeerMappingDelete,
            direction: "response",
            codec_id: CodecId::JsonPeerMappingDeleteResultV1,
        },
        CodecReference {
            operation_id: OperationId::ConfigurationShow,
            direction: "response",
            codec_id: CodecId::JsonConfigurationV1,
        },
        CodecReference {
            operation_id: OperationId::ConfigurationValidate,
            direction: "request",
            codec_id: CodecId::BytesConfigurationCandidateV1,
        },
        CodecReference {
            operation_id: OperationId::ConfigurationValidate,
            direction: "response",
            codec_id: CodecId::JsonConfigurationValidationV1,
        },
        CodecReference {
            operation_id: OperationId::ConfigurationActivate,
            direction: "request",
            codec_id: CodecId::BytesConfigurationActivationV1,
        },
        CodecReference {
            operation_id: OperationId::ConfigurationActivate,
            direction: "response",
            codec_id: CodecId::JsonConfigurationActivationV1,
        },
        CodecReference {
            operation_id: OperationId::StateKeyList,
            direction: "request",
            codec_id: CodecId::QueryStateKeyListV1,
        },
        CodecReference {
            operation_id: OperationId::StateKeyList,
            direction: "response",
            codec_id: CodecId::JsonStateKeyPageV1,
        },
        CodecReference {
            operation_id: OperationId::StateKeyRotate,
            direction: "request",
            codec_id: CodecId::JsonStateKeyRotateV1,
        },
        CodecReference {
            operation_id: OperationId::StateKeyRotate,
            direction: "response",
            codec_id: CodecId::JsonStateKeyRotationV1,
        },
        CodecReference {
            operation_id: OperationId::StateKeyRetire,
            direction: "request",
            codec_id: CodecId::JsonKeyRetirementV1,
        },
        CodecReference {
            operation_id: OperationId::StateKeyRetire,
            direction: "response",
            codec_id: CodecId::JsonKeyRetirementResultV1,
        },
        CodecReference {
            operation_id: OperationId::RecoveryKeyList,
            direction: "request",
            codec_id: CodecId::QueryRecoveryKeyListV1,
        },
        CodecReference {
            operation_id: OperationId::RecoveryKeyList,
            direction: "response",
            codec_id: CodecId::JsonRecoveryKeyPageV1,
        },
        CodecReference {
            operation_id: OperationId::RecoveryKeyGenerate,
            direction: "request",
            codec_id: CodecId::JsonRecoveryKeyGeneratePhaseV1,
        },
        CodecReference {
            operation_id: OperationId::RecoveryKeyGenerate,
            direction: "response",
            codec_id: CodecId::JsonRecoveryKeyGeneratePhaseResultV1,
        },
        CodecReference {
            operation_id: OperationId::RecoveryKeyImport,
            direction: "request",
            codec_id: CodecId::JsonRecoveryKeyImportV1,
        },
        CodecReference {
            operation_id: OperationId::RecoveryKeyImport,
            direction: "response",
            codec_id: CodecId::JsonRecoveryKeyMetadataV1,
        },
        CodecReference {
            operation_id: OperationId::RecoveryKeyRetire,
            direction: "request",
            codec_id: CodecId::JsonKeyRetirementV1,
        },
        CodecReference {
            operation_id: OperationId::RecoveryKeyRetire,
            direction: "response",
            codec_id: CodecId::JsonKeyRetirementResultV1,
        },
        CodecReference {
            operation_id: OperationId::BackupList,
            direction: "request",
            codec_id: CodecId::QueryBackupListV1,
        },
        CodecReference {
            operation_id: OperationId::BackupList,
            direction: "response",
            codec_id: CodecId::JsonBackupPageV1,
        },
        CodecReference {
            operation_id: OperationId::BackupCreate,
            direction: "request",
            codec_id: CodecId::JsonBackupCreateV1,
        },
        CodecReference {
            operation_id: OperationId::BackupCreate,
            direction: "response",
            codec_id: CodecId::JsonBackupJobV1,
        },
        CodecReference {
            operation_id: OperationId::BackupShow,
            direction: "request",
            codec_id: CodecId::PathBackupIdV1,
        },
        CodecReference {
            operation_id: OperationId::BackupShow,
            direction: "response",
            codec_id: CodecId::JsonBackupJobV1,
        },
        CodecReference {
            operation_id: OperationId::BackupManifest,
            direction: "request",
            codec_id: CodecId::PathBackupIdV1,
        },
        CodecReference {
            operation_id: OperationId::BackupManifest,
            direction: "response",
            codec_id: CodecId::JsonBackupManifestV1,
        },
        CodecReference {
            operation_id: OperationId::BackupDownload,
            direction: "request",
            codec_id: CodecId::PathBackupIdV1,
        },
        CodecReference {
            operation_id: OperationId::BackupDownload,
            direction: "response",
            codec_id: CodecId::StreamBackupArtifactV1,
        },
        CodecReference {
            operation_id: OperationId::BackupCancel,
            direction: "request",
            codec_id: CodecId::JsonAdminActionV1,
        },
        CodecReference {
            operation_id: OperationId::BackupCancel,
            direction: "response",
            codec_id: CodecId::JsonBackupJobV1,
        },
        CodecReference {
            operation_id: OperationId::BootstrapCreate,
            direction: "request",
            codec_id: CodecId::JsonBootstrapV1,
        },
        CodecReference {
            operation_id: OperationId::BootstrapCreate,
            direction: "response",
            codec_id: CodecId::JsonBootstrapResultV1,
        },
        CodecReference {
            operation_id: OperationId::RestoreCreate,
            direction: "request",
            codec_id: CodecId::StreamRestoreArtifactV1,
        },
        CodecReference {
            operation_id: OperationId::RestoreCreate,
            direction: "response",
            codec_id: CodecId::JsonRestoreJobV1,
        },
        CodecReference {
            operation_id: OperationId::RestoreShow,
            direction: "request",
            codec_id: CodecId::PathRestoreIdV1,
        },
        CodecReference {
            operation_id: OperationId::RestoreShow,
            direction: "response",
            codec_id: CodecId::JsonRestoreJobV1,
        },
        CodecReference {
            operation_id: OperationId::RestoreReport,
            direction: "request",
            codec_id: CodecId::QueryRestoreReportPageV1,
        },
        CodecReference {
            operation_id: OperationId::RestoreReport,
            direction: "response",
            codec_id: CodecId::JsonRestoreReportPageV1,
        },
        CodecReference {
            operation_id: OperationId::RestoreResume,
            direction: "request",
            codec_id: CodecId::JsonRestoreResumeV1,
        },
        CodecReference {
            operation_id: OperationId::RestoreResume,
            direction: "response",
            codec_id: CodecId::JsonRestoreResumeResultV1,
        },
        CodecReference {
            operation_id: OperationId::StateGenerationList,
            direction: "request",
            codec_id: CodecId::QueryStateGenerationListV1,
        },
        CodecReference {
            operation_id: OperationId::StateGenerationList,
            direction: "response",
            codec_id: CodecId::JsonStateGenerationPageV1,
        },
        CodecReference {
            operation_id: OperationId::StateGenerationDelete,
            direction: "request",
            codec_id: CodecId::JsonStateGenerationDeleteV1,
        },
        CodecReference {
            operation_id: OperationId::StateGenerationDelete,
            direction: "response",
            codec_id: CodecId::JsonStateGenerationDeleteResultV1,
        },
        CodecReference {
            operation_id: OperationId::UpgradeShow,
            direction: "response",
            codec_id: CodecId::JsonUpgradeStatusV1,
        },
        CodecReference {
            operation_id: OperationId::UpgradePrepare,
            direction: "request",
            codec_id: CodecId::JsonUpgradePrepareV1,
        },
        CodecReference {
            operation_id: OperationId::UpgradePrepare,
            direction: "response",
            codec_id: CodecId::JsonUpgradeStatusV1,
        },
        CodecReference {
            operation_id: OperationId::UpgradeMigrate,
            direction: "request",
            codec_id: CodecId::JsonUpgradeMigrateV1,
        },
        CodecReference {
            operation_id: OperationId::UpgradeMigrate,
            direction: "response",
            codec_id: CodecId::JsonUpgradeStatusV1,
        },
        CodecReference {
            operation_id: OperationId::UpgradeActivate,
            direction: "request",
            codec_id: CodecId::JsonUpgradeActivateV1,
        },
        CodecReference {
            operation_id: OperationId::UpgradeActivate,
            direction: "response",
            codec_id: CodecId::JsonUpgradeStatusV1,
        },
        CodecReference {
            operation_id: OperationId::UpgradeRollback,
            direction: "request",
            codec_id: CodecId::JsonUpgradeRollbackV1,
        },
        CodecReference {
            operation_id: OperationId::UpgradeRollback,
            direction: "response",
            codec_id: CodecId::JsonUpgradeStatusV1,
        },
        CodecReference {
            operation_id: OperationId::SystemHealth,
            direction: "response",
            codec_id: CodecId::JsonHealthV1,
        },
        CodecReference {
            operation_id: OperationId::SystemReadiness,
            direction: "response",
            codec_id: CodecId::JsonReadinessV1,
        },
        CodecReference {
            operation_id: OperationId::SystemMetrics,
            direction: "response",
            codec_id: CodecId::TextMetricsV1,
        },
        CodecReference {
            operation_id: OperationId::SystemShutdown,
            direction: "request",
            codec_id: CodecId::JsonShutdownV1,
        },
        CodecReference {
            operation_id: OperationId::SystemShutdown,
            direction: "response",
            codec_id: CodecId::JsonShutdownAcceptedV1,
        },
    ];
    expected.sort();
    if catalog_references(catalog) != expected {
        return Err(CatalogCaseError::Mismatch {
            case_id,
            detail: "codec reference closure differs".into(),
        });
    }
    if SOURCE_DIGEST.is_empty() || FIXTURE_DIGEST.is_empty() {
        return Err(CatalogCaseError::Mismatch {
            case_id,
            detail: "unbound generated input digest".into(),
        });
    }
    Ok(())
}
