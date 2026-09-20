#!/usr/bin/env python3
"""Deterministic structural checks for MsgRiver's frozen first-slice contracts."""

from __future__ import annotations

from collections import Counter
from functools import lru_cache
import hashlib
import html
from html.parser import HTMLParser
from pathlib import Path
import re
import sys
import tomllib
import unicodedata


ROOT = Path(__file__).resolve().parents[1]
PRODUCT_PATH = ROOT / "specs" / "product.md"
ARCHITECTURE_PATH = ROOT / "specs" / "architecture.md"
OPERATIONS_PATH = ROOT / "specs" / "operations.toml"
RELEASE_IDENTITY_PATH = ROOT / "specs" / "release-identity.toml"

RELEASE_IDENTITY_VERSION = 1
RELEASE_IDENTITY_CANONICALIZATION = "utf8-newlines-v1"
RELEASE_IDENTITY_FIELDS = {"manifest_version", "canonicalization", "document"}
RELEASE_IDENTITY_DOCUMENT_FIELDS = {"path", "version", "sha256"}

EXPECTED_PR_NUMBERS = {
    number
    for start, end in (
        (1, 6),
        (20, 23),
        (40, 48),
        (60, 64),
        (70, 77),
        (80, 88),
        (90, 95),
        (100, 155),
    )
    for number in range(start, end + 1)
}
EXPECTED_A_SUBSECTIONS = {
    0: 3,
    1: 2,
    2: 3,
    3: 3,
    4: 2,
    5: 3,
    6: 4,
    7: 7,
    8: 4,
    9: 4,
    10: 7,
    11: 6,
    12: 3,
    13: 4,
    14: 4,
    15: 3,
    16: 4,
    17: 3,
    18: 3,
    19: 0,
    20: 0,
}
EXPECTED_P_SUBSECTIONS = {
    0: 1,
    1: 3,
    2: 2,
    3: 2,
    4: 2,
    5: 3,
    6: 3,
    7: 1,
    8: 2,
    9: 1,
    10: 3,
    11: 0,
    12: 0,
    13: 2,
    14: 0,
    15: 0,
    16: 0,
    17: 0,
    18: 1,
    19: 0,
    20: 0,
}
EXPECTED_PRODUCT_SECTIONS = {
    f"P-{number:02d}" for number in EXPECTED_P_SUBSECTIONS
} | {
    f"P-{number:02d}.{subsection}"
    for number, last_subsection in EXPECTED_P_SUBSECTIONS.items()
    for subsection in range(1, last_subsection + 1)
}
EXPECTED_PRODUCT_NON_GOALS = {f"NG-{number:03d}" for number in range(1, 10)}
EXPECTED_ARCHITECTURE_SECTIONS = {
    f"A-{number:02d}" for number in EXPECTED_A_SUBSECTIONS
} | {
    f"A-{number:02d}.{subsection}"
    for number, last_subsection in EXPECTED_A_SUBSECTIONS.items()
    for subsection in range(1, last_subsection + 1)
} | {"A-10.2.1", "A-10.2.2", "A-13.1.1", "A-13.2.1", "A-13.2.2", "A-13.2.3", "A-13.2.4", "A-13.2.5", "A-13.2.6", "A-13.2.7"}
EXPECTED_IDS = {
    "PR": {f"PR-{number:03d}" for number in EXPECTED_PR_NUMBERS},
    "AC": {f"AC-{number:03d}" for number in range(1, 69)},
    "INV": {f"INV-{number:03d}" for number in range(1, 13)},
    "A": EXPECTED_ARCHITECTURE_SECTIONS,
}
EXPECTED_MAINTENANCE = {
    "configuration.show",
    "configuration.validate",
    "configuration.activate",
    "state_key.list",
    "state_key.rotate",
    "state_key.retire",
    "recovery_key.list",
    "recovery_key.generate",
    "recovery_key.import",
    "recovery_key.retire",
    "bootstrap.create",
    "restore.create",
    "restore.show",
    "state_generation.list",
    "state_generation.delete",
    "upgrade.show",
    "upgrade.migrate",
    "upgrade.rollback",
    "clock.show",
    "clock.acknowledge",
    "system.health",
    "system.readiness",
    "system.shutdown",
}
EXPECTED_UPGRADE_LIFECYCLE_RECORDS = {
    "clock.checkpoint",
    "clock.acknowledge",
    "system.shutdown",
}
EXPECTED_ADDRESSED_STATE = {
    "clock.acknowledge",
    "system.shutdown",
}
EXPECTED_GENERATION_GUARDED = {
    "admission.set",
    "principal.enable",
    "principal.disable",
    "grant.put",
    "grant.delete",
}
EXPECTED_MUTATION_EVIDENCE = (
    ("operation", 1_476),
    ("catalog", 30),
    ("document/version", 385),
    ("definition", 6_243),
    ("maintenance", 7),
    ("lifecycle", 7),
    ("addressed-state", 7),
    ("generation-guarded", 7),
    ("complete-revision", 23),
    ("incarnation-allocator", 66),
    ("upgrade-exit-capacity", 27),
    ("release-integrity", 12),
    ("evidence-parity", 12),
)
EXPECTED_MUTATION_TOTAL = 8_302
EXPECTED_MUTATION_ROUTES = 78
EXPECTED_FIXED_ROOT = {
    "configuration.activate",
    "clock.acknowledge",
    "state_key.rotate",
    "state_key.retire",
    "recovery_key.generate",
    "recovery_key.import",
    "recovery_key.retire",
    "bootstrap.create",
    "restore.create",
    "state_generation.delete",
    "upgrade.prepare",
    "upgrade.migrate",
    "upgrade.activate",
    "upgrade.rollback",
    "system.shutdown",
}
# Independent policy manifest: this intentionally does not derive from operations.toml. It makes a
# known-profile, binding, idempotency, or risk swap a deterministic specification failure.
EXPECTED_OPERATION_POLICY = {
    "provider.list": ("authenticated_catalog", ("normal_uds", "normal_tcp"), "safe", "read"),
    "provider.show": ("authenticated_catalog", ("normal_uds", "normal_tcp"), "safe", "read"),
    "provider.schema": ("authenticated_catalog", ("normal_uds", "normal_tcp"), "safe", "read"),
    "message.submit": ("submit", ("normal_uds", "normal_tcp"), "domain_key", "external_effect"),
    "message.list": ("status_own_or_operator", ("normal_uds", "normal_tcp"), "safe", "read"),
    "message.show": ("status_own_or_operator", ("normal_uds", "normal_tcp"), "safe", "read"),
    "message.attempt.list": ("status_own_or_operator", ("normal_uds", "normal_tcp"), "safe", "read"),
    "message.cancel": ("cancel_own_or_operator", ("normal_uds", "normal_tcp"), "idempotent_action", "mutation"),
    "dead_letter.list": ("operator", ("normal_uds", "normal_tcp"), "safe", "read"),
    "dead_letter.replay": ("local_operator", ("normal_uds",), "domain_key", "external_effect"),
    "payload.purge": ("local_operator", ("normal_uds",), "idempotent_action", "destructive"),
    "queue.list": ("operator", ("normal_uds", "normal_tcp"), "safe", "read"),
    "connector.list": ("local_operator", ("normal_uds",), "safe", "sensitive_read"),
    "connector.show": ("local_operator", ("normal_uds",), "safe", "sensitive_read"),
    "audit.list": ("local_operator", ("normal_uds",), "safe", "sensitive_read"),
    "admission.show": ("operator", ("normal_uds", "normal_tcp"), "safe", "read"),
    "admission.set": ("operator", ("normal_uds", "normal_tcp"), "generation_guarded", "reversible_control"),
    "drain.start": ("operator", ("normal_uds", "normal_tcp"), "command_key", "reversible_control"),
    "clock.show": ("local_operator_or_state_owner_peer", ("normal_uds", "maintenance_uds"), "safe", "sensitive_read"),
    "clock.acknowledge": ("local_operator_or_state_owner_peer", ("normal_uds", "maintenance_uds"), "addressed_state", "safety_override"),
    "principal.list": ("local_operator", ("normal_uds",), "safe", "sensitive_read"),
    "principal.create": ("local_operator", ("normal_uds",), "command_key", "authorization_change"),
    "principal.show": ("local_operator", ("normal_uds",), "safe", "sensitive_read"),
    "principal.update": ("local_operator", ("normal_uds",), "command_key", "authorization_change"),
    "principal.enable": ("local_operator", ("normal_uds",), "generation_guarded", "authorization_change"),
    "principal.disable": ("local_operator", ("normal_uds",), "generation_guarded", "authorization_change"),
    "grant.list": ("local_operator", ("normal_uds",), "safe", "sensitive_read"),
    "grant.put": ("local_operator", ("normal_uds",), "generation_guarded", "authorization_change"),
    "grant.delete": ("local_operator", ("normal_uds",), "generation_guarded", "authorization_change"),
    "api_key.list": ("local_operator", ("normal_uds",), "safe", "sensitive_read"),
    "api_key.issue": ("local_operator", ("normal_uds",), "one_time_secret", "credential_issue"),
    "api_key.rotate": ("local_operator", ("normal_uds",), "one_time_secret", "credential_issue"),
    "api_key.revoke": ("local_operator", ("normal_uds",), "idempotent_action", "authorization_change"),
    "peer_mapping.list": ("local_operator", ("normal_uds",), "safe", "sensitive_read"),
    "peer_mapping.create": ("local_operator", ("normal_uds",), "command_key", "authorization_change"),
    "peer_mapping.show": ("local_operator", ("normal_uds",), "safe", "sensitive_read"),
    "peer_mapping.update": ("local_operator", ("normal_uds",), "command_key", "authorization_change"),
    "peer_mapping.delete": ("local_operator", ("normal_uds",), "idempotent_action", "authorization_change"),
    "configuration.show": ("local_operator_or_state_owner_peer", ("normal_uds", "maintenance_uds"), "safe", "sensitive_read"),
    "configuration.validate": ("local_operator_or_state_owner_peer", ("normal_uds", "maintenance_uds"), "safe_calculation", "sensitive_read"),
    "configuration.activate": ("state_owner_peer", ("maintenance_uds",), "command_key", "configuration_change"),
    "state_key.list": ("state_owner_peer", ("maintenance_uds",), "safe", "sensitive_read"),
    "state_key.rotate": ("state_owner_peer", ("maintenance_uds",), "command_key", "cryptographic_change"),
    "state_key.retire": ("state_owner_peer", ("maintenance_uds",), "command_key", "destructive"),
    "recovery_key.list": ("state_owner_peer", ("maintenance_uds",), "safe", "sensitive_read"),
    "recovery_key.generate": ("state_owner_peer", ("maintenance_uds",), "one_time_secret", "credential_issue"),
    "recovery_key.import": ("state_owner_peer", ("maintenance_uds",), "command_key", "cryptographic_change"),
    "recovery_key.retire": ("state_owner_peer", ("maintenance_uds",), "command_key", "destructive"),
    "backup.list": ("local_operator", ("normal_uds",), "safe", "sensitive_read"),
    "backup.create": ("local_operator", ("normal_uds",), "command_key", "resource_intensive"),
    "backup.show": ("local_operator", ("normal_uds",), "safe", "sensitive_read"),
    "backup.manifest": ("local_operator", ("normal_uds",), "safe", "sensitive_read"),
    "backup.download": ("local_operator", ("normal_uds",), "safe", "sensitive_read"),
    "backup.cancel": ("local_operator", ("normal_uds",), "idempotent_action", "mutation"),
    "bootstrap.create": ("state_owner_peer", ("maintenance_uds",), "command_key", "configuration_change"),
    "restore.create": ("state_owner_peer", ("maintenance_uds",), "command_key", "destructive"),
    "restore.show": ("state_owner_peer", ("maintenance_uds",), "safe", "sensitive_read"),
    "restore.report": ("local_operator", ("normal_uds",), "safe", "sensitive_read"),
    "restore.resume": ("local_recovery_operator", ("normal_uds",), "command_key", "safety_override"),
    "state_generation.list": ("state_owner_peer", ("maintenance_uds",), "safe", "sensitive_read"),
    "state_generation.delete": ("state_owner_peer", ("maintenance_uds",), "command_key", "destructive"),
    "upgrade.show": ("local_operator_or_state_owner_peer", ("normal_uds", "maintenance_uds"), "safe", "sensitive_read"),
    "upgrade.prepare": ("local_operator", ("normal_uds",), "command_key", "safety_control"),
    "upgrade.migrate": ("state_owner_peer", ("maintenance_uds",), "command_key", "destructive"),
    "upgrade.activate": ("local_operator", ("normal_uds",), "command_key", "safety_override"),
    "upgrade.rollback": ("state_owner_peer", ("maintenance_uds",), "command_key", "destructive"),
    "system.health": ("probe_by_binding", ("normal_uds", "normal_tcp", "maintenance_uds"), "safe", "read"),
    "system.readiness": ("probe_by_binding", ("normal_uds", "normal_tcp", "maintenance_uds"), "safe", "read"),
    "system.metrics": ("local_operator", ("normal_uds",), "safe", "sensitive_read"),
    "system.shutdown": ("local_operator_or_state_owner_peer", ("normal_uds", "maintenance_uds"), "addressed_state", "safety_control"),
}
# Independent public-surface manifest. Keeping this separate from the policy manifest makes a route,
# method, CLI spelling, or wire-codec swap fail even when every operation remains unique and well formed.
EXPECTED_OPERATION_SURFACE = {
    "provider.list": ("GET", "/v1/providers", "provider list", "query.provider_list.v1", "json.provider_page.v1"),
    "provider.show": ("GET", "/v1/providers/{provider_id}", "provider show", "path.provider_id.v1", "json.provider.v1"),
    "provider.schema": ("GET", "/v1/providers/{provider_id}/schemas/{schema_id}", "provider schema", "path.provider_schema_id.v1", "json.provider_schema.v1"),
    "message.submit": ("POST", "/v1/messages", "send", "json.message_submit.v1", "json.message_acceptance.v1"),
    "message.list": ("GET", "/v1/messages", "message list", "query.message_list.v1", "json.message_page.v1"),
    "message.show": ("GET", "/v1/messages/{message_id}", "message show", "path.message_id.v1", "json.message_status.v1"),
    "message.attempt.list": ("GET", "/v1/messages/{message_id}/attempts", "message attempts", "query.message_attempt_list.v1", "json.attempt_page.v1"),
    "message.cancel": ("POST", "/v1/messages/{message_id}/cancel", "message cancel", "json.message_cancel.v1", "json.message_status.v1"),
    "dead_letter.list": ("GET", "/v1/dead-letters", "dead-letter list", "query.dead_letter_list.v1", "json.dead_letter_page.v1"),
    "dead_letter.replay": ("POST", "/v1/dead-letters/{message_id}/replays", "dead-letter replay", "json.dead_letter_replay.v1", "json.message_acceptance.v1"),
    "payload.purge": ("DELETE", "/v1/messages/{message_id}/payload", "payload purge", "json.payload_purge.v1", "json.payload_purge_result.v1"),
    "queue.list": ("GET", "/v1/admin/queue", "queue list", "query.queue_list.v1", "json.queue_page.v1"),
    "connector.list": ("GET", "/v1/admin/connectors", "connector list", "query.connector_list.v1", "json.connector_page.v1"),
    "connector.show": ("GET", "/v1/admin/connectors/{connector_id}", "connector show", "path.connector_id.v1", "json.connector_status.v1"),
    "audit.list": ("GET", "/v1/admin/audit-events", "audit list", "query.audit_list.v1", "json.audit_page.v1"),
    "admission.show": ("GET", "/v1/admin/admission", "admission show", "none", "json.admission.v1"),
    "admission.set": ("PUT", "/v1/admin/admission", "admission set", "json.admission_set.v1", "json.admission.v1"),
    "drain.start": ("POST", "/v1/admin/drains", "drain", "json.drain.v1", "json.drain_result.v1"),
    "clock.show": ("GET", "/v1/admin/clock", "clock show", "none", "json.clock_status.v1"),
    "clock.acknowledge": ("POST", "/v1/admin/clock-acknowledgements", "clock acknowledge", "json.clock_acknowledgement.v1", "json.clock_status.v1"),
    "principal.list": ("GET", "/v1/admin/principals", "principal list", "query.principal_list.v1", "json.principal_page.v1"),
    "principal.create": ("POST", "/v1/admin/principals", "principal create", "json.principal_create.v1", "json.principal.v1"),
    "principal.show": ("GET", "/v1/admin/principals/{principal_id}", "principal show", "path.principal_id.v1", "json.principal.v1"),
    "principal.update": ("PATCH", "/v1/admin/principals/{principal_id}", "principal update", "json.principal_update.v1", "json.principal.v1"),
    "principal.enable": ("POST", "/v1/admin/principals/{principal_id}/enable", "principal enable", "json.generation_guarded_action.v1", "json.principal.v1"),
    "principal.disable": ("POST", "/v1/admin/principals/{principal_id}/disable", "principal disable", "json.generation_guarded_action.v1", "json.principal.v1"),
    "grant.list": ("GET", "/v1/admin/principals/{principal_id}/provider-grants", "principal grant list", "query.grant_list.v1", "json.grant_page.v1"),
    "grant.put": ("PUT", "/v1/admin/principals/{principal_id}/provider-grants/{provider_id}", "principal grant set", "json.grant_set.v1", "json.grant.v1"),
    "grant.delete": ("DELETE", "/v1/admin/principals/{principal_id}/provider-grants/{provider_id}", "principal grant revoke", "json.generation_guarded_action.v1", "json.grant_delete_result.v1"),
    "api_key.list": ("GET", "/v1/admin/api-keys", "api-key list", "query.api_key_list.v1", "json.api_key_page.v1"),
    "api_key.issue": ("POST", "/v1/admin/api-keys", "api-key issue", "json.api_key_issue.v1", "json.api_key_secret_once.v1"),
    "api_key.rotate": ("POST", "/v1/admin/api-keys/{key_id}/rotations", "api-key rotate", "json.api_key_rotate.v1", "json.api_key_secret_once.v1"),
    "api_key.revoke": ("DELETE", "/v1/admin/api-keys/{key_id}", "api-key revoke", "json.admin_action.v1", "json.api_key_revoke_result.v1"),
    "peer_mapping.list": ("GET", "/v1/admin/peer-mappings", "peer-mapping list", "query.peer_mapping_list.v1", "json.peer_mapping_page.v1"),
    "peer_mapping.create": ("POST", "/v1/admin/peer-mappings", "peer-mapping create", "json.peer_mapping_create.v1", "json.peer_mapping.v1"),
    "peer_mapping.show": ("GET", "/v1/admin/peer-mappings/{mapping_id}", "peer-mapping show", "path.peer_mapping_id.v1", "json.peer_mapping.v1"),
    "peer_mapping.update": ("PATCH", "/v1/admin/peer-mappings/{mapping_id}", "peer-mapping update", "json.peer_mapping_update.v1", "json.peer_mapping.v1"),
    "peer_mapping.delete": ("DELETE", "/v1/admin/peer-mappings/{mapping_id}", "peer-mapping delete", "json.admin_action.v1", "json.peer_mapping_delete_result.v1"),
    "configuration.show": ("GET", "/v1/admin/configuration", "config show", "none", "json.configuration.v1"),
    "configuration.validate": ("POST", "/v1/admin/config-validations", "config check", "bytes.configuration_candidate.v1", "json.configuration_validation.v1"),
    "configuration.activate": ("PUT", "/v1/admin/configuration", "maintenance config activate", "bytes.configuration_activation.v1", "json.configuration_activation.v1"),
    "state_key.list": ("GET", "/v1/admin/state-keys", "maintenance state-key list", "query.state_key_list.v1", "json.state_key_page.v1"),
    "state_key.rotate": ("POST", "/v1/admin/state-keys/{purpose}/rotations", "maintenance state-key rotate", "json.state_key_rotate.v1", "json.state_key_rotation.v1"),
    "state_key.retire": ("DELETE", "/v1/admin/state-keys/{purpose}/{generation_id}", "maintenance state-key retire", "json.key_retirement.v1", "json.key_retirement_result.v1"),
    "recovery_key.list": ("GET", "/v1/admin/recovery-keys", "maintenance recovery-key list", "query.recovery_key_list.v1", "json.recovery_key_page.v1"),
    "recovery_key.generate": ("POST", "/v1/admin/recovery-keys", "maintenance recovery-key generate", "json.recovery_key_generate_phase.v1", "json.recovery_key_generate_phase_result.v1"),
    "recovery_key.import": ("POST", "/v1/admin/recovery-key-imports", "maintenance recovery-key import", "json.recovery_key_import.v1", "json.recovery_key_metadata.v1"),
    "recovery_key.retire": ("DELETE", "/v1/admin/recovery-keys/{generation_id}", "maintenance recovery-key retire", "json.key_retirement.v1", "json.key_retirement_result.v1"),
    "backup.list": ("GET", "/v1/admin/backups", "backup list", "query.backup_list.v1", "json.backup_page.v1"),
    "backup.create": ("POST", "/v1/admin/backups", "backup create", "json.backup_create.v1", "json.backup_job.v1"),
    "backup.show": ("GET", "/v1/admin/backups/{backup_id}", "backup show", "path.backup_id.v1", "json.backup_job.v1"),
    "backup.manifest": ("GET", "/v1/admin/backups/{backup_id}/manifest", "backup manifest", "path.backup_id.v1", "json.backup_manifest.v1"),
    "backup.download": ("GET", "/v1/admin/backups/{backup_id}/artifact", "backup download", "path.backup_id.v1", "stream.backup_artifact.v1"),
    "backup.cancel": ("POST", "/v1/admin/backups/{backup_id}/cancel", "backup cancel", "json.admin_action.v1", "json.backup_job.v1"),
    "bootstrap.create": ("POST", "/v1/admin/bootstrap", "maintenance bootstrap", "json.bootstrap.v1", "json.bootstrap_result.v1"),
    "restore.create": ("POST", "/v1/admin/restores", "maintenance restore", "stream.restore_artifact.v1", "json.restore_job.v1"),
    "restore.show": ("GET", "/v1/admin/restores/{restore_id}", "maintenance restore show", "path.restore_id.v1", "json.restore_job.v1"),
    "restore.report": ("GET", "/v1/admin/restores/current", "restore report", "query.restore_report_page.v1", "json.restore_report_page.v1"),
    "restore.resume": ("POST", "/v1/admin/restores/current/resume", "restore resume", "json.restore_resume.v1", "json.restore_resume_result.v1"),
    "state_generation.list": ("GET", "/v1/admin/state-generations", "maintenance state-generation list", "query.state_generation_list.v1", "json.state_generation_page.v1"),
    "state_generation.delete": ("DELETE", "/v1/admin/state-generations/{generation_id}", "maintenance state-generation delete", "json.state_generation_delete.v1", "json.state_generation_delete_result.v1"),
    "upgrade.show": ("GET", "/v1/admin/upgrade", "upgrade show", "none", "json.upgrade_status.v1"),
    "upgrade.prepare": ("POST", "/v1/admin/upgrades", "upgrade prepare", "json.upgrade_prepare.v1", "json.upgrade_status.v1"),
    "upgrade.migrate": ("POST", "/v1/admin/upgrades/{upgrade_id}/migration", "maintenance upgrade migrate", "json.upgrade_migrate.v1", "json.upgrade_status.v1"),
    "upgrade.activate": ("POST", "/v1/admin/upgrades/{upgrade_id}/activation", "upgrade activate", "json.upgrade_activate.v1", "json.upgrade_status.v1"),
    "upgrade.rollback": ("POST", "/v1/admin/upgrades/{upgrade_id}/rollback", "maintenance upgrade rollback", "json.upgrade_rollback.v1", "json.upgrade_status.v1"),
    "system.health": ("GET", "/v1/system/health", "health", "none", "json.health.v1"),
    "system.readiness": ("GET", "/v1/system/readiness", "readiness", "none", "json.readiness.v1"),
    "system.metrics": ("GET", "/v1/system/metrics", "metrics", "none", "text.metrics.v1"),
    "system.shutdown": ("POST", "/v1/system/shutdown", "shutdown", "json.shutdown.v1", "json.shutdown_accepted.v1"),
}
EXPECTED_ONE_TIME_MODES = {
    "api_key.issue": "single_phase",
    "api_key.rotate": "single_phase",
    "recovery_key.generate": "escrow_acknowledgement",
}
ALLOWED_BINDINGS = {"normal_uds", "normal_tcp", "maintenance_uds"}
ALLOWED_AUTHORIZATION = {
    "authenticated_catalog",
    "cancel_own_or_operator",
    "local_operator",
    "local_operator_or_state_owner_peer",
    "local_recovery_operator",
    "operator",
    "probe_by_binding",
    "state_owner_peer",
    "status_own_or_operator",
    "submit",
}
ALLOWED_IDEMPOTENCY = {
    "safe",
    "safe_calculation",
    "domain_key",
    "generation_guarded",
    "idempotent_action",
    "addressed_state",
    "command_key",
    "one_time_secret",
}
ALLOWED_RISK = {
    "authorization_change",
    "configuration_change",
    "credential_issue",
    "cryptographic_change",
    "destructive",
    "external_effect",
    "mutation",
    "read",
    "resource_intensive",
    "reversible_control",
    "safety_control",
    "safety_override",
    "sensitive_read",
}
ALLOWED_CODECS = {
    "bytes.configuration_activation.v1",
    "bytes.configuration_candidate.v1",
    "json.admin_action.v1",
    "json.admission.v1",
    "json.admission_set.v1",
    "json.api_key_issue.v1",
    "json.api_key_page.v1",
    "json.api_key_revoke_result.v1",
    "json.api_key_rotate.v1",
    "json.api_key_secret_once.v1",
    "json.attempt_page.v1",
    "json.audit_page.v1",
    "json.backup_create.v1",
    "json.backup_job.v1",
    "json.backup_manifest.v1",
    "json.backup_page.v1",
    "json.bootstrap.v1",
    "json.bootstrap_result.v1",
    "json.clock_acknowledgement.v1",
    "json.clock_status.v1",
    "json.configuration.v1",
    "json.configuration_activation.v1",
    "json.configuration_validation.v1",
    "json.connector_page.v1",
    "json.connector_status.v1",
    "json.dead_letter_page.v1",
    "json.dead_letter_replay.v1",
    "json.drain.v1",
    "json.drain_result.v1",
    "json.grant.v1",
    "json.grant_delete_result.v1",
    "json.grant_page.v1",
    "json.grant_set.v1",
    "json.generation_guarded_action.v1",
    "json.health.v1",
    "json.key_retirement.v1",
    "json.key_retirement_result.v1",
    "json.message_acceptance.v1",
    "json.message_cancel.v1",
    "json.message_page.v1",
    "json.message_status.v1",
    "json.message_submit.v1",
    "json.payload_purge.v1",
    "json.payload_purge_result.v1",
    "json.peer_mapping.v1",
    "json.peer_mapping_create.v1",
    "json.peer_mapping_delete_result.v1",
    "json.peer_mapping_page.v1",
    "json.peer_mapping_update.v1",
    "json.principal.v1",
    "json.principal_create.v1",
    "json.principal_page.v1",
    "json.principal_update.v1",
    "json.provider.v1",
    "json.provider_page.v1",
    "json.provider_schema.v1",
    "json.queue_page.v1",
    "json.readiness.v1",
    "json.recovery_key_generate_phase.v1",
    "json.recovery_key_generate_phase_result.v1",
    "json.recovery_key_import.v1",
    "json.recovery_key_metadata.v1",
    "json.recovery_key_page.v1",
    "json.restore_job.v1",
    "json.restore_report_page.v1",
    "json.restore_resume.v1",
    "json.restore_resume_result.v1",
    "json.shutdown.v1",
    "json.shutdown_accepted.v1",
    "json.state_generation_delete.v1",
    "json.state_generation_delete_result.v1",
    "json.state_generation_page.v1",
    "json.state_key_page.v1",
    "json.state_key_rotate.v1",
    "json.state_key_rotation.v1",
    "json.upgrade_activate.v1",
    "json.upgrade_migrate.v1",
    "json.upgrade_prepare.v1",
    "json.upgrade_rollback.v1",
    "json.upgrade_status.v1",
    "path.backup_id.v1",
    "path.connector_id.v1",
    "path.message_id.v1",
    "path.peer_mapping_id.v1",
    "path.principal_id.v1",
    "path.provider_id.v1",
    "path.provider_schema_id.v1",
    "path.restore_id.v1",
    "query.api_key_list.v1",
    "query.audit_list.v1",
    "query.backup_list.v1",
    "query.connector_list.v1",
    "query.dead_letter_list.v1",
    "query.grant_list.v1",
    "query.message_attempt_list.v1",
    "query.message_list.v1",
    "query.peer_mapping_list.v1",
    "query.principal_list.v1",
    "query.provider_list.v1",
    "query.queue_list.v1",
    "query.recovery_key_list.v1",
    "query.restore_report_page.v1",
    "query.state_generation_list.v1",
    "query.state_key_list.v1",
    "stream.backup_artifact.v1",
    "stream.restore_artifact.v1",
    "text.metrics.v1",
}
REQUIRED_OPERATION_FIELDS = {
    "id",
    "method",
    "path",
    "bindings",
    "authorization",
    "cli",
    "request_codec",
    "response_codec",
    "idempotency",
    "risk",
}
CODEC_RE = re.compile(r"(?:bytes|json|path|query|stream|text)\.[a-z0-9_]+\.v1")
OPERATION_ID_RE = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+")
PARAMETER_RE = re.compile(r"\{[a-z][a-z0-9_]*\}")
DEFINITION_ID_RE = re.compile(
    r"(?:PR-\d{3}|AC-\d{3}|INV-\d{3}|A-\d{2}(?:\.\d+)*)"
)
MAX_DEFINITION_LINE_CHARS = 8_192
MAX_DEFINITION_RENDER_CHARS = MAX_DEFINITION_LINE_CHARS * 4
MAX_NORMALIZED_DEFINITION_CHARS = MAX_DEFINITION_RENDER_CHARS
MAX_TRAILING_PROVENANCE_CANDIDATES = 256
MAX_MARKDOWN_NESTING = 64
MAX_HTML_DOCUMENT_CHARS = 1_048_576
MAX_HTML_NESTING = 64
MAX_HTML_WORK_FACTOR = 2
# Unicode Default_Ignorable_Code_Point ranges. Category-C/M removal below already covers most of
# these; the explicit property table is required for Lo fillers such as U+115F/U+1160.
DEFAULT_IGNORABLE_RANGES = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)
DEFAULT_IGNORABLE_CODEPOINTS = frozenset(
    codepoint
    for start, end in DEFAULT_IGNORABLE_RANGES
    for codepoint in range(start, end + 1)
)
# Unicode Bidi_Control. Unlike other default-ignorable characters, these may change visual order;
# deleting them while retaining source order is unsafe for normative identifiers and metadata.
BIDI_CONTROL_RANGES = (
    (0x061C, 0x061C),
    (0x200E, 0x200F),
    (0x202A, 0x202E),
    (0x2066, 0x2069),
)
BIDI_CONTROL_RE = re.compile(
    "["
    + re.escape(
        "".join(
            chr(codepoint)
            for start, end in BIDI_CONTROL_RANGES
            for codepoint in range(start, end + 1)
        )
    )
    + "]"
)
EXPECTED_TOP_LEVEL_FIELDS = {
    "catalog_version",
    "product_spec",
    "architecture_spec",
    "api_prefix",
    "fixed_root_journaled_operations",
    "operation",
    "provider_ingress",
}


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def reject_bidi_controls(source: str, context: str) -> None:
    require(
        BIDI_CONTROL_RE.search(html.unescape(source)) is None,
        f"{context} contains a Unicode bidi control",
    )


def unique(name: str, values: list[object]) -> None:
    duplicates = sorted(
        (value for value, count in Counter(values).items() if count > 1), key=str
    )
    require(not duplicates, f"duplicate {name}: {duplicates}")


PRODUCT_METADATA_FIELDS = (
    "Document status",
    "Product",
    "Specification version",
    "Updated",
    "Owner",
)

ARCHITECTURE_METADATA_FIELDS = (
    "Document status",
    "Architecture version",
    "Product contract",
    "Updated",
    "Owner",
)


def markdown_table_cells(line: str) -> list[str] | None:
    body = line.strip()
    if "|" not in body:
        return None
    code_mask = markdown_html_validation_source(body)
    cells: list[str] = []
    current: list[str] = []
    preceding_backslashes = 0
    for index, character in enumerate(body):
        if (
            character == "|"
            and preceding_backslashes % 2 == 0
            and code_mask[index] != " "
        ):
            cells.append("".join(current).strip())
            current = []
            preceding_backslashes = 0
            continue
        current.append(character)
        if character == "\\":
            preceding_backslashes += 1
        else:
            preceding_backslashes = 0
    cells.append("".join(current).strip())
    if body.startswith("|"):
        cells = cells[1:]
    if cells and not cells[-1] and body.endswith("|"):
        cells = cells[:-1]
    return cells


def rendered_metadata_field_key(cell: str) -> str:
    """Approximate a GFM table cell's visible metadata label for duplicate detection."""
    rendered = unicodedata.normalize("NFKC", html.unescape(cell)).casefold()
    rendered = re.sub(r"\[([^]]+)]\([^)]*\)", r"\1", rendered)
    rendered = re.sub(r"<!--.*?-->|<[^>]*>", "", rendered)
    return re.sub(r"[^a-z0-9]+", "", rendered)


LINKAGE_METADATA_FIELDS = frozenset(
    {"Specification version", "Architecture version", "Product contract"}
)


def ordered_subsequence(needle: str, haystack: str) -> bool:
    position = 0
    for character in haystack:
        if position < len(needle) and character == needle[position]:
            position += 1
    return position == len(needle)


def metadata_field_occurs(cell: str, field: str) -> bool:
    expected_key = rendered_metadata_field_key(field)
    if rendered_metadata_field_key(cell) == expected_key:
        return True
    if field not in LINKAGE_METADATA_FIELDS:
        return False
    source_key = re.sub(
        r"[^a-z0-9]+",
        "",
        unicodedata.normalize("NFKC", html.unescape(cell)).casefold(),
    )
    return ordered_subsequence(expected_key, source_key)


def metadata_values(document: str, expected_fields: tuple[str, ...]) -> dict[str, str]:
    reject_bidi_controls(document, "document metadata source")
    lines = document.splitlines()
    require(bool(lines) and lines[0].startswith("# "), "document must start with an H1")
    table_start = next(
        (index for index, line in enumerate(lines[1:], start=1) if line.strip()),
        -1,
    )
    require(table_start >= 0, "missing document metadata table")
    require(
        markdown_table_cells(lines[table_start]) == ["Field", "Value"],
        "document metadata header must be Field/Value",
    )
    require(table_start + 1 < len(lines), "missing document metadata separator")
    separator = markdown_table_cells(lines[table_start + 1])
    require(
        separator is not None
        and len(separator) == 2
        and all(re.fullmatch(r":?-{3,}:?", cell) for cell in separator),
        "invalid document metadata separator",
    )

    fields: list[str] = []
    values: dict[str, str] = {}
    row_indexes: set[int] = set()
    index = table_start + 2
    while index < len(lines) and lines[index].strip():
        cells = markdown_table_cells(lines[index])
        require(cells is not None and len(cells) == 2, "invalid document metadata row")
        field, value = cells
        require(field in expected_fields, f"unknown document metadata field: {field}")
        require(field not in values, f"duplicate document metadata field: {field}")
        require(bool(value), f"empty document metadata value: {field}")
        fields.append(field)
        values[field] = value.replace("`", "")
        row_indexes.add(index)
        index += 1

    require(tuple(fields) == expected_fields, "document metadata field/order mismatch")
    fenced_lines = markdown_fenced_line_numbers(document)
    for line_index, line in enumerate(lines):
        if line_index in row_indexes or line_index in fenced_lines:
            continue
        normalized_line, _, list_item, _ = structural_prefixes_with_work(
            line.lstrip()
        )
        if list_item:
            task_marker = re.match(r"^\[[ xX]\]\s+(.*)$", normalized_line)
            if task_marker is not None:
                normalized_line = task_marker.group(1).lstrip()
        cells = markdown_table_cells(normalized_line)
        if not cells:
            continue
        for field in expected_fields:
            if metadata_field_occurs(cells[0], field):
                fail(f"document metadata field occurs outside initial table: {field}")
    return values


HTML_VOID_ELEMENTS = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "source",
        "track",
        "wbr",
    }
)
HTML_HIDDEN_ELEMENTS = frozenset({"script", "style", "template"})
HTML_BREAK_ELEMENTS = frozenset({"br", "hr", "wbr"})
HTML_CONTEXTUAL_VISIBILITY_ELEMENTS = frozenset(
    {
        "audio",
        "canvas",
        "datalist",
        "details",
        "dialog",
        "iframe",
        "img",
        "math",
        "noscript",
        "object",
        "picture",
        "svg",
        "title",
        "video",
    }
)
HTML_STRUCTURAL_ELEMENTS = frozenset(
    {
        "address",
        "article",
        "aside",
        "body",
        "blockquote",
        "caption",
        "dd",
        "div",
        "dl",
        "dt",
        "fieldset",
        "figcaption",
        "figure",
        "footer",
        "form",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "header",
        "hgroup",
        "html",
        "legend",
        "li",
        "main",
        "menu",
        "nav",
        "ol",
        "p",
        "pre",
        "search",
        "section",
        "table",
        "tbody",
        "td",
        "tfoot",
        "th",
        "thead",
        "tr",
        "ul",
    }
)
HTML_INLINE_VISIBLE_ELEMENTS = frozenset(
    {
        "a",
        "abbr",
        "b",
        "cite",
        "code",
        "data",
        "del",
        "dfn",
        "em",
        "i",
        "ins",
        "kbd",
        "label",
        "mark",
        "q",
        "s",
        "samp",
        "small",
        "span",
        "strong",
        "sub",
        "sup",
        "time",
        "u",
        "var",
    }
)
HTML_MODELED_ELEMENTS = (
    HTML_BREAK_ELEMENTS
    | HTML_CONTEXTUAL_VISIBILITY_ELEMENTS
    | HTML_HIDDEN_ELEMENTS
    | HTML_INLINE_VISIBLE_ELEMENTS
    | HTML_STRUCTURAL_ELEMENTS
    | {"link"}
)
MARKDOWN_AUTOLINK_RE = re.compile(
    r"<(?:[A-Za-z][A-Za-z0-9+.-]{1,31}:[^ <>]*|[^ <>@]+@[^ <>@]+)>"
)
# Closed CommonMark block-tag set used only as a conservative inline-provenance barrier. The HTML
# visibility model below remains smaller and fails closed when one of these tags is not modeled.
MARKDOWN_HTML_BLOCK_ELEMENTS = frozenset(
    {
        "address",
        "article",
        "aside",
        "base",
        "basefont",
        "blockquote",
        "body",
        "caption",
        "center",
        "col",
        "colgroup",
        "dd",
        "details",
        "dialog",
        "dir",
        "div",
        "dl",
        "dt",
        "fieldset",
        "figcaption",
        "figure",
        "footer",
        "form",
        "frame",
        "frameset",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "head",
        "header",
        "hr",
        "html",
        "iframe",
        "legend",
        "li",
        "link",
        "main",
        "menu",
        "menuitem",
        "nav",
        "noframes",
        "ol",
        "optgroup",
        "option",
        "p",
        "param",
        "pre",
        "script",
        "search",
        "section",
        "style",
        "summary",
        "table",
        "tbody",
        "td",
        "tfoot",
        "th",
        "thead",
        "title",
        "tr",
        "track",
        "ul",
    }
)
MARKDOWN_HTML_BLOCK_RE = re.compile(
    r"^ {0,3}</?(?:"
    + "|".join(sorted(MARKDOWN_HTML_BLOCK_ELEMENTS))
    + r")(?:[ \t]|/?>|$)",
    re.IGNORECASE,
)


FenceContainer = tuple[tuple[str, int], ...]


def markdown_list_marker(
    line: str, position: int, column: int
) -> tuple[int, int, int | None, int] | None:
    """Return raw/visual content starts, ordered value, and visual padding."""
    marker_start = position
    ordered_value: int | None = None
    if position < len(line) and line[position] in "-*+":
        marker_end = position + 1
    elif (
        position < len(line)
        and line[position].isascii()
        and line[position].isdigit()
    ):
        marker_end = position
        while (
            marker_end < len(line)
            and line[marker_end].isascii()
            and line[marker_end].isdigit()
        ):
            marker_end += 1
        if (
            marker_end - position > 9
            or marker_end >= len(line)
            or line[marker_end] not in ".)"
        ):
            return None
        ordered_value = int(line[position:marker_end])
        marker_end += 1
    else:
        return None

    marker_column = column + marker_end - marker_start
    if marker_end >= len(line) or line[marker_end] not in " \t":
        return None
    whitespace_end = marker_end
    whitespace_column = marker_column
    while whitespace_end < len(line) and line[whitespace_end] in " \t":
        if line[whitespace_end] == "\t":
            whitespace_column += markdown_tab_width(whitespace_column)
        else:
            whitespace_column += 1
        whitespace_end += 1
    return (
        whitespace_end,
        whitespace_column,
        ordered_value,
        whitespace_column - marker_column,
    )


def markdown_fence_opening_content(line: str) -> tuple[str, FenceContainer]:
    """Return content after a bounded blockquote/list container prefix."""
    position = 0
    column = 0
    tokens: list[tuple[str, int]] = []
    while position < len(line):
        start = position
        start_column = column
        spaces = 0
        while position < len(line) and line[position] == " " and spaces < 3:
            position += 1
            column += 1
            spaces += 1
        if position < len(line) and line[position] == ">":
            position += 1
            column += 1
            if position < len(line) and line[position] == " ":
                position += 1
                column += 1
            tokens.append(("quote", column - start_column))
        else:
            marker = markdown_list_marker(line, position, column)
            if marker is None or marker[3] > 4:
                position = start
                column = start_column
                break
            position, column, _, _ = marker
            tokens.append(("list", column - start_column))
    return line[position:], tuple(tokens)


def markdown_fence_continuation_content(
    line: str, container: FenceContainer
) -> str | None:
    """Strip the exact continuation prefix for a recognized fence container."""
    content = line
    column = 0
    for kind, width in container:
        if kind == "quote":
            position = 0
            spaces = 0
            while (
                position < len(content)
                and content[position] == " "
                and spaces < 3
            ):
                position += 1
                column += 1
                spaces += 1
            if position >= len(content) or content[position] != ">":
                return None
            position += 1
            column += 1
            if position < len(content) and content[position] == " ":
                position += 1
                column += 1
            content = content[position:]
        else:
            normalized = markdown_normalized_indentation_view(
                content, column, width
            )
            if normalized is None:
                return None
            content, _ = normalized
            column += width
    return content


def markdown_fence_opening(
    line: str,
) -> tuple[str, int, FenceContainer] | None:
    content, container = markdown_fence_opening_content(line)
    match = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", content)
    if match is None:
        return None
    marker, info = match.groups()
    require(
        len(container) <= MAX_MARKDOWN_NESTING,
        "Markdown fence container nesting exceeds bound",
    )
    if marker[0] == "`" and "`" in info:
        return None
    return marker[0], len(marker), container


def markdown_inline_block_boundary(line: str) -> bool:
    """Recognize conservative block starts that terminate inline-code provenance."""
    content = line.rstrip("\r\n")
    if not content.strip(" \t"):
        return True
    if markdown_fence_opening(content) is not None:
        return True
    position = 0
    column = 0
    spaces = 0
    while position < len(content) and content[position] == " " and spaces < 3:
        position += 1
        column += 1
        spaces += 1
    marker = markdown_list_marker(content, position, column)
    if marker is not None:
        ordered_value = marker[2]
        return ordered_value is None or ordered_value == 1
    if re.fullmatch(r" {0,3}-{1,2}[ \t]*", content):
        return True
    _, container = markdown_fence_opening_content(content)
    if container:
        return True
    if re.match(r"^ {0,3}#{1,6}(?:[ \t]+|$)", content):
        return True
    if re.fullmatch(
        r" {0,3}(?:(?:\*[ \t]*){3,}|(?:_[ \t]*){3,}|(?:-[ \t]*){3,}|=+[ \t]*)",
        content,
    ):
        return True
    if MARKDOWN_HTML_BLOCK_RE.match(content):
        return True
    return re.match(r"^ {0,3}<(?:!--|\?|![A-Z]|!\[CDATA\[)", content) is not None


@lru_cache(maxsize=8)
def markdown_inline_block_boundary_offsets(source: str) -> frozenset[int]:
    """Return source offsets where a new Markdown inline block starts."""
    offsets: set[int] = set()
    offset = 0
    for line in source.splitlines(keepends=True):
        if markdown_inline_block_boundary(line):
            offsets.add(offset)
        offset += len(line)
    return frozenset(offsets)


def markdown_tab_width(column: int) -> int:
    """Return the CommonMark width of a tab beginning at one visual column."""
    return 4 - column % 4


def markdown_leading_indentation(
    source: str, start_column: int = 0
) -> tuple[int, int]:
    """Return raw leading-whitespace bytes and their tab-expanded column width."""
    position = 0
    column = start_column
    while position < len(source) and source[position] in " \t":
        if source[position] == "\t":
            column += markdown_tab_width(column)
        else:
            column += 1
        position += 1
    return position, column - start_column


def markdown_normalized_indentation_view(
    source: str, start_column: int, remove_columns: int
) -> tuple[str, int] | None:
    """Expand only leading indentation and remove proven container columns."""
    raw_width, visual_width = markdown_leading_indentation(source, start_column)
    if visual_width < remove_columns:
        return None
    return " " * (visual_width - remove_columns) + source[raw_width:], raw_width


def markdown_quote_content(
    line: str, depth: int | None = None
) -> tuple[str, int, int, int] | None:
    """Return content, raw offset, depth, and virtual column after blockquotes."""
    position = 0
    observed = 0
    column = 0
    while position < len(line) and (depth is None or observed < depth):
        start = position
        start_column = column
        spaces = 0
        while position < len(line) and line[position] == " " and spaces < 3:
            position += 1
            spaces += 1
            column += 1
        if position >= len(line) or line[position] != ">":
            position = start
            column = start_column
            break
        position += 1
        column += 1
        if position < len(line) and line[position] == " ":
            position += 1
            column += 1
        elif position < len(line) and line[position] == "\t":
            tab_width = markdown_tab_width(column)
            if tab_width == 1:
                position += 1
                column += 1
            else:
                # CommonMark reserves one virtual post-marker column but leaves
                # the wider tab for the nested block parser to expand.
                column += 1
                observed += 1
                if observed > MAX_MARKDOWN_NESTING:
                    return None
                break
        observed += 1
        if observed > MAX_MARKDOWN_NESTING:
            return None
    if depth is not None and observed != depth:
        return None
    return line[position:], position, observed, column


def markdown_list_content_widths(source: str, start_column: int) -> tuple[int, ...]:
    """Return bounded visual content-indent increments for leading list markers."""
    position = 0
    column = start_column
    widths: list[int] = []
    while position < len(source):
        marker_start = position
        if source[position] in "-*+":
            marker_end = position + 1
        elif source[position].isascii() and source[position].isdigit():
            marker_end = position
            while (
                marker_end < len(source)
                and source[marker_end].isascii()
                and source[marker_end].isdigit()
            ):
                marker_end += 1
            if (
                marker_end - position > 9
                or marker_end >= len(source)
                or source[marker_end] not in ".)"
            ):
                break
            marker_end += 1
        else:
            break

        marker_width = marker_end - marker_start
        if marker_end == len(source):
            widths.append(marker_width + 1)
            break
        if source[marker_end] not in " \t":
            break

        whitespace_end = marker_end
        whitespace_column = column + marker_width
        while whitespace_end < len(source) and source[whitespace_end] in " \t":
            if source[whitespace_end] == "\t":
                whitespace_column += markdown_tab_width(whitespace_column)
            else:
                whitespace_column += 1
            whitespace_end += 1
        padding_width = whitespace_column - (column + marker_width)
        effective_padding = padding_width if padding_width <= 4 else 1
        widths.append(marker_width + effective_padding)
        if padding_width > 4:
            break
        position = whitespace_end
        column = whitespace_column
    return tuple(widths)


def gfm_unescaped_pipe_offsets(source: str) -> tuple[int, ...]:
    """Return raw GFM cell delimiters; cell splitting precedes inline parsing."""
    return tuple(
        index
        for index, character in enumerate(source)
        if character == "|" and (index == 0 or source[index - 1] != "\\")
    )


def gfm_header_column_count(source: str) -> int | None:
    """Return the GFM header cell count, including raw code-looking pipes."""
    body = source.strip()
    if "|" not in body:
        return None
    pipe_offsets = gfm_unescaped_pipe_offsets(body)
    cells: list[str] = []
    start = 0
    for offset in pipe_offsets:
        cells.append(body[start:offset])
        start = offset + 1
    cells.append(body[start:])
    if cells and not cells[0]:
        cells.pop(0)
    if cells and not cells[-1]:
        cells.pop()
    return len(cells) or None


def gfm_delimiter_column_count(source: str) -> int | None:
    """Return the GFM delimiter cell count for a syntactically valid row."""
    body = source.strip()
    if len(body) < 2 or any(character not in "|-: \t" for character in body):
        return None
    if body[0] == "-" and body[1] in " \t":
        return None
    cells = body.split("|")
    if cells and not cells[0].strip():
        cells.pop(0)
    if cells and not cells[-1].strip():
        cells.pop()
    if not cells or any(
        re.fullmatch(r":?-+:?", cell.strip()) is None for cell in cells
    ):
        return None
    return len(cells)


def gfm_table_indentation_is_valid(header: str, delimiter: str) -> bool:
    """Reject code-indented rows in the current block container."""
    header_spaces = len(header) - len(header.lstrip(" "))
    delimiter_spaces = len(delimiter) - len(delimiter.lstrip(" "))
    return header_spaces < 4 and delimiter_spaces < 4


def markdown_table_block_terminator(line: str) -> bool:
    """Mirror the GFM table rule's fence/quote/hr/list/HTML/heading terminators."""
    content = line.rstrip("\r\n")
    if len(content) - len(content.lstrip(" ")) >= 4:
        return True
    if markdown_fence_opening(content) is not None:
        return True
    _, container = markdown_fence_opening_content(content)
    if container:
        return True
    if re.match(r"^ {0,3}#{1,6}(?:[ \t]+|$)", content):
        return True
    if re.fullmatch(
        r" {0,3}(?:(?:\*[ \t]*){3,}|(?:_[ \t]*){3,}|(?:-[ \t]*){3,})",
        content,
    ):
        return True
    if MARKDOWN_HTML_BLOCK_RE.match(content):
        return True
    return re.match(r"^ {0,3}<(?:!--|\?|![A-Z]|!\[CDATA\[)", content) is not None


def markdown_inherited_list_indents(lines: list[str]) -> tuple[tuple[int, int], ...]:
    """Return each line's proven quote depth and active list content indent."""
    stacks: dict[int, list[int]] = {}
    blank_before: dict[int, bool] = {}
    pending_partial_dedent: dict[int, int] = {}
    inherited: list[tuple[int, int]] = []

    for raw_line in lines:
        raw = raw_line.rstrip("\r\n")
        view = markdown_quote_content(raw)
        if view is None:
            inherited.append((MAX_MARKDOWN_NESTING + 1, 0))
            continue
        content, _, quote_depth, content_column = view
        stack = stacks.setdefault(quote_depth, [])
        if not content.strip(" \t"):
            inherited.append((quote_depth, stack[-1] if stack else 0))
            blank_before[quote_depth] = True
            pending_partial_dedent.pop(quote_depth, None)
            continue

        raw_indent, leading_columns = markdown_leading_indentation(
            content, content_column
        )
        parent_indent = max(
            (indent for indent in (0, *stack) if indent <= leading_columns),
            default=0,
        )
        marker_widths = (
            markdown_list_content_widths(
                content[raw_indent:], content_column + leading_columns
            )
            if leading_columns - parent_indent <= 3
            else ()
        )

        if marker_widths:
            pending_partial_dedent.pop(quote_depth, None)
            while stack and stack[-1] > parent_indent:
                stack.pop()
            content_indent = parent_indent + (leading_columns - parent_indent)
            for width in marker_widths:
                content_indent += width
                if not stack or stack[-1] != content_indent:
                    stack.append(content_indent)
                require(
                    len(stack) <= MAX_MARKDOWN_NESTING,
                    "Markdown table list nesting exceeds bound",
                )
            line_indent = stack[-2] if len(stack) > 1 else 0
        else:
            prior_partial_dedent = pending_partial_dedent.pop(quote_depth, None)
            lazy_continuation = False
            if stack and leading_columns < stack[-1]:
                lazy_continuation = (
                    not blank_before.get(quote_depth, False)
                    and not markdown_inline_block_boundary(content)
                )
                if not lazy_continuation:
                    while stack and leading_columns < stack[-1]:
                        stack.pop()
                else:
                    # Keep the deepest item as a possible lazy paragraph owner,
                    # while carrying the proven outer indent to the immediately
                    # following delimiter row of a possible table pair.
                    line_indent = max(
                        (indent for indent in stack if indent <= leading_columns),
                        default=0,
                    )
                    pending_partial_dedent[quote_depth] = line_indent
            if not lazy_continuation:
                line_indent = (
                    prior_partial_dedent
                    if prior_partial_dedent is not None
                    and prior_partial_dedent <= leading_columns
                    else max(
                        (indent for indent in stack if indent <= leading_columns),
                        default=0,
                    )
                )

        inherited.append((quote_depth, line_indent))
        blank_before[quote_depth] = False

    return tuple(inherited)


@lru_cache(maxsize=8)
def markdown_table_inline_boundary_offsets(source: str) -> frozenset[int]:
    """Return GFM table row/cell ownership boundaries in one bounded source pass."""
    require(
        len(source) <= MAX_HTML_DOCUMENT_CHARS,
        "document exceeds Markdown/HTML parser bound",
    )
    lines = source.splitlines(keepends=True)
    starts: list[int] = []
    offset = 0
    for line in lines:
        starts.append(offset)
        offset += len(line)
    inherited_list_indents = markdown_inherited_list_indents(lines)

    boundaries: set[int] = set()

    def line_view(
        line_number: int,
        quote_depth: int | None,
        list_container: FenceContainer = (),
        inherited_list_indent: int = 0,
        *,
        list_opening: bool = False,
        allow_lazy_dedent: bool = False,
    ) -> tuple[str, int] | None:
        raw = lines[line_number].rstrip("\r\n")
        view = markdown_quote_content(raw, quote_depth)
        if view is None:
            return None
        content, prefix_width, _, content_column = view
        remove_columns = inherited_list_indent
        if allow_lazy_dedent and inherited_list_indent:
            _, available_columns = markdown_leading_indentation(
                content, content_column
            )
            remove_columns = min(remove_columns, available_columns)
        normalized = markdown_normalized_indentation_view(
            content, content_column, remove_columns
        )
        if normalized is None:
            return None
        content, raw_indent_width = normalized
        prefix_width += raw_indent_width
        if list_container:
            if list_opening:
                continued, observed_container = markdown_fence_opening_content(content)
                if observed_container != list_container:
                    return None
            else:
                continued = markdown_fence_continuation_content(content, list_container)
            if continued is None:
                return None
            content = continued
        return content, starts[line_number] + prefix_width

    def add_row(
        line_number: int,
        quote_depth: int,
        list_container: FenceContainer,
        inherited_list_indent: int,
        *,
        list_opening: bool = False,
        allow_lazy_dedent: bool = False,
    ) -> None:
        view = line_view(
            line_number,
            quote_depth,
            list_container,
            inherited_list_indent,
            list_opening=list_opening,
            allow_lazy_dedent=allow_lazy_dedent,
        )
        if view is None:
            return
        content, content_start = view
        boundaries.add(content_start)
        boundaries.update(
            starts[line_number] + pipe
            for pipe in gfm_unescaped_pipe_offsets(
                lines[line_number].rstrip("\r\n")
            )
        )

    line_number = 0
    while line_number + 1 < len(lines):
        raw_header = lines[line_number].rstrip("\r\n")
        raw_delimiter = lines[line_number + 1].rstrip("\r\n")
        header_all = markdown_quote_content(raw_header)
        delimiter_all = markdown_quote_content(raw_delimiter)
        if header_all is None or delimiter_all is None:
            line_number += 1
            continue
        selected_context: tuple[int, FenceContainer, int] | None = None
        for candidate_depth in range(
            min(header_all[2], delimiter_all[2]), -1, -1
        ):
            header_view = line_view(line_number, candidate_depth)
            delimiter_view = line_view(line_number + 1, candidate_depth)
            if header_view is None or delimiter_view is None:
                continue
            header, _ = header_view
            delimiter, _ = delimiter_view
            candidates: list[tuple[str, str, FenceContainer, int]] = [
                (header, delimiter, (), 0)
            ]
            header_quote_depth, header_list_indent = inherited_list_indents[
                line_number
            ]
            delimiter_quote_depth, delimiter_list_indent = inherited_list_indents[
                line_number + 1
            ]
            if (
                candidate_depth == header_quote_depth == delimiter_quote_depth
                and header_list_indent > 0
                and header_list_indent == delimiter_list_indent
            ):
                inherited_header_view = line_view(
                    line_number,
                    candidate_depth,
                    inherited_list_indent=header_list_indent,
                )
                inherited_delimiter_view = line_view(
                    line_number + 1,
                    candidate_depth,
                    inherited_list_indent=header_list_indent,
                )
                if (
                    inherited_header_view is not None
                    and inherited_delimiter_view is not None
                ):
                    candidates.insert(
                        0,
                        (
                            inherited_header_view[0],
                            inherited_delimiter_view[0],
                            (),
                            header_list_indent,
                        )
                    )
            list_header, list_container = markdown_fence_opening_content(header)
            if list_container and any(kind == "list" for kind, _ in list_container):
                require(
                    len(list_container) <= MAX_MARKDOWN_NESTING,
                    "Markdown table list nesting exceeds bound",
                )
                list_delimiter = markdown_fence_continuation_content(
                    delimiter, list_container
                )
                if list_delimiter is not None:
                    candidates.append(
                        (list_header, list_delimiter, list_container, 0)
                    )
            for (
                candidate_header,
                candidate_delimiter,
                list_context,
                inherited_list_indent,
            ) in candidates:
                header_columns = gfm_header_column_count(candidate_header)
                delimiter_columns = gfm_delimiter_column_count(candidate_delimiter)
                if (
                    header_columns is not None
                    and header_columns == delimiter_columns
                    and gfm_table_indentation_is_valid(
                        candidate_header, candidate_delimiter
                    )
                ):
                    selected_context = (
                        candidate_depth,
                        list_context,
                        inherited_list_indent,
                    )
                    break
            if selected_context is not None:
                break
        if selected_context is None:
            line_number += 1
            continue
        quote_depth, list_container, inherited_list_indent = selected_context

        add_row(
            line_number,
            quote_depth,
            list_container,
            inherited_list_indent,
            list_opening=bool(list_container),
        )
        add_row(
            line_number + 1,
            quote_depth,
            list_container,
            inherited_list_indent,
        )
        cursor = line_number + 2
        while cursor < len(lines):
            row_view = line_view(
                cursor,
                quote_depth,
                list_container,
                inherited_list_indent,
                allow_lazy_dedent=True,
            )
            if row_view is None:
                break
            row, _ = row_view
            if not row.strip() or markdown_table_block_terminator(row):
                break
            add_row(
                cursor,
                quote_depth,
                list_container,
                inherited_list_indent,
                allow_lazy_dedent=True,
            )
            cursor += 1
        if cursor < len(lines):
            boundaries.add(starts[cursor])
        line_number = max(cursor, line_number + 2)

    return frozenset(boundaries)


@lru_cache(maxsize=8)
def markdown_inline_ownership_boundary_offsets(source: str) -> frozenset[int]:
    """Return every block, table-row, and table-cell inline ownership boundary."""
    return markdown_inline_block_boundary_offsets(source) | markdown_table_inline_boundary_offsets(
        source
    )


def markdown_escape_flags(source: str) -> tuple[bool, ...]:
    """Mark characters preceded by an odd-length backslash run."""
    escaped: list[bool] = []
    preceding_backslashes = 0
    for character in source:
        escaped.append(preceding_backslashes % 2 == 1)
        preceding_backslashes = (
            preceding_backslashes + 1 if character == "\\" else 0
        )
    return tuple(escaped)


def noncrossing_markdown_code_spans(
    source: str, eligible: tuple[bool, ...] | None = None
) -> tuple[tuple[int, int, int], ...]:
    """Pair next equal-width backtick runs without crossing inline blocks."""
    if eligible is None:
        eligible = (True,) * len(source)
    require(
        len(eligible) == len(source),
        "Markdown code ownership length mismatch",
    )
    escaped = markdown_escape_flags(source)
    block_boundaries = markdown_inline_ownership_boundary_offsets(source)
    tokens: list[tuple[int, int, int, int, int, int]] = []
    block = 0
    index = 0
    while index < len(source):
        if index in block_boundaries:
            block += 1
        if source[index] != "`" or not eligible[index]:
            index += 1
            continue
        end = index + 1
        while end < len(source) and source[end] == "`" and eligible[end]:
            end += 1
        raw_width = end - index
        opening_start = index + 1 if escaped[index] else index
        opening_width = raw_width - 1 if escaped[index] else raw_width
        tokens.append(
            (index, end, raw_width, block, opening_start, opening_width)
        )
        index = end

    next_closing: list[int | None] = [None] * len(tokens)
    latest: dict[tuple[int, int], int] = {}
    for token_index in range(len(tokens) - 1, -1, -1):
        _, _, raw_width, token_block, _, opening_width = tokens[token_index]
        if opening_width:
            next_closing[token_index] = latest.get((token_block, opening_width))
        latest[(token_block, raw_width)] = token_index

    spans: list[tuple[int, int, int]] = []
    token_index = 0
    while token_index < len(tokens):
        closing_index = next_closing[token_index]
        if closing_index is None:
            token_index += 1
            continue
        _, _, _, _, opening_start, opening_width = tokens[token_index]
        spans.append(
            (opening_start, tokens[closing_index][1], opening_width)
        )
        token_index = closing_index + 1
    return tuple(spans)


@lru_cache(maxsize=8)
def markdown_fenced_line_numbers(source: str) -> frozenset[int]:
    """Return lines in valid bounded GFM fences, including supported containers."""
    require(
        len(source) <= MAX_HTML_DOCUMENT_CHARS,
        "document exceeds Markdown/HTML parser bound",
    )
    fenced: set[int] = set()
    active: tuple[str, int, FenceContainer] | None = None
    for line_number, line in enumerate(source.splitlines()):
        if active is not None:
            character, width, container = active
            content = markdown_fence_continuation_content(line, container)
            if content is not None:
                fenced.add(line_number)
                if re.fullmatch(
                    rf" {{0,3}}{re.escape(character)}{{{width},}}[ \t]*",
                    content,
                ):
                    active = None
                continue
            if not container and not line.strip():
                fenced.add(line_number)
                continue
            active = None
        opening = markdown_fence_opening(line)
        if opening is not None:
            active = opening
            fenced.add(line_number)
    return frozenset(fenced)


def _markdown_code_literal_source(source: str) -> str:
    """Mask fenced/inline code while preserving offsets and raw HTML across source lines."""
    masked = list(source)
    fenced_lines = markdown_fenced_line_numbers(source)
    fenced_positions: set[int] = set()
    offset = 0
    for line_number, line in enumerate(source.splitlines(keepends=True)):
        if line_number in fenced_lines:
            fenced_positions.update(range(offset, offset + len(line)))
        offset += len(line)

    for index in fenced_positions:
        if masked[index] not in "\r\n":
            masked[index] = " "

    eligible = tuple(index not in fenced_positions for index in range(len(source)))
    for start, end, _ in noncrossing_markdown_code_spans(source, eligible):
        for position in range(start, end):
            if source[position] not in "\r\n":
                masked[position] = " "
    return "".join(masked)


def _markdown_html_channels(source: str) -> tuple[str, str, str]:
    """Return raw-HTML, HTML-render, and visible-literal offset provenance."""
    code_source = _markdown_code_literal_source(source)
    length = len(source)
    escaped = [False] * length
    preceding_backslashes = 0
    for index, character in enumerate(source):
        escaped[index] = preceding_backslashes % 2 == 1
        preceding_backslashes = (
            preceding_backslashes + 1 if character == "\\" else 0
        )

    literal = [
        code_source[index] == " " and character not in " \t\r\n"
        for index, character in enumerate(source)
    ]
    nonrendered = [False] * length
    autolink_delimiters: set[int] = set()
    block_boundary_offsets = markdown_inline_ownership_boundary_offsets(source)

    def crosses_inline_block(cursor: int, opening: int) -> bool:
        return cursor > opening and cursor in block_boundary_offsets

    def skip_inline_whitespace(cursor: int, opening: int) -> int | None:
        while cursor < length and source[cursor] in " \t\r\n":
            cursor += 1
            if crosses_inline_block(cursor, opening):
                return None
        return cursor

    def destination_end(opening: int) -> int | None:
        cursor = opening + 1
        if cursor >= length:
            return None
        if source[cursor] == ")":
            return cursor

        if source[cursor] == "<" and not escaped[cursor]:
            cursor += 1
            while cursor < length:
                character = source[cursor]
                if character in "\r\n" or crosses_inline_block(cursor, opening):
                    return None
                if escaped[cursor]:
                    cursor += 1
                    continue
                if character == "<":
                    return None
                if character == ">":
                    cursor += 1
                    break
                cursor += 1
            else:
                return None
        else:
            depth = 0
            while cursor < length:
                character = source[cursor]
                if character in "\r\n":
                    return None
                if escaped[cursor]:
                    cursor += 1
                    continue
                if character in " \t":
                    break
                if character in "<>\"'":
                    return None
                if character == "(":
                    depth += 1
                    require(
                        depth <= MAX_MARKDOWN_NESTING,
                        "definition Markdown destination nesting exceeds bound",
                    )
                elif character == ")":
                    if depth == 0:
                        return cursor
                    depth -= 1
                cursor += 1
            if depth != 0:
                return None

        separator_start = cursor
        whitespace_end = skip_inline_whitespace(cursor, opening)
        if whitespace_end is None or whitespace_end >= length:
            return None
        cursor = whitespace_end
        if source[cursor] == ")":
            return cursor
        if cursor == separator_start:
            return None
        title_open = source[cursor]
        if title_open not in {'"', "'", "("} or escaped[cursor]:
            return None
        title_close = ")" if title_open == "(" else title_open
        cursor += 1
        while cursor < length:
            if crosses_inline_block(cursor, opening):
                return None
            if escaped[cursor]:
                cursor += 1
                continue
            if source[cursor] == title_close:
                cursor += 1
                break
            if title_open == "(" and source[cursor] == "(":
                return None
            cursor += 1
        else:
            return None
        whitespace_end = skip_inline_whitespace(cursor, opening)
        if whitespace_end is None or whitespace_end >= length:
            return None
        return whitespace_end if source[whitespace_end] == ")" else None

    square_depth = 0
    image_label_starts: list[int | None] = []
    index = 0
    while index < length:
        if index in block_boundary_offsets:
            square_depth = 0
            image_label_starts.clear()
        if literal[index] or nonrendered[index]:
            index += 1
            continue
        character = source[index]
        if not escaped[index] and character == "[":
            square_depth += 1
            require(
                square_depth <= MAX_MARKDOWN_NESTING,
                "definition Markdown label nesting exceeds bound",
            )
            image_label_starts.append(
                index
                if index > 0 and source[index - 1] == "!" and not escaped[index - 1]
                else None
            )
        elif not escaped[index] and character == "]" and square_depth > 0:
            image_start = image_label_starts.pop()
            square_depth -= 1
            if image_start is not None:
                for position in range(image_start + 1, index):
                    if source[position] in "<>":
                        literal[position] = True
            if square_depth == 0 and index + 1 < length:
                opening = index + 1
                closing: int | None = None
                if source[opening] == "(":
                    closing = destination_end(opening)
                if closing is not None:
                    for position in range(opening, closing + 1):
                        nonrendered[position] = True
                    index = closing
        index += 1

    index = 0
    while index < length:
        if (
            source[index] == "<"
            and not escaped[index]
            and not literal[index]
            and not nonrendered[index]
        ):
            match = MARKDOWN_AUTOLINK_RE.match(source, index)
            if match is not None:
                for position in range(index, match.end()):
                    literal[position] = True
                autolink_delimiters.update((index, match.end() - 1))
                index = match.end()
                continue
        index += 1

    pending_tag_open: int | None = None
    for index, character in enumerate(source):
        if character in "\r\n":
            pending_tag_open = None
            continue
        if nonrendered[index] or literal[index]:
            continue
        if character == "<":
            if escaped[index]:
                literal[index] = True
                pending_tag_open = None
            else:
                pending_tag_open = index
        elif character == ">":
            if escaped[index]:
                literal[index] = True
                if pending_tag_open is not None:
                    literal[pending_tag_open] = True
            pending_tag_open = None

    raw_html: list[str] = list(source)
    html_render: list[str] = list(source)
    visible_literal = [" "] * length
    for index, character in enumerate(source):
        if character in "\r\n":
            visible_literal[index] = character
            continue
        if nonrendered[index]:
            raw_html[index] = " "
            html_render[index] = " "
            continue
        if literal[index]:
            raw_html[index] = " "
            visible_literal[index] = character
            if index in autolink_delimiters:
                html_render[index] = " "
            elif character == "<":
                html_render[index] = "&lt;"
            elif character == ">":
                html_render[index] = "&gt;"
    return "".join(raw_html), "".join(html_render), "".join(visible_literal)


@lru_cache(maxsize=16_384)
def _cached_markdown_html_channels(source: str) -> tuple[str, str, str]:
    return _markdown_html_channels(source)


def markdown_html_channels(source: str) -> tuple[str, str, str]:
    """Cache bounded candidates, but never retain whole mutated documents."""
    if len(source) <= MAX_DEFINITION_LINE_CHARS:
        return _cached_markdown_html_channels(source)
    return _markdown_html_channels(source)


def markdown_html_validation_source(source: str) -> str:
    return markdown_html_channels(source)[0]


def markdown_html_render_source(source: str) -> str:
    return markdown_html_channels(source)[1]


class DefinitionHTMLText(HTMLParser):
    """Extract bounded visible runs without executing or resolving anything."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.parts: list[str] = []
        self.stack: list[tuple[str, bool]] = []
        self.runs: list[tuple[str | None, str, bool]] = []
        self.current_run: list[str] = []
        self.current_tag: str | None = None
        self.current_candidate = False
        self.boundary_pending = False
        self.hidden_depth = 0
        self.hidden_markup_seen = False
        self.unsafe_visibility = False
        self.incomplete_markup = False
        self.work = 0
        self.max_depth = 0

    def structural_context(self) -> str | None:
        return next(
            (
                tag
                for tag, hidden in reversed(self.stack)
                if tag in HTML_STRUCTURAL_ELEMENTS and not hidden
            ),
            None,
        )

    def flush_run(self) -> None:
        if not self.current_run:
            return
        self.runs.append(
            (self.current_tag, "".join(self.current_run), self.current_candidate)
        )
        self.current_run.clear()
        self.current_tag = None
        self.current_candidate = False

    def rendered_boundary(self) -> None:
        self.flush_run()
        self.parts.append(" ")
        self.boundary_pending = True

    def append_visible(self, value: str) -> None:
        self.parts.append(value)
        for piece in re.split(r"(\r\n|\r|\n)", value):
            if not piece:
                continue
            if piece in {"\r", "\n", "\r\n"}:
                self.flush_run()
                continue
            if not self.current_run:
                self.current_tag = self.structural_context()
                self.current_candidate = (
                    self.boundary_pending or self.current_tag is not None
                )
                self.boundary_pending = False
            self.current_run.append(piece)

    def add_work(self, amount: int) -> None:
        self.work += amount

    @staticmethod
    def element_hidden(tag: str, attributes: list[tuple[str, str | None]]) -> bool:
        values = {name.casefold(): value for name, value in attributes}
        aria_hidden = values.get("aria-hidden")
        return (
            tag in HTML_HIDDEN_ELEMENTS
            or "hidden" in values
            or (isinstance(aria_hidden, str) and aria_hidden.casefold() == "true")
        )

    def handle_starttag(
        self, tag: str, attributes: list[tuple[str, str | None]]
    ) -> None:
        raw_tag = self.get_starttag_text()
        if raw_tag is not None:
            self.add_work(len(raw_tag))
        if raw_tag is not None and MARKDOWN_AUTOLINK_RE.fullmatch(raw_tag):
            self.append_visible(raw_tag[1:-1])
            return
        if raw_tag is not None and ("\n" in raw_tag or "\r" in raw_tag):
            self.unsafe_visibility = True
        tag = tag.casefold()
        normalized_attribute_names = [name.casefold() for name, _ in attributes]
        attribute_names = set(normalized_attribute_names)
        attribute_values = {
            name.casefold(): value.casefold() if isinstance(value, str) else value
            for name, value in attributes
        }
        if (
            len(normalized_attribute_names) != len(attribute_names)
            or tag == "style"
            or tag not in HTML_MODELED_ELEMENTS
            or tag in HTML_CONTEXTUAL_VISIBILITY_ELEMENTS
            or bool(attribute_names & {"class", "dir", "id", "popover", "style"})
            or (
                tag == "link"
                and isinstance(attribute_values.get("rel"), str)
                and "stylesheet" in attribute_values["rel"].split()
            )
        ):
            self.unsafe_visibility = True
        hidden = self.element_hidden(tag, attributes)
        self.hidden_markup_seen = self.hidden_markup_seen or hidden
        if tag in HTML_BREAK_ELEMENTS and self.hidden_depth == 0:
            self.rendered_boundary()
        if tag in HTML_STRUCTURAL_ELEMENTS and self.hidden_depth == 0 and not hidden:
            self.rendered_boundary()
        if tag == "img" and self.hidden_depth == 0 and not hidden:
            alt = next(
                (value for name, value in attributes if name.casefold() == "alt"),
                None,
            )
            if alt is not None:
                self.append_visible(alt)
        if tag not in HTML_VOID_ELEMENTS:
            self.stack.append((tag, hidden))
            self.max_depth = max(self.max_depth, len(self.stack))
            if hidden:
                self.hidden_depth += 1

    def handle_startendtag(
        self, tag: str, attributes: list[tuple[str, str | None]]
    ) -> None:
        raw_tag = self.get_starttag_text()
        if raw_tag is not None and MARKDOWN_AUTOLINK_RE.fullmatch(raw_tag):
            self.append_visible(raw_tag[1:-1])
            return
        self.handle_starttag(tag, attributes)
        if tag.casefold() not in HTML_VOID_ELEMENTS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.casefold()
        self.add_work(len(tag) + 3)
        if not self.stack or self.stack[-1][0] != tag:
            self.unsafe_visibility = True
            return
        _, hidden = self.stack.pop()
        visible_before_pop = self.hidden_depth == 0
        if hidden:
            self.hidden_depth -= 1
        if tag in HTML_STRUCTURAL_ELEMENTS and visible_before_pop:
            self.rendered_boundary()

    def handle_data(self, data: str) -> None:
        self.add_work(len(data))
        if re.search(r"<(?:/?[A-Za-z]|!--|!\[CDATA\[|![A-Z]|\?)", data):
            self.unsafe_visibility = True
        if self.hidden_depth == 0:
            self.append_visible(data)
        elif "\n" in data or "\r" in data:
            self.unsafe_visibility = True

    def handle_comment(self, data: str) -> None:
        self.add_work(len(data) + 7)
        if "\n" in data or "\r" in data:
            self.unsafe_visibility = True

    def handle_decl(self, decl: str) -> None:
        self.add_work(len(decl) + 3)
        if "\n" in decl or "\r" in decl:
            self.unsafe_visibility = True

    def unknown_decl(self, data: str) -> None:
        self.add_work(len(data) + 4)
        if "\n" in data or "\r" in data:
            self.unsafe_visibility = True

    def handle_pi(self, data: str) -> None:
        self.add_work(len(data) + 4)
        if "\n" in data or "\r" in data:
            self.unsafe_visibility = True

    def handle_entityref(self, name: str) -> None:
        self.add_work(len(name) + 2)
        if self.hidden_depth == 0:
            self.append_visible(html.unescape(f"&{name};"))

    def handle_charref(self, name: str) -> None:
        self.add_work(len(name) + 3)
        if self.hidden_depth == 0:
            self.append_visible(html.unescape(f"&#{name};"))

    def finish_runs(self) -> None:
        self.flush_run()


def parse_rendered_definition_html(rendered_source: str) -> DefinitionHTMLText:
    """Validate and parse an already tokenized Markdown/HTML render channel."""
    parser = DefinitionHTMLText()
    try:
        parser.feed(rendered_source)
        parser.incomplete_markup = re.search(
            r"<(?:/?[A-Za-z]|!--|!\[CDATA\[|![A-Z]|\?)",
            parser.rawdata,
        ) is not None
        parser.close()
        parser.finish_runs()
    except (AssertionError, ValueError) as error:
        fail(f"raw HTML visibility parse failed: {error}")
    require(
        not parser.incomplete_markup,
        "raw HTML contains incomplete markup",
    )
    require(
        not parser.unsafe_visibility,
        "raw HTML uses unsupported rendering-affecting markup",
    )
    require(
        not parser.stack,
        "raw HTML contains an unclosed modeled element",
    )
    require(
        parser.max_depth <= MAX_HTML_NESTING,
        "raw HTML nesting exceeds bound",
    )
    require(
        parser.work <= MAX_HTML_WORK_FACTOR * len(rendered_source),
        "raw HTML scanner exceeded linear work bound",
    )
    return parser


def parse_definition_html(source: str) -> DefinitionHTMLText:
    require(
        len(source) <= MAX_HTML_DOCUMENT_CHARS,
        "document exceeds Markdown/HTML parser bound",
    )
    return parse_rendered_definition_html(markdown_html_render_source(source))


@lru_cache(maxsize=16_384)
def html_visible_text(source: str) -> str:
    parser = parse_definition_html(source)
    return "".join(parser.parts)


@lru_cache(maxsize=8)
def html_boundary_visible_texts(source: str) -> tuple[tuple[str | None, str], ...]:
    parser = parse_definition_html(source)
    return tuple((tag, text) for tag, text, candidate in parser.runs if candidate)


def html_visible_runs_with_work(
    source: str,
) -> tuple[tuple[tuple[str | None, str, bool], ...], int, int]:
    """Expose bounded-run, work, and depth evidence for deterministic tests."""
    parser = parse_definition_html(source)
    return tuple(parser.runs), parser.work, parser.max_depth


def default_ignorable(character: str) -> bool:
    return ord(character) in DEFAULT_IGNORABLE_CODEPOINTS


def markdown_visible_labels_with_work(source: str) -> tuple[str, int]:
    """Extract label/alt text in one bounded forward pass and report examined characters."""
    visible: list[str] = []
    index = 0
    work = 0
    preceding_backslashes = 0
    square_depth = 0
    mode = "visible"
    destination_depth = 0
    reference_depth = 0
    quote: str | None = None
    angle = False
    while index < len(source):
        character = source[index]
        work += 1
        escaped = preceding_backslashes % 2 == 1

        if mode == "destination":
            if escaped:
                pass
            elif quote is not None:
                if character == quote:
                    quote = None
            elif angle:
                if character == ">":
                    angle = False
            elif character in {'"', "'"}:
                quote = character
            elif character == "<":
                angle = True
            elif character == "(":
                destination_depth += 1
                require(
                    destination_depth <= MAX_MARKDOWN_NESTING,
                    "definition Markdown destination nesting exceeds bound",
                )
            elif character == ")":
                destination_depth -= 1
                if destination_depth == 0:
                    mode = "visible"
            preceding_backslashes = (
                preceding_backslashes + 1 if character == "\\" else 0
            )
            index += 1
            continue

        if mode == "reference":
            if not escaped and character == "[":
                reference_depth += 1
                require(
                    reference_depth <= MAX_MARKDOWN_NESTING,
                    "definition Markdown reference nesting exceeds bound",
                )
            elif not escaped and character == "]":
                reference_depth -= 1
                if reference_depth == 0:
                    mode = "visible"
            preceding_backslashes = (
                preceding_backslashes + 1 if character == "\\" else 0
            )
            index += 1
            continue

        if (
            not escaped
            and character == "!"
            and index + 1 < len(source)
            and source[index + 1] == "["
        ):
            preceding_backslashes = 0
            index += 1
            continue
        if not escaped and character == "[":
            square_depth += 1
            require(
                square_depth <= MAX_MARKDOWN_NESTING,
                "definition Markdown label nesting exceeds bound",
            )
            preceding_backslashes = 0
            index += 1
            continue
        if not escaped and character == "]" and square_depth > 0:
            square_depth -= 1
            next_character = source[index + 1 : index + 2]
            if next_character == "(":
                mode = "destination"
                destination_depth = 1
                quote = None
                angle = False
                index += 2
                work += 1
            elif next_character == "[":
                mode = "reference"
                reference_depth = 1
                index += 2
                work += 1
            else:
                index += 1
            preceding_backslashes = 0
            continue
        visible.append(character)
        if character == "\\":
            preceding_backslashes += 1
        else:
            preceding_backslashes = 0
        index += 1
    require(work <= len(source), "definition Markdown scanner exceeded linear work bound")
    return "".join(visible), work


def markdown_visible_labels(source: str) -> str:
    return markdown_visible_labels_with_work(source)[0]


@lru_cache(maxsize=16_384)
def rendered_definition_text(source: str) -> str:
    """Conservatively approximate visible bounded Markdown/HTML definition text."""
    require(
        len(source) <= MAX_DEFINITION_RENDER_CHARS,
        "rendered definition candidate exceeds expansion bound",
    )
    rendered = unicodedata.normalize("NFKC", html_visible_text(source))
    require(
        len(rendered) <= MAX_NORMALIZED_DEFINITION_CHARS,
        "normalized definition candidate exceeds expansion bound",
    )
    rendered = "".join(
        character
        for character in rendered
        if not default_ignorable(character)
        and unicodedata.category(character)[0] not in {"C", "M"}
    )
    rendered = markdown_visible_labels(rendered)
    rendered = render_matched_markdown_syntax(rendered)
    return rendered.strip()


def leading_rendered_definition_identifier(
    rendered: str, *, require_separator: bool, allow_colon: bool = False
) -> str | None:
    match = re.match(rf"^({DEFINITION_ID_RE.pattern})\b", rendered)
    if match is None:
        return None
    if not require_separator:
        return match.group(1)
    remainder = rendered[match.end() :].lstrip()
    separators = ("—", ".", ":") if allow_colon else ("—", ".")
    return match.group(1) if remainder.startswith(separators) else None


def leading_definition_identifier(
    source: str, *, require_separator: bool, allow_colon: bool = False
) -> str | None:
    return leading_rendered_definition_identifier(
        rendered_definition_text(source),
        require_separator=require_separator,
        allow_colon=allow_colon,
    )


def html_definition_candidates_from_parser(parser: DefinitionHTMLText) -> set[str]:
    candidates: set[str] = set()
    for tag, segment, is_candidate in parser.runs:
        if not is_candidate:
            continue
        candidate = leading_definition_identifier(
            segment,
            require_separator=tag not in {"td", "th"},
            allow_colon=True,
        )
        if candidate is not None:
            candidates.add(candidate)
    return candidates


def html_definition_candidates(source: str) -> set[str]:
    return html_definition_candidates_from_parser(parse_definition_html(source))


def structural_prefixes_with_work(source: str) -> tuple[str, bool, bool, int]:
    """Strip bounded Markdown structural prefixes in one indexed forward scan."""
    position = 0
    depth = 0
    structural = False
    list_item = False
    examined_through = 0

    def skip_whitespace(index: int) -> int:
        while index < len(source) and source[index].isspace():
            index += 1
        return index

    while position < len(source):
        cursor = position
        matched = False
        current_is_list = False
        character = source[cursor]
        examined_through = max(examined_through, cursor + 1)

        if character == ">":
            cursor = skip_whitespace(cursor + 1)
            matched = True
        elif character == "#":
            while cursor < len(source) and source[cursor] == "#":
                cursor += 1
            heading_width = cursor - position
            if (
                1 <= heading_width <= 6
                and cursor < len(source)
                and source[cursor].isspace()
            ):
                cursor = skip_whitespace(cursor)
                matched = True
        elif character in "-*+":
            cursor += 1
            if cursor < len(source) and source[cursor].isspace():
                cursor = skip_whitespace(cursor)
                matched = True
                current_is_list = True
        elif character.isascii() and character.isdigit():
            while (
                cursor < len(source)
                and source[cursor].isascii()
                and source[cursor].isdigit()
            ):
                cursor += 1
            if (
                cursor < len(source)
                and source[cursor] in ".)"
                and cursor + 1 < len(source)
                and source[cursor + 1].isspace()
            ):
                cursor = skip_whitespace(cursor + 1)
                matched = True
                current_is_list = True

        examined_through = max(examined_through, cursor)
        if not matched:
            break
        depth += 1
        require(
            depth <= MAX_MARKDOWN_NESTING,
            "definition structural-prefix nesting exceeds bound",
        )
        structural = True
        list_item = list_item or current_is_list
        position = cursor

    require(
        examined_through <= len(source),
        "definition structural-prefix scanner exceeded linear work bound",
    )
    return source[position:], structural, list_item, examined_through


def definition_candidates(
    line: str,
    following_line: str = "",
    *,
    source_line_length: int | None = None,
) -> set[str]:
    """Return IDs presented with definition-like Markdown, regardless of document or form."""
    require(
        (len(line) if source_line_length is None else source_line_length)
        <= MAX_DEFINITION_LINE_CHARS,
        "definition candidate line exceeds parser bound",
    )
    reject_bidi_controls(line, "definition candidate line")
    candidates: set[str] = set()
    body = line.lstrip()
    body, structural, list_item, _ = structural_prefixes_with_work(body)
    if list_item:
        task_marker = re.match(r"^\[[ xX]\]\s+(.*)$", body)
        if task_marker is not None:
            body = task_marker.group(1).lstrip()

    if structural:
        raw_emphasis = re.match(
            rf"^(?:\*+|_+)(?={DEFINITION_ID_RE.pattern}\b)(.*)$",
            body,
        )
        if raw_emphasis is not None:
            candidate = leading_definition_identifier(
                raw_emphasis.group(1),
                require_separator=True,
                allow_colon=True,
            )
            if candidate is not None:
                candidates.add(candidate)

    escaped_code_open = re.match(r"^(\\+)`", body)
    escaped_code_close = re.search(r"(\\+)`$", body)
    if (
        escaped_code_open is not None
        and escaped_code_close is not None
        and len(escaped_code_open.group(1)) % 2 == 1
        and len(escaped_code_close.group(1)) % 2 == 1
        and escaped_code_open.end() <= escaped_code_close.start()
    ):
        inner = body[escaped_code_open.end() : escaped_code_close.start()]
        if parse_definition_html(inner).hidden_markup_seen:
            candidate = leading_definition_identifier(
                inner,
                require_separator=True,
                allow_colon=True,
            )
            if candidate is not None:
                candidates.add(candidate)

    cells = markdown_table_cells(body)
    if cells is not None and len(cells) >= 2:
        candidate = leading_definition_identifier(cells[0], require_separator=False)
        if candidate is not None:
            candidates.add(candidate)
    elif cells is not None and len(cells) == 1 and body.startswith("|") and body.endswith("|"):
        preceding_backslashes = 0
        cursor = len(body) - 2
        while cursor >= 0 and body[cursor] == "\\":
            preceding_backslashes += 1
            cursor -= 1
        table_source = markdown_html_validation_source(body)
        if (
            preceding_backslashes % 2 == 0
            and table_source[0] != " "
            and table_source[-1] != " "
        ):
            candidate = leading_definition_identifier(
                cells[0], require_separator=True, allow_colon=True
            )
            if candidate is not None:
                candidates.add(candidate)

    candidate = leading_definition_identifier(
        body, require_separator=True, allow_colon=True
    )
    if candidate is not None:
        candidates.add(candidate)

    if re.fullmatch(r"\s*(?:=+|-+)\s*", following_line):
        candidate = leading_definition_identifier(
            line.strip(), require_separator=True, allow_colon=True
        )
        if candidate is not None:
            candidates.add(candidate)

    candidates.update(html_definition_candidates(line))
    return candidates


TRAILING_RENDERED_STRONG_SEPARATOR_RE = re.compile(
    rf"(?<!\w)({DEFINITION_ID_RE.pattern})\b\s*(?:—|:)"
)


def markdown_delimiter_flanking(
    source: str, start: int, end: int
) -> tuple[bool, bool]:
    """Return CommonMark left/right-flanking status for one delimiter run."""
    before = source[start - 1] if start > 0 else "\n"
    after = source[end] if end < len(source) else "\n"
    before_whitespace = before.isspace()
    after_whitespace = after.isspace()
    before_punctuation = unicodedata.category(before)[0] in {"P", "S"}
    after_punctuation = unicodedata.category(after)[0] in {"P", "S"}
    left_flanking = not after_whitespace and (
        not after_punctuation or before_whitespace or before_punctuation
    )
    right_flanking = not before_whitespace and (
        not before_punctuation or after_whitespace or after_punctuation
    )
    return left_flanking, right_flanking


class MarkdownDelimiter:
    """One emphasis marker or one exact-width tilde delimiter run."""

    __slots__ = (
        "key",
        "length",
        "token",
        "marker_start",
        "marker_end",
        "run_start",
        "run_end",
        "end_index",
        "can_open",
        "can_close",
    )

    def __init__(
        self,
        *,
        key: tuple[str, int],
        length: int,
        token: int,
        marker_start: int,
        marker_end: int,
        run_start: int,
        run_end: int,
        can_open: bool,
        can_close: bool,
    ) -> None:
        self.key = key
        self.length = length
        self.token = token
        self.marker_start = marker_start
        self.marker_end = marker_end
        self.run_start = run_start
        self.run_end = run_end
        self.end_index = -1
        self.can_open = can_open
        self.can_close = can_close


def matched_markdown_syntax(
    source: str,
    code_spans: tuple[tuple[int, int, int], ...],
    eligible: tuple[bool, ...] | None = None,
) -> tuple[tuple[bool, ...], tuple[tuple[int, int], ...]]:
    """Return matched marker positions and noncrossing rendered wrapper spans."""
    if eligible is None:
        eligible = (True,) * len(source)
    require(
        len(eligible) == len(source),
        "Markdown delimiter ownership length mismatch",
    )
    escaped = markdown_escape_flags(source)
    code_owned = [False] * len(source)
    for start, end, _ in code_spans:
        for position in range(start, end):
            code_owned[position] = True

    delimiters: list[MarkdownDelimiter] = []
    index = 0
    while index < len(source):
        if code_owned[index] or escaped[index] or not eligible[index]:
            index += 1
            continue
        character = source[index]
        if character not in "*_~":
            index += 1
            continue
        end = index + 1
        while (
            end < len(source)
            and source[end] == character
            and not code_owned[end]
            and eligible[end]
        ):
            end += 1
        width = end - index
        if character == "~" and width > 2:
            index = end
            continue
        left_flanking, right_flanking = markdown_delimiter_flanking(
            source, index, end
        )
        if character == "_":
            before = source[index - 1] if index > 0 else "\n"
            after = source[end] if end < len(source) else "\n"
            can_open = left_flanking and (
                not right_flanking
                or unicodedata.category(before)[0] in {"P", "S"}
            )
            can_close = right_flanking and (
                not left_flanking or unicodedata.category(after)[0] in {"P", "S"}
            )
        else:
            can_open = left_flanking
            can_close = right_flanking

        if character in "*_":
            for position in range(index, end):
                delimiters.append(
                    MarkdownDelimiter(
                        key=(character, 0),
                        length=width,
                        token=position,
                        marker_start=position,
                        marker_end=position + 1,
                        run_start=index,
                        run_end=end,
                        can_open=can_open,
                        can_close=can_close,
                    )
                )
        else:
            delimiters.append(
                MarkdownDelimiter(
                    key=(character, width),
                    length=0,
                    token=index,
                    marker_start=index,
                    marker_end=end,
                    run_start=index,
                    run_end=end,
                    can_open=can_open,
                    can_close=can_close,
                )
            )
        index = end

    openers_bottom: dict[tuple[str, int], list[int]] = {}
    header_index = 0
    last_token = -2
    jumps: list[int] = []
    for closer_index, closer in enumerate(delimiters):
        jumps.append(0)
        if (
            delimiters[header_index].key != closer.key
            or last_token != closer.token - 1
        ):
            header_index = closer_index
        last_token = closer.token
        if not closer.can_close:
            continue

        lower_bounds = openers_bottom.setdefault(closer.key, [-1] * 6)
        lower_bound_slot = (3 if closer.can_open else 0) + (closer.length % 3)
        minimum_opener = lower_bounds[lower_bound_slot]
        opener_index = header_index - jumps[header_index] - 1
        new_minimum = opener_index
        while opener_index > minimum_opener:
            opener = delimiters[opener_index]
            if opener.key != closer.key:
                opener_index -= jumps[opener_index] + 1
                continue
            if opener.can_open and opener.end_index < 0:
                odd_match = (
                    bool(opener.length)
                    and (opener.can_close or closer.can_open)
                    and (opener.length + closer.length) % 3 == 0
                    and (
                        opener.length % 3 != 0 or closer.length % 3 != 0
                    )
                )
                if not odd_match:
                    last_jump = (
                        jumps[opener_index - 1] + 1
                        if opener_index > 0
                        and not delimiters[opener_index - 1].can_open
                        else 0
                    )
                    jumps[closer_index] = closer_index - opener_index + last_jump
                    jumps[opener_index] = last_jump
                    closer.can_open = False
                    opener.end_index = closer_index
                    opener.can_close = False
                    new_minimum = -1
                    last_token = -2
                    break
            opener_index -= jumps[opener_index] + 1
        if new_minimum != -1:
            lower_bounds[lower_bound_slot] = new_minimum

    syntax = [False] * len(source)
    wrapper_spans: list[tuple[int, int]] = []
    seen_spans: set[tuple[int, int]] = set()
    for opener in delimiters:
        if opener.end_index < 0:
            continue
        closer = delimiters[opener.end_index]
        for position in range(opener.marker_start, opener.marker_end):
            syntax[position] = True
        for position in range(closer.marker_start, closer.marker_end):
            syntax[position] = True
        span = (opener.run_start, closer.run_end)
        if span not in seen_spans:
            seen_spans.add(span)
            wrapper_spans.append(span)
    return tuple(syntax), tuple(wrapper_spans)


MARKDOWN_ESCAPABLE = frozenset("\\`*{}[]()#+.!_|>~-")


def render_matched_markdown_syntax(source: str) -> str:
    """Render code/emphasis markers while preserving every unmatched visible byte."""
    escaped = markdown_escape_flags(source)
    code_spans = noncrossing_markdown_code_spans(source)
    syntax, _ = matched_markdown_syntax(source, code_spans)
    code_by_start = {start: (end, width) for start, end, width in code_spans}
    rendered: list[str] = []
    index = 0
    while index < len(source):
        code_span = code_by_start.get(index)
        if code_span is not None:
            end, width = code_span
            content = source[index + width : end - width]
            content = content.replace("\r\n", " ").replace("\r", " ")
            content = content.replace("\n", " ")
            if (
                content.startswith(" ")
                and content.endswith(" ")
                and content.strip(" ")
            ):
                content = content[1:-1]
            rendered.append(content)
            index = end
            continue
        if syntax[index]:
            index += 1
            continue
        if (
            source[index] == "\\"
            and not escaped[index]
            and index + 1 < len(source)
            and source[index + 1] in MARKDOWN_ESCAPABLE
        ):
            index += 1
            continue
        rendered.append(source[index])
        index += 1
    return "".join(rendered)


@lru_cache(maxsize=16_384)
def trailing_markdown_delimiter_spans(source: str) -> tuple[tuple[int, int], ...]:
    """Return actual rendered Markdown/code wrapper spans, preserving source offsets."""
    length = len(source)
    escaped = markdown_escape_flags(source)

    raw_html, _, visible_literal = markdown_html_channels(source)
    raw_tag_owned = [False] * length
    index = 0
    while index < length:
        if source[index] != "<" or raw_html[index] != "<":
            index += 1
            continue
        if source.startswith("<!--", index):
            marker_end = source.find("-->", index + 4)
            end = length if marker_end < 0 else marker_end + 3
        elif source.startswith("<![CDATA[", index):
            marker_end = source.find("]]>", index + 9)
            end = length if marker_end < 0 else marker_end + 3
        else:
            cursor = index + 1
            quote: str | None = None
            while cursor < length:
                character = source[cursor]
                if quote is not None:
                    if character == quote:
                        quote = None
                elif character in {'"', "'"}:
                    quote = character
                elif character == ">":
                    cursor += 1
                    break
                cursor += 1
            end = cursor
        for position in range(index, min(end, length)):
            raw_tag_owned[position] = True
        index = max(index + 1, end)

    def channel_owned(position: int) -> bool:
        return (
            not raw_tag_owned[position]
            and (raw_html[position] != " " or visible_literal[position] != " ")
        )

    eligible = tuple(channel_owned(position) for position in range(length))
    code_spans = noncrossing_markdown_code_spans(source, eligible)
    _, delimiter_spans = matched_markdown_syntax(source, code_spans, eligible)
    spans = [(start, end) for start, end, _ in code_spans]
    spans.extend(delimiter_spans)

    code_owned = [False] * length
    for start, end, _ in code_spans:
        for position in range(start, end):
            code_owned[position] = True

    bracket_openings: list[int] = []
    index = 0
    while index < length:
        if code_owned[index] or escaped[index] or not eligible[index]:
            index += 1
            continue
        character = source[index]
        if character == "[":
            start = (
                index - 1
                if index > 0
                and source[index - 1] == "!"
                and not escaped[index - 1]
                and eligible[index - 1]
                else index
            )
            bracket_openings.append(start)
            require(
                len(bracket_openings) <= MAX_MARKDOWN_NESTING,
                "trailing Markdown label nesting exceeds bound",
            )
        elif character == "]" and bracket_openings:
            spans.append((bracket_openings.pop(), index + 1))
        index += 1
    unique: list[tuple[int, int]] = []
    seen: set[tuple[int, int]] = set()
    for span in spans:
        if span not in seen:
            seen.add(span)
            unique.append(span)
    return tuple(unique)


class TrailingOuterHTMLSpans(HTMLParser):
    """Collect complete outer raw-HTML spans with offset-preserving nesting."""

    def __init__(self, source: str) -> None:
        super().__init__(convert_charrefs=False)
        self.source = source
        self.line_offsets = [0]
        for line in source.splitlines(keepends=True):
            self.line_offsets.append(self.line_offsets[-1] + len(line))
        self.spans: list[tuple[int, int]] = []
        self.outer_start: int | None = None
        self.depth = 0

    def absolute_offset(self) -> int:
        line, column = self.getpos()
        return self.line_offsets[line - 1] + column

    def handle_starttag(
        self, tag: str, attributes: list[tuple[str, str | None]]
    ) -> None:
        del attributes
        start = self.absolute_offset()
        raw_tag = self.get_starttag_text() or ""
        if self.depth == 0:
            if tag.casefold() in HTML_VOID_ELEMENTS:
                self.spans.append((start, start + len(raw_tag)))
                return
            self.outer_start = start
        self.depth += 1

    def handle_startendtag(
        self, tag: str, attributes: list[tuple[str, str | None]]
    ) -> None:
        del tag, attributes
        start = self.absolute_offset()
        raw_tag = self.get_starttag_text() or ""
        if self.depth == 0:
            self.spans.append((start, start + len(raw_tag)))

    def handle_endtag(self, tag: str) -> None:
        del tag
        if self.depth > 0:
            self.depth -= 1
        if self.depth == 0 and self.outer_start is not None:
            start = self.absolute_offset()
            closing = self.source.find(">", start)
            end = len(self.source) if closing < 0 else closing + 1
            self.spans.append((self.outer_start, end))
            self.outer_start = None


@lru_cache(maxsize=16_384)
def trailing_outer_html_spans(source: str) -> tuple[tuple[int, int], ...]:
    validation_source = markdown_html_validation_source(source)
    parser = TrailingOuterHTMLSpans(validation_source)
    parser.feed(validation_source)
    parser.close()
    return tuple(parser.spans)


def canonical_trailing_source(line: str, identifier: str) -> tuple[str, bool]:
    """Return text after the delimited canonical core and whether it is exact."""
    if identifier.startswith(("PR-", "AC-", "INV-")):
        match = re.match(
            rf"^- \*\*{re.escape(identifier)}(?: —|\.)[^*\n]*\*\*",
            line,
        )
        return (line[match.end() :], True) if match is not None else (line, False)
    match = re.match(rf"^#{{1,6}} +{re.escape(identifier)}\.", line)
    return (line[match.end() :], False) if match is not None else (line, False)


def linear_contains(haystack: str, needle: str) -> bool:
    """Return substring membership with an explicit linear-time KMP scan."""
    if not needle:
        return True
    prefix = [0] * len(needle)
    matched = 0
    for index in range(1, len(needle)):
        while matched and needle[index] != needle[matched]:
            matched = prefix[matched - 1]
        if needle[index] == needle[matched]:
            matched += 1
            prefix[index] = matched
    matched = 0
    for character in haystack:
        while matched and character != needle[matched]:
            matched = prefix[matched - 1]
        if character == needle[matched]:
            matched += 1
            if matched == len(needle):
                return True
    return False


def trailing_definition_identifier(line: str, identifier: str) -> str | None:
    """Find a second definition by suffix position or explicit wrapper provenance."""
    trailing, _ = canonical_trailing_source(line, identifier)
    rendered_trailing = rendered_definition_text(trailing)
    strong_separator = TRAILING_RENDERED_STRONG_SEPARATOR_RE.search(rendered_trailing)
    if strong_separator is not None:
        return strong_separator.group(1)
    delimiter_spans = trailing_markdown_delimiter_spans(trailing)
    html_spans = trailing_outer_html_spans(trailing)
    require(
        len(delimiter_spans) + len(html_spans)
        <= MAX_TRAILING_PROVENANCE_CANDIDATES,
        "trailing definition provenance candidate count exceeds bound",
    )
    for start, end in (*delimiter_spans, *html_spans):
        rendered_fragment = rendered_definition_text(trailing[start:end])
        candidate = leading_rendered_definition_identifier(
            rendered_fragment,
            require_separator=True,
            allow_colon=True,
        )
        if candidate is not None and linear_contains(
            rendered_trailing, rendered_fragment
        ):
            return candidate
    for _, segment, is_candidate in parse_definition_html(trailing).runs:
        if not is_candidate:
            continue
        rendered_fragment = rendered_definition_text(segment)
        candidate = leading_rendered_definition_identifier(
            rendered_fragment,
            require_separator=True,
            allow_colon=True,
        )
        if candidate is not None and linear_contains(
            rendered_trailing, rendered_fragment
        ):
            return candidate
    return None


def check_definition_syntax(product: str, architecture: str) -> None:
    for document_name, document in (("product", product), ("architecture", architecture)):
        lines = document.splitlines()
        for line in lines:
            require(
                len(line) <= MAX_DEFINITION_LINE_CHARS,
                "definition candidate line exceeds parser bound",
            )
        require(
            len(document) <= MAX_HTML_DOCUMENT_CHARS,
            "document exceeds Markdown/HTML parser bound",
        )
        rendered_document = markdown_html_render_source(document)
        whole_html_candidates = html_definition_candidates_from_parser(
            parse_rendered_definition_html(rendered_document)
        )
        rendered_lines = rendered_document.splitlines()
        require(
            len(rendered_lines) == len(lines),
            "Markdown code provenance changed source line count",
        )
        fenced_lines = markdown_fenced_line_numbers(document)
        for line_number, line in enumerate(lines, start=1):
            if line_number - 1 in fenced_lines:
                continue
            following_line = lines[line_number] if line_number < len(lines) else ""
            if line_number in fenced_lines:
                following_line = ""
            candidate_line = rendered_lines[line_number - 1]
            try:
                line_candidates = definition_candidates(
                    candidate_line,
                    following_line,
                    source_line_length=len(line),
                )
            except ValueError as error:
                fragment_only_error = str(error).startswith(
                    (
                        "raw HTML uses unsupported rendering-affecting markup",
                        "raw HTML contains incomplete markup",
                        "raw HTML contains an unclosed modeled element",
                    )
                )
                if not fragment_only_error:
                    raise
                line_candidates = set()
            for identifier in line_candidates:
                if identifier.startswith(("PR-", "AC-")):
                    canonical = (
                        document_name == "product"
                        and re.fullmatch(
                            rf"^- \*\*{re.escape(identifier)}(?: —|\.)[^*\n]*\*\*(?: .*)?",
                            line,
                        )
                        is not None
                    )
                elif identifier.startswith("INV-"):
                    canonical = (
                        document_name == "architecture"
                        and re.fullmatch(
                            rf"^- \*\*{re.escape(identifier)}(?: —|\.)[^*\n]*\*\*(?: .*)?",
                            line,
                        )
                        is not None
                    )
                else:
                    match = re.match(
                        rf"^(#{{1,6}}) +{re.escape(identifier)}\.", line
                    )
                    expected_level = 2 + identifier.count(".")
                    canonical = (
                        document_name == "architecture"
                        and match is not None
                        and len(match.group(1)) == expected_level
                    )
                if canonical:
                    rendered = rendered_definition_text(line)
                    leading = re.search(
                        rf"\b{re.escape(identifier)}\b(?:\s*(?:—|\.|:))?",
                        rendered,
                    )
                    require(
                        leading is not None,
                        f"{document_name}:{line_number}: canonical {identifier} "
                        "does not render as its leading definition",
                    )
                    require(
                        trailing_definition_identifier(line, identifier) is None,
                        f"{document_name}:{line_number}: additional definition-like "
                        "normative ID on canonical line",
                    )
                require(
                    canonical,
                    f"{document_name}:{line_number}: noncanonical or cross-document "
                    f"{identifier} definition",
                )
        for identifier in whole_html_candidates:
            fail(
                f"{document_name}:HTML: noncanonical or cross-document "
                f"{identifier} definition"
            )


def check_definitions(product: str, architecture: str) -> None:
    # Canonical E5 structural/provenance credit comes solely from the shared
    # parser: the frozen definition/section identity manifests are cross-checked
    # against the shared parser's own Structure in _check_shared_structure_provenance,
    # and the shared parser internally validates every unit's source/visible
    # provenance via validate_structure.  No raw-source definition regex credit
    # (no second lexer) remains here; the legacy A-17.1 disguise safety check
    # below is retained as bounded defense-in-depth.
    check_definition_syntax(product, architecture)


def check_codec(operation_id: str, field: str, value: object) -> None:
    require(isinstance(value, str), f"{operation_id}: {field} must be a string")
    require(
        value == "none" or CODEC_RE.fullmatch(value) is not None,
        f"{operation_id}: malformed {field} {value!r}",
    )
    require(value == "none" or value in ALLOWED_CODECS, f"{operation_id}: unknown {field} {value!r}")


def normalized_route(path: str) -> str:
    return PARAMETER_RE.sub("{}", path)


def check_operations(data: dict[str, object]) -> None:
    fields = set(data)
    require(
        fields == EXPECTED_TOP_LEVEL_FIELDS,
        f"catalog top-level field mismatch; "
        f"missing={sorted(EXPECTED_TOP_LEVEL_FIELDS-fields)}, "
        f"unknown={sorted(fields-EXPECTED_TOP_LEVEL_FIELDS)}",
    )
    require(
        type(data.get("catalog_version")) is int and data["catalog_version"] == 1,
        "catalog_version must be the integer 1",
    )
    require(
        isinstance(data.get("product_spec"), str) and data["product_spec"] == "0.3.46",
        "product_spec must be 0.3.46",
    )
    require(
        isinstance(data.get("architecture_spec"), str)
        and data["architecture_spec"] == "0.3.62",
        "architecture_spec must be 0.3.62",
    )
    require(
        isinstance(data.get("api_prefix"), str) and data["api_prefix"] == "/v1",
        "api_prefix must be /v1",
    )

    operations = data.get("operation")
    require(isinstance(operations, list), "operation must be an array of tables")
    require(len(operations) == 70, f"expected 70 operations, got {len(operations)}")

    for index, operation in enumerate(operations):
        require(isinstance(operation, dict), f"operation {index} must be a table")
        operation_id = operation.get("id")
        require(
            isinstance(operation_id, str) and OPERATION_ID_RE.fullmatch(operation_id),
            f"operation {index}: malformed id {operation_id!r}",
        )
        fields = set(operation)
        expected_fields = REQUIRED_OPERATION_FIELDS | (
            {"one_time_mode"} if operation_id in EXPECTED_ONE_TIME_MODES else set()
        )
        require(
            fields == expected_fields,
            f"operation {index}: field mismatch; missing={sorted(expected_fields-fields)}, "
            f"unknown={sorted(fields-expected_fields)}",
        )
        require(
            isinstance(operation["method"], str)
            and operation["method"] in {"GET", "POST", "PUT", "PATCH", "DELETE"},
            f"{operation_id}: unsupported method",
        )
        require(
            isinstance(operation["path"], str) and operation["path"].startswith("/v1/"),
            f"{operation_id}: path must be versioned under /v1",
        )
        bindings = operation["bindings"]
        require(isinstance(bindings, list) and bindings, f"{operation_id}: empty bindings")
        require(
            all(isinstance(binding, str) for binding in bindings),
            f"{operation_id}: every binding must be a string",
        )
        unique(f"binding in {operation_id}", bindings)
        require(set(bindings) <= ALLOWED_BINDINGS, f"{operation_id}: unknown binding")
        require(
            isinstance(operation["authorization"], str)
            and operation["authorization"] in ALLOWED_AUTHORIZATION,
            f"{operation_id}: unknown authorization",
        )
        require(
            isinstance(operation["idempotency"], str)
            and operation["idempotency"] in ALLOWED_IDEMPOTENCY,
            f"{operation_id}: unknown idempotency",
        )
        require(
            isinstance(operation["risk"], str) and operation["risk"] in ALLOWED_RISK,
            f"{operation_id}: unknown risk",
        )
        require(isinstance(operation["cli"], str) and operation["cli"].strip(), f"{operation_id}: empty CLI command")
        check_codec(operation_id, "request_codec", operation["request_codec"])
        check_codec(operation_id, "response_codec", operation["response_codec"])
        if operation_id in EXPECTED_ONE_TIME_MODES:
            require(
                operation["one_time_mode"] == EXPECTED_ONE_TIME_MODES[operation_id],
                f"{operation_id}: one_time_mode must be {EXPECTED_ONE_TIME_MODES[operation_id]!r}",
            )

    ingress = data.get("provider_ingress")
    expected_ingress = [
        {"id": "whatsapp.challenge", "provider": "whatsapp_cloud", "method": "GET", "route_family": "phase0.whatsapp.webhook", "verification_mode": "verification_token_challenge", "request_codec": "query.provider_verification.v1", "response_class": "bounded_challenge_or_safe_rejection", "idempotency": "no_mutation", "body_limit": 0, "deadline_ms": 1000, "risk": "provider_ingress"},
        {"id": "whatsapp.callback", "provider": "whatsapp_cloud", "method": "POST", "route_family": "phase0.whatsapp.webhook", "verification_mode": "raw_body_signature", "request_codec": "bytes.whatsapp_callback.v1", "response_class": "durable_ack_or_retryable_failure", "idempotency": "provider_event_key", "body_limit": 262144, "deadline_ms": 5000, "risk": "provider_ingress"},
    ]
    require(isinstance(ingress, list) and len(ingress) == 2, "expected two provider ingress records")
    for item, expected in zip(ingress, expected_ingress):
        require(isinstance(item, dict) and set(item) == set(expected), "provider ingress schema")
        require(type(item["body_limit"]) is int and type(item["deadline_ms"]) is int, "provider ingress numeric types")
        require(item == expected, "provider ingress manifest mismatch")
        require(item["id"] not in {row["id"] for row in operations}, "provider ingress must not be a normal operation")

    operation_ids = [operation["id"] for operation in operations]
    unique("operation id", operation_ids)
    unique("CLI command", [operation["cli"] for operation in operations])
    unique(
        "method/path pair",
        [(operation["method"], operation["path"]) for operation in operations],
    )
    unique(
        "method/binding/route shape",
        [
            (operation["method"], binding, normalized_route(operation["path"]))
            for operation in operations
            for binding in operation["bindings"]
        ],
    )
    actual_policy = {
        operation["id"]: (
            operation["authorization"],
            tuple(operation["bindings"]),
            operation["idempotency"],
            operation["risk"],
        )
        for operation in operations
    }
    require(
        actual_policy == EXPECTED_OPERATION_POLICY,
        "operation policy manifest mismatch; "
        f"missing={sorted(set(EXPECTED_OPERATION_POLICY)-set(actual_policy))}, "
        f"unknown={sorted(set(actual_policy)-set(EXPECTED_OPERATION_POLICY))}, "
        f"changed={sorted(key for key in set(actual_policy) & set(EXPECTED_OPERATION_POLICY) if actual_policy[key] != EXPECTED_OPERATION_POLICY[key])}",
    )
    actual_addressed_state = {
        operation["id"]
        for operation in operations
        if operation["idempotency"] == "addressed_state"
    }
    require(
        actual_addressed_state == EXPECTED_ADDRESSED_STATE,
        "addressed-state catalog mismatch; "
        f"missing={sorted(EXPECTED_ADDRESSED_STATE-actual_addressed_state)}, "
        f"unknown={sorted(actual_addressed_state-EXPECTED_ADDRESSED_STATE)}",
    )
    actual_generation_guarded = {
        operation["id"]
        for operation in operations
        if operation["idempotency"] == "generation_guarded"
    }
    require(
        actual_generation_guarded == EXPECTED_GENERATION_GUARDED,
        "generation-guarded catalog mismatch; "
        f"missing={sorted(EXPECTED_GENERATION_GUARDED-actual_generation_guarded)}, "
        f"unknown={sorted(actual_generation_guarded-EXPECTED_GENERATION_GUARDED)}",
    )
    actual_surface = {
        operation["id"]: (
            operation["method"],
            operation["path"],
            operation["cli"],
            operation["request_codec"],
            operation["response_codec"],
        )
        for operation in operations
    }
    require(
        actual_surface == EXPECTED_OPERATION_SURFACE,
        "operation surface manifest mismatch; "
        f"missing={sorted(set(EXPECTED_OPERATION_SURFACE)-set(actual_surface))}, "
        f"unknown={sorted(set(actual_surface)-set(EXPECTED_OPERATION_SURFACE))}, "
        f"changed={sorted(key for key in set(actual_surface) & set(EXPECTED_OPERATION_SURFACE) if actual_surface[key] != EXPECTED_OPERATION_SURFACE[key])}",
    )
    actual_one_time_modes = {
        operation["id"]: operation["one_time_mode"]
        for operation in operations
        if operation["idempotency"] == "one_time_secret"
    }
    require(
        actual_one_time_modes == EXPECTED_ONE_TIME_MODES,
        f"one-time mode manifest mismatch: {actual_one_time_modes!r}",
    )
    used_codecs = {
        operation[field]
        for operation in operations
        for field in ("request_codec", "response_codec")
        if operation[field] != "none"
    }
    require(
        used_codecs == ALLOWED_CODECS,
        f"codec registry mismatch; missing={sorted(ALLOWED_CODECS-used_codecs)}, "
        f"unknown={sorted(used_codecs-ALLOWED_CODECS)}",
    )

    maintenance = {
        operation["id"]
        for operation in operations
        if "maintenance_uds" in operation["bindings"]
    }
    require(
        maintenance == EXPECTED_MAINTENANCE,
        f"maintenance catalog mismatch; missing={sorted(EXPECTED_MAINTENANCE-maintenance)}, "
        f"unknown={sorted(maintenance-EXPECTED_MAINTENANCE)}",
    )

    fixed_root = data.get("fixed_root_journaled_operations")
    require(isinstance(fixed_root, list) and fixed_root, "missing fixed-root operation registry")
    require(
        all(isinstance(operation_id, str) for operation_id in fixed_root),
        "every fixed-root operation ID must be a string",
    )
    unique("fixed-root journaled operation", fixed_root)
    by_id = {operation["id"]: operation for operation in operations}
    fixed_root_set = set(fixed_root)
    require(
        fixed_root_set == EXPECTED_FIXED_ROOT,
        f"fixed-root registry mismatch; missing={sorted(EXPECTED_FIXED_ROOT-fixed_root_set)}, "
        f"unknown={sorted(fixed_root_set-EXPECTED_FIXED_ROOT)}",
    )
    require(fixed_root_set <= set(by_id), "fixed-root registry names an unknown operation")
    for operation_id in fixed_root:
        require(
            by_id[operation_id]["idempotency"]
            in {"addressed_state", "command_key", "one_time_secret"},
            f"{operation_id}: fixed-root journal mutator requires addressed_state, command_key, or one_time_secret",
        )
    maintenance_mutators = {
        operation["id"]
        for operation in operations
        if "maintenance_uds" in operation["bindings"]
        and operation["idempotency"]
        in {"addressed_state", "command_key", "one_time_secret"}
    }
    require(
        maintenance_mutators <= fixed_root_set,
        "every maintenance addressed/command operation must be fixed-root journaled; "
        f"missing={sorted(maintenance_mutators-fixed_root_set)}",
    )
    require(
        fixed_root_set - maintenance_mutators == {"upgrade.prepare", "upgrade.activate"},
        "upgrade.prepare and upgrade.activate must be the sole normal-only fixed-root mutators",
    )


def check_maintenance_prose(architecture: str) -> None:
    start = "<!-- maintenance-operation-registry:start -->"
    end = "<!-- maintenance-operation-registry:end -->"
    require(architecture.count(start) == 1, "maintenance prose start marker must occur once")
    require(architecture.count(end) == 1, "maintenance prose end marker must occur once")
    require(
        architecture.index(start) < architecture.index(end),
        "maintenance prose markers are inverted",
    )
    registry = architecture.split(start, 1)[1].split(end, 1)[0]
    count_claims = re.findall(r"\bexact (\d+)-operation registry\b", registry)
    require(
        count_claims == [str(len(EXPECTED_MAINTENANCE))],
        f"maintenance prose count must be exactly {len(EXPECTED_MAINTENANCE)}",
    )
    identifiers = re.findall(rf"`({OPERATION_ID_RE.pattern})`", registry)
    unique("maintenance prose operation", identifiers)
    actual = set(identifiers)
    require(
        actual == EXPECTED_MAINTENANCE,
        f"maintenance prose mismatch; missing={sorted(EXPECTED_MAINTENANCE-actual)}, "
        f"unknown={sorted(actual-EXPECTED_MAINTENANCE)}",
    )


def check_upgrade_lifecycle_prose(architecture: str) -> None:
    start = "<!-- upgrade-lifecycle-record-registry:start -->"
    end = "<!-- upgrade-lifecycle-record-registry:end -->"
    require(architecture.count(start) == 1, "upgrade lifecycle start marker must occur once")
    require(architecture.count(end) == 1, "upgrade lifecycle end marker must occur once")
    require(
        architecture.index(start) < architecture.index(end),
        "upgrade lifecycle markers are inverted",
    )
    registry = architecture.split(start, 1)[1].split(end, 1)[0]
    count_claims = re.findall(r"\bexact (\d+)-record registry\b", registry)
    require(
        count_claims == [str(len(EXPECTED_UPGRADE_LIFECYCLE_RECORDS))],
        "upgrade lifecycle prose count must be exactly "
        f"{len(EXPECTED_UPGRADE_LIFECYCLE_RECORDS)}",
    )
    identifiers = re.findall(rf"`({OPERATION_ID_RE.pattern})`", registry)
    unique("upgrade lifecycle prose record", identifiers)
    actual = set(identifiers)
    require(
        actual == EXPECTED_UPGRADE_LIFECYCLE_RECORDS,
        "upgrade lifecycle prose mismatch; "
        f"missing={sorted(EXPECTED_UPGRADE_LIFECYCLE_RECORDS-actual)}, "
        f"unknown={sorted(actual-EXPECTED_UPGRADE_LIFECYCLE_RECORDS)}",
    )


def check_addressed_state_prose(architecture: str) -> None:
    start = "<!-- addressed-state-operation-registry:start -->"
    end = "<!-- addressed-state-operation-registry:end -->"
    require(
        architecture.count(start) == 1,
        "addressed-state prose start marker must occur once",
    )
    require(
        architecture.count(end) == 1,
        "addressed-state prose end marker must occur once",
    )
    require(
        architecture.index(start) < architecture.index(end),
        "addressed-state prose markers are inverted",
    )
    registry = architecture.split(start, 1)[1].split(end, 1)[0]
    count_claims = re.findall(r"\bexact (\d+)-operation registry\b", registry)
    require(
        count_claims == [str(len(EXPECTED_ADDRESSED_STATE))],
        "addressed-state prose count must be exactly "
        f"{len(EXPECTED_ADDRESSED_STATE)}",
    )
    identifiers = re.findall(rf"`({OPERATION_ID_RE.pattern})`", registry)
    unique("addressed-state prose operation", identifiers)
    actual = set(identifiers)
    require(
        actual == EXPECTED_ADDRESSED_STATE,
        "addressed-state prose mismatch; "
        f"missing={sorted(EXPECTED_ADDRESSED_STATE-actual)}, "
        f"unknown={sorted(actual-EXPECTED_ADDRESSED_STATE)}",
    )


def check_generation_guarded_prose(architecture: str) -> None:
    start = "<!-- generation-guarded-operation-registry:start -->"
    end = "<!-- generation-guarded-operation-registry:end -->"
    require(
        architecture.count(start) == 1,
        "generation-guarded prose start marker must occur once",
    )
    require(
        architecture.count(end) == 1,
        "generation-guarded prose end marker must occur once",
    )
    require(
        architecture.index(start) < architecture.index(end),
        "generation-guarded prose markers are inverted",
    )
    registry = architecture.split(start, 1)[1].split(end, 1)[0]
    count_claims = re.findall(r"\bexact (\d+)-operation registry\b", registry)
    require(
        count_claims == [str(len(EXPECTED_GENERATION_GUARDED))],
        "generation-guarded prose count must be exactly "
        f"{len(EXPECTED_GENERATION_GUARDED)}",
    )
    registry_list = re.search(
        r"\bThe exact \d+-operation registry for `generation_guarded` is:\s*"
        r"(.*?)\.\s+`admission\.set` uses\b",
        registry,
        re.DOTALL,
    )
    require(registry_list is not None, "generation-guarded prose registry list is malformed")
    identifiers = re.findall(
        rf"`({OPERATION_ID_RE.pattern})`", registry_list.group(1)
    )
    unique("generation-guarded prose operation", identifiers)
    actual = set(identifiers)
    require(
        actual == EXPECTED_GENERATION_GUARDED,
        "generation-guarded prose mismatch; "
        f"missing={sorted(EXPECTED_GENERATION_GUARDED-actual)}, "
        f"unknown={sorted(actual-EXPECTED_GENERATION_GUARDED)}",
    )


def normalized_prose(document: str) -> str:
    return re.sub(r"\s+", " ", document)


def normalized_scope_sha256(
    document: str,
    start_marker: str,
    end_marker: str,
    label: str,
) -> str:
    require(
        document.count(start_marker) == 1,
        f"upgrade exit capacity scope start missing or duplicated: {label}",
    )
    require(
        document.count(end_marker) == 1,
        f"upgrade exit capacity scope end missing or duplicated: {label}",
    )
    start = document.index(start_marker)
    end = document.index(end_marker)
    require(
        start < end,
        f"upgrade exit capacity scope markers out of order: {label}",
    )
    normalized = normalized_prose(document[start:end]).strip()
    require(normalized != "", f"upgrade exit capacity scope is empty: {label}")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def check_complete_revision_prose(product: str, architecture: str) -> None:
    normalized_product = normalized_prose(product)
    normalized_architecture = normalized_prose(architecture)
    required_architecture = (
        (
            "API incarnation carrier",
            "Every codec requires both `expected_incarnation`",
        ),
        (
            "incarnation width",
            "`ResourceIncarnation`: the non-secret, non-authorizing selected authenticated structured 256-bit history epoch",
        ),
        (
            "read incarnation carrier",
            "responses expose `resource_incarnation` plus",
        ),
        (
            "CLI incarnation carrier",
            "`--if-incarnation <64-lowercase-hex>` and `--if-generation <u64>`",
        ),
        (
            "receipt incarnation",
            "result generation, the exact resource incarnation",
        ),
        (
            "complete-address comparison",
            "the complete expected pair equal to the complete current pair",
        ),
        (
            "admission writer registry",
            "`admission.set` and `drain.start`",
        ),
        (
            "principal writer registry",
            "`principal.update`, `principal.enable`",
        ),
        (
            "branch replacement registry",
            "`restore.create` and `upgrade.rollback`",
        ),
        (
            "continuation preservation",
            "forward repair preserve the complete address",
        ),
        (
            "generation limb range",
            "each constrained to `0..4294967295`",
        ),
        (
            "generation carry relation",
            "Database checks encode increment exactly: `lo < 4294967295`",
        ),
        (
            "every writer at MAX",
            "Every fresh writer at `u64::MAX`",
        ),
        (
            "readiness reason",
            "`msgriver-core::readiness_reason` MUST compute only the pure exhaustion subset `{generation_exhausted, incarnation_exhausted}` and its mutual precedence from the supplied branch high-water and guarded generations",
        ),
        (
            "readiness CLI",
            "The CLI is rendered by `layer:client` from the `ReasonSet`, using exactly these fixed sentences: "
            "for generation exhaustion, `Guarded resource generation exhausted; select a supported fresh branch "
            "or migrate the representation.`",
        ),
        (
            "readiness metric",
            "series over exactly those closed reasons (`generation_exhausted`",
        ),
        (
            "complete 409 mappings",
            "`shutdown_in_progress`, `drain_in_progress`, `maintenance_transition_busy`, `upgrade_prepare_in_progress`",
        ),
        (
            "complete registry marker enumeration",
            "maintenance, upgrade-lifecycle, addressed-state, generation-guarded, and incarnation-allocator registry markers",
        ),
    )
    required_product = (
        (
            "product request incarnation",
            "carry both `expected_incarnation` and `expected_generation`",
        ),
        (
            "product receipt incarnation",
            "binds the exact resource incarnation, prior and result generations",
        ),
        (
            "product readiness source",
            "That readiness state is derived from the resource value already persisted at `u64::MAX`; the rejected fresh writer performs no readiness mutation",
        ),
        (
            "product generation marker enumeration",
            "exact two-operation membership, and generation-guarded-marker multiplicity/order/count and its exact five-operation membership",
        ),
    )
    for label, required in required_architecture:
        require(
            normalized_architecture.count(required) == 1,
            f"complete revision architecture contract missing or duplicated: {label}",
        )
    for label, required in required_product:
        require(
            normalized_product.count(required) == 1,
            f"complete revision product contract missing or duplicated: {label}",
        )


def check_incarnation_allocator_prose(product: str, architecture: str) -> None:
    normalized_product = normalized_prose(product)
    normalized_architecture = normalized_prose(architecture)
    require(
        architecture.count("<!-- incarnation-allocator-contract:start -->") == 1,
        "incarnation allocator start marker missing or duplicated",
    )
    require(
        architecture.count("<!-- incarnation-allocator-contract:end -->") == 1,
        "incarnation allocator end marker missing or duplicated",
    )
    require(
        architecture.index("<!-- incarnation-allocator-contract:start -->")
        < architecture.index("<!-- incarnation-allocator-contract:end -->"),
        "incarnation allocator markers inverted",
    )
    required_architecture = (
        (
            "wire component order",
            "ResourceIncarnation = OwnerNamespace[24] || BranchSerialBE[8]",
        ),
        ("serial encoding", "unsigned nonzero big-endian `u64`"),
        (
            "namespace derivation",
            'OwnerNamespace = Truncate192(HMAC-SHA-256(host_local_journal_key, "msgriver/resource-incarnation-namespace/v1"))',
        ),
        (
            "allocator registry",
            "The allocation registry MUST be exactly `bootstrap.create`, `restore.create`, and `upgrade.rollback`",
        ),
        (
            "fixed-root ownership",
            "The authenticated fixed-root journal header MUST own `owner_namespace` and `branch_serial_high_water`",
        ),
        (
            "namespace verification",
            "A new header MUST start at zero, MUST recompute the namespace from the final journal key, and MUST reject any stored namespace/key mismatch",
        ),
        (
            "atomic intent burn",
            "MUST atomically advance and burn exactly one serial",
        ),
        (
            "complete intent binding",
            "typed parent epoch/head/certificate inputs",
        ),
        (
            "checked serial exhaustion",
            "zero MUST NOT be issued, carry MUST be exact, and a high-water of `u64::MAX` MUST return `state_incarnation_unavailable` without wrap or a new intent",
        ),
        (
            "same-intent recovery",
            "MUST reuse its exact serial and target bytes; it MUST NOT advance again, MUST NOT choose another target, and MUST NOT reroll",
        ),
        (
            "failed serial retention",
            "Every allocated serial MUST remain burned when staging aborts or terminally fails",
        ),
        (
            "continuation non-allocation",
            "forward repair MUST preserve the complete incarnation and MUST perform no allocator write",
        ),
        (
            "target input prohibition",
            "MUST NOT supply or override the namespace, serial, complete target incarnation, or allocator high-water",
        ),
        (
            "collision scope",
            "retained sibling/parent provenance, every nonterminal intent, and identifiable staged-generation metadata",
        ),
        (
            "same-root deterministic non-reuse",
            "Same-root non-reuse MUST be deterministic from the authenticated monotonic high-water",
        ),
        (
            "cross-host assumption",
            "Cross-host non-reuse MUST rely on independently generated host-local journal keys",
        ),
        (
            "key sample validation",
            "An entropy error, short sample, all-zero sample, or any two equal samples fails closed",
        ),
        (
            "allocator hold precedence",
            "MUST validate the allocator before clock evaluation",
        ),
        (
            "cloned-root exclusion",
            "Copying or importing a fixed owner root or its journal key into concurrently live hosts MUST remain unsupported.",
        ),
        (
            "collision fail-before-effect ordering",
            "A collision, source/parent mismatch, or target/serial mismatch MUST return `state_incarnation_unavailable` in bounded work without selection or pointer mutation.",
        ),
        (
            "forbidding hold before allocator",
            "Exact same-command recovery and an existing restore/upgrade hold that forbids a fresh transition MUST resolve before allocator evaluation.",
        ),
        (
            "capacity before intent burn",
            "With no pre-existing safety hold and usable allocator state, clock evaluation MUST precede fixed-root "
            "control-capacity projection plus admission, drain, and coordinator-conflict disclosure; capacity "
            "admission then MUST precede publishing and burning the allocating intent",
        ),
        (
            "authenticated rollback witnesses",
            "Every physically present selected pointer, retained history/provenance epoch, nonterminal intent, and identifiable staged generation in the same owner root must carry the recomputed namespace and a serial at or below the authenticated high-water",
        ),
        (
            "local allocator witness scope",
            "A `local allocator witness` MUST be exactly a selected pointer or current guarded-resource incarnation, a locally issued target field in an allocating intent, an identifiable locally staged target, or a history/provenance epoch allocated by this owner root",
        ),
        (
            "foreign ancestry admission",
            "Foreign authenticated ancestry MAY be retained only as immutable ancestry reachable through one authenticated blank-restore boundary",
        ),
        (
            "foreign ancestry confinement",
            "It MUST NOT be a local allocator witness, MUST NOT become a selected pointer or current guarded-resource incarnation, MUST NOT supply local high-water evidence, and MUST NOT authorize a request or receipt",
        ),
        (
            "full-root rollback scope",
            "complete rollback of the owner root together with all such witnesses remains outside the supported filesystem threat boundary and is not falsely claimed detectable",
        ),
        (
            "serial-exhaustion recovery path",
            "At branch-serial exhaustion, the supported recovery MUST be a new independently keyed blank owner root plus authenticated disaster restore of a previously valid artifact",
        ),
        (
            "exhausted-root rekey prohibition",
            "The exhausted owner root MUST NOT be re-keyed in place",
        ),
        (
            "serial-exhaustion nonallocating availability",
            "Serial exhaustion alone MUST NOT block delivery, authorized status, exact command/result recovery",
        ),
        (
            "incarnation-exhausted readiness reason",
            "exact `incarnation_exhausted` when the fixed-root branch-serial high-water is at `u64::MAX`",
        ),
        (
            "incarnation-exhausted readiness source",
            "`incarnation_exhausted`; it MUST be derived exclusively from the authenticated persisted "
            "`branch_serial_high_water`, and the rejected allocating operation and a readiness read MUST NOT "
            "perform a readiness or allocator write",
        ),
        (
            "incarnation-exhausted readiness CLI",
            "`Owner-root branch serial exhausted; use a new independently keyed blank root for authenticated disaster restore.`",
        ),
        (
            "incarnation-exhausted readiness metric",
            "`incarnation_exhausted`, `mac_key_serial_exhausted`",
        ),
        (
            "serial-exhaustion failure matrix",
            "Fixed-root branch serial exhausted | Readiness reports only `incarnation_exhausted`; allocating branch transitions return `state_incarnation_unavailable`",
        ),
        (
            "local foreign ancestry classification",
            "In the following local-witness sentence, `retained history/provenance epoch ... in the same owner root` denotes only the former and never the foreign immutable ancestry",
        ),
        (
            "upgrade prepare allocator headroom",
            "After exact same-command recovery and resolution of any pre-existing restore/upgrade hold, and before "
            "creating it, the store actor authenticates the fixed-root header and atomically requires "
            "`branch_serial_high_water < u64::MAX`. At MAX it returns "
            "`state_incarnation_unavailable` before coordinator, hold, operator-admission, journal, or allocator mutation. "
            "At MAX−1 it may proceed: no allocating operation can interleave before phase exit, so rollback may burn MAX "
            "exactly once and exact same-command rollback recovery remains available at MAX",
        ),
        (
            "upgrade prepare clock-drain precedence",
            "With usable serial headroom and no pre-existing safety hold, A-11.5 clock evaluation precedes "
            "nonterminal- drain and capacity disclosure: a clock hold returns exact `503 clock_hold` with null retry "
            "hint; otherwise a drain that serialized first returns `409 drain_in_progress` with no prepare state/hold",
        ),
        (
            "total fresh-mutator clock precedence",
            "Third, with no pre-existing restore/upgrade hold and usable allocator state, every cataloged fresh "
            "mutator—including a different- value complete-expected-current `admission.set`, `backup.create`, "
            "`backup.cancel`, `upgrade.prepare`, and `drain.start`—returns that same `clock_hold` before control-"
            "capacity admission, coordinator creation, or reporting an admission, drain, or coordinator conflict",
        ),
        (
            "upgrade prepare failure matrix",
            "Upgrade prepare at fixed-root serial MAX | `state_incarnation_unavailable` before coordinator or hold | "
            "MAX−1 may prepare; rollback burns MAX exactly once and same-command recovery remains available at MAX",
        ),
        (
            "combined exhaustion CLI precedence",
            "When generation and incarnation exhaustion are both present, the CLI renders the incarnation sentence as the sole recovery instruction "
            "and suppresses the generation-only fresh-branch guidance",
        ),
        (
            "per-current-root blank boundary",
            "For this rule, `one` means the current selected owner root's immediate boundary; earlier authenticated "
            "blank-restore boundaries carried inside that verified artifact lineage MUST NOT count against the current "
            "root's boundary, and every epoch behind it remains foreign",
        ),
        (
            "upgrade headroom evidence",
            "Upgrade-headroom evidence invokes `upgrade.prepare` at branch serial MAX and MAX−1. MAX refuses before "
            "coordinator, hold, admission, journal, or allocator mutation; MAX−1 prepares, rollback burns MAX exactly "
            "once, and same-command rollback recovery remains available at MAX",
        ),
        (
            "allocator recovery composition evidence",
            "Recovery-composition evidence substitutes a complete older authenticated journal with lower high-water "
            "than retained local witnesses and requires corruption hold before selection, then substitutes an equal- "
            "high-water image missing only reconstructable terminal suffix truth and requires convergence without "
            "authority loss, safe-time regression, or duplicate burn. It also performs blank restore A→B, backup on "
            "B, and blank restore B→C across startup, fold, and anchor compaction; every artifact-internal boundary "
            "remains verified foreign ancestry. With one guarded generation and the branch serial both at MAX, API, "
            "CLI, and metrics retain both closed reasons while CLI recovery guidance names only the independently "
            "keyed new-root path",
        ),
    )
    required_product = (
        (
            "product fixed-root ownership",
            "fixed-root journal owns the branch-serial high-water",
        ),
        (
            "product target input prohibition",
            "No request, artifact, hidden default, or CLI option may choose the target namespace, serial, or incarnation",
        ),
        (
            "product allocator precedence",
            "Exact same-command recovery resolves first, then a restore/upgrade hold that forbids the fresh "
            "transition, then nonmutating allocator validation. A transition permitted through its own hold still "
            "returns allocator unavailability before `clock_hold` when allocator state is its immediate blocker. With "
            "no pre-existing safety hold and usable allocator state, clock evaluation precedes fixed-root control-"
            "capacity admission plus any admission, drain, or coordinator conflict; capacity admission then precedes "
            "publishing or burning a new intent",
        ),
        (
            "product serial exhaustion guidance",
            "If the branch serial is exhausted, v1 has no in-place retry or widening: the supported operator path is a new independently keyed blank owner root plus authenticated disaster restore",
        ),
        (
            "product live-intent fold evidence",
            "Fold tail into checkpoint while an allocating intent is nonterminal and crash at every temporary-write, file-fsync, rename, and parent-fsync boundary",
        ),
        (
            "product serial-exhaustion nonallocating availability",
            "Serial exhaustion alone does not block nonallocating delivery, authorized status, exact command/result recovery, or any continuation operation",
        ),
        (
            "product foreign ancestry confinement",
            "authenticated artifact epochs remain only immutable foreign ancestry behind the typed restore boundary. They never become the selected target or a guarded-resource incarnation, never supply the new root's allocator high-water, and never authorize a request or receipt",
        ),
        (
            "product incarnation-exhausted readiness",
            "Readiness reports the terminal allocator condition as `incarnation_exhausted`",
        ),
        (
            "product upgrade prepare allocator headroom",
            "After exact same-command recovery and resolution of any pre-existing restore/upgrade hold, and before "
            "creating a coordinator or hold, `upgrade.prepare` MUST authenticate the fixed-root header and atomically "
            "require `branch_serial_high_water < u64::MAX`. At MAX it returns `state_incarnation_unavailable` before coordinator, hold, "
            "admission, journal, or allocator mutation. At MAX−1 prepare may proceed; no allocating operation can "
            "interleave before phase exit, so a later rollback burns MAX exactly once and same-command recovery of that "
            "rollback remains available at MAX",
        ),
        (
            "product upgrade prepare clock-drain precedence",
            "With usable serial headroom and no pre-existing safety hold, PR-149's clock rule resolves before a "
            "nonterminal drain or control- capacity disclosure: a clock hold returns exact `503 clock_hold` with null "
            "retry hint; otherwise a drain that serialized first returns `409 drain_in_progress` with no prepare state "
            "or hold",
        ),
        (
            "product clock-drain evidence",
            "Start a drain first, keep it nonterminal with a known positive monotonic remainder, then enter a clock "
            "hold and invoke a fresh `upgrade.prepare` with usable branch- serial headroom in both actor orders; it "
            "returns the same `clock_hold` before `drain_in_progress`, control-capacity, or coordinator disclosure and "
            "changes no prepare, drain, allocator, or reservation state",
        ),
        (
            "product incarnation readiness source",
            "The `incarnation_exhausted` condition is derived exclusively from the authenticated persisted "
            "`branch_serial_high_water` already at `u64::MAX`; a rejected allocating operation and a readiness read "
            "perform no readiness or allocator mutation",
        ),
        (
            "product per-current-root blank boundary",
            "The boundary count is relative to the current selected owner root: an artifact may carry earlier "
            "authenticated blank-restore boundaries inside its verified lineage, and all epochs behind the current "
            "root's immediate boundary remain foreign",
        ),
        (
            "product upgrade headroom evidence",
            "At branch serial MAX, `upgrade.prepare` fails before a coordinator or hold; at MAX−1 it may prepare, and "
            "rollback burns MAX exactly once with recoverable same-command truth",
        ),
        (
            "product equal-high-water journal evidence",
            "Separately replace it with an equal-high-water image missing only the reconstructable terminal transition "
            "record; journal-behind-pointer recovery converges without authority loss, safe-time regression, or "
            "duplicate burn",
        ),
        (
            "product nested ancestry evidence",
            "Back up that restored root, restore its artifact again onto a third independently keyed blank root, and "
            "repeat startup, fold, and anchor compaction; every artifact-internal boundary remains verified foreign "
            "ancestry and never becomes local authority or high-water evidence",
        ),
        (
            "product combined readiness evidence",
            "Combine one guarded resource at generation MAX with branch serial MAX and prove both closed readiness "
            "reasons remain observable while CLI guidance names only the independently keyed new-root recovery path, "
            "never an unavailable fresh branch on the exhausted root",
        ),
    )
    for label, required in required_architecture:
        require(
            normalized_architecture.count(required) == 1,
            f"incarnation allocator architecture contract missing or duplicated: {label}",
        )
    for label, required in required_product:
        require(
            normalized_product.count(required) == 1,
            f"incarnation allocator product contract missing or duplicated: {label}",
        )


def check_upgrade_exit_capacity_prose(product: str, architecture: str) -> None:
    normalized_product = normalized_prose(product)
    normalized_architecture = normalized_prose(architecture)
    required_architecture = (
        (
            "prepare binding before coordinator",
            "Still before the first coordinator or hold, the actor acquires the transition gate and "
            "journal-publication lock, revalidates A-11.5's pre-existing-hold, header, serial, clock, drain, pointer, "
            "and plan facts, and computes the canonical `upgrade_exit_capacity_binding`",
        ),
        (
            "four protected roles",
            "maximum encoded bytes and entries for exactly four protected phase roles: one complete-plan "
            "`upgrade.migrate`, one ordinary `upgrade.activate`, one dedicated `upgrade.rollback`, and one "
            "`upgrade.activate` forward repair",
        ),
        (
            "complete path maximum",
            "This conservative sum explicitly includes migrate → rollback serial burn → authenticated mismatch → "
            "durable divergence → forward repair; consuming the rollback role cannot remove the repair role or shared "
            "projection",
        ),
        (
            "capacity failure before effect",
            "If the complete bound cannot fit the ordinary checkpoint entry or byte limit, prepare returns `503 "
            "control_capacity` before fixed-root intent, coordinator, hold, operator-admission, journal, or selected-"
            "state mutation",
        ),
        (
            "binding durable before selected coordinator",
            "One authenticated fixed-root prepare-intent publication makes the binding durable before the selected "
            "coordinator transaction",
        ),
        (
            "plan-bound journal format",
            "Its plan digest, fixed-root journal format, framing, MAC-key format, per-role codec versions, per-role "
            "entry/byte maxima, consumed-role bitmap, reserved total, and release condition are part of the checkpoint "
            "projection and open-upgrade transcript. A continuation binary must support and write that exact bound "
            "format; an incompatible version fails before role consumption and leaves compatible continuation or "
            "rollback authority intact",
        ),
        (
            "unrelated admission accounting",
            "Every unconsumed reserved byte and entry is charged as occupied for unrelated ordinary admission",
        ),
        (
            "role consumption bypasses readmission",
            "A protected phase command atomically converts only its named reservation into actual projection and "
            "does not repeat ordinary- capacity admission",
        ),
        (
            "dedicated rollback role",
            "migrate, ordinary activation, or forward repair can never consume the dedicated rollback role",
        ),
        (
            "fold preservation",
            "Folding preserves the binding semantically and cannot shrink, discard, or reassign it",
        ),
        (
            "post-watermark release",
            "After the watermark, unused binding is released only when the selected-state activation, rollback, or "
            "forward-repair mirror is durable and the fixed root records the same phase exit",
        ),
        (
            "post-burn rollback recovery",
            "Every rollback source, plan, capacity, allocator, certificate, and witness validation that can reject "
            "runs before its allocator transaction burns the serial. Once burned, a filesystem or durability prefix "
            "remains nonterminal and exact same-command recovery must finish it using the bound rollback role",
        ),
        (
            "fixed-root registry binding",
            "The sole cross-operation ordinary-capacity reservation is A-10.7's `upgrade_exit_capacity_binding`. "
            "`upgrade.prepare` is therefore in the exact fixed-root-journaled operation registry even though its "
            "selected coordinator begins in normal mode",
        ),
        (
            "journal projection format binding",
            "it fixes the target plan digest, exact fixed-root journal format/framing/MAC-key format, per-role codec "
            "versions, and exact maxima and consumed state for the migrate, ordinary-activate, dedicated-rollback, and "
            "forward-repair roles. A binary with an incompatible bound format rejects continuation before consuming a "
            "role and preserves the prior bytes and compatible rollback/recovery authority",
        ),
        (
            "deployment format guard",
            "The switched successor must support the plan-bound fixed-root journal format, framing, MAC-key format, "
            "and per-role codec versions or fail held before any role conversion; format migration cannot occur inside "
            "an open rollback-eligible phase",
        ),
        (
            "authenticated role conversion",
            "Role consumption is one atomic authenticated image replacement and bypasses a second ordinary-capacity "
            "decision without borrowing reconciliation space. The rollback role is not fungible",
        ),
        (
            "binding release authority",
            "Prepare failure before a watermark or a durable phase-ending selected-state mirror plus matching fixed-"
            "root terminal publication is the only release authority",
        ),
        (
            "capacity failure matrix",
            "Upgrade prepare cannot fit complete exit capacity | `control_capacity` before fixed-root intent, "
            "coordinator, or hold | Exact-fit sum protects migrate, activation, dedicated rollback, rollback-mismatch "
            "divergence/repair, and the plan-bound journal format through one durable phase exit",
        ),
        (
            "capacity evidence",
            "Upgrade-exit-capacity evidence derives the complete binding independently from the closed plan and codec "
            "maxima, then crosses the ordinary entry and byte boundaries by one. Rejection proves byte-identical fixed-"
            "root, selected-state, coordinator, hold, admission, and allocator state. Exact fit publishes one "
            "authenticated binding before the selected coordinator",
        ),
    )
    required_product = (
        (
            "product prepare binding",
            "Before creating its first coordinator or hold, under the transition gate and journal-publication lock, "
            "prepare MUST project and durably bind the complete worst-case fixed-root ordinary capacity from its own "
            "command record through phase exit",
        ),
        (
            "product four roles",
            "The reserved total is the prepare record plus the sum of the maximum encoded bytes and entries for exactly "
            "four protected roles—one complete-plan `upgrade.migrate`, one ordinary `upgrade.activate`, one "
            "`upgrade.rollback` that no other role may consume, and one `upgrade.activate` forward-repair command—plus "
            "the maximum shared divergence, resolution, and lasting-provenance projection",
        ),
        (
            "product rollback-divergence composition",
            "This conservative sum explicitly covers migrate → rollback serial burn → authenticated mismatch → "
            "durable divergence → forward repair; consuming the rollback role never removes the still-required repair "
            "role or shared projection",
        ),
        (
            "product journal-format binding",
            "The plan digest and binding include the exact fixed-root journal format, framing, MAC-key format, and per-"
            "role codec versions used to derive those maxima. A successor binary that cannot continue that exact format "
            "MUST fail before consuming any role; it may use an explicitly compatible writer or leave rollback/recovery "
            "authority intact, never reinterpret the reservation under a new encoding",
        ),
        (
            "product unrelated accounting",
            "The authenticated `upgrade_exit_capacity_binding` counts every unconsumed byte and entry as occupied "
            "against unrelated ordinary admission",
        ),
        (
            "product terminal release",
            "Unused capacity is released only by the fixed-root publication that records prepare failure before a "
            "watermark or a completed activation, rollback, or forward repair after its selected-state mirror is durable",
        ),
        (
            "product rollback recovery",
            "Every rollback validation capable of rejection precedes the serial burn. After a burn, an incomplete "
            "rollback remains nonterminal and same-command recoverable, or an authenticated mismatch consumes the bound "
            "divergence/forward-repair path; it never terminalizes while retaining rollback eligibility with neither path",
        ),
        (
            "product journal capacity binding",
            "The only cross-operation ordinary-capacity reservation is the authenticated "
            "`upgrade_exit_capacity_binding` created by fixed-root-journaled `upgrade.prepare` before its selected "
            "coordinator or hold",
        ),
        (
            "product binding corruption",
            "A missing, under-sized, reassigned, or prematurely released binding while its phase remains open is fixed-"
            "root corruption",
        ),
        (
            "product capacity evidence",
            "Fill the ordinary fixed-root projection to the exact byte and entry boundaries around the canonical "
            "complete-exit calculation. One byte or entry short makes prepare return `control_capacity` before fixed-"
            "root intent, coordinator, hold, or selected-state mutation; the exact-fit control durably binds prepare "
            "plus all four protected roles",
        ),
        (
            "product journal-format evidence",
            "Bind the plan to the exact fixed-root journal format, framing, MAC-key format, and per-role codecs; start "
            "a successor binary with each incompatible version in turn and prove it fails before role consumption "
            "while compatible continuation or rollback authority remains intact",
        ),
    )
    for label, required in required_architecture:
        require(
            normalized_architecture.count(required) == 1,
            f"upgrade exit capacity architecture contract missing or duplicated: {label}",
        )
    for label, required in required_product:
        require(
            normalized_product.count(required) == 1,
            f"upgrade exit capacity product contract missing or duplicated: {label}",
        )
    scope_expectations = (
        (
            "product PR-146",
            product,
            "- **PR-146.**",
            "- **PR-147.**",
            "ec117cded7d16af58d1c6eab7188ee905fc1a2970a2b56b1603723eb4924e18e",
        ),
        (
            "product PR-150",
            product,
            "- **PR-150.**",
            "\n## P-15.",
            "18a0ef4601a9ca2416684d2a2d6162ce3c83450bd62ac24ce2dfa2f026f5883a",
        ),
        (
            "architecture A-10.7",
            architecture,
            "### A-10.7.",
            "\n## A-11.",
            "e12997eec0ff1e1cf3cfdf070d68e1f65842fe72b23c782ddf1b892d99284ece",
        ),
        (
            "architecture A-13.2",
            architecture,
            "### A-13.2. Secret and key material",
            "\n### A-13.3.",
            "475a256bd918b0971596df8058c18fdac630d477e37f9611d349439cc69d448e",
        ),
    )
    for label, document, start_marker, end_marker, expected_digest in scope_expectations:
        require(
            normalized_scope_sha256(document, start_marker, end_marker, label)
            == expected_digest,
            f"upgrade exit capacity normalized scope digest mismatch: {label}",
        )


def check_evidence_parity_prose(product: str, architecture: str) -> None:
    normalized_product = normalized_prose(product)
    normalized_architecture = normalized_prose(architecture)
    factorization = " + ".join(
        f"{count:,} {label}" for label, count in EXPECTED_MUTATION_EVIDENCE
    )
    product_claims = (
        f"all {EXPECTED_MUTATION_ROUTES} static call sites",
        f"The complete arithmetic is {factorization} = "
        f"{EXPECTED_MUTATION_TOTAL:,} rejected mutations;",
    )
    architecture_claims = (
        f"all {EXPECTED_MUTATION_ROUTES} static rejection sites",
        f"independent harness rejects all {EXPECTED_MUTATION_TOTAL:,} named mutations",
        f"The total is {factorization} = {EXPECTED_MUTATION_TOTAL:,}.",
    )
    for claim in product_claims:
        require(
            normalized_product.count(claim) == 1,
            f"evidence parity product claim missing or duplicated: {claim}",
        )
    for claim in architecture_claims:
        require(
            normalized_architecture.count(claim) == 1,
            f"evidence parity architecture claim missing or duplicated: {claim}",
        )


@lru_cache(maxsize=1)
def load_release_identity() -> dict[str, object]:
    with RELEASE_IDENTITY_PATH.open("rb") as handle:
        return tomllib.load(handle)


def normalize_release_newlines(document: str) -> str:
    return document.replace("\r\n", "\n").replace("\r", "\n")


def canonical_release_document(document: str, label: str) -> bytes:
    # The canonical spec checker and the extractor must call the same release
    # canonicalizer and agree on CRLF/lone-CR and terminal-LF-run normalization:
    # a terminal LF run accepted and reduced to one by extraction is not rejected
    # here.  ``spec_structure.canonicalize_release`` is that single canonicalizer.
    import spec_structure

    try:
        encoded = document.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError(f"release identity document is not strict UTF-8: {label}") from error
    return spec_structure.canonicalize_release(encoded)


def check_release_identity(
    product: str,
    architecture: str,
    operations: dict[str, object],
    identity: dict[str, object],
) -> None:
    require(isinstance(identity, dict), "release identity must be a table")
    fields = set(identity)
    require(
        fields == RELEASE_IDENTITY_FIELDS,
        "release identity top-level field mismatch; "
        f"missing={sorted(RELEASE_IDENTITY_FIELDS-fields)}, "
        f"unknown={sorted(fields-RELEASE_IDENTITY_FIELDS)}",
    )
    require(
        type(identity.get("manifest_version")) is int
        and identity["manifest_version"] == RELEASE_IDENTITY_VERSION,
        f"release identity manifest_version must be {RELEASE_IDENTITY_VERSION}",
    )
    require(
        isinstance(identity.get("canonicalization"), str)
        and identity["canonicalization"] == RELEASE_IDENTITY_CANONICALIZATION,
        "release identity canonicalization must be "
        f"{RELEASE_IDENTITY_CANONICALIZATION!r}",
    )

    documents = identity.get("document")
    require(
        isinstance(documents, list) and len(documents) == 2,
        "release identity must contain exactly two document entries",
    )
    product_version = operations.get("product_spec")
    architecture_version = operations.get("architecture_spec")
    require(
        isinstance(product_version, str) and isinstance(architecture_version, str),
        "release identity requires validated specification versions",
    )
    expected_documents = (
        ("specs/product.md", product_version, product),
        ("specs/architecture.md", architecture_version, architecture),
    )
    for index, (expected_path, expected_version, source) in enumerate(expected_documents):
        entry = documents[index]
        require(
            isinstance(entry, dict),
            f"release identity document entry {index} must be a table",
        )
        entry_fields = set(entry)
        require(
            entry_fields == RELEASE_IDENTITY_DOCUMENT_FIELDS,
            f"release identity document field mismatch at {index}; "
            f"missing={sorted(RELEASE_IDENTITY_DOCUMENT_FIELDS-entry_fields)}, "
            f"unknown={sorted(entry_fields-RELEASE_IDENTITY_DOCUMENT_FIELDS)}",
        )
        require(
            entry.get("path") == expected_path,
            f"release identity document path mismatch at {index}",
        )
        require(
            entry.get("version") == expected_version,
            f"release identity document version mismatch: {expected_path}",
        )
        digest = entry.get("sha256")
        require(
            isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
            f"release identity document digest is malformed: {expected_path}",
        )
        actual_digest = hashlib.sha256(
            canonical_release_document(source, expected_path)
        ).hexdigest()
        require(
            digest == actual_digest,
            f"release identity document digest mismatch: {expected_path}",
        )


def check_document_versions(
    product: str, architecture: str, operations: dict[str, object]
) -> None:
    product_spec = operations.get("product_spec")
    architecture_spec = operations.get("architecture_spec")
    require(isinstance(product_spec, str), "product_spec must be a string")
    require(isinstance(architecture_spec, str), "architecture_spec must be a string")
    product_metadata = metadata_values(product, PRODUCT_METADATA_FIELDS)
    architecture_metadata = metadata_values(architecture, ARCHITECTURE_METADATA_FIELDS)
    require(product_metadata["Specification version"] == product_spec, "product version mismatch")
    require(
        architecture_metadata["Architecture version"] == architecture_spec,
        "architecture version mismatch",
    )
    require(
        architecture_metadata["Product contract"] == f"specs/product.md {product_spec}",
        "architecture product reference mismatch",
    )


def check_task0137_selected_meta_prose(architecture: str) -> None:
    require(
        architecture.count("Bootstrap and stopped-state clone production write\nthe pointer mirror before final checkpoint/close. Their sealing postcondition incorporates committed source\nWAL content and prevents WAL/SHM from changing the ensuing descriptor-bound read-only view.") == 1,
        "Task 0137 A-10.1 producer/sealing contract missing or duplicated",
    )
    require(
        architecture.count("Only the coordinator-borrowed candidate may open `state.sqlite3` relative to itself with `O_RDONLY`, `O_NOFOLLOW`, and `O_CLOEXEC`; fstat requires a current-euid-owned mode-`0600` single-link regular file. Its same-descriptor private sealed-image observation establishes checkpoint/close after the pointer mirror write and that WAL/SHM cannot alter the read-only view. The exact singleton-meta equality fact is private and nonterminal, never selection or completeness. The future internal sealing adapter is [PENDENTE: Task0146/0147 pointer-authenticator ownership]; no crate, FFI/VFS implementation, sealing RED, selected-meta comparison, or root-side substitute is authorized until its source-first reentry condition closes.") == 2,
        "Task 0137 descriptor/sealed-image contract missing or duplicated",
    )
    require(
        architecture.count("The singleton `meta` row contains exactly `active_state_pointer_certificate_digest BLOB NOT NULL CHECK(typeof(active_state_pointer_certificate_digest) = 'blob' AND length(active_state_pointer_certificate_digest) = 32 AND active_state_pointer_certificate_digest <> zeroblob(32))`.") == 1,
        "Task 0137 singleton meta contract missing or duplicated",
    )
    require(
        architecture.count("SELECT active_state_pointer_certificate_digest FROM meta WHERE singleton = 1") == 1,
        "Task 0137 exact singleton query missing or duplicated",
    )


def check_task0148_sealing_deferral_prose(architecture: str) -> None:
    require(architecture.count("[PENDENTE: Task0146/0147 pointer-authenticator ownership]") == 2, "Task 0148 deferral missing or duplicated")
    require(architecture.count("no current implementation or comparison may claim them") == 1, "Task 0148 sealing deferral missing")




def check_task0251_bootstrap_envelope_identity(architecture: str) -> None:
    heading = "#### A-13.1.1. Release bootstrap envelope v1"
    start = architecture.find(heading)
    require(start >= 0 and architecture.find(heading, start + 1) < 0, "Task 0251 bootstrap envelope heading")
    end = architecture.find("Parsing produces immutable `ValidatedConfig`", start)
    require(end >= 0, "Task 0251 bootstrap envelope boundary")
    require(architecture[start:end] == '#### A-13.1.1. Release bootstrap envelope v1\n\nThe only release bootstrap source is the root-controlled TOML file\n`/etc/msgriver/bootstrap.toml`. It has no tables and exactly these six\ntop-level keys, with no unknown or duplicate key accepted:\n\n```toml\nversion = 1\nstate_root = "/srv/msgriver/data"\nservice_user = "msgriver"\ncredential_root = "/run/credentials/msgriver"\nsocket_names = []\nresource_ceiling_profile = "baseline-v1"\n```\n\n`version` is integer `1`. The other scalars are UTF-8 TOML strings;\n`socket_names` is exactly the empty TOML string array in v1. `state_root` and\n`credential_root` must match the displayed absolute spelling exactly: no\nrelative path, dot component, trailing slash, NUL or alternate spelling is\naccepted. `service_user` is exactly the closed literal `msgriver`; it never\nresolves through NSS, passwd, nscd, sssd or a supplementary-group lookup. The\nexisting non-root validation owns the effective UID check. `baseline-v1` is the\nsole compiled resource-ceiling profile and means the existing no-core/\nnon-dumpable process policy. A later ADR must define every listener socket name\nand compiled profile before either field can broaden.\n\nThe parent `/etc/msgriver` is a real directory owned by the compiled expected\nUID and the effective GID, mode `0750`. The envelope is a single-link regular\nfile owned by that same pair, mode `0640`, no larger than 4096 bytes. Startup\nvalidates parent/file metadata, opens no-follow, and requires before/open/after\ndevice, inode and metadata identity to agree. Missing, symlinked, hard-linked,\nnonregular, wrong-owner, wrong-group, broader-mode, oversized, malformed,\nincomplete, duplicate, unknown or replaced input fails closed before owner-lock\nacquisition.\n\nThe envelope contains neither a secret/secret-reference name nor operational\nconfiguration. In v1 `credential_root` is structural metadata only and is not\nopened; the empty socket set grants no socket authority. The binary accepts no\nenvironment, CLI, current-directory, search-path, include, interpolation or\nalternate bootstrap source. After process policy and non-root validation, a\nvalid envelope may supply only the fixed root to the existing trusted-root and\nowner-lock primitives; execution remains unavailable at `SelectedState`.\nIt does not select/open state, read credentials, bind/listen, select\noperational configuration, start a worker, or enable provider/ntfy authority.\nAll failures retain the fixed redacted non-ready diagnostic.\n\n', "Task 0251 bootstrap envelope identity altered or broadened")


def check_all(
    product: str,
    architecture: str,
    operations: dict[str, object],
    release_identity: dict[str, object] | None = None,
) -> None:
    semantic_product = normalize_release_newlines(product)
    semantic_architecture = normalize_release_newlines(architecture)
    check_task0183_phase_zero_planned_prose(semantic_product, semantic_architecture)
    check_task0251_bootstrap_envelope_identity(semantic_architecture)
    check_task0148_sealing_deferral_prose(semantic_architecture)
    check_task0137_selected_meta_prose(semantic_architecture)
    check_definitions(semantic_product, semantic_architecture)
    check_operations(operations)
    check_document_versions(semantic_product, semantic_architecture, operations)
    check_maintenance_prose(semantic_architecture)
    check_upgrade_lifecycle_prose(semantic_architecture)
    check_addressed_state_prose(semantic_architecture)
    check_generation_guarded_prose(semantic_architecture)
    check_complete_revision_prose(semantic_product, semantic_architecture)
    check_incarnation_allocator_prose(semantic_product, semantic_architecture)
    check_upgrade_exit_capacity_prose(semantic_product, semantic_architecture)
    check_evidence_parity_prose(semantic_product, semantic_architecture)
    # Structural definition/section identity must reject semantic mutations
    # before the release digest reports the consequential byte mismatch.
    _check_shared_structure_provenance(product, architecture)
    check_release_identity(
        product,
        architecture,
        operations,
        load_release_identity() if release_identity is None else release_identity,
    )


def _check_shared_structure_provenance(product: str, architecture: str) -> None:
    """Cross-validate the shared E5 parser's structural/visible/table provenance.

    Runs the single shared ``parse_spec_structure_v1`` object once over each
    canonical document and confirms its definition, section, table, visible, and
    normative provenance agrees with this checker's own canonical facts. It is
    reached directly from ``check_all`` (not only from ``main`` / a CLI path).
    """
    import spec_structure

    parse = spec_structure.parse_spec_structure_v1
    canonicalize = spec_structure.canonicalize_release
    validate = spec_structure.validate_structure
    def checked_parse(
        source: str, path: str, label: str
    ) -> spec_structure.Structure:
        try:
            struct = parse(canonicalize(source.encode("utf-8")), path)
            # Validate the exact returned object before reading any unit: a
            # caller, wrapper, or test double can alter it after the parser's
            # internal validation, so the identical validator runs here too.
            validate(struct)
        except spec_structure.StructureError as error:
            detail = str(error)
            if label == "architecture" and detail.startswith(
                "skipped heading depth"
            ):
                detail = f"architecture A definition manifest mismatch: {detail}"
            raise ValueError(
                f"shared parser {label} structure failed validation: {detail}"
            ) from None
        return struct

    product_struct = checked_parse(product, "specs/product.md", "product")
    architecture_struct = checked_parse(
        architecture, "specs/architecture.md", "architecture"
    )
    for struct, label in ((product_struct, "product"), (architecture_struct, "architecture")):
        require(
            bool(struct.units) and struct.units[0].kind == "document",
            f"shared parser produced no document unit for {label}",
        )
    product_definition_units = [
        u for u in product_struct.units if u.kind == "definition"
    ]
    architecture_definition_units = [
        u for u in architecture_struct.units if u.kind == "definition"
    ]
    product_defs = {u.definition_id for u in product_definition_units}
    arch_defs = {u.definition_id for u in architecture_definition_units}
    expected_product_defs = (
        EXPECTED_IDS["PR"] | EXPECTED_IDS["AC"] | EXPECTED_PRODUCT_NON_GOALS
    )
    require(
        len(product_definition_units) == len(expected_product_defs)
        and product_defs == expected_product_defs,
        "shared parser product definition manifest mismatch",
    )
    require(
        len(architecture_definition_units) == len(EXPECTED_IDS["INV"])
        and arch_defs == EXPECTED_IDS["INV"],
        "shared parser architecture definition manifest mismatch",
    )
    # Section provenance: the parser finds exactly the headings this checker
    # recognizes, in both documents.  Equality rejects invented parser units as
    # well as omissions.
    product_sections = {
        u.section_chain[-1][2] for u in product_struct.units if u.kind == "section"
    }
    arch_sections = {
        u.section_chain[-1][2] for u in architecture_struct.units if u.kind == "section"
    }
    require(
        product_sections == EXPECTED_PRODUCT_SECTIONS,
        "shared parser product section provenance differs from canonical facts",
    )
    require(
        len([u for u in architecture_struct.units if u.kind == "section"])
        == len(EXPECTED_IDS["A"])
        and arch_sections == EXPECTED_IDS["A"],
        "shared parser architecture A definition manifest mismatch",
    )
    # Table provenance.
    arch_tables = [u for u in architecture_struct.units if u.kind == "table"]
    require(bool(arch_tables), "shared parser found no architecture table")
    arch_rows = [u for u in architecture_struct.units if u.kind == "table_row"]
    require(
        bool(arch_rows) and all(bool(u.visible_bytes) for u in arch_rows),
        "shared parser produced table rows without visible provenance",
    )
    # Visible provenance: every clause carries non-empty visible bytes.
    product_clauses = [u for u in product_struct.units if u.kind == "clause"]
    require(
        bool(product_clauses) and all(bool(u.visible_bytes) for u in product_clauses),
        "shared parser produced clauses without visible provenance",
    )
    # Normative provenance.
    require(
        any(u.kind == "clause" and u.normative for u in product_struct.units),
        "shared parser found no normative product clause",
    )



# Task 0183 adds Planned sections only; normal operation/definition manifests remain closed.
EXPECTED_PRODUCT_SECTIONS = EXPECTED_PRODUCT_SECTIONS | {"P-05.4"}
EXPECTED_IDS = {**EXPECTED_IDS, "A": EXPECTED_IDS["A"] | {"A-21"}}

def check_task0183_phase_zero_planned_prose(product: str, architecture: str) -> None:
    for marker in ("Planned", "P0R-001", "P0R-002", "P0R-003", "P0R-004", "P0R-010", "P0R-011", "P0R-012", "P0R-013", "P0R-014", "P0R-020", "P0R-021", "P0R-022", "P0R-023", "P0R-024", "P0R-030", "P0R-031", "P0R-032", "P0R-040", "P0R-041"):
        require(marker in product, f"Task 0183 Planned product marker missing: {marker}")
    for marker in ("P0-A0-001", "P0-A0-002", "P0-A0-003", "P0-A0-004", "P0-A0-005", "P0-A0-006"):
        require(marker in architecture, f"Task 0183 Planned architecture marker missing: {marker}")
    require("The following Task 0175 requirements are Planned, individually represented source contracts;" in product, "Task 0183 product Planned boundary missing")
    require("## A-21. Planned Phase 0 provider ingress" in architecture, "Task 0183 architecture Planned boundary missing")
    require("they authorize neither provider support nor an implementation." in product, "Task 0183 Planned/no-support boundary missing")

def main() -> int:
    try:
        product = PRODUCT_PATH.read_text(encoding="utf-8")
        architecture = ARCHITECTURE_PATH.read_text(encoding="utf-8")
        with OPERATIONS_PATH.open("rb") as handle:
            operations = tomllib.load(handle)
        check_all(product, architecture, operations)
    except (OSError, tomllib.TOMLDecodeError, ValueError) as error:
        print(f"spec check failed: {error}", file=sys.stderr)
        return 1
    print(
        "spec check passed: 103 PR, 68 AC, 12 INV, 93 A, 70 operations, "
        "23 maintenance, 15 fixed-root, 3 upgrade lifecycle, 2 addressed-state, "
        "5 generation-guarded, 1 branch-incarnation allocator, 1 upgrade-exit-capacity contract, 107 codecs, "
        "70 frozen policies and surfaces, 8,302 mutation evidence through 78 routes"
    )
    return 0


def __getattr__(name: str):
    """Expose the shared E5 parser object (lazy import; no module-level cycle)."""
    if name == "parse_spec_structure_v1":
        import spec_structure

        return spec_structure.parse_spec_structure_v1
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if __name__ == "__main__":
    raise SystemExit(main())
