# Task 0010 v2 DDL contract — message and idempotency fragment

This is executable SQLite DDL contract text, but not production migration code
and not a partial schema release. It is the first executable fragment of the
complete v2 contract required before the frozen RED suite. The remaining v2
tables must be appended to this same contract before it can be embedded in the
migration catalog.

```sql
CREATE TABLE principals (
    principal_id TEXT PRIMARY KEY CHECK(length(principal_id) > 0),
    display_name TEXT NOT NULL CHECK(length(display_name) > 0),
    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
    scope_mask INTEGER NOT NULL CHECK((scope_mask & ~15) = 0 AND ((scope_mask & 8) = 0 OR (scope_mask & 7) = 7)),
    max_outstanding_messages INTEGER NOT NULL CHECK(max_outstanding_messages > 0),
    max_outstanding_payload_bytes INTEGER NOT NULL CHECK(max_outstanding_payload_bytes > 0),
    accepted_rate_capacity INTEGER NOT NULL CHECK(accepted_rate_capacity > 0),
    accepted_rate_refill_per_second INTEGER NOT NULL CHECK(accepted_rate_refill_per_second > 0),
    resource_incarnation BLOB NOT NULL CHECK(length(resource_incarnation) = 32),
    principal_generation_hi INTEGER NOT NULL CHECK(principal_generation_hi BETWEEN 0 AND 4294967295),
    principal_generation_lo INTEGER NOT NULL CHECK(principal_generation_lo BETWEEN 0 AND 4294967295),
    principal_receipt_incarnation BLOB,
    principal_receipt_prior_hi INTEGER,
    principal_receipt_prior_lo INTEGER,
    principal_receipt_result_hi INTEGER,
    principal_receipt_result_lo INTEGER,
    principal_receipt_actor_namespace TEXT,
    principal_receipt_operation TEXT,
    principal_receipt_desired_state TEXT,
    principal_receipt_reason TEXT,
    principal_receipt_result_ref TEXT,
    grant_generation_hi INTEGER NOT NULL CHECK(grant_generation_hi BETWEEN 0 AND 4294967295),
    grant_generation_lo INTEGER NOT NULL CHECK(grant_generation_lo BETWEEN 0 AND 4294967295),
    grant_receipt_incarnation BLOB,
    grant_receipt_prior_hi INTEGER,
    grant_receipt_prior_lo INTEGER,
    grant_receipt_result_hi INTEGER,
    grant_receipt_result_lo INTEGER,
    grant_receipt_actor_namespace TEXT,
    grant_receipt_operation TEXT,
    grant_receipt_desired_state TEXT,
    grant_receipt_reason TEXT,
    grant_receipt_result_ref TEXT,
    CHECK(principal_generation_hi != 0 OR principal_generation_lo != 0),
    CHECK(grant_generation_hi != 0 OR grant_generation_lo != 0),
    CHECK(
        (principal_receipt_incarnation IS NULL AND principal_receipt_prior_hi IS NULL AND principal_receipt_prior_lo IS NULL AND principal_receipt_result_hi IS NULL AND principal_receipt_result_lo IS NULL AND principal_receipt_actor_namespace IS NULL AND principal_receipt_operation IS NULL AND principal_receipt_desired_state IS NULL AND principal_receipt_reason IS NULL AND principal_receipt_result_ref IS NULL)
        OR
        (principal_receipt_incarnation IS NOT NULL AND principal_receipt_prior_hi IS NOT NULL AND principal_receipt_prior_lo IS NOT NULL AND principal_receipt_result_hi IS NOT NULL AND principal_receipt_result_lo IS NOT NULL AND principal_receipt_actor_namespace IS NOT NULL AND principal_receipt_operation IS NOT NULL AND principal_receipt_desired_state IS NOT NULL AND principal_receipt_reason IS NOT NULL AND principal_receipt_result_ref IS NOT NULL)
    ),
    CHECK(
        (grant_receipt_incarnation IS NULL AND grant_receipt_prior_hi IS NULL AND grant_receipt_prior_lo IS NULL AND grant_receipt_result_hi IS NULL AND grant_receipt_result_lo IS NULL AND grant_receipt_actor_namespace IS NULL AND grant_receipt_operation IS NULL AND grant_receipt_desired_state IS NULL AND grant_receipt_reason IS NULL AND grant_receipt_result_ref IS NULL)
        OR
        (grant_receipt_incarnation IS NOT NULL AND grant_receipt_prior_hi IS NOT NULL AND grant_receipt_prior_lo IS NOT NULL AND grant_receipt_result_hi IS NOT NULL AND grant_receipt_result_lo IS NOT NULL AND grant_receipt_actor_namespace IS NOT NULL AND grant_receipt_operation IS NOT NULL AND grant_receipt_desired_state IS NOT NULL AND grant_receipt_reason IS NOT NULL AND grant_receipt_result_ref IS NOT NULL)
    ),
    CHECK(
        (principal_receipt_incarnation IS NULL AND principal_receipt_prior_hi IS NULL AND principal_receipt_prior_lo IS NULL AND principal_receipt_result_hi IS NULL AND principal_receipt_result_lo IS NULL AND principal_receipt_actor_namespace IS NULL AND principal_receipt_operation IS NULL AND principal_receipt_desired_state IS NULL AND principal_receipt_reason IS NULL AND principal_receipt_result_ref IS NULL)
        OR
        (length(principal_receipt_incarnation) = 32 AND principal_receipt_incarnation = resource_incarnation AND principal_receipt_prior_hi BETWEEN 0 AND 4294967295 AND principal_receipt_prior_lo BETWEEN 0 AND 4294967295 AND principal_receipt_result_hi BETWEEN 0 AND 4294967295 AND principal_receipt_result_lo BETWEEN 0 AND 4294967295 AND (principal_receipt_prior_hi != 0 OR principal_receipt_prior_lo != 0) AND (principal_receipt_result_hi != 0 OR principal_receipt_result_lo != 0) AND ((principal_receipt_result_hi = principal_receipt_prior_hi AND principal_receipt_result_lo = principal_receipt_prior_lo + 1) OR (principal_receipt_result_hi = principal_receipt_prior_hi + 1 AND principal_receipt_result_lo = 0 AND principal_receipt_prior_lo = 4294967295)) AND principal_receipt_result_hi = principal_generation_hi AND principal_receipt_result_lo = principal_generation_lo AND length(principal_receipt_actor_namespace) > 0 AND length(principal_receipt_operation) > 0 AND length(principal_receipt_desired_state) > 0 AND length(principal_receipt_reason) > 0 AND length(principal_receipt_result_ref) > 0)
    ),
    CHECK(
        (grant_receipt_incarnation IS NULL AND grant_receipt_prior_hi IS NULL AND grant_receipt_prior_lo IS NULL AND grant_receipt_result_hi IS NULL AND grant_receipt_result_lo IS NULL AND grant_receipt_actor_namespace IS NULL AND grant_receipt_operation IS NULL AND grant_receipt_desired_state IS NULL AND grant_receipt_reason IS NULL AND grant_receipt_result_ref IS NULL)
        OR
        (length(grant_receipt_incarnation) = 32 AND grant_receipt_incarnation = resource_incarnation AND grant_receipt_prior_hi BETWEEN 0 AND 4294967295 AND grant_receipt_prior_lo BETWEEN 0 AND 4294967295 AND grant_receipt_result_hi BETWEEN 0 AND 4294967295 AND grant_receipt_result_lo BETWEEN 0 AND 4294967295 AND (grant_receipt_prior_hi != 0 OR grant_receipt_prior_lo != 0) AND (grant_receipt_result_hi != 0 OR grant_receipt_result_lo != 0) AND ((grant_receipt_result_hi = grant_receipt_prior_hi AND grant_receipt_result_lo = grant_receipt_prior_lo + 1) OR (grant_receipt_result_hi = grant_receipt_prior_hi + 1 AND grant_receipt_result_lo = 0 AND grant_receipt_prior_lo = 4294967295)) AND grant_receipt_result_hi = grant_generation_hi AND grant_receipt_result_lo = grant_generation_lo AND length(grant_receipt_actor_namespace) > 0 AND length(grant_receipt_operation) > 0 AND length(grant_receipt_desired_state) > 0 AND length(grant_receipt_reason) > 0 AND length(grant_receipt_result_ref) > 0)
    )
);

CREATE TRIGGER principals_id_immutable
BEFORE UPDATE OF principal_id ON principals
BEGIN
    SELECT RAISE(ABORT, 'principal identifier is immutable');
END;

CREATE TABLE principal_provider_grants (
    principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    provider_id TEXT NOT NULL REFERENCES providers(provider_id) ON DELETE RESTRICT,
    PRIMARY KEY (principal_id, provider_id)
);

CREATE TABLE peer_mappings (
    mapping_id TEXT PRIMARY KEY CHECK(length(mapping_id) > 0),
    uid INTEGER NOT NULL UNIQUE CHECK(uid BETWEEN 0 AND 4294967295),
    principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    scope_mask INTEGER NOT NULL CHECK((scope_mask & ~15) = 0 AND ((scope_mask & 8) = 0 OR (scope_mask & 7) = 7)),
    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
    status TEXT NOT NULL CHECK(status IN ('active', 'suspended')),
    mapping_generation_hi INTEGER NOT NULL CHECK(mapping_generation_hi BETWEEN 0 AND 4294967295),
    mapping_generation_lo INTEGER NOT NULL CHECK(mapping_generation_lo BETWEEN 0 AND 4294967295),
    CHECK((enabled = 1) = (status = 'active')),
    CHECK(mapping_generation_hi != 0 OR mapping_generation_lo != 0)
);

CREATE INDEX peer_mappings_principal_idx ON peer_mappings (principal_id, enabled, uid);

CREATE TRIGGER peer_mappings_id_immutable
BEFORE UPDATE OF mapping_id ON peer_mappings
BEGIN
    SELECT RAISE(ABORT, 'peer mapping identifier is immutable');
END;

CREATE TRIGGER peer_mappings_preserve_last_local_operator_on_delete
BEFORE DELETE ON peer_mappings
WHEN OLD.uid = 0
  AND OLD.enabled = 1
  AND (OLD.scope_mask & 8) = 8
  AND EXISTS (
      SELECT 1 FROM principals AS principal
      WHERE principal.principal_id = OLD.principal_id
        AND principal.enabled = 1
        AND (principal.scope_mask & 8) = 8
  )
  AND NOT EXISTS (
      SELECT 1
      FROM peer_mappings AS mapping
      JOIN principals AS principal ON principal.principal_id = mapping.principal_id
      WHERE mapping.mapping_id <> OLD.mapping_id
        AND mapping.uid = 0
        AND mapping.enabled = 1
        AND (mapping.scope_mask & 8) = 8
        AND principal.enabled = 1
        AND (principal.scope_mask & 8) = 8
  )
BEGIN
    SELECT RAISE(ABORT, 'last_local_operator');
END;

CREATE TRIGGER peer_mappings_preserve_last_local_operator_on_update
BEFORE UPDATE OF uid, principal_id, scope_mask, enabled, status ON peer_mappings
WHEN OLD.uid = 0
  AND OLD.enabled = 1
  AND (OLD.scope_mask & 8) = 8
  AND EXISTS (
      SELECT 1 FROM principals AS principal
      WHERE principal.principal_id = OLD.principal_id
        AND principal.enabled = 1
        AND (principal.scope_mask & 8) = 8
  )
  AND NOT (
      (NEW.uid = 0
       AND NEW.enabled = 1
       AND (NEW.scope_mask & 8) = 8
       AND EXISTS (
           SELECT 1 FROM principals AS principal
           WHERE principal.principal_id = NEW.principal_id
             AND principal.enabled = 1
             AND (principal.scope_mask & 8) = 8
       ))
      OR EXISTS (
          SELECT 1
          FROM peer_mappings AS mapping
          JOIN principals AS principal ON principal.principal_id = mapping.principal_id
          WHERE mapping.mapping_id <> OLD.mapping_id
            AND mapping.uid = 0
            AND mapping.enabled = 1
            AND (mapping.scope_mask & 8) = 8
            AND principal.enabled = 1
            AND (principal.scope_mask & 8) = 8
      )
  )
BEGIN
    SELECT RAISE(ABORT, 'last_local_operator');
END;

CREATE TRIGGER principals_preserve_last_local_operator_on_update
BEFORE UPDATE OF enabled, scope_mask ON principals
WHEN OLD.enabled = 1
  AND (OLD.scope_mask & 8) = 8
  AND EXISTS (
      SELECT 1 FROM peer_mappings AS mapping
      WHERE mapping.principal_id = OLD.principal_id
        AND mapping.uid = 0
        AND mapping.enabled = 1
        AND (mapping.scope_mask & 8) = 8
  )
  AND NOT EXISTS (
      SELECT 1
      FROM peer_mappings AS mapping
      JOIN principals AS principal ON principal.principal_id = mapping.principal_id
      WHERE mapping.uid = 0
        AND mapping.enabled = 1
        AND (mapping.scope_mask & 8) = 8
        AND (
            (mapping.principal_id = OLD.principal_id
             AND NEW.enabled = 1
             AND (NEW.scope_mask & 8) = 8)
            OR
            (mapping.principal_id <> OLD.principal_id
             AND principal.enabled = 1
             AND (principal.scope_mask & 8) = 8)
        )
  )
BEGIN
    SELECT RAISE(ABORT, 'last_local_operator');
END;

CREATE TABLE api_keys (
    key_id TEXT PRIMARY KEY CHECK(length(key_id) > 0),
    principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    scope_mask INTEGER NOT NULL CHECK((scope_mask & ~15) = 0 AND ((scope_mask & 8) = 0 OR (scope_mask & 7) = 7)),
    status TEXT NOT NULL CHECK(status IN ('active', 'suspended', 'revoked')),
    created_at_unix_ms INTEGER NOT NULL,
    status_changed_at_unix_ms INTEGER NOT NULL,
    expires_at_unix_ms INTEGER,
    verify_purpose INTEGER NOT NULL CHECK(verify_purpose = 1),
    verify_origin BLOB NOT NULL CHECK(length(verify_origin) = 32),
    verify_serial_hi INTEGER NOT NULL CHECK(verify_serial_hi BETWEEN 0 AND 4294967295),
    verify_serial_lo INTEGER NOT NULL CHECK(verify_serial_lo BETWEEN 0 AND 4294967295),
    verifier BLOB NOT NULL CHECK(length(verifier) = 32),
    CHECK(verify_serial_hi != 0 OR verify_serial_lo != 0),
    CHECK(status_changed_at_unix_ms >= created_at_unix_ms),
    CHECK(expires_at_unix_ms IS NULL OR expires_at_unix_ms >= created_at_unix_ms)
);

CREATE INDEX api_keys_principal_status_idx ON api_keys (principal_id, status, expires_at_unix_ms);

CREATE TABLE configuration_generations (
    configuration_generation INTEGER PRIMARY KEY CHECK(configuration_generation > 0),
    status TEXT NOT NULL CHECK(status IN ('selected', 'retained')),
    canonical_nonsecret_bytes BLOB NOT NULL CHECK(length(canonical_nonsecret_bytes) BETWEEN 1 AND 49152),
    canonical_nonsecret_digest BLOB NOT NULL CHECK(length(canonical_nonsecret_digest) = 32),
    compatibility_report BLOB NOT NULL CHECK(length(compatibility_report) > 0),
    compatibility_report_digest BLOB NOT NULL CHECK(length(compatibility_report_digest) = 32),
    reference_catalog_generation INTEGER NOT NULL CHECK(reference_catalog_generation > 0),
    reference_catalog_digest BLOB NOT NULL CHECK(length(reference_catalog_digest) = 32),
    activated_at_unix_ms INTEGER NOT NULL,
    actor_namespace TEXT NOT NULL CHECK(length(actor_namespace) > 0),
    command_result_ref TEXT NOT NULL CHECK(length(command_result_ref) > 0)
);

CREATE UNIQUE INDEX configuration_generations_one_selected_idx
ON configuration_generations (status)
WHERE status = 'selected';

CREATE TABLE connector_identities (
    connector_identity_id TEXT PRIMARY KEY CHECK(length(connector_identity_id) > 0),
    configuration_generation INTEGER NOT NULL REFERENCES configuration_generations(configuration_generation) ON DELETE RESTRICT,
    driver_id TEXT NOT NULL CHECK(length(driver_id) > 0),
    endpoint_snapshot BLOB NOT NULL CHECK(length(endpoint_snapshot) > 0),
    endpoint_snapshot_digest BLOB NOT NULL CHECK(length(endpoint_snapshot_digest) = 32),
    policy_snapshot BLOB NOT NULL CHECK(length(policy_snapshot) > 0),
    policy_snapshot_digest BLOB NOT NULL CHECK(length(policy_snapshot_digest) = 32),
    credential_reference_name TEXT
);

CREATE TRIGGER connector_identities_immutable
BEFORE UPDATE ON connector_identities
BEGIN
    SELECT RAISE(ABORT, 'connector identity is immutable');
END;

CREATE TABLE providers (
    provider_id TEXT PRIMARY KEY CHECK(length(provider_id) BETWEEN 1 AND 64 AND provider_id GLOB '[a-z]*' AND provider_id NOT GLOB '*[^a-z0-9_-]*'),
    display_name TEXT NOT NULL CHECK(length(display_name) > 0),
    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
    connector_identity_id TEXT NOT NULL UNIQUE REFERENCES connector_identities(connector_identity_id) ON DELETE RESTRICT,
    configuration_generation INTEGER NOT NULL REFERENCES configuration_generations(configuration_generation) ON DELETE RESTRICT
);

CREATE TRIGGER providers_id_immutable
BEFORE UPDATE OF provider_id ON providers
BEGIN
    SELECT RAISE(ABORT, 'provider identifier is immutable');
END;

CREATE TABLE messages (
    message_id TEXT PRIMARY KEY CHECK(length(message_id) > 0),
    owner_principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    provider_id TEXT NOT NULL REFERENCES providers(provider_id) ON DELETE RESTRICT,
    connector_identity_id TEXT NOT NULL REFERENCES connector_identities(connector_identity_id) ON DELETE RESTRICT,
    configuration_generation INTEGER NOT NULL REFERENCES configuration_generations(configuration_generation) ON DELETE RESTRICT,
    destination_schema_id TEXT NOT NULL CHECK(length(destination_schema_id) > 0),
    destination_kind TEXT NOT NULL CHECK(length(destination_kind) > 0),
    destination_schema_version INTEGER NOT NULL CHECK(destination_schema_version BETWEEN 1 AND 4294967295),
    destination_payload BLOB,
    content_schema_id TEXT NOT NULL CHECK(length(content_schema_id) > 0),
    content_kind TEXT NOT NULL CHECK(length(content_kind) > 0),
    content_schema_version INTEGER NOT NULL CHECK(content_schema_version BETWEEN 1 AND 4294967295),
    content_payload BLOB,
    options_schema_id TEXT,
    options_kind TEXT,
    options_schema_version INTEGER,
    options_payload BLOB,
    state TEXT NOT NULL CHECK(state IN ('queued', 'held', 'delivering', 'retry_scheduled', 'provider_accepted', 'failed', 'cancelled', 'expired')),
    hold_reason TEXT CHECK(hold_reason IS NULL OR hold_reason IN ('connector_unconfigured', 'clock_anomaly', 'upgrade_quiescing', 'storage_safety', 'restore_hold')),
    outcome_class TEXT CHECK(outcome_class IS NULL OR outcome_class IN ('accepted', 'transient', 'rate_limited', 'permanent', 'auth_or_config', 'ambiguous')),
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    expires_at_unix_ms INTEGER,
    terminal_at_unix_ms INTEGER,
    created_sequence INTEGER NOT NULL CHECK(created_sequence >= 0),
    attempt_count INTEGER NOT NULL CHECK(attempt_count >= 0),
    next_attempt_at_unix_ms INTEGER,
    lease_generation_hi INTEGER,
    lease_generation_lo INTEGER,
    fence_token BLOB,
    lease_expires_at_unix_ms INTEGER,
    cancel_requested INTEGER NOT NULL CHECK(cancel_requested IN (0, 1)),
    effect_may_have_occurred INTEGER NOT NULL CHECK(effect_may_have_occurred IN (0, 1)),
    duplicate_effect_possible INTEGER NOT NULL CHECK(duplicate_effect_possible IN (0, 1)),
    known_provider_ack_attempt_id TEXT REFERENCES attempts(attempt_id) ON DELETE RESTRICT,
    deferred_outcome_class TEXT CHECK(deferred_outcome_class IS NULL OR deferred_outcome_class IN ('transient', 'rate_limited', 'auth_or_config', 'ambiguous')),
    deferred_relative_delay_ms INTEGER,
    replay_of TEXT REFERENCES messages(message_id) ON DELETE RESTRICT,
    replay_children_count INTEGER NOT NULL CHECK(replay_children_count >= 0),
    payload_available INTEGER NOT NULL CHECK(payload_available IN (0, 1)),
    payload_purged_at_unix_ms INTEGER,
    byte_charge INTEGER,
    CHECK((options_schema_id IS NULL AND options_kind IS NULL AND options_schema_version IS NULL AND options_payload IS NULL) OR (options_schema_id IS NOT NULL AND options_kind IS NOT NULL AND options_schema_version BETWEEN 1 AND 4294967295)),
    CHECK((lease_generation_hi IS NULL AND lease_generation_lo IS NULL AND fence_token IS NULL AND lease_expires_at_unix_ms IS NULL) OR (lease_generation_hi BETWEEN 0 AND 4294967295 AND lease_generation_lo BETWEEN 0 AND 4294967295 AND (lease_generation_hi != 0 OR lease_generation_lo != 0) AND length(fence_token) = 16 AND lease_expires_at_unix_ms IS NOT NULL)),
    CHECK((state = 'delivering') = (lease_generation_hi IS NOT NULL)),
    CHECK((state = 'held') = (hold_reason IS NOT NULL)),
    CHECK((state IN ('provider_accepted', 'failed', 'cancelled', 'expired')) = (terminal_at_unix_ms IS NOT NULL)),
    CHECK((state = 'provider_accepted') = (known_provider_ack_attempt_id IS NOT NULL)),
    CHECK(state <> 'provider_accepted' OR effect_may_have_occurred = 1),
    CHECK((deferred_outcome_class IS NULL AND deferred_relative_delay_ms IS NULL) OR (deferred_outcome_class IS NOT NULL AND deferred_relative_delay_ms >= 0 AND state = 'held' AND hold_reason IN ('clock_anomaly', 'upgrade_quiescing'))),
    CHECK((payload_available = 1 AND destination_payload IS NOT NULL AND content_payload IS NOT NULL AND (options_schema_id IS NULL OR options_payload IS NOT NULL) AND payload_purged_at_unix_ms IS NULL AND byte_charge >= 0) OR (payload_available = 0 AND destination_payload IS NULL AND content_payload IS NULL AND options_payload IS NULL AND payload_purged_at_unix_ms IS NOT NULL AND byte_charge IS NULL))
);

CREATE INDEX messages_eligible_idx ON messages (state, next_attempt_at_unix_ms, provider_id, owner_principal_id, created_sequence);
CREATE INDEX messages_owner_idx ON messages (owner_principal_id, created_sequence, message_id);
CREATE INDEX messages_retention_idx ON messages (terminal_at_unix_ms, payload_purged_at_unix_ms);

CREATE TRIGGER messages_effect_may_have_occurred_monotonic
BEFORE UPDATE OF effect_may_have_occurred ON messages
WHEN OLD.effect_may_have_occurred = 1 AND NEW.effect_may_have_occurred = 0
BEGIN
    SELECT RAISE(ABORT, 'message uncertainty is monotonic');
END;

CREATE TRIGGER messages_duplicate_effect_possible_monotonic
BEFORE UPDATE OF duplicate_effect_possible ON messages
WHEN OLD.duplicate_effect_possible = 1 AND NEW.duplicate_effect_possible = 0
BEGIN
    SELECT RAISE(ABORT, 'message duplicate risk is monotonic');
END;

CREATE TABLE idempotency_records (
    principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    lookup_purpose INTEGER NOT NULL CHECK(lookup_purpose = 2),
    lookup_origin BLOB NOT NULL CHECK(length(lookup_origin) = 32),
    lookup_serial_hi INTEGER NOT NULL CHECK(lookup_serial_hi BETWEEN 0 AND 4294967295),
    lookup_serial_lo INTEGER NOT NULL CHECK(lookup_serial_lo BETWEEN 0 AND 4294967295),
    lookup_digest BLOB NOT NULL CHECK(length(lookup_digest) = 32),
    fingerprint_purpose INTEGER NOT NULL CHECK(fingerprint_purpose = 3),
    fingerprint_origin BLOB NOT NULL CHECK(length(fingerprint_origin) = 32),
    fingerprint_serial_hi INTEGER NOT NULL CHECK(fingerprint_serial_hi BETWEEN 0 AND 4294967295),
    fingerprint_serial_lo INTEGER NOT NULL CHECK(fingerprint_serial_lo BETWEEN 0 AND 4294967295),
    fingerprint_tag BLOB NOT NULL CHECK(length(fingerprint_tag) = 32),
    canonicalizer_version INTEGER NOT NULL CHECK(canonicalizer_version > 0),
    destination_schema_id TEXT NOT NULL CHECK(length(destination_schema_id) > 0),
    destination_kind TEXT NOT NULL CHECK(length(destination_kind) > 0),
    destination_schema_version INTEGER NOT NULL CHECK(destination_schema_version BETWEEN 1 AND 4294967295),
    content_schema_id TEXT NOT NULL CHECK(length(content_schema_id) > 0),
    content_kind TEXT NOT NULL CHECK(length(content_kind) > 0),
    content_schema_version INTEGER NOT NULL CHECK(content_schema_version BETWEEN 1 AND 4294967295),
    options_schema_id TEXT,
    options_kind TEXT,
    options_schema_version INTEGER,
    message_id TEXT NOT NULL REFERENCES messages(message_id) ON DELETE RESTRICT,
    expires_at_unix_ms INTEGER NOT NULL,
    CHECK(lookup_serial_hi != 0 OR lookup_serial_lo != 0),
    CHECK(fingerprint_serial_hi != 0 OR fingerprint_serial_lo != 0),
    CHECK((options_schema_id IS NULL AND options_kind IS NULL AND options_schema_version IS NULL) OR (options_schema_id IS NOT NULL AND options_kind IS NOT NULL AND options_schema_version BETWEEN 1 AND 4294967295))
);

CREATE UNIQUE INDEX idempotency_records_active_lookup_idx
ON idempotency_records (principal_id, lookup_origin, lookup_serial_hi, lookup_serial_lo, lookup_digest);
CREATE INDEX idempotency_records_expiry_idx ON idempotency_records (expires_at_unix_ms);

CREATE TABLE attempts (
    attempt_id TEXT PRIMARY KEY CHECK(length(attempt_id) > 0),
    message_id TEXT NOT NULL REFERENCES messages(message_id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 1 AND 1024),
    fence_generation_hi INTEGER NOT NULL CHECK(fence_generation_hi BETWEEN 0 AND 4294967295),
    fence_generation_lo INTEGER NOT NULL CHECK(fence_generation_lo BETWEEN 0 AND 4294967295),
    fence_token_digest BLOB NOT NULL CHECK(length(fence_token_digest) = 32),
    phase TEXT NOT NULL CHECK(phase IN ('prepared', 'dispatching', 'completed', 'orphaned')),
    prepared_at_unix_ms INTEGER NOT NULL,
    dispatch_marked_at_unix_ms INTEGER,
    finished_at_unix_ms INTEGER,
    configuration_generation INTEGER NOT NULL REFERENCES configuration_generations(configuration_generation) ON DELETE RESTRICT,
    credential_generation INTEGER NOT NULL CHECK(credential_generation > 0),
    jitter_purpose INTEGER NOT NULL CHECK(jitter_purpose = 9),
    jitter_origin BLOB NOT NULL CHECK(length(jitter_origin) = 32),
    jitter_serial_hi INTEGER NOT NULL CHECK(jitter_serial_hi BETWEEN 0 AND 4294967295),
    jitter_serial_lo INTEGER NOT NULL CHECK(jitter_serial_lo BETWEEN 0 AND 4294967295),
    jitter_derivation_version INTEGER NOT NULL CHECK(jitter_derivation_version > 0),
    multiplier_milli INTEGER NOT NULL CHECK(multiplier_milli BETWEEN 500 AND 1500),
    relative_delay_ms INTEGER NOT NULL CHECK(relative_delay_ms BETWEEN 0 AND 3600000),
    outcome_class TEXT CHECK(outcome_class IS NULL OR outcome_class IN ('accepted', 'transient', 'rate_limited', 'permanent', 'auth_or_config', 'ambiguous')),
    ambiguity_observed INTEGER CHECK(ambiguity_observed IS NULL OR ambiguity_observed IN (0, 1)),
    provider_ack_reference TEXT,
    CHECK(fence_generation_hi != 0 OR fence_generation_lo != 0),
    CHECK(jitter_serial_hi != 0 OR jitter_serial_lo != 0),
    CHECK((phase IN ('prepared', 'dispatching') AND finished_at_unix_ms IS NULL AND outcome_class IS NULL AND ambiguity_observed IS NULL AND provider_ack_reference IS NULL) OR (phase IN ('completed', 'orphaned') AND finished_at_unix_ms IS NOT NULL AND outcome_class IS NOT NULL AND ambiguity_observed IS NOT NULL)),
    CHECK(provider_ack_reference IS NULL OR outcome_class = 'accepted')
);

CREATE UNIQUE INDEX attempts_message_ordinal_idx ON attempts (message_id, ordinal);
CREATE UNIQUE INDEX attempts_message_fence_idx ON attempts (message_id, fence_generation_hi, fence_generation_lo);

CREATE TABLE replay_requests (
    actor_principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    replay_purpose INTEGER NOT NULL CHECK(replay_purpose = 4),
    replay_origin BLOB NOT NULL CHECK(length(replay_origin) = 32),
    replay_serial_hi INTEGER NOT NULL CHECK(replay_serial_hi BETWEEN 0 AND 4294967295),
    replay_serial_lo INTEGER NOT NULL CHECK(replay_serial_lo BETWEEN 0 AND 4294967295),
    replay_digest BLOB NOT NULL CHECK(length(replay_digest) = 32),
    fingerprint_purpose INTEGER NOT NULL CHECK(fingerprint_purpose = 5),
    fingerprint_origin BLOB NOT NULL CHECK(length(fingerprint_origin) = 32),
    fingerprint_serial_hi INTEGER NOT NULL CHECK(fingerprint_serial_hi BETWEEN 0 AND 4294967295),
    fingerprint_serial_lo INTEGER NOT NULL CHECK(fingerprint_serial_lo BETWEEN 0 AND 4294967295),
    fingerprint_tag BLOB NOT NULL CHECK(length(fingerprint_tag) = 32),
    canonicalizer_version INTEGER NOT NULL CHECK(canonicalizer_version > 0),
    source_message_id TEXT NOT NULL REFERENCES messages(message_id) ON DELETE RESTRICT,
    child_message_id TEXT NOT NULL UNIQUE REFERENCES messages(message_id) ON DELETE RESTRICT,
    CHECK(replay_serial_hi != 0 OR replay_serial_lo != 0),
    CHECK(fingerprint_serial_hi != 0 OR fingerprint_serial_lo != 0)
);

CREATE UNIQUE INDEX replay_requests_lookup_idx ON replay_requests (actor_principal_id, replay_origin, replay_serial_hi, replay_serial_lo, replay_digest);

CREATE TABLE provider_runtime (
    connector_identity_id TEXT PRIMARY KEY REFERENCES connector_identities(connector_identity_id) ON DELETE RESTRICT,
    circuit_state TEXT NOT NULL CHECK(circuit_state IN ('closed', 'rate_limited', 'open')),
    not_before_unix_ms INTEGER,
    failure_class TEXT CHECK(failure_class IS NULL OR failure_class IN ('transient', 'rate_limited', 'auth_or_config')),
    consecutive_failures INTEGER NOT NULL CHECK(consecutive_failures >= 0),
    probe_generation_hi INTEGER,
    probe_generation_lo INTEGER,
    probe_fence_digest BLOB,
    probe_expires_at_unix_ms INTEGER,
    CHECK((probe_generation_hi IS NULL AND probe_generation_lo IS NULL AND probe_fence_digest IS NULL AND probe_expires_at_unix_ms IS NULL) OR (probe_generation_hi BETWEEN 0 AND 4294967295 AND probe_generation_lo BETWEEN 0 AND 4294967295 AND (probe_generation_hi != 0 OR probe_generation_lo != 0) AND length(probe_fence_digest) = 32 AND probe_expires_at_unix_ms IS NOT NULL)),
    CHECK((circuit_state = 'closed' AND not_before_unix_ms IS NULL AND failure_class IS NULL AND probe_generation_hi IS NULL) OR (circuit_state = 'rate_limited' AND not_before_unix_ms IS NOT NULL AND failure_class = 'rate_limited' AND probe_generation_hi IS NULL) OR (circuit_state = 'open' AND failure_class IS NOT NULL))
);

CREATE TABLE scheduler_principal_cursor (
    provider_id TEXT PRIMARY KEY REFERENCES providers(provider_id) ON DELETE RESTRICT,
    last_principal_id TEXT REFERENCES principals(principal_id) ON DELETE RESTRICT
);

CREATE TABLE operation_commands (
    operation_id TEXT NOT NULL CHECK(length(operation_id) > 0),
    actor_namespace TEXT NOT NULL CHECK(length(actor_namespace) > 0),
    command_purpose INTEGER NOT NULL CHECK(command_purpose = 6),
    command_origin BLOB NOT NULL CHECK(length(command_origin) = 32),
    command_serial_hi INTEGER NOT NULL CHECK(command_serial_hi BETWEEN 0 AND 4294967295),
    command_serial_lo INTEGER NOT NULL CHECK(command_serial_lo BETWEEN 0 AND 4294967295),
    command_digest BLOB NOT NULL CHECK(length(command_digest) = 32),
    semantic_purpose INTEGER NOT NULL CHECK(semantic_purpose = 7),
    semantic_origin BLOB NOT NULL CHECK(length(semantic_origin) = 32),
    semantic_serial_hi INTEGER NOT NULL CHECK(semantic_serial_hi BETWEEN 0 AND 4294967295),
    semantic_serial_lo INTEGER NOT NULL CHECK(semantic_serial_lo BETWEEN 0 AND 4294967295),
    semantic_tag BLOB NOT NULL CHECK(length(semantic_tag) = 32),
    phase_purpose INTEGER NOT NULL CHECK(phase_purpose = 8),
    phase_origin BLOB NOT NULL CHECK(length(phase_origin) = 32),
    phase_serial_hi INTEGER NOT NULL CHECK(phase_serial_hi BETWEEN 0 AND 4294967295),
    phase_serial_lo INTEGER NOT NULL CHECK(phase_serial_lo BETWEEN 0 AND 4294967295),
    phase_tag BLOB NOT NULL CHECK(length(phase_tag) = 32),
    source_runtime_id TEXT NOT NULL CHECK(length(source_runtime_id) > 0),
    source_process_id TEXT NOT NULL CHECK(length(source_process_id) > 0),
    phase TEXT NOT NULL CHECK(length(phase) > 0),
    result_kind TEXT,
    result_ref TEXT,
    terminal_at_unix_ms INTEGER,
    command_expires_at_unix_ms INTEGER,
    portable_purpose INTEGER,
    portable_origin BLOB,
    portable_serial_hi INTEGER,
    portable_serial_lo INTEGER,
    portable_digest BLOB,
    CHECK(command_serial_hi != 0 OR command_serial_lo != 0),
    CHECK(semantic_serial_hi != 0 OR semantic_serial_lo != 0),
    CHECK(phase_serial_hi != 0 OR phase_serial_lo != 0),
    CHECK((result_kind IS NULL AND result_ref IS NULL) OR (result_kind IS NOT NULL AND result_ref IS NOT NULL AND length(result_kind) > 0 AND length(result_ref) > 0)),
    CHECK((terminal_at_unix_ms IS NULL AND command_expires_at_unix_ms IS NULL) OR (terminal_at_unix_ms IS NOT NULL AND command_expires_at_unix_ms IS NOT NULL AND command_expires_at_unix_ms >= terminal_at_unix_ms)),
    CHECK((portable_purpose IS NULL AND portable_origin IS NULL AND portable_serial_hi IS NULL AND portable_serial_lo IS NULL AND portable_digest IS NULL) OR (portable_purpose = 11 AND length(portable_origin) = 32 AND portable_serial_hi BETWEEN 0 AND 4294967295 AND portable_serial_lo BETWEEN 0 AND 4294967295 AND (portable_serial_hi != 0 OR portable_serial_lo != 0) AND length(portable_digest) = 32)),
    UNIQUE (operation_id, actor_namespace, command_origin, command_serial_hi, command_serial_lo, command_digest)
);

CREATE TABLE history_epochs (
    history_epoch_id BLOB PRIMARY KEY CHECK(length(history_epoch_id) = 32),
    owner_namespace BLOB NOT NULL CHECK(length(owner_namespace) = 24),
    branch_serial_hi INTEGER NOT NULL CHECK(branch_serial_hi BETWEEN 0 AND 4294967295),
    branch_serial_lo INTEGER NOT NULL CHECK(branch_serial_lo BETWEEN 0 AND 4294967295),
    origin_transition TEXT NOT NULL CHECK(origin_transition IN ('bootstrap', 'restore', 'rollback')),
    parent_history_epoch_id BLOB,
    parent_batch_sequence INTEGER,
    parent_batch_digest BLOB,
    activation_certificate_digest BLOB NOT NULL CHECK(length(activation_certificate_digest) = 32),
    CHECK(branch_serial_hi != 0 OR branch_serial_lo != 0),
    CHECK((parent_history_epoch_id IS NULL AND parent_batch_sequence IS NULL AND parent_batch_digest IS NULL) OR (length(parent_history_epoch_id) = 32 AND parent_batch_sequence >= 0 AND length(parent_batch_digest) = 32))
);

CREATE TRIGGER history_epochs_immutable
BEFORE UPDATE ON history_epochs
BEGIN
    SELECT RAISE(ABORT, 'history epoch is immutable');
END;

CREATE TABLE restore_comparison_batches (
    batch_sequence INTEGER PRIMARY KEY CHECK(batch_sequence >= 0),
    history_epoch_id BLOB NOT NULL REFERENCES history_epochs(history_epoch_id) ON DELETE RESTRICT,
    source_transaction_sequence INTEGER NOT NULL CHECK(source_transaction_sequence >= 0),
    event_count INTEGER NOT NULL CHECK(event_count >= 0),
    previous_batch_digest BLOB NOT NULL CHECK(length(previous_batch_digest) = 32),
    canonical_batch_digest BLOB NOT NULL CHECK(length(canonical_batch_digest) = 32),
    boundary_parent_history_epoch_id BLOB,
    boundary_parent_batch_sequence INTEGER,
    boundary_parent_batch_digest BLOB,
    boundary_parent_origin TEXT,
    CHECK((boundary_parent_history_epoch_id IS NULL AND boundary_parent_batch_sequence IS NULL AND boundary_parent_batch_digest IS NULL AND boundary_parent_origin IS NULL) OR (length(boundary_parent_history_epoch_id) = 32 AND boundary_parent_batch_sequence >= 0 AND length(boundary_parent_batch_digest) = 32 AND boundary_parent_origin IS NOT NULL)),
    CHECK(boundary_parent_origin IN ('selected_head', 'comparison_unavailable'))
);

CREATE UNIQUE INDEX restore_comparison_one_boundary_per_epoch_idx
ON restore_comparison_batches (history_epoch_id)
WHERE boundary_parent_history_epoch_id IS NOT NULL;

CREATE TRIGGER restore_comparison_batches_immutable
BEFORE UPDATE ON restore_comparison_batches
BEGIN
    SELECT RAISE(ABORT, 'comparison batch is immutable');
END;

CREATE TRIGGER restore_comparison_batches_compaction_prefix_only
BEFORE DELETE ON restore_comparison_batches
WHEN NOT EXISTS (SELECT 1 FROM meta)
  OR OLD.batch_sequence > (SELECT comparison_anchor_batch_sequence FROM meta)
BEGIN
    SELECT RAISE(ABORT, 'comparison batch deletion is outside retained prefix');
END;

CREATE TRIGGER restore_comparison_batches_contiguous_before_insert
BEFORE INSERT ON restore_comparison_batches
WHEN (EXISTS (SELECT 1 FROM meta) AND NOT EXISTS (
    SELECT 1 FROM meta
    WHERE NEW.batch_sequence = comparison_head_batch_sequence + 1
      AND NEW.previous_batch_digest = comparison_head_batch_digest
 ))
 OR (NOT EXISTS (SELECT 1 FROM meta) AND NEW.batch_sequence != 0)
BEGIN
    SELECT RAISE(ABORT, 'comparison batch is not contiguous with selected head');
END;

CREATE TRIGGER restore_comparison_batches_boundary_before_insert
BEFORE INSERT ON restore_comparison_batches
WHEN (NOT EXISTS (SELECT 1 FROM meta) AND NOT EXISTS (
        SELECT 1 FROM history_epochs AS epoch
        WHERE epoch.history_epoch_id = NEW.history_epoch_id
          AND epoch.origin_transition = 'bootstrap'
          AND NEW.boundary_parent_origin IS NULL
    )) OR (EXISTS (SELECT 1 FROM meta) AND EXISTS (
        SELECT 1 FROM meta
        WHERE (NEW.history_epoch_id = active_history_epoch_id AND NEW.boundary_parent_origin IS NOT NULL)
           OR (NEW.history_epoch_id != active_history_epoch_id AND (
                EXISTS (
                    SELECT 1 FROM restore_comparison_batches AS prior
                    WHERE prior.history_epoch_id = NEW.history_epoch_id
                )
                OR NEW.boundary_parent_origin IS NULL
                OR NOT EXISTS (
                    SELECT 1 FROM history_epochs AS epoch
                    WHERE epoch.history_epoch_id = NEW.history_epoch_id
                      AND epoch.origin_transition IN ('restore', 'rollback')
                      AND epoch.parent_history_epoch_id IS NOT NULL
                      AND epoch.parent_batch_sequence IS NOT NULL
                      AND epoch.parent_batch_digest IS NOT NULL
                      AND NEW.boundary_parent_history_epoch_id IS epoch.parent_history_epoch_id
                      AND NEW.boundary_parent_batch_sequence IS epoch.parent_batch_sequence
                      AND NEW.boundary_parent_batch_digest IS epoch.parent_batch_digest
                      AND NEW.boundary_parent_history_epoch_id = active_history_epoch_id
                      AND NEW.boundary_parent_batch_sequence = comparison_head_batch_sequence
                      AND NEW.boundary_parent_batch_digest = comparison_head_batch_digest
                      AND (NEW.boundary_parent_origin != 'comparison_unavailable' OR epoch.origin_transition = 'restore')
                )
           ))
    ))
BEGIN
    SELECT RAISE(ABORT, 'comparison batch has invalid epoch boundary');
END;

CREATE TABLE restore_comparison_events (
    batch_sequence INTEGER NOT NULL REFERENCES restore_comparison_batches(batch_sequence) ON DELETE RESTRICT,
    event_ordinal INTEGER NOT NULL CHECK(event_ordinal >= 0),
    lifecycle_event TEXT NOT NULL CHECK(lifecycle_event IN ('accepted', 'dispatch_marked', 'ambiguity_recorded', 'provider_accepted', 'failed', 'cancelled', 'expired', 'payload_purged')),
    command_ref TEXT,
    message_id TEXT NOT NULL CHECK(length(message_id) > 0),
    attempt_id TEXT,
    terminal INTEGER NOT NULL CHECK(terminal IN (0, 1)),
    effect_may_have_occurred INTEGER NOT NULL CHECK(effect_may_have_occurred IN (0, 1)),
    duplicate_effect_possible INTEGER NOT NULL CHECK(duplicate_effect_possible IN (0, 1)),
    purge_message_id TEXT,
    purge_at_unix_ms INTEGER,
    purge_source TEXT,
    purge_reason TEXT,
    CHECK((lifecycle_event IN ('dispatch_marked', 'ambiguity_recorded', 'provider_accepted')) = (attempt_id IS NOT NULL)),
    CHECK(terminal = CASE WHEN lifecycle_event IN ('provider_accepted', 'failed', 'cancelled', 'expired', 'payload_purged') THEN 1 WHEN lifecycle_event IN ('accepted', 'dispatch_marked') THEN 0 ELSE terminal END),
    CHECK(effect_may_have_occurred = CASE WHEN lifecycle_event IN ('dispatch_marked', 'ambiguity_recorded', 'provider_accepted') THEN 1 ELSE effect_may_have_occurred END),
    CHECK((purge_message_id IS NULL AND purge_at_unix_ms IS NULL AND purge_source IS NULL AND purge_reason IS NULL) OR (lifecycle_event = 'payload_purged' AND purge_message_id = message_id AND purge_at_unix_ms IS NOT NULL AND purge_source IN ('operator', 'maintenance') AND purge_reason IN ('operator_request', 'accepted_retention', 'dead_letter_retention') AND ((purge_source = 'operator' AND purge_reason = 'operator_request') OR (purge_source = 'maintenance' AND purge_reason IN ('accepted_retention', 'dead_letter_retention'))))),
    CHECK((lifecycle_event = 'payload_purged') = (purge_message_id IS NOT NULL)),
    PRIMARY KEY (batch_sequence, event_ordinal)
);

CREATE INDEX restore_comparison_events_message_idx ON restore_comparison_events (message_id);
CREATE INDEX restore_comparison_events_command_idx ON restore_comparison_events (command_ref);

CREATE TRIGGER restore_comparison_events_immutable
BEFORE UPDATE ON restore_comparison_events
BEGIN
    SELECT RAISE(ABORT, 'comparison event is immutable');
END;

CREATE TRIGGER restore_comparison_events_compaction_prefix_only
BEFORE DELETE ON restore_comparison_events
WHEN NOT EXISTS (SELECT 1 FROM meta)
  OR OLD.batch_sequence > (SELECT comparison_anchor_batch_sequence FROM meta)
BEGIN
    SELECT RAISE(ABORT, 'comparison event deletion is outside retained prefix');
END;

CREATE TRIGGER restore_comparison_events_contiguous_before_insert
BEFORE INSERT ON restore_comparison_events
WHEN NOT EXISTS (
    SELECT 1 FROM restore_comparison_batches AS batch
    WHERE batch.batch_sequence = NEW.batch_sequence
      AND NEW.event_ordinal = (
          SELECT COUNT(*)
          FROM restore_comparison_events AS prior
          WHERE prior.batch_sequence = NEW.batch_sequence
      )
      AND NEW.event_ordinal < batch.event_count
)
BEGIN
    SELECT RAISE(ABORT, 'comparison event ordinal is not contiguous');
END;

CREATE TABLE purge_tombstones (
    message_id TEXT PRIMARY KEY CHECK(length(message_id) > 0),
    purged_at_unix_ms INTEGER NOT NULL,
    purge_source TEXT NOT NULL CHECK(purge_source IN ('operator', 'maintenance')),
    purge_reason TEXT NOT NULL CHECK(purge_reason IN ('operator_request', 'accepted_retention', 'dead_letter_retention')),
    history_epoch_id BLOB NOT NULL REFERENCES history_epochs(history_epoch_id) ON DELETE RESTRICT,
    comparison_batch_sequence INTEGER NOT NULL,
    comparison_event_ordinal INTEGER NOT NULL,
    CHECK((purge_source = 'operator' AND purge_reason = 'operator_request') OR (purge_source = 'maintenance' AND purge_reason IN ('accepted_retention', 'dead_letter_retention')))
);

CREATE TRIGGER purge_tombstones_requires_payload_purged_event
BEFORE INSERT ON purge_tombstones
WHEN NOT EXISTS (
    SELECT 1
    FROM restore_comparison_events AS event
    JOIN restore_comparison_batches AS batch ON batch.batch_sequence = event.batch_sequence
    WHERE event.batch_sequence = NEW.comparison_batch_sequence
      AND event.event_ordinal = NEW.comparison_event_ordinal
      AND event.lifecycle_event = 'payload_purged'
      AND event.purge_message_id = NEW.message_id
      AND event.purge_at_unix_ms = NEW.purged_at_unix_ms
      AND event.purge_source = NEW.purge_source
      AND event.purge_reason = NEW.purge_reason
      AND batch.history_epoch_id = NEW.history_epoch_id
      AND event.batch_sequence = COALESCE((SELECT comparison_head_batch_sequence + 1 FROM meta), 0)
)
BEGIN
    SELECT RAISE(ABORT, 'purge tombstone lacks payload-purged comparison event');
END;

CREATE TRIGGER purge_tombstones_immutable
BEFORE UPDATE ON purge_tombstones
BEGIN
    SELECT RAISE(ABORT, 'purge tombstone is immutable');
END;

CREATE TRIGGER purge_tombstones_retained
BEFORE DELETE ON purge_tombstones
BEGIN
    SELECT RAISE(ABORT, 'purge tombstone is retained');
END;

CREATE TABLE audit_events (
    audit_event_id TEXT PRIMARY KEY CHECK(length(audit_event_id) > 0),
    occurred_at_unix_ms INTEGER NOT NULL,
    event_code TEXT NOT NULL CHECK(length(event_code) > 0),
    actor_namespace TEXT,
    message_id TEXT,
    provider_id TEXT,
    command_ref TEXT,
    CHECK((actor_namespace IS NULL OR length(actor_namespace) > 0) AND (message_id IS NULL OR length(message_id) > 0) AND (provider_id IS NULL OR length(provider_id) > 0) AND (command_ref IS NULL OR length(command_ref) > 0))
);

CREATE INDEX audit_events_time_idx ON audit_events (occurred_at_unix_ms, audit_event_id);
CREATE INDEX audit_events_message_idx ON audit_events (message_id, occurred_at_unix_ms);

CREATE TABLE backup_jobs (
    backup_job_id TEXT PRIMARY KEY CHECK(length(backup_job_id) > 0),
    external_state TEXT NOT NULL CHECK(external_state IN ('queued', 'running', 'complete', 'failed', 'cancelled')),
    publication_phase TEXT NOT NULL CHECK(publication_phase IN ('building', 'artifact_staged', 'complete', 'removing')),
    temporary_basename TEXT NOT NULL CHECK(length(temporary_basename) > 0),
    final_basename TEXT NOT NULL CHECK(length(final_basename) > 0),
    expected_artifact_digest BLOB NOT NULL CHECK(length(expected_artifact_digest) = 32),
    expected_artifact_size INTEGER NOT NULL CHECK(expected_artifact_size >= 0),
    cancellation_requested INTEGER NOT NULL CHECK(cancellation_requested IN (0, 1)),
    pin_history_epoch_id BLOB NOT NULL REFERENCES history_epochs(history_epoch_id) ON DELETE RESTRICT,
    pin_batch_sequence INTEGER NOT NULL REFERENCES restore_comparison_batches(batch_sequence) ON DELETE RESTRICT,
    pin_batch_digest BLOB NOT NULL CHECK(length(pin_batch_digest) = 32),
    execution_deadline_unix_ms INTEGER NOT NULL,
    retention_deadline_unix_ms INTEGER NOT NULL,
    terminal_reason TEXT,
    CHECK(temporary_basename <> final_basename),
    CHECK(retention_deadline_unix_ms >= execution_deadline_unix_ms),
    CHECK((external_state IN ('complete', 'failed', 'cancelled')) = (terminal_reason IS NOT NULL))
);

CREATE UNIQUE INDEX backup_jobs_one_running_idx ON backup_jobs (external_state)
WHERE external_state = 'running';

CREATE TABLE backup_history (
    backup_job_id TEXT PRIMARY KEY REFERENCES backup_jobs(backup_job_id) ON DELETE RESTRICT,
    artifact_digest BLOB NOT NULL CHECK(length(artifact_digest) = 32),
    source_instance_id TEXT NOT NULL CHECK(length(source_instance_id) > 0),
    source_lineage_id TEXT NOT NULL CHECK(length(source_lineage_id) > 0),
    snapshot_transaction_sequence INTEGER NOT NULL CHECK(snapshot_transaction_sequence >= 0),
    base_tombstone_count INTEGER NOT NULL CHECK(base_tombstone_count >= 0),
    base_tombstone_digest BLOB NOT NULL CHECK(length(base_tombstone_digest) = 32),
    base_tombstone_watermark INTEGER NOT NULL CHECK(base_tombstone_watermark >= 0),
    history_epoch_id BLOB NOT NULL REFERENCES history_epochs(history_epoch_id) ON DELETE RESTRICT,
    comparison_batch_sequence INTEGER NOT NULL REFERENCES restore_comparison_batches(batch_sequence) ON DELETE RESTRICT,
    comparison_batch_digest BLOB NOT NULL CHECK(length(comparison_batch_digest) = 32),
    nonempty_restore_supported_until_unix_ms INTEGER NOT NULL
);

CREATE TABLE upgrade_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    upgrade_id TEXT NOT NULL CHECK(length(upgrade_id) > 0),
    transition_id TEXT NOT NULL CHECK(length(transition_id) > 0),
    phase TEXT NOT NULL CHECK(phase IN ('quiescing', 'prepared', 'activated', 'repaired', 'rolled_back', 'prepare_failed')),
    prepare_deadline_unix_ms INTEGER NOT NULL,
    source_generation INTEGER NOT NULL CHECK(source_generation > 0),
    target_generation INTEGER NOT NULL CHECK(target_generation > 0),
    source_schema_version INTEGER NOT NULL CHECK(source_schema_version > 0),
    target_schema_version INTEGER NOT NULL CHECK(target_schema_version > 0),
    source_history_epoch_id BLOB NOT NULL REFERENCES history_epochs(history_epoch_id) ON DELETE RESTRICT,
    source_comparison_batch_sequence INTEGER NOT NULL REFERENCES restore_comparison_batches(batch_sequence) ON DELETE RESTRICT,
    source_comparison_batch_digest BLOB NOT NULL CHECK(length(source_comparison_batch_digest) = 32),
    target_certificate_digest BLOB NOT NULL CHECK(length(target_certificate_digest) = 32),
    rollback_eligible INTEGER NOT NULL CHECK(rollback_eligible IN (0, 1)),
    divergence_digest BLOB,
    activation_status TEXT NOT NULL CHECK(length(activation_status) > 0),
    CHECK(divergence_digest IS NULL OR length(divergence_digest) = 32),
    CHECK((phase = 'prepared') = (rollback_eligible = 1))
);

CREATE TABLE meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_version INTEGER NOT NULL CHECK(schema_version > 0),
    active_configuration_generation INTEGER NOT NULL REFERENCES configuration_generations(configuration_generation) ON DELETE RESTRICT,
    runtime_instance_id TEXT NOT NULL CHECK(length(runtime_instance_id) > 0),
    lineage_id TEXT NOT NULL CHECK(length(lineage_id) > 0),
    transaction_sequence INTEGER NOT NULL CHECK(transaction_sequence >= 0),
    authorization_epoch INTEGER NOT NULL CHECK(authorization_epoch >= 0),
    active_history_epoch_id BLOB NOT NULL REFERENCES history_epochs(history_epoch_id) ON DELETE RESTRICT,
    comparison_anchor_batch_sequence INTEGER NOT NULL CHECK(comparison_anchor_batch_sequence >= 0),
    comparison_anchor_batch_digest BLOB NOT NULL CHECK(length(comparison_anchor_batch_digest) = 32),
    comparison_head_batch_sequence INTEGER NOT NULL CHECK(comparison_head_batch_sequence >= comparison_anchor_batch_sequence),
    comparison_head_batch_digest BLOB NOT NULL CHECK(length(comparison_head_batch_digest) = 32),
    selected_origin_incarnation BLOB NOT NULL CHECK(length(selected_origin_incarnation) = 32),
    last_safe_wall_time_unix_ms INTEGER
);

CREATE TRIGGER meta_comparison_head_requires_complete_batch
BEFORE INSERT ON meta
WHEN NOT EXISTS (
    SELECT 1 FROM restore_comparison_batches AS head
    WHERE head.batch_sequence = NEW.comparison_head_batch_sequence
      AND head.history_epoch_id = NEW.active_history_epoch_id
      AND head.canonical_batch_digest = NEW.comparison_head_batch_digest
      AND (SELECT COUNT(*) FROM restore_comparison_events AS event WHERE event.batch_sequence = head.batch_sequence) = head.event_count
) OR NOT EXISTS (
    SELECT 1 FROM restore_comparison_batches AS anchor
    WHERE anchor.batch_sequence = NEW.comparison_anchor_batch_sequence
      AND anchor.canonical_batch_digest = NEW.comparison_anchor_batch_digest
) OR EXISTS (
    SELECT 1 FROM restore_comparison_events AS event
    WHERE event.batch_sequence = NEW.comparison_head_batch_sequence
      AND event.lifecycle_event = 'payload_purged'
      AND NOT EXISTS (
          SELECT 1 FROM purge_tombstones AS tombstone
          WHERE tombstone.message_id = event.purge_message_id
            AND tombstone.purged_at_unix_ms = event.purge_at_unix_ms
            AND tombstone.purge_source = event.purge_source
            AND tombstone.purge_reason = event.purge_reason
            AND tombstone.comparison_batch_sequence = event.batch_sequence
            AND tombstone.comparison_event_ordinal = event.event_ordinal
      )
)
BEGIN
    SELECT RAISE(ABORT, 'meta comparison head is not a complete selected batch');
END;

CREATE TRIGGER meta_comparison_head_advances_one_complete_batch
BEFORE UPDATE OF active_history_epoch_id, comparison_anchor_batch_sequence, comparison_anchor_batch_digest, comparison_head_batch_sequence, comparison_head_batch_digest ON meta
WHEN NOT EXISTS (
    SELECT 1 FROM restore_comparison_batches AS head
    WHERE head.batch_sequence = NEW.comparison_head_batch_sequence
      AND head.history_epoch_id = NEW.active_history_epoch_id
      AND head.canonical_batch_digest = NEW.comparison_head_batch_digest
      AND (SELECT COUNT(*) FROM restore_comparison_events AS event WHERE event.batch_sequence = head.batch_sequence) = head.event_count
) OR EXISTS (
    SELECT 1 FROM restore_comparison_events AS event
    WHERE event.batch_sequence = NEW.comparison_head_batch_sequence
      AND event.lifecycle_event = 'payload_purged'
      AND NOT EXISTS (
          SELECT 1 FROM purge_tombstones AS tombstone
          WHERE tombstone.message_id = event.purge_message_id
            AND tombstone.purged_at_unix_ms = event.purge_at_unix_ms
            AND tombstone.purge_source = event.purge_source
            AND tombstone.purge_reason = event.purge_reason
            AND tombstone.comparison_batch_sequence = event.batch_sequence
            AND tombstone.comparison_event_ordinal = event.event_ordinal
      )
) OR NEW.comparison_anchor_batch_sequence < OLD.comparison_anchor_batch_sequence
 OR ((NEW.comparison_anchor_batch_sequence != OLD.comparison_anchor_batch_sequence
      OR NEW.comparison_anchor_batch_digest != OLD.comparison_anchor_batch_digest)
     AND NOT EXISTS (
        SELECT 1 FROM restore_comparison_batches AS anchor
        WHERE anchor.batch_sequence = NEW.comparison_anchor_batch_sequence
          AND anchor.canonical_batch_digest = NEW.comparison_anchor_batch_digest
     ))
 OR (NEW.comparison_head_batch_sequence != OLD.comparison_head_batch_sequence
      AND NEW.comparison_head_batch_sequence != OLD.comparison_head_batch_sequence + 1)
BEGIN
    SELECT RAISE(ABORT, 'meta comparison head is not one complete successor batch');
END;

CREATE TRIGGER messages_insert_requires_accepted_comparison_event
BEFORE INSERT ON messages
WHEN NOT EXISTS (
    SELECT 1
    FROM restore_comparison_events AS event
    WHERE event.message_id = NEW.message_id
      AND event.lifecycle_event = 'accepted'
      AND event.batch_sequence = COALESCE((SELECT comparison_head_batch_sequence + 1 FROM meta), 0)
)
BEGIN
    SELECT RAISE(ABORT, 'message insert lacks accepted comparison event');
END;

CREATE TRIGGER messages_terminal_state_requires_comparison_event
BEFORE UPDATE OF state ON messages
WHEN NEW.state IN ('provider_accepted', 'failed', 'cancelled', 'expired')
 AND OLD.state != NEW.state
 AND NOT EXISTS (
    SELECT 1
    FROM restore_comparison_events AS event
    WHERE event.message_id = NEW.message_id
      AND event.lifecycle_event = NEW.state
      AND event.batch_sequence = (SELECT comparison_head_batch_sequence + 1 FROM meta)
 )
BEGIN
    SELECT RAISE(ABORT, 'terminal message state lacks comparison event');
END;

CREATE TRIGGER messages_ambiguity_requires_comparison_event
BEFORE UPDATE OF duplicate_effect_possible ON messages
WHEN OLD.duplicate_effect_possible = 0
 AND NEW.duplicate_effect_possible = 1
 AND NOT EXISTS (
    SELECT 1
    FROM restore_comparison_events AS event
    WHERE event.message_id = NEW.message_id
      AND event.lifecycle_event = 'ambiguity_recorded'
      AND event.batch_sequence = (SELECT comparison_head_batch_sequence + 1 FROM meta)
 )
BEGIN
    SELECT RAISE(ABORT, 'message ambiguity lacks comparison event');
END;

CREATE TRIGGER messages_effect_requires_dispatch_comparison_event
BEFORE UPDATE OF effect_may_have_occurred ON messages
WHEN OLD.effect_may_have_occurred = 0
 AND NEW.effect_may_have_occurred = 1
 AND NOT EXISTS (
    SELECT 1
    FROM restore_comparison_events AS event
    WHERE event.message_id = NEW.message_id
      AND event.lifecycle_event = 'dispatch_marked'
      AND event.batch_sequence = (SELECT comparison_head_batch_sequence + 1 FROM meta)
 )
BEGIN
    SELECT RAISE(ABORT, 'message effect evidence lacks dispatch comparison event');
END;

CREATE TABLE meta_mac_serial_high_water (
    purpose INTEGER PRIMARY KEY CHECK(purpose BETWEEN 1 AND 11),
    serial_hi INTEGER NOT NULL CHECK(serial_hi BETWEEN 0 AND 4294967295),
    serial_lo INTEGER NOT NULL CHECK(serial_lo BETWEEN 0 AND 4294967295)
);
```

The static trigger diagnostics are internal SQLite failures only; the later
store actor maps every engine failure to the existing redacted `StoreError`
category. This contract contains no insert/update API, no transaction
execution, no socket, and no provider operation.
