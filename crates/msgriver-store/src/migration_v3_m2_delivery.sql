CREATE TABLE m2_messages (
    message_id TEXT PRIMARY KEY CHECK(length(message_id) = 64),
    idempotency_key TEXT NOT NULL UNIQUE CHECK(length(idempotency_key) BETWEEN 1 AND 128),
    topic TEXT NOT NULL CHECK(length(topic) BETWEEN 1 AND 64),
    title TEXT,
    body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 4096),
    state TEXT NOT NULL CHECK(state IN ('queued', 'sending', 'retry_scheduled', 'provider_accepted', 'ambiguous', 'failed')),
    attempts INTEGER NOT NULL CHECK(attempts BETWEEN 0 AND 5),
    next_attempt_at_unix_ms INTEGER,
    provider_ack TEXT,
    last_error TEXT,
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    CHECK((state IN ('queued', 'retry_scheduled')) = (next_attempt_at_unix_ms IS NOT NULL)),
    CHECK((state = 'provider_accepted') = (provider_ack IS NOT NULL)),
    CHECK((state IN ('ambiguous', 'failed')) = (last_error IS NOT NULL))
);

CREATE INDEX m2_messages_due_idx
ON m2_messages (state, next_attempt_at_unix_ms, created_at_unix_ms);
