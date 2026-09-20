-- M4 keeps the inbound control plane independent from callback input.  The
-- switch, receipt identity, rate accounting and fixed outbound intent share
-- one service-owned SQLite transaction.
CREATE TABLE m4_inbound_control (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))
);

INSERT INTO m4_inbound_control (singleton, enabled) VALUES (1, 0);

CREATE TABLE m4_inbound_receipts (
    provider_message_id TEXT PRIMARY KEY,
    sender TEXT NOT NULL,
    verb TEXT NOT NULL CHECK (verb IN ('notify', 'status')),
    accepted_at_unix_ms INTEGER NOT NULL
);

CREATE TABLE m4_notify_rate_events (
    sender TEXT NOT NULL,
    accepted_at_unix_ms INTEGER NOT NULL
);

CREATE INDEX m4_notify_rate_events_sender_time_idx
ON m4_notify_rate_events (sender, accepted_at_unix_ms);
