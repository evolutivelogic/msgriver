-- M3 preserves the M2 queue in place, then gives every row a provider-neutral
-- envelope. Legacy ntfy columns remain only so an M2-created row can be
-- dispatched identically after upgrade; all future drivers use the closed
-- driver/destination/payload fields and do not require another store shape.
ALTER TABLE m2_messages RENAME TO m3_messages;

ALTER TABLE m3_messages
ADD COLUMN driver TEXT NOT NULL DEFAULT 'ntfy'
CHECK(driver IN ('ntfy', 'whatsapp'));

ALTER TABLE m3_messages
ADD COLUMN destination TEXT NOT NULL DEFAULT '';

ALTER TABLE m3_messages
ADD COLUMN payload TEXT NOT NULL DEFAULT '';

UPDATE m3_messages
SET destination = topic
WHERE driver = 'ntfy';

CREATE INDEX m3_messages_driver_due_idx
ON m3_messages (driver, state, next_attempt_at_unix_ms, created_at_unix_ms);
