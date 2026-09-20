//! Behavioral contract for the static restore-comparison trigger closure.

#![forbid(unsafe_code)]

use msgriver_store::{MigrationProvenance, Store, StoreOpenConfig};
use rusqlite::{Connection, params};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const PROFILE: StoreOpenConfig = StoreOpenConfig::new(1_000, 4 * 1024 * 1024);
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TemporaryDatabase(PathBuf);

impl TemporaryDatabase {
    fn create() -> std::io::Result<Self> {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "msgriver-comparison-trigger-contract-{}-{sequence}",
            std::process::id(),
        ));
        fs::create_dir(&directory)?;
        Ok(Self(directory.join("store.db")))
    }

    fn connection(&self) -> Result<Connection, String> {
        Connection::open(&self.0).map_err(|_| "COMPARISON-CLOSURE: inspection failed".to_owned())
    }
}

impl Drop for TemporaryDatabase {
    fn drop(&mut self) {
        if let Some(directory) = self.0.parent() {
            let _ = fs::remove_dir_all(directory);
        }
    }
}

fn install() -> Result<(TemporaryDatabase, Connection), String> {
    let database = TemporaryDatabase::create().map_err(|_| "COMPARISON-CLOSURE: fixture failed")?;
    let mut store =
        Store::open(&database.0, PROFILE).map_err(|_| "COMPARISON-CLOSURE: store open failed")?;
    store
        .apply_migrations(MigrationProvenance {
            binary_identity: b"comparison-trigger-contract",
            applied_at_unix_ms: 1,
        })
        .map_err(|_| "COMPARISON-CLOSURE: migration failed")?;
    drop(store);
    let connection = database.connection()?;
    connection
        .execute_batch("PRAGMA foreign_keys = OFF")
        .map_err(|_| "COMPARISON-CLOSURE: fixture pragma failed")?;
    Ok((database, connection))
}

fn insert_epoch(
    connection: &Connection,
    epoch: &[u8],
    origin: &str,
    parent: Option<(&[u8], i64, &[u8])>,
) -> Result<(), String> {
    let (parent_epoch, parent_sequence, parent_digest): (
        Option<&[u8]>,
        Option<i64>,
        Option<&[u8]>,
    ) = match parent {
        Some((epoch, sequence, digest)) => (Some(epoch), Some(sequence), Some(digest)),
        None => (None, None, None),
    };
    connection
        .execute(
            "INSERT INTO history_epochs (history_epoch_id, owner_namespace, branch_serial_hi, branch_serial_lo, origin_transition, parent_history_epoch_id, parent_batch_sequence, parent_batch_digest, activation_certificate_digest) VALUES (?1, ?2, 0, 1, ?3, ?4, ?5, ?6, ?7)",
            params![epoch, vec![9_u8; 24], origin, parent_epoch, parent_sequence, parent_digest, vec![8_u8; 32]],
        )
        .map_err(|_| "COMPARISON-CLOSURE: epoch fixture failed")?;
    Ok(())
}

type OptionalBoundary<'a> = (
    Option<&'a [u8]>,
    Option<i64>,
    Option<&'a [u8]>,
    Option<&'a str>,
);

fn insert_batch(
    connection: &Connection,
    sequence: i64,
    epoch: &[u8],
    previous: &[u8],
    digest: &[u8],
    events: i64,
    boundary: Option<(&[u8], i64, &[u8], &str)>,
) -> Result<(), String> {
    let (parent_epoch, parent_sequence, parent_digest, origin): OptionalBoundary<'_> =
        match boundary {
            Some((epoch, sequence, digest, origin)) => {
                (Some(epoch), Some(sequence), Some(digest), Some(origin))
            }
            None => (None, None, None, None),
        };
    connection
        .execute(
            "INSERT INTO restore_comparison_batches (batch_sequence, history_epoch_id, source_transaction_sequence, event_count, previous_batch_digest, canonical_batch_digest, boundary_parent_history_epoch_id, boundary_parent_batch_sequence, boundary_parent_batch_digest, boundary_parent_origin) VALUES (?1, ?2, ?1, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![sequence, epoch, events, previous, digest, parent_epoch, parent_sequence, parent_digest, origin],
        )
        .map_err(|_| "COMPARISON-CLOSURE: batch write rejected")?;
    Ok(())
}

fn insert_event(
    connection: &Connection,
    sequence: i64,
    ordinal: i64,
    lifecycle: &str,
    message: &str,
    purge: Option<(i64, &str, &str)>,
) -> Result<(), String> {
    let (purged_at, source, reason): (Option<i64>, Option<&str>, Option<&str>) = match purge {
        Some((at, source, reason)) => (Some(at), Some(source), Some(reason)),
        None => (None, None, None),
    };
    let terminal = i64::from(matches!(
        lifecycle,
        "provider_accepted" | "failed" | "cancelled" | "expired" | "payload_purged"
    ));
    connection
        .execute(
            "INSERT INTO restore_comparison_events (batch_sequence, event_ordinal, lifecycle_event, command_ref, message_id, attempt_id, terminal, effect_may_have_occurred, duplicate_effect_possible, purge_message_id, purge_at_unix_ms, purge_source, purge_reason) VALUES (?1, ?2, ?3, NULL, ?4, NULL, ?5, 0, 0, CASE WHEN ?3 = 'payload_purged' THEN ?4 END, ?6, ?7, ?8)",
            params![sequence, ordinal, lifecycle, message, terminal, purged_at, source, reason],
        )
        .map_err(|_| "COMPARISON-CLOSURE: event write rejected")?;
    Ok(())
}

fn insert_meta(
    connection: &Connection,
    epoch: &[u8],
    anchor_sequence: i64,
    anchor_digest: &[u8],
    head_sequence: i64,
    head_digest: &[u8],
) -> Result<(), String> {
    connection
        .execute(
            "INSERT INTO meta (singleton, schema_version, active_configuration_generation, runtime_instance_id, lineage_id, transaction_sequence, authorization_epoch, active_history_epoch_id, comparison_anchor_batch_sequence, comparison_anchor_batch_digest, comparison_head_batch_sequence, comparison_head_batch_digest, selected_origin_incarnation, last_safe_wall_time_unix_ms) VALUES (1, 2, 1, 'runtime', 'lineage', 0, 0, ?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            params![epoch, anchor_sequence, anchor_digest, head_sequence, head_digest, vec![7_u8; 32]],
        )
        .map_err(|_| "COMPARISON-CLOSURE: selected meta rejected")?;
    Ok(())
}

#[test]
fn selected_head_rejects_orphan_purge_and_preserves_a_compacted_anchor_chain() -> Result<(), String>
{
    let (_database, connection) = install()?;
    let epoch = vec![1_u8; 32];
    let zero = vec![0_u8; 32];
    let batch_zero = vec![2_u8; 32];
    let batch_one = vec![3_u8; 32];
    let batch_two = vec![4_u8; 32];
    insert_epoch(&connection, &epoch, "bootstrap", None)?;
    insert_batch(&connection, 0, &epoch, &zero, &batch_zero, 1, None)?;
    insert_event(&connection, 0, 0, "accepted", "message-0", None)?;
    insert_meta(&connection, &epoch, 0, &batch_zero, 0, &batch_zero)?;

    if insert_batch(&connection, 2, &epoch, &batch_zero, &batch_two, 1, None).is_ok() {
        return Err("COMPARISON-CLOSURE: noncontiguous batch sequence was accepted".to_owned());
    }

    insert_batch(&connection, 1, &epoch, &batch_zero, &batch_one, 1, None)?;
    insert_event(
        &connection,
        1,
        0,
        "payload_purged",
        "message-0",
        Some((10, "operator", "operator_request")),
    )?;
    if connection
        .execute(
            "UPDATE meta SET comparison_head_batch_sequence = 1, comparison_head_batch_digest = ?1",
            [batch_one.as_slice()],
        )
        .is_ok()
    {
        return Err("COMPARISON-CLOSURE: orphan purge event became selected".to_owned());
    }
    if connection
        .execute(
            "INSERT INTO purge_tombstones (message_id, purged_at_unix_ms, purge_source, purge_reason, history_epoch_id, comparison_batch_sequence, comparison_event_ordinal) VALUES ('message-0', 11, 'operator', 'operator_request', ?1, 1, 0)",
            [epoch.as_slice()],
        )
        .is_ok()
    {
        return Err("COMPARISON-CLOSURE: mismatched tombstone projection was accepted".to_owned());
    }
    connection
        .execute(
            "INSERT INTO purge_tombstones (message_id, purged_at_unix_ms, purge_source, purge_reason, history_epoch_id, comparison_batch_sequence, comparison_event_ordinal) VALUES ('message-0', 10, 'operator', 'operator_request', ?1, 1, 0)",
            [epoch.as_slice()],
        )
        .map_err(|_| "COMPARISON-CLOSURE: matched tombstone rejected")?;
    connection
        .execute(
            "UPDATE meta SET comparison_head_batch_sequence = 1, comparison_head_batch_digest = ?1",
            [batch_one.as_slice()],
        )
        .map_err(|_| "COMPARISON-CLOSURE: matched purge head rejected")?;
    if connection
        .execute(
            "DELETE FROM restore_comparison_events WHERE batch_sequence = 1",
            [],
        )
        .is_ok()
    {
        return Err("COMPARISON-CLOSURE: event above selected anchor was deleted".to_owned());
    }
    connection
        .execute(
            "UPDATE meta SET comparison_anchor_batch_sequence = 1, comparison_anchor_batch_digest = ?1",
            [batch_one.as_slice()],
        )
        .map_err(|_| "COMPARISON-CLOSURE: valid anchor advance rejected")?;
    if connection
        .execute(
            "UPDATE meta SET comparison_anchor_batch_sequence = 0, comparison_anchor_batch_digest = ?1",
            [batch_zero.as_slice()],
        )
        .is_ok()
    {
        return Err("COMPARISON-CLOSURE: anchor regression was accepted".to_owned());
    }
    let wrong_anchor = vec![6_u8; 32];
    if connection
        .execute(
            "UPDATE meta SET comparison_anchor_batch_digest = ?1",
            [wrong_anchor.as_slice()],
        )
        .is_ok()
    {
        return Err("COMPARISON-CLOSURE: anchor digest mismatch was accepted".to_owned());
    }
    connection
        .execute(
            "DELETE FROM restore_comparison_events WHERE batch_sequence = 0",
            [],
        )
        .map_err(|_| "COMPARISON-CLOSURE: compactable event rejected")?;
    connection
        .execute(
            "DELETE FROM restore_comparison_batches WHERE batch_sequence = 0",
            [],
        )
        .map_err(|_| "COMPARISON-CLOSURE: compactable batch rejected")?;
    connection
        .execute(
            "DELETE FROM restore_comparison_events WHERE batch_sequence = 1",
            [],
        )
        .map_err(|_| "COMPARISON-CLOSURE: anchor event compaction rejected")?;
    connection
        .execute(
            "DELETE FROM restore_comparison_batches WHERE batch_sequence = 1",
            [],
        )
        .map_err(|_| "COMPARISON-CLOSURE: anchor batch compaction rejected")?;

    insert_batch(&connection, 2, &epoch, &batch_one, &batch_two, 1, None)?;
    insert_event(&connection, 2, 0, "accepted", "message-2", None)?;
    connection
        .execute(
            "UPDATE meta SET comparison_head_batch_sequence = 2, comparison_head_batch_digest = ?1",
            [batch_two.as_slice()],
        )
        .map_err(|_| "COMPARISON-CLOSURE: compacted anchor blocked next selected head")?;
    Ok(())
}

#[test]
fn typed_boundary_and_event_ordinal_reject_contradictory_rows() -> Result<(), String> {
    let (_database, connection) = install()?;
    let epoch = vec![1_u8; 32];
    let restore_epoch = vec![5_u8; 32];
    let zero = vec![0_u8; 32];
    let batch_zero = vec![2_u8; 32];
    let batch_one = vec![3_u8; 32];
    insert_epoch(&connection, &epoch, "bootstrap", None)?;
    insert_batch(&connection, 0, &epoch, &zero, &batch_zero, 1, None)?;
    insert_event(&connection, 0, 0, "accepted", "message-0", None)?;
    insert_meta(&connection, &epoch, 0, &batch_zero, 0, &batch_zero)?;
    insert_epoch(
        &connection,
        &restore_epoch,
        "restore",
        Some((&epoch, 0, &batch_zero)),
    )?;
    let wrong = vec![9_u8; 32];
    if insert_batch(
        &connection,
        1,
        &restore_epoch,
        &batch_zero,
        &batch_one,
        1,
        Some((&epoch, 0, &wrong, "selected_head")),
    )
    .is_ok()
    {
        return Err("COMPARISON-CLOSURE: stale boundary digest was accepted".to_owned());
    }
    insert_batch(
        &connection,
        1,
        &restore_epoch,
        &batch_zero,
        &batch_one,
        1,
        Some((&epoch, 0, &batch_zero, "selected_head")),
    )?;
    if insert_event(&connection, 1, 1, "accepted", "message-1", None).is_ok() {
        return Err("COMPARISON-CLOSURE: noncontiguous event ordinal was accepted".to_owned());
    }
    Ok(())
}
