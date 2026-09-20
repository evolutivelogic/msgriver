//! Frozen RED contract for the complete selected-state v2 migration.

#![forbid(unsafe_code)]

use msgriver_store::{MigrationProvenance, Store, StoreOpenConfig};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const PROFILE: StoreOpenConfig = StoreOpenConfig::new(1_000, 4 * 1024 * 1024);
const V2_CHECKSUM: [u8; 32] = [
    0xd2, 0x8d, 0x42, 0xfb, 0xa1, 0x3f, 0x53, 0xd1, 0x90, 0x9c, 0xe0, 0x44, 0xd5, 0x99, 0x24, 0xf5,
    0x2e, 0x27, 0x6d, 0x3c, 0xed, 0xc1, 0xc3, 0x88, 0x4b, 0xc4, 0x04, 0xdb, 0x45, 0x55, 0x6d, 0x43,
];
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TemporaryDatabase(PathBuf);

impl TemporaryDatabase {
    fn create() -> std::io::Result<Self> {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "msgriver-v2-schema-red-{}-{sequence}",
            std::process::id(),
        ));
        fs::create_dir(&directory)?;
        Ok(Self(directory.join("store.db")))
    }
}

impl Drop for TemporaryDatabase {
    fn drop(&mut self) {
        if let Some(directory) = self.0.parent() {
            let _ = fs::remove_dir_all(directory);
        }
    }
}

#[test]
fn v2_selected_state_contract_is_explicit_and_applies_as_one_catalog_entry() -> Result<(), String> {
    let catalog = Store::selected_state_migration_catalog();
    let v2 = catalog
        .get(1)
        .ok_or_else(|| "V2-SCHEMA: migration descriptor missing".to_owned())?;
    if catalog.len() != 2
        || catalog[0].version != 1
        || v2.version != 2
        || v2.checksum != V2_CHECKSUM
        || Sha256::digest(v2.sql.as_bytes()).as_slice() != V2_CHECKSUM
    {
        return Err("V2-SCHEMA: catalog is not exactly v1 plus pinned v2".to_owned());
    }

    let database = TemporaryDatabase::create().map_err(|_| "V2-SCHEMA: fixture failed")?;
    let mut store = Store::open(&database.0, PROFILE).map_err(|_| "V2-SCHEMA: open failed")?;
    store
        .apply_migrations(MigrationProvenance {
            binary_identity: b"v2-schema-red",
            applied_at_unix_ms: 1,
        })
        .map_err(|_| "V2-SCHEMA: explicit migration failed")?;

    let connection = Connection::open(&database.0).map_err(|_| "V2-SCHEMA: inspection failed")?;
    let mut expected_tables = vec![
        "api_keys",
        "attempts",
        "audit_events",
        "backup_history",
        "backup_jobs",
        "configuration_generations",
        "connector_identities",
        "history_epochs",
        "idempotency_records",
        "messages",
        "meta",
        "meta_mac_serial_high_water",
        "operation_commands",
        "peer_mappings",
        "principals",
        "principal_provider_grants",
        "provider_runtime",
        "providers",
        "purge_tombstones",
        "replay_requests",
        "restore_comparison_batches",
        "restore_comparison_events",
        "scheduler_principal_cursor",
        "schema_migrations",
        "upgrade_state",
    ];
    expected_tables.sort_unstable();
    let actual_tables: Vec<String> = connection
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .map_err(|_| "V2-SCHEMA: inspection failed")?
        .query_map([], |row| row.get(0))
        .map_err(|_| "V2-SCHEMA: inspection failed")?
        .collect::<Result<_, _>>()
        .map_err(|_| "V2-SCHEMA: inspection failed")?;
    if actual_tables != expected_tables {
        return Err("V2-SCHEMA: derived table inventory drifted".to_owned());
    }
    Ok(())
}

#[test]
fn v2_rejects_a_newer_ledger_history_without_installing_or_rewriting_v2() -> Result<(), String> {
    let database = TemporaryDatabase::create().map_err(|_| "V2-HISTORY: fixture failed")?;
    let v1 = Store::migration_catalog()[0];
    let connection = Connection::open(&database.0).map_err(|_| "V2-HISTORY: seed failed")?;
    connection
        .execute_batch(v1.sql)
        .map_err(|_| "V2-HISTORY: v1 schema seed failed")?;
    connection
        .execute(
            "INSERT INTO schema_migrations (version, checksum, applied_binary, applied_at_unix_ms) VALUES (?1, ?2, ?3, ?4)",
            (1_i64, v1.checksum.as_slice(), b"first-binary".as_slice(), 10_i64),
        )
        .map_err(|_| "V2-HISTORY: v1 row seed failed")?;
    let future_checksum = [0x73_u8; 32];
    connection
        .execute(
            "INSERT INTO schema_migrations (version, checksum, applied_binary, applied_at_unix_ms) VALUES (?1, ?2, ?3, ?4)",
            (3_i64, future_checksum.as_slice(), b"future-binary".as_slice(), 20_i64),
        )
        .map_err(|_| "V2-HISTORY: future row seed failed")?;
    drop(connection);

    let mut store = Store::open(&database.0, PROFILE).map_err(|_| "V2-HISTORY: open failed")?;
    if store
        .apply_migrations(MigrationProvenance {
            binary_identity: b"new-binary",
            applied_at_unix_ms: 30,
        })
        .is_ok()
    {
        return Err("V2-HISTORY: newer history was accepted".to_owned());
    }
    drop(store);

    let inspection = Connection::open(&database.0).map_err(|_| "V2-HISTORY: inspection failed")?;
    let rows: Vec<(i64, Vec<u8>, Vec<u8>, i64)> = inspection
        .prepare(
            "SELECT version, checksum, applied_binary, applied_at_unix_ms FROM schema_migrations ORDER BY version",
        )
        .map_err(|_| "V2-HISTORY: inspection failed")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
        .map_err(|_| "V2-HISTORY: inspection failed")?
        .collect::<Result<_, _>>()
        .map_err(|_| "V2-HISTORY: inspection failed")?;
    if rows
        != vec![
            (1, v1.checksum.to_vec(), b"first-binary".to_vec(), 10),
            (3, future_checksum.to_vec(), b"future-binary".to_vec(), 20),
        ]
    {
        return Err("V2-HISTORY: rejected history was rewritten".to_owned());
    }
    Ok(())
}

#[test]
fn v2_replay_preserves_the_first_v1_and_v2_provenance_rows() -> Result<(), String> {
    let database = TemporaryDatabase::create().map_err(|_| "V2-REPLAY: fixture failed")?;
    let first = MigrationProvenance {
        binary_identity: b"first-binary",
        applied_at_unix_ms: 10,
    };
    {
        let mut store =
            Store::open(&database.0, PROFILE).map_err(|_| "V2-REPLAY: first open failed")?;
        store
            .apply_migrations(first)
            .map_err(|_| "V2-REPLAY: first migration failed")?;
    }
    {
        let mut store =
            Store::open(&database.0, PROFILE).map_err(|_| "V2-REPLAY: replay open failed")?;
        store
            .apply_migrations(MigrationProvenance {
                binary_identity: b"second-binary",
                applied_at_unix_ms: 20,
            })
            .map_err(|_| "V2-REPLAY: replay migration failed")?;
    }

    let connection = Connection::open(&database.0).map_err(|_| "V2-REPLAY: inspection failed")?;
    let rows: Vec<(i64, Vec<u8>, Vec<u8>, i64)> = connection
        .prepare(
            "SELECT version, checksum, applied_binary, applied_at_unix_ms FROM schema_migrations ORDER BY version",
        )
        .map_err(|_| "V2-REPLAY: inspection failed")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
        .map_err(|_| "V2-REPLAY: inspection failed")?
        .collect::<Result<_, _>>()
        .map_err(|_| "V2-REPLAY: inspection failed")?;
    let v1 = Store::migration_catalog()[0];
    if rows
        != vec![
            (1, v1.checksum.to_vec(), b"first-binary".to_vec(), 10),
            (2, V2_CHECKSUM.to_vec(), b"first-binary".to_vec(), 10),
        ]
    {
        return Err("V2-REPLAY: replay rewrote provenance".to_owned());
    }
    Ok(())
}

#[test]
fn v2_messages_require_acknowledgement_evidence_for_provider_acceptance() -> Result<(), String> {
    let database = TemporaryDatabase::create().map_err(|_| "V2-MESSAGES: fixture failed")?;
    let mut store = Store::open(&database.0, PROFILE).map_err(|_| "V2-MESSAGES: open failed")?;
    store
        .apply_migrations(MigrationProvenance {
            binary_identity: b"v2-message-shape",
            applied_at_unix_ms: 1,
        })
        .map_err(|_| "V2-MESSAGES: explicit migration failed")?;
    let connection = Connection::open(&database.0).map_err(|_| "V2-MESSAGES: inspection failed")?;
    let messages_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'messages'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "V2-MESSAGES: inspection failed")?;
    if !messages_sql.contains(
        "CHECK((state = 'provider_accepted') = (known_provider_ack_attempt_id IS NOT NULL))",
    ) || !messages_sql
        .contains("CHECK(state <> 'provider_accepted' OR effect_may_have_occurred = 1)")
    {
        return Err("V2-MESSAGES: provider acceptance lacks acknowledgement evidence".to_owned());
    }
    Ok(())
}

#[test]
fn v2_rejects_a_conflicting_checksum_without_rewriting_provenance() -> Result<(), String> {
    let database = TemporaryDatabase::create().map_err(|_| "V2-CHECKSUM: fixture failed")?;
    {
        let mut store =
            Store::open(&database.0, PROFILE).map_err(|_| "V2-CHECKSUM: first open failed")?;
        store
            .apply_migrations(MigrationProvenance {
                binary_identity: b"first-binary",
                applied_at_unix_ms: 10,
            })
            .map_err(|_| "V2-CHECKSUM: first migration failed")?;
    }
    let conflicting_checksum = [0x4c_u8; 32];
    let connection = Connection::open(&database.0).map_err(|_| "V2-CHECKSUM: seed failed")?;
    connection
        .execute(
            "UPDATE schema_migrations SET checksum = ?1 WHERE version = 2",
            [conflicting_checksum.as_slice()],
        )
        .map_err(|_| "V2-CHECKSUM: checksum seed failed")?;
    drop(connection);

    let mut store =
        Store::open(&database.0, PROFILE).map_err(|_| "V2-CHECKSUM: replay open failed")?;
    if store
        .apply_migrations(MigrationProvenance {
            binary_identity: b"second-binary",
            applied_at_unix_ms: 20,
        })
        .is_ok()
    {
        return Err("V2-CHECKSUM: conflicting checksum was accepted".to_owned());
    }
    drop(store);

    let connection = Connection::open(&database.0).map_err(|_| "V2-CHECKSUM: inspection failed")?;
    let row: (Vec<u8>, Vec<u8>, i64) = connection
        .query_row(
            "SELECT checksum, applied_binary, applied_at_unix_ms FROM schema_migrations WHERE version = 2",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| "V2-CHECKSUM: inspection failed")?;
    if row != (conflicting_checksum.to_vec(), b"first-binary".to_vec(), 10) {
        return Err("V2-CHECKSUM: rejected history was rewritten".to_owned());
    }
    Ok(())
}

#[test]
fn v2_rejects_duplicate_incompatible_history_without_installing_schema() -> Result<(), String> {
    let database = TemporaryDatabase::create().map_err(|_| "V2-DUPLICATE: fixture failed")?;
    let v1 = Store::migration_catalog()[0];
    let connection = Connection::open(&database.0).map_err(|_| "V2-DUPLICATE: seed failed")?;
    connection
        .execute_batch(
            "CREATE TABLE schema_migrations (version INTEGER NOT NULL, checksum BLOB NOT NULL, applied_binary BLOB NOT NULL, applied_at_unix_ms INTEGER NOT NULL);",
        )
        .map_err(|_| "V2-DUPLICATE: schema seed failed")?;
    for applied_at_unix_ms in [10_i64, 20_i64] {
        connection
            .execute(
                "INSERT INTO schema_migrations (version, checksum, applied_binary, applied_at_unix_ms) VALUES (?1, ?2, ?3, ?4)",
                (1_i64, v1.checksum.as_slice(), b"old-binary".as_slice(), applied_at_unix_ms),
            )
            .map_err(|_| "V2-DUPLICATE: row seed failed")?;
    }
    drop(connection);

    let mut store = Store::open(&database.0, PROFILE).map_err(|_| "V2-DUPLICATE: open failed")?;
    if store
        .apply_migrations(MigrationProvenance {
            binary_identity: b"new-binary",
            applied_at_unix_ms: 30,
        })
        .is_ok()
    {
        return Err("V2-DUPLICATE: duplicate history was accepted".to_owned());
    }
    drop(store);

    let inspection =
        Connection::open(&database.0).map_err(|_| "V2-DUPLICATE: inspection failed")?;
    let rows: i64 = inspection
        .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .map_err(|_| "V2-DUPLICATE: inspection failed")?;
    let v2_tables: i64 = inspection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'meta'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "V2-DUPLICATE: inspection failed")?;
    if rows != 2 || v2_tables != 0 {
        return Err("V2-DUPLICATE: rejected history was rewritten".to_owned());
    }
    Ok(())
}
