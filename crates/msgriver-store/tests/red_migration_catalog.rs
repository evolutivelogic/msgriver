//! Frozen RED contract for the explicit A-10.2.1 migration catalog.

#![forbid(unsafe_code)]

use msgriver_store::{MigrationProvenance, Store, StoreFrontier, StoreOpenConfig};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const PROFILE: StoreOpenConfig = StoreOpenConfig::new(1_000, 4 * 1024 * 1024);
const V1_CHECKSUM: [u8; 32] = [
    0xf8, 0x7b, 0x65, 0xde, 0xb2, 0x95, 0x6b, 0x5a, 0x43, 0x41, 0x63, 0x4f, 0x24, 0xf4, 0xc0, 0x30,
    0xbc, 0x91, 0xcd, 0xdd, 0xbf, 0x6d, 0x73, 0x5c, 0xb4, 0xb2, 0x7d, 0x44, 0x18, 0x12, 0x0e, 0x84,
];
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TemporaryDatabase(PathBuf);

impl TemporaryDatabase {
    fn create() -> std::io::Result<Self> {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "msgriver-migration-red-{}-{sequence}",
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
fn migration_catalog_is_explicit_and_starts_only_at_the_migration_frontier() -> Result<(), String> {
    let catalog = Store::migration_catalog();
    if catalog.len() != 1
        || catalog[0].version != 1
        || catalog[0].checksum != V1_CHECKSUM
        || Sha256::digest(catalog[0].sql.as_bytes()).as_slice() != V1_CHECKSUM
    {
        return Err("MIGRATION-CATALOG-V1: compiled inventory drifted".to_owned());
    }
    let database =
        TemporaryDatabase::create().map_err(|_| "MIGRATION-CATALOG-V1: fixture failed")?;
    let mut store =
        Store::open(&database.0, PROFILE).map_err(|_| "MIGRATION-CATALOG-V1: open failed")?;
    let connection =
        Connection::open(&database.0).map_err(|_| "MIGRATION-CATALOG-V1: inspection failed")?;
    let before: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "MIGRATION-CATALOG-V1: inspection failed")?;
    if before != 0 {
        return Err("MIGRATION-CATALOG-V1: Store::open applied migration".to_owned());
    }
    match store.apply_migrations(MigrationProvenance {
        binary_identity: b"red-fixture",
        applied_at_unix_ms: 1,
    }) {
        Err(_) => Err("MIGRATION-CATALOG-V1: unexpected migration error".to_owned()),
        Ok(()) => {
            let row: (i64, Vec<u8>) = connection
                .query_row(
                    "SELECT version, checksum FROM schema_migrations",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| "MIGRATION-CATALOG-V1: v1 row missing")?;
            if row == (1, V1_CHECKSUM.to_vec()) {
                Ok(())
            } else {
                Err("MIGRATION-CATALOG-V1: v1 row mismatched".to_owned())
            }
        }
    }
}

#[test]
fn migration_catalog_persists_v1_once_and_replays_without_rewriting_provenance()
-> Result<(), String> {
    let database = TemporaryDatabase::create().map_err(|_| "MIGRATION-REPLAY: fixture failed")?;
    let first = MigrationProvenance {
        binary_identity: b"first-binary",
        applied_at_unix_ms: 10,
    };
    {
        let mut store =
            Store::open(&database.0, PROFILE).map_err(|_| "MIGRATION-REPLAY: open failed")?;
        match store.apply_migrations(first) {
            Err(error) if error.scaffold_frontier() == Some(StoreFrontier::MigrationCatalog) => {
                return Err("MIGRATION-REPLAY: behavior missing — terminated at RED frontier `migration_catalog`".to_owned());
            }
            Err(_) => return Err("MIGRATION-REPLAY: unexpected first migration error".to_owned()),
            Ok(()) => {}
        }
    }
    {
        let mut store =
            Store::open(&database.0, PROFILE).map_err(|_| "MIGRATION-REPLAY: reopen failed")?;
        store
            .apply_migrations(MigrationProvenance {
                binary_identity: b"different-binary",
                applied_at_unix_ms: 20,
            })
            .map_err(|_| "MIGRATION-REPLAY: exact retry failed")?;
    }
    let connection =
        Connection::open(&database.0).map_err(|_| "MIGRATION-REPLAY: inspection failed")?;
    let replay_row: (i64, Vec<u8>, Vec<u8>, i64) = connection
        .query_row(
            "SELECT version, checksum, applied_binary, applied_at_unix_ms FROM schema_migrations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| "MIGRATION-REPLAY: v1 row disappeared")?;
    if replay_row != (1, V1_CHECKSUM.to_vec(), b"first-binary".to_vec(), 10) {
        return Err("MIGRATION-REPLAY: retry rewrote provenance".to_owned());
    }
    Ok(())
}

#[test]
fn migration_catalog_rejects_checksum_conflict_without_rewriting_history() -> Result<(), String> {
    let database = TemporaryDatabase::create().map_err(|_| "MIGRATION-CONFLICT: fixture failed")?;
    let descriptor = Store::migration_catalog()[0];
    let connection =
        Connection::open(&database.0).map_err(|_| "MIGRATION-CONFLICT: seed failed")?;
    connection
        .execute_batch(descriptor.sql)
        .map_err(|_| "MIGRATION-CONFLICT: schema seed failed")?;
    let conflicting_checksum = vec![0_u8; 32];
    connection
        .execute(
            "INSERT INTO schema_migrations (version, checksum, applied_binary, applied_at_unix_ms) VALUES (?1, ?2, ?3, ?4)",
            (1_i64, &conflicting_checksum, b"old-binary".as_slice(), 7_i64),
        )
        .map_err(|_| "MIGRATION-CONFLICT: row seed failed")?;
    drop(connection);

    let mut store =
        Store::open(&database.0, PROFILE).map_err(|_| "MIGRATION-CONFLICT: open failed")?;
    match store.apply_migrations(MigrationProvenance {
        binary_identity: b"new-binary",
        applied_at_unix_ms: 8,
    }) {
        Err(error) if error.scaffold_frontier() == Some(StoreFrontier::MigrationCatalog) => {
            return Err("MIGRATION-CONFLICT: behavior missing — terminated at RED frontier `migration_catalog`".to_owned());
        }
        Err(_) => {}
        Ok(()) => return Err("MIGRATION-CONFLICT: checksum conflict was accepted".to_owned()),
    }
    let connection =
        Connection::open(&database.0).map_err(|_| "MIGRATION-CONFLICT: inspection failed")?;
    let row: (Vec<u8>, Vec<u8>, i64) = connection
        .query_row(
            "SELECT checksum, applied_binary, applied_at_unix_ms FROM schema_migrations WHERE version = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| "MIGRATION-CONFLICT: original row disappeared")?;
    if row != (conflicting_checksum, b"old-binary".to_vec(), 7) {
        return Err("MIGRATION-CONFLICT: conflict rewrote history".to_owned());
    }
    Ok(())
}

#[test]
fn migration_catalog_rejects_missing_and_newer_history_without_rewriting_it() -> Result<(), String>
{
    let missing = TemporaryDatabase::create().map_err(|_| "MIGRATION-HISTORY: fixture failed")?;
    let descriptor = Store::migration_catalog()[0];
    let connection =
        Connection::open(&missing.0).map_err(|_| "MIGRATION-HISTORY: missing seed failed")?;
    connection
        .execute_batch(descriptor.sql)
        .map_err(|_| "MIGRATION-HISTORY: missing schema seed failed")?;
    drop(connection);
    let mut store =
        Store::open(&missing.0, PROFILE).map_err(|_| "MIGRATION-HISTORY: missing open failed")?;
    if store
        .apply_migrations(MigrationProvenance {
            binary_identity: b"new-binary",
            applied_at_unix_ms: 8,
        })
        .is_ok()
    {
        return Err("MIGRATION-HISTORY: missing required row was accepted".to_owned());
    }
    drop(store);
    let connection =
        Connection::open(&missing.0).map_err(|_| "MIGRATION-HISTORY: missing inspection failed")?;
    let missing_rows: i64 = connection
        .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .map_err(|_| "MIGRATION-HISTORY: missing inspection failed")?;
    if missing_rows != 0 {
        return Err("MIGRATION-HISTORY: missing history was rewritten".to_owned());
    }
    drop(connection);

    let newer = TemporaryDatabase::create().map_err(|_| "MIGRATION-HISTORY: fixture failed")?;
    let connection =
        Connection::open(&newer.0).map_err(|_| "MIGRATION-HISTORY: newer seed failed")?;
    connection
        .execute_batch(descriptor.sql)
        .map_err(|_| "MIGRATION-HISTORY: newer schema seed failed")?;
    connection
        .execute(
            "INSERT INTO schema_migrations (version, checksum, applied_binary, applied_at_unix_ms) VALUES (?1, ?2, ?3, ?4)",
            (1_i64, V1_CHECKSUM.as_slice(), b"old-binary".as_slice(), 7_i64),
        )
        .map_err(|_| "MIGRATION-HISTORY: v1 row seed failed")?;
    connection
        .execute(
            "INSERT INTO schema_migrations (version, checksum, applied_binary, applied_at_unix_ms) VALUES (?1, ?2, ?3, ?4)",
            (2_i64, V1_CHECKSUM.as_slice(), b"future-binary".as_slice(), 8_i64),
        )
        .map_err(|_| "MIGRATION-HISTORY: newer row seed failed")?;
    drop(connection);
    let mut store =
        Store::open(&newer.0, PROFILE).map_err(|_| "MIGRATION-HISTORY: newer open failed")?;
    if store
        .apply_migrations(MigrationProvenance {
            binary_identity: b"new-binary",
            applied_at_unix_ms: 9,
        })
        .is_ok()
    {
        return Err("MIGRATION-HISTORY: newer history was accepted".to_owned());
    }
    drop(store);
    let connection =
        Connection::open(&newer.0).map_err(|_| "MIGRATION-HISTORY: newer inspection failed")?;
    let rows: Vec<(i64, Vec<u8>, Vec<u8>, i64)> = connection
        .prepare(
            "SELECT version, checksum, applied_binary, applied_at_unix_ms FROM schema_migrations ORDER BY version",
        )
        .map_err(|_| "MIGRATION-HISTORY: newer inspection failed")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
        .map_err(|_| "MIGRATION-HISTORY: newer inspection failed")?
        .collect::<Result<_, _>>()
        .map_err(|_| "MIGRATION-HISTORY: newer inspection failed")?;
    if rows
        != vec![
            (1, V1_CHECKSUM.to_vec(), b"old-binary".to_vec(), 7),
            (2, V1_CHECKSUM.to_vec(), b"future-binary".to_vec(), 8),
        ]
    {
        return Err("MIGRATION-HISTORY: newer history was rewritten".to_owned());
    }
    Ok(())
}

#[test]
fn migration_catalog_rejects_incompatible_populated_ledger() -> Result<(), String> {
    let database =
        TemporaryDatabase::create().map_err(|_| "MIGRATION-INCOMPATIBLE: fixture failed")?;
    let connection =
        Connection::open(&database.0).map_err(|_| "MIGRATION-INCOMPATIBLE: seed failed")?;
    connection
        .execute_batch(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, checksum BLOB NOT NULL);",
        )
        .map_err(|_| "MIGRATION-INCOMPATIBLE: schema seed failed")?;
    connection
        .execute(
            "INSERT INTO schema_migrations (version, checksum) VALUES (?1, ?2)",
            (1_i64, V1_CHECKSUM.as_slice()),
        )
        .map_err(|_| "MIGRATION-INCOMPATIBLE: row seed failed")?;
    drop(connection);
    let mut store =
        Store::open(&database.0, PROFILE).map_err(|_| "MIGRATION-INCOMPATIBLE: open failed")?;
    let error = match store.apply_migrations(MigrationProvenance {
        binary_identity: b"caller-controlled-binary",
        applied_at_unix_ms: 9,
    }) {
        Err(error) => error,
        Ok(()) => return Err("MIGRATION-INCOMPATIBLE: incompatible ledger was accepted".to_owned()),
    };
    let sentinel = database.0.to_string_lossy();
    if format!("{error:?}").contains(sentinel.as_ref())
        || error.to_string().contains(sentinel.as_ref())
        || format!("{error:?}").contains("schema_migrations")
        || error.to_string().contains("schema_migrations")
        || format!("{error:?}").contains("caller-controlled-binary")
        || error.to_string().contains("caller-controlled-binary")
        || std::error::Error::source(&error).is_some()
    {
        return Err("MIGRATION-INCOMPATIBLE: error exposed diagnostics".to_owned());
    }
    let connection =
        Connection::open(&database.0).map_err(|_| "MIGRATION-INCOMPATIBLE: inspection failed")?;
    let columns: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('schema_migrations')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "MIGRATION-INCOMPATIBLE: inspection failed")?;
    if columns != 2 {
        return Err("MIGRATION-INCOMPATIBLE: incompatible ledger changed".to_owned());
    }
    Ok(())
}

#[test]
fn migration_catalog_rejects_empty_provenance_against_valid_history() -> Result<(), String> {
    let database =
        TemporaryDatabase::create().map_err(|_| "MIGRATION-PROVENANCE: fixture failed")?;
    let mut store =
        Store::open(&database.0, PROFILE).map_err(|_| "MIGRATION-PROVENANCE: open failed")?;
    store
        .apply_migrations(MigrationProvenance {
            binary_identity: b"first-binary",
            applied_at_unix_ms: 1,
        })
        .map_err(|_| "MIGRATION-PROVENANCE: initial migration failed")?;
    if store
        .apply_migrations(MigrationProvenance {
            binary_identity: b"",
            applied_at_unix_ms: 2,
        })
        .is_ok()
    {
        return Err("MIGRATION-PROVENANCE: empty provenance was accepted".to_owned());
    }
    drop(store);
    let connection =
        Connection::open(&database.0).map_err(|_| "MIGRATION-PROVENANCE: inspection failed")?;
    let row: (Vec<u8>, i64) = connection
        .query_row(
            "SELECT applied_binary, applied_at_unix_ms FROM schema_migrations WHERE version = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| "MIGRATION-PROVENANCE: v1 row missing")?;
    if row != (b"first-binary".to_vec(), 1) {
        return Err("MIGRATION-PROVENANCE: empty retry rewrote history".to_owned());
    }
    Ok(())
}
