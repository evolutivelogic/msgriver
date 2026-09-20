//! MsgRiver durable store.
//!
//! The first executable seam is deliberately limited to opening one future
//! actor-owned SQLite connection under the verified A-10.1 profile. Enqueue,
//! schema, migrations, actor ownership, and every product mutation remain
//! outside this initial scaffold frontier.

#![forbid(unsafe_code)]

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;
use std::time::Duration;

const SQLITE_VERSION_FLOOR: i32 = 3_051_003;
const BUSY_TIMEOUT_MS: u64 = 5_000;
const SYNCHRONOUS_FULL: i64 = 2;

/// The private initial store behavior frontier used by frozen RED tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum StoreFrontier {
    /// Opening and verifying the retained SQLite connection.
    ProfileOpen,
    /// Applying the explicit migration catalog.
    MigrationCatalog,
    /// Reading the selected non-secret state-key snapshot.
    SelectedKeySnapshot,
}

/// One checksum-pinned, embedded migration entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationDescriptor {
    /// Strictly increasing, nonzero schema version.
    pub version: u32,
    /// SHA-256 of the exact embedded SQL bytes.
    pub checksum: [u8; 32],
    /// Immutable SQL source bytes.
    pub sql: &'static str,
}

/// Maintenance-owned provenance persisted by an explicit migration call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationProvenance<'a> {
    /// Opaque nonempty binary identity supplied by the maintenance caller.
    pub binary_identity: &'a [u8],
    /// Caller-supplied Unix time in milliseconds.
    pub applied_at_unix_ms: i64,
}

const MIGRATION_V1_SQL: &str = "CREATE TABLE schema_migrations (\n    version INTEGER PRIMARY KEY CHECK (version > 0),\n    checksum BLOB NOT NULL CHECK (length(checksum) = 32),\n    applied_binary BLOB NOT NULL CHECK (length(applied_binary) > 0),\n    applied_at_unix_ms INTEGER NOT NULL\n);\n";
const MIGRATION_V1_CHECKSUM: [u8; 32] = [
    0xf8, 0x7b, 0x65, 0xde, 0xb2, 0x95, 0x6b, 0x5a, 0x43, 0x41, 0x63, 0x4f, 0x24, 0xf4, 0xc0, 0x30,
    0xbc, 0x91, 0xcd, 0xdd, 0xbf, 0x6d, 0x73, 0x5c, 0xb4, 0xb2, 0x7d, 0x44, 0x18, 0x12, 0x0e, 0x84,
];
const MIGRATION_V2_SQL: &str =
    include_str!(concat!(env!("OUT_DIR"), "/migration_v2_selected_state.sql"));
const MIGRATION_V2_CHECKSUM: [u8; 32] = [
    0xd2, 0x8d, 0x42, 0xfb, 0xa1, 0x3f, 0x53, 0xd1, 0x90, 0x9c, 0xe0, 0x44, 0xd5, 0x99, 0x24, 0xf5,
    0x2e, 0x27, 0x6d, 0x3c, 0xed, 0xc1, 0xc3, 0x88, 0x4b, 0xc4, 0x04, 0xdb, 0x45, 0x55, 0x6d, 0x43,
];
const MIGRATION_V3_SQL: &str = include_str!("migration_v3_m2_delivery.sql");
const MIGRATION_V3_CHECKSUM: [u8; 32] = [
    0x98, 0x72, 0x5f, 0x75, 0xc0, 0xa3, 0xd2, 0x85, 0xd2, 0xf4, 0x0a, 0x47, 0x33, 0x52, 0xb1, 0x5b,
    0xce, 0xdb, 0x3b, 0x09, 0x43, 0x5f, 0xfc, 0x4f, 0x49, 0xf3, 0x1a, 0x32, 0x38, 0x13, 0x76, 0xa6,
];
const MIGRATION_V4_SQL: &str = include_str!("migration_v4_driver_queue.sql");
const MIGRATION_V4_CHECKSUM: [u8; 32] = [
    0x44, 0x9b, 0xb7, 0xc7, 0x53, 0x4e, 0xd3, 0x46, 0x99, 0x46, 0xc3, 0x82, 0x63, 0xf2, 0x87, 0xb1,
    0x69, 0x47, 0xc8, 0x91, 0xf4, 0x95, 0xc0, 0xd8, 0xcd, 0x55, 0x65, 0xc4, 0x54, 0x34, 0xd7, 0x4f,
];
const MIGRATION_V5_SQL: &str = include_str!("migration_v5_whatsapp_inbound.sql");
const MIGRATION_V5_CHECKSUM: [u8; 32] = [
    0xf7, 0x12, 0x7c, 0xa8, 0x7e, 0xf7, 0x5d, 0x0c, 0xf1, 0xe0, 0x1a, 0x9c, 0x6c, 0x9d, 0x24, 0xd6,
    0x79, 0x89, 0xda, 0xc6, 0xe1, 0xf8, 0xae, 0xf0, 0xdc, 0x1b, 0x98, 0xec, 0x12, 0x51, 0x56, 0xa9,
];
const MIGRATION_CATALOG: [MigrationDescriptor; 1] = [MigrationDescriptor {
    version: 1,
    checksum: MIGRATION_V1_CHECKSUM,
    sql: MIGRATION_V1_SQL,
}];
const SELECTED_STATE_MIGRATION_CATALOG: [MigrationDescriptor; 2] = [
    MigrationDescriptor {
        version: 1,
        checksum: MIGRATION_V1_CHECKSUM,
        sql: MIGRATION_V1_SQL,
    },
    MigrationDescriptor {
        version: 2,
        checksum: MIGRATION_V2_CHECKSUM,
        sql: MIGRATION_V2_SQL,
    },
];
const PRODUCT_MIGRATION_CATALOG: [MigrationDescriptor; 5] = [
    MigrationDescriptor {
        version: 1,
        checksum: MIGRATION_V1_CHECKSUM,
        sql: MIGRATION_V1_SQL,
    },
    MigrationDescriptor {
        version: 2,
        checksum: MIGRATION_V2_CHECKSUM,
        sql: MIGRATION_V2_SQL,
    },
    MigrationDescriptor {
        version: 3,
        checksum: MIGRATION_V3_CHECKSUM,
        sql: MIGRATION_V3_SQL,
    },
    MigrationDescriptor {
        version: 4,
        checksum: MIGRATION_V4_CHECKSUM,
        sql: MIGRATION_V4_SQL,
    },
    MigrationDescriptor {
        version: 5,
        checksum: MIGRATION_V5_CHECKSUM,
        sql: MIGRATION_V5_SQL,
    },
];

/// Configuration whose policy values are supplied by the later operator
/// configuration layer. This type defines only SQLite-representable inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreOpenConfig {
    /// Requested WAL autocheckpoint pages; zero is invalid.
    pub wal_autocheckpoint_pages: u32,
    /// Requested SQLite journal-size limit in bytes; negative is invalid.
    pub journal_size_limit_bytes: i64,
}

impl StoreOpenConfig {
    /// Construct the profile input without imposing policy defaults.
    pub const fn new(wal_autocheckpoint_pages: u32, journal_size_limit_bytes: i64) -> Self {
        Self {
            wal_autocheckpoint_pages,
            journal_size_limit_bytes,
        }
    }
}

/// Non-sensitive evidence returned only after a future connection profile is
/// verified on the same retained connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedStoreProfile {
    /// Linked SQLite numeric version.
    pub sqlite_version_number: i32,
    /// Verified WAL autocheckpoint setting.
    pub wal_autocheckpoint_pages: i32,
    /// Verified journal-size limit setting.
    pub journal_size_limit_bytes: i64,
}

/// Closed store-open failure categories. Their display/debug behavior must
/// never include paths, SQL, schema diagnostics, or integrity output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// The profile-opening behavior has not landed yet.
    #[doc(hidden)]
    Scaffold(StoreFrontier),
    /// Caller profile input is outside SQLite's representable safe domain.
    InvalidProfile,
    /// Linked SQLite is below the architecture floor.
    RuntimeVersion,
    /// Opening the database failed.
    Open,
    /// A required pragma did not install or read back exactly.
    Profile,
    /// Full integrity checking did not yield exactly `ok`.
    Integrity,
    /// Explicit migration validation or transaction completion failed.
    Migration,
    /// Selected state-key snapshot was unreadable or structurally invalid.
    SelectedKeySnapshot,
    /// The runnable-service message boundary could not complete durably.
    Delivery,
}

impl StoreError {
    /// The temporary RED frontier, absent once real behavior responds.
    #[doc(hidden)]
    pub const fn scaffold_frontier(&self) -> Option<StoreFrontier> {
        match self {
            Self::Scaffold(frontier) => Some(*frontier),
            Self::InvalidProfile
            | Self::RuntimeVersion
            | Self::Open
            | Self::Profile
            | Self::Integrity
            | Self::Migration
            | Self::SelectedKeySnapshot
            | Self::Delivery => None,
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Scaffold(_) => "store behavior is not available",
            Self::InvalidProfile => "invalid store profile",
            Self::RuntimeVersion => "unsupported SQLite runtime version",
            Self::Open => "store database open failed",
            Self::Profile => "store database profile verification failed",
            Self::Integrity => "store database integrity verification failed",
            Self::Migration => "store database migration failed",
            Self::SelectedKeySnapshot => "selected state-key snapshot unavailable",
            Self::Delivery => "durable message operation failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for StoreError {}

/// Opaque future owner of the actor's SQLite connection.
pub struct Store {
    connection: Option<Connection>,
    profile: VerifiedStoreProfile,
}

/// Non-secret raw selected-key facts extracted from one store snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedKeySnapshotRaw {
    pub selected_origin: Vec<u8>,
    pub high_waters: Vec<RawHighWaterCell>,
    pub manifest_rows: Vec<RawManifestCell>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHighWaterCell {
    pub purpose: i64,
    pub serial_hi: i64,
    pub serial_lo: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawManifestCell {
    pub purpose: i64,
    pub origin: Vec<u8>,
    pub serial_hi: i64,
    pub serial_lo: i64,
    pub status: i64,
    pub created_at: i64,
}

/// The smallest durable message accepted by the first runnable service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M2Submission<'a> {
    pub idempotency_key: &'a str,
    pub topic: &'a str,
    pub title: Option<&'a str>,
    pub body: &'a str,
}

/// Provider-neutral admission after the service has canonicalized a closed
/// driver command. The store intentionally receives no endpoint or secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M3Submission<'a> {
    pub idempotency_key: &'a str,
    pub driver: &'a str,
    pub destination: &'a str,
    pub payload: &'a str,
}

/// One already-authenticated and policy-authorized WhatsApp inbound effect.
/// Its fixed driver intent is committed with replay/rate accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M4InboundSubmission<'a> {
    pub provider_message_id: &'a str,
    pub sender: &'a str,
    pub verb: &'a str,
    pub driver: &'a str,
    pub destination: &'a str,
    pub payload: &'a str,
}

/// A non-oracular disposition for an authenticated callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum M4InboundDisposition {
    Accepted,
    Disabled,
    Replayed,
    RateLimited,
}

/// The stable result of durable admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum M2Accepted {
    New { message_id: String },
    Existing { message_id: String },
}

/// One service-owned work item that crossed a durable sending boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M2Delivery {
    pub message_id: String,
    /// Closed driver identity pinned at durable admission.
    pub driver: String,
    /// Provider-neutral canonical destination snapshot.
    pub destination: String,
    /// Provider-neutral canonical payload snapshot.
    pub payload: String,
    pub topic: String,
    pub title: Option<String>,
    pub body: String,
    pub attempt: u8,
}

type ClaimedM3Row = (
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    String,
    i64,
);

fn read_selected_key_snapshot_raw_in_transaction(
    transaction: &Transaction<'_>,
) -> Result<SelectedKeySnapshotRaw, StoreError> {
    let selected_origin = {
        let mut statement = transaction
            .prepare("SELECT selected_origin_incarnation FROM meta WHERE singleton = 1")
            .map_err(|_| StoreError::SelectedKeySnapshot)?;
        let mut rows = statement
            .query([])
            .map_err(|_| StoreError::SelectedKeySnapshot)?;
        let first = rows
            .next()
            .map_err(|_| StoreError::SelectedKeySnapshot)?
            .ok_or(StoreError::SelectedKeySnapshot)?;
        let origin = first.get(0).map_err(|_| StoreError::SelectedKeySnapshot)?;
        if rows
            .next()
            .map_err(|_| StoreError::SelectedKeySnapshot)?
            .is_some()
        {
            return Err(StoreError::SelectedKeySnapshot);
        }
        origin
    };
    let high_waters = {
        let mut statement = transaction.prepare("SELECT purpose, serial_hi, serial_lo FROM meta_mac_serial_high_water ORDER BY purpose ASC").map_err(|_| StoreError::SelectedKeySnapshot)?;
        let rows = statement
            .query_map([], |row| {
                Ok(RawHighWaterCell {
                    purpose: row.get(0)?,
                    serial_hi: row.get(1)?,
                    serial_lo: row.get(2)?,
                })
            })
            .map_err(|_| StoreError::SelectedKeySnapshot)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| StoreError::SelectedKeySnapshot)?
    };
    let manifest_rows = {
        let mut statement = transaction.prepare("SELECT purpose, origin, serial_hi, serial_lo, status, created_at FROM state_mac_keys ORDER BY purpose ASC, origin ASC, serial_hi ASC, serial_lo ASC").map_err(|_| StoreError::SelectedKeySnapshot)?;
        let rows = statement
            .query_map([], |row| {
                Ok(RawManifestCell {
                    purpose: row.get(0)?,
                    origin: row.get(1)?,
                    serial_hi: row.get(2)?,
                    serial_lo: row.get(3)?,
                    status: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })
            .map_err(|_| StoreError::SelectedKeySnapshot)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| StoreError::SelectedKeySnapshot)?
    };
    Ok(SelectedKeySnapshotRaw {
        selected_origin,
        high_waters,
        manifest_rows,
    })
}

#[cfg(test)]
fn read_selected_key_snapshot_raw(
    connection: &Connection,
) -> Result<SelectedKeySnapshotRaw, StoreError> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Deferred)
        .map_err(|_| StoreError::SelectedKeySnapshot)?;
    let snapshot = read_selected_key_snapshot_raw_in_transaction(&transaction)?;
    transaction
        .commit()
        .map_err(|_| StoreError::SelectedKeySnapshot)?;
    Ok(snapshot)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MigrationTransactionFailure {
    Rejected,
    ConnectionPoisoned,
}

impl Store {
    /// Open and verify one actor-owned SQLite connection.
    ///
    /// The connection is configured outside a transaction and verified before
    /// it is retained. No schema or product mutation is performed here.
    pub fn open(path: &Path, config: StoreOpenConfig) -> Result<Self, StoreError> {
        let autocheckpoint_pages = i32::try_from(config.wal_autocheckpoint_pages)
            .map_err(|_| StoreError::InvalidProfile)?;
        if autocheckpoint_pages == 0 || config.journal_size_limit_bytes < 0 {
            return Err(StoreError::InvalidProfile);
        }

        let sqlite_version_number = rusqlite::version_number();
        validate_runtime_version(sqlite_version_number)?;

        let connection = Connection::open(path).map_err(|_| StoreError::Open)?;
        connection
            .busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))
            .map_err(|_| StoreError::Profile)?;
        connection
            .pragma_update(None, "trusted_schema", 0_i64)
            .map_err(|_| StoreError::Profile)?;
        connection
            .pragma_update(None, "recursive_triggers", 0_i64)
            .map_err(|_| StoreError::Profile)?;
        connection
            .pragma_update(None, "foreign_keys", 1_i64)
            .map_err(|_| StoreError::Profile)?;

        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .map_err(|_| StoreError::Profile)?;
        if journal_mode != "wal" {
            return Err(StoreError::Profile);
        }

        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|_| StoreError::Profile)?;
        connection
            .pragma_update(None, "wal_autocheckpoint", autocheckpoint_pages)
            .map_err(|_| StoreError::Profile)?;
        connection
            .pragma_update(None, "journal_size_limit", config.journal_size_limit_bytes)
            .map_err(|_| StoreError::Profile)?;

        let synchronous: i64 = pragma_i64(&connection, "synchronous")?;
        let foreign_keys: i64 = pragma_i64(&connection, "foreign_keys")?;
        let trusted_schema: i64 = pragma_i64(&connection, "trusted_schema")?;
        let recursive_triggers: i64 = pragma_i64(&connection, "recursive_triggers")?;
        let busy_timeout: i64 = pragma_i64(&connection, "busy_timeout")?;
        let verified_autocheckpoint: i64 = pragma_i64(&connection, "wal_autocheckpoint")?;
        let verified_journal_limit: i64 = pragma_i64(&connection, "journal_size_limit")?;
        if synchronous != SYNCHRONOUS_FULL
            || foreign_keys != 1
            || trusted_schema != 0
            || recursive_triggers != 0
            || busy_timeout != i64::try_from(BUSY_TIMEOUT_MS).map_err(|_| StoreError::Profile)?
            || verified_autocheckpoint != i64::from(autocheckpoint_pages)
            || verified_journal_limit != config.journal_size_limit_bytes
        {
            return Err(StoreError::Profile);
        }

        verify_integrity(&connection)?;
        Ok(Self {
            connection: Some(connection),
            profile: VerifiedStoreProfile {
                sqlite_version_number,
                wal_autocheckpoint_pages: autocheckpoint_pages,
                journal_size_limit_bytes: verified_journal_limit,
            },
        })
    }

    /// Return the profile only after [`Self::open`] has verified it.
    pub fn profile(&self) -> VerifiedStoreProfile {
        self.profile
    }

    /// Read the non-secret selected state-key facts from one verified v2 snapshot.
    pub fn read_selected_key_snapshot_raw(&self) -> Result<SelectedKeySnapshotRaw, StoreError> {
        let connection = self
            .connection
            .as_ref()
            .ok_or(StoreError::SelectedKeySnapshot)?;
        let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Deferred)
            .map_err(|_| StoreError::SelectedKeySnapshot)?;
        let checksum: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version = 2",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StoreError::SelectedKeySnapshot)?;
        if checksum.as_deref() != Some(MIGRATION_V2_CHECKSUM.as_slice()) {
            return Err(StoreError::SelectedKeySnapshot);
        }
        let snapshot = read_selected_key_snapshot_raw_in_transaction(&transaction)?;
        transaction
            .commit()
            .map_err(|_| StoreError::SelectedKeySnapshot)?;
        Ok(snapshot)
    }

    /// Return the immutable compiled migration inventory without applying it.
    pub const fn migration_catalog() -> &'static [MigrationDescriptor] {
        &MIGRATION_CATALOG
    }

    /// Return the complete product catalog, including the runnable M2 delivery
    /// state. The older v1-only accessor remains frozen provenance for its RED
    /// frontier; production service startup uses this catalog.
    pub const fn product_migration_catalog() -> &'static [MigrationDescriptor] {
        &PRODUCT_MIGRATION_CATALOG
    }

    /// Return the checksum-pinned inventory including selected-state v2.
    pub const fn selected_state_migration_catalog() -> &'static [MigrationDescriptor] {
        &SELECTED_STATE_MIGRATION_CATALOG
    }

    /// Apply migrations only when explicitly invoked by maintenance.
    #[doc(hidden)]
    pub fn apply_migrations(
        &mut self,
        provenance: MigrationProvenance<'_>,
    ) -> Result<(), StoreError> {
        if provenance.binary_identity.is_empty() {
            return Err(StoreError::Migration);
        }
        let v1_checksum: [u8; 32] = Sha256::digest(MIGRATION_V1_SQL.as_bytes()).into();
        let v2_checksum: [u8; 32] = Sha256::digest(MIGRATION_V2_SQL.as_bytes()).into();
        let v3_checksum: [u8; 32] = Sha256::digest(MIGRATION_V3_SQL.as_bytes()).into();
        let v4_checksum: [u8; 32] = Sha256::digest(MIGRATION_V4_SQL.as_bytes()).into();
        let v5_checksum: [u8; 32] = Sha256::digest(MIGRATION_V5_SQL.as_bytes()).into();
        if v1_checksum != MIGRATION_V1_CHECKSUM
            || v2_checksum != MIGRATION_V2_CHECKSUM
            || v3_checksum != MIGRATION_V3_CHECKSUM
            || v4_checksum != MIGRATION_V4_CHECKSUM
            || v5_checksum != MIGRATION_V5_CHECKSUM
        {
            return Err(StoreError::Migration);
        }
        let connection = match self.connection.as_ref() {
            Some(connection) => connection,
            None => return Err(StoreError::Migration),
        };
        match apply_catalog(connection, provenance) {
            Ok(()) => Ok(()),
            Err(MigrationTransactionFailure::Rejected) => Err(StoreError::Migration),
            Err(MigrationTransactionFailure::ConnectionPoisoned) => {
                drop(self.connection.take());
                Err(StoreError::Migration)
            }
        }
    }

    /// Apply the runnable service migrations after the frozen v2 maintenance
    /// catalog. Product startup, not legacy maintenance callers, owns this
    /// advancing delivery schema.
    pub fn apply_product_migrations(
        &mut self,
        provenance: MigrationProvenance<'_>,
    ) -> Result<(), StoreError> {
        if provenance.binary_identity.is_empty() {
            return Err(StoreError::Migration);
        }
        let connection = match self.connection.as_ref() {
            Some(connection) => connection,
            None => return Err(StoreError::Migration),
        };
        match apply_product_catalog(connection, provenance) {
            Ok(()) => Ok(()),
            Err(MigrationTransactionFailure::Rejected) => Err(StoreError::Migration),
            Err(MigrationTransactionFailure::ConnectionPoisoned) => {
                drop(self.connection.take());
                Err(StoreError::Migration)
            }
        }
    }

    /// Record one message in the service-owned durable queue before returning
    /// an acceptance result. Reusing a key with a different request is refused.
    pub fn m2_submit(
        &mut self,
        submission: M2Submission<'_>,
        now_unix_ms: i64,
    ) -> Result<M2Accepted, StoreError> {
        validate_m2_submission(&submission)?;
        let connection = self.connection.as_ref().ok_or(StoreError::Delivery)?;
        let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Delivery)?;
        let existing: Option<(String, String, Option<String>, String)> = transaction
            .query_row(
                "SELECT message_id, topic, title, body FROM m3_messages WHERE idempotency_key = ?1",
                [submission.idempotency_key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| StoreError::Delivery)?;
        if let Some((message_id, topic, title, body)) = existing {
            if topic == submission.topic
                && title.as_deref() == submission.title
                && body == submission.body
            {
                transaction.commit().map_err(|_| StoreError::Delivery)?;
                return Ok(M2Accepted::Existing { message_id });
            }
            return Err(StoreError::Delivery);
        }
        let message_id = m2_message_id(&submission);
        transaction
            .execute(
                "INSERT INTO m3_messages (message_id, idempotency_key, topic, title, body, destination, payload, state, attempts, next_attempt_at_unix_ms, provider_ack, last_error, created_at_unix_ms, updated_at_unix_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?3, '', 'queued', 0, ?6, NULL, NULL, ?6, ?6)",
                (&message_id, submission.idempotency_key, submission.topic, submission.title, submission.body, now_unix_ms),
            )
            .map_err(|_| StoreError::Delivery)?;
        transaction.commit().map_err(|_| StoreError::Delivery)?;
        Ok(M2Accepted::New { message_id })
    }

    /// Durably accept one already-canonical closed-driver delivery.
    pub fn m3_submit(
        &mut self,
        submission: M3Submission<'_>,
        now_unix_ms: i64,
    ) -> Result<M2Accepted, StoreError> {
        if !valid_idempotency_key(submission.idempotency_key)
            || !matches!(submission.driver, "ntfy" | "whatsapp")
            || !valid_text(submission.destination, 256)
            || !valid_text(submission.payload, 4_096)
        {
            return Err(StoreError::Delivery);
        }
        let connection = self.connection.as_ref().ok_or(StoreError::Delivery)?;
        let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Delivery)?;
        let existing: Option<(String, String, String, String)> = transaction
            .query_row(
                "SELECT message_id, driver, destination, payload FROM m3_messages WHERE idempotency_key = ?1",
                [submission.idempotency_key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| StoreError::Delivery)?;
        if let Some((message_id, driver, destination, payload)) = existing {
            if driver == submission.driver
                && destination == submission.destination
                && payload == submission.payload
            {
                transaction.commit().map_err(|_| StoreError::Delivery)?;
                return Ok(M2Accepted::Existing { message_id });
            }
            return Err(StoreError::Delivery);
        }
        let message_id = m3_message_id(&submission);
        transaction
            .execute(
                "INSERT INTO m3_messages (message_id, idempotency_key, driver, destination, payload, topic, title, body, state, attempts, next_attempt_at_unix_ms, provider_ack, last_error, created_at_unix_ms, updated_at_unix_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?3, NULL, ?5, 'queued', 0, ?6, NULL, NULL, ?6, ?6)",
                (&message_id, submission.idempotency_key, submission.driver, submission.destination, submission.payload, now_unix_ms),
            )
            .map_err(|_| StoreError::Delivery)?;
        transaction.commit().map_err(|_| StoreError::Delivery)?;
        Ok(M2Accepted::New { message_id })
    }

    /// Persist the local-only inbound switch. Callback input has no path to
    /// this method; callers use the Unix control surface owned by the service.
    pub fn m4_set_inbound_enabled(&mut self, enabled: bool) -> Result<(), StoreError> {
        let connection = self.connection.as_ref().ok_or(StoreError::Delivery)?;
        let changed = connection
            .execute(
                "UPDATE m4_inbound_control SET enabled = ?1 WHERE singleton = 1",
                [i64::from(enabled)],
            )
            .map_err(|_| StoreError::Delivery)?;
        (changed == 1).then_some(()).ok_or(StoreError::Delivery)
    }

    /// Atomically applies callback replay/rate policy and records exactly one
    /// closed outbound intent before the webhook is acknowledged.
    pub fn m4_submit_inbound(
        &mut self,
        submission: M4InboundSubmission<'_>,
        now_unix_ms: i64,
    ) -> Result<M4InboundDisposition, StoreError> {
        if !valid_idempotency_key(submission.provider_message_id)
            || !valid_phone_sender(submission.sender)
            || !matches!(submission.verb, "notify" | "status")
            || !matches!(submission.driver, "ntfy" | "whatsapp")
            || !valid_text(submission.destination, 256)
            || !valid_text(submission.payload, 4_096)
        {
            return Err(StoreError::Delivery);
        }
        let connection = self.connection.as_ref().ok_or(StoreError::Delivery)?;
        let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Delivery)?;
        let enabled: i64 = transaction
            .query_row(
                "SELECT enabled FROM m4_inbound_control WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| StoreError::Delivery)?;
        if enabled != 1 {
            transaction.commit().map_err(|_| StoreError::Delivery)?;
            return Ok(M4InboundDisposition::Disabled);
        }
        let replayed: Option<i64> = transaction
            .query_row(
                "SELECT 1 FROM m4_inbound_receipts WHERE provider_message_id = ?1",
                [submission.provider_message_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StoreError::Delivery)?;
        if replayed.is_some() {
            transaction.commit().map_err(|_| StoreError::Delivery)?;
            return Ok(M4InboundDisposition::Replayed);
        }
        if submission.verb == "notify" {
            let start = now_unix_ms
                .checked_sub(600_000)
                .ok_or(StoreError::Delivery)?;
            let count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM m4_notify_rate_events WHERE sender = ?1 AND accepted_at_unix_ms > ?2",
                    (submission.sender, start),
                    |row| row.get(0),
                )
                .map_err(|_| StoreError::Delivery)?;
            if count >= 4 {
                transaction.commit().map_err(|_| StoreError::Delivery)?;
                return Ok(M4InboundDisposition::RateLimited);
            }
        }
        let key = format!("m4-{}", submission.provider_message_id);
        if !valid_idempotency_key(&key) {
            return Err(StoreError::Delivery);
        }
        let message_id = m3_message_id(&M3Submission {
            idempotency_key: &key,
            driver: submission.driver,
            destination: submission.destination,
            payload: submission.payload,
        });
        transaction
            .execute(
                "INSERT INTO m3_messages (message_id, idempotency_key, driver, destination, payload, topic, title, body, state, attempts, next_attempt_at_unix_ms, provider_ack, last_error, created_at_unix_ms, updated_at_unix_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?4, NULL, ?5, 'queued', 0, ?6, NULL, NULL, ?6, ?6)",
                (&message_id, &key, submission.driver, submission.destination, submission.payload, now_unix_ms),
            )
            .map_err(|_| StoreError::Delivery)?;
        transaction
            .execute(
                "INSERT INTO m4_inbound_receipts (provider_message_id, sender, verb, accepted_at_unix_ms) VALUES (?1, ?2, ?3, ?4)",
                (submission.provider_message_id, submission.sender, submission.verb, now_unix_ms),
            )
            .map_err(|_| StoreError::Delivery)?;
        if submission.verb == "notify" {
            transaction
                .execute(
                    "INSERT INTO m4_notify_rate_events (sender, accepted_at_unix_ms) VALUES (?1, ?2)",
                    (submission.sender, now_unix_ms),
                )
                .map_err(|_| StoreError::Delivery)?;
        }
        transaction.commit().map_err(|_| StoreError::Delivery)?;
        Ok(M4InboundDisposition::Accepted)
    }

    /// Move one due message across the durable pre-dispatch boundary.
    pub fn m2_claim_due(&mut self, now_unix_ms: i64) -> Result<Option<M2Delivery>, StoreError> {
        let connection = self.connection.as_ref().ok_or(StoreError::Delivery)?;
        let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Delivery)?;
        let candidate: Option<ClaimedM3Row> = transaction
            .query_row(
                "SELECT message_id, driver, destination, payload, topic, title, body, attempts FROM m3_messages WHERE state IN ('queued', 'retry_scheduled') AND next_attempt_at_unix_ms <= ?1 ORDER BY created_at_unix_ms, message_id LIMIT 1",
                [now_unix_ms],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)),
            )
            .optional()
            .map_err(|_| StoreError::Delivery)?;
        let Some((message_id, driver, destination, payload, topic, title, body, attempts)) =
            candidate
        else {
            transaction.commit().map_err(|_| StoreError::Delivery)?;
            return Ok(None);
        };
        let changed = transaction
            .execute(
                "UPDATE m3_messages SET state = 'sending', attempts = attempts + 1, next_attempt_at_unix_ms = NULL, updated_at_unix_ms = ?2 WHERE message_id = ?1 AND state IN ('queued', 'retry_scheduled')",
                (&message_id, now_unix_ms),
            )
            .map_err(|_| StoreError::Delivery)?;
        if changed != 1 {
            return Err(StoreError::Delivery);
        }
        let attempt = u8::try_from(attempts + 1).map_err(|_| StoreError::Delivery)?;
        transaction.commit().map_err(|_| StoreError::Delivery)?;
        Ok(Some(M2Delivery {
            message_id,
            driver,
            destination,
            payload,
            topic,
            title,
            body,
            attempt,
        }))
    }

    /// Persist a provider acknowledgement after a successful HTTP response.
    pub fn m2_mark_accepted(
        &mut self,
        message_id: &str,
        provider_ack: &str,
        now_unix_ms: i64,
    ) -> Result<(), StoreError> {
        if !valid_text(provider_ack, 256) {
            return Err(StoreError::Delivery);
        }
        self.m2_transition_sending(
            message_id,
            "UPDATE m3_messages SET state = 'provider_accepted', provider_ack = ?2, updated_at_unix_ms = ?3 WHERE message_id = ?1 AND state = 'sending'",
            (provider_ack, now_unix_ms),
        )
    }

    /// Persist a bounded retry or a terminal failure once the retry budget ends.
    pub fn m2_mark_retry(
        &mut self,
        message_id: &str,
        reason: &str,
        delay_ms: u32,
        now_unix_ms: i64,
    ) -> Result<(), StoreError> {
        if !valid_text(reason, 256) || !(1_000..=3_600_000).contains(&delay_ms) {
            return Err(StoreError::Delivery);
        }
        let connection = self.connection.as_ref().ok_or(StoreError::Delivery)?;
        let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Delivery)?;
        let attempts: i64 = transaction
            .query_row(
                "SELECT attempts FROM m3_messages WHERE message_id = ?1 AND state = 'sending'",
                [message_id],
                |row| row.get(0),
            )
            .map_err(|_| StoreError::Delivery)?;
        let changed = if attempts >= 5 {
            transaction.execute(
                "UPDATE m3_messages SET state = 'failed', last_error = ?2, updated_at_unix_ms = ?3 WHERE message_id = ?1 AND state = 'sending'",
                (message_id, reason, now_unix_ms),
            )
        } else {
            let next = now_unix_ms
                .checked_add(i64::from(delay_ms))
                .ok_or(StoreError::Delivery)?;
            transaction.execute(
                "UPDATE m3_messages SET state = 'retry_scheduled', next_attempt_at_unix_ms = ?2, last_error = NULL, updated_at_unix_ms = ?3 WHERE message_id = ?1 AND state = 'sending'",
                (message_id, next, now_unix_ms),
            )
        }
        .map_err(|_| StoreError::Delivery)?;
        if changed != 1 {
            return Err(StoreError::Delivery);
        }
        transaction.commit().map_err(|_| StoreError::Delivery)
    }

    /// Record a provider's definite rejection without pretending it may be
    /// retried safely.
    pub fn m2_mark_failed(
        &mut self,
        message_id: &str,
        reason: &str,
        now_unix_ms: i64,
    ) -> Result<(), StoreError> {
        if !valid_text(reason, 256) {
            return Err(StoreError::Delivery);
        }
        self.m2_transition_sending(
            message_id,
            "UPDATE m3_messages SET state = 'failed', last_error = ?2, updated_at_unix_ms = ?3 WHERE message_id = ?1 AND state = 'sending'",
            (reason, now_unix_ms),
        )
    }

    /// Never guess after an interrupted external effect: it is retained as
    /// ambiguous for an operator instead of being silently retried.
    pub fn m2_mark_ambiguous(
        &mut self,
        message_id: &str,
        reason: &str,
        now_unix_ms: i64,
    ) -> Result<(), StoreError> {
        if !valid_text(reason, 256) {
            return Err(StoreError::Delivery);
        }
        self.m2_transition_sending(
            message_id,
            "UPDATE m3_messages SET state = 'ambiguous', last_error = ?2, updated_at_unix_ms = ?3 WHERE message_id = ?1 AND state = 'sending'",
            (reason, now_unix_ms),
        )
    }

    /// Recover a crash across the pre-dispatch boundary without risking a
    /// duplicate provider effect.
    pub fn m2_recover_interrupted(&mut self, now_unix_ms: i64) -> Result<u64, StoreError> {
        let connection = self.connection.as_ref().ok_or(StoreError::Delivery)?;
        let changed = connection
            .execute(
                "UPDATE m3_messages SET state = 'ambiguous', last_error = 'interrupted external delivery may have occurred', updated_at_unix_ms = ?1 WHERE state = 'sending'",
                [now_unix_ms],
            )
            .map_err(|_| StoreError::Delivery)?;
        u64::try_from(changed).map_err(|_| StoreError::Delivery)
    }

    /// Return the non-secret durable state for local client status handling.
    pub fn m2_state(&self, message_id: &str) -> Result<Option<String>, StoreError> {
        self.connection
            .as_ref()
            .ok_or(StoreError::Delivery)?
            .query_row(
                "SELECT state FROM m3_messages WHERE message_id = ?1",
                [message_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StoreError::Delivery)
    }

    fn m2_transition_sending(
        &self,
        message_id: &str,
        statement: &str,
        values: (&str, i64),
    ) -> Result<(), StoreError> {
        let connection = self.connection.as_ref().ok_or(StoreError::Delivery)?;
        let changed = connection
            .execute(statement, (message_id, values.0, values.1))
            .map_err(|_| StoreError::Delivery)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(StoreError::Delivery)
        }
    }
}

fn validate_m2_submission(submission: &M2Submission<'_>) -> Result<(), StoreError> {
    if !valid_idempotency_key(submission.idempotency_key)
        || !valid_topic(submission.topic)
        || !valid_text(submission.body, 4_096)
        || submission
            .title
            .is_some_and(|title| !valid_text(title, 256) || title.contains(['\r', '\n']))
    {
        return Err(StoreError::Delivery);
    }
    Ok(())
}

fn valid_idempotency_key(value: &str) -> bool {
    valid_text(value, 128)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_topic(value: &str) -> bool {
    valid_text(value, 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_phone_sender(value: &str) -> bool {
    (7..=20).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.contains('\0')
}

fn m2_message_id(submission: &M2Submission<'_>) -> String {
    let mut digest = Sha256::new();
    for field in [
        submission.idempotency_key,
        submission.topic,
        submission.title.unwrap_or(""),
        submission.body,
    ] {
        digest.update(u64::try_from(field.len()).unwrap_or(0).to_be_bytes());
        digest.update(field.as_bytes());
    }
    digest_to_hex(digest.finalize().as_slice())
}

fn m3_message_id(submission: &M3Submission<'_>) -> String {
    let mut digest = Sha256::new();
    for field in [
        submission.idempotency_key,
        submission.driver,
        submission.destination,
        submission.payload,
    ] {
        digest.update(u64::try_from(field.len()).unwrap_or(0).to_be_bytes());
        digest.update(field.as_bytes());
    }
    digest_to_hex(digest.finalize().as_slice())
}

fn digest_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn apply_catalog(
    connection: &Connection,
    provenance: MigrationProvenance<'_>,
) -> Result<(), MigrationTransactionFailure> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
        .map_err(|_| MigrationTransactionFailure::Rejected)?;
    match apply_catalog_v1_in_transaction(&transaction, provenance)
        .and_then(|_| apply_catalog_v2_in_transaction(&transaction, provenance, false))
    {
        Ok(()) => transaction
            .commit()
            .map_err(|_| MigrationTransactionFailure::ConnectionPoisoned),
        Err(_) => match transaction.rollback() {
            Ok(()) => Err(MigrationTransactionFailure::Rejected),
            Err(_) => Err(MigrationTransactionFailure::ConnectionPoisoned),
        },
    }
}

fn apply_product_catalog(
    connection: &Connection,
    provenance: MigrationProvenance<'_>,
) -> Result<(), MigrationTransactionFailure> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
        .map_err(|_| MigrationTransactionFailure::Rejected)?;
    match apply_catalog_v1_in_transaction(&transaction, provenance)
        .and_then(|_| apply_catalog_v2_in_transaction(&transaction, provenance, true))
        .and_then(|_| apply_catalog_v3_in_transaction(&transaction, provenance))
        .and_then(|_| apply_catalog_v4_in_transaction(&transaction, provenance))
        .and_then(|_| apply_catalog_v5_in_transaction(&transaction, provenance))
    {
        Ok(()) => transaction
            .commit()
            .map_err(|_| MigrationTransactionFailure::ConnectionPoisoned),
        Err(_) => match transaction.rollback() {
            Ok(()) => Err(MigrationTransactionFailure::Rejected),
            Err(_) => Err(MigrationTransactionFailure::ConnectionPoisoned),
        },
    }
}

fn apply_catalog_v1_in_transaction(
    transaction: &Transaction<'_>,
    provenance: MigrationProvenance<'_>,
) -> rusqlite::Result<()> {
    let schema_sql: Option<String> = transaction
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(schema_sql) = schema_sql {
        let expected_schema_sql = MIGRATION_V1_SQL
            .strip_suffix(";\n")
            .ok_or(rusqlite::Error::InvalidQuery)?;
        if schema_sql != expected_schema_sql {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })?;
        let checksum: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if count < 1 || checksum.as_deref() != Some(MIGRATION_V1_CHECKSUM.as_slice()) {
            return Err(rusqlite::Error::InvalidQuery);
        }
    } else {
        transaction.execute_batch(MIGRATION_V1_SQL)?;
        transaction
            .execute(
                "INSERT INTO schema_migrations (version, checksum, applied_binary, applied_at_unix_ms) VALUES (?1, ?2, ?3, ?4)",
                (1_i64, MIGRATION_V1_CHECKSUM.as_slice(), provenance.binary_identity, provenance.applied_at_unix_ms),
            )?;
    }
    Ok(())
}

fn apply_catalog_v2_in_transaction(
    transaction: &Transaction<'_>,
    provenance: MigrationProvenance<'_>,
    allow_product_versions: bool,
) -> rusqlite::Result<()> {
    (|| {
        let allowed_versions = if allow_product_versions {
            "1, 2, 3, 4, 5"
        } else {
            "1, 2"
        };
        let unknown_versions: i64 = transaction.query_row(
            &format!(
                "SELECT COUNT(*) FROM schema_migrations WHERE version NOT IN ({allowed_versions})"
            ),
            [],
            |row| row.get(0),
        )?;
        // A binary that does not know every recorded migration must not install
        // older state beside a future schema history.
        if unknown_versions != 0 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version = 2",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(checksum) if checksum.as_slice() == MIGRATION_V2_CHECKSUM.as_slice() => Ok(()),
            Some(_) => Err(rusqlite::Error::InvalidQuery),
            None => transaction.execute_batch(MIGRATION_V2_SQL).and_then(|_| {
                transaction
                    .execute(
                        "INSERT INTO schema_migrations (version, checksum, applied_binary, applied_at_unix_ms) VALUES (?1, ?2, ?3, ?4)",
                        (2_i64, MIGRATION_V2_CHECKSUM.as_slice(), provenance.binary_identity, provenance.applied_at_unix_ms),
                    )
                    .map(|_| ())
            }),
        }
    })()
}

fn apply_catalog_v3_in_transaction(
    transaction: &Transaction<'_>,
    provenance: MigrationProvenance<'_>,
) -> rusqlite::Result<()> {
    let existing: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT checksum FROM schema_migrations WHERE version = 3",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match existing {
        Some(checksum) if checksum.as_slice() == MIGRATION_V3_CHECKSUM.as_slice() => Ok(()),
        Some(_) => Err(rusqlite::Error::InvalidQuery),
        None => transaction.execute_batch(MIGRATION_V3_SQL).and_then(|_| {
            transaction
                .execute(
                    "INSERT INTO schema_migrations (version, checksum, applied_binary, applied_at_unix_ms) VALUES (?1, ?2, ?3, ?4)",
                    (3_i64, MIGRATION_V3_CHECKSUM.as_slice(), provenance.binary_identity, provenance.applied_at_unix_ms),
                )
                .map(|_| ())
        }),
    }
}

fn apply_catalog_v4_in_transaction(
    transaction: &Transaction<'_>,
    provenance: MigrationProvenance<'_>,
) -> rusqlite::Result<()> {
    let existing: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT checksum FROM schema_migrations WHERE version = 4",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match existing {
        Some(checksum) if checksum.as_slice() == MIGRATION_V4_CHECKSUM.as_slice() => Ok(()),
        Some(_) => Err(rusqlite::Error::InvalidQuery),
        None => transaction.execute_batch(MIGRATION_V4_SQL).and_then(|_| {
            transaction
                .execute(
                    "INSERT INTO schema_migrations (version, checksum, applied_binary, applied_at_unix_ms) VALUES (?1, ?2, ?3, ?4)",
                    (4_i64, MIGRATION_V4_CHECKSUM.as_slice(), provenance.binary_identity, provenance.applied_at_unix_ms),
                )
                .map(|_| ())
        }),
    }
}

fn apply_catalog_v5_in_transaction(
    transaction: &Transaction<'_>,
    provenance: MigrationProvenance<'_>,
) -> rusqlite::Result<()> {
    let existing: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT checksum FROM schema_migrations WHERE version = 5",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match existing {
        Some(checksum) if checksum.as_slice() == MIGRATION_V5_CHECKSUM.as_slice() => Ok(()),
        Some(_) => Err(rusqlite::Error::InvalidQuery),
        None => transaction.execute_batch(MIGRATION_V5_SQL).and_then(|_| {
            transaction
                .execute(
                    "INSERT INTO schema_migrations (version, checksum, applied_binary, applied_at_unix_ms) VALUES (?1, ?2, ?3, ?4)",
                    (5_i64, MIGRATION_V5_CHECKSUM.as_slice(), provenance.binary_identity, provenance.applied_at_unix_ms),
                )
                .map(|_| ())
        }),
    }
}

fn pragma_i64(connection: &Connection, name: &str) -> Result<i64, StoreError> {
    connection
        .pragma_query_value(None, name, |row| row.get(0))
        .map_err(|_| StoreError::Profile)
}

fn validate_runtime_version(sqlite_version_number: i32) -> Result<(), StoreError> {
    if sqlite_version_number < SQLITE_VERSION_FLOOR {
        Err(StoreError::RuntimeVersion)
    } else {
        Ok(())
    }
}

fn verify_integrity(connection: &Connection) -> Result<(), StoreError> {
    let mut statement = integrity_result(connection.prepare("PRAGMA integrity_check"))?;
    let mut rows = integrity_result(statement.query([]))?;
    verify_integrity_rows(&mut || {
        let maybe_row = integrity_result(rows.next())?;
        match maybe_row {
            Some(row) => integrity_result(row.get(0)).map(Some),
            None => Ok(None),
        }
    })
}

fn integrity_result<T>(result: rusqlite::Result<T>) -> Result<T, StoreError> {
    result.map_err(|_| StoreError::Integrity)
}

fn verify_integrity_rows(
    next_row: &mut impl FnMut() -> Result<Option<String>, StoreError>,
) -> Result<(), StoreError> {
    let first = next_row()?.ok_or(StoreError::Integrity)?;
    if first != "ok" || next_row()?.is_some() {
        Err(StoreError::Integrity)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MigrationProvenance, SQLITE_VERSION_FLOOR, Store, StoreError, StoreFrontier,
        VerifiedStoreProfile, integrity_result, read_selected_key_snapshot_raw,
        validate_runtime_version, verify_integrity_rows,
    };
    use rusqlite::{
        Connection,
        hooks::{AuthAction, AuthContext, Authorization, TransactionOperation},
    };
    use std::{
        collections::VecDeque,
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    const MIGRATION_TEST_CONFIG: super::StoreOpenConfig = super::StoreOpenConfig::new(1_000, 1);
    static NEXT_MIGRATION_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct MigrationTestDatabase(PathBuf);

    impl MigrationTestDatabase {
        fn create() -> Result<Self, String> {
            let sequence = NEXT_MIGRATION_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "msgriver-migration-transaction-{}-{sequence}",
                std::process::id(),
            ));
            fs::create_dir(&directory)
                .map_err(|_| "MIGRATION-TRANSACTION: fixture directory failed")?;
            Ok(Self(directory.join("store.db")))
        }
    }

    impl Drop for MigrationTestDatabase {
        fn drop(&mut self) {
            if let Some(directory) = self.0.parent() {
                let _ = fs::remove_dir_all(directory);
            }
        }
    }

    #[test]
    fn runtime_version_rejects_only_values_below_the_architecture_floor() {
        assert_eq!(
            validate_runtime_version(SQLITE_VERSION_FLOOR - 1),
            Err(StoreError::RuntimeVersion)
        );
        assert_eq!(validate_runtime_version(SQLITE_VERSION_FLOOR), Ok(()));
        assert_eq!(validate_runtime_version(SQLITE_VERSION_FLOOR + 1), Ok(()));
    }

    fn verify_rows(rows: VecDeque<Result<Option<&str>, StoreError>>) -> Result<(), StoreError> {
        let mut rows = rows;
        verify_integrity_rows(&mut || {
            rows.pop_front()
                .unwrap_or(Ok(None))
                .map(|row| row.map(str::to_owned))
        })
    }

    #[test]
    fn integrity_rows_accept_only_one_ok_text_row() {
        assert_eq!(
            verify_rows(VecDeque::from([Ok(Some("ok")), Ok(None)])),
            Ok(())
        );
        assert_eq!(
            verify_rows(VecDeque::from([Ok(Some("corrupt"))])),
            Err(StoreError::Integrity)
        );
        assert_eq!(
            verify_rows(VecDeque::from([Ok(Some("ok")), Ok(Some("extra"))])),
            Err(StoreError::Integrity)
        );
        assert_eq!(
            verify_rows(VecDeque::from([Ok(None)])),
            Err(StoreError::Integrity)
        );
    }

    #[test]
    fn integrity_rows_and_sqlite_statement_errors_fail_closed() {
        assert_eq!(
            verify_rows(VecDeque::from([Err(StoreError::Integrity)])),
            Err(StoreError::Integrity)
        );
        assert_eq!(
            integrity_result::<()>(Err(rusqlite::Error::InvalidQuery)),
            Err(StoreError::Integrity)
        );
    }

    #[test]
    fn selected_key_snapshot_is_ordered_and_nonsecret() {
        let connection = Connection::open_in_memory().expect("test connection");
        connection.execute_batch("CREATE TABLE meta (singleton INTEGER, selected_origin_incarnation BLOB); CREATE TABLE meta_mac_serial_high_water (purpose INTEGER, serial_hi INTEGER, serial_lo INTEGER); CREATE TABLE state_mac_keys (purpose INTEGER, origin BLOB, serial_hi INTEGER, serial_lo INTEGER, status INTEGER, created_at INTEGER); INSERT INTO meta VALUES (1, X'0102'); INSERT INTO meta_mac_serial_high_water VALUES (2,0,2),(1,0,1); INSERT INTO state_mac_keys VALUES (2,X'bb',0,2,2,-2),(1,X'aa',0,1,1,-1);").expect("fixture");
        let snapshot = match read_selected_key_snapshot_raw(&connection) {
            Ok(snapshot) => snapshot,
            Err(StoreError::Scaffold(StoreFrontier::SelectedKeySnapshot)) => {
                panic!("MissingSelectedKeySnapshot: selected_key_snapshot")
            }
            Err(error) => panic!("canonical selected key snapshot rejected: {error:?}"),
        };
        assert_eq!(snapshot.selected_origin, vec![1, 2]);
        assert_eq!(snapshot.high_waters[0].purpose, 1);
        assert_eq!(snapshot.manifest_rows[0].purpose, 1);
        assert_eq!(snapshot.manifest_rows[0].origin, vec![0xaa]);
    }

    fn migration_test_store() -> Result<Store, String> {
        let connection =
            Connection::open_in_memory().map_err(|_| "MIGRATION-TRANSACTION: fixture failed")?;
        Ok(Store {
            connection: Some(connection),
            profile: VerifiedStoreProfile {
                sqlite_version_number: SQLITE_VERSION_FLOOR,
                wal_autocheckpoint_pages: 1,
                journal_size_limit_bytes: 1,
            },
        })
    }

    fn migration_provenance() -> MigrationProvenance<'static> {
        MigrationProvenance {
            binary_identity: b"transaction-test",
            applied_at_unix_ms: 1,
        }
    }

    fn assert_migration_error_is_redacted(
        error: StoreError,
        forbidden: &[&str],
    ) -> Result<(), String> {
        let display = error.to_string();
        let debug = format!("{error:?}");
        if forbidden
            .iter()
            .any(|value| display.contains(value) || debug.contains(value))
            || std::error::Error::source(&error).is_some()
        {
            return Err("MIGRATION-TRANSACTION: error exposed diagnostics".to_owned());
        }
        Ok(())
    }

    #[test]
    fn migration_statement_failure_rolls_back_before_reopen() -> Result<(), String> {
        let database = MigrationTestDatabase::create()?;
        let mut store = Store::open(&database.0, MIGRATION_TEST_CONFIG)
            .map_err(|_| "MIGRATION-TRANSACTION: profile open failed")?;
        {
            let connection = store
                .connection
                .as_ref()
                .ok_or_else(|| "MIGRATION-TRANSACTION: connection missing".to_owned())?;
            connection
                .authorizer(Some(|context: AuthContext<'_>| match context.action {
                    AuthAction::Insert {
                        table_name: "schema_migrations",
                    } => Authorization::Deny,
                    _ => Authorization::Allow,
                }))
                .map_err(|_| "MIGRATION-TRANSACTION: authorizer setup failed")?;
        }
        let error = store
            .apply_migrations(migration_provenance())
            .err()
            .ok_or_else(|| {
                "MIGRATION-TRANSACTION: injected statement failure was accepted".to_owned()
            })?;
        let path = database.0.to_string_lossy();
        assert_migration_error_is_redacted(
            error,
            &[
                path.as_ref(),
                "not authorized",
                "INSERT INTO schema_migrations",
                "transaction-test",
            ],
        )?;
        {
            let connection = store
                .connection
                .as_ref()
                .ok_or_else(|| "MIGRATION-TRANSACTION: rollback discarded connection".to_owned())?;
            connection
                .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
                .map_err(|_| "MIGRATION-TRANSACTION: authorizer teardown failed")?;
        }
        drop(store);
        let inspection = Connection::open(&database.0)
            .map_err(|_| "MIGRATION-TRANSACTION: reopen inspection failed")?;
        let table_count: i64 = inspection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| "MIGRATION-TRANSACTION: reopen inspection failed")?;
        if table_count != 0 {
            return Err("MIGRATION-TRANSACTION: rollback left ledger table".to_owned());
        }
        drop(inspection);
        let mut reopened = Store::open(&database.0, MIGRATION_TEST_CONFIG)
            .map_err(|_| "MIGRATION-TRANSACTION: second profile open failed")?;
        reopened
            .apply_migrations(migration_provenance())
            .map_err(|_| {
                "MIGRATION-TRANSACTION: reopen observed partial transaction state".to_owned()
            })
    }

    #[test]
    fn v2_statement_failure_rolls_back_the_entire_catalog_before_reopen() -> Result<(), String> {
        let database = MigrationTestDatabase::create()?;
        let mut store = Store::open(&database.0, MIGRATION_TEST_CONFIG)
            .map_err(|_| "V2-MIGRATION-TRANSACTION: profile open failed")?;
        {
            let connection = store
                .connection
                .as_ref()
                .ok_or_else(|| "V2-MIGRATION-TRANSACTION: connection missing".to_owned())?;
            connection
                .authorizer(Some(|context: AuthContext<'_>| match context.action {
                    AuthAction::CreateTable {
                        table_name: "messages",
                    } => Authorization::Deny,
                    _ => Authorization::Allow,
                }))
                .map_err(|_| "V2-MIGRATION-TRANSACTION: authorizer setup failed")?;
        }
        let error = store
            .apply_migrations(migration_provenance())
            .err()
            .ok_or_else(|| {
                "V2-MIGRATION-TRANSACTION: injected v2 statement was accepted".to_owned()
            })?;
        assert_migration_error_is_redacted(
            error,
            &["messages", "not authorized", "transaction-test"],
        )?;
        {
            let connection = store.connection.as_ref().ok_or_else(|| {
                "V2-MIGRATION-TRANSACTION: successful rollback discarded connection".to_owned()
            })?;
            connection
                .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
                .map_err(|_| "V2-MIGRATION-TRANSACTION: authorizer teardown failed")?;
        }
        drop(store);

        let inspection = Connection::open(&database.0)
            .map_err(|_| "V2-MIGRATION-TRANSACTION: reopen inspection failed")?;
        let catalog_tables: i64 = inspection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| "V2-MIGRATION-TRANSACTION: reopen inspection failed")?;
        if catalog_tables != 0 {
            return Err("V2-MIGRATION-TRANSACTION: rollback left v1 or v2 state".to_owned());
        }
        drop(inspection);

        let mut reopened = Store::open(&database.0, MIGRATION_TEST_CONFIG)
            .map_err(|_| "V2-MIGRATION-TRANSACTION: second profile open failed")?;
        reopened
            .apply_migrations(migration_provenance())
            .map_err(|_| "V2-MIGRATION-TRANSACTION: reopen observed partial v2 state".to_owned())
    }

    #[test]
    fn selected_state_catalog_commit_failure_poisoned_store_leaves_no_schema() -> Result<(), String>
    {
        let database = MigrationTestDatabase::create()?;
        let mut store = Store::open(&database.0, MIGRATION_TEST_CONFIG)
            .map_err(|_| "V2-COMMIT-TRANSACTION: profile open failed")?;
        store
            .connection
            .as_ref()
            .ok_or_else(|| "V2-COMMIT-TRANSACTION: connection missing".to_owned())?
            .commit_hook(Some(|| true))
            .map_err(|_| "V2-COMMIT-TRANSACTION: commit hook setup failed")?;
        if store.apply_migrations(migration_provenance()) != Err(StoreError::Migration) {
            return Err("V2-COMMIT-TRANSACTION: injected commit failure was accepted".to_owned());
        }
        if store.connection.is_some()
            || store.apply_migrations(migration_provenance()) != Err(StoreError::Migration)
        {
            return Err("V2-COMMIT-TRANSACTION: failed commit retained usable store".to_owned());
        }
        drop(store);

        let inspection = Connection::open(&database.0)
            .map_err(|_| "V2-COMMIT-TRANSACTION: reopen inspection failed")?;
        let tables: i64 = inspection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| "V2-COMMIT-TRANSACTION: reopen inspection failed")?;
        if tables != 0 {
            return Err("V2-COMMIT-TRANSACTION: failed commit published schema".to_owned());
        }
        drop(inspection);
        let mut reopened = Store::open(&database.0, MIGRATION_TEST_CONFIG)
            .map_err(|_| "V2-COMMIT-TRANSACTION: second profile open failed")?;
        reopened
            .apply_migrations(migration_provenance())
            .map_err(|_| "V2-COMMIT-TRANSACTION: reopen observed partial catalog".to_owned())
    }

    #[test]
    fn selected_state_catalog_rollback_failure_poisoned_store_leaves_no_schema()
    -> Result<(), String> {
        let database = MigrationTestDatabase::create()?;
        let mut store = Store::open(&database.0, MIGRATION_TEST_CONFIG)
            .map_err(|_| "V2-ROLLBACK-TRANSACTION: profile open failed")?;
        {
            let connection = store
                .connection
                .as_ref()
                .ok_or_else(|| "V2-ROLLBACK-TRANSACTION: connection missing".to_owned())?;
            connection
                .authorizer(Some(|context: AuthContext<'_>| match context.action {
                    AuthAction::CreateTable {
                        table_name: "messages",
                    }
                    | AuthAction::Transaction {
                        operation: TransactionOperation::Rollback,
                    } => Authorization::Deny,
                    _ => Authorization::Allow,
                }))
                .map_err(|_| "V2-ROLLBACK-TRANSACTION: authorizer setup failed")?;
        }
        if store.apply_migrations(migration_provenance()) != Err(StoreError::Migration) {
            return Err(
                "V2-ROLLBACK-TRANSACTION: injected rollback failure was accepted".to_owned(),
            );
        }
        if store.connection.is_some()
            || store.apply_migrations(migration_provenance()) != Err(StoreError::Migration)
        {
            return Err(
                "V2-ROLLBACK-TRANSACTION: failed rollback retained usable store".to_owned(),
            );
        }
        drop(store);

        let inspection = Connection::open(&database.0)
            .map_err(|_| "V2-ROLLBACK-TRANSACTION: reopen inspection failed")?;
        let tables: i64 = inspection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| "V2-ROLLBACK-TRANSACTION: reopen inspection failed")?;
        if tables != 0 {
            return Err("V2-ROLLBACK-TRANSACTION: failed rollback published schema".to_owned());
        }
        drop(inspection);
        let mut reopened = Store::open(&database.0, MIGRATION_TEST_CONFIG)
            .map_err(|_| "V2-ROLLBACK-TRANSACTION: second profile open failed")?;
        reopened
            .apply_migrations(migration_provenance())
            .map_err(|_| "V2-ROLLBACK-TRANSACTION: reopen observed partial catalog".to_owned())
    }

    #[test]
    fn migration_rollback_failure_discards_the_retained_connection() -> Result<(), String> {
        let mut store = migration_test_store()?;
        {
            let connection = store
                .connection
                .as_ref()
                .ok_or_else(|| "MIGRATION-TRANSACTION: connection missing".to_owned())?;
            connection
                .authorizer(Some(|context: AuthContext<'_>| match context.action {
                    AuthAction::Insert {
                        table_name: "schema_migrations",
                    } => Authorization::Deny,
                    AuthAction::Transaction {
                        operation: TransactionOperation::Rollback,
                    } => Authorization::Deny,
                    _ => Authorization::Allow,
                }))
                .map_err(|_| "MIGRATION-TRANSACTION: authorizer setup failed")?;
        }
        if store.apply_migrations(migration_provenance()) != Err(StoreError::Migration) {
            return Err("MIGRATION-TRANSACTION: rollback failure was not closed".to_owned());
        }
        if store.connection.is_some() {
            return Err("MIGRATION-TRANSACTION: rollback failure retained connection".to_owned());
        }
        if store.apply_migrations(migration_provenance()) != Err(StoreError::Migration) {
            return Err("MIGRATION-TRANSACTION: poisoned store accepted retry".to_owned());
        }
        Ok(())
    }

    #[test]
    fn migration_commit_failure_discards_the_retained_connection() -> Result<(), String> {
        let mut store = migration_test_store()?;
        store
            .connection
            .as_ref()
            .ok_or_else(|| "MIGRATION-TRANSACTION: connection missing".to_owned())?
            .commit_hook(Some(|| true))
            .map_err(|_| "MIGRATION-TRANSACTION: commit hook setup failed")?;
        if store.apply_migrations(migration_provenance()) != Err(StoreError::Migration) {
            return Err("MIGRATION-TRANSACTION: commit failure was not closed".to_owned());
        }
        if store.connection.is_some() {
            return Err("MIGRATION-TRANSACTION: commit failure retained connection".to_owned());
        }
        Ok(())
    }
}
