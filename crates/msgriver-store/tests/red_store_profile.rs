//! Frozen RED contract for the first verified SQLite store boundary.
//!
//! The suite calls the production `Store::open` seam. Until Task 0002 lands it
//! must terminate only at `store_profile_open`; a setup/fixture failure is not
//! an acceptable RED result.

#![forbid(unsafe_code)]

use msgriver_store::{Store, StoreError, StoreFrontier, StoreOpenConfig, VerifiedStoreProfile};
use rusqlite::Connection;
use std::fmt;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const SQLITE_FLOOR: i32 = 3_051_003;
const PROFILE: StoreOpenConfig = StoreOpenConfig::new(1_000, 4 * 1024 * 1024);
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TemporaryDatabase {
    directory: PathBuf,
    path: PathBuf,
}

impl TemporaryDatabase {
    fn create() -> std::io::Result<Self> {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "msgriver-store-profile-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory)?;
        let path = directory.join("store.db");
        Ok(Self { directory, path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[derive(Debug)]
enum CaseError {
    BehaviorRed {
        case_id: &'static str,
    },
    Mismatch {
        case_id: &'static str,
        detail: &'static str,
    },
}

impl fmt::Display for CaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BehaviorRed { case_id } => write!(
                formatter,
                "{case_id}: behavior missing — terminated at RED frontier `store_profile_open`"
            ),
            Self::Mismatch { case_id, detail } => {
                write!(formatter, "{case_id}: observable mismatch — {detail}")
            }
        }
    }
}

impl std::error::Error for CaseError {}

fn profile_case(
    case_id: &'static str,
    path: &Path,
    config: StoreOpenConfig,
    expected: Result<VerifiedStoreProfile, StoreError>,
) -> Result<(), CaseError> {
    match Store::open(path, config) {
        Err(error) if error.scaffold_frontier() == Some(StoreFrontier::ProfileOpen) => {
            Err(CaseError::BehaviorRed { case_id })
        }
        Ok(store) => {
            let actual = Ok(store.profile());
            if actual == expected {
                Ok(())
            } else {
                Err(CaseError::Mismatch {
                    case_id,
                    detail: "unexpected verified profile",
                })
            }
        }
        Err(actual) if Err(actual) == expected => Ok(()),
        Err(_) => Err(CaseError::Mismatch {
            case_id,
            detail: "unexpected store-open error",
        }),
    }
}

fn verified_profile_case(path: &Path) -> Result<(), CaseError> {
    match Store::open(path, PROFILE) {
        Err(error) if error.scaffold_frontier() == Some(StoreFrontier::ProfileOpen) => {
            Err(CaseError::BehaviorRed {
                case_id: "STORE-PROFILE-VERIFIED",
            })
        }
        Ok(store) => {
            let profile = store.profile();
            if profile.sqlite_version_number < SQLITE_FLOOR
                || profile.wal_autocheckpoint_pages != 1_000
                || profile.journal_size_limit_bytes != 4 * 1024 * 1024
            {
                Err(CaseError::Mismatch {
                    case_id: "STORE-PROFILE-VERIFIED",
                    detail: "unexpected verified profile",
                })
            } else {
                Ok(())
            }
        }
        Err(_) => Err(CaseError::Mismatch {
            case_id: "STORE-PROFILE-VERIFIED",
            detail: "unexpected store-open error",
        }),
    }
}

fn write_integrity_fixture(path: &Path) -> Result<(), CaseError> {
    {
        let connection = Connection::open(path).map_err(|_| CaseError::Mismatch {
            case_id: "STORE-PROFILE-INTEGRITY",
            detail: "integrity fixture setup failed",
        })?;
        connection
            .execute_batch(
                "PRAGMA page_size = 4096;
                 VACUUM;
                 CREATE TABLE integrity_fixture (value TEXT NOT NULL);",
            )
            .map_err(|_| CaseError::Mismatch {
                case_id: "STORE-PROFILE-INTEGRITY",
                detail: "integrity fixture setup failed",
            })?;
        for index in 0..200 {
            let value = format!("fixture-{index:03}-{}", "x".repeat(200));
            connection
                .execute("INSERT INTO integrity_fixture (value) VALUES (?1)", [value])
                .map_err(|_| CaseError::Mismatch {
                    case_id: "STORE-PROFILE-INTEGRITY",
                    detail: "integrity fixture setup failed",
                })?;
        }
    }

    let mut database = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| CaseError::Mismatch {
            case_id: "STORE-PROFILE-INTEGRITY",
            detail: "integrity fixture setup failed",
        })?;
    database
        .seek(SeekFrom::Start(4096))
        .and_then(|_| {
            let mut page_type = [0_u8; 1];
            database.read_exact(&mut page_type)?;
            if page_type != [0x05] {
                return Err(std::io::Error::other("unexpected SQLite fixture page"));
            }
            database.seek(SeekFrom::Start(4096))?;
            database.write_all(&[0])?;
            database.sync_all()
        })
        .map_err(|_| CaseError::Mismatch {
            case_id: "STORE-PROFILE-INTEGRITY",
            detail: "integrity fixture corruption failed",
        })?;
    drop(database);

    let connection = Connection::open(path).map_err(|_| CaseError::Mismatch {
        case_id: "STORE-PROFILE-INTEGRITY",
        detail: "corrupt fixture could not reopen",
    })?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .map_err(|_| CaseError::Mismatch {
            case_id: "STORE-PROFILE-INTEGRITY",
            detail: "corrupt fixture rejected WAL before integrity check",
        })?;
    if journal_mode != "wal" {
        return Err(CaseError::Mismatch {
            case_id: "STORE-PROFILE-INTEGRITY",
            detail: "corrupt fixture did not accept WAL",
        });
    }
    let integrity_result: Result<String, _> =
        connection.query_row("PRAGMA integrity_check", [], |row| row.get(0));
    if matches!(integrity_result, Ok(result) if result == "ok") {
        return Err(CaseError::Mismatch {
            case_id: "STORE-PROFILE-INTEGRITY",
            detail: "fixture did not reach an integrity diagnostic",
        });
    }
    Ok(())
}

fn assert_error_is_redacted(error: StoreError, sentinel: &str) -> Result<(), CaseError> {
    let debug = format!("{error:?}");
    let display = error.to_string();
    if debug.contains(sentinel)
        || display.contains(sentinel)
        || std::error::Error::source(&error).is_some()
    {
        Err(CaseError::Mismatch {
            case_id: "STORE-PROFILE-REDACTION",
            detail: "public store error exposed sensitive diagnostic data",
        })
    } else {
        Ok(())
    }
}

#[test]
fn store_profile_opens_only_after_exact_profile_verification() -> Result<(), CaseError> {
    let database = TemporaryDatabase::create().map_err(|_| CaseError::Mismatch {
        case_id: "STORE-PROFILE-VERIFIED",
        detail: "temporary database setup failed",
    })?;
    verified_profile_case(database.path())
}

#[test]
fn store_profile_rejects_zero_autocheckpoint_before_opening() -> Result<(), CaseError> {
    let database = TemporaryDatabase::create().map_err(|_| CaseError::Mismatch {
        case_id: "STORE-PROFILE-ZERO-AUTOCHECKPOINT",
        detail: "temporary database setup failed",
    })?;
    profile_case(
        "STORE-PROFILE-ZERO-AUTOCHECKPOINT",
        database.path(),
        StoreOpenConfig::new(0, 0),
        Err(StoreError::InvalidProfile),
    )?;
    if database.path().exists() {
        Err(CaseError::Mismatch {
            case_id: "STORE-PROFILE-ZERO-AUTOCHECKPOINT",
            detail: "invalid profile created database",
        })
    } else {
        Ok(())
    }
}

#[test]
fn store_profile_rejects_negative_journal_limit_before_opening() -> Result<(), CaseError> {
    let database = TemporaryDatabase::create().map_err(|_| CaseError::Mismatch {
        case_id: "STORE-PROFILE-NEGATIVE-JOURNAL-LIMIT",
        detail: "temporary database setup failed",
    })?;
    profile_case(
        "STORE-PROFILE-NEGATIVE-JOURNAL-LIMIT",
        database.path(),
        StoreOpenConfig::new(1, -1),
        Err(StoreError::InvalidProfile),
    )?;
    if database.path().exists() {
        Err(CaseError::Mismatch {
            case_id: "STORE-PROFILE-NEGATIVE-JOURNAL-LIMIT",
            detail: "invalid profile created database",
        })
    } else {
        Ok(())
    }
}

#[test]
fn store_profile_fails_closed_on_a_true_integrity_diagnostic() -> Result<(), CaseError> {
    let database = TemporaryDatabase::create().map_err(|_| CaseError::Mismatch {
        case_id: "STORE-PROFILE-INTEGRITY",
        detail: "temporary database setup failed",
    })?;
    write_integrity_fixture(database.path())?;
    match Store::open(database.path(), PROFILE) {
        Err(StoreError::Integrity) => Ok(()),
        Err(_) => Err(CaseError::Mismatch {
            case_id: "STORE-PROFILE-INTEGRITY",
            detail: "integrity diagnostic mapped to a different error",
        }),
        Ok(_) => Err(CaseError::Mismatch {
            case_id: "STORE-PROFILE-INTEGRITY",
            detail: "corrupt database was accepted",
        }),
    }
}

#[test]
fn store_profile_redacts_database_path_from_public_errors() -> Result<(), CaseError> {
    const SENTINEL: &str = "msgriver-redaction-sentinel";
    let database = TemporaryDatabase::create().map_err(|_| CaseError::Mismatch {
        case_id: "STORE-PROFILE-REDACTION",
        detail: "temporary database setup failed",
    })?;
    let directory_path = database.path().with_file_name(SENTINEL);
    fs::create_dir(&directory_path).map_err(|_| CaseError::Mismatch {
        case_id: "STORE-PROFILE-REDACTION",
        detail: "redaction fixture setup failed",
    })?;
    match Store::open(&directory_path, PROFILE) {
        Err(error @ StoreError::Open) => assert_error_is_redacted(error, SENTINEL),
        Err(_) => Err(CaseError::Mismatch {
            case_id: "STORE-PROFILE-REDACTION",
            detail: "directory open mapped to a different error",
        }),
        Ok(_) => Err(CaseError::Mismatch {
            case_id: "STORE-PROFILE-REDACTION",
            detail: "directory was accepted as a database",
        }),
    }
}
