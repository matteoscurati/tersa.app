// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Defines the bounded `SQLCipher` migration contract and canonical schemas.

#![forbid(unsafe_code)]

use std::error::Error;
use std::ffi::OsStr;

use rusqlite::{Connection, Transaction};

const GLOBAL_APPLICATION_ID: i64 = 0x5447_4c42;
const ACCOUNT_APPLICATION_ID: i64 = 0x5441_4343;
const GLOBAL_MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        sql: include_str!("../migrations/global/0001_initial.sql"),
    },
    Migration {
        version: 2,
        sql: include_str!("../migrations/global/0002_preferences.sql"),
    },
];
const ACCOUNT_MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        sql: include_str!("../migrations/account/0001_mail_cache.sql"),
    },
    Migration {
        version: 2,
        sql: include_str!("../migrations/account/0002_pending_operations.sql"),
    },
];

type Result<T = ()> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

/// Applies a compiled migration chain to an already configured connection.
pub(crate) fn migrate_connection(
    mut connection: Connection,
    kind: DatabaseKind,
    target_version: i64,
) -> Result<(Connection, i64)> {
    validate_migration_chain(kind.migrations())?;
    if !(0..=kind.latest()).contains(&target_version) {
        return Err("requested migration target is outside the compiled chain".into());
    }
    let mut version = validate_open_state(&connection, kind)?;
    if version > target_version {
        return Err("database downgrade is prohibited".into());
    }
    let mut applied = 0;
    while version < target_version {
        let migration = &kind.migrations()[usize::try_from(version)?];
        let transaction = connection.transaction()?;
        apply_migration_body(&transaction, kind, migration)?;
        transaction.commit()?;
        version = migration.version;
        applied += 1;
        validate_database_state(&connection, kind, version)?;
    }
    Ok((connection, applied))
}

/// Executes migration DDL and writes its transactional ownership cursors.
pub(crate) fn apply_migration_body(
    transaction: &Transaction<'_>,
    kind: DatabaseKind,
    migration: &Migration,
) -> Result {
    transaction.execute_batch(migration.sql)?;
    if migration.version == 1 {
        transaction.pragma_update(None, "application_id", kind.application_id())?;
    }
    transaction.pragma_update(None, "user_version", migration.version)?;
    Ok(())
}

/// Validates exact ownership, version, and canonical schema state.
pub(crate) fn validate_database_state(
    connection: &Connection,
    kind: DatabaseKind,
    version: i64,
) -> Result {
    let application_id: i64 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if application_id != kind.application_id() || user_version != version {
        return Err("database ownership or version differs from the expected state".into());
    }
    validate_schema_objects(kind, version, &schema_objects(connection)?)
}

/// Runs foreign-key, `SQLite`, and `SQLCipher` integrity checks.
pub(crate) fn verify_database_health(connection: &Connection) -> Result {
    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    if foreign_keys != 1 {
        return Err("foreign key enforcement is disabled".into());
    }
    let mut foreign_key_check = connection.prepare("PRAGMA foreign_key_check")?;
    if foreign_key_check.query([])?.next()?.is_some() {
        return Err("foreign_key_check returned a failure".into());
    }
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err("integrity_check did not return ok".into());
    }
    let mut cipher_integrity = connection.prepare("PRAGMA cipher_integrity_check")?;
    if cipher_integrity.query([])?.next()?.is_some() {
        return Err("cipher_integrity_check returned a failure".into());
    }
    Ok(())
}

/// Captures the exact ownership and normalized structural schema state.
pub(crate) fn schema_snapshot(connection: &Connection) -> Result<SchemaSnapshot> {
    Ok(SchemaSnapshot {
        application_id: connection.query_row("PRAGMA application_id", [], |row| row.get(0))?,
        user_version: connection.query_row("PRAGMA user_version", [], |row| row.get(0))?,
        objects: schema_objects(connection)?,
    })
}

fn validate_migration_chain(migrations: &[Migration]) -> Result {
    if migrations.is_empty()
        || migrations
            .iter()
            .enumerate()
            .any(|(index, migration)| migration.version != i64::try_from(index + 1).unwrap_or(-1))
    {
        return Err("compiled migration chain is empty or noncontiguous".into());
    }
    Ok(())
}

fn validate_open_state(connection: &Connection, kind: DatabaseKind) -> Result<i64> {
    let application_id: i64 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let schema = schema_objects(connection)?;
    if application_id == 0 {
        if user_version != 0 || !schema.is_empty() {
            return Err("unowned database is not exactly empty and fresh".into());
        }
        return Ok(0);
    }
    if application_id != kind.application_id() || user_version == 0 {
        return Err("database application ownership is unknown or inconsistent".into());
    }
    if user_version > kind.latest() {
        return Err("database version is newer than the compiled chain".into());
    }
    validate_schema_objects(kind, user_version, &schema)?;
    Ok(user_version)
}

fn schema_objects(connection: &Connection) -> Result<Vec<SchemaObject>> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name, tbl_name",
    )?;
    let mut objects = statement
        .query_map([], |row| {
            Ok(SchemaObject {
                object_type: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql: row
                    .get::<_, Option<String>>(3)?
                    .map(|sql| normalize_sql(&sql)),
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    objects.sort();
    Ok(objects)
}

fn validate_schema_objects(kind: DatabaseKind, version: i64, actual: &[SchemaObject]) -> Result {
    if actual != canonical_schema(kind, version)?.as_slice() {
        return Err("database schema differs from the canonical structure".into());
    }
    Ok(())
}

fn canonical_schema(kind: DatabaseKind, version: i64) -> Result<Vec<SchemaObject>> {
    let mut objects = match (kind, version) {
        (_, 0) => Vec::new(),
        (DatabaseKind::Global, 1) => vec![table(
            "accounts",
            "CREATE TABLE accounts ( id INTEGER PRIMARY KEY )",
        )],
        (DatabaseKind::Global, 2) => vec![
            index("sqlite_autoindex_preferences_1", "preferences"),
            table(
                "accounts",
                "CREATE TABLE accounts ( id INTEGER PRIMARY KEY )",
            ),
            table(
                "preferences",
                "CREATE TABLE preferences ( key TEXT PRIMARY KEY, value BLOB NOT NULL )",
            ),
        ],
        (DatabaseKind::Account, 1) => account_schema(false),
        (DatabaseKind::Account, 2) => account_schema(true),
        _ => return Err("canonical schema version is unavailable".into()),
    };
    objects.sort();
    Ok(objects)
}

fn account_schema(include_pending_operations: bool) -> Vec<SchemaObject> {
    let mut objects = vec![
        index("sqlite_autoindex_message_labels_1", "message_labels"),
        table("labels", "CREATE TABLE labels ( id INTEGER PRIMARY KEY )"),
        table(
            "message_labels",
            "CREATE TABLE message_labels ( message_id INTEGER REFERENCES messages(id), label_id INTEGER REFERENCES labels(id), PRIMARY KEY (message_id, label_id) )",
        ),
        table(
            "messages",
            "CREATE TABLE messages ( id INTEGER PRIMARY KEY, thread_id INTEGER REFERENCES threads(id) )",
        ),
        table("threads", "CREATE TABLE threads ( id INTEGER PRIMARY KEY )"),
    ];
    if include_pending_operations {
        objects.push(table("pending_operations", "CREATE TABLE pending_operations ( id INTEGER PRIMARY KEY, message_id INTEGER REFERENCES messages(id), operation BLOB NOT NULL )"));
    }
    objects
}

fn table(name: &str, sql: &str) -> SchemaObject {
    SchemaObject {
        object_type: "table".into(),
        name: name.into(),
        table_name: name.into(),
        sql: Some(sql.into()),
    }
}

fn index(name: &str, table_name: &str) -> SchemaObject {
    SchemaObject {
        object_type: "index".into(),
        name: name.into(),
        table_name: table_name.into(),
        sql: None,
    }
}

fn normalize_sql(sql: &str) -> String {
    sql.trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Migration {
    version: i64,
    sql: &'static str,
}

/// Selects the separately owned synthetic database schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DatabaseKind {
    Global,
    Account,
}

impl DatabaseKind {
    pub(crate) fn from_os_str(value: &OsStr) -> Option<Self> {
        match value.to_str()? {
            "global" => Some(Self::Global),
            "account" => Some(Self::Account),
            _ => None,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Account => "account",
        }
    }

    pub(crate) fn application_id(self) -> i64 {
        match self {
            Self::Global => GLOBAL_APPLICATION_ID,
            Self::Account => ACCOUNT_APPLICATION_ID,
        }
    }

    pub(crate) fn other(self) -> Self {
        match self {
            Self::Global => Self::Account,
            Self::Account => Self::Global,
        }
    }

    pub(crate) fn migrations(self) -> &'static [Migration] {
        match self {
            Self::Global => GLOBAL_MIGRATIONS,
            Self::Account => ACCOUNT_MIGRATIONS,
        }
    }

    pub(crate) fn latest(self) -> i64 {
        i64::try_from(self.migrations().len()).unwrap_or(-1)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SchemaObject {
    object_type: String,
    name: String,
    table_name: String,
    sql: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SchemaSnapshot {
    application_id: i64,
    user_version: i64,
    objects: Vec<SchemaObject>,
}

#[cfg(test)]
mod tests {
    use super::{
        DatabaseKind, Migration, canonical_schema, normalize_sql, validate_migration_chain,
    };

    #[test]
    fn compiled_chains_are_contiguous() {
        for kind in [DatabaseKind::Global, DatabaseKind::Account] {
            validate_migration_chain(kind.migrations()).expect("compiled chain must be contiguous");
        }
    }

    #[test]
    fn noncontiguous_chain_is_rejected() {
        let migrations = [
            Migration {
                version: 1,
                sql: "",
            },
            Migration {
                version: 3,
                sql: "",
            },
        ];
        assert!(validate_migration_chain(&migrations).is_err());
    }

    #[test]
    fn database_kinds_have_distinct_ownership() {
        for kind in [DatabaseKind::Global, DatabaseKind::Account] {
            assert!(kind.application_id() != kind.other().application_id());
            assert!(kind.other().other() == kind);
        }
    }

    #[test]
    fn canonical_schema_versions_are_distinct() {
        for kind in [DatabaseKind::Global, DatabaseKind::Account] {
            let version_one = canonical_schema(kind, 1).expect("version one must be canonical");
            let version_two = canonical_schema(kind, 2).expect("version two must be canonical");
            assert!(version_one != version_two);
            assert!(canonical_schema(kind, 3).is_err());
        }
    }

    #[test]
    fn sql_normalization_is_whitespace_stable() {
        assert_eq!(
            normalize_sql("CREATE  TABLE x (\n id INTEGER\t);"),
            "CREATE TABLE x ( id INTEGER )"
        );
    }
}

// Rust guideline compliant 1.0.
