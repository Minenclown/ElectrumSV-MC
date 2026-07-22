// db/connection.rs — SQLite connection with WAL mode and PRAGMAs
//
// Provides async SQLite connection via sqlx.
// Handles wallet database creation and migration (0022-0028).

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::path::Path;
use std::str::FromStr;

/// Current migration version (matches Python MIGRATION_CURRENT).
pub const MIGRATION_CURRENT: i64 = 31;

/// First migration version (matches Python MIGRATION_FIRST).
pub const MIGRATION_FIRST: i64 = 22;

/// SQL for migration 0022 — creates all base tables.
const SQL_0022: &str = include_str!("../../migrations/0022_create_database.sql");
/// SQL for migration 0023 — adds wallet events table.
const SQL_0023: &str = include_str!("../../migrations/0023_add_wallet_events.sql");
/// SQL for migration 0024 — account transactions view + payment request state.
const SQL_0024: &str = include_str!("../../migrations/0024_account_transactions.sql");
/// SQL for migration 0025 — adds invoices table.
const SQL_0025: &str = include_str!("../../migrations/0025_invoices.sql");
/// SQL for migration 0026 — TXO coinbase flag.
const SQL_0026: &str = include_str!("../../migrations/0026_txo_coinbase_flag.sql");
/// SQL for migration 0027 — TOTP secrets table.
const SQL_0027: &str = include_str!("../../migrations/0027_totp_secrets.sql");
/// SQL for migration 0028 — TOTP recovery codes table.
const SQL_0028: &str = include_str!("../../migrations/0028_totp_recovery_codes.sql");
/// SQL for migration 0029 — contacts tables.
const SQL_0029: &str = include_str!("../../migrations/0029_contacts.sql");
/// SQL for migration 0030 — multisig account configurations table.
const SQL_0030: &str = include_str!("../../migrations/0030_multisig_configs.sql");
/// SQL for migration 0031 — add script_pubkey to TransactionOutputs.
const SQL_0031: &str = include_str!("../../migrations/0031_txo_script_pubkey.sql");

/// All migration SQL in order.
const ALL_MIGRATIONS: [(i64, &str); 10] = [
    (22, SQL_0022),
    (23, SQL_0023),
    (24, SQL_0024),
    (25, SQL_0025),
    (26, SQL_0026),
    (27, SQL_0027),
    (28, SQL_0028),
    (29, SQL_0029),
    (30, SQL_0030),
    (31, SQL_0031),
];

/// Create a new wallet database file from scratch.
///
/// Applies all migrations (0022-0028) in order and sets the
/// `migration` key in WalletData to MIGRATION_CURRENT.
///
/// # Arguments
/// * `wallet_path` — Absolute path to the .sqlite file to create
pub async fn create_wallet_db(wallet_path: &str) -> anyhow::Result<()> {
    let path = Path::new(wallet_path);

    if path.exists() {
        anyhow::bail!("Wallet database already exists: {}", wallet_path);
    }

    log::info!("Creating new wallet database: {}", wallet_path);

    let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", wallet_path))?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
        .foreign_keys(true)
        .busy_timeout(std::time::Duration::from_secs(5));

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;

    // Apply all migrations in a single transaction
    let mut tx = pool.begin().await?;

    for (version, sql) in ALL_MIGRATIONS.iter() {
        log::debug!("Applying migration {:04}", version);
        sqlx::query(sql).execute(&mut *tx).await?;
    }

    // Set migration version in WalletData
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO WalletData (key, value, date_created, date_updated) VALUES ('migration', ?, ?, ?)",
    )
    .bind(MIGRATION_CURRENT.to_string())
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    // Initialize next_* counters in WalletData
    for (key, value) in &[
        ("next_masterkey_id", "1"),
        ("next_account_id", "1"),
        ("next_keyinstance_id", "1"),
        ("next_paymentrequest_id", "1"),
    ] {
        sqlx::query(
            "INSERT INTO WalletData (key, value, date_created, date_updated) VALUES (?, ?, ?, ?)",
        )
        .bind(key)
        .bind(value)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    pool.close().await;

    log::info!(
        "Wallet database created at {} (migration {})",
        wallet_path,
        MIGRATION_CURRENT
    );
    Ok(())
}

/// Opens a SQLite connection for an existing wallet file.
///
/// - Enables WAL mode for better concurrent read performance
/// - Sets foreign_keys ON
/// - Runs pending migrations if needed
///
/// # Arguments
/// * `wallet_path` — Absolute path to the .sqlite file
pub async fn open_wallet_db(wallet_path: &str) -> anyhow::Result<SqlitePool> {
    let path = Path::new(wallet_path);

    if !path.exists() {
        anyhow::bail!("Wallet file does not exist: {}", wallet_path);
    }

    log::info!("Opening wallet database: {}", wallet_path);

    let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", wallet_path))?
        .create_if_missing(false)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
        .foreign_keys(true)
        .busy_timeout(std::time::Duration::from_secs(5));

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;

    // Apply pending migrations
    ensure_migrations(&pool).await?;

    Ok(pool)
}

/// Checks the migration version in WalletData and applies missing migrations.
///
/// The Python version uses a `migration` field in the WalletData table
/// (values 22-28). We respect this and only apply missing ones.
///
/// AUD-019 fix: This function is fail-closed. A missing WalletData table,
/// a missing migration key, or a future/unknown version are all treated
/// as errors rather than silently proceeding.
async fn ensure_migrations(pool: &SqlitePool) -> anyhow::Result<()> {
    // Check if WalletData table exists — fail-closed if not
    let table_exists: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='WalletData'",
    )
    .fetch_one(pool)
    .await?;

    if table_exists.0 == 0 {
        anyhow::bail!("WalletData table not found — database is corrupted or not a valid wallet");
    }

    // Read current migration version — fail-closed if key is missing
    let row: Option<(String,)> =
        sqlx::query_as("SELECT value FROM WalletData WHERE key='migration'")
            .fetch_optional(pool)
            .await?;

    let current_version: i64 = match row {
        Some((value,)) => value.parse::<i64>().map_err(|_| {
            anyhow::anyhow!(
                "Migration version is not a valid integer: '{}' — database may be corrupted",
                value
            )
        })?,
        None => {
            anyhow::bail!(
                "No migration key in WalletData — database is corrupted or incompletely initialized"
            );
        }
    };

    // Reject future/unknown versions — fail-closed
    if current_version > MIGRATION_CURRENT {
        anyhow::bail!(
            "Wallet database migration version {} is newer than supported {} — \
             downgrade is not supported. Update the application or use a compatible version.",
            current_version,
            MIGRATION_CURRENT
        );
    }

    log::info!("Wallet database at migration {}", current_version);

    if current_version == MIGRATION_CURRENT {
        log::debug!("Database is up to date (migration {})", current_version);
        return Ok(());
    }

    // Apply pending migrations
    let mut tx = pool.begin().await?;
    let mut version = current_version;

    for (mig_version, sql) in ALL_MIGRATIONS.iter() {
        if version < *mig_version {
            log::info!("Applying migration {:04}", mig_version);
            sqlx::query(sql).execute(&mut *tx).await?;
            version = *mig_version;
        }
    }

    // Update migration version in WalletData
    let now = chrono::Utc::now().timestamp();
    let result = sqlx::query("UPDATE WalletData SET value=?, date_updated=? WHERE key='migration'")
        .bind(MIGRATION_CURRENT.to_string())
        .bind(now)
        .execute(&mut *tx)
        .await?;

    // Verify the migration key was actually updated (AUD-019: check affected rows)
    if result.rows_affected() == 0 {
        // Key doesn't exist — insert it
        sqlx::query(
            "INSERT INTO WalletData (key, value, date_created, date_updated) VALUES ('migration', ?, ?, ?)",
        )
        .bind(MIGRATION_CURRENT.to_string())
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    log::info!(
        "Migrations applied — database now at version {}",
        MIGRATION_CURRENT
    );
    Ok(())
}

/// Lists all .sqlite files in the data directory.
///
/// Returns an error if the directory cannot be read (AUD fix: do not
/// silently swallow filesystem errors — the caller must be able to
/// distinguish "no wallets" from "directory unreadable").
pub fn list_wallet_files(data_dir: &str) -> Result<Vec<WalletFileInfo>, std::io::Error> {
    let mut wallets = Vec::new();

    let dir = Path::new(data_dir);
    if !dir.is_dir() {
        return Ok(wallets);
    }

    let entries = std::fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("sqlite") {
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();

            // Skip non-wallet database files
            if name == "headers" {
                continue;
            }

            let metadata = entry.metadata()?;
            let size = metadata.len();
            let modified = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);

            wallets.push(WalletFileInfo {
                name,
                path: path.to_string_lossy().to_string(),
                size_bytes: size,
                modified_unix: modified,
            });
        }
    }

    // Sort by name
    wallets.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(wallets)
}

/// Info about a wallet file on disk.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WalletFileInfo {
    /// Wallet name (filename without .sqlite)
    pub name: String,
    /// Absolute path to the .sqlite file
    pub path: String,
    /// File size in bytes
    pub size_bytes: u64,
    /// Last modified (Unix timestamp)
    pub modified_unix: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_test_dir(test_name: &str) -> std::path::PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("electrumsv_mc_{}_{}", test_name, id));
        // Clean up any leftover from previous test runs
        if dir.exists() {
            std::fs::remove_dir_all(&dir).ok();
        }
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_list_wallet_files_finds_sqlite() {
        // AUD-023 fix: hermetic test — creates its own temp dir with a sqlite file
        let temp_dir = unique_test_dir("lwf_finds");
        std::fs::write(temp_dir.join("mywallet.sqlite"), b"sqlite").unwrap();

        let wallets = list_wallet_files(temp_dir.to_str().unwrap()).unwrap();
        assert_eq!(wallets.len(), 1);
        assert_eq!(wallets[0].name, "mywallet");

        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_list_wallet_files_nonexistent_dir() {
        // Non-existent dir returns Ok(empty), not an error
        let wallets = list_wallet_files("/nonexistent/path/that/does/not/exist").unwrap();
        assert!(wallets.is_empty());
    }

    #[test]
    fn test_list_wallet_files_ignores_non_sqlite() {
        let temp_dir = unique_test_dir("lwf_ignores");
        std::fs::write(temp_dir.join("wallet.bak"), b"backup").unwrap();
        std::fs::write(temp_dir.join("wallet.bak-shm"), b"shm").unwrap();
        std::fs::write(temp_dir.join("wallet.bak-wal"), b"wal").unwrap();
        std::fs::write(temp_dir.join("valid.sqlite"), b"sqlite").unwrap();

        let wallets = list_wallet_files(temp_dir.to_str().unwrap()).unwrap();
        assert_eq!(wallets.len(), 1);
        assert_eq!(wallets[0].name, "valid");

        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[tokio::test]
    async fn test_create_wallet_db_from_scratch() {
        let temp_dir = unique_test_dir("create_db");
        let db_path = temp_dir.join("test_create.sqlite");
        if db_path.exists() {
            std::fs::remove_file(&db_path).unwrap();
        }

        // Create the database
        create_wallet_db(db_path.to_str().unwrap()).await.unwrap();

        // Verify the file exists
        assert!(db_path.exists());

        // Open it and verify tables exist
        let pool = open_wallet_db(db_path.to_str().unwrap()).await.unwrap();

        // Check WalletData has migration key
        let row: (String,) = sqlx::query_as("SELECT value FROM WalletData WHERE key='migration'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row.0, "31");

        // Check MasterKeys table exists
        let count: (i64,) = sqlx::query_as("SELECT count(*) FROM MasterKeys")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 0);

        // Check Accounts table exists
        let count: (i64,) = sqlx::query_as("SELECT count(*) FROM Accounts")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 0);

        // Check WalletEvents table exists (migration 0023)
        let count: (i64,) = sqlx::query_as("SELECT count(*) FROM WalletEvents")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 0);

        // Check Invoices table exists (migration 0025)
        let count: (i64,) = sqlx::query_as("SELECT count(*) FROM Invoices")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 0);

        // Check TotpSecrets table exists (migration 0027)
        let count: (i64,) = sqlx::query_as("SELECT count(*) FROM TotpSecrets")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 0);

        // Check TotpRecoveryCodes table exists (migration 0028)
        let count: (i64,) = sqlx::query_as("SELECT count(*) FROM TotpRecoveryCodes")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 0);

        // Verify next_* counters
        let row: (String,) =
            sqlx::query_as("SELECT value FROM WalletData WHERE key='next_masterkey_id'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(row.0, "1");

        pool.close().await;
        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[tokio::test]
    async fn test_create_wallet_db_refuses_existing() {
        let temp_dir = unique_test_dir("refuse_existing");
        let db_path = temp_dir.join("test_refuse.sqlite");
        std::fs::write(&db_path, b"existing").unwrap();

        let result = create_wallet_db(db_path.to_str().unwrap()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));

        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[tokio::test]
    async fn test_open_wallet_db_refuses_nonexistent() {
        let result = open_wallet_db("/nonexistent/path/wallet.sqlite").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }

    #[tokio::test]
    async fn test_ensure_migrations_rejects_future_version() {
        // AUD-019: fail-closed on future migration version
        let temp_dir = unique_test_dir("future_version");
        let db_path = temp_dir.join("test_future.sqlite");

        create_wallet_db(db_path.to_str().unwrap()).await.unwrap();
        let pool = open_wallet_db(db_path.to_str().unwrap()).await.unwrap();

        // Manually set migration to a future version
        let now = chrono::Utc::now().timestamp();
        sqlx::query("UPDATE WalletData SET value='999', date_updated=? WHERE key='migration'")
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();

        pool.close().await;

        // Re-opening should fail with future version error
        let result = open_wallet_db(db_path.to_str().unwrap()).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("newer than supported") || err_msg.contains("downgrade"),
            "Expected future version error, got: {}",
            err_msg
        );

        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[tokio::test]
    async fn test_ensure_migrations_rejects_missing_walletdata() {
        // AUD-019: fail-closed on missing WalletData table
        let temp_dir = unique_test_dir("no_walletdata");
        let db_path = temp_dir.join("test_no_wd.sqlite");

        // Create a valid DB first, then drop WalletData
        create_wallet_db(db_path.to_str().unwrap()).await.unwrap();
        let pool = open_wallet_db(db_path.to_str().unwrap()).await.unwrap();
        sqlx::query("DROP TABLE WalletData")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;

        // Re-opening should fail
        let result = open_wallet_db(db_path.to_str().unwrap()).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("WalletData table not found"));

        std::fs::remove_dir_all(&temp_dir).ok();
    }
}
