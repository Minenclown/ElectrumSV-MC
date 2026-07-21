// db/repositories.rs — SQL queries for MasterKeys, Accounts, WalletData
//
// Provides typed database operations for the wallet tables.
// All queries use sqlx async SQLite.

use sqlx::SqlitePool;

/// Script type constants (matches Python ScriptType.IntEnum).
pub mod script_type {
    pub const NONE: i32 = 0;
    pub const COINBASE: i32 = 1;
    pub const P2PKH: i32 = 2;
    pub const P2PK: i32 = 3;
    /// Multisig account using accumulator-style m-of-n script (see core/multisig.rs).
    pub const MULTISIG: i32 = 4;
}

/// Derivation type constants (matches Python DerivationType.IntEnum).
pub mod derivation_type {
    pub const BIP32: i32 = 3;
}

/// A MasterKey row from the database.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct MasterKeyRow {
    pub masterkey_id: i64,
    pub parent_masterkey_id: Option<i64>,
    pub derivation_type: i32,
    pub derivation_data: Vec<u8>,
    pub date_created: i64,
    pub date_updated: i64,
}

/// An Account row from the database.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct AccountRow {
    pub account_id: i64,
    pub default_masterkey_id: Option<i64>,
    pub default_script_type: i32,
    pub account_name: String,
    pub date_created: i64,
    pub date_updated: i64,
}

/// Insert a master key into the MasterKeys table.
pub async fn insert_master_key(
    pool: &SqlitePool,
    parent_masterkey_id: Option<i64>,
    derivation_type: i32,
    derivation_data: &[u8],
) -> anyhow::Result<i64> {
    let now = chrono::Utc::now().timestamp();
    let result = sqlx::query(
        "INSERT INTO MasterKeys (parent_masterkey_id, derivation_type, derivation_data, date_created, date_updated) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(parent_masterkey_id)
    .bind(derivation_type)
    .bind(derivation_data)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Insert an account into the Accounts table.
pub async fn insert_account(
    pool: &SqlitePool,
    default_masterkey_id: Option<i64>,
    default_script_type: i32,
    account_name: &str,
) -> anyhow::Result<i64> {
    let now = chrono::Utc::now().timestamp();
    let result = sqlx::query(
        "INSERT INTO Accounts (default_masterkey_id, default_script_type, account_name, date_created, date_updated) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(default_masterkey_id)
    .bind(default_script_type)
    .bind(account_name)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Get a single WalletData value by key.
pub async fn get_wallet_data(pool: &SqlitePool, key: &str) -> anyhow::Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as("SELECT value FROM WalletData WHERE key=?")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(v,)| v))
}

/// Set a WalletData value (insert or update).
pub async fn set_wallet_data(pool: &SqlitePool, key: &str, value: &str) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO WalletData (key, value, date_created, date_updated) VALUES (?, ?, ?, ?) \
         ON CONFLICT(key) DO UPDATE SET value=excluded.value, date_updated=excluded.date_updated",
    )
    .bind(key)
    .bind(value)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Read the first master key from the database (the primary wallet key).
pub async fn get_first_master_key(pool: &SqlitePool) -> anyhow::Result<Option<MasterKeyRow>> {
    let row =
        sqlx::query_as::<_, MasterKeyRow>("SELECT * FROM MasterKeys ORDER BY masterkey_id LIMIT 1")
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

/// Read the first account from the database.
pub async fn get_first_account(pool: &SqlitePool) -> anyhow::Result<Option<AccountRow>> {
    let row = sqlx::query_as::<_, AccountRow>("SELECT * FROM Accounts ORDER BY account_id LIMIT 1")
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

// ============================================================================
// KeyInstance queries (Milestone 3)
// ============================================================================

/// A KeyInstance row from the database.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct KeyInstanceRow {
    pub keyinstance_id: i64,
    pub account_id: i64,
    pub masterkey_id: Option<i64>,
    pub derivation_type: i32,
    pub derivation_data: Vec<u8>,
    pub script_type: i32,
    pub flags: i32,
    pub description: Option<String>,
    pub date_created: i64,
    pub date_updated: i64,
}

/// Get all KeyInstances for a given account.
pub async fn get_keyinstances_for_account(
    pool: &SqlitePool,
    account_id: i64,
) -> anyhow::Result<Vec<KeyInstanceRow>> {
    let rows = sqlx::query_as::<_, KeyInstanceRow>(
        "SELECT * FROM KeyInstances WHERE account_id = ? ORDER BY keyinstance_id",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Get a single KeyInstance by ID.
pub async fn get_keyinstance(
    pool: &SqlitePool,
    keyinstance_id: i64,
) -> anyhow::Result<Option<KeyInstanceRow>> {
    let row =
        sqlx::query_as::<_, KeyInstanceRow>("SELECT * FROM KeyInstances WHERE keyinstance_id = ?")
            .bind(keyinstance_id)
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

/// Insert a new KeyInstance.
pub async fn insert_keyinstance(
    pool: &SqlitePool,
    account_id: i64,
    masterkey_id: Option<i64>,
    derivation_type: i32,
    derivation_data: &[u8],
    script_type: i32,
    flags: i32,
    description: Option<&str>,
) -> anyhow::Result<i64> {
    let now = chrono::Utc::now().timestamp();
    let result = sqlx::query(
        "INSERT INTO KeyInstances \
         (account_id, masterkey_id, derivation_type, derivation_data, script_type, flags, description, date_created, date_updated) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(account_id)
    .bind(masterkey_id)
    .bind(derivation_type)
    .bind(derivation_data)
    .bind(script_type)
    .bind(flags)
    .bind(description)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Get the next keyinstance index for an account.
/// Returns (receiving_count, change_count) based on existing KeyInstances.
pub async fn get_keyinstance_counts(
    pool: &SqlitePool,
    account_id: i64,
) -> anyhow::Result<(i64, i64)> {
    // Count KeyInstances by parsing derivation_data JSON for subpath type
    // subpath[0] = 0 → receiving, subpath[0] = 1 → change
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
        "SELECT derivation_data FROM KeyInstances WHERE account_id = ? AND derivation_type = ?",
    )
    .bind(account_id)
    .bind(derivation_type::BIP32)
    .fetch_all(pool)
    .await?;

    let mut receiving = 0i64;
    let mut change = 0i64;

    for (data,) in &rows {
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) {
            if let Some(subpath) = json.get("subpath").and_then(|s| s.as_array()) {
                if let Some(type_idx) = subpath.first().and_then(|t| t.as_i64()) {
                    if type_idx == 0 {
                        receiving += 1;
                    } else if type_idx == 1 {
                        change += 1;
                    }
                }
            }
        }
    }

    Ok((receiving, change))
}

// ============================================================================
// TransactionOutput queries (Milestone 3)
// ============================================================================

/// TransactionOutput flag constants (matches Python TransactionOutputFlag).
pub mod txo_flags {
    /// Output is coinbase (bit 0).
    pub const IS_COINBASE: i32 = 1;
    /// Output is spent (bit 1).
    pub const IS_SPENT: i32 = 2;
}

/// A TransactionOutput row from the database.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TransactionOutputRow {
    pub tx_hash: Vec<u8>,
    pub tx_index: i64,
    pub value: i64,
    pub keyinstance_id: i64,
    pub flags: i32,
    pub date_created: i64,
    pub date_updated: i64,
}

/// Get all unspent TransactionOutputs (UTXOs) for KeyInstances of an account.
///
/// UTXO = TransactionOutputs where flags & IS_SPENT == 0
pub async fn get_utxos_for_account(
    pool: &SqlitePool,
    account_id: i64,
) -> anyhow::Result<Vec<TransactionOutputRow>> {
    let rows = sqlx::query_as::<_, TransactionOutputRow>(
        "SELECT txo.* FROM TransactionOutputs txo \
         INNER JOIN KeyInstances ki ON txo.keyinstance_id = ki.keyinstance_id \
         WHERE ki.account_id = ? AND (txo.flags & ?) = 0 \
         ORDER BY txo.date_created",
    )
    .bind(account_id)
    .bind(txo_flags::IS_SPENT)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Get the balance (sum of UTXO values) for an account.
///
/// Returns (confirmed, unconfirmed, total).
/// confirmed = UTXOs where the corresponding Transaction has a block_height
/// unconfirmed = UTXOs where the Transaction has no block_height
pub async fn get_balance_for_account(
    pool: &SqlitePool,
    account_id: i64,
) -> anyhow::Result<(i64, i64, i64)> {
    let rows: Vec<(i64, Option<i64>)> = sqlx::query_as(
        "SELECT txo.value, tx.block_height \
         FROM TransactionOutputs txo \
         INNER JOIN KeyInstances ki ON txo.keyinstance_id = ki.keyinstance_id \
         INNER JOIN Transactions tx ON txo.tx_hash = tx.tx_hash \
         WHERE ki.account_id = ? AND (txo.flags & ?) = 0",
    )
    .bind(account_id)
    .bind(txo_flags::IS_SPENT)
    .fetch_all(pool)
    .await?;

    let mut confirmed = 0i64;
    let mut unconfirmed = 0i64;

    for (value, block_height) in &rows {
        if block_height.is_some() {
            confirmed += value;
        } else {
            unconfirmed += value;
        }
    }

    Ok((confirmed, unconfirmed, confirmed + unconfirmed))
}

// ============================================================================
// TransactionDelta queries (Milestone 3)
// ============================================================================

/// A TransactionDelta row joined with Transaction data for history.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct TxDeltaHistoryRow {
    /// Display hex txid (reversed byte order, AUD-014 fix)
    pub tx_hash_hex: String,
    /// Net value delta for this account (sum of deltas)
    pub value_delta: i64,
    /// Transaction creation timestamp
    pub date_created: i64,
    /// Block height (None = unconfirmed)
    pub block_height: Option<i64>,
    /// Transaction description (if any)
    pub description: Option<String>,
}

/// Get transaction history (deltas) for an account.
///
/// Joins TransactionDeltas with Transactions, grouped by tx_hash.
/// Uses hash_to_hex_str for proper byte-order conversion (AUD-014).
pub async fn get_tx_history_for_account(
    pool: &SqlitePool,
    account_id: i64,
    limit: i64,
    offset: i64,
) -> anyhow::Result<Vec<TxDeltaHistoryRow>> {
    // First get the raw deltas joined with transactions
    let rows: Vec<(Vec<u8>, i64, i64, Option<i64>, Option<String>)> = sqlx::query_as(
        "SELECT td.tx_hash, SUM(td.value_delta) as value_delta, \
         MIN(tx.date_created) as date_created, \
         tx.block_height, tx.description \
         FROM TransactionDeltas td \
         INNER JOIN KeyInstances ki ON td.keyinstance_id = ki.keyinstance_id \
         INNER JOIN Transactions tx ON td.tx_hash = tx.tx_hash \
         WHERE ki.account_id = ? \
         GROUP BY td.tx_hash \
         ORDER BY MIN(tx.date_created) DESC \
         LIMIT ? OFFSET ?",
    )
    .bind(account_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    // Convert tx_hash bytes to display hex (reversed)
    let result: Vec<TxDeltaHistoryRow> = rows
        .into_iter()
        .map(
            |(tx_hash, value_delta, date_created, block_height, description)| TxDeltaHistoryRow {
                tx_hash_hex: crate::core::address::hash_to_hex_str(&tx_hash),
                value_delta,
                date_created,
                block_height,
                description,
            },
        )
        .collect();

    Ok(result)
}

/// UTXO info for API responses (with display hex txid).
#[derive(Debug, Clone, serde::Serialize)]
pub struct UtxoInfo {
    /// Display hex txid (reversed byte order, AUD-014 fix)
    pub tx_hash_hex: String,
    pub tx_index: i64,
    pub value: i64,
    pub keyinstance_id: i64,
    pub is_coinbase: bool,
}

/// Get UTXOs for an account as serializable UtxoInfo.
pub async fn get_utxo_infos_for_account(
    pool: &SqlitePool,
    account_id: i64,
) -> anyhow::Result<Vec<UtxoInfo>> {
    let rows = get_utxos_for_account(pool, account_id).await?;

    let result: Vec<UtxoInfo> = rows
        .into_iter()
        .map(|row| UtxoInfo {
            tx_hash_hex: crate::core::address::hash_to_hex_str(&row.tx_hash),
            tx_index: row.tx_index,
            value: row.value,
            keyinstance_id: row.keyinstance_id,
            is_coinbase: (row.flags & txo_flags::IS_COINBASE) != 0,
        })
        .collect();

    Ok(result)
}

// ============================================================================
// Transaction / TransactionOutput / TransactionDelta upserts (Milestone 4 Teil 4)
// ============================================================================

/// Transaction flag constants (matches Python TransactionFlag).
pub mod tx_flags {
    /// Transaction is unconfirmed (bit 0).
    pub const IS_UNCONFIRMED: i32 = 1;
    /// Transaction is coinbase (bit 1).
    pub const IS_COINBASE: i32 = 2;
}

/// Upsert a Transaction row (insert or update by tx_hash).
///
/// `tx_hash` is the internal byte order hash (not display/reversed).
/// `block_height` is None for unconfirmed transactions.
/// `tx_data` is the raw transaction bytes (optional — we don't fetch full tx yet).
pub async fn upsert_transaction(
    pool: &SqlitePool,
    tx_hash: &[u8],
    block_height: Option<i64>,
    tx_data: Option<&[u8]>,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();
    let flags = if block_height.is_none() {
        tx_flags::IS_UNCONFIRMED
    } else {
        0
    };

    sqlx::query(
        "INSERT INTO Transactions (tx_hash, tx_data, block_height, flags, date_created, date_updated) \
         VALUES (?, ?, ?, ?, ?, ?) \
         ON CONFLICT(tx_hash) DO UPDATE SET \
            block_height = excluded.block_height, \
            flags = excluded.flags, \
            tx_data = COALESCE(excluded.tx_data, Transactions.tx_data), \
            date_updated = excluded.date_updated",
    )
    .bind(tx_hash)
    .bind(tx_data)
    .bind(block_height)
    .bind(flags)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Upsert a TransactionOutput row (insert or update by (tx_hash, tx_index)).
///
/// `tx_hash` is the internal byte order hash.
/// `keyinstance_id` links to the KeyInstance that owns this output.
/// `value` is in satoshis. `flags` uses txo_flags constants.
pub async fn upsert_transaction_output(
    pool: &SqlitePool,
    tx_hash: &[u8],
    tx_index: i64,
    value: i64,
    keyinstance_id: i64,
    flags: i32,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();

    sqlx::query(
        "INSERT INTO TransactionOutputs (tx_hash, tx_index, value, keyinstance_id, flags, date_created, date_updated) \
         VALUES (?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT(tx_hash, tx_index) DO UPDATE SET \
            value = excluded.value, \
            keyinstance_id = excluded.keyinstance_id, \
            flags = excluded.flags, \
            date_updated = excluded.date_updated",
    )
    .bind(tx_hash)
    .bind(tx_index)
    .bind(value)
    .bind(keyinstance_id)
    .bind(flags)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Upsert a TransactionDelta row (insert or update by (keyinstance_id, tx_hash)).
///
/// `tx_hash` is the internal byte order hash.
/// `value_delta` is the net change in satoshis (positive = received, negative = sent).
pub async fn upsert_transaction_delta(
    pool: &SqlitePool,
    keyinstance_id: i64,
    tx_hash: &[u8],
    value_delta: i64,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();

    sqlx::query(
        "INSERT INTO TransactionDeltas (keyinstance_id, tx_hash, value_delta, date_created, date_updated) \
         VALUES (?, ?, ?, ?, ?) \
         ON CONFLICT(keyinstance_id, tx_hash) DO UPDATE SET \
            value_delta = excluded.value_delta, \
            date_updated = excluded.date_updated",
    )
    .bind(keyinstance_id)
    .bind(tx_hash)
    .bind(value_delta)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Mark a TransactionOutput as spent (set IS_SPENT flag).
///
/// Called during sync when the server's UTXO list no longer includes
/// an output that we previously had as unspent.
pub async fn mark_output_spent(
    pool: &SqlitePool,
    tx_hash: &[u8],
    tx_index: i64,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();

    sqlx::query(
        "UPDATE TransactionOutputs \
         SET flags = flags | ?, date_updated = ? \
         WHERE tx_hash = ? AND tx_index = ?",
    )
    .bind(txo_flags::IS_SPENT)
    .bind(now)
    .bind(tx_hash)
    .bind(tx_index)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get all TransactionOutputs for a set of keyinstance_ids.
///
/// Used during sync to compare local UTXOs against server-reported UTXOs.
pub async fn get_outputs_for_keyinstances(
    pool: &SqlitePool,
    keyinstance_ids: &[i64],
) -> anyhow::Result<Vec<TransactionOutputRow>> {
    if keyinstance_ids.is_empty() {
        return Ok(Vec::new());
    }

    // Build IN clause placeholders
    let placeholders: Vec<String> = (0..keyinstance_ids.len())
        .map(|_| "?".to_string())
        .collect();
    let in_clause = placeholders.join(",");

    let sql = format!(
        "SELECT * FROM TransactionOutputs WHERE keyinstance_id IN ({}) AND (flags & ?) = 0",
        in_clause
    );

    let mut query = sqlx::query_as::<_, TransactionOutputRow>(&sql).bind(txo_flags::IS_SPENT);
    for id in keyinstance_ids {
        query = query.bind(id);
    }

    let rows = query.fetch_all(pool).await?;
    Ok(rows)
}

/// Delete all TransactionOutputs and TransactionDeltas for a set of keyinstance_ids.
///
/// This is used during sync to clear stale data before re-populating from
/// the server's fresh UTXO list. Transactions themselves are not deleted
/// (they may be referenced by other keyinstances).
pub async fn clear_outputs_and_deltas_for_keyinstances(
    pool: &SqlitePool,
    keyinstance_ids: &[i64],
) -> anyhow::Result<()> {
    if keyinstance_ids.is_empty() {
        return Ok(());
    }

    let placeholders: Vec<String> = (0..keyinstance_ids.len())
        .map(|_| "?".to_string())
        .collect();
    let in_clause = placeholders.join(",");

    let del_outputs = format!(
        "DELETE FROM TransactionOutputs WHERE keyinstance_id IN ({})",
        in_clause
    );
    let mut q1 = sqlx::query(&del_outputs);
    for id in keyinstance_ids {
        q1 = q1.bind(id);
    }
    q1.execute(pool).await?;

    let placeholders2: Vec<String> = (0..keyinstance_ids.len())
        .map(|_| "?".to_string())
        .collect();
    let in_clause2 = placeholders2.join(",");

    let del_deltas = format!(
        "DELETE FROM TransactionDeltas WHERE keyinstance_id IN ({})",
        in_clause2
    );
    let mut q2 = sqlx::query(&del_deltas);
    for id in keyinstance_ids {
        q2 = q2.bind(id);
    }
    q2.execute(pool).await?;

    Ok(())
}

// ============================================================================
// TOTP Secret queries (Milestone 5)
// ============================================================================

/// Store a TOTP secret in the TotpSecrets table.
///
/// The secret should be AES-CBC encrypted with the wallet password before storing.
/// This function stores the raw (already-encrypted) bytes.
/// The TotpSecrets table has a single row (id=1 CHECK constraint).
pub async fn store_totp_secret(pool: &SqlitePool, secret_encrypted: &[u8]) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();

    // Upsert: if row exists, update; otherwise insert
    sqlx::query(
        "INSERT INTO TotpSecrets (id, secret_encrypted, nonce, scope, date_created, date_updated) \
         VALUES (1, ?, '', 'login', ?, ?) \
         ON CONFLICT(id) DO UPDATE SET secret_encrypted = excluded.secret_encrypted, date_updated = excluded.date_updated",
    )
    .bind(secret_encrypted)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Load the TOTP secret from the TotpSecrets table.
///
/// Returns None if no TOTP secret is stored (TOTP not enabled).
pub async fn load_totp_secret(pool: &SqlitePool) -> anyhow::Result<Option<Vec<u8>>> {
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT secret_encrypted FROM TotpSecrets WHERE id = 1")
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(secret,)| secret))
}

/// Delete the TOTP secret (disable TOTP).
pub async fn delete_totp_secret(pool: &SqlitePool) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM TotpSecrets WHERE id = 1")
        .execute(pool)
        .await?;
    Ok(())
}

/// Check if TOTP is enabled (a secret exists in the TotpSecrets table).
pub async fn is_totp_enabled(pool: &SqlitePool) -> anyhow::Result<bool> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM TotpSecrets WHERE id = 1")
        .fetch_one(pool)
        .await?;
    Ok(count.0 > 0)
}

// ============================================================================
// Hardware wallet enabled flag (Milestone 5)
// ============================================================================

/// WalletData key for hardware wallet enabled flag.
pub const HW_WALLET_ENABLED_KEY: &str = "hardware_wallet_enabled";

/// Get whether hardware wallet support is enabled in this wallet.
///
/// Default: false (disabled). Uses WalletData key-value store.
pub async fn get_hardware_wallet_enabled(pool: &SqlitePool) -> anyhow::Result<bool> {
    let value = get_wallet_data(pool, HW_WALLET_ENABLED_KEY).await?;
    Ok(value.map(|v| v == "true").unwrap_or(false))
}

/// Set the hardware wallet enabled flag.
pub async fn set_hardware_wallet_enabled(pool: &SqlitePool, enabled: bool) -> anyhow::Result<()> {
    set_wallet_data(
        pool,
        HW_WALLET_ENABLED_KEY,
        if enabled { "true" } else { "false" },
    )
    .await
}

// ============================================================================
// Contact queries (Milestone 6 — contacts, labels, payment requests, config)
// ============================================================================

/// Contact identity system_id constants (matches Python ContactIdentityType).
pub mod contact_identity_system {
    /// On-chain address identity.
    pub const ONCHAIN: i64 = 1;
    /// Paymail handle identity.
    pub const PAYMAIL: i64 = 2;
}

/// A Contacts row from the database.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ContactRow {
    pub contact_id: i64,
    pub label: String,
    pub date_created: i64,
    pub date_updated: i64,
}

/// A ContactIdentities row from the database.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ContactIdentityRow {
    pub identity_id: Vec<u8>,
    pub contact_id: i64,
    pub system_id: i64,
    pub system_data: String,
    pub last_verified: Option<i64>,
    pub date_created: i64,
    pub date_updated: i64,
}

/// Get all contacts ordered by contact_id.
pub async fn get_all_contacts(pool: &SqlitePool) -> anyhow::Result<Vec<ContactRow>> {
    let rows =
        sqlx::query_as::<_, ContactRow>("SELECT * FROM Contacts ORDER BY contact_id")
            .fetch_all(pool)
            .await?;
    Ok(rows)
}

/// Get a single contact by ID.
pub async fn get_contact_by_id(
    pool: &SqlitePool,
    contact_id: i64,
) -> anyhow::Result<Option<ContactRow>> {
    let row =
        sqlx::query_as::<_, ContactRow>("SELECT * FROM Contacts WHERE contact_id = ?")
            .bind(contact_id)
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

/// Insert a new contact and return its contact_id.
pub async fn insert_contact(pool: &SqlitePool, label: &str) -> anyhow::Result<i64> {
    let now = chrono::Utc::now().timestamp();
    let result = sqlx::query(
        "INSERT INTO Contacts (label, date_created, date_updated) VALUES (?, ?, ?)",
    )
    .bind(label)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(result.last_insert_rowid())
}

/// Update a contact's label.
pub async fn update_contact_label(
    pool: &SqlitePool,
    contact_id: i64,
    label: &str,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE Contacts SET label = ?, date_updated = ? WHERE contact_id = ?")
        .bind(label)
        .bind(now)
        .bind(contact_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete a contact by ID (ContactIdentities cascade-deleted via FK).
pub async fn delete_contact(pool: &SqlitePool, contact_id: i64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM Contacts WHERE contact_id = ?")
        .bind(contact_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Get all identities for a contact.
pub async fn get_contact_identities(
    pool: &SqlitePool,
    contact_id: i64,
) -> anyhow::Result<Vec<ContactIdentityRow>> {
    let rows = sqlx::query_as::<_, ContactIdentityRow>(
        "SELECT * FROM ContactIdentities WHERE contact_id = ? ORDER BY date_created",
    )
    .bind(contact_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Insert a new contact identity with a random 16-byte identity_id.
pub async fn insert_contact_identity(
    pool: &SqlitePool,
    contact_id: i64,
    system_id: i64,
    system_data: &str,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();
    // Generate a random 16-byte identity_id
    let identity_id: [u8; 16] = rand::random();
    sqlx::query(
        "INSERT INTO ContactIdentities \
         (identity_id, contact_id, system_id, system_data, last_verified, date_created, date_updated) \
         VALUES (?, ?, ?, ?, NULL, ?, ?)",
    )
    .bind(&identity_id[..])
    .bind(contact_id)
    .bind(system_id)
    .bind(system_data)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Check if a label is already in use by any contact.
pub async fn check_label_in_use(pool: &SqlitePool, label: &str) -> anyhow::Result<bool> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM Contacts WHERE label = ?")
        .bind(label)
        .fetch_one(pool)
        .await?;
    Ok(count.0 > 0)
}

// ============================================================================
// Label queries (description column on KeyInstances and Transactions)
// ============================================================================

/// Set or clear the label (description) on a KeyInstance.
pub async fn set_keyinstance_label(
    pool: &SqlitePool,
    keyinstance_id: i64,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE KeyInstances SET description = ?, date_updated = ? WHERE keyinstance_id = ?")
        .bind(label)
        .bind(now)
        .bind(keyinstance_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Set or clear the label (description) on a Transaction.
pub async fn set_transaction_label(
    pool: &SqlitePool,
    tx_hash: &[u8],
    label: Option<&str>,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE Transactions SET description = ?, date_updated = ? WHERE tx_hash = ?")
        .bind(label)
        .bind(now)
        .bind(tx_hash)
        .execute(pool)
        .await?;
    Ok(())
}

/// Get the label (description) of a KeyInstance.
pub async fn get_keyinstance_label(
    pool: &SqlitePool,
    keyinstance_id: i64,
) -> anyhow::Result<Option<String>> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT description FROM KeyInstances WHERE keyinstance_id = ?")
            .bind(keyinstance_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.and_then(|(v,)| v))
}

/// Get the label (description) of a Transaction.
pub async fn get_transaction_label(
    pool: &SqlitePool,
    tx_hash: &[u8],
) -> anyhow::Result<Option<String>> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT description FROM Transactions WHERE tx_hash = ?")
            .bind(tx_hash)
            .fetch_optional(pool)
            .await?;
    Ok(row.and_then(|(v,)| v))
}

// ============================================================================
// Payment request queries (PaymentRequests table from migration 0022)
// ============================================================================

/// A PaymentRequests row from the database.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct PaymentRequestRow {
    pub paymentrequest_id: i64,
    pub keyinstance_id: i64,
    pub state: i32,
    pub description: Option<String>,
    pub expiration: Option<i64>,
    pub value: Option<i64>,
    pub date_created: i64,
    pub date_updated: i64,
}

/// Insert a new payment request and return its paymentrequest_id.
///
/// `state` defaults to 0 (pending). `expiration` is None (no expiry).
pub async fn insert_payment_request(
    pool: &SqlitePool,
    keyinstance_id: i64,
    value: Option<i64>,
    description: Option<&str>,
) -> anyhow::Result<i64> {
    let now = chrono::Utc::now().timestamp();
    let result = sqlx::query(
        "INSERT INTO PaymentRequests \
         (keyinstance_id, state, description, expiration, value, date_created, date_updated) \
         VALUES (?, 0, ?, NULL, ?, ?, ?)",
    )
    .bind(keyinstance_id)
    .bind(description)
    .bind(value)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(result.last_insert_rowid())
}

/// Get all payment requests ordered by paymentrequest_id.
pub async fn get_payment_requests(pool: &SqlitePool) -> anyhow::Result<Vec<PaymentRequestRow>> {
    let rows = sqlx::query_as::<_, PaymentRequestRow>(
        "SELECT * FROM PaymentRequests ORDER BY paymentrequest_id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// ============================================================================
// Config queries (WalletData key-value store aliases)
// ============================================================================

/// Read all WalletData rows and return them as a JSON object.
pub async fn get_all_config(pool: &SqlitePool) -> anyhow::Result<serde_json::Value> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT key, value FROM WalletData ORDER BY key")
            .fetch_all(pool)
            .await?;
    let mut map = serde_json::Map::new();
    for (key, value) in rows {
        map.insert(key, serde_json::Value::String(value));
    }
    Ok(serde_json::Value::Object(map))
}

/// Get a config value by key (alias for get_wallet_data).
pub async fn get_config_value(pool: &SqlitePool, key: &str) -> anyhow::Result<Option<String>> {
    get_wallet_data(pool, key).await
}

/// Set a config value by key (alias for set_wallet_data).
pub async fn set_config_value(pool: &SqlitePool, key: &str, value: &str) -> anyhow::Result<()> {
    set_wallet_data(pool, key, value).await
}

// ============================================================================
// Account queries (for get_accounts command)
// ============================================================================

/// Get all accounts ordered by account_id.
pub async fn get_all_accounts(pool: &SqlitePool) -> anyhow::Result<Vec<AccountRow>> {
    let rows =
        sqlx::query_as::<_, AccountRow>("SELECT * FROM Accounts ORDER BY account_id")
            .fetch_all(pool)
            .await?;
    Ok(rows)
}

/// Get a single account by ID.
pub async fn get_account_by_id(
    pool: &SqlitePool,
    account_id: i64,
) -> anyhow::Result<Option<AccountRow>> {
    let row =
        sqlx::query_as::<_, AccountRow>("SELECT * FROM Accounts WHERE account_id = ?")
            .bind(account_id)
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

// ============================================================================
// Multisig configuration (Task 5 — Multisig account type)
// ============================================================================

/// A MultisigConfigs row from the database.
///
/// `public_keys` is deserialised from the stored JSON array of hex-encoded
/// public keys into a `Vec<String>` for convenience.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct MultisigConfigRow {
    pub account_id: i64,
    pub threshold: i64,
    /// Hex-encoded public keys (deserialised from the JSON array in DB).
    pub public_keys: Vec<String>,
    pub date_created: i64,
    pub date_updated: i64,
}

/// Insert a multisig configuration row for an account.
///
/// `public_keys_json` is a JSON array of hex-encoded public keys, e.g.
/// `["02ab...", "03cd..."]`. The caller is responsible for serialising the
/// array; this function stores it verbatim.
pub async fn insert_multisig_config(
    pool: &SqlitePool,
    account_id: i64,
    threshold: i64,
    public_keys_json: &str,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO MultisigConfigs (account_id, threshold, public_keys, date_created, date_updated) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(account_id)
    .bind(threshold)
    .bind(public_keys_json)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Get the multisig configuration for an account.
///
/// Returns `None` if the account has no multisig config (i.e. is not a
/// multisig account). The `public_keys` JSON array in the DB is decoded
/// into a `Vec<String>` of hex strings.
pub async fn get_multisig_config(
    pool: &SqlitePool,
    account_id: i64,
) -> anyhow::Result<Option<MultisigConfigRow>> {
    // Fetch the raw row with public_keys as TEXT, then decode JSON.
    let row: Option<(i64, i64, String, i64, i64)> = sqlx::query_as(
        "SELECT account_id, threshold, public_keys, date_created, date_updated \
         FROM MultisigConfigs WHERE account_id = ?",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some((account_id, threshold, public_keys_json, date_created, date_updated)) => {
            let public_keys: Vec<String> = serde_json::from_str(&public_keys_json)?;
            Ok(Some(MultisigConfigRow {
                account_id,
                threshold,
                public_keys,
                date_created,
                date_updated,
            }))
        }
        None => Ok(None),
    }
}

// ============================================================================
// TOTP Recovery codes (Milestone 8-C)
// ============================================================================

/// WalletData key for TOTP recovery codes (stored as JSON array of SHA256 hashes).
pub const TOTP_RECOVERY_CODES_KEY: &str = "totp_recovery_codes";

/// Store hashed recovery codes in WalletData.
///
/// Each code should already be SHA256-hashed by the caller. The hashes are
/// stored as a JSON array string under the `totp_recovery_codes` key.
pub async fn store_recovery_codes(pool: &SqlitePool, hashed_codes: &[String]) -> anyhow::Result<()> {
    let json = serde_json::to_string(hashed_codes)?;
    set_wallet_data(pool, TOTP_RECOVERY_CODES_KEY, &json).await
}

/// Load the hashed recovery codes from WalletData.
///
/// Returns an empty vector if no recovery codes are stored.
pub async fn load_recovery_codes(pool: &SqlitePool) -> anyhow::Result<Vec<String>> {
    let value = get_wallet_data(pool, TOTP_RECOVERY_CODES_KEY).await?;
    match value {
        Some(json) => {
            let codes: Vec<String> = serde_json::from_str(&json)?;
            Ok(codes)
        }
        None => Ok(Vec::new()),
    }
}

/// Delete all recovery codes from WalletData.
pub async fn delete_recovery_codes(pool: &SqlitePool) -> anyhow::Result<()> {
    set_wallet_data(pool, TOTP_RECOVERY_CODES_KEY, "[]").await
}

/// Consume a recovery code: check if the given plaintext code matches any
/// stored hash (SHA256 compare). If matched, remove that hash from the list
/// and return true. If none match, return false.
pub async fn consume_recovery_code(pool: &SqlitePool, code_hash: &str) -> anyhow::Result<bool> {
    let mut codes = load_recovery_codes(pool).await?;
    if codes.is_empty() {
        return Ok(false);
    }

    let position = codes.iter().position(|h| h == code_hash);
    match position {
        Some(idx) => {
            codes.remove(idx);
            store_recovery_codes(pool, &codes).await?;
            Ok(true)
        }
        None => Ok(false),
    }
}

// ============================================================================
// Extra repository functions for ported features
// ============================================================================

/// Get a transaction by txid from the wallet DB.
pub async fn get_transaction_by_txid(
    pool: &SqlitePool,
    txid: &str,
) -> anyhow::Result<Option<TransactionRow>> {
    let row = sqlx::query_as::<_, TransactionRow>(
        "SELECT tx_hash_hex as txid, status, raw_tx, account_id, fee \
         FROM AccountTransactions WHERE tx_hash_hex = ?",
    )
    .bind(txid)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Transaction row for get_transaction_by_txid.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct TransactionRow {
    pub txid: String,
    pub status: String,
    pub raw_tx: Option<String>,
    pub account_id: Option<i64>,
    pub fee: Option<i64>,
}

/// Get transaction inputs by txid.
pub async fn get_transaction_inputs(
    pool: &SqlitePool,
    txid: &str,
) -> anyhow::Result<Vec<TransactionInputRow>> {
    let rows = sqlx::query_as::<_, TransactionInputRow>(
        "SELECT prev_tx_hash, prev_vout, script_sig, sequence \
         FROM TransactionInputs WHERE tx_hash_hex = ? ORDER BY input_index",
    )
    .bind(txid)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct TransactionInputRow {
    pub prev_tx_hash: String,
    pub prev_vout: i64,
    pub script_sig: String,
    pub sequence: u32,
}

/// Get transaction outputs by txid.
pub async fn get_transaction_outputs(
    pool: &SqlitePool,
    txid: &str,
) -> anyhow::Result<Vec<TxOutputDetailRow>> {
    let rows = sqlx::query_as::<_, TxOutputDetailRow>(
        "SELECT value, script_pubkey \
         FROM TransactionOutputs WHERE tx_hash_hex = ? ORDER BY output_index",
    )
    .bind(txid)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Transaction output row for get_transaction_outputs (value + script_pubkey only).
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct TxOutputDetailRow {
    pub value: i64,
    pub script_pubkey: String,
}

/// Get a transaction label by txid.
pub async fn get_tx_label(
    pool: &SqlitePool,
    txid: &str,
) -> anyhow::Result<Option<String>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT label FROM TransactionLabels WHERE tx_hash_hex = ?")
            .bind(txid)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(label,)| label))
}

/// Count remaining (unused) TOTP recovery codes.
pub async fn count_remaining_recovery_codes(pool: &SqlitePool) -> anyhow::Result<i64> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM TotpRecoveryCodes WHERE used = 0",
    )
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::connection;
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

    async fn setup_test_db(test_name: &str) -> (SqlitePool, std::path::PathBuf) {
        let temp_dir = unique_test_dir(test_name);
        let db_path = temp_dir.join("test_repo.sqlite");
        // Remove any leftover database file
        if db_path.exists() {
            std::fs::remove_file(&db_path).unwrap();
        }
        connection::create_wallet_db(db_path.to_str().unwrap())
            .await
            .unwrap();
        let pool = connection::open_wallet_db(db_path.to_str().unwrap())
            .await
            .unwrap();
        (pool, temp_dir)
    }

    #[tokio::test]
    async fn test_insert_and_read_master_key() {
        let (pool, _dir) = setup_test_db("mk_rw").await;

        let derivation_data = br#"{"xpub":"test_xpub","xprv":"encrypted_xprv"}"#;
        let id = insert_master_key(&pool, None, derivation_type::BIP32, derivation_data)
            .await
            .unwrap();
        assert_eq!(id, 1);

        let mk = get_first_master_key(&pool).await.unwrap().unwrap();
        assert_eq!(mk.masterkey_id, 1);
        assert_eq!(mk.derivation_type, derivation_type::BIP32);
        assert!(mk.parent_masterkey_id.is_none());

        pool.close().await;
    }

    #[tokio::test]
    async fn test_insert_and_read_account() {
        let (pool, _dir) = setup_test_db("acct_rw").await;

        let mk_id = insert_master_key(&pool, None, derivation_type::BIP32, b"test")
            .await
            .unwrap();
        let acct_id = insert_account(&pool, Some(mk_id), script_type::P2PKH, "Standard account")
            .await
            .unwrap();
        assert_eq!(acct_id, 1);

        let acct = get_first_account(&pool).await.unwrap().unwrap();
        assert_eq!(acct.account_id, 1);
        assert_eq!(acct.account_name, "Standard account");
        assert_eq!(acct.default_script_type, script_type::P2PKH);
        assert_eq!(acct.default_masterkey_id, Some(1));

        pool.close().await;
    }

    #[tokio::test]
    async fn test_wallet_data_get_set() {
        let (pool, _dir) = setup_test_db("wd_gs").await;

        // migration key should already be set by create_wallet_db
        let migration = get_wallet_data(&pool, "migration").await.unwrap();
        assert_eq!(migration, Some("30".to_string()));

        // Set a new key
        set_wallet_data(&pool, "password-token", "encrypted_token")
            .await
            .unwrap();
        let val = get_wallet_data(&pool, "password-token").await.unwrap();
        assert_eq!(val, Some("encrypted_token".to_string()));

        // Update existing key
        set_wallet_data(&pool, "password-token", "new_token")
            .await
            .unwrap();
        let val = get_wallet_data(&pool, "password-token").await.unwrap();
        assert_eq!(val, Some("new_token".to_string()));

        pool.close().await;
    }

    #[tokio::test]
    async fn test_get_first_master_key_empty() {
        let (pool, _dir) = setup_test_db("mk_empty").await;
        let mk = get_first_master_key(&pool).await.unwrap();
        assert!(mk.is_none());

        pool.close().await;
    }

    // ========================================================================
    // Milestone 4 Teil 4 — upsert tests
    // ========================================================================

    #[tokio::test]
    async fn test_upsert_transaction_confirmed() {
        let (pool, _dir) = setup_test_db("upsert_tx_conf").await;

        let tx_hash = vec![0xaa; 32];
        upsert_transaction(&pool, &tx_hash, Some(800000), None)
            .await
            .unwrap();

        // Read back
        let row: Option<(Vec<u8>, Option<i64>, i32)> = sqlx::query_as(
            "SELECT tx_hash, block_height, flags FROM Transactions WHERE tx_hash = ?",
        )
        .bind(&tx_hash)
        .fetch_optional(&pool)
        .await
        .unwrap();

        assert!(row.is_some());
        let (hash, height, flags) = row.unwrap();
        assert_eq!(hash, tx_hash);
        assert_eq!(height, Some(800000));
        assert_eq!(flags, 0); // confirmed = no flags

        pool.close().await;
    }

    #[tokio::test]
    async fn test_upsert_transaction_unconfirmed() {
        let (pool, _dir) = setup_test_db("upsert_tx_unconf").await;

        let tx_hash = vec![0xbb; 32];
        upsert_transaction(&pool, &tx_hash, None, None)
            .await
            .unwrap();

        let row: Option<(Option<i64>, i32)> =
            sqlx::query_as("SELECT block_height, flags FROM Transactions WHERE tx_hash = ?")
                .bind(&tx_hash)
                .fetch_optional(&pool)
                .await
                .unwrap();

        let (height, flags) = row.unwrap();
        assert_eq!(height, None);
        assert_eq!(flags, tx_flags::IS_UNCONFIRMED);

        pool.close().await;
    }

    #[tokio::test]
    async fn test_upsert_transaction_updates() {
        let (pool, _dir) = setup_test_db("upsert_tx_update").await;

        let tx_hash = vec![0xcc; 32];
        // Insert as unconfirmed
        upsert_transaction(&pool, &tx_hash, None, None)
            .await
            .unwrap();
        // Update to confirmed
        upsert_transaction(&pool, &tx_hash, Some(800001), None)
            .await
            .unwrap();

        let row: Option<(Option<i64>, i32)> =
            sqlx::query_as("SELECT block_height, flags FROM Transactions WHERE tx_hash = ?")
                .bind(&tx_hash)
                .fetch_optional(&pool)
                .await
                .unwrap();

        let (height, flags) = row.unwrap();
        assert_eq!(height, Some(800001));
        assert_eq!(flags, 0); // confirmed now

        pool.close().await;
    }

    #[tokio::test]
    async fn test_upsert_transaction_output() {
        let (pool, _dir) = setup_test_db("upsert_txo").await;

        // Need a masterkey + account + keyinstance for FK
        let mk_id = insert_master_key(&pool, None, derivation_type::BIP32, b"test")
            .await
            .unwrap();
        let acct_id = insert_account(&pool, Some(mk_id), script_type::P2PKH, "Test")
            .await
            .unwrap();
        let ki_id = insert_keyinstance(
            &pool,
            acct_id,
            Some(mk_id),
            derivation_type::BIP32,
            br#"{"subpath":[0,0]}"#,
            script_type::P2PKH,
            0,
            None,
        )
        .await
        .unwrap();

        let tx_hash = vec![0xdd; 32];
        upsert_transaction(&pool, &tx_hash, Some(800000), None)
            .await
            .unwrap();
        upsert_transaction_output(&pool, &tx_hash, 0, 50000, ki_id, 0)
            .await
            .unwrap();

        // Read back
        let row: Option<(i64, i64, i32)> = sqlx::query_as(
            "SELECT value, keyinstance_id, flags FROM TransactionOutputs WHERE tx_hash = ? AND tx_index = ?",
        )
        .bind(&tx_hash)
        .bind(0i64)
        .fetch_optional(&pool)
        .await
        .unwrap();

        let (value, ki, flags) = row.unwrap();
        assert_eq!(value, 50000);
        assert_eq!(ki, ki_id);
        assert_eq!(flags, 0);

        pool.close().await;
    }

    #[tokio::test]
    async fn test_upsert_transaction_delta() {
        let (pool, _dir) = setup_test_db("upsert_txd").await;

        let mk_id = insert_master_key(&pool, None, derivation_type::BIP32, b"test")
            .await
            .unwrap();
        let acct_id = insert_account(&pool, Some(mk_id), script_type::P2PKH, "Test")
            .await
            .unwrap();
        let ki_id = insert_keyinstance(
            &pool,
            acct_id,
            Some(mk_id),
            derivation_type::BIP32,
            br#"{"subpath":[0,0]}"#,
            script_type::P2PKH,
            0,
            None,
        )
        .await
        .unwrap();

        let tx_hash = vec![0xee; 32];
        upsert_transaction(&pool, &tx_hash, None, None)
            .await
            .unwrap();
        upsert_transaction_delta(&pool, ki_id, &tx_hash, 25000)
            .await
            .unwrap();

        // Update delta
        upsert_transaction_delta(&pool, ki_id, &tx_hash, 30000)
            .await
            .unwrap();

        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT value_delta FROM TransactionDeltas WHERE keyinstance_id = ? AND tx_hash = ?",
        )
        .bind(ki_id)
        .bind(&tx_hash)
        .fetch_optional(&pool)
        .await
        .unwrap();

        let (delta,) = row.unwrap();
        assert_eq!(delta, 30000); // Updated value

        pool.close().await;
    }

    #[tokio::test]
    async fn test_mark_output_spent() {
        let (pool, _dir) = setup_test_db("mark_spent").await;

        let mk_id = insert_master_key(&pool, None, derivation_type::BIP32, b"test")
            .await
            .unwrap();
        let acct_id = insert_account(&pool, Some(mk_id), script_type::P2PKH, "Test")
            .await
            .unwrap();
        let ki_id = insert_keyinstance(
            &pool,
            acct_id,
            Some(mk_id),
            derivation_type::BIP32,
            br#"{"subpath":[0,0]}"#,
            script_type::P2PKH,
            0,
            None,
        )
        .await
        .unwrap();

        let tx_hash = vec![0xff; 32];
        upsert_transaction(&pool, &tx_hash, Some(800000), None)
            .await
            .unwrap();
        upsert_transaction_output(&pool, &tx_hash, 0, 50000, ki_id, 0)
            .await
            .unwrap();

        // Mark as spent
        mark_output_spent(&pool, &tx_hash, 0).await.unwrap();

        let row: Option<(i32,)> = sqlx::query_as(
            "SELECT flags FROM TransactionOutputs WHERE tx_hash = ? AND tx_index = ?",
        )
        .bind(&tx_hash)
        .bind(0i64)
        .fetch_optional(&pool)
        .await
        .unwrap();

        let (flags,) = row.unwrap();
        assert_eq!(flags, txo_flags::IS_SPENT);

        pool.close().await;
    }

    #[tokio::test]
    async fn test_clear_outputs_and_deltas() {
        let (pool, _dir) = setup_test_db("clear_outputs").await;

        let mk_id = insert_master_key(&pool, None, derivation_type::BIP32, b"test")
            .await
            .unwrap();
        let acct_id = insert_account(&pool, Some(mk_id), script_type::P2PKH, "Test")
            .await
            .unwrap();
        let ki_id = insert_keyinstance(
            &pool,
            acct_id,
            Some(mk_id),
            derivation_type::BIP32,
            br#"{"subpath":[0,0]}"#,
            script_type::P2PKH,
            0,
            None,
        )
        .await
        .unwrap();

        let tx_hash = vec![0x11; 32];
        upsert_transaction(&pool, &tx_hash, Some(800000), None)
            .await
            .unwrap();
        upsert_transaction_output(&pool, &tx_hash, 0, 50000, ki_id, 0)
            .await
            .unwrap();
        upsert_transaction_delta(&pool, ki_id, &tx_hash, 50000)
            .await
            .unwrap();

        // Clear
        clear_outputs_and_deltas_for_keyinstances(&pool, &[ki_id])
            .await
            .unwrap();

        // Verify outputs deleted
        let out_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM TransactionOutputs WHERE keyinstance_id = ?")
                .bind(ki_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(out_count, 0);

        // Verify deltas deleted
        let delta_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM TransactionDeltas WHERE keyinstance_id = ?")
                .bind(ki_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(delta_count, 0);

        // Transaction should still exist (not deleted)
        let tx_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM Transactions WHERE tx_hash = ?")
                .bind(&tx_hash)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(tx_count, 1);

        pool.close().await;
    }

    // ========================================================================
    // Milestone 5 — TOTP Secret queries
    // ========================================================================

    #[tokio::test]
    async fn test_totp_secret_store_and_load() {
        let (pool, _dir) = setup_test_db("totp_secret").await;

        let secret = b"my_totp_secret_20_bytes";
        store_totp_secret(&pool, secret).await.unwrap();

        let loaded = load_totp_secret(&pool).await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap(), secret.to_vec());

        pool.close().await;
    }

    #[tokio::test]
    async fn test_totp_secret_none_when_empty() {
        let (pool, _dir) = setup_test_db("totp_empty").await;

        let loaded = load_totp_secret(&pool).await.unwrap();
        assert!(loaded.is_none());

        pool.close().await;
    }

    #[tokio::test]
    async fn test_totp_secret_delete() {
        let (pool, _dir) = setup_test_db("totp_delete").await;

        store_totp_secret(&pool, b"secret_to_delete").await.unwrap();
        assert!(load_totp_secret(&pool).await.unwrap().is_some());

        delete_totp_secret(&pool).await.unwrap();
        assert!(load_totp_secret(&pool).await.unwrap().is_none());

        pool.close().await;
    }

    #[tokio::test]
    async fn test_hardware_wallet_enabled_default_false() {
        let (pool, _dir) = setup_test_db("hw_default").await;

        let enabled = get_hardware_wallet_enabled(&pool).await.unwrap();
        assert!(!enabled);

        pool.close().await;
    }

    #[tokio::test]
    async fn test_hardware_wallet_enabled_set_true() {
        let (pool, _dir) = setup_test_db("hw_true").await;

        set_hardware_wallet_enabled(&pool, true).await.unwrap();
        let enabled = get_hardware_wallet_enabled(&pool).await.unwrap();
        assert!(enabled);

        pool.close().await;
    }

    #[tokio::test]
    async fn test_hardware_wallet_enabled_toggle() {
        let (pool, _dir) = setup_test_db("hw_toggle").await;

        set_hardware_wallet_enabled(&pool, true).await.unwrap();
        assert!(get_hardware_wallet_enabled(&pool).await.unwrap());

        set_hardware_wallet_enabled(&pool, false).await.unwrap();
        assert!(!get_hardware_wallet_enabled(&pool).await.unwrap());

        pool.close().await;
    }

    // ========================================================================
    // Milestone 6 — Contacts, Labels, Payment Requests, Config tests
    // ========================================================================

    #[tokio::test]
    async fn test_contact_insert_get_update_delete() {
        let (pool, _dir) = setup_test_db("contact_crud").await;

        // Insert
        let id1 = insert_contact(&pool, "Alice").await.unwrap();
        let id2 = insert_contact(&pool, "Bob").await.unwrap();
        assert!(id1 >= 1);
        assert!(id2 > id1);

        // Get all
        let contacts = get_all_contacts(&pool).await.unwrap();
        assert_eq!(contacts.len(), 2);
        assert_eq!(contacts[0].label, "Alice");

        // Get by id
        let alice = get_contact_by_id(&pool, id1).await.unwrap().unwrap();
        assert_eq!(alice.label, "Alice");

        // Update label
        update_contact_label(&pool, id1, "Alice Smith").await.unwrap();
        let alice = get_contact_by_id(&pool, id1).await.unwrap().unwrap();
        assert_eq!(alice.label, "Alice Smith");

        // Delete
        delete_contact(&pool, id2).await.unwrap();
        let contacts = get_all_contacts(&pool).await.unwrap();
        assert_eq!(contacts.len(), 1);

        pool.close().await;
    }

    #[tokio::test]
    async fn test_check_label_in_use() {
        let (pool, _dir) = setup_test_db("contact_label_check").await;

        assert!(!check_label_in_use(&pool, "Charlie").await.unwrap());

        insert_contact(&pool, "Charlie").await.unwrap();
        assert!(check_label_in_use(&pool, "Charlie").await.unwrap());
        assert!(!check_label_in_use(&pool, "Dave").await.unwrap());

        pool.close().await;
    }

    #[tokio::test]
    async fn test_contact_identities() {
        let (pool, _dir) = setup_test_db("contact_identities").await;

        let contact_id = insert_contact(&pool, "Alice").await.unwrap();

        // Insert on-chain identity
        insert_contact_identity(
            &pool,
            contact_id,
            contact_identity_system::ONCHAIN,
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        )
        .await
        .unwrap();

        // Insert paymail identity
        insert_contact_identity(
            &pool,
            contact_id,
            contact_identity_system::PAYMAIL,
            "alice@example.com",
        )
        .await
        .unwrap();

        // Get identities
        let identities = get_contact_identities(&pool, contact_id).await.unwrap();
        assert_eq!(identities.len(), 2);
        assert_eq!(identities[0].system_id, contact_identity_system::ONCHAIN);
        assert_eq!(identities[0].system_data, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert_eq!(identities[0].identity_id.len(), 16);
        assert!(identities[0].last_verified.is_none());

        assert_eq!(identities[1].system_id, contact_identity_system::PAYMAIL);
        assert_eq!(identities[1].system_data, "alice@example.com");

        // Deleting contact should cascade-delete identities
        delete_contact(&pool, contact_id).await.unwrap();
        let identities = get_contact_identities(&pool, contact_id).await.unwrap();
        assert_eq!(identities.len(), 0);

        pool.close().await;
    }

    #[tokio::test]
    async fn test_keyinstance_label_set_get() {
        let (pool, _dir) = setup_test_db("ki_label").await;

        // Setup: create masterkey, account, keyinstance
        let mk_id = insert_master_key(&pool, None, derivation_type::BIP32, b"test")
            .await
            .unwrap();
        let acct_id = insert_account(&pool, Some(mk_id), script_type::P2PKH, "Test")
            .await
            .unwrap();
        let ki_id = insert_keyinstance(
            &pool,
            acct_id,
            Some(mk_id),
            derivation_type::BIP32,
            br#"{"subpath":[0,0]}"#,
            script_type::P2PKH,
            0,
            None,
        )
        .await
        .unwrap();

        // Initially no label
        let label = get_keyinstance_label(&pool, ki_id).await.unwrap();
        assert!(label.is_none());

        // Set label
        set_keyinstance_label(&pool, ki_id, Some("My Address")).await.unwrap();
        let label = get_keyinstance_label(&pool, ki_id).await.unwrap();
        assert_eq!(label.as_deref(), Some("My Address"));

        // Clear label
        set_keyinstance_label(&pool, ki_id, None).await.unwrap();
        let label = get_keyinstance_label(&pool, ki_id).await.unwrap();
        assert!(label.is_none());

        pool.close().await;
    }

    #[tokio::test]
    async fn test_transaction_label_set_get() {
        let (pool, _dir) = setup_test_db("tx_label").await;

        let tx_hash = vec![0x42; 32];
        upsert_transaction(&pool, &tx_hash, Some(800000), None)
            .await
            .unwrap();

        // Initially no label
        let label = get_transaction_label(&pool, &tx_hash).await.unwrap();
        assert!(label.is_none());

        // Set label
        set_transaction_label(&pool, &tx_hash, Some("Payment to Alice")).await.unwrap();
        let label = get_transaction_label(&pool, &tx_hash).await.unwrap();
        assert_eq!(label.as_deref(), Some("Payment to Alice"));

        // Clear label
        set_transaction_label(&pool, &tx_hash, None).await.unwrap();
        let label = get_transaction_label(&pool, &tx_hash).await.unwrap();
        assert!(label.is_none());

        pool.close().await;
    }

    #[tokio::test]
    async fn test_payment_request_insert_list() {
        let (pool, _dir) = setup_test_db("payreq").await;

        // Setup: create masterkey, account, keyinstance
        let mk_id = insert_master_key(&pool, None, derivation_type::BIP32, b"test")
            .await
            .unwrap();
        let acct_id = insert_account(&pool, Some(mk_id), script_type::P2PKH, "Test")
            .await
            .unwrap();
        let ki_id = insert_keyinstance(
            &pool,
            acct_id,
            Some(mk_id),
            derivation_type::BIP32,
            br#"{"subpath":[0,0]}"#,
            script_type::P2PKH,
            0,
            None,
        )
        .await
        .unwrap();

        // Insert payment request with value and description
        let pr_id1 = insert_payment_request(&pool, ki_id, Some(50000), Some("Invoice #1"))
            .await
            .unwrap();
        assert!(pr_id1 >= 1);

        // Insert payment request with no value, no description
        let pr_id2 = insert_payment_request(&pool, ki_id, None, None)
            .await
            .unwrap();
        assert!(pr_id2 > pr_id1);

        // List
        let requests = get_payment_requests(&pool).await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].keyinstance_id, ki_id);
        assert_eq!(requests[0].state, 0);
        assert_eq!(requests[0].value, Some(50000));
        assert_eq!(requests[0].description.as_deref(), Some("Invoice #1"));
        assert!(requests[0].expiration.is_none());

        assert_eq!(requests[1].value, None);
        assert!(requests[1].description.is_none());

        pool.close().await;
    }

    #[tokio::test]
    async fn test_config_set_get_all() {
        let (pool, _dir) = setup_test_db("config").await;

        // Set config values
        set_config_value(&pool, "theme", "dark").await.unwrap();
        set_config_value(&pool, "language", "en").await.unwrap();

        // Get individual
        let theme = get_config_value(&pool, "theme").await.unwrap();
        assert_eq!(theme.as_deref(), Some("dark"));
        let lang = get_config_value(&pool, "language").await.unwrap();
        assert_eq!(lang.as_deref(), Some("en"));
        let missing = get_config_value(&pool, "nonexistent").await.unwrap();
        assert!(missing.is_none());

        // Get all config
        let all = get_all_config(&pool).await.unwrap();
        let obj = all.as_object().unwrap();
        assert!(obj.contains_key("theme"));
        assert_eq!(obj["theme"], "dark");
        assert!(obj.contains_key("language"));
        assert_eq!(obj["language"], "en");
        // migration key should also be present
        assert!(obj.contains_key("migration"));

        // Update existing
        set_config_value(&pool, "theme", "light").await.unwrap();
        let theme = get_config_value(&pool, "theme").await.unwrap();
        assert_eq!(theme.as_deref(), Some("light"));

        pool.close().await;
    }

    #[tokio::test]
    async fn test_get_all_accounts_and_by_id() {
        let (pool, _dir) = setup_test_db("accounts_query").await;

        // No accounts initially
        let accounts = get_all_accounts(&pool).await.unwrap();
        assert!(accounts.is_empty());
        assert!(get_account_by_id(&pool, 1).await.unwrap().is_none());

        // Create accounts
        let mk_id = insert_master_key(&pool, None, derivation_type::BIP32, b"test")
            .await
            .unwrap();
        let acct1 = insert_account(&pool, Some(mk_id), script_type::P2PKH, "Account 1")
            .await
            .unwrap();
        let acct2 = insert_account(&pool, Some(mk_id), script_type::P2PKH, "Account 2")
            .await
            .unwrap();

        // Get all
        let accounts = get_all_accounts(&pool).await.unwrap();
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].account_name, "Account 1");
        assert_eq!(accounts[1].account_name, "Account 2");

        // Get by id
        let acct = get_account_by_id(&pool, acct2).await.unwrap().unwrap();
        assert_eq!(acct.account_name, "Account 2");
        assert_eq!(acct.account_id, acct2);

        // Non-existent id
        assert!(get_account_by_id(&pool, 999).await.unwrap().is_none());

        pool.close().await;
    }
}
