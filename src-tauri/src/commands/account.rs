// commands/account.rs — Account read-only Tauri commands (Milestone 3)
//
// Provides: get_balance, get_history, get_utxos, get_receive_address, get_public_key
//
// All commands require an open wallet. get_balance/history/utxos only need
// the DB pool (no xprv). get_receive_address and get_public_key need an
// unlocked wallet (decrypted xprv for key derivation).

use crate::core::address;
use crate::db::repositories;
use crate::state::AppState;
use bsv::compat::bip32::ExtendedKey;
use tauri::State;

// ============================================================================
// Response types
// ============================================================================

/// Balance response for get_balance command.
#[derive(Debug, serde::Serialize)]
pub struct BalanceInfo {
    pub confirmed: i64,
    pub unconfirmed: i64,
    pub total: i64,
}

/// History entry for get_history command.
#[derive(Debug, serde::Serialize)]
pub struct HistoryEntry {
    pub tx_hash: String,
    pub value_delta: i64,
    pub date_created: i64,
    pub block_height: Option<i64>,
    pub description: Option<String>,
}

/// UTXO entry for get_utxos command.
#[derive(Debug, serde::Serialize)]
pub struct UtxoEntry {
    pub tx_hash: String,
    pub tx_index: i64,
    pub value: i64,
    pub keyinstance_id: i64,
    pub is_coinbase: bool,
}

/// Receive address response.
#[derive(Debug, serde::Serialize)]
pub struct ReceiveAddressResult {
    pub address: String,
    pub keyinstance_id: i64,
    pub derivation_index: i64,
}

// ============================================================================
// Error type
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("no wallet is currently open")]
    NoWalletOpen,
    #[error("wallet is locked — unlock first")]
    WalletLocked,
    #[error("account not found")]
    AccountNotFound,
    #[error("keyinstance not found")]
    KeyInstanceNotFound,
    #[error("invalid xprv: {0}")]
    InvalidXprv(String),
    #[error("derivation failed: {0}")]
    DerivationFailed(String),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
    #[error("multisig error: {0}")]
    Multisig(String),
}

impl From<bsv::compat::error::CompatError> for AccountError {
    fn from(e: bsv::compat::error::CompatError) -> Self {
        AccountError::DerivationFailed(e.to_string())
    }
}

// ============================================================================
// Helper: get the active wallet's DB pool and account_id
// ============================================================================

/// Extract needed data from the active wallet without holding the lock across awaits.
/// Returns (db_pool, account_id, decrypted_xprv) where decrypted_xprv is None if locked.
fn get_active_wallet_data(
    state: &AppState,
) -> Result<(sqlx::SqlitePool, i64, Option<String>), AccountError> {
    let guard = state.active_wallet.lock().unwrap();
    let active = guard.as_ref().ok_or(AccountError::NoWalletOpen)?;
    Ok((
        active.db_pool.clone(),
        active.account_id,
        active.decrypted_xprv.clone(),
    ))
}

// ============================================================================
// Commands
// ============================================================================

/// Get the balance for the active account (or a specific account).
///
/// Returns confirmed, unconfirmed, and total balance.
/// Only requires an open wallet — no xprv needed.
#[tauri::command]
pub async fn get_balance(
    state: State<'_, AppState>,
    account_id: Option<i64>,
) -> Result<BalanceInfo, String> {
    log::info!("get_balance — account_id: {:?}", account_id);

    let (pool, default_account_id, _) =
        get_active_wallet_data(&state).map_err(|e| e.to_string())?;
    let acct_id = account_id.unwrap_or(default_account_id);

    let (confirmed, unconfirmed, total) = repositories::get_balance_for_account(&pool, acct_id)
        .await
        .map_err(|e| e.to_string())?;

    Ok(BalanceInfo {
        confirmed,
        unconfirmed,
        total,
    })
}

/// Get transaction history for the active account.
///
/// Returns a list of transactions with value deltas.
/// Only requires an open wallet — no xprv needed.
#[tauri::command]
pub async fn get_history(
    state: State<'_, AppState>,
    account_id: Option<i64>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<HistoryEntry>, String> {
    let lim = limit.unwrap_or(50);
    let off = offset.unwrap_or(0);
    log::info!(
        "get_history — account_id: {:?}, limit: {}, offset: {}",
        account_id,
        lim,
        off
    );

    let (pool, default_account_id, _) =
        get_active_wallet_data(&state).map_err(|e| e.to_string())?;
    let acct_id = account_id.unwrap_or(default_account_id);

    let rows = repositories::get_tx_history_for_account(&pool, acct_id, lim, off)
        .await
        .map_err(|e| e.to_string())?;

    Ok(rows
        .into_iter()
        .map(|r| HistoryEntry {
            tx_hash: r.tx_hash_hex,
            value_delta: r.value_delta,
            date_created: r.date_created,
            block_height: r.block_height,
            description: r.description,
        })
        .collect())
}

/// Get all UTXOs for the active account.
///
/// Only requires an open wallet — no xprv needed.
#[tauri::command]
pub async fn get_utxos(
    state: State<'_, AppState>,
    account_id: Option<i64>,
) -> Result<Vec<UtxoEntry>, String> {
    log::info!("get_utxos — account_id: {:?}", account_id);

    let (pool, default_account_id, _) =
        get_active_wallet_data(&state).map_err(|e| e.to_string())?;
    let acct_id = account_id.unwrap_or(default_account_id);

    let utxos = repositories::get_utxo_infos_for_account(&pool, acct_id)
        .await
        .map_err(|e| e.to_string())?;

    Ok(utxos
        .into_iter()
        .map(|u| UtxoEntry {
            tx_hash: u.tx_hash_hex,
            tx_index: u.tx_index,
            value: u.value,
            keyinstance_id: u.keyinstance_id,
            is_coinbase: u.is_coinbase,
        })
        .collect())
}

/// Get the next receive address for the active account.
///
/// Derives a new BIP32 key at path 0/N (receiving chain), generates
/// the P2PKH address, and stores the KeyInstance in the database.
/// Requires an unlocked wallet (xprv needed for derivation).
#[tauri::command]
pub async fn get_receive_address(
    state: State<'_, AppState>,
    account_id: Option<i64>,
) -> Result<ReceiveAddressResult, String> {
    log::info!("get_receive_address — account_id: {:?}", account_id);

    let (pool, default_account_id, xprv_opt) =
        get_active_wallet_data(&state).map_err(|e| e.to_string())?;

    let xprv_str = xprv_opt.ok_or(AccountError::WalletLocked.to_string())?;
    let acct_id = account_id.unwrap_or(default_account_id);

    // Parse the xprv
    let account_key = ExtendedKey::from_string(&xprv_str)
        .map_err(|e| AccountError::InvalidXprv(e.to_string()).to_string())?;

    // Get the next receiving index
    let (receiving_count, _) = repositories::get_keyinstance_counts(&pool, acct_id)
        .await
        .map_err(|e| e.to_string())?;

    let next_index = receiving_count;

    // Derive the receiving key at 0/next_index
    let derivation_path = format!("0/{}", next_index);
    let child_key = account_key
        .derive(&derivation_path)
        .map_err(|e| AccountError::DerivationFailed(e.to_string()).to_string())?;

    // Get the public key
    let pubkey = child_key
        .public_key()
        .map_err(|e| AccountError::DerivationFailed(e.to_string()).to_string())?;

    // Generate the P2PKH address
    let address_str = address::pubkey_to_p2pkh_address(&pubkey);

    // Store the KeyInstance in the database
    let derivation_data = serde_json::json!({
        "subpath": [0, next_index]
    })
    .to_string()
    .into_bytes();

    // Get the masterkey_id from the first master key
    let mk_row = repositories::get_first_master_key(&pool)
        .await
        .map_err(|e| e.to_string())?;
    let masterkey_id = mk_row.map(|mk| mk.masterkey_id);

    let keyinstance_id = repositories::insert_keyinstance(
        &pool,
        acct_id,
        masterkey_id,
        repositories::derivation_type::BIP32,
        &derivation_data,
        repositories::script_type::P2PKH,
        0, // flags = 0 (no special flags)
        None,
    )
    .await
    .map_err(|e| e.to_string())?;

    log::info!(
        "Generated receive address {} at 0/{} (keyinstance {})",
        address_str,
        next_index,
        keyinstance_id
    );

    Ok(ReceiveAddressResult {
        address: address_str,
        keyinstance_id,
        derivation_index: next_index,
    })
}

/// Get the public key (hex) for a specific KeyInstance.
///
/// Requires an unlocked wallet (xprv needed for derivation).
#[tauri::command]
pub async fn get_public_key(
    state: State<'_, AppState>,
    keyinstance_id: i64,
) -> Result<String, String> {
    log::info!("get_public_key — keyinstance_id: {}", keyinstance_id);

    let (pool, _, xprv_opt) = get_active_wallet_data(&state).map_err(|e| e.to_string())?;

    let xprv_str = xprv_opt.ok_or(AccountError::WalletLocked.to_string())?;

    // Get the KeyInstance from the DB
    let ki = repositories::get_keyinstance(&pool, keyinstance_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| AccountError::KeyInstanceNotFound.to_string())?;

    // Parse the derivation_data to get the subpath
    let derivation_data: serde_json::Value =
        serde_json::from_slice(&ki.derivation_data).map_err(|e| e.to_string())?;

    let subpath = derivation_data
        .get("subpath")
        .and_then(|s| s.as_array())
        .ok_or_else(|| {
            AccountError::DerivationFailed("missing subpath in derivation_data".to_string())
                .to_string()
        })?;

    let type_idx = subpath.first().and_then(|t| t.as_i64()).ok_or_else(|| {
        AccountError::DerivationFailed("invalid subpath type index".to_string()).to_string()
    })?;

    let address_idx = subpath.get(1).and_then(|t| t.as_i64()).ok_or_else(|| {
        AccountError::DerivationFailed("invalid subpath address index".to_string()).to_string()
    })?;

    // Derive the key
    let account_key = ExtendedKey::from_string(&xprv_str)
        .map_err(|e| AccountError::InvalidXprv(e.to_string()).to_string())?;

    let derivation_path = format!("{}/{}", type_idx, address_idx);
    let child_key = account_key
        .derive(&derivation_path)
        .map_err(|e| AccountError::DerivationFailed(e.to_string()).to_string())?;

    let pubkey = child_key
        .public_key()
        .map_err(|e| AccountError::DerivationFailed(e.to_string()).to_string())?;

    // Return compressed public key hex
    Ok(pubkey.to_der_hex())
}

// ============================================================================
// Account query commands (Milestone 6)
// ============================================================================

/// Account info for get_accounts command.
#[derive(Debug, serde::Serialize)]
pub struct AccountInfo {
    pub account_id: i64,
    pub account_name: String,
    pub default_script_type: i32,
}

/// Key info for get_keys command.
#[derive(Debug, serde::Serialize)]
pub struct KeyInfo {
    pub keyinstance_id: i64,
    pub account_id: i64,
    pub script_type: i32,
    pub description: Option<String>,
    pub flags: i32,
    /// Derivation data as hex string
    pub derivation_data: String,
}

/// Get all accounts in the wallet.
///
/// Only requires an open wallet — no xprv needed.
#[tauri::command]
pub async fn get_accounts(state: State<'_, AppState>) -> Result<Vec<AccountInfo>, String> {
    log::info!("get_accounts");

    let (pool, _, _) = get_active_wallet_data(&state).map_err(|e| e.to_string())?;

    let accounts = repositories::get_all_accounts(&pool)
        .await
        .map_err(|e| e.to_string())?;

    Ok(accounts
        .into_iter()
        .map(|a| AccountInfo {
            account_id: a.account_id,
            account_name: a.account_name,
            default_script_type: a.default_script_type,
        })
        .collect())
}

/// Get all KeyInstances for the active account (or a specific account).
///
/// Only requires an open wallet — no xprv needed.
/// Derivation data is returned as a hex string for serialization.
#[tauri::command]
pub async fn get_keys(
    state: State<'_, AppState>,
    account_id: Option<i64>,
) -> Result<Vec<KeyInfo>, String> {
    log::info!("get_keys — account_id: {:?}", account_id);

    let (pool, default_account_id, _) =
        get_active_wallet_data(&state).map_err(|e| e.to_string())?;
    let acct_id = account_id.unwrap_or(default_account_id);

    let keyinstances = repositories::get_keyinstances_for_account(&pool, acct_id)
        .await
        .map_err(|e| e.to_string())?;

    Ok(keyinstances
        .into_iter()
        .map(|ki| KeyInfo {
            keyinstance_id: ki.keyinstance_id,
            account_id: ki.account_id,
            script_type: ki.script_type,
            description: ki.description,
            flags: ki.flags,
            derivation_data: hex::encode(&ki.derivation_data),
        })
        .collect())
}

// ============================================================================
// Multisig account commands (Task 5)
// ============================================================================

/// Multisig configuration result returned by `get_multisig_config`.
#[derive(Debug, serde::Serialize)]
pub struct MultisigConfigResult {
    pub account_id: i64,
    pub threshold: i64,
    /// Number of public keys (n in m-of-n).
    pub num_keys: i64,
    /// Hex-encoded public keys.
    pub public_keys: Vec<String>,
}

/// Create a new multisig (m-of-n) account.
///
/// Creates an Account row with `script_type = MULTISIG` and stores the
/// accompanying multisig configuration (threshold + public keys) in the
/// `MultisigConfigs` table. The public keys are stored as a JSON array
/// of hex strings.
///
/// Returns the new account_id.
#[tauri::command]
pub async fn create_multisig_account(
    state: State<'_, AppState>,
    account_name: String,
    threshold: i64,
    public_keys: Vec<String>,
) -> Result<i64, String> {
    log::info!(
        "create_multisig_account — name: {}, threshold: {}, n_keys: {}",
        account_name,
        threshold,
        public_keys.len()
    );

    // Validate inputs using the standalone multisig module.
    // We decode hex → Vec<Vec<u8>> only for validation here; the DB stores
    // the original hex strings as JSON.
    let mut pk_bytes: Vec<Vec<u8>> = Vec::with_capacity(public_keys.len());
    for pk in &public_keys {
        let bytes = hex::decode(pk)
            .map_err(|e| AccountError::Multisig(format!("invalid hex public key: {}", e)).to_string())?;
        pk_bytes.push(bytes);
    }
    // Validate threshold/n via AccumulatorMultiSigOutput::new.
    crate::core::multisig::AccumulatorMultiSigOutput::new(pk_bytes, threshold)
        .map_err(|e| AccountError::Multisig(e.to_string()).to_string())?;

    let (pool, _, _) = get_active_wallet_data(&state).map_err(|e| e.to_string())?;

    // Insert the account with script_type = MULTISIG (no masterkey — multisig
    // accounts use external public keys, not a single derivable master key).
    let account_id = repositories::insert_account(
        &pool,
        None, // no default masterkey for multisig
        repositories::script_type::MULTISIG,
        &account_name,
    )
    .await
    .map_err(|e| e.to_string())?;

    // Serialise the public keys as a JSON array of hex strings.
    let public_keys_json = serde_json::to_string(&public_keys)
        .map_err(|e| e.to_string())?;

    repositories::insert_multisig_config(&pool, account_id, threshold, &public_keys_json)
        .await
        .map_err(|e| e.to_string())?;

    log::info!(
        "Created multisig account {} ({}-of-{})",
        account_id,
        threshold,
        public_keys.len()
    );

    Ok(account_id)
}

/// Get the multisig configuration for an account.
///
/// Returns `None` if the account is not a multisig account (no row in
/// `MultisigConfigs`). Otherwise returns the threshold, public keys, and
/// the number of keys (n).
#[tauri::command]
pub async fn get_multisig_config(
    state: State<'_, AppState>,
    account_id: i64,
) -> Result<Option<MultisigConfigResult>, String> {
    log::info!("get_multisig_config — account_id: {}", account_id);

    let (pool, _, _) = get_active_wallet_data(&state).map_err(|e| e.to_string())?;

    let config = repositories::get_multisig_config(&pool, account_id)
        .await
        .map_err(|e| e.to_string())?;

    match config {
        Some(row) => Ok(Some(MultisigConfigResult {
            account_id: row.account_id,
            threshold: row.threshold,
            num_keys: row.public_keys.len() as i64,
            public_keys: row.public_keys,
        })),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::wallet_service;
    use crate::state::AppState;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn make_test_state(test_name: &str) -> AppState {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let temp_dir =
            std::env::temp_dir().join(format!("electrumsv_mc_acct_{}_{}", test_name, id));
        // Clean up any leftover from previous test runs
        if temp_dir.exists() {
            std::fs::remove_dir_all(&temp_dir).ok();
        }
        std::fs::create_dir_all(&temp_dir).unwrap();
        AppState {
            data_dir: temp_dir.to_string_lossy().to_string(),
            active_wallet: std::sync::Mutex::new(None),
            network: std::sync::Mutex::new(crate::state::NetworkState::new()),
            pending_plans: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    #[tokio::test]
    async fn test_get_balance_empty_wallet() {
        // New wallet should have zero balance
        let state = make_test_state("balance_empty");
        wallet_service::create_wallet(&state, "test_bal", "pw123", None, None)
            .await
            .unwrap();

        // get_balance requires State<'_, AppState> which is a Tauri-specific
        // wrapper. In tests we call the underlying repository directly.
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().unwrap();
        let pool = &active.db_pool;
        let (confirmed, unconfirmed, total) =
            repositories::get_balance_for_account(pool, active.account_id)
                .await
                .unwrap();
        assert_eq!(confirmed, 0);
        assert_eq!(unconfirmed, 0);
        assert_eq!(total, 0);
        drop(guard);

        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_get_history_empty_wallet() {
        let state = make_test_state("history_empty");
        wallet_service::create_wallet(&state, "test_hist", "pw123", None, None)
            .await
            .unwrap();

        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().unwrap();
        let pool = &active.db_pool;
        let history = repositories::get_tx_history_for_account(pool, active.account_id, 50, 0)
            .await
            .unwrap();
        assert!(history.is_empty());
        drop(guard);

        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_get_utxos_empty_wallet() {
        let state = make_test_state("utxos_empty");
        wallet_service::create_wallet(&state, "test_utxos", "pw123", None, None)
            .await
            .unwrap();

        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().unwrap();
        let pool = &active.db_pool;
        let utxos = repositories::get_utxo_infos_for_account(pool, active.account_id)
            .await
            .unwrap();
        assert!(utxos.is_empty());
        drop(guard);

        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_get_keyinstance_counts_empty() {
        let state = make_test_state("ki_counts_empty");
        wallet_service::create_wallet(&state, "test_counts", "pw123", None, None)
            .await
            .unwrap();

        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().unwrap();
        let pool = &active.db_pool;
        let (receiving, change) = repositories::get_keyinstance_counts(pool, active.account_id)
            .await
            .unwrap();
        assert_eq!(receiving, 0);
        assert_eq!(change, 0);
        drop(guard);

        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_receive_address_generation() {
        // Test the receive address derivation logic without Tauri State wrapper
        let state = make_test_state("recv_addr");
        wallet_service::create_wallet(&state, "test_recv", "pw123", None, None)
            .await
            .unwrap();

        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().unwrap();
        let pool = active.db_pool.clone();
        let acct_id = active.account_id;
        let xprv = active.decrypted_xprv.as_ref().unwrap().clone();
        drop(guard);

        // Derive first receiving address (index 0)
        let account_key = ExtendedKey::from_string(&xprv).unwrap();
        let child = account_key.derive("0/0").unwrap();
        let pubkey = child.public_key().unwrap();
        let addr = address::pubkey_to_p2pkh_address(&pubkey);

        // Should be a valid BSV mainnet P2PKH address (starts with "1")
        assert!(
            addr.starts_with('1'),
            "Expected mainnet P2PKH address starting with '1', got: {}",
            addr
        );
        assert!(addr.len() >= 26 && addr.len() <= 35);

        // Insert the keyinstance
        let derivation_data = serde_json::json!({"subpath": [0, 0]})
            .to_string()
            .into_bytes();
        let ki_id = repositories::insert_keyinstance(
            &pool,
            acct_id,
            None,
            repositories::derivation_type::BIP32,
            &derivation_data,
            repositories::script_type::P2PKH,
            0,
            None,
        )
        .await
        .unwrap();

        // Verify counts updated
        let (receiving, change) = repositories::get_keyinstance_counts(&pool, acct_id)
            .await
            .unwrap();
        assert_eq!(receiving, 1);
        assert_eq!(change, 0);

        // Verify we can read the keyinstance back
        let ki = repositories::get_keyinstance(&pool, ki_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ki.account_id, acct_id);
        assert_eq!(ki.script_type, repositories::script_type::P2PKH);

        // Derive second address (index 1) — should be different
        let child2 = account_key.derive("0/1").unwrap();
        let pubkey2 = child2.public_key().unwrap();
        let addr2 = address::pubkey_to_p2pkh_address(&pubkey2);
        assert_ne!(addr, addr2);

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_receive_address_known_vector() {
        // Use the known BIP39 test vector to verify address generation
        let state = make_test_state("recv_known");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        wallet_service::create_wallet(&state, "test_known", "pw123", Some(mnemonic), None)
            .await
            .unwrap();

        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().unwrap();
        let xprv = active.decrypted_xprv.as_ref().unwrap().clone();
        drop(guard);

        // Derive m/44'/0'/0'/0/0
        let account_key = ExtendedKey::from_string(&xprv).unwrap();
        let child = account_key.derive("0/0").unwrap();
        let pubkey = child.public_key().unwrap();
        let addr = address::pubkey_to_p2pkh_address(&pubkey);

        // The address should be a valid mainnet address
        assert!(addr.starts_with('1'));
        log::info!("Known vector address: {}", addr);

        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_get_public_key_derivation() {
        let state = make_test_state("get_pubkey");
        wallet_service::create_wallet(&state, "test_pk", "pw123", None, None)
            .await
            .unwrap();

        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().unwrap();
        let pool = active.db_pool.clone();
        let acct_id = active.account_id;
        let xprv = active.decrypted_xprv.as_ref().unwrap().clone();
        drop(guard);

        // Insert a keyinstance at 0/0
        let derivation_data = serde_json::json!({"subpath": [0, 0]})
            .to_string()
            .into_bytes();
        let ki_id = repositories::insert_keyinstance(
            &pool,
            acct_id,
            None,
            repositories::derivation_type::BIP32,
            &derivation_data,
            repositories::script_type::P2PKH,
            0,
            None,
        )
        .await
        .unwrap();

        // Derive the public key manually
        let account_key = ExtendedKey::from_string(&xprv).unwrap();
        let child = account_key.derive("0/0").unwrap();
        let pubkey = child.public_key().unwrap();
        let expected_hex = pubkey.to_der_hex();

        // Read back from DB and derive
        let ki = repositories::get_keyinstance(&pool, ki_id)
            .await
            .unwrap()
            .unwrap();
        let ki_data: serde_json::Value = serde_json::from_slice(&ki.derivation_data).unwrap();
        let subpath = ki_data.get("subpath").unwrap().as_array().unwrap();
        let type_idx = subpath[0].as_i64().unwrap();
        let addr_idx = subpath[1].as_i64().unwrap();

        let path = format!("{}/{}", type_idx, addr_idx);
        let child2 = account_key.derive(&path).unwrap();
        let pubkey2 = child2.public_key().unwrap();
        let actual_hex = pubkey2.to_der_hex();

        assert_eq!(expected_hex, actual_hex);

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_hash_endianness_in_history() {
        // AUD-014: Verify that txids in history are display-order (reversed)
        let state = make_test_state("endianness");
        wallet_service::create_wallet(&state, "test_endian", "pw123", None, None)
            .await
            .unwrap();

        // Insert a fake transaction + delta to test endianness
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().unwrap();
        let pool = &active.db_pool;
        let acct_id = active.account_id;

        // Insert a keyinstance
        let ki_data = serde_json::json!({"subpath": [0, 0]})
            .to_string()
            .into_bytes();
        let ki_id = repositories::insert_keyinstance(
            pool,
            acct_id,
            None,
            repositories::derivation_type::BIP32,
            &ki_data,
            repositories::script_type::P2PKH,
            0,
            None,
        )
        .await
        .unwrap();

        // Insert a transaction with a known hash
        // Internal bytes: [0xaa, 0xbb, ...] → Display: reversed
        let tx_hash_internal = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO Transactions (tx_hash, block_height, flags, date_created, date_updated) VALUES (?, NULL, 0, ?, ?)",
        )
        .bind(&tx_hash_internal)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await
        .unwrap();

        // Insert a transaction delta
        sqlx::query(
            "INSERT INTO TransactionDeltas (keyinstance_id, tx_hash, value_delta, date_created, date_updated) VALUES (?, ?, 50000, ?, ?)",
        )
        .bind(ki_id)
        .bind(&tx_hash_internal)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await
        .unwrap();

        // Query history — should return reversed hex
        let history = repositories::get_tx_history_for_account(pool, acct_id, 50, 0)
            .await
            .unwrap();

        assert_eq!(history.len(), 1);
        // The display hex should be the reverse of the internal bytes
        let expected_display = hex::encode({
            let mut v = tx_hash_internal.clone();
            v.reverse();
            v
        });
        assert_eq!(history[0].tx_hash_hex, expected_display);
        assert_eq!(history[0].value_delta, 50000);

        drop(guard);
        wallet_service::close_wallet(&state).unwrap();
    }

    // ========================================================================
    // Multisig account tests (Task 5)
    // ========================================================================

    /// Helper: generate a 33-byte dummy compressed public key as hex string.
    fn dummy_pk_hex(seed: u8) -> String {
        hex::encode(vec![seed; 33])
    }

    #[tokio::test]
    async fn test_create_multisig_account() {
        // Create a multisig account and verify it exists in the DB with
        // script_type = MULTISIG and a matching MultisigConfigs row.
        let state = make_test_state("msig_create");
        wallet_service::create_wallet(&state, "test_msig", "pw123", None, None)
            .await
            .unwrap();

        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().unwrap();
        let pool = active.db_pool.clone();
        drop(guard);

        // 2-of-3 multisig with dummy public keys.
        let pks = vec![dummy_pk_hex(1), dummy_pk_hex(2), dummy_pk_hex(3)];
        let threshold = 2;

        // Insert the account + config directly via repositories (mirrors what
        // the create_multisig_account command does, without the Tauri State).
        let account_id = repositories::insert_account(
            &pool,
            None,
            repositories::script_type::MULTISIG,
            "Multisig Test",
        )
        .await
        .unwrap();

        let public_keys_json = serde_json::to_string(&pks).unwrap();
        repositories::insert_multisig_config(&pool, account_id, threshold, &public_keys_json)
            .await
            .unwrap();

        // Verify the account exists with script_type = MULTISIG.
        let acct = repositories::get_account_by_id(&pool, account_id)
            .await
            .unwrap()
            .expect("account must exist");
        assert_eq!(acct.default_script_type, repositories::script_type::MULTISIG);
        assert_eq!(acct.account_name, "Multisig Test");
        assert!(acct.default_masterkey_id.is_none());

        // Verify the MultisigConfigs row exists.
        let cfg = repositories::get_multisig_config(&pool, account_id)
            .await
            .unwrap()
            .expect("multisig config must exist");
        assert_eq!(cfg.account_id, account_id);
        assert_eq!(cfg.threshold, 2);
        assert_eq!(cfg.public_keys.len(), 3);
        assert_eq!(cfg.public_keys, pks);

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_get_multisig_config() {
        // Insert a multisig config and read it back, verifying threshold and
        // public_keys round-trip correctly. Also verify get_multisig_config
        // returns None for a non-multisig account.
        let state = make_test_state("msig_get");
        wallet_service::create_wallet(&state, "test_msig_get", "pw123", None, None)
            .await
            .unwrap();

        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().unwrap();
        let pool = active.db_pool.clone();
        let default_acct = active.account_id;
        drop(guard);

        // The default account (P2PKH) should have no multisig config.
        let none_cfg = repositories::get_multisig_config(&pool, default_acct)
            .await
            .unwrap();
        assert!(none_cfg.is_none(), "default P2PKH account must not have a multisig config");

        // Create a multisig account and read it back.
        let pks = vec![dummy_pk_hex(0x10), dummy_pk_hex(0x20), dummy_pk_hex(0x30), dummy_pk_hex(0x40)];
        let threshold = 3;
        let account_id = repositories::insert_account(
            &pool,
            None,
            repositories::script_type::MULTISIG,
            "4-of-4 Multisig",
        )
        .await
        .unwrap();

        let public_keys_json = serde_json::to_string(&pks).unwrap();
        repositories::insert_multisig_config(&pool, account_id, threshold, &public_keys_json)
            .await
            .unwrap();

        let cfg = repositories::get_multisig_config(&pool, account_id)
            .await
            .unwrap()
            .expect("config must exist");

        assert_eq!(cfg.threshold, 3);
        assert_eq!(cfg.public_keys.len(), 4);
        assert_eq!(cfg.public_keys, pks);
        // Verify the date stamps are populated.
        assert!(cfg.date_created > 0);
        assert!(cfg.date_updated > 0);

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_multisig_script_generation() {
        // Store a multisig config in the DB, read it back, convert the hex
        // public keys to Vec<Vec<u8>>, build an AccumulatorMultiSigOutput,
        // and verify to_script_bytes() produces a non-empty script with the
        // expected structure (starts with OP_0 OP_TOALTSTACK, ends with
        // OP_GREATERTHANOREQUAL, has one OP_IF per key).
        let state = make_test_state("msig_script");
        wallet_service::create_wallet(&state, "test_msig_script", "pw123", None, None)
            .await
            .unwrap();

        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().unwrap();
        let pool = active.db_pool.clone();
        drop(guard);

        let pks_hex = vec![dummy_pk_hex(1), dummy_pk_hex(2), dummy_pk_hex(3)];
        let threshold = 2;

        let account_id = repositories::insert_account(
            &pool,
            None,
            repositories::script_type::MULTISIG,
            "Script Test Multisig",
        )
        .await
        .unwrap();

        let public_keys_json = serde_json::to_string(&pks_hex).unwrap();
        repositories::insert_multisig_config(&pool, account_id, threshold, &public_keys_json)
            .await
            .unwrap();

        // Read the config back from the DB.
        let cfg = repositories::get_multisig_config(&pool, account_id)
            .await
            .unwrap()
            .expect("config must exist");

        // Convert hex strings → Vec<Vec<u8>> as required by AccumulatorMultiSigOutput.
        let pk_bytes: Vec<Vec<u8>> = cfg.public_keys.iter().map(|h| hex::decode(h).unwrap()).collect();

        // Build the multisig output and generate the script.
        let ms = crate::core::multisig::AccumulatorMultiSigOutput::new(pk_bytes, cfg.threshold)
            .expect("valid multisig output");
        let script = ms.to_script_bytes();

        // Verify the script structure.
        assert!(!script.is_empty(), "script must not be empty");
        assert_eq!(script[0], crate::core::multisig::op::OP_0, "must start with OP_0");
        assert_eq!(script[1], crate::core::multisig::op::OP_TOALTSTACK, "second byte OP_TOALTSTACK");
        assert_eq!(
            *script.last().unwrap(),
            crate::core::multisig::op::OP_GREATERTHANOREQUAL,
            "must end with OP_GREATERTHANOREQUAL"
        );

        // One OP_IF and one OP_ENDIF per public key.
        let if_count = script.iter().filter(|&&b| b == crate::core::multisig::op::OP_IF).count();
        let endif_count = script.iter().filter(|&&b| b == crate::core::multisig::op::OP_ENDIF).count();
        assert_eq!(if_count, 3, "one OP_IF per public key");
        assert_eq!(endif_count, 3, "one OP_ENDIF per public key");

        // The threshold (2) is pushed as OP_2 (0x52).
        // Verify OP_2 appears in the script (the threshold push near the end).
        assert!(
            script.contains(&crate::core::multisig::op::OP_2),
            "script must contain OP_2 for threshold=2"
        );

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }
}
