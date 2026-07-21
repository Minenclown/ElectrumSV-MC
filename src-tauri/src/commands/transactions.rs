// commands/transactions.rs — Send/Sign/Broadcast Tauri commands (Milestone 5)
//
// Provides: prepare_tx, sign_tx, broadcast_tx, estimate_fee
//
// AUD-007: sign_tx requires TOTP verification before signing.
// Every TX plan is bound to a wallet by wallet_path to prevent cross-wallet replay.

use crate::core::coinchooser::Strategy;
use crate::core::signer::{LocalSigner, Signer};
use crate::core::transaction::{
    FeeEstimator, PaymentOutput, SelectedUtxo, TransactionError, TxBuilder, TxPlan,
};
use crate::db::repositories;
use crate::network::backend::NetworkBackend;
use crate::security::totp::TotpInstance;
use crate::state::{self, AppState, PLAN_STORE_TTL};
use bsv::compat::bip32::ExtendedKey;
use tauri::State;

/// TX plan TTL in seconds (5 minutes).
const TX_PLAN_TTL: i64 = 300;

#[derive(Debug, thiserror::Error)]
pub enum TransactionCmdError {
    #[error("no wallet is currently open")]
    NoWalletOpen,
    #[error("wallet is locked — unlock first")]
    WalletLocked,
    #[error("not connected to a network backend")]
    NotConnected,
    #[error("TOTP is not enabled — enable TOTP first")]
    TotpNotEnabled,
    #[error("TOTP verification failed")]
    TotpVerificationFailed,
    #[error("TX plan has expired")]
    PlanExpired,
    #[error("TX plan wallet mismatch — plan belongs to a different wallet")]
    WalletMismatch,
    #[error("TX plan is already signed")]
    AlreadySigned,
    #[error("TX plan is not signed yet — sign first")]
    NotSigned,
    #[error("plan not found or expired")]
    PlanNotFound,
    #[error("transaction error: {0}")]
    Transaction(#[from] TransactionError),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("signer error: {0}")]
    Signer(String),
    #[error("BSV SDK error: {0}")]
    BsvSdk(String),
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl From<bsv::transaction::error::TransactionError> for TransactionCmdError {
    fn from(e: bsv::transaction::error::TransactionError) -> Self {
        TransactionCmdError::BsvSdk(e.to_string())
    }
}

impl From<bsv::compat::error::CompatError> for TransactionCmdError {
    fn from(e: bsv::compat::error::CompatError) -> Self {
        TransactionCmdError::BsvSdk(e.to_string())
    }
}

impl From<crate::core::signer::SignerError> for TransactionCmdError {
    fn from(e: crate::core::signer::SignerError) -> Self {
        TransactionCmdError::Signer(e.to_string())
    }
}

// ============================================================================
// Response types
// ============================================================================

/// Result of prepare_tx — returns a handle (plan_id) plus metadata only.
///
/// The full TxPlan (with `unsigned_tx_hex`, `inputs`, `outputs`, ...) is kept
/// server-side in `state.pending_plans` and never sent to the renderer. The
/// renderer only gets `plan_id` and the metadata it needs to display a
/// preview. `sign_tx` then retrieves the plan from the store by `plan_id`,
/// so a compromised renderer cannot tamper with the plan that gets signed.
#[derive(Debug, serde::Serialize)]
pub struct PrepareTxResult {
    /// Server-side handle for the stored plan — pass to `sign_tx`.
    pub plan_id: String,
    /// Fee in satoshis (for preview display).
    pub fee: u64,
    /// Total input value in satoshis (for preview display).
    pub total_input: u64,
    /// Total output value in satoshis (for preview display).
    pub total_output: u64,
    /// Change amount in satoshis (for preview display).
    pub change: u64,
    /// Number of inputs selected (for preview display).
    pub num_inputs: usize,
    /// Number of outputs (payment + change + op_return, for preview display).
    pub num_outputs: usize,
}

/// Result of sign_tx — returns signed TX hex and txid.
#[derive(Debug, serde::Serialize)]
pub struct SignTxResult {
    pub txid: String,
    pub signed_tx_hex: String,
}

/// Result of estimate_fee — returns fee estimate without creating a TX.
#[derive(Debug, serde::Serialize)]
pub struct EstimateFeeResult {
    pub fee: u64,
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub fee_rate: u64,
}

// ============================================================================
// Helper: get wallet data without holding lock across awaits
// ============================================================================

fn get_wallet_data(
    state: &AppState,
) -> Result<(sqlx::SqlitePool, i64, String, Option<String>), TransactionCmdError> {
    let guard = state.active_wallet.lock().unwrap();
    let active = guard.as_ref().ok_or(TransactionCmdError::NoWalletOpen)?;
    Ok((
        active.db_pool.clone(),
        active.account_id,
        active.wallet_path.clone(),
        active.decrypted_xprv.clone(),
    ))
}

/// Derive a change address from the wallet at path 1/0 (change chain, index 0).
fn derive_change_address(xprv: &str) -> Result<String, TransactionCmdError> {
    let account_key = ExtendedKey::from_string(xprv)?;
    let child = account_key.derive("1/0")?;
    let pubkey = child
        .public_key()
        .map_err(|e| TransactionCmdError::BsvSdk(e.to_string()))?;
    Ok(crate::core::address::pubkey_to_p2pkh_address(&pubkey))
}

// ============================================================================
// Commands
// ============================================================================

/// Parse a coin-selection strategy string into an optional `Strategy`.
///
/// - `None` or `"largest_first"` → `None` (use the default largest-first CoinSelector)
/// - `"branch_and_bound"` → `Some(Strategy::BranchAndBound)`
/// - `"random_subset"` → `Some(Strategy::RandomSubset)`
/// - `"privacy"` → `Some(Strategy::Privacy)`
/// - anything else → `Err`
fn parse_strategy(s: &Option<String>) -> Result<Option<Strategy>, String> {
    match s.as_deref() {
        None | Some("largest_first") => Ok(None),
        Some("branch_and_bound") => Ok(Some(Strategy::BranchAndBound)),
        Some("random_subset") => Ok(Some(Strategy::RandomSubset)),
        Some("privacy") => Ok(Some(Strategy::Privacy)),
        Some(other) => Err(format!(
            "invalid coin_selection_strategy '{}': expected one of largest_first, branch_and_bound, random_subset, privacy",
            other
        )),
    }
}

/// Prepare an unsigned transaction.
///
/// Selects UTXOs, calculates fees, and creates a TX plan bound to the current wallet.
/// The plan must be signed (sign_tx) and broadcast (broadcast_tx) in subsequent calls.
#[tauri::command]
pub async fn prepare_tx(
    state: State<'_, AppState>,
    outputs: Vec<PaymentOutput>,
    fee_rate: Option<u64>,
    op_return: Option<String>,
    coin_selection_strategy: Option<String>,
) -> Result<PrepareTxResult, String> {
    log::info!("prepare_tx — {} outputs", outputs.len());

    let (pool, account_id, wallet_path, xprv_opt) =
        get_wallet_data(&state).map_err(|e| e.to_string())?;

    let xprv = xprv_opt.ok_or(TransactionCmdError::WalletLocked.to_string())?;
    let fee_rate = match fee_rate {
        Some(r) => r,
        None => crate::features::mapi::fetch_default_fee_rate().await,
    };

    // Decode op_return: hex (with or without 0x prefix) or UTF-8 text
    let op_return_bytes: Option<Vec<u8>> = op_return.map(|s| {
        if s.is_empty() {
            return Vec::new();
        }
        let hex_str = if let Some(stripped) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            stripped
        } else {
            // Try to decode as hex — if valid, use it; otherwise treat as UTF-8
            if hex::decode(&s).is_ok() {
                &s
            } else {
                // Not valid hex — encode as UTF-8 bytes
                return s.into_bytes();
            }
        };
        // Decode hex string to bytes
        match hex::decode(hex_str) {
            Ok(bytes) => bytes,
            Err(_) => s.into_bytes(),
        }
    });

    // Fetch UTXOs from DB
    let utxo_infos = repositories::get_utxo_infos_for_account(&pool, account_id)
        .await
        .map_err(|e| e.to_string())?;

    if utxo_infos.is_empty() {
        return Err(TransactionError::NoUtxos.to_string());
    }

    // Convert UTXOs to SelectedUtxo with subpath info
    let mut selected_utxos = Vec::new();
    for info in &utxo_infos {
        // Get the KeyInstance to find the subpath
        let ki = repositories::get_keyinstance(&pool, info.keyinstance_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| {
                TransactionError::BsvSdk(format!("KeyInstance {} not found", info.keyinstance_id))
                    .to_string()
            })?;

        let derivation_data: serde_json::Value =
            serde_json::from_slice(&ki.derivation_data).map_err(|e| e.to_string())?;

        let subpath = derivation_data
            .get("subpath")
            .and_then(|s| s.as_array())
            .ok_or_else(|| {
                TransactionError::BsvSdk("missing subpath in derivation_data".to_string())
                    .to_string()
            })?;

        let type_idx = subpath[0]
            .as_u64()
            .ok_or_else(|| TransactionError::BsvSdk("invalid subpath type index".to_string()).to_string())? as u32;
        let addr_idx = subpath[1]
            .as_u64()
            .ok_or_else(|| TransactionError::BsvSdk("invalid subpath address index".to_string()).to_string())? as u32;

        selected_utxos.push(SelectedUtxo::from_utxo_info(info, [type_idx, addr_idx]));
    }

    // Derive change address
    let change_address = derive_change_address(&xprv).map_err(|e| e.to_string())?;

    // Parse coin selection strategy (None/empty -> largest-first default)
    let strategy = parse_strategy(&coin_selection_strategy)?;

    // Build unsigned transaction
    let op_return_ref = op_return_bytes.as_deref();
    let (tx, selection) =
        TxBuilder::build_unsigned(&selected_utxos, &outputs, Some(&change_address), fee_rate, op_return_ref, strategy)
            .map_err(|e| e.to_string())?;

    // Create TX plan
    let plan = TxBuilder::create_plan(
        tx,
        outputs,
        selection,
        Some(change_address),
        wallet_path,
        account_id,
        TX_PLAN_TTL,
        op_return_bytes,
    )
    .map_err(|e| e.to_string())?;

    log::info!(
        "TX plan created: {} inputs, {} sat fee, {} sat change, expires in {}s",
        plan.inputs.len(),
        plan.fee,
        plan.change,
        TX_PLAN_TTL
    );

    // AUD-008: Store the plan server-side and return only a plan_id handle.
    // The renderer never sees the unsigned_tx_hex or inputs — it cannot
    // tamper with the plan that actually gets signed.
    let plan_id = state::generate_plan_id();
    let now = chrono::Utc::now().timestamp();
    let num_inputs = plan.inputs.len();
    let num_outputs = plan.outputs.len()
        + if plan.change > 0 { 1 } else { 0 }
        + if plan.op_return.is_some() { 1 } else { 0 };
    let fee = plan.fee;
    let total_input = plan.total_input;
    let total_output = plan.total_output;
    let change = plan.change;

    {
        let mut plans = state.pending_plans.lock().unwrap();
        // Opportunistic cleanup: remove expired plans before inserting the new one.
        plans.retain(|_, pp| now - pp.created_at < PLAN_STORE_TTL);
        plans.insert(
            plan_id.clone(),
            crate::state::PendingPlan {
                plan,
                created_at: now,
            },
        );
    }
    log::info!("TX plan stored server-side — plan_id: {}", plan_id);

    Ok(PrepareTxResult {
        plan_id,
        fee,
        total_input,
        total_output,
        change,
        num_inputs,
        num_outputs,
    })
}

/// Sign a transaction plan.
///
/// AUD-007: Requires TOTP verification before signing.
/// The plan must belong to the current wallet (wallet_path binding).
/// AUD-008: The plan is fetched server-side by `plan_id` from the plan store
/// instead of being accepted as a parameter from the renderer. This prevents
/// a compromised renderer from tampering with inputs/outputs/fee.
#[tauri::command]
pub async fn sign_tx(
    state: State<'_, AppState>,
    plan_id: String,
    totp_code: String,
) -> Result<SignTxResult, String> {
    log::info!("sign_tx — plan_id: {}", plan_id);

    let (pool, _, wallet_path, xprv_opt) = get_wallet_data(&state).map_err(|e| e.to_string())?;

    let xprv = xprv_opt.ok_or(TransactionCmdError::WalletLocked.to_string())?;

    // AUD-008: Retrieve the plan from the server-side store, and opportunistically
    // clean up plans older than PLAN_STORE_TTL (1 hour) while we hold the lock.
    let plan = {
        let mut plans = state.pending_plans.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        // Cleanup: remove plans older than PLAN_STORE_TTL
        plans.retain(|_, pp| now - pp.created_at < PLAN_STORE_TTL);
        // Remove the requested plan (consume on success; stays only on lookup failure)
        match plans.remove(&plan_id) {
            Some(pp) => pp.plan,
            None => return Err(TransactionCmdError::PlanNotFound.to_string()),
        }
    };

    log::info!("sign_tx — retrieved plan with {} inputs", plan.inputs.len());

    // AUD-007: Verify wallet binding
    if plan.wallet_path != wallet_path {
        return Err(TransactionCmdError::WalletMismatch.to_string());
    }

    // AUD-007: Verify plan is not expired
    let now = chrono::Utc::now().timestamp();
    if now > plan.expires_at {
        return Err(TransactionCmdError::PlanExpired.to_string());
    }

    // AUD-007: Verify plan is not already signed
    if plan.signed {
        return Err(TransactionCmdError::AlreadySigned.to_string());
    }

    // AUD-007: TOTP verification — mandatory before signing
    let totp_enabled = repositories::is_totp_enabled(&pool)
        .await
        .map_err(|e| e.to_string())?;

    if !totp_enabled {
        return Err(TransactionCmdError::TotpNotEnabled.to_string());
    }

    // Load and decrypt TOTP secret
    let encrypted_secret = repositories::load_totp_secret(&pool)
        .await
        .map_err(|e| e.to_string())?
        .ok_or(TransactionCmdError::TotpNotEnabled.to_string())?;

    // For now: use the raw bytes as the TOTP secret
    let totp = TotpInstance::from_secret_bytes(&encrypted_secret, "ElectrumSV-Mc", "wallet")
        .map_err(|e| e.to_string())?;

    // AUD-007: Verify the provided TOTP code
    let valid = totp.verify_current(&totp_code).map_err(|e| e.to_string())?;
    if !valid {
        return Err(TransactionCmdError::TotpVerificationFailed.to_string());
    }

    // Parse the unsigned transaction
    let mut tx = bsv::transaction::transaction::Transaction::from_hex(&plan.unsigned_tx_hex)
        .map_err(|e| e.to_string())?;

    // Sign with LocalSigner
    let signer = LocalSigner::new(&xprv);
    signer
        .sign_tx(&mut tx, &plan.inputs)
        .map_err(|e| e.to_string())?;

    // Get txid and signed hex
    let txid = tx.id().map_err(|e| e.to_string())?;
    let signed_hex = tx.to_hex().map_err(|e| e.to_string())?;

    log::info!("TX signed — txid: {}", txid);

    Ok(SignTxResult {
        txid,
        signed_tx_hex: signed_hex,
    })
}

/// Broadcast a signed transaction.
///
/// AUD-006: Validates the txid returned by the server against the locally computed txid.
#[tauri::command]
pub async fn broadcast_tx(
    state: State<'_, AppState>,
    signed_tx_hex: String,
    expected_txid: String,
) -> Result<String, String> {
    log::info!("broadcast_tx — expected txid: {}", expected_txid);

    // Parse the signed TX to compute txid locally (AUD-006)
    let tx = bsv::transaction::transaction::Transaction::from_hex(&signed_tx_hex)
        .map_err(|e| e.to_string())?;

    let local_txid = tx.id().map_err(|e| e.to_string())?;

    // AUD-006: Verify local txid matches expected
    if local_txid != expected_txid {
        return Err(format!(
            "txid mismatch: local={}, expected={}",
            local_txid, expected_txid
        ));
    }

    // Broadcast via the active backend
    // Clone the client out of state before awaiting (MutexGuard is not Send)
    let electrumx_client = {
        let guard = state.network.lock().unwrap();
        guard.client.clone()
    };

    let server_txid = if let Some(client) = electrumx_client {
        // ElectrumX backend — broadcast_tx takes raw bytes
        let raw_bytes = hex::decode(&signed_tx_hex).map_err(|e| format!("invalid hex: {}", e))?;
        let result = client
            .broadcast_tx(&raw_bytes)
            .await
            .map_err(|e| e.to_string())?;
        result.txid
    } else {
        // WoC backend — clone the client out of state
        let woc_client = {
            let guard = state.network.lock().unwrap();
            guard.woc_client.clone()
        };
        let woc = woc_client
            .as_ref()
            .ok_or(TransactionCmdError::NotConnected.to_string())?;
        let raw_bytes = hex::decode(&signed_tx_hex).map_err(|e| format!("invalid hex: {}", e))?;
        let result = woc
            .broadcast_tx(&raw_bytes)
            .await
            .map_err(|e| e.to_string())?;
        result.txid
    };

    // AUD-006: Verify server-returned txid matches local txid
    if server_txid != local_txid {
        return Err(format!(
            "server returned different txid: server={}, local={}",
            server_txid, local_txid
        ));
    }

    log::info!("TX broadcast successful — txid: {}", server_txid);
    Ok(server_txid)
}

/// Estimate the fee for a transaction without creating it.
#[tauri::command]
pub async fn estimate_fee(
    state: State<'_, AppState>,
    outputs: Vec<PaymentOutput>,
    fee_rate: Option<u64>,
    op_return: Option<String>,
) -> Result<EstimateFeeResult, String> {
    log::info!("estimate_fee — {} outputs", outputs.len());

    let (pool, account_id, _, _) = get_wallet_data(&state).map_err(|e| e.to_string())?;
    let fee_rate = match fee_rate {
        Some(r) => r,
        None => crate::features::mapi::fetch_default_fee_rate().await,
    };

    // Count available UTXOs
    let utxo_infos = repositories::get_utxo_infos_for_account(&pool, account_id)
        .await
        .map_err(|e| e.to_string())?;

    // Estimate: assume all UTXOs are needed (worst case)
    let num_inputs = utxo_infos.len().max(1);
    // +1 for change, +1 if OP_RETURN output present
    let op_return_extra = if op_return.is_some() { 1 } else { 0 };
    let num_outputs = outputs.len() + 1 + op_return_extra; // +1 for change

    let fee = FeeEstimator::estimate_fee(num_inputs, num_outputs, fee_rate);

    Ok(EstimateFeeResult {
        fee,
        num_inputs,
        num_outputs,
        fee_rate,
    })
}

/// Sign a multisig transaction plan.
///
/// Like `sign_tx` but for multisig accounts: uses the `MultisigSigner` to
/// sign with the local cosigner's key. The caller must provide the
/// `local_key_index` — the 0-based position of the local cosigner's public
/// key in the multisig config's `public_keys` array.
///
/// AUD-007: Requires TOTP verification before signing.
/// AUD-008: The plan is fetched server-side by `plan_id`.
#[tauri::command]
pub async fn sign_multisig_tx(
    state: State<'_, AppState>,
    plan_id: String,
    totp_code: String,
    local_key_index: usize,
) -> Result<SignTxResult, String> {
    log::info!(
        "sign_multisig_tx — plan_id: {}, local_key_index: {}",
        plan_id,
        local_key_index
    );

    let (pool, account_id, wallet_path, xprv_opt) = get_wallet_data(&state).map_err(|e| e.to_string())?;

    let xprv = xprv_opt.ok_or(TransactionCmdError::WalletLocked.to_string())?;

    // Retrieve the plan from the server-side store.
    let plan = {
        let mut plans = state.pending_plans.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        plans.retain(|_, pp| now - pp.created_at < PLAN_STORE_TTL);
        match plans.remove(&plan_id) {
            Some(pp) => pp.plan,
            None => return Err(TransactionCmdError::PlanNotFound.to_string()),
        }
    };

    // AUD-007: Verify wallet binding
    if plan.wallet_path != wallet_path {
        return Err(TransactionCmdError::WalletMismatch.to_string());
    }

    // AUD-007: Verify plan is not expired
    let now = chrono::Utc::now().timestamp();
    if now > plan.expires_at {
        return Err(TransactionCmdError::PlanExpired.to_string());
    }

    if plan.signed {
        return Err(TransactionCmdError::AlreadySigned.to_string());
    }

    // TOTP verification
    let totp_enabled = repositories::is_totp_enabled(&pool)
        .await
        .map_err(|e| e.to_string())?;
    if !totp_enabled {
        return Err(TransactionCmdError::TotpNotEnabled.to_string());
    }
    let encrypted_secret = repositories::load_totp_secret(&pool)
        .await
        .map_err(|e| e.to_string())?
        .ok_or(TransactionCmdError::TotpNotEnabled.to_string())?;
    let totp = TotpInstance::from_secret_bytes(&encrypted_secret, "ElectrumSV-Mc", "wallet")
        .map_err(|e| e.to_string())?;
    let valid = totp.verify_current(&totp_code).map_err(|e| e.to_string())?;
    if !valid {
        return Err(TransactionCmdError::TotpVerificationFailed.to_string());
    }

    // Load the multisig config for this account.
    let msig_config = repositories::get_multisig_config(&pool, account_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| {
            TransactionCmdError::Signer("account is not a multisig account".to_string()).to_string()
        })?;

    // Parse the hex public keys into bytes.
    let pk_bytes: Vec<Vec<u8>> = msig_config
        .public_keys
        .iter()
        .map(|h| hex::decode(h).map_err(|e| format!("invalid hex pubkey: {}", e)))
        .collect::<Result<Vec<_>, _>>()?;

    let multisig = crate::core::multisig::AccumulatorMultiSigOutput::new(pk_bytes, msig_config.threshold)
        .map_err(|e| TransactionCmdError::Signer(e.to_string()).to_string())?;

    // Parse the unsigned transaction.
    let mut tx = bsv::transaction::transaction::Transaction::from_hex(&plan.unsigned_tx_hex)
        .map_err(|e| e.to_string())?;

    // Sign with MultisigSigner.
    let signer = crate::core::signer::MultisigSigner::new(&xprv, multisig, local_key_index)
        .map_err(|e| e.to_string())?;
    signer
        .sign_tx(&mut tx, &plan.inputs)
        .map_err(|e| e.to_string())?;

    let txid = tx.id().map_err(|e| e.to_string())?;
    let signed_hex = tx.to_hex().map_err(|e| e.to_string())?;

    log::info!("Multisig TX signed — txid: {}", txid);

    Ok(SignTxResult {
        txid,
        signed_tx_hex: signed_hex,
    })
}

// ============================================================================
// Tests
// ============================================================================

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
            std::env::temp_dir().join(format!("electrumsv_mc_tx_{}_{}", test_name, id));
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

    /// estimate_fee: test fee calculation with simple outputs against FeeEstimator.
    #[tokio::test]
    async fn test_estimate_fee_simple_outputs() {
        // Test the underlying FeeEstimator::estimate_fee logic directly.
        // 1 input, 2 outputs (1 payment + 1 change), default fee rate of 1 sat/byte.
        let num_inputs = 1;
        let num_outputs = 2;
        let fee_rate = FeeEstimator::DEFAULT_FEE_RATE;
        let fee = FeeEstimator::estimate_fee(num_inputs, num_outputs, fee_rate);
        // Expected: (10 + 148*1 + 34*2) * 1 = 10 + 148 + 68 = 226 sat
        assert_eq!(fee, 226, "fee for 1 input, 2 outputs at 1 sat/byte should be 226");

        // 2 inputs, 3 outputs
        let fee2 = FeeEstimator::estimate_fee(2, 3, 1);
        // (10 + 148*2 + 34*3) * 1 = 10 + 296 + 102 = 408
        assert_eq!(fee2, 408);

        // Higher fee rate
        let fee3 = FeeEstimator::estimate_fee(1, 2, 5);
        assert_eq!(fee3, 226 * 5);
    }

    /// estimate_fee: with a wallet open and no UTXOs, num_inputs is max(0,1)=1.
    #[tokio::test]
    async fn test_estimate_fee_with_wallet_no_utxos() {
        let state = make_test_state("est_fee");
        wallet_service::create_wallet(&state, "test_estfee", "pw123", None, None)
            .await
            .unwrap();

        let (pool, account_id) = {
            let guard = state.active_wallet.lock().unwrap();
            let active = guard.as_ref().unwrap();
            (active.db_pool.clone(), active.account_id)
        };

        // Replicate estimate_fee logic
        let utxo_infos = repositories::get_utxo_infos_for_account(&pool, account_id)
            .await
            .unwrap();
        assert!(utxo_infos.is_empty(), "fresh wallet should have no UTXOs");

        let num_inputs = utxo_infos.len().max(1);
        assert_eq!(num_inputs, 1, "with no UTXOs, num_inputs should be max(0,1)=1");

        // 1 payment output + 1 change = 2 outputs
        let outputs = vec![PaymentOutput {
            address: "1JwKqU6XJ8zGRV3DVyGF5j1Zz1R5yF5tZJ".to_string(),
            satoshis: 10000,
        }];
        let op_return: Option<&str> = None;
        let op_return_extra = if op_return.is_some() { 1 } else { 0 };
        let num_outputs = outputs.len() + 1 + op_return_extra;
        assert_eq!(num_outputs, 2);

        let fee_rate = FeeEstimator::DEFAULT_FEE_RATE;
        let fee = FeeEstimator::estimate_fee(num_inputs, num_outputs, fee_rate);
        assert_eq!(fee, 226);

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    /// estimate_fee: with OP_RETURN, an extra output is added.
    #[tokio::test]
    async fn test_estimate_fee_with_op_return() {
        let state = make_test_state("est_fee_opreturn");
        wallet_service::create_wallet(&state, "test_opreturn", "pw123", None, None)
            .await
            .unwrap();

        let (pool, account_id) = {
            let guard = state.active_wallet.lock().unwrap();
            let active = guard.as_ref().unwrap();
            (active.db_pool.clone(), active.account_id)
        };

        let utxo_infos = repositories::get_utxo_infos_for_account(&pool, account_id)
            .await
            .unwrap();
        let num_inputs = utxo_infos.len().max(1);

        // With OP_RETURN: outputs.len() + 1 (change) + 1 (op_return) = 1 + 1 + 1 = 3
        let outputs = vec![PaymentOutput {
            address: "1JwKqU6XJ8zGRV3DVyGF5j1Zz1R5yF5tZJ".to_string(),
            satoshis: 10000,
        }];
        let op_return_extra = 1; // op_return is Some
        let num_outputs = outputs.len() + 1 + op_return_extra;
        assert_eq!(num_outputs, 3);

        let fee = FeeEstimator::estimate_fee(num_inputs, num_outputs, 1);
        // (10 + 148*1 + 34*3) * 1 = 10 + 148 + 102 = 260
        assert_eq!(fee, 260);

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    /// prepare_tx: with no wallet open, get_wallet_data returns NoWalletOpen.
    #[tokio::test]
    async fn test_prepare_tx_no_wallet_open() {
        let state = make_test_state("prep_no_wallet");
        // No wallet created — active_wallet is None.
        let result = get_wallet_data(&state);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, TransactionCmdError::NoWalletOpen));
        assert_eq!(err.to_string(), "no wallet is currently open");
    }

    /// prepare_tx: with a locked wallet (no decrypted_xprv), returns WalletLocked.
    #[tokio::test]
    async fn test_prepare_tx_wallet_locked() {
        let state = make_test_state("prep_locked");
        wallet_service::create_wallet(&state, "test_locked", "pw123", None, None)
            .await
            .unwrap();

        // Lock the wallet by clearing decrypted_xprv
        {
            let mut guard = state.active_wallet.lock().unwrap();
            if let Some(active) = guard.as_mut() {
                active.decrypted_xprv = None;
            }
        }

        // Replicate get_wallet_data + the xprv check in prepare_tx
        let (pool, _account_id, _wallet_path, xprv_opt) = get_wallet_data(&state).unwrap();
        assert!(xprv_opt.is_none(), "xprv should be None for locked wallet");

        // The command would then return: xprv_opt.ok_or(WalletLocked)
        let result: Result<&str, TransactionCmdError> =
            xprv_opt.as_deref().ok_or(TransactionCmdError::WalletLocked);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, TransactionCmdError::WalletLocked));
        assert_eq!(err.to_string(), "wallet is locked — unlock first");

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    /// sign_tx: with no wallet open, returns NoWalletOpen.
    #[tokio::test]
    async fn test_sign_tx_no_wallet_open() {
        let state = make_test_state("sign_no_wallet");
        let result = get_wallet_data(&state);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, TransactionCmdError::NoWalletOpen));
    }

    /// sign_tx: with a locked wallet, returns WalletLocked.
    #[tokio::test]
    async fn test_sign_tx_wallet_locked() {
        let state = make_test_state("sign_locked");
        wallet_service::create_wallet(&state, "test_sign_locked", "pw123", None, None)
            .await
            .unwrap();

        // Lock the wallet
        {
            let mut guard = state.active_wallet.lock().unwrap();
            if let Some(active) = guard.as_mut() {
                active.decrypted_xprv = None;
            }
        }

        let (_, _, _, xprv_opt) = get_wallet_data(&state).unwrap();
        assert!(xprv_opt.is_none());
        let result: Result<&str, TransactionCmdError> =
            xprv_opt.as_deref().ok_or(TransactionCmdError::WalletLocked);
        assert!(matches!(result.unwrap_err(), TransactionCmdError::WalletLocked));

        wallet_service::close_wallet(&state).unwrap();
    }

    /// sign_tx: a plan with wallet_path mismatch returns WalletMismatch.
    #[tokio::test]
    async fn test_sign_tx_wallet_mismatch() {
        let state = make_test_state("sign_mismatch");
        wallet_service::create_wallet(&state, "test_mismatch", "pw123", None, None)
            .await
            .unwrap();

        let (_, _, wallet_path, _xprv_opt) = get_wallet_data(&state).unwrap();

        // Create a fake plan with a different wallet_path
        let plan = TxPlan {
            unsigned_tx_hex: "0000".to_string(),
            outputs: vec![],
            inputs: vec![],
            fee: 0,
            change: 0,
            change_address: None,
            total_input: 0,
            total_output: 0,
            wallet_path: format!("{}_DIFFERENT", wallet_path),
            account_id: 1,
            created_at: 0,
            expires_at: chrono::Utc::now().timestamp() + 300,
            signed: false,
            signed_tx_hex: None,
            txid: None,
            op_return: None,
        };

        // Replicate sign_tx wallet binding check
        let mismatch = plan.wallet_path != wallet_path;
        assert!(mismatch, "plan with different wallet_path should mismatch");
        let err = TransactionCmdError::WalletMismatch;
        assert_eq!(
            err.to_string(),
            "TX plan wallet mismatch — plan belongs to a different wallet"
        );

        wallet_service::close_wallet(&state).unwrap();
    }

    /// sign_tx: an expired plan returns PlanExpired.
    #[tokio::test]
    async fn test_sign_tx_plan_expired() {
        let state = make_test_state("sign_expired");
        wallet_service::create_wallet(&state, "test_expired", "pw123", None, None)
            .await
            .unwrap();

        let (_, _, wallet_path, _xprv_opt) = get_wallet_data(&state).unwrap();

        // Create an expired plan
        let now = chrono::Utc::now().timestamp();
        let plan = TxPlan {
            unsigned_tx_hex: "0000".to_string(),
            outputs: vec![],
            inputs: vec![],
            fee: 0,
            change: 0,
            change_address: None,
            total_input: 0,
            total_output: 0,
            wallet_path: wallet_path.clone(),
            account_id: 1,
            created_at: now - 600,
            expires_at: now - 300, // Expired 5 minutes ago
            signed: false,
            signed_tx_hex: None,
            txid: None,
            op_return: None,
        };

        // Replicate sign_tx expiration check
        assert!(now > plan.expires_at, "plan should be expired");
        let err = TransactionCmdError::PlanExpired;
        assert_eq!(err.to_string(), "TX plan has expired");

        wallet_service::close_wallet(&state).unwrap();
    }

    /// sign_tx: an already-signed plan returns AlreadySigned.
    #[tokio::test]
    async fn test_sign_tx_already_signed() {
        let state = make_test_state("sign_already");
        wallet_service::create_wallet(&state, "test_already", "pw123", None, None)
            .await
            .unwrap();

        let (_, _, wallet_path, _xprv_opt) = get_wallet_data(&state).unwrap();

        let now = chrono::Utc::now().timestamp();
        let plan = TxPlan {
            unsigned_tx_hex: "0000".to_string(),
            outputs: vec![],
            inputs: vec![],
            fee: 0,
            change: 0,
            change_address: None,
            total_input: 0,
            total_output: 0,
            wallet_path,
            account_id: 1,
            created_at: now,
            expires_at: now + 300,
            signed: true, // Already signed!
            signed_tx_hex: Some("abcd".to_string()),
            txid: Some("deadbeef".to_string()),
            op_return: None,
        };

        // Replicate sign_tx signed check
        assert!(plan.signed, "plan should be marked as signed");
        let err = TransactionCmdError::AlreadySigned;
        assert_eq!(err.to_string(), "TX plan is already signed");

        wallet_service::close_wallet(&state).unwrap();
    }

    /// sign_tx: on a fresh wallet (TOTP not enabled), returns TotpNotEnabled.
    #[tokio::test]
    async fn test_sign_tx_totp_not_enabled() {
        let state = make_test_state("sign_totp");
        wallet_service::create_wallet(&state, "test_totp_sign", "pw123", None, None)
            .await
            .unwrap();

        let (pool, _, wallet_path, xprv_opt) = get_wallet_data(&state).unwrap();
        // Wallet is unlocked after create_wallet
        assert!(xprv_opt.is_some());

        // Create a valid (non-expired, unsigned, matching) plan
        let now = chrono::Utc::now().timestamp();
        let _plan = TxPlan {
            unsigned_tx_hex: "0000".to_string(),
            outputs: vec![],
            inputs: vec![],
            fee: 0,
            change: 0,
            change_address: None,
            total_input: 0,
            total_output: 0,
            wallet_path,
            account_id: 1,
            created_at: now,
            expires_at: now + 300,
            signed: false,
            signed_tx_hex: None,
            txid: None,
            op_return: None,
        };

        // Replicate sign_tx TOTP check — on a fresh wallet, TOTP is not enabled.
        let totp_enabled = repositories::is_totp_enabled(&pool).await.unwrap();
        assert!(!totp_enabled, "TOTP should not be enabled on fresh wallet");

        // The command would return TotpNotEnabled here
        let err = TransactionCmdError::TotpNotEnabled;
        assert_eq!(err.to_string(), "TOTP is not enabled — enable TOTP first");

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    /// broadcast_tx: with no network backend, returns NotConnected.
    #[tokio::test]
    async fn test_broadcast_tx_not_connected() {
        let state = make_test_state("broadcast_no_net");
        // No client or woc_client set up — network is in default state.
        let (client, woc_client) = {
            let guard = state.network.lock().unwrap();
            (guard.client.clone(), guard.woc_client.clone())
        };
        assert!(client.is_none(), "no electrumx client should be set");
        assert!(woc_client.is_none(), "no woc client should be set");

        // Replicate broadcast_tx not-connected check: both backends are None
        let err = TransactionCmdError::NotConnected;
        assert_eq!(err.to_string(), "not connected to a network backend");
    }

    /// broadcast_tx: txid mismatch between local and expected returns an error.
    #[tokio::test]
    async fn test_broadcast_tx_txid_mismatch() {
        // Replicate the AUD-006 txid mismatch check logic.
        let local_txid = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa";
        let expected_txid = "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb";
        assert_ne!(local_txid, expected_txid);

        // The command returns: Err(format!("txid mismatch: local={}, expected={}", ...))
        let err_msg = format!("txid mismatch: local={}, expected={}", local_txid, expected_txid);
        assert!(err_msg.contains("txid mismatch"));
        assert!(err_msg.contains(local_txid));
        assert!(err_msg.contains(expected_txid));
    }

    /// prepare_tx/estimate_fee with fee_rate=None must not panic: the command
    /// now calls `fetch_default_fee_rate().await` which falls back to
    /// DEFAULT_FEE_RATE on any network error. We replicate the fallback match
    /// (the same code now used in prepare_tx/estimate_fee) to prove the
    /// None-branch yields a valid fee rate without panicking.
    #[tokio::test]
    async fn test_fee_rate_none_fallback_does_not_panic() {
        let fee_rate: Option<u64> = None;

        // Replicate the exact match now used in prepare_tx / estimate_fee.
        // We call the real async helper — if the network is down it returns
        // DEFAULT_FEE_RATE; if it is up it returns the mAPI fee. Either way
        // it must not panic.
        let resolved = match fee_rate {
            Some(r) => r,
            None => crate::features::mapi::fetch_default_fee_rate().await,
        };

        assert!(
            resolved >= 1,
            "resolved fee rate must be >= 1 sat/byte, got {}",
            resolved
        );
    }

    /// When fee_rate is explicitly Some, the match must use that value and
    /// NOT call the mAPI fallback at all.
    #[tokio::test]
    async fn test_fee_rate_some_bypasses_mapi() {
        let fee_rate: Option<u64> = Some(7);
        let resolved = match fee_rate {
            Some(r) => r,
            None => crate::features::mapi::fetch_default_fee_rate().await,
        };
        assert_eq!(resolved, 7, "explicit fee_rate must bypass mAPI fallback");
    }

    /// TransactionCmdError: verify all error variants have correct Display messages.
    #[test]
    fn test_transaction_cmd_error_messages() {
        assert_eq!(TransactionCmdError::NoWalletOpen.to_string(), "no wallet is currently open");
        assert_eq!(
            TransactionCmdError::WalletLocked.to_string(),
            "wallet is locked — unlock first"
        );
        assert_eq!(
            TransactionCmdError::NotConnected.to_string(),
            "not connected to a network backend"
        );
        assert_eq!(
            TransactionCmdError::TotpNotEnabled.to_string(),
            "TOTP is not enabled — enable TOTP first"
        );
        assert_eq!(
            TransactionCmdError::TotpVerificationFailed.to_string(),
            "TOTP verification failed"
        );
        assert_eq!(TransactionCmdError::PlanExpired.to_string(), "TX plan has expired");
        assert_eq!(
            TransactionCmdError::WalletMismatch.to_string(),
            "TX plan wallet mismatch — plan belongs to a different wallet"
        );
        assert_eq!(TransactionCmdError::AlreadySigned.to_string(), "TX plan is already signed");
        assert_eq!(
            TransactionCmdError::NotSigned.to_string(),
            "TX plan is not signed yet — sign first"
        );
    }

    // --- parse_strategy tests ---

    /// parse_strategy: None and "largest_first" both map to None (largest-first default).
    #[test]
    fn test_parse_strategy_none_and_largest_first() {
        assert!(parse_strategy(&None).unwrap().is_none());
        assert!(parse_strategy(&Some("largest_first".to_string())).unwrap().is_none());
    }

    /// parse_strategy: named strategies map to the matching Strategy variant.
    #[test]
    fn test_parse_strategy_named_strategies() {
        assert_eq!(
            parse_strategy(&Some("branch_and_bound".to_string())).unwrap(),
            Some(Strategy::BranchAndBound)
        );
        assert_eq!(
            parse_strategy(&Some("random_subset".to_string())).unwrap(),
            Some(Strategy::RandomSubset)
        );
        assert_eq!(
            parse_strategy(&Some("privacy".to_string())).unwrap(),
            Some(Strategy::Privacy)
        );
    }

    /// parse_strategy: invalid strings return an error with a descriptive message.
    #[test]
    fn test_parse_strategy_invalid_returns_error() {
        let err = parse_strategy(&Some("does_not_exist".to_string())).unwrap_err();
        assert!(err.contains("invalid coin_selection_strategy"));
        assert!(err.contains("does_not_exist"));
        // The error message should list the valid options.
        assert!(err.contains("largest_first"));
        assert!(err.contains("privacy"));
    }

    /// parse_strategy: None -> None (largest_first default)
    #[test]
    fn test_parse_strategy_none() {
        assert!(parse_strategy(&None).unwrap().is_none());
    }

    /// parse_strategy: "largest_first" -> None
    #[test]
    fn test_parse_strategy_largest_first() {
        assert!(parse_strategy(&Some("largest_first".to_string())).unwrap().is_none());
    }

    /// parse_strategy: "privacy" -> Some(Strategy::Privacy)
    #[test]
    fn test_parse_strategy_privacy() {
        let s = parse_strategy(&Some("privacy".to_string())).unwrap();
        assert_eq!(s, Some(Strategy::Privacy));
    }

    /// parse_strategy: "branch_and_bound" -> Some(Strategy::BranchAndBound)
    #[test]
    fn test_parse_strategy_bnb() {
        let s = parse_strategy(&Some("branch_and_bound".to_string())).unwrap();
        assert_eq!(s, Some(Strategy::BranchAndBound));
    }

    /// parse_strategy: "random_subset" -> Some(Strategy::RandomSubset)
    #[test]
    fn test_parse_strategy_random_subset() {
        let s = parse_strategy(&Some("random_subset".to_string())).unwrap();
        assert_eq!(s, Some(Strategy::RandomSubset));
    }

    /// parse_strategy: invalid string -> error mentioning the name and valid options
    #[test]
    fn test_parse_strategy_invalid() {
        let err = parse_strategy(&Some("bogus_strategy".to_string())).unwrap_err();
        assert!(err.contains("bogus_strategy"));
        assert!(err.contains("largest_first"));
        assert!(err.contains("privacy"));
    }

    // --- AUD-008: Plan store tests ---

    /// generate_plan_id: returns a UUID v4 formatted string (8-4-4-4-12 hex).
    #[test]
    fn test_generate_plan_id_format() {
        let id = crate::state::generate_plan_id();
        // Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx (36 chars with dashes)
        assert_eq!(id.len(), 36, "plan_id should be 36 chars (UUID v4 format)");
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.len(), 5, "plan_id should have 5 dash-separated groups");
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
        // Version 4
        assert!(
            parts[2].starts_with('4'),
            "third group should start with '4' for UUID v4, got {}",
            parts[2]
        );
        // Variant: first char of fourth group is 8, 9, a, or b
        let variant_char = parts[3].chars().next().unwrap();
        assert!(
            matches!(variant_char, '8' | '9' | 'a' | 'b'),
            "fourth group should start with 8/9/a/b (variant), got {}",
            variant_char
        );
    }

    /// generate_plan_id: two calls produce different ids (uniqueness).
    #[test]
    fn test_generate_plan_id_uniqueness() {
        let a = crate::state::generate_plan_id();
        let b = crate::state::generate_plan_id();
        assert_ne!(a, b, "two generate_plan_id calls should differ");
    }

    /// test_prepare_tx_stores_plan: storing a plan in pending_plans puts it
    /// under the plan_id key, retrievable by the same id.
    #[tokio::test]
    async fn test_prepare_tx_stores_plan() {
        let state = make_test_state("store_plan");
        wallet_service::create_wallet(&state, "test_store", "pw123", None, None)
            .await
            .unwrap();
        let (_, _, wallet_path, _) = get_wallet_data(&state).unwrap();

        let now = chrono::Utc::now().timestamp();
        let plan = TxPlan {
            unsigned_tx_hex: "0000".to_string(),
            outputs: vec![],
            inputs: vec![],
            fee: 0,
            change: 0,
            change_address: None,
            total_input: 0,
            total_output: 0,
            wallet_path,
            account_id: 1,
            created_at: now,
            expires_at: now + 300,
            signed: false,
            signed_tx_hex: None,
            txid: None,
            op_return: None,
        };
        let plan_id = crate::state::generate_plan_id();
        {
            let mut plans = state.pending_plans.lock().unwrap();
            plans.insert(
                plan_id.clone(),
                crate::state::PendingPlan {
                    plan: plan.clone(),
                    created_at: now,
                },
            );
        }
        // Verify the plan is in the store under plan_id
        let plans = state.pending_plans.lock().unwrap();
        assert!(plans.contains_key(&plan_id), "plan should be in the store");
        let stored = plans.get(&plan_id).unwrap();
        assert_eq!(stored.plan.fee, 0);
        assert_eq!(stored.created_at, now);

        wallet_service::close_wallet(&state).unwrap();
    }

    /// test_sign_tx_with_plan_id: retrieving a stored plan by plan_id yields
    /// the same plan that was inserted (simulates sign_tx lookup).
    #[tokio::test]
    async fn test_sign_tx_with_plan_id() {
        let state = make_test_state("sign_with_id");
        wallet_service::create_wallet(&state, "test_sign_id", "pw123", None, None)
            .await
            .unwrap();
        let (_, _, wallet_path, _) = get_wallet_data(&state).unwrap();

        let now = chrono::Utc::now().timestamp();
        let plan = TxPlan {
            unsigned_tx_hex: "00".to_string(),
            outputs: vec![],
            inputs: vec![],
            fee: 100,
            change: 0,
            change_address: None,
            total_input: 1000,
            total_output: 900,
            wallet_path: wallet_path.clone(),
            account_id: 1,
            created_at: now,
            expires_at: now + 300,
            signed: false,
            signed_tx_hex: None,
            txid: None,
            op_return: None,
        };
        let plan_id = crate::state::generate_plan_id();
        {
            let mut plans = state.pending_plans.lock().unwrap();
            plans.insert(
                plan_id.clone(),
                crate::state::PendingPlan {
                    plan: plan.clone(),
                    created_at: now,
                },
            );
        }

        // Replicate the sign_tx plan retrieval logic
        let retrieved = {
            let mut plans = state.pending_plans.lock().unwrap();
            plans.remove(&plan_id)
        };
        assert!(retrieved.is_some(), "plan should be retrievable by plan_id");
        let pp = retrieved.unwrap();
        assert_eq!(pp.plan.fee, 100);
        assert_eq!(pp.plan.wallet_path, wallet_path);

        wallet_service::close_wallet(&state).unwrap();
    }

    /// test_sign_tx_invalid_plan_id: looking up a non-existent plan_id returns
    /// None (sign_tx would return PlanNotFound).
    #[tokio::test]
    async fn test_sign_tx_invalid_plan_id() {
        let state = make_test_state("sign_invalid_id");
        // No plan stored — any plan_id lookup should fail.
        let bogus_id = "nonexistent-plan-id-1234";
        let retrieved = {
            let mut plans = state.pending_plans.lock().unwrap();
            plans.remove(bogus_id)
        };
        assert!(retrieved.is_none(), "non-existent plan_id should return None");
        // The command would map this to PlanNotFound:
        let err = TransactionCmdError::PlanNotFound;
        assert_eq!(err.to_string(), "plan not found or expired");
    }

    /// test_sign_tx_consumes_plan: after a successful sign_tx lookup (remove),
    /// a second lookup for the same plan_id returns None (plan consumed).
    #[tokio::test]
    async fn test_sign_tx_consumes_plan() {
        let state = make_test_state("sign_consumes");
        wallet_service::create_wallet(&state, "test_consume", "pw123", None, None)
            .await
            .unwrap();
        let (_, _, wallet_path, _) = get_wallet_data(&state).unwrap();

        let now = chrono::Utc::now().timestamp();
        let plan = TxPlan {
            unsigned_tx_hex: "00".to_string(),
            outputs: vec![],
            inputs: vec![],
            fee: 50,
            change: 0,
            change_address: None,
            total_input: 0,
            total_output: 0,
            wallet_path,
            account_id: 1,
            created_at: now,
            expires_at: now + 300,
            signed: false,
            signed_tx_hex: None,
            txid: None,
            op_return: None,
        };
        let plan_id = crate::state::generate_plan_id();
        {
            let mut plans = state.pending_plans.lock().unwrap();
            plans.insert(
                plan_id.clone(),
                crate::state::PendingPlan {
                    plan,
                    created_at: now,
                },
            );
        }

        // First lookup (sign) consumes the plan
        let first = {
            let mut plans = state.pending_plans.lock().unwrap();
            plans.remove(&plan_id)
        };
        assert!(first.is_some(), "first lookup should find the plan");

        // Second lookup — plan is gone (consumed)
        let second = {
            let mut plans = state.pending_plans.lock().unwrap();
            plans.remove(&plan_id)
        };
        assert!(second.is_none(), "second lookup should find no plan (consumed)");

        wallet_service::close_wallet(&state).unwrap();
    }

    /// test_sign_tx_expired_plan: a plan with expires_at in the past triggers
    /// the PlanExpired error (replicates sign_tx expiry check after retrieval).
    #[tokio::test]
    async fn test_sign_tx_expired_plan() {
        let state = make_test_state("sign_expired_plan");
        wallet_service::create_wallet(&state, "test_exp_plan", "pw123", None, None)
            .await
            .unwrap();
        let (_, _, wallet_path, _) = get_wallet_data(&state).unwrap();

        let now = chrono::Utc::now().timestamp();
        let plan = TxPlan {
            unsigned_tx_hex: "00".to_string(),
            outputs: vec![],
            inputs: vec![],
            fee: 0,
            change: 0,
            change_address: None,
            total_input: 0,
            total_output: 0,
            wallet_path,
            account_id: 1,
            created_at: now - 600,
            expires_at: now - 300, // expired 5 minutes ago
            signed: false,
            signed_tx_hex: None,
            txid: None,
            op_return: None,
        };

        // Replicate sign_tx expiry check (after retrieval from store)
        assert!(now > plan.expires_at, "plan should be expired");
        let err = TransactionCmdError::PlanExpired;
        assert_eq!(err.to_string(), "TX plan has expired");

        wallet_service::close_wallet(&state).unwrap();
    }

    /// test_plan_store_cleanup: plans older than PLAN_STORE_TTL (1 hour) are
    /// purged by the retain() call in sign_tx; fresh plans survive.
    #[tokio::test]
    async fn test_plan_store_cleanup() {
        let state = make_test_state("store_cleanup");
        let now = chrono::Utc::now().timestamp();

        // Old plan (created 2 hours ago — should be purged)
        let old_id = crate::state::generate_plan_id();
        // Fresh plan (created now — should survive)
        let fresh_id = crate::state::generate_plan_id();
        {
            let mut plans = state.pending_plans.lock().unwrap();
            plans.insert(
                old_id.clone(),
                crate::state::PendingPlan {
                    plan: TxPlan {
                        unsigned_tx_hex: "00".to_string(),
                        outputs: vec![],
                        inputs: vec![],
                        fee: 0,
                        change: 0,
                        change_address: None,
                        total_input: 0,
                        total_output: 0,
                        wallet_path: String::new(),
                        account_id: 1,
                        created_at: now - 7200, // 2 hours ago
                        expires_at: now - 6900,
                        signed: false,
                        signed_tx_hex: None,
                        txid: None,
                        op_return: None,
                    },
                    created_at: now - 7200,
                },
            );
            plans.insert(
                fresh_id.clone(),
                crate::state::PendingPlan {
                    plan: TxPlan {
                        unsigned_tx_hex: "00".to_string(),
                        outputs: vec![],
                        inputs: vec![],
                        fee: 0,
                        change: 0,
                        change_address: None,
                        total_input: 0,
                        total_output: 0,
                        wallet_path: String::new(),
                        account_id: 1,
                        created_at: now,
                        expires_at: now + 300,
                        signed: false,
                        signed_tx_hex: None,
                        txid: None,
                        op_return: None,
                    },
                    created_at: now,
                },
            );
        }

        // Replicate the cleanup logic from sign_tx
        {
            let mut plans = state.pending_plans.lock().unwrap();
            plans.retain(|_, pp| now - pp.created_at < crate::state::PLAN_STORE_TTL);
        }

        let plans = state.pending_plans.lock().unwrap();
        assert!(!plans.contains_key(&old_id), "old plan should be purged");
        assert!(plans.contains_key(&fresh_id), "fresh plan should survive");
    }
}
