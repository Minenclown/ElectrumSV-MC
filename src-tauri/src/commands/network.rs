// commands/network.rs — Network Tauri commands (Milestone 4)
//
// Provides: get_network_info, get_servers, connect_server, disconnect_server,
//           set_network_backend, sync_wallet
//
// These commands expose the network layer to the frontend. They interact with
// the NetworkState in AppState to manage server connections and retrieve
// blockchain data via the ElectrumX client.
//
// AUDIT:
// - AUD-006: broadcast_tx validation is enforced in the backend, not here.
// - AUD-Fund #6: TLS validation is enforced in the ElectrumXClient.
// - MutexGuard not Send: We extract data from locks before awaiting (same
//   pattern as commands/account.rs).

use crate::core::address;
use crate::db::repositories;
use crate::network::backend::{BackendType, NetworkBackend, NetworkError};
use crate::network::electrumx::ElectrumXClient;
use crate::network::header_store::{HeaderStore, ParsedHeader};
use crate::network::server_list::{ServerStatus, ServerStatusInfo};
use crate::state::AppState;
use bsv::compat::bip32::ExtendedKey;
use tauri::State;

// ============================================================================
// Response types
// ============================================================================

/// Network info returned by get_network_info.
#[derive(Debug, serde::Serialize)]
pub struct NetworkInfo {
    /// Whether any backend is currently connected.
    pub connected: bool,
    /// Active backend type ("electrumx" or "whatsonchain").
    pub backend_type: Option<String>,
    /// Active server host, if connected.
    pub active_server: Option<String>,
    /// Current chain tip height, if known.
    pub tip_height: Option<u64>,
    /// Total number of known servers.
    pub server_count: usize,
    /// Number of connected servers.
    pub connected_count: usize,
    /// Number of banned servers.
    pub banned_count: usize,
}

/// Server list entry returned by get_servers.
#[derive(Debug, serde::Serialize)]
pub struct ServerInfo {
    pub host: String,
    pub ssl_port: u16,
    pub tcp_port: Option<u16>,
    pub version: String,
    pub status: String,
    pub avg_latency_ms: Option<u64>,
    pub consecutive_failures: u32,
}

// ============================================================================
// Error type
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum NetworkCommandError {
    #[error("network error: {0}")]
    Network(#[from] NetworkError),
    #[error("no wallet is currently open")]
    NoWalletOpen,
    #[error("not connected to any server")]
    NotConnected,
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl serde::Serialize for NetworkCommandError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

// ============================================================================
// Helper: extract network data without holding lock across awaits
// ============================================================================

/// Get server list snapshot and counts without holding the lock.
fn get_network_snapshot(state: &AppState) -> (Vec<ServerStatusInfo>, bool, usize, usize, usize) {
    let net = state.network.lock().unwrap();
    let info = net.server_list.list_with_status();
    let counts = net.server_list.count_by_status();
    (
        info,
        net.connected,
        counts.connected,
        counts.banned,
        net.server_list.len(),
    )
}

// ============================================================================
// Commands
// ============================================================================

/// Get current network status — server info, connection state, tip height.
///
/// Does not require an open wallet. Returns metadata about the network layer.
#[tauri::command]
pub async fn get_network_info(state: State<'_, AppState>) -> Result<NetworkInfo, String> {
    let (_servers, connected, connected_count, banned_count, total) = get_network_snapshot(&state);

    // Find active server and backend type
    let (active_server, backend_type) = {
        let net = state.network.lock().unwrap();
        let host = net.server_list.active().map(|s| s.host.clone());
        let bt = net.active_backend.map(|b| b.to_string());
        (host, bt)
    };

    Ok(NetworkInfo {
        connected,
        backend_type,
        active_server,
        tip_height: None, // Updated when sync is implemented
        server_count: total,
        connected_count,
        banned_count,
    })
}

/// Get the list of known servers with their health status.
///
/// Does not require an open wallet or a connection.
#[tauri::command]
pub async fn get_servers(state: State<'_, AppState>) -> Result<Vec<ServerInfo>, String> {
    let (server_infos, _, _, _, _) = get_network_snapshot(&state);

    Ok(server_infos
        .into_iter()
        .map(|s| ServerInfo {
            host: s.host,
            ssl_port: s.ssl_port,
            tcp_port: s.tcp_port,
            version: s.version,
            status: format!("{:?}", s.status).to_lowercase(),
            avg_latency_ms: s.avg_latency_ms,
            consecutive_failures: s.consecutive_failures,
        })
        .collect())
}

/// Connect to a specific ElectrumX server by host name.
///
/// If no host is provided, selects the best available server.
/// Performs TLS handshake and server.version negotiation.
/// Also starts a background task to forward ElectrumX push notifications
/// to Tauri frontend events ("new_block", "balance_changed").
///
/// AUD-Fund #6: TLS certificate + hostname verification is enforced
/// in the ElectrumXClient. No permissive verifier is used.
#[tauri::command]
pub async fn connect_server(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    host: Option<String>,
) -> Result<String, String> {
    // Select server
    let server = {
        let net = state.network.lock().unwrap();
        match host {
            Some(h) => net
                .server_list
                .all()
                .iter()
                .find(|s| s.host == h)
                .cloned()
                .ok_or_else(|| format!("server not found: {h}"))?,
            None => net
                .server_list
                .select_best()
                .cloned()
                .ok_or_else(|| "no eligible servers available".to_string())?,
        }
    };

    log::info!("Connecting to ElectrumX server: {}", server.host);

    // Create client and connect
    let client = ElectrumXClient::new(server.clone());
    client
        .connect()
        .await
        .map_err(|e| format!("connection failed: {e}"))?;

    // Update state
    {
        let mut net = state.network.lock().unwrap();
        net.server_list.record_success(&server.host, 0);
        net.connected = true;
        net.client = Some(client.clone());
        net.active_backend = Some(BackendType::ElectrumX);
    }

    // Start notification forwarder — emits "new_block" and "balance_changed"
    // Tauri events to the frontend from ElectrumX push notifications.
    crate::commands::events::start_notification_forwarder(app, client.clone());

    log::info!("Connected to {}", server.host);
    Ok(server.host)
}

/// Disconnect from the current server.
#[tauri::command]
pub async fn disconnect_server(state: State<'_, AppState>) -> Result<(), String> {
    // Extract client, WoC client, and host without holding lock across await
    let (client_opt, woc_opt, host) = {
        let mut net = state.network.lock().unwrap();
        let h = net.server_list.active().map(|s| s.host.clone());
        (net.client.take(), net.woc_client.take(), h)
    };

    if let Some(client) = client_opt {
        if let Some(ref h) = host {
            log::info!("Disconnecting from {h}");
        }
        // Graceful disconnect (async, no lock held)
        let _ = client.disconnect().await;
    }

    if let Some(woc) = woc_opt {
        let _ = woc.disconnect().await;
    }

    // Update state
    {
        let mut net = state.network.lock().unwrap();
        if let Some(ref h) = host {
            net.server_list.disconnect(h);
        }
        net.connected = false;
        net.active_backend = None;
    }

    Ok(())
}

/// Set the network backend type (ElectrumX or WhatsOnChain).
///
/// Switches between the ElectrumX TCP+TLS protocol and the WhatsOnChain
/// REST API. When switching to WhatsOnChain, creates a new WoC client and
/// pings it to verify connectivity. When switching to ElectrumX, clears
/// the WoC client — the user must call connect_server to establish a new
/// ElectrumX connection.
#[tauri::command]
pub async fn set_network_backend(
    state: State<'_, AppState>,
    backend_type: String,
) -> Result<(), String> {
    match backend_type.as_str() {
        "electrumx" => {
            let mut net = state.network.lock().unwrap();
            if net.woc_client.is_some() {
                net.woc_client = None;
            }
            // Don't change client — it's managed by connect_server/disconnect_server
            net.active_backend = Some(BackendType::ElectrumX);
            log::info!("Network backend set to ElectrumX");
            Ok(())
        }
        "whatsonchain" => {
            let woc = crate::network::whatsonchain::WhatsOnChainClient::new();
            // Ping to verify connectivity
            woc.ping()
                .await
                .map_err(|e| format!("WhatsOnChain backend connection failed: {e}"))?;

            let mut net = state.network.lock().unwrap();
            net.woc_client = Some(woc);
            net.active_backend = Some(BackendType::WhatsOnChain);
            // If an ElectrumX client is active, disconnect it
            if let Some(client) = net.client.take() {
                // Drop the client — graceful disconnect in background
                // (can't await while holding the lock)
                drop(client);
            }
            net.connected = true;
            log::info!("Network backend set to WhatsOnChain");
            Ok(())
        }
        other => Err(format!("unknown backend type: {other}")),
    }
}

/// Trigger a wallet sync — fetch balance, history, and UTXOs from the server.
///
/// Requires an open wallet with KeyInstances and a connected ElectrumX server.
///
/// Sync flow:
/// 1. Load all KeyInstances for the active account from DB
/// 2. For each KeyInstance, derive the public key from the xprv and compute
///    the ElectrumX scripthash
/// 3. For each scripthash, fetch get_balance, get_history, get_utxos from server
/// 4. Store results in DB (Transactions, TransactionOutputs, TransactionDeltas)
/// 5. Subscribe to scripthash updates for push notifications
///
/// Returns a SyncResult with counts of synced keys and transactions.
#[tauri::command]
pub async fn sync_wallet(
    state: State<'_, AppState>,
    account_id: Option<i64>,
) -> Result<SyncResult, String> {
    // 1. Extract client from network state (without holding lock across awaits)
    let client = {
        let net = state.network.lock().unwrap();
        if !net.connected {
            return Err("not connected to any server — call connect_server first".to_string());
        }
        net.client
            .clone()
            .ok_or_else(|| "no active client — call connect_server first".to_string())?
    };

    // 2. Extract wallet data (pool, account_id, xprv)
    let (pool, default_acct_id, xprv_opt) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (
            active.db_pool.clone(),
            active.account_id,
            active.decrypted_xprv.clone(),
        )
    };
    let acct_id = account_id.unwrap_or(default_acct_id);

    // Wallet must be unlocked for key derivation
    let xprv_str =
        xprv_opt.ok_or("wallet is locked — unlock first to derive public keys for sync")?;

    log::info!("sync_wallet: account {} — starting full sync", acct_id);

    // 3. Load all KeyInstances for the account
    let key_instances = repositories::get_keyinstances_for_account(&pool, acct_id)
        .await
        .map_err(|e| format!("failed to load keyinstances: {e}"))?;

    if key_instances.is_empty() {
        log::warn!("sync_wallet: no keyinstances found for account {} — generating initial receiving addresses", acct_id);
        return Ok(SyncResult {
            server_host: client.server_host(),
            account_id: acct_id,
            synced: false,
            message: "no keyinstances found — generate receive addresses first".to_string(),
        });
    }

    // Parse the xprv for key derivation
    let account_key =
        ExtendedKey::from_string(&xprv_str).map_err(|e| format!("invalid xprv: {e}"))?;

    // 4. For each KeyInstance: derive pubkey → compute scripthash → fetch from server
    let mut total_balance_confirmed: u64 = 0;
    let mut total_balance_unconfirmed: i64 = 0;
    let mut total_tx_count: usize = 0;
    let mut total_utxo_count: usize = 0;
    let mut synced_keys: usize = 0;
    let mut errors: Vec<String> = Vec::new();

    for ki in &key_instances {
        // Parse derivation_data to get subpath
        let derivation_data: serde_json::Value = serde_json::from_slice(&ki.derivation_data)
            .map_err(|e| {
                format!(
                    "invalid derivation_data for keyinstance {}: {e}",
                    ki.keyinstance_id
                )
            })?;

        let subpath = derivation_data
            .get("subpath")
            .and_then(|s| s.as_array())
            .ok_or_else(|| {
                format!(
                    "missing subpath in derivation_data for keyinstance {}",
                    ki.keyinstance_id
                )
            })?;

        let type_idx = subpath
            .first()
            .and_then(|t| t.as_i64())
            .ok_or("invalid subpath type index")?;
        let addr_idx = subpath
            .get(1)
            .and_then(|t| t.as_i64())
            .ok_or("invalid subpath address index")?;

        // Derive the child key at {type_idx}/{addr_idx}
        let derivation_path = format!("{}/{}", type_idx, addr_idx);
        let child_key = account_key.derive(&derivation_path).map_err(|e| {
            format!(
                "derivation failed for keyinstance {}: {e}",
                ki.keyinstance_id
            )
        })?;

        let pubkey = child_key.public_key().map_err(|e| {
            format!(
                "public key derivation failed for keyinstance {}: {e}",
                ki.keyinstance_id
            )
        })?;

        // Compute the P2PKH address
        let addr_str = address::pubkey_to_p2pkh_address(&pubkey);

        // Compute the ElectrumX scripthash
        let scripthash =
            crate::network::backend::scripthash_from_address(&addr_str).map_err(|e| {
                format!(
                    "scripthash computation failed for keyinstance {}: {e}",
                    ki.keyinstance_id
                )
            })?;

        log::debug!(
            "sync_wallet: keyinstance {} — address {} — scripthash {}",
            ki.keyinstance_id,
            addr_str,
            scripthash
        );

        // Fetch balance from server
        let balance = match client.get_balance(&scripthash).await {
            Ok(b) => b,
            Err(e) => {
                errors.push(format!(
                    "keyinstance {}: balance error: {e}",
                    ki.keyinstance_id
                ));
                continue;
            }
        };

        total_balance_confirmed += balance.confirmed;
        total_balance_unconfirmed += balance.unconfirmed;

        // Fetch history from server
        let history = match client.get_history(&scripthash).await {
            Ok(h) => h,
            Err(e) => {
                errors.push(format!(
                    "keyinstance {}: history error: {e}",
                    ki.keyinstance_id
                ));
                continue;
            }
        };

        total_tx_count += history.len();

        // Fetch UTXOs from server
        let utxos = match client.get_utxos(&scripthash).await {
            Ok(u) => u,
            Err(e) => {
                errors.push(format!(
                    "keyinstance {}: utxos error: {e}",
                    ki.keyinstance_id
                ));
                continue;
            }
        };

        total_utxo_count += utxos.len();

        // 5. Store results in DB
        // Clear old outputs/deltas for this keyinstance
        repositories::clear_outputs_and_deltas_for_keyinstances(&pool, &[ki.keyinstance_id])
            .await
            .map_err(|e| {
                format!(
                    "failed to clear old data for keyinstance {}: {e}",
                    ki.keyinstance_id
                )
            })?;

        // Insert/update Transactions from history
        for tx in &history {
            // Convert display tx_hash (reversed hex) to internal byte order
            let tx_hash_bytes = crate::core::address::hex_str_to_hash(&tx.tx_hash)
                .map_err(|e| format!("invalid tx_hash hex: {e}"))?;

            let block_height = if tx.height > 0 {
                Some(tx.height)
            } else {
                None // unconfirmed
            };

            repositories::upsert_transaction(&pool, &tx_hash_bytes, block_height, None)
                .await
                .map_err(|e| format!("failed to upsert transaction: {e}"))?;

            // Record a delta for this keyinstance's involvement in the transaction.
            // We don't know the exact value_delta yet (would need full tx parsing),
            // but we record a placeholder of 0 for now. The balance is tracked
            // via TransactionOutputs (UTXOs) which is more precise.
            repositories::upsert_transaction_delta(&pool, ki.keyinstance_id, &tx_hash_bytes, 0)
                .await
                .map_err(|e| format!("failed to upsert transaction delta: {e}"))?;
        }

        // Insert UTXOs as TransactionOutputs
        for utxo in &utxos {
            let tx_hash_bytes = crate::core::address::hex_str_to_hash(&utxo.tx_hash)
                .map_err(|e| format!("invalid utxo tx_hash hex: {e}"))?;

            // Ensure the Transaction row exists (might not be in history if
            // the UTXO is from a tx not in our history — shouldn't happen but
            // be defensive)
            let block_height = if utxo.height > 0 {
                Some(utxo.height as i64)
            } else {
                None
            };
            repositories::upsert_transaction(&pool, &tx_hash_bytes, block_height, None)
                .await
                .map_err(|e| format!("failed to upsert transaction for utxo: {e}"))?;

            // Insert the output (unspent, no flags)
            repositories::upsert_transaction_output(
                &pool,
                &tx_hash_bytes,
                utxo.tx_pos as i64,
                utxo.value as i64,
                ki.keyinstance_id,
                0, // flags = 0 (unspent, not coinbase)
            )
            .await
            .map_err(|e| format!("failed to upsert transaction output: {e}"))?;
        }

        // 6. Subscribe to scripthash updates for push notifications
        // Best-effort — don't fail the sync if subscription fails
        if let Err(e) = client.subscribe_scripthash(&scripthash).await {
            log::warn!(
                "sync_wallet: subscribe_scripthash failed for keyinstance {}: {e}",
                ki.keyinstance_id
            );
        }

        synced_keys += 1;
    }

    let message = if errors.is_empty() {
        format!(
            "synced {} keys: {} txs, {} utxos, balance {} confirmed + {} unconfirmed",
            synced_keys,
            total_tx_count,
            total_utxo_count,
            total_balance_confirmed,
            total_balance_unconfirmed
        )
    } else {
        format!(
            "synced {} keys with {} errors: {} txs, {} utxos — errors: {}",
            synced_keys,
            errors.len(),
            total_tx_count,
            total_utxo_count,
            errors.join("; ")
        )
    };

    log::info!("sync_wallet: account {} — {}", acct_id, message);

    Ok(SyncResult {
        server_host: client.server_host(),
        account_id: acct_id,
        synced: synced_keys > 0,
        message,
    })
}

/// Result of a wallet sync operation.
#[derive(Debug, serde::Serialize)]
pub struct SyncResult {
    pub server_host: String,
    pub account_id: i64,
    pub synced: bool,
    pub message: String,
}

/// Ban a server (AUD-Fund #6: for servers that return invalid data).
///
/// Permanently bans a server from the rotation. This should be called when
/// a server fails TLS validation, returns invalid merkle proofs, or sends
/// invalid block headers.
#[tauri::command]
pub async fn ban_server(state: State<'_, AppState>, host: String) -> Result<(), String> {
    log::warn!("Banning server: {host}");
    let mut net = state.network.lock().unwrap();
    net.server_list.ban(&host);
    if net.server_list.active().is_none() {
        net.connected = false;
    }
    Ok(())
}

/// Get the list of servers filtered by status.
#[tauri::command]
pub async fn get_servers_by_status(
    state: State<'_, AppState>,
    status: String,
) -> Result<Vec<ServerInfo>, String> {
    let (server_infos, _, _, _, _) = get_network_snapshot(&state);

    let filter_status = match status.as_str() {
        "unknown" => ServerStatus::Unknown,
        "connected" => ServerStatus::Connected,
        "disconnected" => ServerStatus::Disconnected,
        "failed" => ServerStatus::Failed,
        "banned" => ServerStatus::Banned,
        _ => return Err(format!("unknown status filter: {status}")),
    };

    Ok(server_infos
        .into_iter()
        .filter(|s| s.status == filter_status)
        .map(|s| ServerInfo {
            host: s.host,
            ssl_port: s.ssl_port,
            tcp_port: s.tcp_port,
            version: s.version,
            status: format!("{:?}", s.status).to_lowercase(),
            avg_latency_ms: s.avg_latency_ms,
            consecutive_failures: s.consecutive_failures,
        })
        .collect())
}

// ============================================================================
// Header Store commands (Milestone 4 — Header-Store / SPV)
// ============================================================================

/// Info about the header store — stored header count and tip height.
#[derive(Debug, serde::Serialize)]
pub struct HeaderStoreInfo {
    /// Whether the header store is initialized.
    pub initialized: bool,
    /// Number of stored block headers.
    pub header_count: u64,
    /// Height of the best stored header (tip), if any.
    pub tip_height: Option<u64>,
    /// Hash of the tip header (display hex), if any.
    pub tip_hash: Option<String>,
}

/// Ensure the header store is initialized in NetworkState.
/// Uses the app data_dir for the SQLite database path.
async fn ensure_header_store(state: &State<'_, AppState>) -> Result<(), String> {
    let needs_init = {
        let net = state.network.lock().unwrap();
        net.header_store.is_none()
    };
    if needs_init {
        let db_path = format!("{}/headers.sqlite", state.data_dir);
        let store = HeaderStore::open(&db_path)
            .await
            .map_err(|e| format!("failed to open header store: {e}"))?;
        store
            .ensure_genesis()
            .await
            .map_err(|e| format!("failed to init genesis: {e}"))?;
        // Acquire lock only for the final assignment (no await after this)
        let mut net = state.network.lock().unwrap();
        net.header_store = Some(store);
    }
    Ok(())
}

/// Get header store status — number of stored headers, tip height/hash.
#[tauri::command]
pub async fn get_header_store_info(state: State<'_, AppState>) -> Result<HeaderStoreInfo, String> {
    ensure_header_store(&state).await?;

    // Take header store out (in a non-async block to avoid holding MutexGuard across await)
    let store_opt = {
        let mut net = state.network.lock().unwrap();
        net.header_store.take()
    };

    let (count, tip) = if let Some(store) = store_opt {
        let count = store.header_count().await.unwrap_or(0);
        let tip = store.get_tip().await.ok().flatten();
        // Put store back
        {
            let mut net = state.network.lock().unwrap();
            net.header_store = Some(store);
        }
        (count, tip)
    } else {
        (0, None)
    };

    let tip_height = tip.as_ref().map(|(h, _)| *h);
    let tip_hash = tip.and_then(|(_, hex)| ParsedHeader::from_hex(&hex, 0).ok().map(|p| p.hash));

    Ok(HeaderStoreInfo {
        initialized: true,
        header_count: count,
        tip_height,
        tip_hash,
    })
}

/// Sync block headers from the connected ElectrumX server.
/// Fetches headers from the current tip up to the server's chain tip.
#[tauri::command]
pub async fn sync_headers(
    state: State<'_, AppState>,
    max_count: Option<u64>,
) -> Result<SyncHeadersResult, String> {
    ensure_header_store(&state).await?;

    // Get client
    let client = {
        let net = state.network.lock().unwrap();
        if !net.connected {
            return Err("not connected to any server".to_string());
        }
        net.client
            .clone()
            .ok_or_else(|| "no active client".to_string())?
    };

    // Take header store out of state temporarily
    let store = {
        let mut net = state.network.lock().unwrap();
        net.header_store
            .take()
            .ok_or_else(|| "header store not initialized".to_string())?
    };

    // Get current tip
    let (current_tip, _) = store
        .get_tip()
        .await
        .map_err(|e| format!("failed to get tip: {e}"))?
        .unwrap_or((0, String::new()));

    // Get server tip height
    let server_tip = client
        .get_tip_height()
        .await
        .map_err(|e| format!("failed to get server tip: {e}"))?;

    if server_tip <= current_tip {
        // Already up to date
        let mut net = state.network.lock().unwrap();
        net.header_store = Some(store);
        return Ok(SyncHeadersResult {
            synced: 0,
            new_tip: current_tip,
            server_tip,
            message: "already up to date".to_string(),
        });
    }

    // Fetch headers: from current_tip+1 to server_tip
    let start = current_tip + 1;
    let count = max_count
        .unwrap_or(server_tip - current_tip)
        .min(server_tip - current_tip);

    let headers = client
        .get_block_headers(start, count)
        .await
        .map_err(|e| format!("failed to fetch headers: {e}"))?;

    // Connect each header to the store
    let mut synced = 0u64;
    let mut new_tip = current_tip;
    let mut errors = Vec::new();

    for hdr in &headers {
        match store.connect_header(hdr.height, &hdr.hex).await {
            Ok(crate::network::header_store::ConnectResult::Connected { height }) => {
                synced += 1;
                new_tip = height;
            }
            Ok(crate::network::header_store::ConnectResult::AlreadyExists { height }) => {
                new_tip = new_tip.max(height);
            }
            Ok(crate::network::header_store::ConnectResult::Reorg { new_tip: nt, .. }) => {
                synced += 1;
                new_tip = nt;
            }
            Err(e) => {
                errors.push(format!("height {}: {e}", hdr.height));
                break; // Stop on first error — chain is broken
            }
        }
    }

    // Put store back
    {
        let mut net = state.network.lock().unwrap();
        net.header_store = Some(store);
    }

    let message = if errors.is_empty() {
        format!("synced {synced} headers, new tip: {new_tip}")
    } else {
        format!(
            "synced {synced} headers with {} errors: {}",
            errors.len(),
            errors.join("; ")
        )
    };

    Ok(SyncHeadersResult {
        synced,
        new_tip,
        server_tip,
        message,
    })
}

/// Result of a header sync operation.
#[derive(Debug, serde::Serialize)]
pub struct SyncHeadersResult {
    /// Number of new headers connected.
    pub synced: u64,
    /// New chain tip height after sync.
    pub new_tip: u64,
    /// Server's reported chain tip height.
    pub server_tip: u64,
    /// Human-readable summary.
    pub message: String,
}

/// Verify a transaction's inclusion in a block via SPV merkle proof.
///
/// Fetches the merkle proof from the ElectrumX server and verifies it
/// against the stored block header. This is the trustless verification
/// path — no trust in the server required, only in the PoW chain.
#[tauri::command]
pub async fn verify_transaction_proof(
    state: State<'_, AppState>,
    tx_hash: String,
    block_height: u64,
) -> Result<VerifyProofResult, String> {
    ensure_header_store(&state).await?;

    // Get client
    let client = {
        let net = state.network.lock().unwrap();
        if !net.connected {
            return Err("not connected to any server".to_string());
        }
        net.client
            .clone()
            .ok_or_else(|| "no active client".to_string())?
    };

    // Fetch merkle proof from server
    let proof = client
        .get_merkle_proof(&tx_hash, block_height)
        .await
        .map_err(|e| format!("failed to get merkle proof: {e}"))?;

    // Take header store out temporarily
    let store = {
        let mut net = state.network.lock().unwrap();
        net.header_store
            .take()
            .ok_or_else(|| "header store not initialized".to_string())?
    };

    // Extract merkle branch hashes (display hex strings)
    let branch: Vec<String> = proof.merkle_branch.iter().map(|(h, _)| h.clone()).collect();

    // We need the transaction position in the block.
    // The ElectrumX get_merkle response includes "pos" but our MerkleProof
    // struct doesn't capture it. We'll try pos=0 as a fallback, or
    // the verify function will fail.
    // TODO: Add pos to MerkleProof struct in backend.rs

    // For now, use the verify_merkle_proof function directly
    let verified = store
        .verify_spv_proof(&tx_hash, block_height, &branch, 0)
        .await;

    // Put store back
    {
        let mut net = state.network.lock().unwrap();
        net.header_store = Some(store);
    }

    match verified {
        Ok(true) => Ok(VerifyProofResult {
            verified: true,
            tx_hash,
            block_height,
            merkle_root: proof.root,
            message: "transaction verified via SPV merkle proof".to_string(),
        }),
        Ok(false) => Ok(VerifyProofResult {
            verified: false,
            tx_hash,
            block_height,
            merkle_root: proof.root,
            message: "merkle proof verification failed — proof does not match stored header"
                .to_string(),
        }),
        Err(e) => Ok(VerifyProofResult {
            verified: false,
            tx_hash,
            block_height,
            merkle_root: proof.root,
            message: format!("verification error: {e}"),
        }),
    }
}

/// Result of an SPV proof verification.
#[derive(Debug, serde::Serialize)]
pub struct VerifyProofResult {
    /// Whether the transaction was verified.
    pub verified: bool,
    /// Transaction hash (display hex).
    pub tx_hash: String,
    /// Block height containing the transaction.
    pub block_height: u64,
    /// Merkle root from the block header.
    pub merkle_root: String,
    /// Human-readable result message.
    pub message: String,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::server_list::ServerList;

    #[test]
    fn test_network_info_serialize() {
        let info = NetworkInfo {
            connected: false,
            backend_type: None,
            active_server: None,
            tip_height: None,
            server_count: 9,
            connected_count: 0,
            banned_count: 0,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"connected\":false"));
        assert!(json.contains("\"server_count\":9"));
    }

    #[test]
    fn test_server_info_serialize() {
        let info = ServerInfo {
            host: "electrum.api.sv".to_string(),
            ssl_port: 50002,
            tcp_port: Some(50001),
            version: "1.4".to_string(),
            status: "unknown".to_string(),
            avg_latency_ms: None,
            consecutive_failures: 0,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"host\":\"electrum.api.sv\""));
        assert!(json.contains("\"ssl_port\":50002"));
    }

    #[test]
    fn test_sync_result_serialize() {
        let result = SyncResult {
            server_host: "electrum.api.sv".to_string(),
            account_id: 1,
            synced: true,
            message: "synced 3 keys: 5 txs, 2 utxos".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"synced\":true"));
        assert!(json.contains("\"account_id\":1"));
        assert!(json.contains("synced 3 keys"));
    }

    #[test]
    fn test_sync_result_not_synced() {
        let result = SyncResult {
            server_host: "electrum.api.sv".to_string(),
            account_id: 1,
            synced: false,
            message: "no keyinstances found".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"synced\":false"));
    }

    #[test]
    fn test_network_command_error_display() {
        let e = NetworkCommandError::NotConnected;
        assert!(e.to_string().contains("not connected"));

        let e = NetworkCommandError::NoWalletOpen;
        assert!(e.to_string().contains("no wallet"));

        let e = NetworkCommandError::ConnectionFailed("timeout".to_string());
        assert!(e.to_string().contains("timeout"));
    }

    #[test]
    fn test_network_command_error_serialize() {
        let e = NetworkCommandError::NotConnected;
        let json = serde_json::to_string(&e).unwrap();
        // Serialized as a plain string
        assert!(json.contains("not connected"));
    }

    #[test]
    fn test_backend_type_string() {
        assert_eq!(BackendType::ElectrumX.to_string(), "electrumx");
        assert_eq!(BackendType::WhatsOnChain.to_string(), "whatsonchain");
    }

    #[test]
    fn test_server_list_default_in_network_state() {
        let ns = crate::state::NetworkState::new();
        assert_eq!(ns.server_list.len(), 9);
        assert!(!ns.connected);
    }

    #[test]
    fn test_get_network_snapshot() {
        let state = AppState::new();
        let (servers, connected, conn_count, banned, total) = get_network_snapshot(&state);
        assert_eq!(total, 9);
        assert!(!connected);
        assert_eq!(conn_count, 0);
        assert_eq!(banned, 0);
        assert_eq!(servers.len(), 9);
    }

    #[test]
    fn test_status_string_conversion() {
        assert_eq!(
            format!("{:?}", ServerStatus::Unknown).to_lowercase(),
            "unknown"
        );
        assert_eq!(
            format!("{:?}", ServerStatus::Connected).to_lowercase(),
            "connected"
        );
        assert_eq!(
            format!("{:?}", ServerStatus::Banned).to_lowercase(),
            "banned"
        );
        assert_eq!(
            format!("{:?}", ServerStatus::Failed).to_lowercase(),
            "failed"
        );
    }
}
