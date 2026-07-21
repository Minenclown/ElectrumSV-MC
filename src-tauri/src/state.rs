// state.rs — App state with loaded wallet + network state
//
// Holds the currently open wallet's DB pool, keystore data, and decrypted key.
// Also holds the network layer state (server list, active backend).
// Managed by Tauri via `.manage(AppState::new())`.

use crate::core::keystore::KeyStoreData;
use crate::core::transaction::TxPlan;
use crate::network::electrumx::ElectrumXClient;
use crate::network::header_store::HeaderStore;
use crate::network::server_list::ServerList;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Mutex;

/// A TX plan held server-side, keyed by a UUID `plan_id`.
///
/// The backend stores the plan produced by `prepare_tx` here. The renderer
/// only receives the `plan_id` (and metadata) and must pass the same id back
/// to `sign_tx`. This prevents a compromised renderer from tampering with
/// inputs/outputs/fee on the plan that actually gets signed.
pub struct PendingPlan {
    /// The full TX plan (unsigned_tx_hex, inputs, outputs, fee, ...).
    pub plan: TxPlan,
    /// Unix timestamp (seconds) when the plan was stored.
    pub created_at: i64,
}

/// How long a pending plan remains valid in the store before being eligible
/// for cleanup. Plans older than this are purged opportunistically on lookup.
/// Must be >= TX_PLAN_TTL (300s) so plans don't expire from the store before
/// their own TTL would naturally reject them at sign time.
pub const PLAN_STORE_TTL: i64 = 600; // 10 minutes

/// State of the entire app — managed by Tauri via `.manage(AppState::new())`.
pub struct AppState {
    /// Path to the data directory (ELECTRUMSV_DATA_DIR or fallback).
    pub data_dir: String,
    /// Currently open wallet (None = no wallet open).
    pub active_wallet: Mutex<Option<ActiveWallet>>,
    /// Network state (server list, active backend).
    pub network: Mutex<NetworkState>,
    /// Server-side TX plan store: plan_id -> PendingPlan.
    /// Lives outside `active_wallet` so plans survive wallet-close for cleanup.
    pub pending_plans: Mutex<HashMap<String, PendingPlan>>,
}

/// Generate a fresh UUID v4 plan id (RFC 4122 variant, random bits).
pub fn generate_plan_id() -> String {
    // 16 random bytes
    let mut bytes = [0u8; 16];
    // rand 0.8: use thread_rng
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut bytes);
    // Set version (v4) and variant bits per RFC 4122 §4.4
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10
    // Format as 8-4-4-4-12 hex
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

/// Represents a loaded wallet in memory.
pub struct ActiveWallet {
    /// Absolute path to the .sqlite file
    pub wallet_path: String,
    /// Wallet name (filename without .sqlite)
    pub wallet_name: String,
    /// SQLite connection pool
    pub db_pool: SqlitePool,
    /// Keystore data loaded from MasterKeys table (xpub, encrypted xprv, etc.)
    pub keystore_data: KeyStoreData,
    /// Account ID of the default account
    pub account_id: i64,
    /// Decrypted xprv (None = locked, Some = unlocked)
    pub decrypted_xprv: Option<String>,
}

impl ActiveWallet {
    /// Whether the wallet is unlocked (decrypted xprv available).
    pub fn is_unlocked(&self) -> bool {
        self.decrypted_xprv.is_some()
    }
}

/// Network layer state — server list and active backend info.
///
/// The actual ElectrumXClient is not stored here directly because it contains
/// a tokio task handle and TLS stream. Instead, connection state is managed
/// at a higher level. This struct holds the server list and metadata.
pub struct NetworkState {
    /// List of known servers with health tracking.
    pub server_list: ServerList,
    /// Whether a backend is currently connected.
    pub connected: bool,
    /// The active ElectrumX client (None = not connected).
    /// Cloned cheaply (Arc<Inner> inside) for use in commands.
    pub client: Option<ElectrumXClient>,
    /// The active WhatsOnChain client (None = not using WoC backend).
    pub woc_client: Option<crate::network::whatsonchain::WhatsOnChainClient>,
    /// Active backend type (None = not connected).
    pub active_backend: Option<crate::network::backend::BackendType>,
    /// Persistent block header store for SPV verification.
    /// Lazy-initialized on first use (requires a data directory path).
    pub header_store: Option<HeaderStore>,
    /// Active network ID: "mainnet", "testnet", or "stn".
    pub active_network: String,
}

impl NetworkState {
    pub fn new() -> Self {
        Self {
            server_list: ServerList::with_defaults(),
            connected: false,
            client: None,
            woc_client: None,
            active_backend: None,
            header_store: None,
            active_network: "mainnet".to_string(),
        }
    }
}

impl Default for NetworkState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        let data_dir = std::env::var("ELECTRUMSV_DATA_DIR").unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            format!("{}/.electrum-sv", home)
        });

        log::info!("Data directory: {}", data_dir);

        Self {
            data_dir,
            active_wallet: Mutex::new(None),
            network: Mutex::new(NetworkState::new()),
            pending_plans: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
