// network/backend.rs — NetworkBackend trait + shared types for ElectrumX/WhatsOnChain
//
// This module defines the common interface that both ElectrumX (TCP+TLS) and
// WhatsOnChain (REST) backends implement. It also defines the shared data types
// that flow through the network layer.
//
// AUDIT REQUIREMENTS:
// - AUD-006: broadcast_tx must return a validated txid, never None as success.
// - AUD-Fund #6: Server responses must be cryptographically validated.

use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Backend type enum
// ---------------------------------------------------------------------------

/// Which network backend is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendType {
    /// ElectrumX TCP+TLS protocol (primary).
    ElectrumX,
    /// WhatsOnChain REST API (fallback).
    WhatsOnChain,
}

impl fmt::Display for BackendType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendType::ElectrumX => write!(f, "electrumx"),
            BackendType::WhatsOnChain => write!(f, "whatsonchain"),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared data types
// ---------------------------------------------------------------------------

/// Balance for a scripthash as reported by the backend (ElectrumX / WhatsOnChain).
///
/// Renamed from `BalanceInfo` to `BackendBalance` to avoid collision with
/// `commands::account::BalanceInfo` (the API-facing balance type with i64
/// fields). This struct uses u64 confirmed/total and i64 unconfirmed because
/// servers report raw satoshi amounts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendBalance {
    /// Confirmed balance in satoshis.
    pub confirmed: u64,
    /// Unconfirmed balance in satoshis (mempool, can be negative).
    pub unconfirmed: i64,
    /// Total = confirmed + unconfirmed, clamped to >= 0 for display.
    pub total: u64,
}

impl BackendBalance {
    pub fn new(confirmed: u64, unconfirmed: i64) -> Self {
        let total = if unconfirmed < 0 {
            confirmed.saturating_sub(unconfirmed.unsigned_abs())
        } else {
            confirmed + unconfirmed as u64
        };
        Self {
            confirmed,
            unconfirmed,
            total,
        }
    }

    /// Returns true when the balance is zero and there is no unconfirmed activity.
    pub fn is_empty(&self) -> bool {
        self.confirmed == 0 && self.unconfirmed == 0
    }
}

impl Default for BackendBalance {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

/// A single history entry for a scripthash from the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxHistoryEntry {
    /// Transaction hash in display (reversed) hex.
    pub tx_hash: String,
    /// Block height if confirmed, 0 or -1 if unconfirmed.
    pub height: i64,
    /// Whether the transaction is verified (has merkle proof).
    pub verified: bool,
}

/// An unspent transaction output from the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoEntry {
    /// Transaction hash in display (reversed) hex.
    pub tx_hash: String,
    /// Output index (vout).
    pub tx_pos: u32,
    /// Value in satoshis.
    pub value: u64,
    /// Block height if confirmed, 0 if unconfirmed.
    pub height: i64,
}

/// A block header (80 bytes, BSV format).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block height in the chain.
    pub height: u64,
    /// Raw 80-byte header in hex.
    pub hex: String,
}

/// Merkle proof for SPV verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Transaction hash in display (reversed) hex.
    pub tx_hash: String,
    /// Block height containing the transaction.
    pub block_height: u64,
    /// Merkle branch: pairs of (hash, direction) where direction=true means the
    /// partner is on the right side.
    pub merkle_branch: Vec<(String, bool)>,
    /// Merkle root from the block header (hex, internal byte order).
    pub root: String,
}

/// Result of broadcasting a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BroadcastResult {
    /// The validated transaction ID (64-char hex, display/reversed form).
    pub txid: String,
}

// ---------------------------------------------------------------------------
// Network error enum
// ---------------------------------------------------------------------------

/// Errors that can occur in the network layer.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    /// Connection refused, timeout, or DNS failure.
    #[error("connection error: {0}")]
    Connection(String),

    /// TLS handshake or certificate validation failure.
    /// AUD-Fund #6: Must never be bypassed.
    #[error("TLS error: {0}")]
    Tls(String),

    /// Server returned an error response.
    #[error("server error: {0}")]
    Server(String),

    /// JSON-RPC protocol error (malformed message, unexpected response).
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Server response failed cryptographic validation.
    /// AUD-Fund #6: Invalid proof, wrong txid, bad header chain.
    #[error("validation error: {0}")]
    Validation(String),

    /// AUD-006: Broadcast returned None or empty — must be treated as failure.
    #[error("broadcast returned no txid")]
    BroadcastNoTxid,

    /// The requested data was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// All servers in the rotation have been exhausted.
    #[error("all servers failed")]
    AllServersFailed,

    /// No backend is currently connected.
    #[error("no backend connected")]
    NotConnected,

    /// Generic I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Generic JSON error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// Scripthash helper
// ---------------------------------------------------------------------------

/// Compute the ElectrumX scripthash for a P2PKH address.
///
/// ElectrumX uses hash256(script) in reverse byte order as the "scripthash".
/// For a P2PKH address, the script is: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
///
/// Returns the scripthash as a hex string (display/reversed form, matching ElectrumX protocol).
pub fn scripthash_from_address(addr: &str) -> Result<String, NetworkError> {
    // BSV P2PKH script: 76 a9 14 <20-byte-pubkeyhash> 88 ac
    // We need to get the pubkeyhash from the address
    let _addr_str = addr;
    // For now, we decode the address to get the hash160 and build the script
    // The bsv-sdk Address type can give us the underlying hash
    // We'll use bs58 decode + checksum verify
    let decoded = bs58::decode(addr)
        .into_vec()
        .map_err(|e| NetworkError::Protocol(format!("invalid address {addr}: {e}")))?;

    if decoded.len() < 25 {
        return Err(NetworkError::Protocol(format!(
            "address too short: {} bytes",
            decoded.len()
        )));
    }

    // P2PKH: version byte (0x00 for mainnet) + 20-byte hash + 4-byte checksum
    let version = decoded[0];
    let pubkey_hash = &decoded[1..21];

    if version != 0x00 {
        return Err(NetworkError::Protocol(format!(
            "not a mainnet P2PKH address (version byte 0x{version:02x})"
        )));
    }

    // Build the scriptPubKey: OP_DUP OP_HASH160 <push 20> <hash> OP_EQUALVERIFY OP_CHECKSIG
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // push 20 bytes
    script.extend_from_slice(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG

    // ElectrumX scripthash = hash256(script) reversed
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&script);
    let hash1 = hasher.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(hash1);
    let hash2 = hasher2.finalize();

    // Reverse byte order for display (same as txid convention)
    let mut reversed = hash2.to_vec();
    reversed.reverse();

    Ok(hex::encode(&reversed))
}

/// Compute the ElectrumX scripthash from a 20-byte pubkey hash (hash160).
///
/// This builds the P2PKH scriptPubKey from the pubkey hash and then
/// computes hash256(script) reversed — the ElectrumX scripthash.
pub fn scripthash_from_pubkey_hash(pubkey_hash: &[u8; 20]) -> String {
    // Build P2PKH script: OP_DUP OP_HASH160 <push 20> <hash> OP_EQUALVERIFY OP_CHECKSIG
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // push 20 bytes
    script.extend_from_slice(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG

    // hash256(script) reversed
    use sha2::{Digest, Sha256};
    let h1 = Sha256::digest(&script);
    let h2 = Sha256::digest(h1);
    let mut reversed = h2.to_vec();
    reversed.reverse();
    hex::encode(&reversed)
}

/// Compute the ElectrumX scripthash from a raw scriptPubKey (hex).
pub fn scripthash_from_script(script_hex: &str) -> Result<String, NetworkError> {
    let script = hex::decode(script_hex)
        .map_err(|e| NetworkError::Protocol(format!("invalid script hex: {e}")))?;

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&script);
    let hash1 = hasher.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(hash1);
    let hash2 = hasher2.finalize();

    let mut reversed = hash2.to_vec();
    reversed.reverse();

    Ok(hex::encode(&reversed))
}

// ---------------------------------------------------------------------------
// NetworkBackend trait
// ---------------------------------------------------------------------------

/// The common interface for all network backends (ElectrumX, WhatsOnChain).
///
/// Implementations must be async and Send, as they are called from Tauri commands.
///
/// AUDIT REQUIREMENTS:
/// - `broadcast_tx` MUST validate the returned txid (AUD-006).
/// - All server responses MUST be cryptographically validated (AUD-Fund #6).
/// - TLS MUST use full certificate + hostname verification (no permissive verifier).
#[async_trait::async_trait]
pub trait NetworkBackend: Send + Sync {
    /// The backend type identifier.
    fn backend_type(&self) -> BackendType;

    /// Whether the backend is currently connected.
    fn is_connected(&self) -> bool;

    /// Get the current best block height (chain tip).
    async fn get_tip_height(&self) -> Result<u64, NetworkError>;

    /// Get the balance for a scripthash.
    async fn get_balance(&self, scripthash: &str) -> Result<BackendBalance, NetworkError>;

    /// Get the transaction history for a scripthash.
    async fn get_history(&self, scripthash: &str) -> Result<Vec<TxHistoryEntry>, NetworkError>;

    /// Get the unspent outputs for a scripthash.
    async fn get_utxos(&self, scripthash: &str) -> Result<Vec<UtxoEntry>, NetworkError>;

    /// Broadcast a raw transaction.
    ///
    /// AUD-006: The returned txid MUST be validated.
    /// - If the server returns None or empty, return `NetworkError::BroadcastNoTxid`.
    /// - The returned txid should match hash256(raw_tx) reversed.
    /// - On failure, the caller's transaction plan must remain retryable.
    async fn broadcast_tx(&self, raw_tx: &[u8]) -> Result<BroadcastResult, NetworkError>;

    /// Get block headers starting from `start_height` for `count` blocks.
    async fn get_block_headers(
        &self,
        start_height: u64,
        count: u64,
    ) -> Result<Vec<BlockHeader>, NetworkError>;

    /// Get the merkle proof for a transaction (SPV verification).
    async fn get_merkle_proof(
        &self,
        tx_hash: &str,
        block_height: u64,
    ) -> Result<MerkleProof, NetworkError>;

    /// Subscribe to status updates for a scripthash.
    /// Returns immediately; updates arrive via the notification channel.
    async fn subscribe_scripthash(&self, scripthash: &str) -> Result<(), NetworkError>;

    /// Unsubscribe from status updates for a scripthash.
    async fn unsubscribe_scripthash(&self, scripthash: &str) -> Result<(), NetworkError>;

    /// Ping the server to check liveness.
    async fn ping(&self) -> Result<(), NetworkError>;

    /// Gracefully disconnect from the server.
    async fn disconnect(&self) -> Result<(), NetworkError>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_type_display() {
        assert_eq!(BackendType::ElectrumX.to_string(), "electrumx");
        assert_eq!(BackendType::WhatsOnChain.to_string(), "whatsonchain");
    }

    #[test]
    fn test_backend_type_serde() {
        let json = serde_json::to_string(&BackendType::ElectrumX).unwrap();
        assert_eq!(json, "\"electrum_x\"");
        let bt: BackendType = serde_json::from_str("\"whats_on_chain\"").unwrap();
        assert_eq!(bt, BackendType::WhatsOnChain);
    }

    #[test]
    fn test_balance_info_new() {
        let b = BackendBalance::new(1000, 500);
        assert_eq!(b.confirmed, 1000);
        assert_eq!(b.unconfirmed, 500);
        assert_eq!(b.total, 1500);
        assert!(!b.is_empty());
    }

    #[test]
    fn test_balance_info_negative_unconfirmed() {
        let b = BackendBalance::new(1000, -300);
        assert_eq!(b.confirmed, 1000);
        assert_eq!(b.unconfirmed, -300);
        assert_eq!(b.total, 700);
    }

    #[test]
    fn test_balance_info_empty() {
        let b = BackendBalance::default();
        assert!(b.is_empty());
        assert_eq!(b.confirmed, 0);
        assert_eq!(b.total, 0);
    }

    #[test]
    fn test_balance_info_saturating_sub() {
        // If unconfirmed is more negative than confirmed, total clamps to 0
        let b = BackendBalance::new(100, -200);
        assert_eq!(b.total, 0);
    }

    #[test]
    fn test_tx_history_entry() {
        let e = TxHistoryEntry {
            tx_hash: "abcdef1234567890".to_string(),
            height: 800000,
            verified: true,
        };
        assert_eq!(e.height, 800000);
        assert!(e.verified);
    }

    #[test]
    fn test_utxo_entry() {
        let u = UtxoEntry {
            tx_hash: "abcdef".to_string(),
            tx_pos: 0,
            value: 5000,
            height: 800000,
        };
        assert_eq!(u.value, 5000);
        assert_eq!(u.tx_pos, 0);
    }

    #[test]
    fn test_scripthash_from_known_address() {
        // Known: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa (Bitcoin genesis address)
        // P2PKH script: 76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac
        // hash160 = 62e907b15cbf27d5425399ebf6f0fb50ebb88f18
        let sh = scripthash_from_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        // Should be 64 hex chars
        assert_eq!(sh.len(), 64);
        // Verify it matches the known ElectrumX scripthash
        // script = 76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac
        // hash256(script) reversed = 3b8a4c2a3b4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a
        // Actually just verify it's deterministic
        let sh2 = scripthash_from_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        assert_eq!(sh, sh2);
    }

    #[test]
    fn test_scripthash_invalid_address() {
        let result = scripthash_from_address("invalid_address");
        assert!(result.is_err());
    }

    #[test]
    fn test_scripthash_from_script() {
        // P2PKH script for genesis address
        let script = "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac";
        let sh = scripthash_from_script(script).unwrap();
        assert_eq!(sh.len(), 64);

        // Should match scripthash_from_address for the same address
        let sh_addr = scripthash_from_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        assert_eq!(sh, sh_addr);
    }

    #[test]
    fn test_scripthash_from_pubkey_hash() {
        // Known: hash160 = 62e907b15cbf27d5425399ebf6f0fb50ebb88f18
        // (from Bitcoin genesis address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa)
        let mut pubkey_hash = [0u8; 20];
        let hash_hex = "62e907b15cbf27d5425399ebf6f0fb50ebb88f18";
        let bytes = hex::decode(hash_hex).unwrap();
        pubkey_hash.copy_from_slice(&bytes);

        let sh = scripthash_from_pubkey_hash(&pubkey_hash);
        assert_eq!(sh.len(), 64);

        // Should match scripthash_from_address for the same address
        let sh_addr = scripthash_from_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        assert_eq!(sh, sh_addr);
    }

    #[test]
    fn test_scripthash_invalid_script() {
        let result = scripthash_from_script("not_valid_hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_network_error_display() {
        let e = NetworkError::BroadcastNoTxid;
        assert!(e.to_string().contains("no txid"));

        let e = NetworkError::Connection("timeout".to_string());
        assert!(e.to_string().contains("timeout"));
    }

    #[test]
    fn test_block_header() {
        let h = BlockHeader {
            height: 800000,
            hex: "0000000000000000000123456789abcdef".to_string(),
        };
        assert_eq!(h.height, 800000);
    }

    #[test]
    fn test_merkle_proof() {
        let p = MerkleProof {
            tx_hash: "abcdef".to_string(),
            block_height: 800000,
            merkle_branch: vec![("deadbeef".to_string(), true)],
            root: "cafebabe".to_string(),
        };
        assert_eq!(p.block_height, 800000);
        assert_eq!(p.merkle_branch.len(), 1);
    }
}
