// network/whatsonchain.rs — WhatsOnChain REST API client (fallback backend)
//
// Implements the NetworkBackend trait over the WhatsOnChain REST API.
// This is a fallback/alternative backend to ElectrumX — no push notifications,
// polling only. Uses reqwest with rustls-tls (AUD-Fund #6: no permissive TLS).
//
// API base: https://api.whatsonchain.com/v1/bsv/main
// Endpoints:
//   GET  /chain/info                          — chain tip height
//   GET  /address/{addr}/balance              — confirmed/unconfirmed balance
//   GET  /address/{addr}/history              — transaction history
//   GET  /address/{addr}/unspent              — UTXOs
//   POST /tx/raw                              — broadcast (body: {"txhex": "..."})
//   GET  /block/{height}/header               — block header
//   GET  /tx/{txid}/proof                     — merkle proof (if available)
//
// AUDIT:
// - AUD-006: broadcast_tx validates returned txid by computing hash256 locally.
// - AUD-Fund #6: reqwest with rustls-tls, no permissive verifier.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::backend::{
    BackendType, BackendBalance, BlockHeader, BroadcastResult, MerkleProof, NetworkBackend,
    NetworkError, TxHistoryEntry, UtxoEntry,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BASE_URL: &str = "https://api.whatsonchain.com/v1/bsv/main";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const USER_AGENT: &str = "ElectrumSV-Mc/0.1.0";

// ---------------------------------------------------------------------------
// Internal response types (deserialize from WhatsOnChain JSON)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ChainInfo {
    blocks: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddressBalance {
    confirmed: u64,
    unconfirmed: i64,
    value: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddressHistoryEntry {
    tx_hash: String,
    // WhatsOnChain uses block_height (confirmed) or 0/null (unconfirmed)
    block_height: Option<i64>,
    // Some endpoints return "height" instead
    height: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddressUtxoEntry {
    tx_hash: String,
    // WoC uses "vout" or "tx_pos"
    vout: Option<u32>,
    tx_pos: Option<u32>,
    value: u64,
    // block height if confirmed
    block_height: Option<i64>,
    height: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlockHeaderResponse {
    // WhatsOnChain returns header fields in a JSON object.
    // We need the raw 80-byte hex. The "hash" field is the block hash.
    // The actual header hex is not always provided, so we construct what we can.
    height: Option<u64>,
    hash: Option<String>,
    // Some responses include "hex" for the raw header
    hex: Option<String>,
    merkle_root: Option<String>,
    bits: Option<u64>,
    time: Option<u64>,
    version: Option<u32>,
    nonce: Option<u64>,
    previous_block_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BroadcastResponse {
    // WoC broadcast returns txid directly or in a JSON object
    #[serde(rename = "txid")]
    txid: Option<String>,
}

// ---------------------------------------------------------------------------
// WhatsOnChain client
// ---------------------------------------------------------------------------

/// WhatsOnChain REST API client.
///
/// `Clone` is cheap (Arc inside), allowing use across Tauri commands.
/// This backend does NOT support push notifications — all data must be polled.
/// `subscribe_scripthash` and `unsubscribe_scripthash` are no-ops.
#[derive(Clone)]
pub struct WhatsOnChainClient {
    inner: Arc<Inner>,
}

struct Inner {
    base_url: String,
    http: reqwest::Client,
    connected: AtomicBool,
}

impl WhatsOnChainClient {
    /// Create a new WhatsOnChain client for BSV mainnet.
    pub fn new() -> Self {
        Self::with_base_url(BASE_URL)
    }

    /// Create a client with a custom base URL (useful for testing).
    pub fn with_base_url(base_url: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(USER_AGENT)
            // AUD-Fund #6: rustls-tls, full certificate verification by default.
            // reqwest with rustls-tls feature does NOT disable any verification.
            .build()
            .expect("failed to build reqwest client");

        Self {
            inner: Arc::new(Inner {
                base_url: base_url.to_string(),
                http,
                connected: AtomicBool::new(false),
            }),
        }
    }

    /// Mark the client as connected (after first successful request).
    fn mark_connected(&self) {
        self.inner.connected.store(true, Ordering::SeqCst);
    }

    /// Mark the client as disconnected.
    fn mark_disconnected(&self) {
        self.inner.connected.store(false, Ordering::SeqCst);
    }

    /// Perform a GET request and return the JSON body.
    async fn get<T: serde::de::DeserializeOwned>(&self, endpoint: &str) -> Result<T, NetworkError> {
        let url = format!("{}/{}", self.inner.base_url, endpoint);
        let resp = self
            .inner
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| NetworkError::Connection(format!("WoC GET {url}: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            if status == reqwest::StatusCode::NOT_FOUND {
                return Err(NetworkError::NotFound(format!("WoC: {endpoint}")));
            }
            return Err(NetworkError::Server(format!(
                "WoC GET {url}: HTTP {status}: {text}"
            )));
        }

        resp.json::<T>()
            .await
            .map_err(|e| NetworkError::Protocol(format!("WoC GET {url}: JSON decode: {e}")))
    }

    /// Perform a POST request and return the JSON body.
    async fn post<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &self,
        endpoint: &str,
        body: &B,
    ) -> Result<T, NetworkError> {
        let url = format!("{}/{}", self.inner.base_url, endpoint);
        let resp = self
            .inner
            .http
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| NetworkError::Connection(format!("WoC POST {url}: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(NetworkError::Server(format!(
                "WoC POST {url}: HTTP {status}: {text}"
            )));
        }

        resp.json::<T>()
            .await
            .map_err(|e| NetworkError::Protocol(format!("WoC POST {url}: JSON decode: {e}")))
    }

    /// Compute txid (display form) from raw transaction bytes.
    /// txid = hash256(raw_tx) reversed → hex.
    /// AUD-006: Used to validate server's broadcast response.
    fn compute_txid(raw_tx: &[u8]) -> String {
        let h1 = Sha256::digest(raw_tx);
        let h2 = Sha256::digest(h1);
        let mut reversed = h2.to_vec();
        reversed.reverse();
        hex::encode(&reversed)
    }
}

impl Default for WhatsOnChainClient {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// NetworkBackend trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl NetworkBackend for WhatsOnChainClient {
    fn backend_type(&self) -> BackendType {
        BackendType::WhatsOnChain
    }

    fn is_connected(&self) -> bool {
        self.inner.connected.load(Ordering::SeqCst)
    }

    async fn get_tip_height(&self) -> Result<u64, NetworkError> {
        let info: ChainInfo = self.get("chain/info").await?;
        self.mark_connected();
        Ok(info.blocks)
    }

    async fn get_balance(&self, scripthash: &str) -> Result<BackendBalance, NetworkError> {
        // WhatsOnChain uses addresses, not scripthashes.
        // The caller must pass a BSV address, not a scripthash.
        // For the WoC backend, we treat "scripthash" as an address.
        let endpoint = format!("address/{scripthash}/balance");
        let bal: AddressBalance = self.get(&endpoint).await?;
        self.mark_connected();
        Ok(BackendBalance::new(bal.confirmed, bal.unconfirmed))
    }

    async fn get_history(&self, scripthash: &str) -> Result<Vec<TxHistoryEntry>, NetworkError> {
        let endpoint = format!("address/{scripthash}/history");
        let entries: Vec<AddressHistoryEntry> = self.get(&endpoint).await?;
        self.mark_connected();

        let mut result = Vec::with_capacity(entries.len());
        for e in entries {
            let height = e.block_height.or(e.height).unwrap_or(0);
            let verified = height > 0;
            result.push(TxHistoryEntry {
                tx_hash: e.tx_hash,
                height,
                verified,
            });
        }
        Ok(result)
    }

    async fn get_utxos(&self, scripthash: &str) -> Result<Vec<UtxoEntry>, NetworkError> {
        let endpoint = format!("address/{scripthash}/unspent");
        let entries: Vec<AddressUtxoEntry> = self.get(&endpoint).await?;
        self.mark_connected();

        let mut result = Vec::with_capacity(entries.len());
        for e in entries {
            let tx_pos = e.vout.or(e.tx_pos).unwrap_or(0);
            let height = e.block_height.or(e.height).unwrap_or(0);
            result.push(UtxoEntry {
                tx_hash: e.tx_hash,
                tx_pos,
                value: e.value,
                height,
            });
        }
        Ok(result)
    }

    async fn broadcast_tx(&self, raw_tx: &[u8]) -> Result<BroadcastResult, NetworkError> {
        // AUD-006: Compute expected txid locally
        let expected_txid = Self::compute_txid(raw_tx);
        let raw_hex = hex::encode(raw_tx);

        // WhatsOnChain broadcast endpoint: POST /tx/raw with {"txhex": "..."}
        // Response: JSON with "txid" field, or plain text txid
        let url = format!("{}/tx/raw", self.inner.base_url);
        let resp = self
            .inner
            .http
            .post(&url)
            .json(&serde_json::json!({ "txhex": raw_hex }))
            .send()
            .await
            .map_err(|e| NetworkError::Connection(format!("WoC broadcast: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(NetworkError::Server(format!(
                "WoC broadcast: HTTP {status}: {text}"
            )));
        }

        // Try to parse as JSON first, then as plain text
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let server_txid = if content_type.contains("application/json") {
            let parsed: BroadcastResponse = resp
                .json()
                .await
                .map_err(|e| NetworkError::Protocol(format!("WoC broadcast JSON: {e}")))?;
            parsed
                .txid
                .ok_or(NetworkError::BroadcastNoTxid)?
                .trim()
                .to_string()
        } else {
            // Plain text response — the txid itself
            let text = resp
                .text()
                .await
                .map_err(|e| NetworkError::Protocol(format!("WoC broadcast text: {e}")))?;
            text.trim().to_string()
        };

        if server_txid.is_empty() {
            return Err(NetworkError::BroadcastNoTxid);
        }

        // AUD-006: Validate returned txid matches locally computed txid
        if expected_txid != server_txid {
            return Err(NetworkError::Validation(format!(
                "txid mismatch: server returned '{server_txid}', expected '{expected_txid}'"
            )));
        }

        self.mark_connected();
        Ok(BroadcastResult { txid: server_txid })
    }

    async fn get_block_headers(
        &self,
        start_height: u64,
        count: u64,
    ) -> Result<Vec<BlockHeader>, NetworkError> {
        // WhatsOnChain doesn't have a batch header endpoint like ElectrumX.
        // We fetch individual block headers one at a time.
        let mut headers = Vec::with_capacity(count as usize);
        for i in 0..count {
            let height = start_height + i;
            let endpoint = format!("block/{height}/header");
            let hdr: BlockHeaderResponse = match self.get(&endpoint).await {
                Ok(h) => h,
                Err(NetworkError::NotFound(_)) => break, // No more blocks
                Err(e) => return Err(e),
            };

            // If the API returns raw hex, use it; otherwise construct from fields.
            let hex = if let Some(h) = hdr.hex {
                h
            } else {
                // Construct 80-byte header from fields if available.
                // This is a fallback — ideally the API provides raw hex.
                // Fields: version(4 LE) | prev_hash(32 LE) | merkle_root(32 LE) |
                //         time(4 LE) | bits(4 LE) | nonce(4 LE)
                let version = hdr.version.unwrap_or(0) as u32;
                let default_hash = "0".repeat(64);
                let prev_hash = hdr.previous_block_hash.as_deref().unwrap_or(&default_hash);
                let merkle_root = hdr.merkle_root.as_deref().unwrap_or(&default_hash);
                let time = hdr.time.unwrap_or(0) as u32;
                let bits = hdr.bits.unwrap_or(0) as u32;
                let nonce = hdr.nonce.unwrap_or(0) as u32;

                // Decode prev_hash and merkle_root (they come in display/big-endian form)
                let prev_bytes = hex::decode(prev_hash).unwrap_or_else(|_| vec![0u8; 32]);
                let merkle_bytes = hex::decode(merkle_root).unwrap_or_else(|_| vec![0u8; 32]);

                // Reverse from display (big-endian) to internal (little-endian)
                let mut prev_le = prev_bytes;
                prev_le.reverse();
                let mut merkle_le = merkle_bytes;
                merkle_le.reverse();

                let mut raw = Vec::with_capacity(80);
                raw.extend_from_slice(&version.to_le_bytes());
                raw.extend_from_slice(&prev_le[..32.min(prev_le.len())]);
                raw.extend_from_slice(&merkle_le[..32.min(merkle_le.len())]);
                raw.extend_from_slice(&time.to_le_bytes());
                raw.extend_from_slice(&bits.to_le_bytes());
                raw.extend_from_slice(&nonce.to_le_bytes());
                hex::encode(&raw)
            };

            headers.push(BlockHeader { height, hex });
        }

        self.mark_connected();
        Ok(headers)
    }

    async fn get_merkle_proof(
        &self,
        tx_hash: &str,
        block_height: u64,
    ) -> Result<MerkleProof, NetworkError> {
        // WhatsOnChain: GET /tx/{txid}/proof or /block/{height}/txs
        // The proof endpoint may not always be available.
        let endpoint = format!("tx/{tx_hash}/proof");
        let resp: serde_json::Value = match self.get(&endpoint).await {
            Ok(v) => v,
            Err(NetworkError::NotFound(_)) => {
                return Err(NetworkError::NotFound(format!(
                    "no merkle proof available for tx {tx_hash}"
                )))
            }
            Err(e) => return Err(e),
        };

        self.mark_connected();

        // Parse the proof response. WoC returns:
        // { "txid": "...", "proof": { "merkleRoot": "...", "branches": [...] } }
        // or similar structure.
        let merkle_root = resp
            .get("merkleRoot")
            .or_else(|| resp.get("merkle_root"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                NetworkError::Protocol("WoC merkle proof: missing merkle root".to_string())
            })?
            .to_string();

        let branches = resp
            .get("branches")
            .or_else(|| resp.get("proof"))
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                NetworkError::Protocol("WoC merkle proof: missing branches".to_string())
            })?;

        let mut merkle_branch = Vec::with_capacity(branches.len());
        for item in branches {
            let hash = item
                .as_str()
                .or_else(|| item.get("hash").and_then(|h| h.as_str()))
                .ok_or_else(|| {
                    NetworkError::Protocol("WoC merkle proof: branch item not str".to_string())
                })?
                .to_string();
            merkle_branch.push((hash, false));
        }

        Ok(MerkleProof {
            tx_hash: tx_hash.to_string(),
            block_height,
            merkle_branch,
            root: merkle_root,
        })
    }

    async fn subscribe_scripthash(&self, _scripthash: &str) -> Result<(), NetworkError> {
        // WhatsOnChain is a REST API — no push notifications.
        // Subscriptions are no-ops; the frontend must poll.
        Ok(())
    }

    async fn unsubscribe_scripthash(&self, _scripthash: &str) -> Result<(), NetworkError> {
        // No-op for REST backend.
        Ok(())
    }

    async fn ping(&self) -> Result<(), NetworkError> {
        // Use chain/info as a ping — if it succeeds, we're alive.
        let _: ChainInfo = self.get("chain/info").await?;
        self.mark_connected();
        Ok(())
    }

    async fn disconnect(&self) -> Result<(), NetworkError> {
        self.mark_disconnected();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Extra REST methods (ported from Python features/whatsonchain.py)
// ---------------------------------------------------------------------------

impl WhatsOnChainClient {
    /// Get chain info from WhatsOnChain.
    pub async fn get_chain_info(&self) -> Result<serde_json::Value, NetworkError> {
        self.get("chain/info").await
    }

    /// Get block header by height from WhatsOnChain.
    pub async fn get_block_header(&self, height: i64) -> Result<serde_json::Value, NetworkError> {
        self.get(&format!("block-header/{height}")).await
    }

    /// Get transaction data by txid from WhatsOnChain.
    pub async fn get_tx(&self, txid: &str) -> Result<serde_json::Value, NetworkError> {
        self.get(&format!("tx/hash/{txid}")).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_txid_empty() {
        // hash256(b"") reversed
        let computed = WhatsOnChainClient::compute_txid(b"");
        assert_eq!(computed.len(), 64);
        // Should match the same computation as ElectrumXClient
        let h1 = Sha256::digest(b"");
        let h2 = Sha256::digest(h1);
        let mut reversed = h2.to_vec();
        reversed.reverse();
        assert_eq!(computed, hex::encode(&reversed));
    }

    #[test]
    fn test_compute_txid_deterministic() {
        let raw = b"\x01\x00\x00\x00\x00\xff\xff\xff";
        let t1 = WhatsOnChainClient::compute_txid(raw);
        let t2 = WhatsOnChainClient::compute_txid(raw);
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 64);
    }

    #[test]
    fn test_compute_txid_different_inputs() {
        let t1 = WhatsOnChainClient::compute_txid(b"hello");
        let t2 = WhatsOnChainClient::compute_txid(b"world");
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_backend_type() {
        let client = WhatsOnChainClient::new();
        assert_eq!(client.backend_type(), BackendType::WhatsOnChain);
    }

    #[test]
    fn test_new_not_connected() {
        let client = WhatsOnChainClient::new();
        assert!(!client.is_connected());
    }

    #[test]
    fn test_with_custom_base_url() {
        let client = WhatsOnChainClient::with_base_url("http://localhost:9999");
        assert_eq!(client.inner.base_url, "http://localhost:9999");
        assert_eq!(client.backend_type(), BackendType::WhatsOnChain);
    }

    #[test]
    fn test_mark_connected() {
        let client = WhatsOnChainClient::new();
        assert!(!client.is_connected());
        client.mark_connected();
        assert!(client.is_connected());
        client.mark_disconnected();
        assert!(!client.is_connected());
    }

    #[test]
    fn test_address_balance_deserialize() {
        let json = r#"{"confirmed": 50000, "unconfirmed": -1000, "value": 49000}"#;
        let bal: AddressBalance = serde_json::from_str(json).unwrap();
        assert_eq!(bal.confirmed, 50000);
        assert_eq!(bal.unconfirmed, -1000);
    }

    #[test]
    fn test_address_history_entry_deserialize() {
        let json = r#"{"txHash":"abc123","blockHeight":800000}"#;
        let entry: AddressHistoryEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.tx_hash, "abc123");
        assert_eq!(entry.block_height, Some(800000));
    }

    #[test]
    fn test_address_history_entry_unconfirmed() {
        let json = r#"{"txHash":"def456"}"#;
        let entry: AddressHistoryEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.tx_hash, "def456");
        assert!(entry.block_height.is_none());
        assert!(entry.height.is_none());
    }

    #[test]
    fn test_address_utxo_entry_deserialize() {
        let json = r#"{"txHash":"abc","vout":0,"value":5000,"blockHeight":800000}"#;
        let utxo: AddressUtxoEntry = serde_json::from_str(json).unwrap();
        assert_eq!(utxo.tx_hash, "abc");
        assert_eq!(utxo.vout, Some(0));
        assert_eq!(utxo.value, 5000);
        assert_eq!(utxo.block_height, Some(800000));
    }

    #[test]
    fn test_address_utxo_entry_tx_pos_variant() {
        let json = r#"{"txHash":"xyz","txPos":3,"value":10000}"#;
        let utxo: AddressUtxoEntry = serde_json::from_str(json).unwrap();
        assert_eq!(utxo.tx_pos, Some(3));
        assert_eq!(utxo.value, 10000);
    }

    #[test]
    fn test_broadcast_response_deserialize() {
        let json = r#"{"txid":"abcdef1234567890"}"#;
        let resp: BroadcastResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.txid.as_deref(), Some("abcdef1234567890"));
    }

    #[test]
    fn test_broadcast_response_empty() {
        let json = r#"{"txid":null}"#;
        let resp: BroadcastResponse = serde_json::from_str(json).unwrap();
        assert!(resp.txid.is_none());
    }

    #[test]
    fn test_chain_info_deserialize() {
        let json = r#"{"blocks": 800000}"#;
        let info: ChainInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.blocks, 800000);
    }

    #[test]
    fn test_block_header_response_deserialize() {
        let json = r#"{"height": 800000, "hash": "abc123", "merkleRoot": "def456", "bits": 486604799, "time": 1700000000, "version": 1, "nonce": 12345, "previousBlockHash": "prev789"}"#;
        let hdr: BlockHeaderResponse = serde_json::from_str(json).unwrap();
        assert_eq!(hdr.height, Some(800000));
        assert_eq!(hdr.hash.as_deref(), Some("abc123"));
        assert_eq!(hdr.merkle_root.as_deref(), Some("def456"));
    }

    #[test]
    fn test_clone_is_cheap() {
        let client = WhatsOnChainClient::new();
        let cloned = client.clone();
        // Both share the same inner Arc
        client.mark_connected();
        assert!(cloned.is_connected());
    }
}
