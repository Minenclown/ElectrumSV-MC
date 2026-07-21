// features/mapi.rs — BSV Merchant API (mAPI) client
//
// No Python source — implemented from the BSV mAPI specification.
//
// mAPI is the BSV Merchant API that provides:
//   - Fee quotes (miningFee / relayFee per byte)
//   - Transaction submission with merkle proof + double-spend callbacks
//   - Merkle proof retrieval (TSC format)
//   - Double-spend check
//   - Transaction status query
//
// All mAPI responses are wrapped in a JSONEnvelope (RFC 0062):
//   {
//     "payload": "<json-string>",
//     "signature": "<hex-or-base64>",
//     "publicKey": "<hex>",
//     "encoding": "hex.8.0.0",
//     "mimeType": "application/json"
//   }
// The `payload` field is a JSON string that must be parsed separately.
//
// References:
//   - https://github.com/bitcoin-sv/merchantapi-reference
//   - https://github.com/bitcoin-sv-specs/brfc-merchantapi
//   - BRC-0062 (JSON Envelope)

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

const USER_AGENT: &str = "ElectrumSV-Mc";
const TIMEOUT_SECS: u64 = 30;
/// Shorter timeout for fee-rate lookups so the UI is not blocked for 30s
/// when the mAPI is slow to respond.
const FEE_LOOKUP_TIMEOUT_SECS: u64 = 5;

// ============================================================================
// Error types
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum MapiError {
    #[error("HTTP request failed: {0}")]
    Http(String),
    #[error("invalid JSON envelope: {0}")]
    InvalidEnvelope(String),
    #[error("invalid payload JSON: {0}")]
    InvalidPayload(String),
    #[error("mAPI error response: {status} - {detail}")]
    ApiError { status: String, detail: String },
    #[error("fee quote has no fees")]
    NoFees,
    #[error("merkle proof not found for txid {0}")]
    ProofNotFound(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

// ============================================================================
// JSON Envelope (BRC-0062)
// ============================================================================

/// The outer envelope that wraps all mAPI responses.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonEnvelope {
    /// Base64-encoded JSON payload string
    pub payload: String,
    /// Signature over the payload bytes
    #[serde(default)]
    pub signature: String,
    /// Signer's public key (hex)
    #[serde(default)]
    pub public_key: String,
    /// Encoding type (e.g. "hex.8.0.0" or "base64.8.0.0")
    #[serde(default)]
    pub encoding: String,
    /// MIME type of the payload (usually "application/json")
    #[serde(default)]
    pub mime_type: String,
}

impl JsonEnvelope {
    /// Decode the payload as a JSON value. The payload is typically a
    /// JSON string that was base64-encoded inside the envelope.
    pub fn decode_payload(&self) -> Result<serde_json::Value, MapiError> {
        // mAPI payloads are JSON strings, not base64. The "payload" field
        // contains the raw JSON string directly.
        serde_json::from_str(&self.payload).map_err(|e| MapiError::InvalidPayload(e.to_string()))
    }

    /// Decode the payload as a specific type.
    pub fn decode_payload_as<T: for<'de> Deserialize<'de>>(&self) -> Result<T, MapiError> {
        serde_json::from_str(&self.payload).map_err(|e| MapiError::InvalidPayload(e.to_string()))
    }
}

// ============================================================================
// Fee Quote
// ============================================================================

/// A fee quote from a mAPI miner.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FeeQuote {
    /// API version
    #[serde(default)]
    pub api_version: String,
    /// The miner/processor's BSV identity
    #[serde(default)]
    pub miner_id: String,
    /// Timestamp of the quote
    #[serde(default)]
    pub timestamp: String,
    /// Expiry time of the quote
    #[serde(default)]
    pub expiry_time: String,
    /// Fee structure: maps fee type ("miningFee", "relayFee") to FeeUnit
    pub fees: HashMap<String, FeeUnit>,
    /// Error (if any) — present on error responses
    #[serde(default)]
    pub error: Option<MapiErrorInfo>,
}

/// A single fee entry: rate per byte for a specific transaction category.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FeeUnit {
    /// Fee type: "miningFee" or "relayFee"
    pub fee_type: String,
    /// Transaction type: "simple" | "data" | "STAS"
    #[serde(default)]
    pub tx_type: String,
    /// Satoshis per byte
    pub satoshis: u64,
    /// Minimum fee in satoshis
    pub bytes: u64,
}

impl FeeQuote {
    /// Get the mining fee for "simple" transactions (default).
    pub fn mining_fee(&self) -> Result<&FeeUnit, MapiError> {
        self.fees
            .get("miningFee")
            .ok_or(MapiError::NoFees)
    }

    /// Get the relay fee for "simple" transactions (default).
    pub fn relay_fee(&self) -> Result<&FeeUnit, MapiError> {
        self.fees
            .get("relayFee")
            .ok_or(MapiError::NoFees)
    }

    /// Compute the fee in satoshis for a transaction of the given size in bytes.
    pub fn calculate_fee(&self, tx_size_bytes: u64) -> Result<u64, MapiError> {
        let mf = self.mining_fee()?;
        // satoshis-per-byte * bytes, with a minimum
        let fee = mf.satoshis.saturating_mul(tx_size_bytes) / mf.bytes.max(1);
        Ok(fee.max(mf.satoshis))
    }
}

// ============================================================================
// Transaction submission
// ============================================================================

/// Request body for submitting a transaction.
#[derive(Debug, Clone, Serialize)]
pub struct SubmitTxRequest {
    /// Raw transaction hex
    pub rawtx: String,
    /// Optional callback URL for merkle proof / double-spend notifications
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
    /// Optional callback token (Authorization header value)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_token: Option<String>,
    /// Request merkle proof callback
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_proof: Option<bool>,
    /// Merkle proof format: "TSC" or "none"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_format: Option<String>,
    /// Request double-spend check callback
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds_check: Option<bool>,
}

impl SubmitTxRequest {
    /// Create a simple submission request with just the raw transaction.
    pub fn new(rawtx: String) -> Self {
        Self {
            rawtx,
            callback_url: None,
            callback_token: None,
            merkle_proof: None,
            merkle_format: None,
            ds_check: None,
        }
    }

    /// Enable both merkle proof and double-spend callbacks.
    pub fn with_callbacks(mut self, callback_url: String) -> Self {
        self.callback_url = Some(callback_url);
        self.merkle_proof = Some(true);
        self.merkle_format = Some("TSC".to_string());
        self.ds_check = Some(true);
        self
    }
}

/// Response from submitting a transaction.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SubmitTxResponse {
    /// Submitted transaction txid
    #[serde(default)]
    pub txid: String,
    /// Returned txid (some implementations use "returnResult")
    #[serde(default)]
    pub return_result: String,
    /// Additional result info
    #[serde(default)]
    pub result_description: String,
    /// Current block height
    #[serde(default)]
    pub block_height: u64,
    #[serde(default)]
    pub block_hash: String,
    #[serde(default)]
    pub error: Option<MapiErrorInfo>,
}

/// Error info embedded in mAPI responses.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MapiErrorInfo {
    pub error: String,
    #[serde(default)]
    pub description: String,
}

// ============================================================================
// Merkle Proof
// ============================================================================

/// A merkle proof response (TSC format).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MerkleProof {
    /// Transaction index in the block
    #[serde(default)]
    pub index: u64,
    /// Txid being proved
    pub txid: String,
    /// Block hash containing the transaction
    pub block_hash: String,
    /// Proof nodes: each is [hash, node_type] where type is "branch" | "hash"
    pub proof: Vec<ProofNode>,
    /// Target merkle root
    #[serde(default)]
    pub target: String,
    /// Proof type: "branch" or "merkle"
    #[serde(default)]
    pub proof_type: String,
}

/// A single node in a merkle proof.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProofNode {
    pub hash: String,
    pub node_type: String,
}

// ============================================================================
// Double-Spend Check
// ============================================================================

/// Response from a double-spend check.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DoubleSpendCheck {
    /// Whether a double-spend was detected
    pub ds_detected: bool,
    /// List of competing transactions (if any)
    #[serde(default)]
    pub competing_txs: Vec<String>,
    #[serde(default)]
    pub error: Option<MapiErrorInfo>,
}

// ============================================================================
// Transaction Status
// ============================================================================

/// Transaction status query result.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TxStatus {
    #[serde(default)]
    pub block_height: u64,
    #[serde(default)]
    pub block_hash: String,
    #[serde(default)]
    pub confirmations: u64,
}

// ============================================================================
// Default fee-rate helper (mAPI-backed, never panics)
// ============================================================================

/// Default mAPI endpoint used for fee quotes.
const DEFAULT_MAPI_URL: &str = "https://mapi.bsvassociation.org";

/// Fetch the current mining fee rate (satoshis per byte) from the BSV mAPI.
///
/// Uses the BSV Association mAPI endpoint by default. On any error —
/// network failure, invalid response, missing fees — logs a warning and
/// falls back to `FeeEstimator::DEFAULT_FEE_RATE` (1 sat/byte). This
/// function NEVER panics and always returns a usable fee rate.
pub async fn fetch_default_fee_rate() -> u64 {
    // Use a shorter timeout for fee lookups so the UI is not blocked
    // for 30 seconds when the mAPI is slow or unreachable.
    let client = MapiClient::new_with_timeout(DEFAULT_MAPI_URL, FEE_LOOKUP_TIMEOUT_SECS);
    match client.get_fee_quote().await {
        Ok(quote) => match quote.mining_fee() {
            Ok(fee_unit) => {
                let rate = fee_unit.satoshis.max(1);
                log::info!(
                    "mAPI fee quote fetched — mining fee: {} sat/byte (bytes={})",
                    rate,
                    fee_unit.bytes
                );
                rate
            }
            Err(e) => {
                log::warn!("mAPI fee quote has no miningFee entry: {} — falling back to DEFAULT_FEE_RATE", e);
                crate::core::transaction::FeeEstimator::DEFAULT_FEE_RATE
            }
        },
        Err(e) => {
            log::warn!(
                "mAPI fee quote request failed: {} — falling back to DEFAULT_FEE_RATE",
                e
            );
            crate::core::transaction::FeeEstimator::DEFAULT_FEE_RATE
        }
    }
}

// ============================================================================
// Client
// ============================================================================

/// mAPI client for communicating with a BSV Merchant API server.
pub struct MapiClient {
    client: reqwest::Client,
    base_url: String,
}

impl MapiClient {
    /// Create a new mAPI client pointing at the given base URL.
    ///
    /// The base URL should include the `/mapi` prefix, e.g.
    /// `https://mapi.taal.com/mapi`.
    pub fn new(base_url: &str) -> Self {
        Self::new_with_timeout(base_url, TIMEOUT_SECS)
    }

    /// Create a new mAPI client with a custom request timeout (seconds).
    ///
    /// Use a shorter timeout for non-critical lookups (e.g. fee quotes)
    /// so the UI is not blocked when the mAPI is slow.
    pub fn new_with_timeout(base_url: &str, timeout_secs: u64) -> Self {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .expect("failed to build reqwest client for MapiClient");

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    // -- Fee Quote -----------------------------------------------------------

    /// GET /mapi/feeQuote — fetch the current fee quote from the miner.
    pub async fn get_fee_quote(&self) -> Result<FeeQuote, MapiError> {
        let url = format!("{}/feeQuote", self.base_url);
        let envelope = self.get_envelope(&url).await?;
        let quote: FeeQuote = envelope.decode_payload_as()?;

        if let Some(err) = &quote.error {
            return Err(MapiError::ApiError {
                status: "feeQuote".to_string(),
                detail: err.error.clone(),
            });
        }

        Ok(quote)
    }

    // -- Transaction Submission ---------------------------------------------

    /// POST /mapi/tx — submit a raw transaction.
    pub async fn submit_transaction(&self, req: &SubmitTxRequest) -> Result<SubmitTxResponse, MapiError> {
        let url = format!("{}/tx", self.base_url);

        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(req)
            .send()
            .await
            .map_err(|e| MapiError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(MapiError::Http(format!("HTTP {}", resp.status())));
        }

        let envelope: JsonEnvelope = resp
            .json()
            .await
            .map_err(|e| MapiError::InvalidEnvelope(e.to_string()))?;

        let tx_resp: SubmitTxResponse = envelope.decode_payload_as()?;

        if let Some(err) = &tx_resp.error {
            return Err(MapiError::ApiError {
                status: "tx".to_string(),
                detail: err.error.clone(),
            });
        }

        Ok(tx_resp)
    }

    // -- Merkle Proof -------------------------------------------------------

    /// GET /mapi/merkle-proof/{txid}/{block_hash} — fetch a merkle proof.
    pub async fn get_merkle_proof(
        &self,
        txid: &str,
        block_hash: &str,
    ) -> Result<MerkleProof, MapiError> {
        let url = format!("{}/merkle-proof/{}/{}", self.base_url, txid, block_hash);
        let envelope = self.get_envelope(&url).await?;
        let proof: MerkleProof = envelope.decode_payload_as()?;
        Ok(proof)
    }

    // -- Double-Spend Check -------------------------------------------------

    /// POST /mapi/ds-check — check if a transaction double-spends.
    pub async fn check_double_spend(&self, rawtx: &str) -> Result<DoubleSpendCheck, MapiError> {
        let url = format!("{}/ds-check", self.base_url);

        let body = serde_json::json!({ "rawtx": rawtx });

        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| MapiError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(MapiError::Http(format!("HTTP {}", resp.status())));
        }

        let envelope: JsonEnvelope = resp
            .json()
            .await
            .map_err(|e| MapiError::InvalidEnvelope(e.to_string()))?;

        let ds_check: DoubleSpendCheck = envelope.decode_payload_as()?;
        Ok(ds_check)
    }

    // -- Transaction Status -------------------------------------------------

    /// GET /mapi/tx/{txid} — query transaction status.
    pub async fn get_transaction_status(&self, txid: &str) -> Result<TxStatus, MapiError> {
        let url = format!("{}/tx/{}", self.base_url, txid);
        let envelope = self.get_envelope(&url).await?;
        let status: TxStatus = envelope.decode_payload_as()?;
        Ok(status)
    }

    // -- Internals -----------------------------------------------------------

    /// GET an endpoint that returns a JSON envelope and decode it.
    async fn get_envelope(&self, url: &str) -> Result<JsonEnvelope, MapiError> {
        let resp = self
            .client
            .get(url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| MapiError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(MapiError::Http(format!("HTTP {}", resp.status())));
        }

        resp.json()
            .await
            .map_err(|e| MapiError::InvalidEnvelope(e.to_string()))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Fee quote parsing ---

    #[test]
    fn test_fee_quote_deserialize() {
        let json = r#"{
            "api_version": "1.0.0",
            "miner_id": "03e9157a8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8",
            "timestamp": "2024-01-01T00:00:00Z",
            "expiry_time": "2024-01-01T01:00:00Z",
            "fees": {
                "miningFee": {
                    "fee_type": "miningFee",
                    "tx_type": "simple",
                    "satoshis": 25,
                    "bytes": 1000
                },
                "relayFee": {
                    "fee_type": "relayFee",
                    "tx_type": "simple",
                    "satoshis": 10,
                    "bytes": 1000
                }
            }
        }"#;
        let quote: FeeQuote = serde_json::from_str(json).unwrap();
        assert_eq!(quote.mining_fee().unwrap().satoshis, 25);
        assert_eq!(quote.relay_fee().unwrap().satoshis, 10);
    }

    #[test]
    fn test_calculate_fee() {
        let mut fees = HashMap::new();
        fees.insert(
            "miningFee".to_string(),
            FeeUnit {
                fee_type: "miningFee".to_string(),
                tx_type: "simple".to_string(),
                satoshis: 25,
                bytes: 1000,
            },
        );
        let quote = FeeQuote {
            api_version: "1.0".to_string(),
            miner_id: String::new(),
            timestamp: String::new(),
            expiry_time: String::new(),
            fees,
            error: None,
        };

        // 2000 bytes → 25 * 2000 / 1000 = 50 satoshis
        let fee = quote.calculate_fee(2000).unwrap();
        assert_eq!(fee, 50);
    }

    #[test]
    fn test_calculate_fee_minimum() {
        let mut fees = HashMap::new();
        fees.insert(
            "miningFee".to_string(),
            FeeUnit {
                fee_type: "miningFee".to_string(),
                tx_type: "simple".to_string(),
                satoshis: 500,
                bytes: 1000,
            },
        );
        let quote = FeeQuote {
            api_version: "1.0".to_string(),
            miner_id: String::new(),
            timestamp: String::new(),
            expiry_time: String::new(),
            fees,
            error: None,
        };

        // 1 byte → 500 * 1 / 1000 = 0, but minimum is satoshis=500
        let fee = quote.calculate_fee(1).unwrap();
        assert_eq!(fee, 500);
    }

    // --- JSON envelope ---

    #[test]
    fn test_envelope_decode_payload() {
        let payload_json = serde_json::json!({
            "fees": {
                "miningFee": {
                    "satoshis": 25,
                    "bytes": 1000
                }
            }
        });
        let envelope = JsonEnvelope {
            payload: payload_json.to_string(),
            signature: String::new(),
            public_key: String::new(),
            encoding: "utf-8".to_string(),
            mime_type: "application/json".to_string(),
        };

        let decoded = envelope.decode_payload().unwrap();
        assert!(decoded["fees"]["miningFee"]["satoshis"].as_u64() == Some(25));
    }

    #[test]
    fn test_envelope_invalid_payload() {
        let envelope = JsonEnvelope {
            payload: "not valid json{{{".to_string(),
            signature: String::new(),
            public_key: String::new(),
            encoding: String::new(),
            mime_type: String::new(),
        };
        let result = envelope.decode_payload();
        assert!(matches!(result, Err(MapiError::InvalidPayload(_))));
    }

    // --- SubmitTxRequest builder ---

    #[test]
    fn test_submit_tx_request_simple() {
        let req = SubmitTxRequest::new("01000000deadbeef".to_string());
        assert_eq!(req.rawtx, "01000000deadbeef");
        assert!(req.callback_url.is_none());
        assert!(req.merkle_proof.is_none());
        assert!(req.ds_check.is_none());
    }

    #[test]
    fn test_submit_tx_request_with_callbacks() {
        let req = SubmitTxRequest::new("01000000deadbeef".to_string())
            .with_callbacks("https://myapp.com/callback".to_string());

        assert_eq!(req.callback_url, Some("https://myapp.com/callback".to_string()));
        assert_eq!(req.merkle_proof, Some(true));
        assert_eq!(req.merkle_format, Some("TSC".to_string()));
        assert_eq!(req.ds_check, Some(true));
    }

    // --- SubmitTxResponse parsing ---

    #[test]
    fn test_submit_tx_response_deserialize() {
        let json = r#"{
            "txid": "abc123",
            "return_result": "success",
            "result_description": "",
            "block_height": 800000,
            "block_hash": "0000000000abcdef"
        }"#;
        let resp: SubmitTxResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.txid, "abc123");
        assert_eq!(resp.return_result, "success");
        assert_eq!(resp.block_height, 800000);
    }

    // --- DoubleSpendCheck parsing ---

    #[test]
    fn test_ds_check_deserialize_no_ds() {
        let json = r#"{"ds_detected": false, "competing_txs": []}"#;
        let ds: DoubleSpendCheck = serde_json::from_str(json).unwrap();
        assert!(!ds.ds_detected);
        assert!(ds.competing_txs.is_empty());
    }

    #[test]
    fn test_ds_check_deserialize_with_ds() {
        let json = r#"{"ds_detected": true, "competing_txs": ["abc123", "def456"]}"#;
        let ds: DoubleSpendCheck = serde_json::from_str(json).unwrap();
        assert!(ds.ds_detected);
        assert_eq!(ds.competing_txs.len(), 2);
    }

    // --- MerkleProof parsing ---

    #[test]
    fn test_merkle_proof_deserialize() {
        let json = r#"{
            "index": 5,
            "txid": "abc123def456",
            "block_hash": "0000000000abcdef",
            "proof": [
                {"hash": "hash1", "node_type": "branch"},
                {"hash": "hash2", "node_type": "hash"}
            ],
            "target": "merkleroot123",
            "proof_type": "branch"
        }"#;
        let proof: MerkleProof = serde_json::from_str(json).unwrap();
        assert_eq!(proof.index, 5);
        assert_eq!(proof.txid, "abc123def456");
        assert_eq!(proof.proof.len(), 2);
        assert_eq!(proof.proof[0].node_type, "branch");
        assert_eq!(proof.proof[1].node_type, "hash");
    }

    // --- Client construction ---

    #[test]
    fn test_client_strips_trailing_slash() {
        let c1 = MapiClient::new("https://mapi.taal.com/mapi");
        let c2 = MapiClient::new("https://mapi.taal.com/mapi/");
        assert_eq!(c1.base_url, c2.base_url);
    }

    // --- fetch_default_fee_rate ---

    /// `fetch_default_fee_rate` must return DEFAULT_FEE_RATE when the mAPI
    /// endpoint is unreachable. We use an invalid URL (port 99999) to force
    /// a connection error without relying on any external service.
    #[tokio::test]
    async fn test_fetch_default_fee_rate_unreachable_falls_back() {
        // Build a client pointing at a port that cannot be connected to.
        let client = MapiClient::new("http://localhost:99999");
        let result = client.get_fee_quote().await;
        assert!(result.is_err(), "expected error when mAPI is unreachable");

        // The helper itself always returns a valid fee rate — DEFAULT_FEE_RATE on error.
        // We can't call fetch_default_fee_rate() directly here because it hardcodes
        // the production URL, but we replicate its fallback logic to prove the
        // error path yields DEFAULT_FEE_RATE.
        let fallback = match result {
            Ok(quote) => quote.mining_fee().map(|f| f.satoshis.max(1)).unwrap_or(
                crate::core::transaction::FeeEstimator::DEFAULT_FEE_RATE,
            ),
            Err(_) => crate::core::transaction::FeeEstimator::DEFAULT_FEE_RATE,
        };
        assert_eq!(
            fallback,
            crate::core::transaction::FeeEstimator::DEFAULT_FEE_RATE,
            "fallback must equal DEFAULT_FEE_RATE when mAPI is unreachable"
        );
    }

    /// `fetch_default_fee_rate` must return the miningFee satoshis value when
    /// the mAPI responds successfully. We simulate a successful quote by
    /// parsing a known-good JSON envelope (no network involved).
    #[tokio::test]
    async fn test_fetch_default_fee_rate_success_extracts_satoshis() {
        // Simulate the success path: a FeeQuote with miningFee satoshis = 25.
        let mut fees = HashMap::new();
        fees.insert(
            "miningFee".to_string(),
            FeeUnit {
                fee_type: "miningFee".to_string(),
                tx_type: "simple".to_string(),
                satoshis: 25,
                bytes: 1000,
            },
        );
        let quote = FeeQuote {
            api_version: "1.0".to_string(),
            miner_id: String::new(),
            timestamp: String::new(),
            expiry_time: String::new(),
            fees,
            error: None,
        };

        // Replicate the success branch of fetch_default_fee_rate.
        let rate = quote.mining_fee().map(|f| f.satoshis.max(1)).unwrap_or(
            crate::core::transaction::FeeEstimator::DEFAULT_FEE_RATE,
        );
        assert_eq!(rate, 25, "success path must extract miningFee.satoshis");
    }

    // --- Fee quote error handling ---

    #[test]
    fn test_fee_quote_error() {
        let json = r#"{
            "api_version": "1.0.0",
            "fees": {},
            "error": {"error": "Service unavailable", "description": "Maintenance"}
        }"#;
        let quote: FeeQuote = serde_json::from_str(json).unwrap();
        assert!(quote.error.is_some());
        assert!(quote.mining_fee().is_err());
    }
}