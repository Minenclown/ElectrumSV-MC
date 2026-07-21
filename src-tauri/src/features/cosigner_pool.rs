// features/cosigner_pool.rs — Cosigner transaction pool for multi-sig wallets
//
// Standalone network service module (NOT an OnChainDataDetector).
//
// Provides a client for a cosigner pool server: multi-signature wallets use it
// to discover and share partially signed transactions with their co-signers.
// Each cosigner submits a partially signed transaction; the pool stores it and
// makes it available to the other cosigners, who add their signatures and
// re-upload until the transaction is fully signed and ready to broadcast.
//
// Ported conceptually from archive/electrumsv/feature_controller.py
// (CosignerPoolFeature, feature_id="cosigner_pool",
//  description="Multi-signature wallet cosigner communication").

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Error type
// ============================================================================

/// Errors that can occur when interacting with a cosigner pool server.
#[derive(Debug, Error)]
pub enum CosignerPoolError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("server returned status {status}: {body}")]
    Server { status: u16, body: String },
    #[error("invalid hex transaction data: {0}")]
    InvalidHex(String),
    #[error("wallet id '{0}' not found on the pool")]
    WalletNotFound(String),
    #[error("transaction '{0}' already fully signed")]
    AlreadyComplete(String),
}

// ============================================================================
// Data types
// ============================================================================

/// A partially signed multi-sig transaction shared via the cosigner pool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PartiallySignedTx {
    /// Wallet id this transaction belongs to.
    pub wallet_id: String,
    /// Transaction id (txid) of the unsigned transaction.
    pub txid: String,
    /// Raw transaction hex (BSV transaction, possibly with dummy signatures).
    pub tx_hex: String,
    /// Cosigner ids that have already signed.
    pub signers: Vec<String>,
    /// Number of signatures required to finalize (m of m-of-n).
    pub required_sigs: u16,
    /// Total number of cosigners (n of m-of-n).
    pub total_cosigners: u16,
}

impl PartiallySignedTx {
    /// Whether the transaction has enough signatures to be broadcast.
    pub fn is_complete(&self) -> bool {
        self.signers.len() >= self.required_sigs as usize
    }

    /// Add a cosigner's signature, marking that cosigner as having signed.
    /// Returns an error if the transaction is already complete.
    pub fn add_signature(&mut self, cosigner_id: &str) -> Result<(), CosignerPoolError> {
        if self.is_complete() {
            return Err(CosignerPoolError::AlreadyComplete(self.txid.clone()));
        }
        if !self.signers.iter().any(|s| s == cosigner_id) {
            self.signers.push(cosigner_id.to_string());
        }
        Ok(())
    }
}

/// Summary of pending transactions for a wallet, returned by the pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolSummary {
    pub wallet_id: String,
    pub pending: Vec<PartiallySignedTx>,
}

// ============================================================================
// Client
// ============================================================================

/// HTTP client for a cosigner pool server.
///
/// The server is a simple REST endpoint that stores partially signed
/// transactions keyed by wallet id and makes them available to all cosigners
/// of that wallet. This client wraps the REST calls.
pub struct CosignerPoolClient {
    base_url: String,
    http: reqwest::Client,
}

impl CosignerPoolClient {
    /// Create a new client pointing at `base_url` (e.g. "https://pool.example.com").
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: reqwest::Client::new(),
        }
    }

    /// Build a client with a custom reqwest::Client (e.g. for custom TLS config).
    pub fn with_client(base_url: impl Into<String>, http: reqwest::Client) -> Self {
        Self {
            base_url: base_url.into(),
            http,
        }
    }

    fn url(&self, path: &str) -> String {
        let base = self.base_url.trim_end_matches('/');
        format!("{}/{}", base, path.trim_start_matches('/'))
    }

    /// Submit (or re-submit) a partially signed transaction to the pool.
    ///
    /// The pool stores the latest version keyed by `txid`. Co-signers can
    /// later fetch it, add their signature, and re-upload.
    pub async fn submit_tx(
        &self,
        tx: &PartiallySignedTx,
    ) -> Result<(), CosignerPoolError> {
        // Validate hex before sending.
        if hex::decode(&tx.tx_hex).is_err() {
            return Err(CosignerPoolError::InvalidHex(tx.tx_hex.clone()));
        }

        let resp = self
            .http
            .post(self.url(&format!("api/v1/wallet/{}/tx", tx.wallet_id)))
            .json(tx)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CosignerPoolError::Server { status, body });
        }
        Ok(())
    }

    /// Fetch all pending partially signed transactions for a wallet.
    pub async fn get_pending(
        &self,
        wallet_id: &str,
    ) -> Result<Vec<PartiallySignedTx>, CosignerPoolError> {
        let resp = self
            .http
            .get(self.url(&format!("api/v1/wallet/{}/pending", wallet_id)))
            .send()
            .await?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(CosignerPoolError::WalletNotFound(wallet_id.to_string()));
        }
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CosignerPoolError::Server { status, body });
        }

        let summary: PoolSummary = resp.json().await?;
        Ok(summary.pending)
    }

    /// Delete a transaction from the pool once it is fully signed and broadcast.
    pub async fn delete_tx(
        &self,
        wallet_id: &str,
        txid: &str,
    ) -> Result<(), CosignerPoolError> {
        let resp = self
            .http
            .delete(self.url(&format!("api/v1/wallet/{}/tx/{}", wallet_id, txid)))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CosignerPoolError::Server { status, body });
        }
        Ok(())
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Group a list of partially signed transactions by wallet id.
pub fn group_by_wallet(txs: &[PartiallySignedTx]) -> HashMap<String, Vec<PartiallySignedTx>> {
    let mut map: HashMap<String, Vec<PartiallySignedTx>> = HashMap::new();
    for tx in txs {
        map.entry(tx.wallet_id.clone()).or_default().push(tx.clone());
    }
    map
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tx(required: u16, total: u16, signers: &[&str]) -> PartiallySignedTx {
        PartiallySignedTx {
            wallet_id: "wallet-1".to_string(),
            txid: "abcd1234".to_string(),
            tx_hex: "01000000000000000000".to_string(),
            signers: signers.iter().map(|s| s.to_string()).collect(),
            required_sigs: required,
            total_cosigners: total,
        }
    }

    #[test]
    fn test_is_complete_and_add_signature() {
        let mut tx = sample_tx(2, 3, &["alice"]);
        assert!(!tx.is_complete());

        // Adding a second signature should make it complete.
        tx.add_signature("bob").expect("add bob");
        assert!(tx.is_complete());
        assert_eq!(tx.signers.len(), 2);

        // Adding a third should be a no-op (already counted) — but still Ok
        // because we're not yet over the required count in a way that errors.
        // Actually is_complete is true now, so further adds error.
        let err = tx.add_signature("carol").unwrap_err();
        assert!(matches!(err, CosignerPoolError::AlreadyComplete(_)));
    }

    #[test]
    fn test_add_duplicate_signature_is_idempotent() {
        let mut tx = sample_tx(2, 2, &["alice"]);
        tx.add_signature("alice").expect("duplicate add is ok");
        // Signer list should not grow.
        assert_eq!(tx.signers.len(), 1);
    }

    #[test]
    fn test_invalid_hex_rejected_by_submit() {
        // We can't hit the network in a unit test, but we can exercise the
        // validation path by giving the client a bogus URL and a bad hex tx.
        // The hex check happens before the HTTP call, so this is safe.
        let client = CosignerPoolClient::new("http://localhost:0");
        let bad = PartiallySignedTx {
            wallet_id: "w".to_string(),
            txid: "t".to_string(),
            tx_hex: "nothex!".to_string(),
            signers: vec![],
            required_sigs: 2,
            total_cosigners: 2,
        };
        // Runtime: the async fn would normally block; use a runtime here.
        let rt = tokio::runtime::Runtime::new().expect("rt");
        let err = rt.block_on(client.submit_tx(&bad)).unwrap_err();
        assert!(matches!(err, CosignerPoolError::InvalidHex(_)));
    }

    #[test]
    fn test_group_by_wallet() {
        let txs = vec![
            sample_tx(2, 3, &["a"]),
            PartiallySignedTx {
                wallet_id: "wallet-2".to_string(),
                ..sample_tx(2, 3, &["a"])
            },
            sample_tx(2, 3, &["a", "b"]),
        ];
        let grouped = group_by_wallet(&txs);
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped["wallet-1"].len(), 2);
        assert_eq!(grouped["wallet-2"].len(), 1);
    }

    #[test]
    fn test_url_construction_trims_trailing_slash() {
        let client = CosignerPoolClient::new("https://pool.example.com/");
        assert_eq!(
            client.url("api/v1/wallet/w1/pending"),
            "https://pool.example.com/api/v1/wallet/w1/pending"
        );
    }

    #[test]
    fn test_serde_roundtrip() {
        let tx = sample_tx(2, 3, &["alice", "bob"]);
        let json = serde_json::to_string(&tx).expect("serialize");
        let back: PartiallySignedTx = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(tx, back);
    }
}