// features/label_sync.rs — Wallet label synchronization across devices
//
// Standalone network service module (NOT an OnChainDataDetector).
//
// Syncs user-defined labels (address labels, transaction labels) across
// multiple devices running the same wallet. Labels are encrypted client-side
// with AES-256-CBC before being uploaded to a shared label-sync server, so
// the server never sees plaintext label data.
//
// Ported conceptually from archive/electrumsv/feature_controller.py
// (LabelSyncFeature, feature_id="label_sync",
//  description="Sync address and transaction labels").

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Error type
// ============================================================================

/// Errors that can occur during label synchronization.
#[derive(Debug, Error)]
pub enum LabelSyncError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("server returned status {status}: {body}")]
    Server { status: u16, body: String },
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("decryption failed: {0}")]
    Decryption(String),
    #[error("invalid label id: {0}")]
    InvalidId(String),
}

// ============================================================================
// Data types
// ============================================================================

/// What kind of object a label is attached to.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LabelKind {
    Address,
    Transaction,
}

/// A user-defined label stored locally (plaintext).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletLabel {
    /// Unique id (e.g. the address or txid the label applies to).
    pub id: String,
    /// Kind of object being labelled.
    pub kind: LabelKind,
    /// Human-readable label text.
    pub label: String,
    /// Last-modified timestamp (unix seconds).
    pub updated_at: i64,
}

/// An encrypted label as exchanged with the sync server.
///
/// The server only ever sees the ciphertext; the wallet key never leaves
/// the device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EncryptedLabel {
    pub id: String,
    pub kind: LabelKind,
    /// Base64-encoded ciphertext (AES-256-CBC).
    pub ciphertext: String,
    /// Base64-encoded IV / nonce used for this ciphertext.
    pub nonce: String,
    pub updated_at: i64,
}

// ============================================================================
// Local crypto — AES-256-CBC with a passphrase-derived key
// ============================================================================

/// Derive a 256-bit AES key from a passphrase using PBKDF2-HMAC-SHA256.
fn derive_key(passphrase: &[u8], salt: &[u8]) -> [u8; 32] {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase, salt, 100_000, &mut key);
    key
}

/// Encrypt a label's text with AES-256-CBC.
///
/// Returns (ciphertext_base64, iv_base64).
fn encrypt_label(
    plaintext: &str,
    key: &[u8; 32],
) -> Result<(String, String), LabelSyncError> {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use rand::RngCore;

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let padded = Aes256CbcEnc::new(key.into(), &iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes());

    Ok((B64.encode(&padded), B64.encode(iv)))
}

/// Decrypt a label's text with AES-256-CBC.
fn decrypt_label(
    ciphertext_b64: &str,
    iv_b64: &str,
    key: &[u8; 32],
) -> Result<String, LabelSyncError> {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    let ciphertext = B64
        .decode(ciphertext_b64)
        .map_err(|e| LabelSyncError::Decryption(e.to_string()))?;
    let iv = B64
        .decode(iv_b64)
        .map_err(|e| LabelSyncError::Decryption(e.to_string()))?;

    if iv.len() != 16 {
        return Err(LabelSyncError::Decryption("IV must be 16 bytes".to_string()));
    }
    let mut iv_arr = [0u8; 16];
    iv_arr.copy_from_slice(&iv);

    let plaintext = Aes256CbcDec::new(key.into(), &iv_arr.into())
        .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
        .map_err(|e| LabelSyncError::Decryption(e.to_string()))?;

    String::from_utf8(plaintext).map_err(|e| LabelSyncError::Decryption(e.to_string()))
}

// ============================================================================
// Sync client
// ============================================================================

/// HTTP client for a label-sync server.
///
/// Holds the wallet's passphrase-derived key in memory so labels can be
/// encrypted before upload and decrypted after download.
pub struct LabelSyncClient {
    base_url: String,
    http: reqwest::Client,
    key: [u8; 32],
}

impl LabelSyncClient {
    /// Create a client with a passphrase and a fixed salt.
    /// The same passphrase + salt must be used on every device sharing labels.
    pub fn new(
        base_url: impl Into<String>,
        passphrase: &str,
        salt: &[u8],
    ) -> Self {
        Self {
            base_url: base_url.into(),
            http: reqwest::Client::new(),
            key: derive_key(passphrase.as_bytes(), salt),
        }
    }

    fn url(&self, path: &str) -> String {
        let base = self.base_url.trim_end_matches('/');
        format!("{}/{}", base, path.trim_start_matches('/'))
    }

    /// Encrypt a local label into the wire format.
    pub fn encrypt(&self, label: &WalletLabel) -> Result<EncryptedLabel, LabelSyncError> {
        let (ciphertext, nonce) = encrypt_label(&label.label, &self.key)?;
        Ok(EncryptedLabel {
            id: label.id.clone(),
            kind: label.kind,
            ciphertext,
            nonce,
            updated_at: label.updated_at,
        })
    }

    /// Decrypt a downloaded encrypted label back into plaintext form.
    pub fn decrypt(&self, enc: &EncryptedLabel) -> Result<WalletLabel, LabelSyncError> {
        let plaintext = decrypt_label(&enc.ciphertext, &enc.nonce, &self.key)?;
        Ok(WalletLabel {
            id: enc.id.clone(),
            kind: enc.kind,
            label: plaintext,
            updated_at: enc.updated_at,
        })
    }

    /// Push all local labels to the sync server (full overwrite).
    pub async fn push(&self, wallet_id: &str, labels: &[WalletLabel]) -> Result<(), LabelSyncError> {
        let encrypted: Vec<EncryptedLabel> = labels
            .iter()
            .map(|l| self.encrypt(l))
            .collect::<Result<_, _>>()?;

        let resp = self
            .http
            .post(self.url(&format!("api/v1/labels/{}/push", wallet_id)))
            .json(&encrypted)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(LabelSyncError::Server { status, body });
        }
        Ok(())
    }

    /// Pull all labels for a wallet from the sync server and decrypt them.
    pub async fn pull(&self, wallet_id: &str) -> Result<Vec<WalletLabel>, LabelSyncError> {
        let resp = self
            .http
            .get(self.url(&format!("api/v1/labels/{}/pull", wallet_id)))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(LabelSyncError::Server { status, body });
        }

        let encrypted: Vec<EncryptedLabel> = resp.json().await?;
        encrypted
            .iter()
            .map(|e| self.decrypt(e))
            .collect()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PASSPHRASE: &str = "correct horse battery staple";
    const TEST_SALT: &[u8] = b"electrumsv-mc-labelsalt";

    fn make_client() -> LabelSyncClient {
        LabelSyncClient::new("http://localhost:0", TEST_PASSPHRASE, TEST_SALT)
    }

    fn sample_label() -> WalletLabel {
        WalletLabel {
            id: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            kind: LabelKind::Address,
            label: "Satoshi's address".to_string(),
            updated_at: 1700000000,
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let client = make_client();
        let label = sample_label();
        let enc = client.encrypt(&label).expect("encrypt");
        assert_ne!(enc.ciphertext, label.label);
        let dec = client.decrypt(&enc).expect("decrypt");
        assert_eq!(dec, label);
    }

    #[test]
    fn test_decrypt_with_wrong_passphrase_fails() {
        let client_a = LabelSyncClient::new("http://localhost:0", "passphrase A", TEST_SALT);
        let client_b = LabelSyncClient::new("http://localhost:0", "passphrase B", TEST_SALT);

        let label = sample_label();
        let enc = client_a.encrypt(&label).expect("encrypt with A");
        let err = client_b.decrypt(&enc).unwrap_err();
        assert!(matches!(err, LabelSyncError::Decryption(_)));
    }

    #[test]
    fn test_encrypted_label_is_not_plaintext() {
        let client = make_client();
        let label = sample_label();
        let enc = client.encrypt(&label).expect("encrypt");
        // Ciphertext must not contain the plaintext label.
        assert!(!enc.ciphertext.contains(&label.label));
        // Ciphertext must be valid base64.
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        assert!(B64.decode(&enc.ciphertext).is_ok());
    }

    #[test]
    fn test_serde_roundtrip_encrypted_label() {
        let enc = EncryptedLabel {
            id: "txid-1".to_string(),
            kind: LabelKind::Transaction,
            ciphertext: "Y2lwaGVy".to_string(),
            nonce: "bm9uY2U=".to_string(),
            updated_at: 1234567890,
        };
        let json = serde_json::to_string(&enc).expect("serialize");
        let back: EncryptedLabel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(enc, back);
    }

    #[test]
    fn test_label_kind_serialization() {
        assert_eq!(
            serde_json::to_string(&LabelKind::Address).expect("ser"),
            "\"address\""
        );
        assert_eq!(
            serde_json::to_string(&LabelKind::Transaction).expect("ser"),
            "\"transaction\""
        );
    }
}