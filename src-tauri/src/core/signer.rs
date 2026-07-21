// core/signer.rs — Signer trait for transaction signing
//
// Provides a pluggable signing architecture:
// - Signer trait: unified interface for signing transactions
// - LocalSigner: signs with decrypted xprv using ECDSA via bsv-sdk
// - HardwareSigner: stub for external signing devices (feature-gated)
//
// Design (Murena-Prinzip):
// - HardwareSigner is compile-time gated with #[cfg(feature = "hardware-wallet")]
// - Runtime toggle is `hardware_wallet_enabled` in WalletData DB
// - Handy-App as signing device: later via Bluetooth/NFC/QR

use crate::core::transaction::{SelectedUtxo, TransactionError};
use bsv::compat::bip32::ExtendedKey;
use bsv::primitives::private_key::PrivateKey;
use bsv::primitives::transaction_signature::{SIGHASH_ALL, SIGHASH_FORKID};
use bsv::script::templates::p2pkh::P2PKH;
use bsv::script::templates::ScriptTemplateLock;
// ScriptTemplateUnlock import removed — not used in current implementation
use bsv::transaction::transaction::Transaction;
use thiserror::Error;

/// Signer type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SignerType {
    /// Local signer using decrypted xprv (ECDSA via bsv-sdk)
    Local,
    /// Hardware wallet signer (external device)
    Hardware,
}

/// Signer trait — pluggable transaction signing.
///
/// Implementations:
/// - LocalSigner: signs with xprv in memory
/// - HardwareSigner: delegates signing to external device (stub)
pub trait Signer: Send + Sync {
    /// Returns the type of this signer.
    fn signer_type(&self) -> SignerType;

    /// Whether this signer can currently sign (has key material / device connected).
    fn can_sign(&self) -> bool;

    /// Sign all unsigned inputs in the given transaction.
    ///
    /// Each input must have `source_txid` and `source_output_index` set.
    /// The signer derives the private key for each input's subpath,
    /// creates a P2PKH unlocking script, and sets it on the input.
    fn sign_tx(&self, tx: &mut Transaction, inputs: &[SelectedUtxo]) -> Result<(), SignerError>;
}

/// Signer errors.
#[derive(Debug, Error)]
pub enum SignerError {
    #[error("signer cannot sign: {0}")]
    CannotSign(String),
    #[error("key derivation failed: {0}")]
    DerivationFailed(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("BSV SDK error: {0}")]
    BsvSdk(String),
    #[error("input/source mismatch at index {index}: expected {expected} inputs, got {actual}")]
    InputMismatch {
        index: usize,
        expected: usize,
        actual: usize,
    },
    #[error("input {index} has no source txid")]
    NoSourceTxid { index: usize },
}

impl From<bsv::compat::error::CompatError> for SignerError {
    fn from(e: bsv::compat::error::CompatError) -> Self {
        SignerError::DerivationFailed(e.to_string())
    }
}

impl From<bsv::primitives::error::PrimitivesError> for SignerError {
    fn from(e: bsv::primitives::error::PrimitivesError) -> Self {
        SignerError::BsvSdk(e.to_string())
    }
}

impl From<bsv::script::error::ScriptError> for SignerError {
    fn from(e: bsv::script::error::ScriptError) -> Self {
        SignerError::BsvSdk(e.to_string())
    }
}

impl From<bsv::transaction::error::TransactionError> for SignerError {
    fn from(e: bsv::transaction::error::TransactionError) -> Self {
        SignerError::BsvSdk(e.to_string())
    }
}

impl From<TransactionError> for SignerError {
    fn from(e: TransactionError) -> Self {
        SignerError::BsvSdk(e.to_string())
    }
}

/// Local signer — signs transactions with a decrypted xprv.
///
/// The xprv is the account-level extended private key (Base58Check string).
/// For each input, the signer derives the child key at the input's subpath
/// (e.g. 0/3 for receiving index 3, or 1/0 for change index 0), creates a
/// P2PKH template, and signs the input.
pub struct LocalSigner {
    /// Account-level xprv (Base58Check string, decrypted)
    xprv: String,
}

impl LocalSigner {
    /// Create a new LocalSigner from a decrypted xprv string.
    pub fn new(xprv: &str) -> Self {
        LocalSigner {
            xprv: xprv.to_string(),
        }
    }

    /// Derive the private key for a given subpath (e.g. [0, 3] → "0/3").
    fn derive_private_key(&self, subpath: &[u32; 2]) -> Result<PrivateKey, SignerError> {
        let account_key = ExtendedKey::from_string(&self.xprv)?;
        let path = format!("{}/{}", subpath[0], subpath[1]);
        let child_key = account_key.derive(&path)?;

        // ExtendedKey.key is private — we extract the private key bytes
        // by re-encoding to base58 and decoding the payload.
        // The xprv base58 payload is 78 bytes: version(4) + depth(1) +
        // fingerprint(4) + child_index(4) + chain_code(32) + 0x00 + key(32)
        // So key bytes are at payload[46..78].
        let xprv_b58 = child_key.to_base58();
        let decoded = bsv::primitives::utils::base58_decode(&xprv_b58)
            .map_err(|e| SignerError::DerivationFailed(format!("base58 decode: {}", e)))?;

        if decoded.len() < 78 {
            return Err(SignerError::DerivationFailed(format!(
                "decoded xprv too short: {} bytes",
                decoded.len()
            )));
        }

        // Private key bytes are at [46..78] (after 0x00 prefix at [45])
        if decoded[45] != 0x00 {
            return Err(SignerError::DerivationFailed(
                "invalid xprv: expected 0x00 prefix before key bytes".to_string(),
            ));
        }

        let key_bytes = &decoded[46..78];
        let priv_key = PrivateKey::from_bytes(key_bytes)?;
        Ok(priv_key)
    }
}

impl Signer for LocalSigner {
    fn signer_type(&self) -> SignerType {
        SignerType::Local
    }

    fn can_sign(&self) -> bool {
        !self.xprv.is_empty()
    }

    fn sign_tx(&self, tx: &mut Transaction, inputs: &[SelectedUtxo]) -> Result<(), SignerError> {
        if !self.can_sign() {
            return Err(SignerError::CannotSign("xprv is empty".to_string()));
        }

        if tx.inputs.len() != inputs.len() {
            return Err(SignerError::InputMismatch {
                index: 0,
                expected: tx.inputs.len(),
                actual: inputs.len(),
            });
        }

        let sighash_type = SIGHASH_ALL | SIGHASH_FORKID; // 0x41

        for (i, utxo) in inputs.iter().enumerate() {
            // Verify the input has a source txid
            if tx.inputs[i].source_txid.is_none() {
                return Err(SignerError::NoSourceTxid { index: i });
            }

            // Derive the private key for this input's subpath
            let priv_key = self.derive_private_key(&utxo.subpath)?;

            // Create P2PKH template for signing
            let p2pkh = P2PKH::from_private_key(priv_key);

            // Create the source locking script (P2PKH for the sender)
            let source_locking_script = p2pkh.lock()?;

            // Sign the input: computes sighash preimage (BIP143/ForkID) and
            // creates the unlocking script
            tx.sign(
                i,
                &p2pkh,
                sighash_type,
                utxo.satoshis,
                &source_locking_script,
            )?;
        }

        Ok(())
    }
}

/// Hardware wallet signer — stub for external signing devices.
///
/// This signer is only compiled when the `hardware-wallet` cargo feature is enabled.
/// It delegates signing to an external device (hardware wallet, handy-app).
///
/// Murena-Prinzip: The feature is OFF by default. Enable with:
///   cargo build --features hardware-wallet
///
/// Runtime toggle: `hardware_wallet_enabled` in WalletData DB.
#[cfg(feature = "hardware-wallet")]
pub struct HardwareSigner {
    /// Device identifier (e.g. Bluetooth MAC, NFC ID, or app instance ID)
    device_id: String,
}

#[cfg(feature = "hardware-wallet")]
impl HardwareSigner {
    /// Create a new HardwareSigner stub.
    pub fn new(device_id: &str) -> Self {
        HardwareSigner {
            device_id: device_id.to_string(),
        }
    }
}

#[cfg(feature = "hardware-wallet")]
impl Signer for HardwareSigner {
    fn signer_type(&self) -> SignerType {
        SignerType::Hardware
    }

    fn can_sign(&self) -> bool {
        // Stub: always false until device communication is implemented
        false
    }

    fn sign_tx(&self, _tx: &mut Transaction, _inputs: &[SelectedUtxo]) -> Result<(), SignerError> {
        Err(SignerError::CannotSign(format!(
            "hardware wallet signing not yet implemented (device: {})",
            self.device_id
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::transaction::{PaymentOutput, TxBuilder};
    use bsv::compat::bip32::ExtendedKey;
    use bsv::primitives::private_key::PrivateKey;

    // Use a known test mnemonic to derive a deterministic xprv
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn get_test_xprv() -> String {
        let seed = crate::core::mnemonic::mnemonic_to_seed(TEST_MNEMONIC, "").unwrap();
        let derived = crate::core::keystore::derive_keys_from_seed(&seed).unwrap();
        derived.xprv
    }

    fn make_test_utxos() -> Vec<SelectedUtxo> {
        // Derive a real address from the test xprv to create a valid UTXO
        let xprv = get_test_xprv();
        let account_key = ExtendedKey::from_string(&xprv).unwrap();
        let child = account_key.derive("0/0").unwrap();
        let pubkey = child.public_key().unwrap();
        let address = crate::core::address::pubkey_to_p2pkh_address(&pubkey);

        // We need a real source txid — use a dummy one for testing
        // The signing will work as long as the locking script matches the key
        vec![SelectedUtxo {
            tx_hash_hex: "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458"
                .to_string(),
            tx_index: 0,
            satoshis: 100_000,
            keyinstance_id: 1,
            subpath: [0, 0],
        }]
    }

    #[test]
    fn test_local_signer_type() {
        let signer = LocalSigner::new("xprv_test");
        assert_eq!(signer.signer_type(), SignerType::Local);
    }

    #[test]
    fn test_local_signer_can_sign() {
        let signer = LocalSigner::new("xprv_test");
        assert!(signer.can_sign());

        let empty = LocalSigner::new("");
        assert!(!empty.can_sign());
    }

    #[test]
    fn test_local_signer_derive_private_key() {
        let xprv = get_test_xprv();
        let signer = LocalSigner::new(&xprv);

        // Derive key at 0/0
        let key = signer.derive_private_key(&[0, 0]).unwrap();
        let key_hex = key.to_hex();
        assert_eq!(key_hex.len(), 64); // 32 bytes = 64 hex chars

        // Derive the same key via ExtendedKey for verification
        let account_key = ExtendedKey::from_string(&xprv).unwrap();
        let child = account_key.derive("0/0").unwrap();
        let child_xprv = child.to_base58();
        let decoded = bsv::primitives::utils::base58_decode(&child_xprv).unwrap();
        let expected_hex = hex::encode(&decoded[46..78]);
        assert_eq!(key_hex, expected_hex);
    }

    #[test]
    fn test_local_signer_signs_transaction() {
        let xprv = get_test_xprv();
        let signer = LocalSigner::new(&xprv);

        // Build an unsigned transaction
        let utxos = make_test_utxos();
        let outputs = vec![PaymentOutput {
            address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(), // genesis address
            satoshis: 50_000,
        }];

        let (mut tx, _) = TxBuilder::build_unsigned(
            &utxos,
            &outputs,
            Some("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
            1,
            None,
            None,
        )
        .unwrap();

        // Before signing: no unlocking script
        assert!(tx.inputs[0].unlocking_script.is_none());

        // Sign
        signer.sign_tx(&mut tx, &utxos).unwrap();

        // After signing: unlocking script should be set
        assert!(tx.inputs[0].unlocking_script.is_some());

        // Verify the txid can be computed (serialization works)
        let txid = tx.id().unwrap();
        assert_eq!(txid.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_local_signer_wrong_input_count() {
        let xprv = get_test_xprv();
        let signer = LocalSigner::new(&xprv);

        let utxos = make_test_utxos();
        let outputs = vec![PaymentOutput {
            address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            satoshis: 50_000,
        }];

        let (mut tx, _) = TxBuilder::build_unsigned(
            &utxos,
            &outputs,
            Some("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
            1,
            None,
            None,
        )
        .unwrap();

        // Pass wrong number of inputs metadata
        let wrong_inputs = vec![];
        let result = signer.sign_tx(&mut tx, &wrong_inputs);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::InputMismatch { .. }
        ));
    }

    #[test]
    fn test_local_signer_empty_xprv_cannot_sign() {
        let signer = LocalSigner::new("");
        let mut tx = Transaction::new();
        let result = signer.sign_tx(&mut tx, &[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::CannotSign(_)));
    }

    #[test]
    fn test_signer_type_serialization() {
        let local = SignerType::Local;
        let json = serde_json::to_string(&local).unwrap();
        assert!(json.contains("Local") || json.contains("local"));

        let restored: SignerType = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, SignerType::Local);
    }

    #[test]
    fn test_local_signer_signs_multiple_inputs() {
        let xprv = get_test_xprv();
        let signer = LocalSigner::new(&xprv);

        // Create UTXOs at different subpaths
        let utxos = vec![
            SelectedUtxo {
                tx_hash_hex: "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458"
                    .to_string(),
                tx_index: 0,
                satoshis: 100_000,
                keyinstance_id: 1,
                subpath: [0, 0],
            },
            SelectedUtxo {
                tx_hash_hex: "b477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58459"
                    .to_string(),
                tx_index: 1,
                satoshis: 50_000,
                keyinstance_id: 2,
                subpath: [0, 1],
            },
        ];

        let outputs = vec![PaymentOutput {
            address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            satoshis: 120_000,
        }];

        let (mut tx, _) = TxBuilder::build_unsigned(
            &utxos,
            &outputs,
            Some("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
            1,
            None,
            None,
        )
        .unwrap();

        // Sign both inputs
        signer.sign_tx(&mut tx, &utxos).unwrap();

        // Both inputs should have unlocking scripts
        assert!(tx.inputs[0].unlocking_script.is_some());
        assert!(tx.inputs[1].unlocking_script.is_some());

        // Verify txid
        let txid = tx.id().unwrap();
        assert_eq!(txid.len(), 64);
    }
}
