// core/keystore.rs — BIP32 HD key derivation and wallet keystore management
//
// Derives the master xprv from a BIP39 seed using BIP44 path m/44'/0'/0'
// (standard for Bitcoin/BSV). Stores the xprv encrypted with the wallet password
// using the same AES-CBC format as the Python backend (pw_encode/pw_decode).
//
// Database storage format (MasterKeys table, derivation_data BLOB):
//   JSON object with keys: xpub, xprv (encrypted), seed (encrypted),
//   seed_type, derivation, bip39_words
//
// This matches the Python keystore's to_derivation_data() format so
// wallets created by Python can be opened by Rust and vice versa.

use crate::security::encryption;
use bsv::compat::bip32::ExtendedKey;
use bsv::compat::error::CompatError;
use serde::{Deserialize, Serialize};

/// BIP44 derivation path for BSV (same as Bitcoin): m/44'/0'/0'
pub const DERIVATION_PATH: &str = "m/44'/0'/0'";

/// DerivationType::BIP32 = 3 (matches Python DerivationType.IntEnum)
pub const DERIVATION_TYPE_BIP32: i32 = 3;

fn legacy_seed_type() -> String {
    "legacy".to_string()
}

/// Derivation data stored in the MasterKeys table.
///
/// This is serialized as JSON and stored in the `derivation_data` BLOB column.
/// It matches the Python keystore's `to_derivation_data()` output format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyStoreData {
    /// Extended public key (Base58Check xpub string, unencrypted)
    pub xpub: String,
    /// Extended private key (Base58Check xprv string, AES-CBC encrypted with password)
    pub xprv: String,
    /// Seed type — always "bip39" for new wallets
    #[serde(default = "legacy_seed_type")]
    pub seed_type: String,
    /// BIP44 derivation path — e.g. "m/44'/0'/0'"
    pub derivation: String,
    /// BIP39 mnemonic words (AES-CBC encrypted with password)
    #[serde(default)]
    pub seed: String,
    /// BIP39 passphrase if any (AES-CBC encrypted with password), empty string if none
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
}

/// Result of deriving keys from a mnemonic.
pub struct DerivedKeys {
    /// Extended private key string (Base58Check xprv)
    pub xprv: String,
    /// Extended public key string (Base58Check xpub)
    pub xpub: String,
    /// BIP39 seed bytes (64 bytes)
    pub seed: Vec<u8>,
}

/// Derive the account-level xprv/xpub from a BIP39 seed.
///
/// Uses BIP44 path m/44'/0'/0' (purpose=44', coin=0', account=0').
/// This matches the Python wallet_service.create_wallet() flow.
pub fn derive_keys_from_seed(seed: &[u8]) -> Result<DerivedKeys, CompatError> {
    let master = ExtendedKey::from_seed(seed)?;
    let account_key = master.derive(DERIVATION_PATH)?;
    let xprv = account_key.to_base58();
    let xpub = account_key.to_public()?.to_base58();

    Ok(DerivedKeys {
        xprv,
        xpub,
        seed: seed.to_vec(),
    })
}

/// Create keystore data for storage in the MasterKeys table.
///
/// Encrypts the xprv, mnemonic seed phrase, and passphrase with the wallet password.
pub fn create_keystore_data(
    mnemonic: &str,
    mnemonic_passphrase: Option<&str>,
    password: &str,
    derived: &DerivedKeys,
) -> KeyStoreData {
    KeyStoreData {
        xpub: derived.xpub.clone(),
        xprv: encryption::pw_encode(&derived.xprv, password),
        seed_type: "bip39".to_string(),
        derivation: DERIVATION_PATH.to_string(),
        seed: encryption::pw_encode(mnemonic, password),
        passphrase: mnemonic_passphrase.map(|p| encryption::pw_encode(p, password)),
    }
}

/// Serialize keystore data to JSON bytes for the derivation_data BLOB column.
pub fn keystore_data_to_bytes(data: &KeyStoreData) -> Vec<u8> {
    serde_json::to_vec(data).expect("keystore data serialization should not fail")
}

/// Deserialize keystore data from the derivation_data BLOB.
pub fn keystore_data_from_bytes(bytes: &[u8]) -> Result<KeyStoreData, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// Decrypt the xprv from keystore data using the wallet password.
///
/// Returns the raw xprv string (Base58Check).
pub fn decrypt_xprv(
    data: &KeyStoreData,
    password: &str,
) -> Result<String, encryption::EncryptionError> {
    encryption::pw_decode(&data.xprv, password)
}

/// Decrypt the mnemonic seed phrase from keystore data.
pub fn decrypt_mnemonic(
    data: &KeyStoreData,
    password: &str,
) -> Result<String, encryption::EncryptionError> {
    encryption::pw_decode(&data.seed, password)
}

/// Verify a password against keystore data by attempting to decrypt the xprv.
pub fn verify_password(data: &KeyStoreData, password: &str) -> bool {
    decrypt_xprv(data, password).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::mnemonic;

    // Known BIP39 test vector: "abandon abandon ... about" with empty passphrase
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_derive_keys_from_known_seed() {
        let seed = mnemonic::mnemonic_to_seed(TEST_MNEMONIC, "").unwrap();
        let derived = derive_keys_from_seed(&seed).unwrap();

        // The xprv should start with "xprv" (mainnet private key prefix)
        assert!(derived.xprv.starts_with("xprv"));
        assert!(derived.xpub.starts_with("xpub"));
        assert_ne!(derived.xprv, derived.xpub);
    }

    #[test]
    fn test_keystore_data_encrypt_decrypt_roundtrip() {
        let seed = mnemonic::mnemonic_to_seed(TEST_MNEMONIC, "").unwrap();
        let derived = derive_keys_from_seed(&seed).unwrap();
        let password = "test_password_123";

        let ks_data = create_keystore_data(TEST_MNEMONIC, None, password, &derived);

        // xprv should be encrypted (not plaintext)
        assert_ne!(ks_data.xprv, derived.xprv);

        // Decrypt and verify
        let decrypted_xprv = decrypt_xprv(&ks_data, password).unwrap();
        assert_eq!(decrypted_xprv, derived.xprv);

        let decrypted_mnemonic = decrypt_mnemonic(&ks_data, password).unwrap();
        assert_eq!(decrypted_mnemonic, TEST_MNEMONIC);
    }

    #[test]
    fn test_verify_password_correct() {
        let seed = mnemonic::mnemonic_to_seed(TEST_MNEMONIC, "").unwrap();
        let derived = derive_keys_from_seed(&seed).unwrap();
        let password = "correct_password";
        let ks_data = create_keystore_data(TEST_MNEMONIC, None, password, &derived);

        assert!(verify_password(&ks_data, password));
    }

    #[test]
    fn test_verify_password_wrong() {
        let seed = mnemonic::mnemonic_to_seed(TEST_MNEMONIC, "").unwrap();
        let derived = derive_keys_from_seed(&seed).unwrap();
        let password = "correct_password";
        let ks_data = create_keystore_data(TEST_MNEMONIC, None, password, &derived);

        assert!(!verify_password(&ks_data, "wrong_password"));
    }

    #[test]
    fn test_keystore_data_serialization_roundtrip() {
        let seed = mnemonic::mnemonic_to_seed(TEST_MNEMONIC, "").unwrap();
        let derived = derive_keys_from_seed(&seed).unwrap();
        let password = "test_password";
        let ks_data =
            create_keystore_data(TEST_MNEMONIC, Some("passphrase123"), password, &derived);

        let bytes = keystore_data_to_bytes(&ks_data);
        let restored = keystore_data_from_bytes(&bytes).unwrap();

        assert_eq!(restored.xpub, ks_data.xpub);
        assert_eq!(restored.xprv, ks_data.xprv);
        assert_eq!(restored.seed_type, ks_data.seed_type);
        assert_eq!(restored.derivation, ks_data.derivation);
        assert_eq!(restored.passphrase, ks_data.passphrase);
    }

    #[test]
    fn test_keystore_data_deserializes_legacy_python_bip32_wallet() {
        let legacy = br#"{
            "subpaths": [[0, 0], [1, 0]],
            "xpub": "legacy-xpub",
            "xprv": "legacy-encrypted-xprv",
            "derivation": "m/44'/0'/0'"
        }"#;

        let restored = keystore_data_from_bytes(legacy).unwrap();

        assert_eq!(restored.xpub, "legacy-xpub");
        assert_eq!(restored.xprv, "legacy-encrypted-xprv");
        assert_eq!(restored.derivation, "m/44'/0'/0'");
        assert_eq!(restored.seed_type, "legacy");
        assert!(restored.seed.is_empty());
        assert_eq!(restored.passphrase, None);
    }
}
