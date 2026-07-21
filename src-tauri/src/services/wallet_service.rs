// services/wallet_service.rs — Wallet lifecycle orchestration
//
// Coordinates mnemonic generation, BIP32 key derivation, DB creation,
// and state management for wallet create/open/unlock operations.
//
// This is the Rust equivalent of Python's wallet_service.py.

use crate::core::{keystore, mnemonic};
use crate::db::{connection, repositories};
use crate::security::encryption;
use crate::state::{ActiveWallet, AppState};
use std::path::{Path, PathBuf};

/// Join a directory and filename into a cross-platform path string.
/// Uses std::path::PathBuf so the OS-native separator is applied
/// (/ on Unix, \ on Windows).
fn join_path(dir: &str, filename: &str) -> String {
    PathBuf::from(dir)
        .join(filename)
        .to_string_lossy()
        .to_string()
}

/// Result of creating a new wallet.
#[derive(Debug, serde::Serialize)]
pub struct CreateWalletResult {
    /// The BIP39 mnemonic phrase (only returned on creation, never stored in plaintext)
    pub mnemonic: String,
    /// Absolute path to the .sqlite file
    pub wallet_path: String,
    /// Account ID of the created default account
    pub account_id: i64,
    /// Whether a new mnemonic was generated (true) or an existing one was used (false)
    pub is_new_mnemonic: bool,
}

/// Result of opening an existing wallet.
#[derive(Debug, serde::Serialize)]
pub struct OpenWalletResult {
    pub wallet_path: String,
    pub wallet_name: String,
    pub account_name: String,
    pub is_unlocked: bool,
}

/// Result of getting wallet status.
#[derive(Debug, serde::Serialize)]
pub struct WalletStatus {
    pub is_open: bool,
    pub wallet_name: Option<String>,
    pub is_unlocked: bool,
    pub account_id: Option<i64>,
    pub xpub: Option<String>,
}

/// Error type for wallet operations.
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("password is required")]
    PasswordRequired,
    #[error("wallet already exists: {0}")]
    WalletAlreadyExists(String),
    #[error("wallet not found: {0}")]
    WalletNotFound(String),
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),
    #[error("no wallet is currently open")]
    NoWalletOpen,
    #[error("wallet is already unlocked")]
    AlreadyUnlocked,
    #[error("wallet is locked — unlock first")]
    WalletLocked,
    #[error("wrong password")]
    WrongPassword,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("encryption error: {0}")]
    Encryption(#[from] encryption::EncryptionError),
    #[error("BSV SDK error: {0}")]
    BsvSdk(String),
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl From<bsv::compat::error::CompatError> for WalletError {
    fn from(e: bsv::compat::error::CompatError) -> Self {
        WalletError::BsvSdk(e.to_string())
    }
}

/// Create a new wallet with a BIP32 account from a BIP39 mnemonic.
///
/// If no mnemonic is provided, a new 12-word mnemonic is generated.
/// The mnemonic is returned to the caller — it is NEVER stored in plaintext.
/// Only the derived xprv is stored (AES-CBC encrypted with the password).
pub async fn create_wallet(
    state: &AppState,
    name: &str,
    password: &str,
    provided_mnemonic: Option<&str>,
    mnemonic_passphrase: Option<&str>,
) -> Result<CreateWalletResult, WalletError> {
    if password.is_empty() {
        return Err(WalletError::PasswordRequired);
    }

    let name = if name.is_empty() {
        "default_wallet"
    } else {
        name
    };
    let wallet_path = join_path(&state.data_dir, &format!("{}.sqlite", name));

    if Path::new(&wallet_path).exists() {
        return Err(WalletError::WalletAlreadyExists(wallet_path));
    }

    // Generate or validate mnemonic
    let (mnemonic_str, is_new_mnemonic) = match provided_mnemonic {
        Some(m) => {
            mnemonic::validate_mnemonic(m)
                .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;
            (m.to_string(), false)
        }
        None => {
            let m =
                mnemonic::generate_mnemonic().map_err(|e| WalletError::BsvSdk(e.to_string()))?;
            (m, true)
        }
    };

    // Derive seed and BIP32 keys
    let seed = mnemonic::mnemonic_to_seed(&mnemonic_str, mnemonic_passphrase.unwrap_or(""))
        .map_err(|e| WalletError::BsvSdk(e.to_string()))?;
    let derived = keystore::derive_keys_from_seed(&seed)?;

    // Create keystore data (encrypts xprv, seed, passphrase with password)
    let ks_data =
        keystore::create_keystore_data(&mnemonic_str, mnemonic_passphrase, password, &derived);

    // Create the database file (all migrations + initial WalletData entries)
    connection::create_wallet_db(&wallet_path).await?;

    // Open the database
    let pool = connection::open_wallet_db(&wallet_path).await?;

    // Insert MasterKey
    let derivation_data = keystore::keystore_data_to_bytes(&ks_data);
    let masterkey_id = repositories::insert_master_key(
        &pool,
        None,
        keystore::DERIVATION_TYPE_BIP32,
        &derivation_data,
    )
    .await?;

    // Insert Account (Standard account, P2PKH)
    let account_id = repositories::insert_account(
        &pool,
        Some(masterkey_id),
        repositories::script_type::P2PKH,
        "Standard account",
    )
    .await?;

    // Store password-token in WalletData (for password verification)
    let random_bytes = {
        use rand::RngCore;
        let mut buf = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        hex::encode(buf)
    };
    let encrypted_token = encryption::pw_encode(&random_bytes, password);
    repositories::set_wallet_data(&pool, "password-token", &encrypted_token).await?;

    // Update next_* counters
    repositories::set_wallet_data(&pool, "next_masterkey_id", "2").await?;
    repositories::set_wallet_data(&pool, "next_account_id", "2").await?;

    // Set as active wallet in state
    let active = ActiveWallet {
        wallet_path: wallet_path.clone(),
        wallet_name: name.to_string(),
        db_pool: pool,
        keystore_data: ks_data,
        account_id,
        decrypted_xprv: Some(derived.xprv), // freshly created — already unlocked
    };

    let mut guard = state.active_wallet.lock().unwrap();
    *guard = Some(active);

    log::info!(
        "Wallet created at {} with account {} (new mnemonic: {})",
        wallet_path,
        account_id,
        is_new_mnemonic
    );

    Ok(CreateWalletResult {
        mnemonic: mnemonic_str,
        wallet_path,
        account_id,
        is_new_mnemonic,
    })
}

/// Open an existing wallet from disk.
///
/// Loads the DB and reads the keystore data from MasterKeys.
/// The wallet is opened in locked state — call unlock_wallet to decrypt the xprv.
pub async fn open_wallet(
    state: &AppState,
    wallet_path: &str,
) -> Result<OpenWalletResult, WalletError> {
    // Normalize path: accept with or without .sqlite extension
    let wallet_path = if wallet_path.ends_with(".sqlite") {
        wallet_path.to_string()
    } else {
        format!("{}.sqlite", wallet_path)
    };

    if !Path::new(&wallet_path).exists() {
        return Err(WalletError::WalletNotFound(wallet_path));
    }

    // Check if already open
    {
        let guard = state.active_wallet.lock().unwrap();
        if let Some(ref active) = *guard {
            if active.wallet_path == wallet_path {
                return Ok(OpenWalletResult {
                    wallet_path: active.wallet_path.clone(),
                    wallet_name: active.wallet_name.clone(),
                    account_name: "Standard account".to_string(),
                    is_unlocked: active.is_unlocked(),
                });
            }
        }
    }

    // Open DB
    let pool = connection::open_wallet_db(&wallet_path).await?;

    // Read master key
    let mk_row = repositories::get_first_master_key(&pool)
        .await?
        .ok_or_else(|| WalletError::Internal(anyhow::anyhow!("No master key found in wallet")))?;

    let ks_data = keystore::keystore_data_from_bytes(&mk_row.derivation_data).map_err(|e| {
        WalletError::Internal(anyhow::anyhow!("Failed to parse keystore data: {}", e))
    })?;

    // Read account
    let account = repositories::get_first_account(&pool).await?;
    let (account_name, account_id) = match account {
        Some(a) => (a.account_name, a.account_id),
        None => ("Unknown".to_string(), 0),
    };

    // Extract wallet name from path
    let wallet_name = Path::new(&wallet_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Set as active wallet (locked)
    let active = ActiveWallet {
        wallet_path: wallet_path.clone(),
        wallet_name: wallet_name.clone(),
        db_pool: pool,
        keystore_data: ks_data,
        account_id,
        decrypted_xprv: None, // locked
    };

    let mut guard = state.active_wallet.lock().unwrap();
    *guard = Some(active);

    log::info!("Wallet opened: {} (locked)", wallet_path);

    Ok(OpenWalletResult {
        wallet_path,
        wallet_name: wallet_name.clone(),
        account_name,
        is_unlocked: false,
    })
}

/// Close the currently open wallet.
pub fn close_wallet(state: &AppState) -> Result<(), WalletError> {
    let mut guard = state.active_wallet.lock().unwrap();
    if guard.is_none() {
        return Err(WalletError::NoWalletOpen);
    }

    let active = guard.take();
    if let Some(w) = active {
        // Close the DB pool synchronously — spawn a task if needed
        // Actually pool.close() is async, but we can just drop it
        // sqlx will close connections when the pool is dropped
        drop(w);
    }

    log::info!("Wallet closed");
    Ok(())
}

/// Unlock the currently open wallet by decrypting the xprv with the password.
pub fn unlock_wallet(state: &AppState, password: &str) -> Result<(), WalletError> {
    let mut guard = state.active_wallet.lock().unwrap();
    let active = guard.as_mut().ok_or(WalletError::NoWalletOpen)?;

    if active.is_unlocked() {
        return Err(WalletError::AlreadyUnlocked);
    }

    // Decrypt xprv
    let xprv = keystore::decrypt_xprv(&active.keystore_data, password)?;
    active.decrypted_xprv = Some(xprv);

    log::info!("Wallet unlocked: {}", active.wallet_name);
    Ok(())
}

/// Get the status of the currently open wallet.
pub fn get_wallet_status(state: &AppState) -> WalletStatus {
    let guard = state.active_wallet.lock().unwrap();
    match &*guard {
        None => WalletStatus {
            is_open: false,
            wallet_name: None,
            is_unlocked: false,
            account_id: None,
            xpub: None,
        },
        Some(active) => WalletStatus {
            is_open: true,
            wallet_name: Some(active.wallet_name.clone()),
            is_unlocked: active.is_unlocked(),
            account_id: Some(active.account_id),
            xpub: Some(active.keystore_data.xpub.clone()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn make_test_state(test_name: &str) -> AppState {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let temp_dir = std::env::temp_dir().join(format!("electrumsv_mc_ws_{}_{}", test_name, id));
        // Clean up any leftover from previous test runs
        if temp_dir.exists() {
            std::fs::remove_dir_all(&temp_dir).ok();
        }
        std::fs::create_dir_all(&temp_dir).unwrap();
        // Construct AppState directly with the unique data_dir
        AppState {
            data_dir: temp_dir.to_string_lossy().to_string(),
            active_wallet: std::sync::Mutex::new(None),
            network: std::sync::Mutex::new(crate::state::NetworkState::new()),
            pending_plans: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    #[tokio::test]
    async fn test_create_wallet_generates_mnemonic() {
        let state = make_test_state("gen_mnemonic");
        let result = create_wallet(&state, "test_create", "password123", None, None)
            .await
            .unwrap();

        assert!(result.is_new_mnemonic);
        assert!(!result.mnemonic.is_empty());
        let words: Vec<&str> = result.mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12);
        assert_eq!(result.account_id, 1);

        // Wallet should be open and unlocked
        let status = get_wallet_status(&state);
        assert!(status.is_open);
        assert!(status.is_unlocked);
        assert_eq!(status.wallet_name, Some("test_create".to_string()));

        close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_create_wallet_with_existing_mnemonic() {
        let state = make_test_state("existing_mnemonic");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let result = create_wallet(&state, "test_existing", "password123", Some(mnemonic), None)
            .await
            .unwrap();

        assert!(!result.is_new_mnemonic);
        assert_eq!(result.mnemonic, mnemonic);

        close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_create_wallet_invalid_mnemonic() {
        let state = make_test_state("invalid_mnemonic");
        let result = create_wallet(
            &state,
            "test_invalid",
            "password123",
            Some("not a valid mnemonic"),
            None,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_wallet_no_password() {
        let state = make_test_state("no_password");
        let result = create_wallet(&state, "test_no_pw", "", None, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_wallet_duplicate_name() {
        let state = make_test_state("dup_name");
        create_wallet(&state, "test_dup", "password123", None, None)
            .await
            .unwrap();
        close_wallet(&state).unwrap();

        let result = create_wallet(&state, "test_dup", "password123", None, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_open_wallet_locked() {
        let state = make_test_state("open_locked");
        create_wallet(&state, "test_open", "password123", None, None)
            .await
            .unwrap();
        close_wallet(&state).unwrap();

        // Wallet should not be open
        let status = get_wallet_status(&state);
        assert!(!status.is_open);

        // Open it
        let wallet_path = join_path(&state.data_dir, "test_open.sqlite");
        let result = open_wallet(&state, &wallet_path).await.unwrap();
        assert!(!result.is_unlocked);

        let status = get_wallet_status(&state);
        assert!(status.is_open);
        assert!(!status.is_unlocked);

        close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_unlock_wallet_correct_password() {
        let state = make_test_state("unlock_correct");
        create_wallet(&state, "test_unlock", "password123", None, None)
            .await
            .unwrap();
        close_wallet(&state).unwrap();

        let wallet_path = join_path(&state.data_dir, "test_unlock.sqlite");
        open_wallet(&state, &wallet_path).await.unwrap();

        // Should be locked
        let status = get_wallet_status(&state);
        assert!(!status.is_unlocked);

        // Unlock
        unlock_wallet(&state, "password123").unwrap();

        let status = get_wallet_status(&state);
        assert!(status.is_unlocked);

        close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_unlock_wallet_wrong_password() {
        let state = make_test_state("unlock_wrong");
        create_wallet(&state, "test_wrong_pw", "password123", None, None)
            .await
            .unwrap();
        close_wallet(&state).unwrap();

        let wallet_path = join_path(&state.data_dir, "test_wrong_pw.sqlite");
        open_wallet(&state, &wallet_path).await.unwrap();

        let result = unlock_wallet(&state, "wrong_password");
        assert!(result.is_err());

        // Should still be locked
        let status = get_wallet_status(&state);
        assert!(!status.is_unlocked);

        close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_full_lifecycle() {
        let state = make_test_state("lifecycle");

        // 1. Create
        let create_result = create_wallet(&state, "test_lifecycle", "mypass", None, None)
            .await
            .unwrap();
        assert!(create_result.is_new_mnemonic);
        assert!(get_wallet_status(&state).is_unlocked);

        // 2. Close
        close_wallet(&state).unwrap();
        assert!(!get_wallet_status(&state).is_open);

        // 3. Open
        let wallet_path = join_path(&state.data_dir, "test_lifecycle.sqlite");
        open_wallet(&state, &wallet_path).await.unwrap();
        assert!(get_wallet_status(&state).is_open);
        assert!(!get_wallet_status(&state).is_unlocked);

        // 4. Unlock
        unlock_wallet(&state, "mypass").unwrap();
        assert!(get_wallet_status(&state).is_unlocked);

        // 5. Close
        close_wallet(&state).unwrap();
        assert!(!get_wallet_status(&state).is_open);
    }

    #[tokio::test]
    async fn test_open_nonexistent_wallet() {
        let state = make_test_state("nonexistent");
        let result = open_wallet(&state, "/nonexistent/wallet.sqlite").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unlock_no_wallet_open() {
        let state = make_test_state("unlock_none");
        let result = unlock_wallet(&state, "password");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_close_no_wallet_open() {
        let state = make_test_state("close_none");
        let result = close_wallet(&state);
        assert!(result.is_err());
    }
}
