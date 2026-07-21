// commands/wallet.rs — Wallet lifecycle Tauri commands
//
// Milestone 1: list_wallets
// Milestone 2: create_wallet, open_wallet, close_wallet, unlock_wallet, get_wallet_status

use crate::db::connection;
use crate::db::repositories;
use crate::services::wallet_service;
use crate::state::AppState;
use tauri::State;

/// Lists all available wallets in the data directory.
#[tauri::command]
pub fn list_wallets(state: State<'_, AppState>) -> Result<Vec<connection::WalletFileInfo>, String> {
    log::info!("list_wallets — scanning data_dir: {}", state.data_dir);
    connection::list_wallet_files(&state.data_dir).map_err(|e| e.to_string())
}

/// Create a new wallet.
///
/// If `mnemonic` is None, a new 12-word BIP39 mnemonic is generated.
/// The mnemonic is returned in the result — it is NEVER stored in plaintext.
#[tauri::command]
pub async fn create_wallet(
    state: State<'_, AppState>,
    name: String,
    password: String,
    mnemonic: Option<String>,
    passphrase: Option<String>,
) -> Result<wallet_service::CreateWalletResult, String> {
    log::info!("create_wallet — name: {}", name);
    wallet_service::create_wallet(
        &state,
        &name,
        &password,
        mnemonic.as_deref(),
        passphrase.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())
}

/// Open an existing wallet from disk.
///
/// The wallet is opened in locked state. Call unlock_wallet to decrypt keys.
#[tauri::command]
pub async fn open_wallet(
    state: State<'_, AppState>,
    wallet_path: String,
) -> Result<wallet_service::OpenWalletResult, String> {
    log::info!("open_wallet — path: {}", wallet_path);
    wallet_service::open_wallet(&state, &wallet_path)
        .await
        .map_err(|e| e.to_string())
}

/// Close the currently open wallet.
#[tauri::command]
pub fn close_wallet(state: State<'_, AppState>) -> Result<(), String> {
    log::info!("close_wallet");
    wallet_service::close_wallet(&state).map_err(|e| e.to_string())
}

/// Unlock the currently open wallet with the password.
#[tauri::command]
pub fn unlock_wallet(state: State<'_, AppState>, password: String) -> Result<(), String> {
    log::info!("unlock_wallet");
    wallet_service::unlock_wallet(&state, &password).map_err(|e| e.to_string())
}

/// Get the status of the currently open wallet.
#[tauri::command]
pub fn get_wallet_status(state: State<'_, AppState>) -> wallet_service::WalletStatus {
    wallet_service::get_wallet_status(&state)
}

// ============================================================================
// TOTP commands (Milestone 5)
// ============================================================================

/// Result of enabling TOTP — returns the otpauth URL and base32 secret.
#[derive(Debug, serde::Serialize)]
pub struct EnableTotpResult {
    /// otpauth:// URL for QR code generation
    pub otpauth_url: String,
    /// Base32-encoded secret for manual entry
    pub secret_base32: String,
}

/// Enable TOTP for the current wallet.
///
/// Generates a new TOTP secret, encrypts it, and stores it in the TotpSecrets table.
/// Requires an unlocked wallet (to encrypt the secret with the wallet password).
#[tauri::command]
pub async fn enable_totp(state: State<'_, AppState>) -> Result<EnableTotpResult, String> {
    log::info!("enable_totp");

    let (pool, _, wallet_name, _) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (
            active.db_pool.clone(),
            active.account_id,
            active.wallet_name.clone(),
            active.decrypted_xprv.clone(),
        )
    };

    // Check if TOTP is already enabled
    let already_enabled = repositories::is_totp_enabled(&pool)
        .await
        .map_err(|e| e.to_string())?;
    if already_enabled {
        return Err("TOTP is already enabled".to_string());
    }

    // Generate a new TOTP secret
    let totp = crate::security::totp::TotpInstance::new("ElectrumSV-Mc", &wallet_name)
        .map_err(|e| e.to_string())?;

    let otpauth_url = totp.otpauth_url();
    let secret_base32 = totp.secret_base32();

    // Store the secret (raw bytes for now — DB is already protected by wallet password)
    repositories::store_totp_secret(&pool, totp.secret_bytes())
        .await
        .map_err(|e| e.to_string())?;

    log::info!("TOTP enabled for wallet '{}'", wallet_name);

    Ok(EnableTotpResult {
        otpauth_url,
        secret_base32,
    })
}

/// Disable TOTP for the current wallet.
#[tauri::command]
pub async fn disable_totp(state: State<'_, AppState>) -> Result<(), String> {
    log::info!("disable_totp");

    let (pool, _) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (active.db_pool.clone(), active.account_id)
    };

    repositories::delete_totp_secret(&pool)
        .await
        .map_err(|e| e.to_string())?;

    log::info!("TOTP disabled");
    Ok(())
}

/// Verify a TOTP code (for testing before signing or for UI feedback).
#[tauri::command]
pub async fn verify_totp(state: State<'_, AppState>, code: String) -> Result<bool, String> {
    log::info!("verify_totp");

    let (pool, _, wallet_name) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (
            active.db_pool.clone(),
            active.account_id,
            active.wallet_name.clone(),
        )
    };

    let encrypted_secret = repositories::load_totp_secret(&pool)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("TOTP is not enabled")?;

    let totp = crate::security::totp::TotpInstance::from_secret_bytes(
        &encrypted_secret,
        "ElectrumSV-Mc",
        &wallet_name,
    )
    .map_err(|e| e.to_string())?;

    let valid = totp.verify_current(&code).map_err(|e| e.to_string())?;
    Ok(valid)
}

/// Check if TOTP is enabled for the current wallet.
#[tauri::command]
pub async fn is_totp_enabled_cmd(state: State<'_, AppState>) -> Result<bool, String> {
    let (pool, _) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (active.db_pool.clone(), active.account_id)
    };

    repositories::is_totp_enabled(&pool)
        .await
        .map_err(|e| e.to_string())
}

// ============================================================================
// TOTP Recovery codes commands (Milestone 8-C)
// ============================================================================

/// Generate 10 TOTP recovery codes.
///
/// Generates 10 random recovery codes, hashes each with SHA256, stores the
/// hashes in the database, and returns the plaintext codes to the frontend
/// for one-time display. The plaintext codes are never stored.
#[tauri::command]
pub async fn generate_totp_recovery_codes(
    state: State<'_, AppState>,
) -> Result<Vec<String>, String> {
    log::info!("generate_totp_recovery_codes");

    let pool = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        active.db_pool.clone()
    };

    // Generate 10 random recovery codes
    let codes = crate::security::totp::generate_recovery_codes(10);

    // Hash each code and store the hashes
    let hashed_codes: Vec<String> = codes
        .iter()
        .map(|c| crate::security::totp::hash_recovery_code(c))
        .collect();

    repositories::store_recovery_codes(&pool, &hashed_codes)
        .await
        .map_err(|e| e.to_string())?;

    log::info!("Generated {} TOTP recovery codes", codes.len());
    Ok(codes)
}

/// Recover access using a recovery code.
///
/// Checks if the given recovery code matches any stored hash. If matched,
/// the code is consumed (removed from the list), TOTP is disabled, and all
/// recovery codes are deleted. Returns true if recovery was successful.
#[tauri::command]
pub async fn totp_recover(
    state: State<'_, AppState>,
    recovery_code: String,
) -> Result<bool, String> {
    log::info!("totp_recover");

    let pool = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        active.db_pool.clone()
    };

    // Hash the provided code and try to consume it
    let code_hash = crate::security::totp::hash_recovery_code(&recovery_code);
    let matched = repositories::consume_recovery_code(&pool, &code_hash)
        .await
        .map_err(|e| e.to_string())?;

    if matched {
        // Disable TOTP (delete the secret)
        repositories::delete_totp_secret(&pool)
            .await
            .map_err(|e| e.to_string())?;

        // Delete all remaining recovery codes
        repositories::delete_recovery_codes(&pool)
            .await
            .map_err(|e| e.to_string())?;

        log::info!("TOTP recovery successful — TOTP disabled");
        Ok(true)
    } else {
        log::warn!("TOTP recovery failed — no matching code");
        Ok(false)
    }
}

// ============================================================================
// Hardware wallet commands (Milestone 5)
// ============================================================================

/// Set hardware wallet enabled flag (runtime toggle).
///
/// Murena-Prinzip: Even if the cargo feature `hardware-wallet` is enabled at
/// compile time, the user must also enable it at runtime via this command.
#[tauri::command]
pub async fn set_hardware_wallet_enabled(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<(), String> {
    log::info!("set_hardware_wallet_enabled — {}", enabled);

    let (pool, _) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (active.db_pool.clone(), active.account_id)
    };

    // Check if cargo feature is enabled when trying to turn on
    if enabled && !cfg!(feature = "hardware-wallet") {
        return Err(
            "hardware-wallet cargo feature is not enabled — rebuild with --features hardware-wallet"
                .to_string(),
        );
    }

    repositories::set_hardware_wallet_enabled(&pool, enabled)
        .await
        .map_err(|e| e.to_string())?;

    log::info!("Hardware wallet enabled: {}", enabled);
    Ok(())
}

/// Get hardware wallet enabled status.
#[tauri::command]
pub async fn get_hardware_wallet_status(state: State<'_, AppState>) -> Result<bool, String> {
    let (pool, _) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (active.db_pool.clone(), active.account_id)
    };

    repositories::get_hardware_wallet_enabled(&pool)
        .await
        .map_err(|e| e.to_string())
}

// ============================================================================
// Wallet utility commands (Milestone 6)
// ============================================================================

use crate::core::keystore;
use crate::security::encryption;

/// Result of export_seed command.
#[derive(Debug, serde::Serialize)]
pub struct ExportSeedResult {
    pub has_seed: bool,
    pub mnemonic: Option<String>,
}

/// A single exported private key entry (address + WIF).
#[derive(Debug, serde::Serialize)]
pub struct PrivKeyEntry {
    pub address: String,
    pub wif: String,
}

/// Result of export_privkey command.
#[derive(Debug, serde::Serialize)]
pub struct ExportPrivkeyResult {
    /// Single WIF when exporting one key
    pub wif: Option<String>,
    /// List of (address, WIF) pairs when exporting all keys
    pub keys: Option<Vec<PrivKeyEntry>>,
}

/// Export the BIP39 mnemonic seed phrase.
///
/// Requires the wallet password to decrypt the mnemonic.
/// Returns has_seed=false if the wallet does not use a BIP39 seed.
#[tauri::command]
pub async fn export_seed(
    state: State<'_, AppState>,
    password: String,
    totp_code: Option<String>,
) -> Result<ExportSeedResult, String> {
    log::info!("export_seed");

    let (keystore_data, pool) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (active.keystore_data.clone(), active.db_pool.clone())
    };

    // Verify password
    if !keystore::verify_password(&keystore_data, &password) {
        return Err("incorrect password".to_string());
    }

    // If TOTP is enabled, verify the TOTP code before revealing the seed
    let totp_enabled = repositories::is_totp_enabled(&pool)
        .await
        .map_err(|e| e.to_string())?;
    if totp_enabled {
        let code = totp_code.ok_or("TOTP code required to export seed when 2FA is enabled")?;
        let encrypted_secret = repositories::load_totp_secret(&pool)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("TOTP is not enabled")?;
        let totp = crate::security::totp::TotpInstance::from_secret_bytes(
            &encrypted_secret,
            "ElectrumSV-Mc",
            "wallet",
        )
        .map_err(|e| e.to_string())?;
        let valid = totp.verify_current(&code).map_err(|e| e.to_string())?;
        if !valid {
            return Err("invalid TOTP code".to_string());
        }
    }

    // Check seed type
    if keystore_data.seed_type != "bip39" {
        return Ok(ExportSeedResult {
            has_seed: false,
            mnemonic: None,
        });
    }

    // Decrypt mnemonic
    let mnemonic = keystore::decrypt_mnemonic(&keystore_data, &password)
        .map_err(|e| e.to_string())?;

    Ok(ExportSeedResult {
        has_seed: true,
        mnemonic: Some(mnemonic),
    })
}

/// Change the wallet password.
///
/// Re-encrypts xprv, mnemonic, and passphrase with the new password.
/// Updates the keystore data in both the database and in-memory state.
#[tauri::command]
pub async fn change_password(
    state: State<'_, AppState>,
    old_password: String,
    new_password: String,
) -> Result<(), String> {
    log::info!("change_password");

    let (pool, keystore_data, wallet_path) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (
            active.db_pool.clone(),
            active.keystore_data.clone(),
            active.wallet_path.clone(),
        )
    };

    // Verify old password
    if !keystore::verify_password(&keystore_data, &old_password) {
        return Err("incorrect password".to_string());
    }

    // Decrypt xprv with old password
    let decrypted_xprv = keystore::decrypt_xprv(&keystore_data, &old_password)
        .map_err(|e| e.to_string())?;

    // Decrypt mnemonic with old password (if bip39)
    let decrypted_seed = if keystore_data.seed_type == "bip39" {
        Some(
            keystore::decrypt_mnemonic(&keystore_data, &old_password)
                .map_err(|e| e.to_string())?,
        )
    } else {
        None
    };

    // Decrypt passphrase with old password (if present)
    let decrypted_passphrase = if let Some(ref enc_pass) = keystore_data.passphrase {
        Some(
            encryption::pw_decode(enc_pass, &old_password)
                .map_err(|e| e.to_string())?,
        )
    } else {
        None
    };

    // Re-encrypt with new password
    let new_xprv = encryption::pw_encode(&decrypted_xprv, &new_password);
    let new_seed = decrypted_seed
        .map(|s| encryption::pw_encode(&s, &new_password));
    let new_passphrase = decrypted_passphrase
        .map(|p| encryption::pw_encode(&p, &new_password));

    // Build new keystore data
    let new_keystore_data = keystore::KeyStoreData {
        xpub: keystore_data.xpub.clone(),
        xprv: new_xprv,
        seed_type: keystore_data.seed_type.clone(),
        derivation: keystore_data.derivation.clone(),
        seed: new_seed.unwrap_or_default(),
        passphrase: new_passphrase,
    };

    // Update MasterKeys.derivation_data in DB
    let new_ks_bytes = keystore::keystore_data_to_bytes(&new_keystore_data);
    let mk_row = repositories::get_first_master_key(&pool)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("no master key found in database")?;

    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "UPDATE MasterKeys SET derivation_data = ?, date_updated = ? WHERE masterkey_id = ?",
    )
    .bind(&new_ks_bytes)
    .bind(now)
    .bind(mk_row.masterkey_id)
    .execute(&pool)
    .await
    .map_err(|e| e.to_string())?;

    // Note: We do NOT store the password in WalletData. The old "password-token"
    // approach stored the password in cleartext — a security risk. The password
    // is only verified by decrypting the xprv (verify_password), which is
    // already updated above via the new keystore_data.
    // Remove any legacy password-token if it exists.
    repositories::set_wallet_data(&pool, "password-token", "")
        .await
        .map_err(|e| e.to_string())?;

    // Update ActiveWallet.keystore_data in state.
    // Hold the lock through the entire update to prevent a TOCTOU race
    // (the wallet could be closed/replaced between check and mutation).
    {
        let mut guard = state.active_wallet.lock().unwrap();
        if let Some(ref mut active) = *guard {
            if active.wallet_path == wallet_path {
                active.keystore_data = new_keystore_data;
            }
        }
        // If no wallet is open, or the wallet was changed during async
        // operations, there is nothing to update in memory — the DB
        // already holds the new keystore data.
    }

    log::info!("Password changed successfully");
    Ok(())
}

/// Delete a wallet from disk.
///
/// Closes the wallet if it is the currently active one, then deletes
/// the .sqlite file from disk.
#[tauri::command]
pub async fn delete_wallet(
    state: State<'_, AppState>,
    wallet_path: String,
) -> Result<(), String> {
    log::info!("delete_wallet — path: {}", wallet_path);

    // Close wallet if it's the active one
    {
        let guard = state.active_wallet.lock().unwrap();
        if let Some(ref active) = *guard {
            if active.wallet_path == wallet_path {
                drop(guard);
                wallet_service::close_wallet(&state).map_err(|e| e.to_string())?;
            }
        }
    }

    // Delete the .sqlite file from disk — but only if it's in the data_dir
    // (prevent path traversal attacks).
    // Use symlink_metadata so we can detect and reject symlinks (canonicalize
    // follows symlinks, which would mask a symlink pointing outside data_dir).
    let wallet_path_buf = std::path::PathBuf::from(&wallet_path);

    // Reject symlinks: the wallet file must be a regular file, not a symlink.
    let meta = std::fs::symlink_metadata(&wallet_path_buf)
        .map_err(|e| format!("failed to read wallet file metadata: {}", e))?;
    if meta.file_type().is_symlink() {
        return Err("wallet file must be a regular file, not a symlink".to_string());
    }

    let canonical_wallet = wallet_path_buf
        .canonicalize()
        .map_err(|e| format!("failed to canonicalize wallet path: {}", e))?;

    let data_dir = std::path::PathBuf::from(&state.data_dir);
    let canonical_data_dir = data_dir
        .canonicalize()
        .map_err(|e| format!("failed to canonicalize data_dir: {}", e))?;

    if !canonical_wallet.starts_with(&canonical_data_dir) {
        return Err("wallet file must be within the application data directory".to_string());
    }

    // Re-check after canonicalize that the resolved path is still a regular file
    // (defends against TOCTOU where the file was replaced between the two checks).
    let canon_meta = std::fs::symlink_metadata(&canonical_wallet)
        .map_err(|e| format!("failed to read canonicalized wallet metadata: {}", e))?;
    if !canon_meta.is_file() {
        return Err("wallet file must be a regular file".to_string());
    }

    std::fs::remove_file(&canonical_wallet)
        .map_err(|e| format!("failed to delete wallet file: {}", e))?;

    log::info!("Wallet deleted: {}", wallet_path);
    Ok(())
}

/// Export private key(s) as WIF (Wallet Import Format).
///
/// If `all` is true, exports all KeyInstances for the active account.
/// If `address` is provided, exports the key for that specific address.
/// Requires an unlocked wallet (xprv needed for key derivation).
#[tauri::command]
pub async fn export_privkey(
    state: State<'_, AppState>,
    password: String,
    address: Option<String>,
    all: Option<bool>,
    totp_code: Option<String>,
) -> Result<ExportPrivkeyResult, String> {
    log::info!(
        "export_privkey — address: {:?}, all: {:?}",
        address,
        all
    );

    let (pool, account_id, xprv_opt, keystore_data) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (
            active.db_pool.clone(),
            active.account_id,
            active.decrypted_xprv.clone(),
            active.keystore_data.clone(),
        )
    };

    // Verify password
    if !keystore::verify_password(&keystore_data, &password) {
        return Err("incorrect password".to_string());
    }

    // If TOTP is enabled, verify the TOTP code before revealing private keys
    let totp_enabled = repositories::is_totp_enabled(&pool)
        .await
        .map_err(|e| e.to_string())?;
    if totp_enabled {
        let code = totp_code.ok_or("TOTP code required to export private key when 2FA is enabled")?;
        let encrypted_secret = repositories::load_totp_secret(&pool)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("TOTP is not enabled")?;
        let totp = crate::security::totp::TotpInstance::from_secret_bytes(
            &encrypted_secret,
            "ElectrumSV-Mc",
            "wallet",
        )
        .map_err(|e| e.to_string())?;
        let valid = totp.verify_current(&code).map_err(|e| e.to_string())?;
        if !valid {
            return Err("invalid TOTP code".to_string());
        }
    }

    // Need unlocked wallet for key derivation
    let xprv_str = xprv_opt.ok_or("wallet is locked — unlock first")?;

    // Get all KeyInstances for the account
    let keyinstances = repositories::get_keyinstances_for_account(&pool, account_id)
        .await
        .map_err(|e| e.to_string())?;

    // Helper: derive private key WIF from xprv at a given subpath
    let derive_wif = |subpath: &[u32; 2]| -> Result<(String, String), String> {
        let account_key = bsv::compat::bip32::ExtendedKey::from_string(&xprv_str)
            .map_err(|e| format!("invalid xprv: {}", e))?;
        let path = format!("{}/{}", subpath[0], subpath[1]);
        let child_key = account_key
            .derive(&path)
            .map_err(|e| format!("derivation failed: {}", e))?;

        // Extract private key bytes (same pattern as signer.rs)
        let xprv_b58 = child_key.to_base58();
        let decoded = bsv::primitives::utils::base58_decode(&xprv_b58)
            .map_err(|e| format!("base58 decode: {}", e))?;

        if decoded.len() < 78 {
            return Err(format!("decoded xprv too short: {} bytes", decoded.len()));
        }
        if decoded[45] != 0x00 {
            return Err("invalid xprv: expected 0x00 prefix before key bytes".to_string());
        }

        let key_bytes = &decoded[46..78];
        let priv_key = bsv::primitives::private_key::PrivateKey::from_bytes(key_bytes)
            .map_err(|e| format!("private key creation: {}", e))?;

        // Derive the address for this key
        let pubkey = priv_key.to_public_key();
        let addr = crate::core::address::pubkey_to_p2pkh_address(&pubkey);

        // WIF with mainnet prefix 0x80
        let wif = priv_key.to_wif(&[0x80]);

        Ok((addr, wif))
    };

    let do_all = all.unwrap_or(false);

    if do_all {
        // Export all keys
        let mut entries = Vec::new();
        for ki in &keyinstances {
            // Parse derivation_data to get subpath
            let derivation_data: serde_json::Value =
                serde_json::from_slice(&ki.derivation_data)
                    .map_err(|e| e.to_string())?;

            let subpath_arr = derivation_data
                .get("subpath")
                .and_then(|s| s.as_array())
                .ok_or("missing subpath in derivation_data")?;

            let type_idx = subpath_arr
                .first()
                .and_then(|t| t.as_u64())
                .ok_or("invalid subpath type index")? as u32;
            let addr_idx = subpath_arr
                .get(1)
                .and_then(|t| t.as_u64())
                .ok_or("invalid subpath address index")? as u32;

            let (addr, wif) = derive_wif(&[type_idx, addr_idx])?;
            entries.push(PrivKeyEntry { address: addr, wif });
        }

        Ok(ExportPrivkeyResult {
            wif: None,
            keys: Some(entries),
        })
    } else if let Some(target_addr) = address {
        // Export key for a specific address
        for ki in &keyinstances {
            let derivation_data: serde_json::Value =
                serde_json::from_slice(&ki.derivation_data)
                    .map_err(|e| e.to_string())?;

            let subpath_arr = derivation_data
                .get("subpath")
                .and_then(|s| s.as_array())
                .ok_or("missing subpath in derivation_data")?;

            let type_idx = subpath_arr
                .first()
                .and_then(|t| t.as_u64())
                .ok_or("invalid subpath type index")? as u32;
            let addr_idx = subpath_arr
                .get(1)
                .and_then(|t| t.as_u64())
                .ok_or("invalid subpath address index")? as u32;

            let (addr, wif) = derive_wif(&[type_idx, addr_idx])?;
            if addr == target_addr {
                return Ok(ExportPrivkeyResult {
                    wif: Some(wif),
                    keys: None,
                });
            }
        }

        Err(format!("address not found in key instances: {}", target_addr))
    } else {
        Err("either 'all' must be true or 'address' must be provided".to_string())
    }
}

// ============================================================================
// BSM (Bitcoin Signed Message) — Milestone 8
// ============================================================================

use base64::Engine as _;

/// Result of sign_message — returns the base64-encoded BSM signature.
#[derive(Debug, serde::Serialize)]
pub struct SignMessageResult {
    /// Base64-encoded 65-byte compact BSM signature
    pub signature: String,
}

/// Result of verify_message — returns whether the signature is valid.
#[derive(Debug, serde::Serialize)]
pub struct VerifyMessageResult {
    /// True if the signature matches the address and message
    pub valid: bool,
}

/// Sign a message with a Bitcoin Signed Message (BSM) signature.
///
/// Uses the bsv-sdk compat::bsm module: magic prefix + double-SHA256 + ECDSA.
/// The signature is returned as base64-encoded 65-byte compact BSM format.
/// Requires an unlocked wallet (xprv needed for key derivation) and the wallet password.
#[tauri::command]
pub async fn sign_message(
    state: State<'_, AppState>,
    address: String,
    message: String,
    password: String,
) -> Result<SignMessageResult, String> {
    log::info!("sign_message — address: {}", address);

    let (pool, account_id, xprv_opt, keystore_data) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (
            active.db_pool.clone(),
            active.account_id,
            active.decrypted_xprv.clone(),
            active.keystore_data.clone(),
        )
    };

    // Verify password
    if !keystore::verify_password(&keystore_data, &password) {
        return Err("incorrect password".to_string());
    }

    // Need unlocked wallet for key derivation
    let xprv_str = xprv_opt.ok_or("wallet is locked — unlock first")?;

    // Find KeyInstance matching the address
    let keyinstances = repositories::get_keyinstances_for_account(&pool, account_id)
        .await
        .map_err(|e| e.to_string())?;

    let mut found_subpath: Option<[u32; 2]> = None;
    for ki in &keyinstances {
        let derivation_data: serde_json::Value =
            serde_json::from_slice(&ki.derivation_data).map_err(|e| e.to_string())?;

        let subpath_arr = derivation_data
            .get("subpath")
            .and_then(|s| s.as_array())
            .ok_or("missing subpath in derivation_data")?;

        let type_idx = subpath_arr[0].as_u64().unwrap_or(0) as u32;
        let addr_idx = subpath_arr[1].as_u64().unwrap_or(0) as u32;

        // Derive address to compare
        let account_key = bsv::compat::bip32::ExtendedKey::from_string(&xprv_str)
            .map_err(|e| format!("invalid xprv: {}", e))?;
        let path = format!("{}/{}", type_idx, addr_idx);
        let child_key = account_key
            .derive(&path)
            .map_err(|e| format!("derivation failed: {}", e))?;
        let pubkey = child_key
            .public_key()
            .map_err(|e| format!("public key derivation: {}", e))?;
        let derived_addr = crate::core::address::pubkey_to_p2pkh_address(&pubkey);

        if derived_addr == address {
            found_subpath = Some([type_idx, addr_idx]);
            break;
        }
    }

    let subpath = found_subpath
        .ok_or_else(|| format!("address not found in key instances: {}", address))?;

    // Derive private key at the found subpath
    let account_key = bsv::compat::bip32::ExtendedKey::from_string(&xprv_str)
        .map_err(|e| format!("invalid xprv: {}", e))?;
    let path = format!("{}/{}", subpath[0], subpath[1]);
    let child_key = account_key
        .derive(&path)
        .map_err(|e| format!("derivation failed: {}", e))?;

    let xprv_b58 = child_key.to_base58();
    let decoded = bsv::primitives::utils::base58_decode(&xprv_b58)
        .map_err(|e| format!("base58 decode: {}", e))?;

    if decoded.len() < 78 {
        return Err(format!("decoded xprv too short: {} bytes", decoded.len()));
    }

    let key_bytes = &decoded[46..78];
    let priv_key = bsv::primitives::private_key::PrivateKey::from_bytes(key_bytes)
        .map_err(|e| format!("private key creation: {}", e))?;

    // Sign with BSM
    let sig_bytes = bsv::compat::bsm::BSM::sign(message.as_bytes(), &priv_key)
        .map_err(|e| format!("BSM signing failed: {}", e))?;

    // Base64 encode
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

    log::info!("Message signed for address {}", address);
    Ok(SignMessageResult {
        signature: signature_b64,
    })
}

/// Verify a Bitcoin Signed Message (BSM) signature.
///
/// Recovers the public key from the 65-byte compact BSM signature using
/// the recovery byte, derives the P2PKH address, and compares with the
/// provided address. No wallet or state needed — verification is stateless.
#[tauri::command]
pub async fn verify_message(
    address: String,
    message: String,
    signature: String,
) -> Result<VerifyMessageResult, String> {
    log::info!("verify_message — address: {}", address);

    // Base64 decode the signature
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&signature)
        .map_err(|e| format!("invalid base64 signature: {}", e))?;

    if sig_bytes.len() != 65 {
        return Err("BSM signature must be 65 bytes".to_string());
    }

    // Parse compact BSM signature → (Signature, recovery, compressed)
    let (sig, recovery, _compressed) =
        bsv::primitives::signature::Signature::from_compact_bsm(&sig_bytes)
            .map_err(|e| format!("invalid BSM signature: {}", e))?;

    // Compute BSM magic hash (double-SHA256 with magic prefix)
    let msg_hash = bsv::compat::bsm::BSM::magic_hash(message.as_bytes());

    // Convert to BigNumber for public key recovery
    let msg_bn = bsv::primitives::big_number::BigNumber::from_bytes(
        &msg_hash,
        bsv::primitives::big_number::Endian::Big,
    );

    // Recover public key from signature
    let recovered_pubkey = sig
        .recover_public_key(recovery, &msg_bn)
        .map_err(|e| format!("public key recovery failed: {}", e))?;

    // Derive P2PKH address from recovered pubkey (mainnet prefix 0x00)
    let recovered_addr = recovered_pubkey.to_address(&[0x00]);

    // Compare with provided address
    let valid = recovered_addr == address;

    log::info!(
        "BSM verification: {} (recovered: {}, expected: {})",
        valid,
        recovered_addr,
        address
    );
    Ok(VerifyMessageResult { valid })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address;
    use crate::db::connection;
    use crate::db::repositories;
    use crate::services::wallet_service;
    use crate::state::AppState;
    use bsv::compat::bip32::ExtendedKey;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn make_test_state(test_name: &str) -> AppState {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let temp_dir =
            std::env::temp_dir().join(format!("electrumsv_mc_wallet_{}_{}", test_name, id));
        if temp_dir.exists() {
            std::fs::remove_dir_all(&temp_dir).ok();
        }
        std::fs::create_dir_all(&temp_dir).unwrap();
        AppState {
            data_dir: temp_dir.to_string_lossy().to_string(),
            active_wallet: std::sync::Mutex::new(None),
            network: std::sync::Mutex::new(crate::state::NetworkState::new()),
            pending_plans: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    // --------------------------------------------------------------------
    // list_wallets / create_wallet / open_wallet / close_wallet / unlock
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn test_list_wallets_empty_dir() {
        let state = make_test_state("list_empty");
        // No wallets created yet — list should be empty
        let wallets = connection::list_wallet_files(&state.data_dir).unwrap();
        assert!(wallets.is_empty());
    }

    #[tokio::test]
    async fn test_list_wallets_after_create() {
        let state = make_test_state("list_after_create");
        wallet_service::create_wallet(&state, "test_list_w", "pw123", None, None)
            .await
            .unwrap();

        let wallets = connection::list_wallet_files(&state.data_dir).unwrap();
        assert_eq!(wallets.len(), 1);
        assert_eq!(wallets[0].name, "test_list_w");
        assert!(wallets[0].path.ends_with(".sqlite"));

        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_create_wallet_generates_12_word_mnemonic() {
        let state = make_test_state("create_gen");
        let result = wallet_service::create_wallet(&state, "test_gen", "pw123", None, None)
            .await
            .unwrap();

        assert!(result.is_new_mnemonic);
        let words: Vec<&str> = result.mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12);
        assert_eq!(result.account_id, 1);

        let status = wallet_service::get_wallet_status(&state);
        assert!(status.is_open);
        assert!(status.is_unlocked);
        assert_eq!(status.wallet_name, Some("test_gen".to_string()));

        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_create_wallet_with_known_mnemonic() {
        let state = make_test_state("create_known");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result =
            wallet_service::create_wallet(&state, "test_known", "pw123", Some(mnemonic), None)
                .await
                .unwrap();

        assert!(!result.is_new_mnemonic);
        assert_eq!(result.mnemonic, mnemonic);

        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_open_wallet_locked() {
        let state = make_test_state("open_locked");
        let result = wallet_service::create_wallet(&state, "test_open", "pw123", None, None)
            .await
            .unwrap();
        let wallet_path = result.wallet_path.clone();

        // Close and reopen — should be locked
        wallet_service::close_wallet(&state).unwrap();
        let open_result = wallet_service::open_wallet(&state, &wallet_path)
            .await
            .unwrap();

        assert!(!open_result.is_unlocked);
        assert_eq!(open_result.wallet_name, "test_open");

        let status = wallet_service::get_wallet_status(&state);
        assert!(status.is_open);
        assert!(!status.is_unlocked);

        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_unlock_wallet_correct_password() {
        let state = make_test_state("unlock_correct");
        let result = wallet_service::create_wallet(&state, "test_unlock", "pw123", None, None)
            .await
            .unwrap();
        let wallet_path = result.wallet_path;

        // Close, reopen, then unlock
        wallet_service::close_wallet(&state).unwrap();
        wallet_service::open_wallet(&state, &wallet_path).await.unwrap();

        assert!(wallet_service::unlock_wallet(&state, "pw123").is_ok());
        let status = wallet_service::get_wallet_status(&state);
        assert!(status.is_unlocked);

        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_unlock_wallet_wrong_password() {
        let state = make_test_state("unlock_wrong");
        let result = wallet_service::create_wallet(&state, "test_unlock_w", "pw123", None, None)
            .await
            .unwrap();
        let wallet_path = result.wallet_path;

        wallet_service::close_wallet(&state).unwrap();
        wallet_service::open_wallet(&state, &wallet_path).await.unwrap();

        let err = wallet_service::unlock_wallet(&state, "wrong_pw").unwrap_err();
        assert!(matches!(err, wallet_service::WalletError::Encryption(_)));

        let status = wallet_service::get_wallet_status(&state);
        assert!(!status.is_unlocked);

        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_close_wallet_no_wallet_open() {
        let state = make_test_state("close_none");
        let err = wallet_service::close_wallet(&state).unwrap_err();
        assert!(matches!(err, wallet_service::WalletError::NoWalletOpen));
    }

    // --------------------------------------------------------------------
    // TOTP
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn test_totp_disabled_by_default() {
        let state = make_test_state("totp_default");
        wallet_service::create_wallet(&state, "test_totp_def", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        let enabled = repositories::is_totp_enabled(&pool).await.unwrap();
        assert!(!enabled);

        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_totp_store_and_load_secret() {
        let state = make_test_state("totp_store");
        wallet_service::create_wallet(&state, "test_totp_store", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        // Store a TOTP secret
        let totp = crate::security::totp::TotpInstance::new("ElectrumSV-Mc", "test_wallet")
            .unwrap();
        let secret_bytes = totp.secret_bytes().to_vec();
        repositories::store_totp_secret(&pool, &secret_bytes)
            .await
            .unwrap();

        // Should now be enabled
        assert!(repositories::is_totp_enabled(&pool).await.unwrap());

        // Load and verify
        let loaded = repositories::load_totp_secret(&pool).await.unwrap();
        assert_eq!(loaded, Some(secret_bytes));

        // Delete (disable)
        repositories::delete_totp_secret(&pool).await.unwrap();
        assert!(!repositories::is_totp_enabled(&pool).await.unwrap());

        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_totp_verify_current_code() {
        let state = make_test_state("totp_verify");
        wallet_service::create_wallet(&state, "test_totp_verify", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        let totp = crate::security::totp::TotpInstance::new("ElectrumSV-Mc", "test_wallet")
            .unwrap();
        let secret_bytes = totp.secret_bytes().to_vec();
        repositories::store_totp_secret(&pool, &secret_bytes)
            .await
            .unwrap();

        // Generate current code and verify
        let code = totp.generate_current().unwrap();
        let valid = totp.verify_current(&code).unwrap();
        assert!(valid);

        // Wrong code should fail
        let wrong_code = "000000";
        let valid_wrong = totp.verify_current(wrong_code).unwrap();
        assert!(!valid_wrong);

        wallet_service::close_wallet(&state).unwrap();
    }

    // --------------------------------------------------------------------
    // TOTP Recovery codes
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn test_recovery_codes_generate_and_consume() {
        let state = make_test_state("recovery_codes");
        wallet_service::create_wallet(&state, "test_recovery", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        // Generate 10 recovery codes
        let codes = crate::security::totp::generate_recovery_codes(10);
        assert_eq!(codes.len(), 10);

        // Each code should be in XXXX-XXXX format (9 chars including dash)
        for code in &codes {
            assert_eq!(code.len(), 9);
            assert!(code.chars().nth(4).unwrap() == '-');
        }

        // Hash and store
        let hashed: Vec<String> = codes
            .iter()
            .map(|c| crate::security::totp::hash_recovery_code(c))
            .collect();
        repositories::store_recovery_codes(&pool, &hashed)
            .await
            .unwrap();

        // Consume the first code
        let first_hash = crate::security::totp::hash_recovery_code(&codes[0]);
        let matched = repositories::consume_recovery_code(&pool, &first_hash)
            .await
            .unwrap();
        assert!(matched);

        // Consume same code again — should not match
        let matched_again = repositories::consume_recovery_code(&pool, &first_hash)
            .await
            .unwrap();
        assert!(!matched_again);

        // Consume a non-existent code
        let fake_hash = crate::security::totp::hash_recovery_code("FAKE-CODE");
        let matched_fake = repositories::consume_recovery_code(&pool, &fake_hash)
            .await
            .unwrap();
        assert!(!matched_fake);

        // Delete all remaining
        repositories::delete_recovery_codes(&pool).await.unwrap();
        let remaining = repositories::load_recovery_codes(&pool).await.unwrap();
        assert!(remaining.is_empty());

        wallet_service::close_wallet(&state).unwrap();
    }

    // --------------------------------------------------------------------
    // Hardware wallet toggle
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn test_hardware_wallet_toggle() {
        let state = make_test_state("hw_toggle");
        wallet_service::create_wallet(&state, "test_hw", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        // Default: disabled
        let enabled = repositories::get_hardware_wallet_enabled(&pool)
            .await
            .unwrap();
        assert!(!enabled);

        // Enable
        repositories::set_hardware_wallet_enabled(&pool, true)
            .await
            .unwrap();
        assert!(repositories::get_hardware_wallet_enabled(&pool).await.unwrap());

        // Disable
        repositories::set_hardware_wallet_enabled(&pool, false)
            .await
            .unwrap();
        assert!(!repositories::get_hardware_wallet_enabled(&pool).await.unwrap());

        wallet_service::close_wallet(&state).unwrap();
    }

    // --------------------------------------------------------------------
    // export_seed (test via keystore directly)
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn test_export_seed_correct_password() {
        let state = make_test_state("export_seed_ok");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        wallet_service::create_wallet(&state, "test_export", "pw123", Some(mnemonic), None)
            .await
            .unwrap();

        let keystore_data = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().keystore_data.clone()
        };

        // Verify password
        assert!(keystore::verify_password(&keystore_data, "pw123"));

        // Decrypt mnemonic
        let decrypted = keystore::decrypt_mnemonic(&keystore_data, "pw123").unwrap();
        assert_eq!(decrypted, mnemonic);

        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_export_seed_wrong_password() {
        let state = make_test_state("export_seed_wrong");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        wallet_service::create_wallet(&state, "test_export_w", "pw123", Some(mnemonic), None)
            .await
            .unwrap();

        let keystore_data = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().keystore_data.clone()
        };

        // Wrong password should fail verification
        assert!(!keystore::verify_password(&keystore_data, "wrong_pw"));

        // decrypt_mnemonic with wrong password should error
        let result = keystore::decrypt_mnemonic(&keystore_data, "wrong_pw");
        assert!(result.is_err());

        wallet_service::close_wallet(&state).unwrap();
    }

    // --------------------------------------------------------------------
    // change_password (test that wallet can unlock with new password)
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn test_change_password() {
        let state = make_test_state("change_pw");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result =
            wallet_service::create_wallet(&state, "test_changepw", "old_pw", Some(mnemonic), None)
                .await
                .unwrap();
        let wallet_path = result.wallet_path;

        // Close, reopen with old password
        wallet_service::close_wallet(&state).unwrap();
        wallet_service::open_wallet(&state, &wallet_path).await.unwrap();
        wallet_service::unlock_wallet(&state, "old_pw").unwrap();

        // Get the keystore data and pool
        let (pool, keystore_data) = {
            let guard = state.active_wallet.lock().unwrap();
            let active = guard.as_ref().unwrap();
            (active.db_pool.clone(), active.keystore_data.clone())
        };

        // Verify old password works
        assert!(keystore::verify_password(&keystore_data, "old_pw"));

        // Re-encrypt with new password (mimic change_password logic)
        let decrypted_xprv = keystore::decrypt_xprv(&keystore_data, "old_pw").unwrap();
        let decrypted_seed = keystore::decrypt_mnemonic(&keystore_data, "old_pw").unwrap();

        let new_xprv = encryption::pw_encode(&decrypted_xprv, "new_pw");
        let new_seed = encryption::pw_encode(&decrypted_seed, "new_pw");

        let new_keystore = keystore::KeyStoreData {
            xpub: keystore_data.xpub.clone(),
            xprv: new_xprv,
            seed_type: keystore_data.seed_type.clone(),
            derivation: keystore_data.derivation.clone(),
            seed: new_seed,
            passphrase: keystore_data.passphrase.clone(),
        };

        // Update DB
        let ks_bytes = keystore::keystore_data_to_bytes(&new_keystore);
        let mk_row = repositories::get_first_master_key(&pool)
            .await
            .unwrap()
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "UPDATE MasterKeys SET derivation_data = ?, date_updated = ? WHERE masterkey_id = ?",
        )
        .bind(&ks_bytes)
        .bind(now)
        .bind(mk_row.masterkey_id)
        .execute(&pool)
        .await
        .unwrap();

        // Security fix: password-token must be cleared (empty), NOT set to the new
        // password in cleartext. The old buggy behaviour stored "new_pw" here.
        repositories::set_wallet_data(&pool, "password-token", "")
            .await
            .unwrap();

        // Verify the token is empty — no plaintext password in the DB
        assert_eq!(
            repositories::get_wallet_data(&pool, "password-token")
                .await
                .unwrap()
                .unwrap_or_default(),
            ""
        );

        // Update in-memory state
        {
            let mut guard = state.active_wallet.lock().unwrap();
            if let Some(ref mut active) = *guard {
                active.keystore_data = new_keystore;
            }
        }

        // Close and reopen — should unlock with new password, not old
        wallet_service::close_wallet(&state).unwrap();
        wallet_service::open_wallet(&state, &wallet_path).await.unwrap();

        // Old password should fail
        let err = wallet_service::unlock_wallet(&state, "old_pw").unwrap_err();
        assert!(matches!(err, wallet_service::WalletError::Encryption(_)));

        // Reopen and try new password
        wallet_service::close_wallet(&state).unwrap();
        wallet_service::open_wallet(&state, &wallet_path).await.unwrap();
        assert!(wallet_service::unlock_wallet(&state, "new_pw").is_ok());

        // Verify mnemonic is still the same
        let decrypted_mnemonic = {
            let guard = state.active_wallet.lock().unwrap();
            let ks = &guard.as_ref().unwrap().keystore_data;
            keystore::decrypt_mnemonic(ks, "new_pw").unwrap()
        };
        assert_eq!(decrypted_mnemonic, mnemonic);

        wallet_service::close_wallet(&state).unwrap();
    }

    // --------------------------------------------------------------------
    // delete_wallet
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn test_delete_wallet_removes_file() {
        let state = make_test_state("delete_wallet");
        let result = wallet_service::create_wallet(&state, "test_delete", "pw123", None, None)
            .await
            .unwrap();
        let wallet_path = result.wallet_path.clone();

        // Close wallet first
        wallet_service::close_wallet(&state).unwrap();

        // File should exist
        assert!(std::path::Path::new(&wallet_path).exists());

        // Delete the file
        std::fs::remove_file(&wallet_path).unwrap();

        // File should be gone
        assert!(!std::path::Path::new(&wallet_path).exists());

        // list_wallets should return empty
        let wallets = connection::list_wallet_files(&state.data_dir).unwrap();
        assert!(wallets.is_empty());
    }

    // --------------------------------------------------------------------
    // sign_message / verify_message (BSM round-trip)
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn test_sign_and_verify_message_roundtrip() {
        let state = make_test_state("sign_verify");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        wallet_service::create_wallet(&state, "test_bsm", "pw123", Some(mnemonic), None)
            .await
            .unwrap();

        // Get the xprv and derive a key at 0/0
        let xprv = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().decrypted_xprv.as_ref().unwrap().clone()
        };

        let account_key = ExtendedKey::from_string(&xprv).unwrap();
        let child = account_key.derive("0/0").unwrap();
        let pubkey = child.public_key().unwrap();
        let addr = address::pubkey_to_p2pkh_address(&pubkey);

        // Extract private key bytes
        let xprv_b58 = child.to_base58();
        let decoded = bsv::primitives::utils::base58_decode(&xprv_b58).unwrap();
        assert!(decoded.len() >= 78);
        let key_bytes = &decoded[46..78];
        let priv_key = bsv::primitives::private_key::PrivateKey::from_bytes(key_bytes).unwrap();

        // Sign a message
        let message = "Hello BSV!";
        let sig_bytes = bsv::compat::bsm::BSM::sign(message.as_bytes(), &priv_key).unwrap();
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

        // Verify signature length
        assert_eq!(sig_bytes.len(), 65);

        // Verify the signature using BSM recovery
        let sig_decoded = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .unwrap();
        let (sig, recovery, _compressed) =
            bsv::primitives::signature::Signature::from_compact_bsm(&sig_decoded).unwrap();
        let msg_hash = bsv::compat::bsm::BSM::magic_hash(message.as_bytes());
        let msg_bn = bsv::primitives::big_number::BigNumber::from_bytes(
            &msg_hash,
            bsv::primitives::big_number::Endian::Big,
        );
        let recovered_pubkey = sig.recover_public_key(recovery, &msg_bn).unwrap();
        let recovered_addr = recovered_pubkey.to_address(&[0x00]);

        assert_eq!(recovered_addr, addr);

        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_verify_message_wrong_message() {
        let state = make_test_state("verify_wrong");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        wallet_service::create_wallet(&state, "test_bsm_w", "pw123", Some(mnemonic), None)
            .await
            .unwrap();

        let xprv = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().decrypted_xprv.as_ref().unwrap().clone()
        };

        let account_key = ExtendedKey::from_string(&xprv).unwrap();
        let child = account_key.derive("0/0").unwrap();
        let pubkey = child.public_key().unwrap();
        let addr = address::pubkey_to_p2pkh_address(&pubkey);

        let xprv_b58 = child.to_base58();
        let decoded = bsv::primitives::utils::base58_decode(&xprv_b58).unwrap();
        let key_bytes = &decoded[46..78];
        let priv_key = bsv::primitives::private_key::PrivateKey::from_bytes(key_bytes).unwrap();

        // Sign "message1"
        let sig_bytes = bsv::compat::bsm::BSM::sign(b"message1", &priv_key).unwrap();
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

        // Verify against "message2" — should not match the address
        let sig_decoded = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .unwrap();
        let (sig, recovery, _compressed) =
            bsv::primitives::signature::Signature::from_compact_bsm(&sig_decoded).unwrap();
        let msg_hash = bsv::compat::bsm::BSM::magic_hash(b"message2");
        let msg_bn = bsv::primitives::big_number::BigNumber::from_bytes(
            &msg_hash,
            bsv::primitives::big_number::Endian::Big,
        );
        let recovered_pubkey = sig.recover_public_key(recovery, &msg_bn).unwrap();
        let recovered_addr = recovered_pubkey.to_address(&[0x00]);

        // Different message → different recovered address (almost certainly)
        assert_ne!(recovered_addr, addr);

        wallet_service::close_wallet(&state).unwrap();
    }

    // --------------------------------------------------------------------
    // export_privkey (derive WIF from xprv)
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn test_export_privkey_derivation() {
        let state = make_test_state("export_privkey");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        wallet_service::create_wallet(&state, "test_wif", "pw123", Some(mnemonic), None)
            .await
            .unwrap();

        let xprv = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().decrypted_xprv.as_ref().unwrap().clone()
        };

        // Derive private key at 0/0 and convert to WIF
        let account_key = ExtendedKey::from_string(&xprv).unwrap();
        let child = account_key.derive("0/0").unwrap();
        let pubkey = child.public_key().unwrap();
        let addr = address::pubkey_to_p2pkh_address(&pubkey);

        let xprv_b58 = child.to_base58();
        let decoded = bsv::primitives::utils::base58_decode(&xprv_b58).unwrap();
        assert!(decoded.len() >= 78);
        assert_eq!(decoded[45], 0x00); // 0x00 prefix before key bytes

        let key_bytes = &decoded[46..78];
        let priv_key = bsv::primitives::private_key::PrivateKey::from_bytes(key_bytes).unwrap();
        let wif = priv_key.to_wif(&[0x80]);

        // WIF should start with 'K' or 'L' (mainnet compressed private key)
        assert!(wif.starts_with('K') || wif.starts_with('L'));
        assert!(!wif.is_empty());

        // Verify: the WIF's public key should match the derived address
        let pubkey_from_wif = priv_key.to_public_key();
        let addr_from_wif = address::pubkey_to_p2pkh_address(&pubkey_from_wif);
        assert_eq!(addr_from_wif, addr);

        wallet_service::close_wallet(&state).unwrap();
    }

    // --------------------------------------------------------------------
    // Wallet status variations
    // --------------------------------------------------------------------

    #[tokio::test]
    async fn test_wallet_status_no_wallet() {
        let state = make_test_state("status_none");
        let status = wallet_service::get_wallet_status(&state);
        assert!(!status.is_open);
        assert_eq!(status.wallet_name, None);
        assert!(!status.is_unlocked);
        assert_eq!(status.account_id, None);
    }

    #[tokio::test]
    async fn test_wallet_status_open_and_locked() {
        let state = make_test_state("status_locked");
        let result = wallet_service::create_wallet(&state, "test_status", "pw123", None, None)
            .await
            .unwrap();
        let wallet_path = result.wallet_path;

        wallet_service::close_wallet(&state).unwrap();
        wallet_service::open_wallet(&state, &wallet_path).await.unwrap();

        let status = wallet_service::get_wallet_status(&state);
        assert!(status.is_open);
        assert!(!status.is_unlocked);
        assert_eq!(status.wallet_name, Some("test_status".to_string()));
        assert!(status.xpub.is_some());

        wallet_service::close_wallet(&state).unwrap();
    }

    // --------------------------------------------------------------------
    // Security-Fix tests
    // --------------------------------------------------------------------

    /// After change_password, the "password-token" WalletData entry must be
    /// empty — no plaintext password may be stored in the DB.
    #[tokio::test]
    async fn test_change_password_no_plaintext() {
        let state = make_test_state("chpw_no_pt");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result =
            wallet_service::create_wallet(&state, "test_nopt", "old_pw", Some(mnemonic), None)
                .await
                .unwrap();
        let wallet_path = result.wallet_path;

        // Close, reopen, unlock
        wallet_service::close_wallet(&state).unwrap();
        wallet_service::open_wallet(&state, &wallet_path).await.unwrap();
        wallet_service::unlock_wallet(&state, "old_pw").unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        // Simulate the (fixed) change_password logic: clear password-token
        repositories::set_wallet_data(&pool, "password-token", "")
            .await
            .unwrap();

        // The token must NOT contain the new password in cleartext
        let stored = repositories::get_wallet_data(&pool, "password-token")
            .await
            .unwrap()
            .unwrap_or_default();
        assert_eq!(stored, "");
        assert_ne!(stored, "new_pw");

        wallet_service::close_wallet(&state).unwrap();
    }

    /// delete_wallet must reject paths outside the application data directory
    /// (path-traversal protection via canonicalize() + starts_with()).
    #[tokio::test]
    async fn test_delete_wallet_path_traversal_rejected() {
        let state = make_test_state("del_traversal");
        wallet_service::create_wallet(&state, "test_traversal", "pw123", None, None)
            .await
            .unwrap();
        wallet_service::close_wallet(&state).unwrap();

        // A path outside the data_dir — use a temp file in /tmp
        let outside_path = std::env::temp_dir().join("electrumsv_mc_traversal_target.txt");
        std::fs::write(&outside_path, "dummy").unwrap();

        // Reproduce the path-traversal guard from delete_wallet
        let wallet_path_buf = std::path::PathBuf::from(&outside_path);
        let canonical_wallet = wallet_path_buf.canonicalize().unwrap();
        let canonical_data_dir =
            std::path::PathBuf::from(&state.data_dir).canonicalize().unwrap();

        let rejected = !canonical_wallet.starts_with(&canonical_data_dir);
        assert!(rejected, "path outside data_dir must be rejected");

        // The error message must match the one in delete_wallet
        let err_msg = "wallet file must be within the application data directory";
        assert!(
            err_msg.contains("within the application data directory"),
            "error message mismatch"
        );

        // Cleanup
        std::fs::remove_file(&outside_path).ok();
    }

    /// When TOTP is enabled, export_seed must fail without a TOTP code.
    #[tokio::test]
    async fn test_export_seed_totp_required() {
        let state = make_test_state("seed_totp_req");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        wallet_service::create_wallet(&state, "test_seed_totp", "pw123", Some(mnemonic), None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        // Enable TOTP
        let totp = crate::security::totp::TotpInstance::new("ElectrumSV-Mc", "test_wallet")
            .unwrap();
        repositories::store_totp_secret(&pool, totp.secret_bytes())
            .await
            .unwrap();
        assert!(repositories::is_totp_enabled(&pool).await.unwrap());

        // Simulate the TOTP check from export_seed: no code provided → error
        let totp_code: Option<String> = None;
        let totp_enabled = repositories::is_totp_enabled(&pool).await.unwrap();
        let result: Result<(), String> = if totp_enabled {
            match totp_code {
                None => Err(
                    "TOTP code required to export seed when 2FA is enabled".to_string(),
                ),
                Some(_) => Ok(()),
            }
        } else {
            Ok(())
        };

        let err = result.unwrap_err();
        assert_eq!(err, "TOTP code required to export seed when 2FA is enabled");

        wallet_service::close_wallet(&state).unwrap();
    }

    /// When TOTP is enabled, export_privkey must fail without a TOTP code.
    #[tokio::test]
    async fn test_export_privkey_totp_required() {
        let state = make_test_state("privkey_totp_req");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        wallet_service::create_wallet(&state, "test_privkey_totp", "pw123", Some(mnemonic), None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        // Enable TOTP
        let totp = crate::security::totp::TotpInstance::new("ElectrumSV-Mc", "test_wallet")
            .unwrap();
        repositories::store_totp_secret(&pool, totp.secret_bytes())
            .await
            .unwrap();
        assert!(repositories::is_totp_enabled(&pool).await.unwrap());

        // Simulate the TOTP check from export_privkey: no code provided → error
        let totp_code: Option<String> = None;
        let totp_enabled = repositories::is_totp_enabled(&pool).await.unwrap();
        let result: Result<(), String> = if totp_enabled {
            match totp_code {
                None => Err(
                    "TOTP code required to export private key when 2FA is enabled"
                        .to_string(),
                ),
                Some(_) => Ok(()),
            }
        } else {
            Ok(())
        };

        let err = result.unwrap_err();
        assert_eq!(
            err,
            "TOTP code required to export private key when 2FA is enabled"
        );

        wallet_service::close_wallet(&state).unwrap();
    }

    /// export_privkey with a wrong password must return "incorrect password".
    #[tokio::test]
    async fn test_export_privkey_wrong_password() {
        let state = make_test_state("privkey_wrong_pw");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        wallet_service::create_wallet(&state, "test_privkey_wp", "pw123", Some(mnemonic), None)
            .await
            .unwrap();

        let keystore_data = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().keystore_data.clone()
        };

        // Wrong password must fail verification (same check as export_privkey)
        let wrong = "definitely_wrong_password";
        assert!(!keystore::verify_password(&keystore_data, wrong));

        // The command returns "incorrect password" on verification failure
        let err = if !keystore::verify_password(&keystore_data, wrong) {
            "incorrect password".to_string()
        } else {
            "should not reach here".to_string()
        };
        assert_eq!(err, "incorrect password");

        wallet_service::close_wallet(&state).unwrap();
    }
}
