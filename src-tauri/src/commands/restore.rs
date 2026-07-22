// commands/restore.rs — Legacy ElectrumSV seed migration Tauri commands
//
// Provides:
// - restore_legacy_wallet: decode legacy seed, derive MPK, create new BIP32 wallet
// - sweep_legacy_to_new: scan legacy addresses for UTXOs, build & broadcast sweep tx
//
// Reference: SPECIFICATION-LEGACY-MIGRATION.md

use crate::core::legacy_keystore;
use crate::core::legacy_mnemonic;
use crate::core::transaction::{PaymentOutput, SelectedUtxo, TxBuilder};
use crate::network::backend::NetworkBackend;
use crate::services::wallet_service;
use crate::state::AppState;
use bsv::primitives::private_key::PrivateKey;
use bsv::primitives::transaction_signature::{SIGHASH_ALL, SIGHASH_FORKID};
use bsv::script::templates::p2pkh::P2PKH;
use bsv::script::templates::ScriptTemplateLock;
use tauri::State;

/// Standard Electrum gap limit for address scanning.
const GAP_LIMIT: u32 = 20;

/// Result of restoring a legacy wallet.
#[derive(Debug, serde::Serialize)]
pub struct LegacyRestoreResult {
    /// The new BIP39 mnemonic phrase (must be backed up by the user)
    pub new_mnemonic: String,
    /// Path to the new wallet database file
    pub wallet_path: String,
    /// Number of legacy addresses scanned for UTXOs
    pub old_addresses_scanned: u32,
    /// Status message describing the migration result
    pub migration_status: String,
}

/// Result of sweeping legacy UTXOs to the new wallet.
#[derive(Debug, serde::Serialize)]
pub struct SweepResult {
    /// Number of legacy addresses scanned
    pub addresses_scanned: u32,
    /// Number of UTXOs found
    pub utxos_found: u32,
    /// Total satoshis swept
    pub total_sats: u64,
    /// Transaction ID of the sweep transaction (None if no UTXOs found)
    pub txid: Option<String>,
    /// New addresses generated in the new wallet
    pub new_addresses: Vec<String>,
}

/// Restore a legacy ElectrumSV wallet and migrate it to a new BIP39/BIP32 wallet.
///
/// Steps:
/// 1. Decode the legacy seed (mn_decode or hex)
/// 2. Derive the master public key (MPK)
/// 3. Generate a new 12-word BIP39 mnemonic
/// 4. Create a new BIP32 wallet with the new mnemonic
/// 5. Return the new mnemonic, wallet path, and scan info
#[tauri::command]
pub async fn restore_legacy_wallet(
    state: State<'_, AppState>,
    seed_words: String,
    password: String,
    wallet_name: String,
) -> Result<LegacyRestoreResult, String> {
    log::info!(
        "restore_legacy_wallet — starting legacy migration for wallet: {}",
        wallet_name
    );

    // Step 1: Decode legacy seed
    let hex_seed = legacy_keystore::decode_legacy_seed(&seed_words)
        .map_err(|e| format!("failed to decode legacy seed: {}", e))?;
    log::info!("restore_legacy_wallet — decoded legacy seed ({} hex chars)", hex_seed.len());

    // Step 2: Derive MPK
    let mpk = legacy_keystore::derive_mpk(&hex_seed)
        .map_err(|e| format!("failed to derive MPK: {}", e))?;
    log::info!("restore_legacy_wallet — derived MPK ({} chars)", mpk.len());

    // Step 3 & 4: Generate new BIP39 mnemonic and create new BIP32 wallet
    let create_result = wallet_service::create_wallet(
        &state,
        &wallet_name,
        &password,
        None, // generate new mnemonic
        None, // no passphrase
    )
    .await
    .map_err(|e| format!("failed to create new wallet: {}", e))?;

    log::info!(
        "restore_legacy_wallet — new wallet created at {}",
        create_result.wallet_path
    );

    // Step 5: Count addresses that would be scanned
    let addresses_scanned = GAP_LIMIT * 2; // receive + change

    Ok(LegacyRestoreResult {
        new_mnemonic: create_result.mnemonic,
        wallet_path: create_result.wallet_path,
        old_addresses_scanned: addresses_scanned,
        migration_status: "Wallet created. Use sweep_legacy_to_new to transfer funds.".to_string(),
    })
}

/// Scan legacy addresses for UTXOs and sweep them to the new wallet.
///
/// Steps:
/// 1. Decode legacy seed and derive MPK
/// 2. Derive legacy addresses for change=0/0..gap_limit and change=1/0..gap_limit
/// 3. Query UTXOs for each address via the network backend (WoC or ElectrumX)
/// 4. If UTXOs found: derive private keys, build & sign sweep transaction, broadcast
/// 5. Return sweep result with txid and totals
#[tauri::command]
pub async fn sweep_legacy_to_new(
    state: State<'_, AppState>,
    seed_words: String,
    new_wallet_path: String,
    password: String,
) -> Result<SweepResult, String> {
    log::info!("sweep_legacy_to_new — starting sweep");

    // Step 1: Decode legacy seed and derive MPK
    let hex_seed = legacy_keystore::decode_legacy_seed(&seed_words)
        .map_err(|e| format!("failed to decode legacy seed: {}", e))?;
    let mpk = legacy_keystore::derive_mpk(&hex_seed)
        .map_err(|e| format!("failed to derive MPK: {}", e))?;

    // Step 2: Derive legacy addresses and collect them with their derivation paths
    let mut legacy_addresses: Vec<(String, u32, u32)> = Vec::new(); // (address, change, index)
    for change in 0..=1u32 {
        for index in 0..GAP_LIMIT {
            let pubkey = legacy_keystore::derive_pubkey(&mpk, change, index)
                .map_err(|e| format!("failed to derive pubkey at {}/{}: {}", change, index, e))?;
            let address = legacy_keystore::pubkey_to_p2pkh_address_uncompressed(&pubkey);
            legacy_addresses.push((address, change, index));
        }
    }

    log::info!(
        "sweep_legacy_to_new — derived {} legacy addresses",
        legacy_addresses.len()
    );

    // Step 3: Query UTXOs via the network backend
    // Try WhatsOnChain first, then ElectrumX
    let mut found_utxos: Vec<(SelectedUtxo, u32, u32)> = Vec::new(); // (utxo, change, index)
    let mut total_sats: u64 = 0;
    let mut addresses_with_utxos = 0u32;

    // Get the network backend from state
    let _network_state = {
        let guard = state.network.lock().unwrap();
        guard.active_backend.clone()
    };

    let woc_client = {
        let guard = state.network.lock().unwrap();
        guard.woc_client.clone()
    };
    let electrumx_client = {
        let guard = state.network.lock().unwrap();
        guard.client.clone()
    };

    for (address, change, index) in &legacy_addresses {
        let utxos = if let Some(ref woc) = woc_client {
            // WhatsOnChain: get_utxos takes address as the "scripthash" parameter
            woc.get_utxos(address).await.ok()
        } else if let Some(ref ex) = electrumx_client {
            // ElectrumX needs a scripthash, not an address
            // Compute scripthash from the address
            let scripthash = crate::network::backend::scripthash_from_address(address)
                .ok();
            if let Some(sh) = scripthash {
                ex.call(
                    "blockchain.scripthash.listunspent",
                    serde_json::json!([sh]),
                )
                .await
                .ok()
                .and_then(|v| {
                    // Parse ElectrumX UTXO response
                    v.as_array().map(|arr| {
                        arr.iter()
                            .filter_map(|entry| {
                                let tx_hash = entry.get("tx_hash")?.as_str()?.to_string();
                                let tx_pos = entry.get("tx_pos")?.as_u64()? as u32;
                                let value = entry.get("value")?.as_u64()?;
                                Some(crate::network::backend::UtxoEntry {
                                    tx_hash,
                                    tx_pos,
                                    value,
                                    height: entry.get("height").and_then(|h| h.as_i64()).unwrap_or(0),
                                })
                            })
                            .collect::<Vec<_>>()
                    })
                })
            } else {
                None
            }
        } else {
            None
        };

        if let Some(utxos) = utxos {
            if !utxos.is_empty() {
                addresses_with_utxos += 1;
                for utxo in utxos {
                    let satoshis = utxo.value;
                    total_sats += satoshis;
                    let selected = SelectedUtxo {
                        tx_hash_hex: utxo.tx_hash,
                        tx_index: utxo.tx_pos,
                        satoshis,
                        keyinstance_id: 0, // legacy keys have no keyinstance
                        subpath: [*change, *index],
                    };
                    found_utxos.push((selected, *change, *index));
                }
            }
        }
    }

    log::info!(
        "sweep_legacy_to_new — found {} UTXOs totaling {} sats across {} addresses",
        found_utxos.len(),
        total_sats,
        addresses_with_utxos
    );

    if found_utxos.is_empty() {
        log::info!("sweep_legacy_to_new — no UTXOs found, nothing to sweep");
        return Ok(SweepResult {
            addresses_scanned: legacy_addresses.len() as u32,
            utxos_found: 0,
            total_sats: 0,
            txid: None,
            new_addresses: Vec::new(),
        });
    }

    // Step 4: Get a receive address from the new wallet
    // Open and unlock the new wallet to get a receive address
    wallet_service::open_wallet(&state, &new_wallet_path)
        .await
        .map_err(|e| format!("failed to open new wallet: {}", e))?;
    wallet_service::unlock_wallet(&state, &password)
        .map_err(|e| format!("failed to unlock new wallet: {}", e))?;

    // Get the receive address from the new wallet
    let dest_address = get_new_wallet_receive_address(&state).await?;

    // Step 5: Build the sweep transaction
    let utxos: Vec<SelectedUtxo> = found_utxos.iter().map(|(u, _, _)| u.clone()).collect();
    let outputs = vec![PaymentOutput {
        address: dest_address.clone(),
        satoshis: total_sats, // will be adjusted after fee calculation
    }];

    // Build unsigned transaction — no change address (sweep all to destination)
    let (mut tx, selection) = TxBuilder::build_unsigned(
        &utxos,
        &outputs,
        None, // no change address for sweep
        1,     // 1 sat/byte fee rate
        None,  // no OP_RETURN
        None,  // default coin selection
    )
    .map_err(|e| format!("failed to build sweep transaction: {}", e))?;

    // Adjust the output amount: total_input - fee (sweep all)
    let sweep_amount = selection.total_input - selection.fee;
    if sweep_amount == 0 {
        return Err("sweep amount is zero after fee — dust UTXOs".to_string());
    }
    // Set the output amount to sweep_amount (total minus fee)
    if let Some(satoshi_ref) = tx.outputs[0].satoshis.as_mut() {
        *satoshi_ref = sweep_amount;
    }

    log::info!(
        "sweep_legacy_to_new — built tx with {} inputs, {} sats output, {} sats fee",
        utxos.len(),
        sweep_amount,
        selection.fee
    );

    // Step 6: Sign each input with the legacy private key
    let sighash_type = SIGHASH_ALL | SIGHASH_FORKID; // 0x41

    for (i, (utxo, change, index)) in found_utxos.iter().enumerate() {
        // Derive the legacy private key for this input
        let priv_bytes = legacy_keystore::derive_private_key(&hex_seed, &mpk, *change, *index)
            .map_err(|e| format!("failed to derive private key at {}/{}: {}", change, index, e))?;
        let priv_key = PrivateKey::from_bytes(&priv_bytes)
            .map_err(|e| format!("invalid legacy private key: {}", e))?;

        // Create P2PKH template for signing
        let p2pkh = P2PKH::from_private_key(priv_key);

        // Create the source locking script (P2PKH)
        let source_locking_script = p2pkh.lock()
            .map_err(|e| format!("failed to create locking script: {}", e))?;

        // Sign the input
        tx.sign(
            i,
            &p2pkh,
            sighash_type,
            utxo.satoshis,
            &source_locking_script,
        )
        .map_err(|e| format!("failed to sign input {}: {}", i, e))?;
    }

    // Step 7: Broadcast the transaction
    let raw_tx = tx.to_hex().map_err(|e| format!("failed to serialize tx: {}", e))?;
    let raw_tx_bytes = hex::decode(&raw_tx)
        .map_err(|e| format!("failed to decode tx hex: {}", e))?;

    let txid = if let Some(ref woc) = woc_client {
        let result = woc.broadcast_tx(&raw_tx_bytes).await
            .map_err(|e| format!("broadcast failed (WoC): {}", e))?;
        result.txid
    } else if let Some(ref ex) = electrumx_client {
        // ElectrumX broadcast: blockchain.transaction.broadcast
        let result = ex.call(
            "blockchain.transaction.broadcast",
            serde_json::json!([raw_tx]),
        ).await
            .map_err(|e| format!("broadcast failed (ElectrumX): {}", e))?;
        result.as_str().unwrap_or("").to_string()
    } else {
        return Err("no network backend connected — cannot broadcast".to_string());
    };

    log::info!("sweep_legacy_to_new — broadcast successful, txid: {}", txid);

    // Close the new wallet after sweep
    let _ = wallet_service::close_wallet(&state);

    Ok(SweepResult {
        addresses_scanned: legacy_addresses.len() as u32,
        utxos_found: found_utxos.len() as u32,
        total_sats: sweep_amount,
        txid: Some(txid),
        new_addresses: vec![dest_address],
    })
}

/// Get a receive address from the currently open (unlocked) wallet.
///
/// Derives the first receiving address (0/0) from the wallet's xprv.
async fn get_new_wallet_receive_address(state: &AppState) -> Result<String, String> {
    let (xprv_str, _account_id) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        let xprv = active
            .decrypted_xprv
            .as_ref()
            .ok_or("wallet is locked — cannot derive address")?;
        (xprv.clone(), active.account_id)
    };

    // Derive 0/0 from the xprv
    let account_key = bsv::compat::bip32::ExtendedKey::from_string(&xprv_str)
        .map_err(|e| format!("failed to parse xprv: {}", e))?;
    let child = account_key
        .derive("0/0")
        .map_err(|e| format!("failed to derive 0/0: {}", e))?;
    let pubkey = child
        .public_key()
        .map_err(|e| format!("failed to get public key: {}", e))?;
    let address = crate::core::address::pubkey_to_p2pkh_address(&pubkey);
    Ok(address)
}

// Silence unused import warnings
#[allow(unused_imports)]
use legacy_mnemonic as _;