// commands/restore.rs — Legacy ElectrumSV seed migration Tauri commands
//
// Provides:
// - restore_legacy_wallet: decode legacy seed, validate, create new BIP32 wallet
// - sweep_legacy_to_new: scan legacy addresses for UTXOs, build & broadcast sweep tx
//
// Reference: SPECIFICATION-LEGACY-MIGRATION.md

use crate::core::legacy_keystore;
use crate::core::transaction::{PaymentOutput, SelectedUtxo, TxBuilder};
use crate::network::backend::NetworkBackend;
use crate::services::wallet_service;
use crate::state::AppState;
use bsv::primitives::private_key::PrivateKey;
use bsv::primitives::public_key::PublicKey;
use bsv::primitives::transaction_signature::{SIGHASH_ALL, SIGHASH_FORKID};
use bsv::script::templates::p2pkh::P2PKH;
use bsv::script::templates::ScriptTemplateLock;
use sha2::{Digest, Sha256};
use tauri::State;

/// Standard Electrum gap limit for address scanning.
const GAP_LIMIT: u32 = 20;

/// Safety cap to prevent infinite scanning loops.
const MAX_SCAN_ADDRESSES: u32 = 10_000;

/// Result of restoring a legacy wallet.
#[derive(Debug, serde::Serialize)]
pub struct LegacyRestoreResult {
    pub new_mnemonic: String,
    pub wallet_path: String,
    pub old_addresses_scanned: u32,
    pub migration_status: String,
}

/// Result of sweeping legacy UTXOs to the new wallet.
#[derive(Debug, serde::Serialize)]
pub struct SweepResult {
    pub addresses_scanned: u32,
    pub utxos_found: u32,
    pub total_sats: u64,
    pub txid: Option<String>,
    pub new_addresses: Vec<String>,
    pub sweep_amount: Option<u64>,
    pub message: String,
}

/// Restore a legacy ElectrumSV wallet and migrate it to a new BIP39/BIP32 wallet.
///
/// Steps:
/// 1. Validate and decode the legacy seed
/// 2. Derive the MPK (master public key) from the legacy seed
/// 3. Create a new BIP39/BIP32 wallet (with a fresh random mnemonic)
/// 4. Import the legacy private keys into the new wallet as IMPORTED_PRIVATE_KEY entries
///    so the user can spend from both the new BIP32 addresses and the old legacy addresses.
/// 5. Return the new mnemonic and wallet path
#[tauri::command]
pub async fn restore_legacy_wallet(
    state: State<'_, AppState>,
    seed_words: String,
    password: String,
    wallet_name: String,
) -> Result<LegacyRestoreResult, String> {
    log::info!("restore_legacy_wallet — starting legacy migration for wallet: {}", wallet_name);

    // Validate that the input is actually a legacy seed
    if !legacy_keystore::is_legacy_seed(&seed_words) {
        return Err(
            "The entered seed is not a valid legacy ElectrumSV seed. \
             If this is a BIP39 mnemonic, disable legacy mode."
                .to_string(),
        );
    }

    // Step 1: Decode legacy seed
    let hex_seed = legacy_keystore::decode_legacy_seed(&seed_words)
        .map_err(|e| format!("failed to decode legacy seed: {}", e))?;
    log::info!("restore_legacy_wallet — decoded legacy seed ({} hex chars)", hex_seed.len());

    // Step 2: Derive MPK (validates the seed produces a usable key)
    let mpk = legacy_keystore::derive_mpk(&hex_seed)
        .map_err(|e| format!("failed to derive MPK: {}", e))?;
    log::info!("restore_legacy_wallet — derived MPK ({} chars)", mpk.len());

    // Step 3: Generate new BIP39 mnemonic and create new BIP32 wallet
    let create_result = wallet_service::create_wallet(
        &state,
        &wallet_name,
        &password,
        None, // generate new mnemonic
        None, // no passphrase
    )
    .await
    .map_err(|e| format!("failed to create new wallet: {}", e))?;

    log::info!("restore_legacy_wallet — new wallet created at {}", create_result.wallet_path);

    // Step 4: Import legacy private keys into the new wallet
    // The new wallet is already open and unlocked after create_wallet.
    let (pool, account_id) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (active.db_pool.clone(), active.account_id)
    };

    let mk_row = crate::db::repositories::get_first_master_key(&pool)
        .await
        .map_err(|e| format!("failed to get master key: {}", e))?;
    let masterkey_id = mk_row.map(|mk| mk.masterkey_id);

    let mut imported_count: u32 = 0;
    for change in 0..=1u32 {
        for index in 0..GAP_LIMIT {
            // Derive the legacy private key for this (change, index)
            let priv_bytes = match legacy_keystore::derive_private_key(&hex_seed, &mpk, change, index) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::warn!("restore_legacy_wallet — failed to derive privkey at {}/{}: {}", change, index, e);
                    continue;
                }
            };

            let priv_key = match PrivateKey::from_bytes(&priv_bytes) {
                Ok(pk) => pk,
                Err(e) => {
                    log::warn!("restore_legacy_wallet — invalid private key at {}/{}: {}", change, index, e);
                    continue;
                }
            };

            // Get the legacy address (uncompressed pubkey P2PKH)
            let pubkey = priv_key.to_public_key();
            let address = legacy_keystore::pubkey_to_p2pkh_address_uncompressed(&pubkey);

            // Convert private key to WIF for storage (encrypted with password)
            let wif = priv_key.to_wif(&[0x80]);

            // Store as imported key (derivation_type = IMPORTED_PRIVATE_KEY = 1)
            let derivation_data = serde_json::json!({
                "type": "imported_privkey",
                "wif_encrypted": crate::security::encryption::pw_encode(&wif, &password),
                "legacy_change": change,
                "legacy_index": index,
                "legacy_address": address,
            })
            .to_string()
            .into_bytes();

            let description = format!("Legacy ElectrumSV key {}/{}", change, index);

            if let Err(e) = crate::db::repositories::insert_keyinstance(
                &pool,
                account_id,
                masterkey_id,
                1, // DerivationType::IMPORTED_PRIVATE_KEY
                &derivation_data,
                crate::db::repositories::script_type::P2PKH,
                0,
                Some(&description),
            )
            .await
            {
                log::warn!("restore_legacy_wallet — failed to insert keyinstance at {}/{}: {}", change, index, e);
                continue;
            }

            imported_count += 1;
        }
    }

    log::info!(
        "restore_legacy_wallet — imported {} legacy keys into new wallet",
        imported_count
    );

    Ok(LegacyRestoreResult {
        new_mnemonic: create_result.mnemonic,
        wallet_path: create_result.wallet_path,
        old_addresses_scanned: imported_count,
        migration_status: format!(
            "Wallet created with {} legacy keys imported. Call sweep_legacy_to_new to transfer funds.",
            imported_count
        ),
    })
}

/// Scan legacy addresses for UTXOs and sweep them to the new wallet.
#[tauri::command]
pub async fn sweep_legacy_to_new(
    state: State<'_, AppState>,
    seed_words: String,
    new_wallet_path: String,
    password: String,
) -> Result<SweepResult, String> {
    log::info!("sweep_legacy_to_new — starting sweep");

    // Validate legacy seed
    if !legacy_keystore::is_legacy_seed(&seed_words) {
        return Err("invalid legacy seed".to_string());
    }

    let hex_seed = legacy_keystore::decode_legacy_seed(&seed_words)
        .map_err(|e| format!("failed to decode legacy seed: {}", e))?;
    let mpk = legacy_keystore::derive_mpk(&hex_seed)
        .map_err(|e| format!("failed to derive MPK: {}", e))?;

    // Check network backend availability upfront
    let woc_client = { state.network.lock().unwrap().woc_client.clone() };
    let electrumx_client = { state.network.lock().unwrap().client.clone() };

    if woc_client.is_none() && electrumx_client.is_none() {
        return Err(
            "No network backend connected — cannot scan for UTXOs. \
             Connect to WhatsOnChain or ElectrumX first."
                .to_string(),
        );
    }

    // Step 2: Scan legacy addresses with gap-limit continuation
    let mut found_utxos: Vec<(SelectedUtxo, u32, u32)> = Vec::new();
    let mut total_sats: u64 = 0;
    let mut addresses_scanned: u32 = 0;
    let mut query_failures: u32 = 0;
    let mut query_successes: u32 = 0;

    for change in 0..=1u32 {
        let mut last_found_index: Option<u32> = None;
        let mut index = 0u32;

        loop {
            // Derive address
            let pubkey = legacy_keystore::derive_pubkey(&mpk, change, index)
                .map_err(|e| format!("failed to derive pubkey at {}/{}: {}", change, index, e))?;
            let address = legacy_keystore::pubkey_to_p2pkh_address_uncompressed(&pubkey);
            addresses_scanned += 1;

            // Query UTXOs
            let utxos_result: Result<Vec<crate::network::backend::UtxoEntry>, String> = if let Some(ref woc) = woc_client {
                woc.get_utxos(&address).await.map_err(|e| e.to_string())
            } else if let Some(ref ex) = electrumx_client {
                let scripthash = match crate::network::backend::scripthash_from_address(&address) {
                    Ok(sh) => sh,
                    Err(e) => {
                        query_failures += 1;
                        log::warn!("scripthash computation failed for {}: {}", address, e);
                        // Gap continuation
                        if let Some(last) = last_found_index {
                            if index - last >= GAP_LIMIT { break; }
                        } else if index + 1 >= GAP_LIMIT { break; }
                        index += 1;
                        if index >= MAX_SCAN_ADDRESSES { break; }
                        continue;
                    }
                };
                ex.call("blockchain.scripthash.listunspent", serde_json::json!([scripthash]))
                    .await
                    .map(|v| {
                        v.as_array().map(|arr| {
                            arr.iter().filter_map(|entry| {
                                let tx_hash = entry.get("tx_hash")?.as_str()?.to_string();
                                let tx_pos = entry.get("tx_pos")?.as_u64()? as u32;
                                let value = entry.get("value")?.as_u64()?;
                                Some(crate::network::backend::UtxoEntry {
                                    tx_hash,
                                    tx_pos,
                                    value,
                                    height: entry.get("height").and_then(|h| h.as_i64()).unwrap_or(0),
                                })
                            }).collect::<Vec<_>>()
                        }).unwrap_or_default()
                    })
                    .map_err(|e| e.to_string())
            } else {
                unreachable!("backend checked above");
            };

            match utxos_result {
                Ok(utxos) => {
                    query_successes += 1;
                    if !utxos.is_empty() {
                        last_found_index = Some(index);
                        for utxo in utxos {
                            let satoshis = utxo.value;
                            total_sats = total_sats.checked_add(satoshis)
                                .ok_or("total UTXO value overflow")?;
                            let selected = SelectedUtxo {
                                tx_hash_hex: utxo.tx_hash,
                                tx_index: utxo.tx_pos,
                                satoshis,
                                keyinstance_id: 0,
                                subpath: [change, index],
                            };
                            found_utxos.push((selected, change, index));
                        }
                    }
                }
                Err(e) => {
                    query_failures += 1;
                    log::warn!("UTXO query failed for {}: {}", address, e);
                }
            }

            // Gap-limit continuation logic
            if let Some(last) = last_found_index {
                if index - last >= GAP_LIMIT {
                    break;
                }
            } else if index + 1 >= GAP_LIMIT {
                break;
            }

            index += 1;
            if index >= MAX_SCAN_ADDRESSES {
                log::warn!("reached max scan limit {} for change={}", MAX_SCAN_ADDRESSES, change);
                break;
            }
        }
    }

    log::info!(
        "sweep_legacy_to_new — scanned {} addresses, found {} UTXOs totaling {} sats (successes={}, failures={})",
        addresses_scanned, found_utxos.len(), total_sats, query_successes, query_failures
    );

    // Distinguish "no UTXOs" from "all queries failed"
    if query_successes == 0 && query_failures > 0 {
        return Err(format!(
            "all {} UTXO queries failed — check your network connection",
            query_failures
        ));
    }

    if found_utxos.is_empty() {
        log::info!("sweep_legacy_to_new — no UTXOs found, nothing to sweep");
        return Ok(SweepResult {
            addresses_scanned,
            utxos_found: 0,
            total_sats: 0,
            txid: None,
            new_addresses: Vec::new(),
            sweep_amount: None,
            message: "No UTXOs found on legacy addresses — nothing to sweep.".to_string(),
        });
    }

    // Step 4: Open and unlock the new wallet to get a receive address
    wallet_service::open_wallet(&state, &new_wallet_path)
        .await
        .map_err(|e| format!("failed to open new wallet: {}", e))?;
    wallet_service::unlock_wallet(&state, &password)
        .map_err(|e| format!("failed to unlock new wallet: {}", e))?;

    let dest_address = get_new_wallet_receive_address(&state).await?;

    // Step 5: Build the sweep transaction
    // Use a minimal output amount initially, with change going to the destination.
    // After building, adjust the output to total_input - fee (true sweep).
    let utxos: Vec<SelectedUtxo> = found_utxos.iter().map(|(u, _, _)| u.clone()).collect();
    let outputs = vec![PaymentOutput {
        address: dest_address.clone(),
        satoshis: 1, // placeholder — will be adjusted after fee calc
    }];

    let (mut tx, selection) = TxBuilder::build_unsigned(
        &utxos,
        &outputs,
        Some(&dest_address), // change goes back to destination
        1,                   // 1 sat/byte fee rate
        None,                // no OP_RETURN
        None,                // default coin selection
    )
    .map_err(|e| format!("failed to build sweep transaction: {}", e))?;

    // Calculate the true sweep amount: total inputs - fee
    let sweep_amount = selection.total_input.saturating_sub(selection.fee);
    if sweep_amount == 0 {
        let _ = wallet_service::close_wallet(&state);
        return Err("sweep amount is zero after fee — dust UTXOs".to_string());
    }

    // Set the first output to the sweep amount and remove any change output (true sweep)
    if let Some(satoshi_ref) = tx.outputs[0].satoshis.as_mut() {
        *satoshi_ref = sweep_amount;
    }
    // Truncate to a single output (remove change output if added)
    if tx.outputs.len() > 1 {
        tx.outputs.truncate(1);
    }

    log::info!(
        "sweep_legacy_to_new — built tx with {} inputs, {} sats output, {} sats fee",
        utxos.len(), sweep_amount, selection.fee
    );

    // Step 6: Sign each input with the legacy private key using UNCOMPRESSED pubkeys
    let sighash_type = SIGHASH_ALL | SIGHASH_FORKID; // 0x41

    for (i, (utxo, change, index)) in found_utxos.iter().enumerate() {
        let priv_bytes = legacy_keystore::derive_private_key(&hex_seed, &mpk, *change, *index)
            .map_err(|e| format!("failed to derive private key at {}/{}: {}", change, index, e))?;
        let priv_key = PrivateKey::from_bytes(&priv_bytes)
            .map_err(|e| format!("invalid legacy private key: {}", e))?;

        // Build the correct P2PKH locking script using the UNCOMPRESSED public key
        let pub_key = priv_key.to_public_key();
        let uncompressed_der = pub_key.to_der_uncompressed(); // 65 bytes: 0x04 + X + Y
        let sha = Sha256::digest(&uncompressed_der);
        let hash160 = bsv::primitives::hash::ripemd160(&sha);

        // Build P2PKH script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let mut script_bytes = Vec::with_capacity(25);
        script_bytes.push(0x76); // OP_DUP
        script_bytes.push(0xa9); // OP_HASH160
        script_bytes.push(0x14); // push 20 bytes
        script_bytes.extend_from_slice(&hash160);
        script_bytes.push(0x88); // OP_EQUALVERIFY
        script_bytes.push(0xac); // OP_CHECKSIG

        let source_locking_script = bsv::script::locking_script::LockingScript::from_script(
            bsv::script::script::Script::from_binary(&script_bytes),
        );

        // Sign the input with the legacy P2PKH template
        let p2pkh_template = P2PKH::from_private_key(priv_key);
        tx.sign(
            i,
            &p2pkh_template,
            sighash_type,
            utxo.satoshis,
            &source_locking_script,
        )
        .map_err(|e| format!("failed to sign input {}: {}", i, e))?;

        // IMPORTANT: The unlocking script generated by tx.sign uses the compressed public key.
        // For legacy ElectrumSV UTXOs, we need the UNCOMPRESSED public key in the unlocking script.
        // Replace the unlocking script with one using the uncompressed pubkey.
        let sig = tx.inputs[i]
            .unlocking_script
            .as_ref()
            .ok_or("unlocking script missing after sign")?;
        let sig_bytes = sig.to_binary();
        // Extract just the signature (first push in the unlocking script)
        let sig_len = sig_bytes.first().copied().unwrap_or(0) as usize;
        let sig_data = &sig_bytes[1..1 + sig_len.min(sig_bytes.len() - 1)];

        // Rebuild unlocking script: <sig+sighash> <uncompressed_pubkey>
        let mut unlock_bytes = Vec::new();
        unlock_bytes.push(sig_data.len() as u8);
        unlock_bytes.extend_from_slice(sig_data);
        unlock_bytes.push(65); // push 65 bytes (uncompressed pubkey)
        unlock_bytes.extend_from_slice(&uncompressed_der);

        let unlock_script = bsv::script::unlocking_script::UnlockingScript::from_script(
            bsv::script::script::Script::from_binary(&unlock_bytes),
        );
        tx.inputs[i].unlocking_script = Some(unlock_script);
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
        let result = ex.call(
            "blockchain.transaction.broadcast",
            serde_json::json!([raw_tx]),
        )
        .await
        .map_err(|e| format!("broadcast failed (ElectrumX): {}", e))?;
        result.as_str().unwrap_or("").to_string()
    } else {
        let _ = wallet_service::close_wallet(&state);
        return Err("no network backend connected — cannot broadcast".to_string());
    };

    log::info!("sweep_legacy_to_new — broadcast successful, txid: {}", txid);

    let _ = wallet_service::close_wallet(&state);

    Ok(SweepResult {
        addresses_scanned,
        utxos_found: found_utxos.len() as u32,
        total_sats,
        txid: Some(txid),
        new_addresses: vec![dest_address],
        sweep_amount: Some(sweep_amount),
        message: format!(
            "Sweep broadcast. {} satoshis sent to new wallet. \
             Please verify confirmation on a block explorer before deleting your legacy seed.",
            sweep_amount
        ),
    })
}

/// Get a receive address from the currently open (unlocked) wallet.
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