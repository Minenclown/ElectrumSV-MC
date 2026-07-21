// ElectrumSV-Mc — Rust/Tauri Port
// lib.rs — Tauri Builder + IPC command registration
//
// Replaces the old sidecar approach (starting a Python daemon).
// As of Milestone 1, Rust is the backend — no ports, no Python.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

pub mod commands;
pub mod core;
pub mod db;
pub mod features;
pub mod network;
pub mod security;
pub mod services;
pub mod state;

use state::AppState;

// Existing commands (kept for compatibility)
#[tauri::command]
fn get_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[tauri::command]
fn get_app_name() -> String {
    env!("CARGO_PKG_NAME").to_string()
}

pub fn run() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .format_timestamp_secs()
        .init();

    log::info!("ElectrumSV-Mc starting (Rust/Tauri native mode)");

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            get_app_version,
            get_app_name,
            // Wallet commands
            commands::wallet::list_wallets,
            commands::wallet::create_wallet,
            commands::wallet::open_wallet,
            commands::wallet::close_wallet,
            commands::wallet::unlock_wallet,
            commands::wallet::get_wallet_status,
            // Account commands (Milestone 3)
            commands::account::get_balance,
            commands::account::get_history,
            commands::account::get_utxos,
            commands::account::get_receive_address,
            commands::account::get_public_key,
            // Network commands (Milestone 4)
            commands::network::get_network_info,
            commands::network::get_servers,
            commands::network::connect_server,
            commands::network::disconnect_server,
            commands::network::set_network_backend,
            commands::network::sync_wallet,
            commands::network::ban_server,
            commands::network::get_servers_by_status,
            // Header Store commands (Milestone 4 — Header-Store / SPV)
            commands::network::get_header_store_info,
            commands::network::sync_headers,
            commands::network::verify_transaction_proof,
            // Transaction commands (Milestone 5 — Send/Sign Workflow)
            commands::transactions::prepare_tx,
            commands::transactions::sign_tx,
            commands::transactions::sign_multisig_tx,
            commands::transactions::broadcast_tx,
            commands::transactions::estimate_fee,
            // TOTP commands (Milestone 5 — AUD-007)
            commands::wallet::enable_totp,
            commands::wallet::disable_totp,
            commands::wallet::verify_totp,
            commands::wallet::is_totp_enabled_cmd,
            // TOTP Recovery codes (Milestone 8-C)
            commands::wallet::generate_totp_recovery_codes,
            commands::wallet::totp_recover,
            // Hardware wallet commands (Milestone 5 — Murena-Prinzip)
            commands::wallet::set_hardware_wallet_enabled,
            commands::wallet::get_hardware_wallet_status,
            // Contacts commands (Milestone 6)
            commands::contacts::get_contacts,
            commands::contacts::add_contact,
            commands::contacts::update_contact,
            commands::contacts::delete_contact,
            // Labels commands (Milestone 6)
            commands::labels::set_key_label,
            commands::labels::set_tx_label,
            commands::labels::get_all_labels,
            // Payment Request commands (Milestone 6)
            commands::payment_requests::create_payment_request,
            commands::payment_requests::list_payment_requests,
            // Config commands (Milestone 6)
            commands::config::get_config,
            commands::config::update_config,
            // Wallet utility commands (Milestone 6)
            commands::wallet::export_seed,
            commands::wallet::export_privkey,
            commands::wallet::change_password,
            commands::wallet::delete_wallet,
            commands::wallet::sign_message,
            commands::wallet::verify_message,
            // Account query commands (Milestone 6)
            commands::account::get_accounts,
            commands::account::get_keys,
            // Multisig account commands (Task 5)
            commands::account::create_multisig_account,
            commands::account::get_multisig_config,
            // QR code commands (Phase 4 — PicQr integration)
            commands::qrcode::generate_qr,
            // Feature decoding commands (BSV on-chain data protocols)
            commands::features::decode_output,
            commands::features::decode_tx_outputs,
            commands::features::get_ordinals,
            commands::features::get_protocol_data,
            commands::features::get_token_transfers,
            // Extra commands (ported from Python)
            commands::extra::get_totp_status,
            commands::extra::set_totp_scope,
            commands::extra::get_transaction,
            commands::extra::backup_wallet,
            commands::extra::list_networks,
            commands::extra::switch_network,
            commands::extra::send,
            commands::extra::woc_get_chain_info,
            commands::extra::woc_get_block_header,
            commands::extra::woc_get_tx,
            commands::extra::import_privkey,
            // Ecosystem feature commands (PayMail, exchange rates, mAPI, BIP276)
            commands::ecosystem::resolve_paymail,
            commands::ecosystem::get_exchange_rates,
            commands::ecosystem::get_exchange_rate,
            commands::ecosystem::satoshis_to_fiat,
            commands::ecosystem::get_mapi_fee_quote,
            commands::ecosystem::parse_bip276_uri,
            commands::ecosystem::get_coin_selection_strategies,
            // Service commands (Task 6 — SPV Channels, Cosigner Pool, Label Sync)
            commands::services::spv_create_channel,
            commands::services::spv_list_messages,
            commands::services::spv_post_message,
            commands::services::spv_mark_read,
            commands::services::spv_delete_channel,
            commands::services::cosigner_submit_tx,
            commands::services::cosigner_get_pending,
            commands::services::cosigner_delete_tx,
            commands::services::label_sync_push,
            commands::services::label_sync_pull,
        ])
        .setup(|_app| {
            log::info!("Tauri setup complete — ready for IPC commands");
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
