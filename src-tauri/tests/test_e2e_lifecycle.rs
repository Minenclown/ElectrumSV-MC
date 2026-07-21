// tests/test_e2e_lifecycle.rs — End-to-end wallet lifecycle integration test
//
// Exercises the full wallet flow as far as possible without a live ElectrumX
// network connection:
//
//   create wallet -> open -> unlock -> get receive address -> check balance
//   -> get UTXOs -> prepare_tx (empty UTXOs -> NoUtxos error)
//   -> change password -> export seed -> close -> reopen (locked)
//   -> unlock with new password -> cleanup
//
// All assertions exercise real wallet_service + repositories + keystore logic.
// No mocks, no #[ignore] — the test runs and passes on every `cargo test`.

use electrumsv_mc_lib::core::keystore;
use electrumsv_mc_lib::core::transaction::{PaymentOutput, SelectedUtxo, TxBuilder, TransactionError};
use electrumsv_mc_lib::db::repositories;
use electrumsv_mc_lib::security::encryption;
use electrumsv_mc_lib::services::wallet_service;
use electrumsv_mc_lib::state::AppState;
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Known BIP39 test vector (all "abandon" + "about").
const KNOWN_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Build a fresh AppState backed by a unique temp data_dir.
fn make_test_state(test_name: &str) -> AppState {
    let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let temp_dir = std::env::temp_dir().join(format!("electrumsv_mc_e2e_{}_{}", test_name, id));
    if temp_dir.exists() {
        std::fs::remove_dir_all(&temp_dir).ok();
    }
    std::fs::create_dir_all(&temp_dir).unwrap();
    AppState {
        data_dir: temp_dir.to_string_lossy().to_string(),
        active_wallet: std::sync::Mutex::new(None),
        network: std::sync::Mutex::new(electrumsv_mc_lib::state::NetworkState::new()),
        pending_plans: std::sync::Mutex::new(std::collections::HashMap::new()),
    }
}

/// Extract (db_pool, account_id, keystore_data, decrypted_xprv) from the active wallet.
fn grab_active_wallet(state: &AppState) -> (sqlx::SqlitePool, i64, keystore::KeyStoreData, Option<String>) {
    let guard = state.active_wallet.lock().unwrap();
    let active = guard.as_ref().expect("wallet should be open");
    (
        active.db_pool.clone(),
        active.account_id,
        active.keystore_data.clone(),
        active.decrypted_xprv.clone(),
    )
}

// ---------------------------------------------------------------------------
// The single E2E test — everything in one #[tokio::test] so the steps run
// sequentially against the same wallet/state, exactly like a real user session.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_e2e_wallet_lifecycle() {
    let state = make_test_state("lifecycle");
    let password = "testpw123";
    let new_password = "new_password_456";

    // -----------------------------------------------------------------
    // Step 1: Create wallet with a known mnemonic
    // -----------------------------------------------------------------
    let result = wallet_service::create_wallet(&state, "e2e_test", password, Some(KNOWN_MNEMONIC), None)
        .await
        .expect("create_wallet should succeed");

    assert!(!result.is_new_mnemonic, "using a known mnemonic -> is_new_mnemonic=false");
    assert_eq!(result.mnemonic, KNOWN_MNEMONIC, "mnemonic should match the input");
    assert_eq!(result.account_id, 1, "first account should have id=1");

    let wallet_path = result.wallet_path.clone();
    let account_id = result.account_id;

    // Verify the wallet file exists on disk
    assert!(std::path::Path::new(&wallet_path).exists(), "wallet file must exist after create");

    // Verify active_wallet is set and unlocked (decrypted_xprv present)
    {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().expect("active_wallet should be set after create");
        assert_eq!(active.wallet_path, wallet_path);
        assert!(active.is_unlocked(), "freshly created wallet should be unlocked");
        assert!(active.decrypted_xprv.is_some(), "decrypted_xprv must be Some after create");
    }

    // -----------------------------------------------------------------
    // Step 2: Get accounts — at least one must exist
    // -----------------------------------------------------------------
    let (pool, _, _, _) = grab_active_wallet(&state);
    let accounts = repositories::get_all_accounts(&pool)
        .await
        .expect("get_all_accounts should succeed");
    assert!(!accounts.is_empty(), "fresh wallet should have at least one account");
    assert_eq!(accounts[0].account_id, account_id, "account_id should match create result");

    // -----------------------------------------------------------------
    // Step 3: Get a receive address — must be a mainnet P2PKH address ("1...")
    // -----------------------------------------------------------------
    let (pool, default_acct_id, _, xprv_opt) = grab_active_wallet(&state);
    let xprv = xprv_opt.expect("wallet should be unlocked for address derivation");

    // Derive the next receive address (0/N) — mirrors get_receive_address logic
    let (receiving_count, _) = repositories::get_keyinstance_counts(&pool, default_acct_id)
        .await
        .expect("get_keyinstance_counts should succeed");
    let next_index = receiving_count;

    let account_key = bsv::compat::bip32::ExtendedKey::from_string(&xprv)
        .expect("xprv should parse");
    let child_key = account_key
        .derive(&format!("0/{}", next_index))
        .expect("derivation should succeed");
    let pubkey = child_key
        .public_key()
        .expect("public_key derivation should succeed");
    let address = electrumsv_mc_lib::core::address::pubkey_to_p2pkh_address(&pubkey);

    assert!(
        address.starts_with('1'),
        "mainnet P2PKH address must start with '1', got: {}",
        address
    );
    assert!(address.len() >= 26 && address.len() <= 35, "address length in valid range");

    // -----------------------------------------------------------------
    // Step 4: Check balance — fresh wallet must have zero balance
    // -----------------------------------------------------------------
    let (pool, default_acct_id, _, _) = grab_active_wallet(&state);
    let (confirmed, unconfirmed, total) = repositories::get_balance_for_account(&pool, default_acct_id)
        .await
        .expect("get_balance_for_account should succeed");
    assert_eq!(confirmed, 0, "fresh wallet confirmed balance must be 0");
    assert_eq!(unconfirmed, 0, "fresh wallet unconfirmed balance must be 0");
    assert_eq!(total, 0, "fresh wallet total balance must be 0");

    // -----------------------------------------------------------------
    // Step 5: Get UTXOs — fresh wallet must have no UTXOs
    // -----------------------------------------------------------------
    let (pool, default_acct_id, _, _) = grab_active_wallet(&state);
    let utxos = repositories::get_utxo_infos_for_account(&pool, default_acct_id)
        .await
        .expect("get_utxo_infos_for_account should succeed");
    assert!(utxos.is_empty(), "fresh wallet must have zero UTXOs");

    // -----------------------------------------------------------------
    // Step 6: Prepare TX with empty UTXOs — should return NoUtxos error
    // -----------------------------------------------------------------
    let empty_utxos: Vec<SelectedUtxo> = vec![];
    let outputs = vec![PaymentOutput {
        address: address.clone(),
        satoshis: 1000,
    }];
    let result = TxBuilder::build_unsigned(
        &empty_utxos,
        &outputs,
        Some(&address), // change address
        1,              // fee_rate: 1 sat/byte
        None,           // no OP_RETURN
        None,           // default largest-first strategy
    );
    assert!(
        matches!(result, Err(TransactionError::NoUtxos)),
        "build_unsigned with empty UTXOs must return NoUtxos error, got: {:?}",
        result
    );

    // -----------------------------------------------------------------
    // Step 7: Change password — decrypt xprv, re-encrypt with new password
    // -----------------------------------------------------------------
    let (_, _, ks_data, _) = grab_active_wallet(&state);

    // Decrypt xprv with old password — should succeed
    let decrypted_xprv = keystore::decrypt_xprv(&ks_data, password)
        .expect("decrypt_xprv with old password should succeed");

    // Decrypt mnemonic with old password
    let decrypted_mnemonic = keystore::decrypt_mnemonic(&ks_data, password)
        .expect("decrypt_mnemonic with old password should succeed");

    // Re-encrypt xprv and mnemonic with the new password
    let new_xprv_enc = encryption::pw_encode(&decrypted_xprv, new_password);
    let new_seed_enc = encryption::pw_encode(&decrypted_mnemonic, new_password);

    // Build updated keystore data
    let new_ks_data = keystore::KeyStoreData {
        xpub: ks_data.xpub.clone(),
        xprv: new_xprv_enc,
        seed_type: ks_data.seed_type.clone(),
        derivation: ks_data.derivation.clone(),
        seed: new_seed_enc,
        passphrase: ks_data.passphrase.clone(),
    };

    // Verify old password now FAILS to decrypt the new xprv
    let old_pw_result = keystore::decrypt_xprv(&new_ks_data, password);
    assert!(old_pw_result.is_err(), "old password must fail after change_password");

    // Verify new password SUCCEEDS to decrypt the new xprv
    let new_pw_result = keystore::decrypt_xprv(&new_ks_data, new_password)
        .expect("new password must decrypt the re-encrypted xprv");
    assert_eq!(new_pw_result, decrypted_xprv, "decrypted xprv must be unchanged");

    // Update the in-memory active wallet's keystore_data + decrypted_xprv
    // (mirrors what change_password command does internally)
    {
        let mut guard = state.active_wallet.lock().unwrap();
        if let Some(ref mut active) = *guard {
            active.keystore_data = new_ks_data.clone();
            // Keep decrypted_xprv as-is (already unlocked) — but verify it still works
            // by re-checking against the new keystore data below.
        }
    }

    // Also persist the new keystore to the DB (like the real change_password command)
    {
        let (pool, _, _, _) = grab_active_wallet(&state);
        let new_ks_bytes = keystore::keystore_data_to_bytes(&new_ks_data);
        let mk_row = repositories::get_first_master_key(&pool)
            .await
            .expect("get_first_master_key should succeed")
            .expect("master key must exist");
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "UPDATE MasterKeys SET derivation_data = ?, date_updated = ? WHERE masterkey_id = ?",
        )
        .bind(&new_ks_bytes)
        .bind(now)
        .bind(mk_row.masterkey_id)
        .execute(&pool)
        .await
        .expect("UPDATE MasterKeys should succeed");

        // Clear legacy password-token (matching the real command's behaviour)
        repositories::set_wallet_data(&pool, "password-token", "")
            .await
            .expect("set_wallet_data should succeed");
    }

    // -----------------------------------------------------------------
    // Step 8: Export seed — decrypt mnemonic, verify it matches the original
    // -----------------------------------------------------------------
    let (_, _, ks_data, _) = grab_active_wallet(&state);
    // Verify password
    assert!(
        keystore::verify_password(&ks_data, new_password),
        "new password must verify against updated keystore"
    );
    assert!(
        !keystore::verify_password(&ks_data, password),
        "old password must NOT verify against updated keystore"
    );

    // Decrypt mnemonic with the new password
    let exported_mnemonic = keystore::decrypt_mnemonic(&ks_data, new_password)
        .expect("decrypt_mnemonic with new password should succeed");
    assert_eq!(exported_mnemonic, KNOWN_MNEMONIC, "exported mnemonic must match original");

    // -----------------------------------------------------------------
    // Step 9: Close wallet — active_wallet must become None
    // -----------------------------------------------------------------
    wallet_service::close_wallet(&state).expect("close_wallet should succeed");
    {
        let guard = state.active_wallet.lock().unwrap();
        assert!(guard.is_none(), "active_wallet must be None after close");
    }

    // -----------------------------------------------------------------
    // Step 10: Reopen wallet — must be open but LOCKED (no decrypted_xprv)
    // -----------------------------------------------------------------
    let open_result = wallet_service::open_wallet(&state, &wallet_path)
        .await
        .expect("open_wallet should succeed");
    assert!(!open_result.is_unlocked, "reopened wallet must be locked");

    {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().expect("active_wallet should be set after open");
        assert!(!active.is_unlocked(), "wallet must be locked after reopen");
        assert!(active.decrypted_xprv.is_none(), "decrypted_xprv must be None after reopen");
    }

    // -----------------------------------------------------------------
    // Step 11: Unlock wallet with the NEW password — must succeed
    // -----------------------------------------------------------------
    // First verify old password fails on the reopened wallet
    let old_pw_unlock = wallet_service::unlock_wallet(&state, password);
    assert!(old_pw_unlock.is_err(), "old password must fail to unlock the reopened wallet");

    // Still locked after a failed unlock attempt
    {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().expect("wallet still open");
        assert!(!active.is_unlocked(), "wallet must remain locked after wrong password");
    }

    // Now unlock with the new password
    wallet_service::unlock_wallet(&state, new_password)
        .expect("unlock_wallet with new password should succeed");
    {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().expect("wallet still open after unlock");
        assert!(active.is_unlocked(), "wallet must be unlocked after correct password");
        assert!(active.decrypted_xprv.is_some(), "decrypted_xprv must be Some after unlock");
    }

    // -----------------------------------------------------------------
    // Step 12: Cleanup — close wallet, remove temp dir
    // -----------------------------------------------------------------
    wallet_service::close_wallet(&state).expect("final close_wallet should succeed");

    // Extract data_dir before dropping state
    let data_dir = state.data_dir.clone();
    std::fs::remove_dir_all(&data_dir).ok();
}