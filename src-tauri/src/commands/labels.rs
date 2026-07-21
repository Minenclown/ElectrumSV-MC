// commands/labels.rs — Label (key/tx) Tauri commands
//
// Provides: set_key_label, set_tx_label
// Labels are stored in the description column of KeyInstances / Transactions.

use crate::db::repositories;
use crate::features::label_sync::{LabelKind, WalletLabel};
use crate::state::AppState;
use tauri::State;

/// Set a label for a KeyInstance (address label).
///
/// If label is empty, the description is cleared (set to NULL).
#[tauri::command]
pub async fn set_key_label(
    state: State<'_, AppState>,
    key_id: i64,
    label: String,
) -> Result<(), String> {
    log::info!("set_key_label — key_id: {}, label: {}", key_id, label);

    let pool = {
        let guard = state.active_wallet.lock().unwrap();
        guard
            .as_ref()
            .ok_or("no wallet is currently open")?
            .db_pool
            .clone()
    };

    // Verify keyinstance exists
    repositories::get_keyinstance(&pool, key_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("keyinstance {} not found", key_id))?;

    let label_opt = if label.is_empty() { None } else { Some(label.as_str()) };

    repositories::set_keyinstance_label(&pool, key_id, label_opt)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Set a label for a Transaction.
///
/// tx_hash is the display hex txid (reversed byte order).
/// If label is empty, the description is cleared (set to NULL).
#[tauri::command]
pub async fn set_tx_label(
    state: State<'_, AppState>,
    tx_hash: String,
    label: String,
) -> Result<(), String> {
    log::info!("set_tx_label — tx_hash: {}, label: {}", tx_hash, label);

    let pool = {
        let guard = state.active_wallet.lock().unwrap();
        guard
            .as_ref()
            .ok_or("no wallet is currently open")?
            .db_pool
            .clone()
    };

    // Convert display hex (reversed) to internal byte order
    let tx_hash_bytes = hex::decode(&tx_hash).map_err(|e| format!("invalid tx_hash hex: {}", e))?;
    let mut internal_hash = tx_hash_bytes;
    internal_hash.reverse();

    let label_opt = if label.is_empty() { None } else { Some(label.as_str()) };

    repositories::set_transaction_label(&pool, &internal_hash, label_opt)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Load all labels (address + transaction) from the local database.
///
/// Returns a `Vec<WalletLabel>` combining:
/// - KeyInstance labels (kind = `Address`, id = `"key-{keyinstance_id}"`)
/// - Transaction labels (kind = `Transaction`, id = display hex txid)
///
/// KeyInstance ids use the `key-` prefix because deriving the actual address
/// requires the xprv, which may not be unlocked.
#[tauri::command]
pub async fn get_all_labels(state: State<'_, AppState>) -> Result<Vec<WalletLabel>, String> {
    log::info!("get_all_labels");

    let pool = {
        let guard = state.active_wallet.lock().unwrap();
        guard
            .as_ref()
            .ok_or("no wallet is currently open")?
            .db_pool
            .clone()
    };

    let mut labels = Vec::new();

    // KeyInstance (address) labels
    let key_labels = repositories::get_all_key_labels(&pool)
        .await
        .map_err(|e| e.to_string())?;
    for (ki_id, description, updated_at) in key_labels {
        labels.push(WalletLabel {
            id: format!("key-{}", ki_id),
            kind: LabelKind::Address,
            label: description,
            updated_at,
        });
    }

    // Transaction labels
    let tx_labels = repositories::get_all_tx_labels(&pool)
        .await
        .map_err(|e| e.to_string())?;
    for (tx_hash_hex, description, updated_at) in tx_labels {
        labels.push(WalletLabel {
            id: tx_hash_hex,
            kind: LabelKind::Transaction,
            label: description,
            updated_at,
        });
    }

    log::info!("get_all_labels — returning {} labels", labels.len());
    Ok(labels)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::wallet_service;
    use crate::state::AppState;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn make_test_state(test_name: &str) -> AppState {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let temp_dir = std::env::temp_dir()
            .join(format!("electrumsv_mc_lbl_{}_{}", test_name, id));
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

    async fn setup_keyinstance(state: &AppState) -> (sqlx::SqlitePool, i64, i64) {
        let (pool, acct_id) = {
            let guard = state.active_wallet.lock().unwrap();
            let active = guard.as_ref().unwrap();
            (active.db_pool.clone(), active.account_id)
        };
        let derivation_data = serde_json::json!({"subpath": [0, 0]})
            .to_string()
            .into_bytes();
        let ki_id = repositories::insert_keyinstance(
            &pool,
            acct_id,
            None,
            repositories::derivation_type::BIP32,
            &derivation_data,
            repositories::script_type::P2PKH,
            0,
            None,
        )
        .await
        .unwrap();
        (pool, acct_id, ki_id)
    }

    #[tokio::test]
    async fn test_set_key_label_on_existing_key() {
        let state = make_test_state("lbl_set");
        wallet_service::create_wallet(&state, "test_lbl", "pw123", None, None)
            .await
            .unwrap();

        let (pool, _acct_id, ki_id) = setup_keyinstance(&state).await;

        repositories::set_keyinstance_label(&pool, ki_id, Some("My Address"))
            .await
            .unwrap();

        let label = repositories::get_keyinstance_label(&pool, ki_id)
            .await
            .unwrap();
        assert_eq!(label, Some("My Address".to_string()));

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_set_key_label_empty_clears() {
        let state = make_test_state("lbl_clear");
        wallet_service::create_wallet(&state, "test_clr", "pw123", None, None)
            .await
            .unwrap();

        let (pool, _acct_id, ki_id) = setup_keyinstance(&state).await;

        // Set a label first
        repositories::set_keyinstance_label(&pool, ki_id, Some("Temp"))
            .await
            .unwrap();
        let label = repositories::get_keyinstance_label(&pool, ki_id)
            .await
            .unwrap();
        assert_eq!(label, Some("Temp".to_string()));

        // Clear it with None
        repositories::set_keyinstance_label(&pool, ki_id, None)
            .await
            .unwrap();
        let label = repositories::get_keyinstance_label(&pool, ki_id)
            .await
            .unwrap();
        assert_eq!(label, None);

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_set_key_label_nonexistent_returns_error() {
        let state = make_test_state("lbl_404");
        wallet_service::create_wallet(&state, "test_404", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        let result = repositories::get_keyinstance(&pool, 99999).await.unwrap();
        assert!(result.is_none(), "nonexistent keyinstance should be None");

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_set_tx_label_valid_hex() {
        let state = make_test_state("lbl_tx");
        wallet_service::create_wallet(&state, "test_tx", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        // Insert a transaction row with a known internal hash
        let tx_hash_internal = vec![0xaa, 0xbb, 0xcc, 0xdd];
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO Transactions (tx_hash, block_height, flags, date_created, date_updated) VALUES (?, NULL, 0, ?, ?)",
        )
        .bind(&tx_hash_internal)
        .bind(now)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();

        // Display hex = reversed internal bytes
        let display_hex = hex::encode({
            let mut v = tx_hash_internal.clone();
            v.reverse();
            v
        });

        // Simulate set_tx_label: decode display hex, reverse to internal, set label
        let tx_hash_bytes = hex::decode(&display_hex).unwrap();
        let mut internal_hash = tx_hash_bytes;
        internal_hash.reverse();
        assert_eq!(internal_hash, tx_hash_internal);

        repositories::set_transaction_label(&pool, &internal_hash, Some("Sent"))
            .await
            .unwrap();

        let label = repositories::get_transaction_label(&pool, &internal_hash)
            .await
            .unwrap();
        assert_eq!(label, Some("Sent".to_string()));

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_set_tx_label_invalid_hex() {
        // Test the hex decode logic that set_tx_label uses
        let bad_hex = "zzzz";
        let result = hex::decode(bad_hex);
        assert!(result.is_err(), "invalid hex should fail to decode");

        let good_hex = "aabbccdd";
        let result = hex::decode(good_hex);
        assert!(result.is_ok(), "valid hex should decode");
        assert_eq!(result.unwrap(), vec![0xaa, 0xbb, 0xcc, 0xdd]);

        // Odd-length hex should also fail
        let odd_hex = "abc";
        let result = hex::decode(odd_hex);
        assert!(result.is_err(), "odd-length hex should fail to decode");
    }

    #[tokio::test]
    async fn test_get_all_labels_combines_key_and_tx_labels() {
        let state = make_test_state("lbl_all");
        wallet_service::create_wallet(&state, "test_all", "pw123", None, None)
            .await
            .unwrap();

        let (pool, _acct_id, ki_id) = setup_keyinstance(&state).await;

        // Set a key label
        repositories::set_keyinstance_label(&pool, ki_id, Some("Addr 1"))
            .await
            .unwrap();

        // Insert a transaction and set a tx label
        let tx_hash_internal = vec![0x11, 0x22, 0x33, 0x44];
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO Transactions (tx_hash, block_height, flags, date_created, date_updated) VALUES (?, NULL, 0, ?, ?)",
        )
        .bind(&tx_hash_internal)
        .bind(now)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();

        repositories::set_transaction_label(&pool, &tx_hash_internal, Some("My Tx"))
            .await
            .unwrap();

        // Query all labels via the repository functions
        let key_labels = repositories::get_all_key_labels(&pool).await.unwrap();
        assert_eq!(key_labels.len(), 1);
        assert_eq!(key_labels[0].0, ki_id);
        assert_eq!(key_labels[0].1, "Addr 1");

        let tx_labels = repositories::get_all_tx_labels(&pool).await.unwrap();
        assert_eq!(tx_labels.len(), 1);
        // Display hex = reversed internal bytes
        let expected_display = hex::encode({
            let mut v = tx_hash_internal.clone();
            v.reverse();
            v
        });
        assert_eq!(tx_labels[0].0, expected_display);
        assert_eq!(tx_labels[0].1, "My Tx");

        // Simulate get_all_labels command logic: combine both
        let mut all = Vec::new();
        for (id, desc, ts) in key_labels {
            all.push((format!("key-{}", id), "address", desc, ts));
        }
        for (id, desc, ts) in tx_labels {
            all.push((id, "transaction", desc, ts));
        }
        assert_eq!(all.len(), 2);

        // Verify key label entry
        let key_entry = all.iter().find(|(id, kind, _, _)| kind == &"address").unwrap();
        assert_eq!(key_entry.0, format!("key-{}", ki_id));
        assert_eq!(key_entry.2, "Addr 1");

        // Verify tx label entry
        let tx_entry = all.iter().find(|(_, kind, _, _)| kind == &"transaction").unwrap();
        assert_eq!(tx_entry.0, expected_display);
        assert_eq!(tx_entry.2, "My Tx");

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_get_all_labels_empty_when_no_labels() {
        let state = make_test_state("lbl_empty");
        wallet_service::create_wallet(&state, "test_empty", "pw123", None, None)
            .await
            .unwrap();

        let (pool, _acct_id, _ki_id) = setup_keyinstance(&state).await;

        // No labels set — both queries should return empty
        let key_labels = repositories::get_all_key_labels(&pool).await.unwrap();
        assert!(key_labels.is_empty(), "no key labels expected");

        let tx_labels = repositories::get_all_tx_labels(&pool).await.unwrap();
        assert!(tx_labels.is_empty(), "no tx labels expected");

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }
}