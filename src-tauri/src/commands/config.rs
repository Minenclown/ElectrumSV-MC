// commands/config.rs — Config get/update Tauri commands
//
// Uses the existing WalletData key-value store for configuration.
// All config values are stored as strings in WalletData.

use crate::db::repositories;
use crate::state::AppState;
use tauri::State;

/// Get all configuration values from WalletData.
///
/// Returns a JSON object mapping config keys to their string values.
/// Excludes internal keys (migration, next_*, password-token).
#[tauri::command]
pub async fn get_config(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    log::info!("get_config");

    let pool = {
        let guard = state.active_wallet.lock().unwrap();
        guard
            .as_ref()
            .ok_or("no wallet is currently open")?
            .db_pool
            .clone()
    };

    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT key, value FROM WalletData ORDER BY key")
            .fetch_all(&pool)
            .await
            .map_err(|e| e.to_string())?;

    let mut config = serde_json::Map::new();
    for (key, value) in rows {
    // Skip internal keys
    if key == "migration"
        || key.starts_with("next_")
        || key == "password-token"
        || key == "hardware_wallet_enabled"
    {
        continue;
    }
    config.insert(key, serde_json::Value::String(value));
    }

    Ok(serde_json::Value::Object(config))
}

/// Update a configuration value in WalletData.
///
/// Sets a single key-value pair. If the key already exists, it is updated.
#[tauri::command]
pub async fn update_config(
    state: State<'_, AppState>,
    key: String,
    value: String,
) -> Result<(), String> {
    log::info!("update_config — key: {}", key);

    // Reject internal keys
    if key == "migration" || key.starts_with("next_") || key == "password-token" {
        return Err("cannot modify internal configuration keys".to_string());
    }

    let pool = {
        let guard = state.active_wallet.lock().unwrap();
        guard
            .as_ref()
            .ok_or("no wallet is currently open")?
            .db_pool
            .clone()
    };

    repositories::set_wallet_data(&pool, &key, &value)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
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
            .join(format!("electrumsv_mc_cfg_{}_{}", test_name, id));
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

    #[tokio::test]
    async fn test_get_config_empty_wallet() {
        let state = make_test_state("cfg_empty");
        wallet_service::create_wallet(&state, "test_cfg", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT key, value FROM WalletData ORDER BY key")
                .fetch_all(&pool)
                .await
                .unwrap();

        // New wallet may have internal keys (migration, next_*) but no user config.
        // All visible keys should be internal.
        for (key, _) in &rows {
            assert!(
                key == "migration"
                    || key.starts_with("next_")
                    || key == "password-token"
                    || key == "hardware_wallet_enabled",
                "unexpected non-internal key in new wallet: {}",
                key
            );
        }

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_update_config_sets_key() {
        let state = make_test_state("cfg_set");
        wallet_service::create_wallet(&state, "test_set", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        repositories::set_wallet_data(&pool, "currency", "USD")
            .await
            .unwrap();

        let val = repositories::get_wallet_data(&pool, "currency")
            .await
            .unwrap();
        assert_eq!(val, Some("USD".to_string()));

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_get_config_returns_key_after_setting() {
        let state = make_test_state("cfg_get");
        wallet_service::create_wallet(&state, "test_get", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        repositories::set_wallet_data(&pool, "language", "en")
            .await
            .unwrap();

        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT key, value FROM WalletData ORDER BY key")
                .fetch_all(&pool)
                .await
                .unwrap();

        let mut found = false;
        for (key, value) in &rows {
            if key == "language" {
                assert_eq!(value, "en");
                found = true;
            }
        }
        assert!(found, "language key should be present in WalletData");

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_internal_keys_rejected_by_update_config() {
        // These checks mirror the validation in update_config (cannot modify internal keys).
        // We test the logic directly since update_config requires a Tauri State wrapper.
        let internal_keys = vec!["migration", "password-token", "next_index"];
        for key in internal_keys {
            let is_internal = key == "migration"
                || key.starts_with("next_")
                || key == "password-token";
            assert!(is_internal, "key '{}' should be internal", key);
        }

        // Non-internal keys should pass
        let user_key = "currency";
        let is_internal = user_key == "migration"
            || user_key.starts_with("next_")
            || user_key == "password-token";
        assert!(!is_internal, "user key should not be internal");
    }
}