// commands/contacts.rs — Contact CRUD Tauri commands
//
// Provides: get_contacts, add_contact, update_contact, delete_contact
// Contacts are stored per-wallet in the Contacts/ContactIdentities tables (migration 0029).

use crate::db::repositories;
use crate::state::AppState;
use tauri::State;

/// Identity system constants.
pub const IDENTITY_SYSTEM_ONCHAIN: i64 = 1;
pub const IDENTITY_SYSTEM_PAYMAIL: i64 = 2;

// ============================================================================
// Response types
// ============================================================================

#[derive(Debug, serde::Serialize)]
pub struct ContactIdentityInfo {
    pub identity_id: String,
    pub system: String,
    pub system_data: String,
    pub last_verified: Option<i64>,
}

#[derive(Debug, serde::Serialize)]
pub struct ContactInfo {
    pub contact_id: i64,
    pub label: String,
    pub identities: Vec<ContactIdentityInfo>,
}

// ============================================================================
// Helper
// ============================================================================

fn system_id_to_name(system_id: i64) -> String {
    match system_id {
        IDENTITY_SYSTEM_ONCHAIN => "OnChain".to_string(),
        IDENTITY_SYSTEM_PAYMAIL => "Paymail".to_string(),
        _ => format!("Unknown({})", system_id),
    }
}

fn system_name_to_id(name: &str) -> i64 {
    match name.trim() {
        "OnChain" | "onchain" => IDENTITY_SYSTEM_ONCHAIN,
        "Paymail" | "paymail" => IDENTITY_SYSTEM_PAYMAIL,
        _ => IDENTITY_SYSTEM_ONCHAIN, // default
    }
}

async fn load_contact_identities(
    pool: &sqlx::SqlitePool,
    contact_id: i64,
) -> Result<Vec<ContactIdentityInfo>, String> {
    let identities = repositories::get_contact_identities(pool, contact_id)
        .await
        .map_err(|e| e.to_string())?;

    Ok(identities
        .into_iter()
        .map(|id| ContactIdentityInfo {
            identity_id: hex::encode(&id.identity_id),
            system: system_id_to_name(id.system_id),
            system_data: id.system_data,
            last_verified: id.last_verified,
        })
        .collect())
}

// ============================================================================
// Commands
// ============================================================================

/// Get all contacts for the active wallet.
#[tauri::command]
pub async fn get_contacts(state: State<'_, AppState>) -> Result<Vec<ContactInfo>, String> {
    log::info!("get_contacts");

    let pool = {
        let guard = state.active_wallet.lock().unwrap();
        guard
            .as_ref()
            .ok_or("no wallet is currently open")?
            .db_pool
            .clone()
    };

    let contacts = repositories::get_all_contacts(&pool)
        .await
        .map_err(|e| e.to_string())?;

    let mut result = Vec::new();
    for c in contacts {
        let identities = load_contact_identities(&pool, c.contact_id).await?;
        result.push(ContactInfo {
            contact_id: c.contact_id,
            label: c.label,
            identities,
        });
    }

    Ok(result)
}

/// Add a new contact.
///
/// system: "OnChain" or "Paymail"
/// system_data: hex pubkey for OnChain, paymail handle for Paymail
#[tauri::command]
pub async fn add_contact(
    state: State<'_, AppState>,
    label: String,
    system: String,
    system_data: String,
) -> Result<ContactInfo, String> {
    log::info!("add_contact — label: {}, system: {}", label, system);

    let label = label.trim().to_string();
    if label.is_empty() {
        return Err("label must not be empty".to_string());
    }
    if system_data.is_empty() {
        return Err("system_data must not be empty".to_string());
    }

    let pool = {
        let guard = state.active_wallet.lock().unwrap();
        guard
            .as_ref()
            .ok_or("no wallet is currently open")?
            .db_pool
            .clone()
    };

    // Check if label is already in use
    let in_use = repositories::check_label_in_use(&pool, &label)
        .await
        .map_err(|e| e.to_string())?;
    if in_use {
        return Err(format!("label '{}' is already in use", label));
    }

    let system_id = system_name_to_id(&system);

    let contact_id = repositories::insert_contact(&pool, &label)
        .await
        .map_err(|e| e.to_string())?;

    repositories::insert_contact_identity(&pool, contact_id, system_id, &system_data)
        .await
        .map_err(|e| e.to_string())?;

    let identities = load_contact_identities(&pool, contact_id).await?;

    Ok(ContactInfo {
        contact_id,
        label,
        identities,
    })
}

/// Update a contact's label.
#[tauri::command]
pub async fn update_contact(
    state: State<'_, AppState>,
    contact_id: i64,
    label: String,
) -> Result<(), String> {
    log::info!("update_contact — contact_id: {}, label: {}", contact_id, label);

    let label = label.trim().to_string();
    if label.is_empty() {
        return Err("label must not be empty".to_string());
    }

    let pool = {
        let guard = state.active_wallet.lock().unwrap();
        guard
            .as_ref()
            .ok_or("no wallet is currently open")?
            .db_pool
            .clone()
    };

    // Check contact exists
    let contact = repositories::get_contact_by_id(&pool, contact_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("contact {} not found", contact_id))?;

    // Check if new label is already in use by a different contact
    if contact.label != label {
        let in_use = repositories::check_label_in_use(&pool, &label)
            .await
            .map_err(|e| e.to_string())?;
        if in_use {
            return Err(format!("label '{}' is already in use", label));
        }
    }

    repositories::update_contact_label(&pool, contact_id, &label)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Delete a contact by ID.
#[tauri::command]
pub async fn delete_contact(
    state: State<'_, AppState>,
    contact_id: i64,
) -> Result<(), String> {
    log::info!("delete_contact — contact_id: {}", contact_id);

    let pool = {
        let guard = state.active_wallet.lock().unwrap();
        guard
            .as_ref()
            .ok_or("no wallet is currently open")?
            .db_pool
            .clone()
    };

    // Check contact exists
    repositories::get_contact_by_id(&pool, contact_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("contact {} not found", contact_id))?;

    repositories::delete_contact(&pool, contact_id)
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
        let temp_dir = std::env::temp_dir().join(format!(
            "electrumsv_mc_contacts_{}_{}",
            test_name, id
        ));
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
    async fn test_get_contacts_empty_wallet() {
        let state = make_test_state("contacts_empty");
        wallet_service::create_wallet(&state, "test_contacts", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        let contacts = repositories::get_all_contacts(&pool).await.unwrap();
        assert!(contacts.is_empty());

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_add_contact_and_identity() {
        let state = make_test_state("contacts_add");
        wallet_service::create_wallet(&state, "test_add", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        let label = "Alice";
        let contact_id = repositories::insert_contact(&pool, label)
            .await
            .unwrap();
        assert!(contact_id > 0);

        let system_data = "02deadbeef";
        repositories::insert_contact_identity(
            &pool,
            contact_id,
            IDENTITY_SYSTEM_ONCHAIN,
            system_data,
        )
        .await
        .unwrap();

        // Verify contact exists
        let contact = repositories::get_contact_by_id(&pool, contact_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(contact.label, label);

        // Verify identity exists
        let identities = repositories::get_contact_identities(&pool, contact_id)
            .await
            .unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].system_id, IDENTITY_SYSTEM_ONCHAIN);
        assert_eq!(identities[0].system_data, system_data);

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_duplicate_label_rejected() {
        let state = make_test_state("contacts_dup");
        wallet_service::create_wallet(&state, "test_dup", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        repositories::insert_contact(&pool, "Bob")
            .await
            .unwrap();

        let in_use = repositories::check_label_in_use(&pool, "Bob")
            .await
            .unwrap();
        assert!(in_use, "label should be in use");

        let not_in_use = repositories::check_label_in_use(&pool, "Carol")
            .await
            .unwrap();
        assert!(!not_in_use, "unused label should not be in use");

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_update_contact_label() {
        let state = make_test_state("contacts_update");
        wallet_service::create_wallet(&state, "test_upd", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        let contact_id = repositories::insert_contact(&pool, "OldLabel")
            .await
            .unwrap();
        repositories::update_contact_label(&pool, contact_id, "NewLabel")
            .await
            .unwrap();

        let contact = repositories::get_contact_by_id(&pool, contact_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(contact.label, "NewLabel");

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_delete_contact() {
        let state = make_test_state("contacts_delete");
        wallet_service::create_wallet(&state, "test_del", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        let contact_id = repositories::insert_contact(&pool, "ToDelete")
            .await
            .unwrap();
        repositories::insert_contact_identity(
            &pool,
            contact_id,
            IDENTITY_SYSTEM_PAYMAIL,
            "alice@example.com",
        )
        .await
        .unwrap();

        repositories::delete_contact(&pool, contact_id).await.unwrap();

        let contact = repositories::get_contact_by_id(&pool, contact_id)
            .await
            .unwrap();
        assert!(contact.is_none(), "contact should be deleted");

        // Identities should also be gone (cascade)
        let identities = repositories::get_contact_identities(&pool, contact_id)
            .await
            .unwrap();
        assert!(identities.is_empty());

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_get_contact_by_id_not_found() {
        let state = make_test_state("contacts_byid");
        wallet_service::create_wallet(&state, "test_byid", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        let contact = repositories::get_contact_by_id(&pool, 99999)
            .await
            .unwrap();
        assert!(contact.is_none());

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_system_name_to_id_default() {
        // Unknown system name defaults to OnChain
        let id = system_name_to_id("unknown");
        assert_eq!(id, IDENTITY_SYSTEM_ONCHAIN);

        let onchain = system_name_to_id("OnChain");
        assert_eq!(onchain, IDENTITY_SYSTEM_ONCHAIN);

        let paymail = system_name_to_id("Paymail");
        assert_eq!(paymail, IDENTITY_SYSTEM_PAYMAIL);
    }

    #[tokio::test]
    async fn test_system_id_to_name() {
        assert_eq!(system_id_to_name(IDENTITY_SYSTEM_ONCHAIN), "OnChain");
        assert_eq!(system_id_to_name(IDENTITY_SYSTEM_PAYMAIL), "Paymail");
        assert_eq!(system_id_to_name(99), "Unknown(99)");
    }
}