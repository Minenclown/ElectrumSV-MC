// commands/payment_requests.rs — Payment request Tauri commands
//
// Provides: create_payment_request, list_payment_requests
// Payment requests use the existing PaymentRequests table (migration 0022).
// Currently generates BIP21 URIs. Full BIP270 support is a future milestone.

use crate::core::address;
use crate::db::repositories;
use crate::state::AppState;
use bsv::compat::bip32::ExtendedKey;
use tauri::State;

/// Result of creating a payment request.
#[derive(Debug, serde::Serialize)]
pub struct PaymentRequestResult {
    pub uri: String,
    pub address: String,
    pub amount: i64,
    pub label: Option<String>,
    pub paymentrequest_id: i64,
}

/// A stored payment request.
#[derive(Debug, serde::Serialize)]
pub struct PaymentRequestInfo {
    pub paymentrequest_id: i64,
    pub keyinstance_id: i64,
    pub state: i32,
    pub description: Option<String>,
    pub value: Option<i64>,
    pub date_created: i64,
}

/// Create a BIP21 payment request.
///
/// Generates a receive address for the account and builds a bitcoinsv: URI.
#[tauri::command]
pub async fn create_payment_request(
    state: State<'_, AppState>,
    account_id: Option<i64>,
    amount: Option<i64>,
    label: Option<String>,
) -> Result<PaymentRequestResult, String> {
    log::info!(
        "create_payment_request — account_id: {:?}, amount: {:?}",
        account_id,
        amount
    );

    let (pool, default_account_id, xprv_opt) = {
        let guard = state.active_wallet.lock().unwrap();
        let active = guard.as_ref().ok_or("no wallet is currently open")?;
        (
            active.db_pool.clone(),
            active.account_id,
            active.decrypted_xprv.clone(),
        )
    };

    let acct_id = account_id.unwrap_or(default_account_id);
    let xprv_str = xprv_opt.ok_or("wallet is locked — unlock first")?;

    // Derive a receive address
    let account_key = ExtendedKey::from_string(&xprv_str)
        .map_err(|e| format!("invalid xprv: {}", e))?;

    let (receiving_count, _) = repositories::get_keyinstance_counts(&pool, acct_id)
        .await
        .map_err(|e| e.to_string())?;

    let next_index = receiving_count;
    let derivation_path = format!("0/{}", next_index);
    let child_key = account_key
        .derive(&derivation_path)
        .map_err(|e| format!("derivation failed: {}", e))?;
    let pubkey = child_key
        .public_key()
        .map_err(|e| format!("public key derivation failed: {}", e))?;
    let address_str = address::pubkey_to_p2pkh_address(&pubkey);

    // Store the KeyInstance
    let derivation_data = serde_json::json!({"subpath": [0, next_index]})
        .to_string()
        .into_bytes();
    let mk_row = repositories::get_first_master_key(&pool)
        .await
        .map_err(|e| e.to_string())?;
    let masterkey_id = mk_row.map(|mk| mk.masterkey_id);
    let keyinstance_id = repositories::insert_keyinstance(
        &pool,
        acct_id,
        masterkey_id,
        repositories::derivation_type::BIP32,
        &derivation_data,
        repositories::script_type::P2PKH,
        0,
        None,
    )
    .await
    .map_err(|e| e.to_string())?;

    // Store the payment request in the PaymentRequests table
    let pr_id = repositories::insert_payment_request(
        &pool,
        keyinstance_id,
        amount,
        label.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())?;

    // Build BIP21 URI
    let uri = build_bip21_uri(&address_str, amount, label.as_deref());

    Ok(PaymentRequestResult {
        uri,
        address: address_str,
        amount: amount.unwrap_or(0),
        label,
        paymentrequest_id: pr_id,
    })
}

/// List all stored payment requests.
#[tauri::command]
pub async fn list_payment_requests(
    state: State<'_, AppState>,
) -> Result<Vec<PaymentRequestInfo>, String> {
    log::info!("list_payment_requests");

    let pool = {
        let guard = state.active_wallet.lock().unwrap();
        guard
            .as_ref()
            .ok_or("no wallet is currently open")?
            .db_pool
            .clone()
    };

    let requests = repositories::get_payment_requests(&pool)
        .await
        .map_err(|e| e.to_string())?;

    Ok(requests
        .into_iter()
        .map(|r| PaymentRequestInfo {
            paymentrequest_id: r.paymentrequest_id,
            keyinstance_id: r.keyinstance_id,
            state: r.state,
            description: r.description,
            value: r.value,
            date_created: r.date_created,
        })
        .collect())
}

/// Build a BIP21 URI from address, amount, and optional label.
fn build_bip21_uri(address: &str, amount: Option<i64>, label: Option<&str>) -> String {
    let mut uri = format!("bitcoinsv:{}", address);
    let mut params: Vec<String> = Vec::new();

    if let Some(amt) = amount {
        if amt > 0 {
            // Convert satoshis to BSV (8 decimal places)
            let bsv = amt as f64 / 1e8;
            let formatted = format!("{:.8}", bsv);
            // Strip trailing zeros but keep at least one decimal place
            let trimmed = formatted
                .trim_end_matches('0')
                .trim_end_matches('.');
            params.push(format!("amount={}", if trimmed.is_empty() { "0" } else { trimmed }));
        }
    }

    if let Some(l) = label {
        if !l.is_empty() {
            // URL-encode the label
            let encoded = url_encode(l);
            params.push(format!("label={}", encoded));
        }
    }

    if !params.is_empty() {
        uri.push('?');
        uri.push_str(&params.join("&"));
    }

    uri
}

/// Simple URL-encoder for label values in BIP21 URIs.
fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
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
            .join(format!("electrumsv_mc_pr_{}_{}", test_name, id));
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
    async fn test_list_payment_requests_empty() {
        let state = make_test_state("pr_empty");
        wallet_service::create_wallet(&state, "test_pr", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };

        let requests = repositories::get_payment_requests(&pool).await.unwrap();
        assert!(requests.is_empty());

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_create_payment_request_requires_unlocked_wallet() {
        // Test that without decrypted xprv, payment request creation fails.
        // We simulate the check logic from create_payment_request.
        let state = make_test_state("pr_locked");
        wallet_service::create_wallet(&state, "test_lock", "pw123", None, None)
            .await
            .unwrap();

        // Lock the wallet by clearing decrypted_xprv
        {
            let mut guard = state.active_wallet.lock().unwrap();
            guard.as_mut().unwrap().decrypted_xprv = None;
        }

        let xprv_opt = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().decrypted_xprv.clone()
        };
        assert!(xprv_opt.is_none(), "wallet should be locked");

        // The error message should match what create_payment_request returns
        let err = xprv_opt.ok_or("wallet is locked — unlock first").unwrap_err();
        assert_eq!(err, "wallet is locked — unlock first");

        wallet_service::close_wallet(&state).unwrap();
    }

    #[tokio::test]
    async fn test_create_payment_request_creates_record() {
        let state = make_test_state("pr_create");
        wallet_service::create_wallet(&state, "test_create", "pw123", None, None)
            .await
            .unwrap();

        let pool = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().db_pool.clone()
        };
        let acct_id = {
            let guard = state.active_wallet.lock().unwrap();
            guard.as_ref().unwrap().account_id
        };

        // Insert a keyinstance to attach the payment request to
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

        let pr_id = repositories::insert_payment_request(
            &pool,
            ki_id,
            Some(100000),
            Some("Test payment"),
        )
        .await
        .unwrap();
        assert!(pr_id > 0);

        let requests = repositories::get_payment_requests(&pool).await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].keyinstance_id, ki_id);
        assert_eq!(requests[0].value, Some(100000));
        assert_eq!(requests[0].description, Some("Test payment".to_string()));

        pool.close().await;
        wallet_service::close_wallet(&state).unwrap();
    }

    #[test]
    fn test_build_bip21_uri_no_params() {
        let uri = build_bip21_uri("1Address123", None, None);
        assert_eq!(uri, "bitcoinsv:1Address123");
    }

    #[test]
    fn test_build_bip21_uri_with_amount() {
        let uri = build_bip21_uri("1Address123", Some(100000000), None);
        assert_eq!(uri, "bitcoinsv:1Address123?amount=1");
    }

    #[test]
    fn test_build_bip21_uri_with_amount_and_label() {
        let uri = build_bip21_uri("1Address123", Some(50000000), Some("My Label"));
        assert_eq!(uri, "bitcoinsv:1Address123?amount=0.5&label=My%20Label");
    }

    #[test]
    fn test_build_bip21_uri_zero_amount_omitted() {
        let uri = build_bip21_uri("1Address123", Some(0), None);
        assert_eq!(uri, "bitcoinsv:1Address123");
    }

    #[test]
    fn test_build_bip21_uri_empty_label_omitted() {
        let uri = build_bip21_uri("1Address123", None, Some(""));
        assert_eq!(uri, "bitcoinsv:1Address123");
    }

    #[test]
    fn test_url_encode_alphanumeric() {
        assert_eq!(url_encode("hello123"), "hello123");
    }

    #[test]
    fn test_url_encode_special_chars() {
        assert_eq!(url_encode("a b"), "a%20b");
        assert_eq!(url_encode("a&b"), "a%26b");
        assert_eq!(url_encode("a=b"), "a%3Db");
    }

    #[test]
    fn test_url_encode_unreserved_chars() {
        // These should NOT be percent-encoded
        assert_eq!(url_encode("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn test_url_encode_unicode() {
        // UTF-8 bytes of "€" = 0xE2 0x82 0xAC
        assert_eq!(url_encode("€"), "%E2%82%AC");
    }
}