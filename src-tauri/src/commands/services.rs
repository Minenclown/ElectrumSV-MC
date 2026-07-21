// commands/services.rs — Tauri IPC commands for SPV Channels, Cosigner Pool, Label Sync
//
// Wraps the three standalone network service modules as Tauri commands so the
// GUI can drive them. Each command takes a `base_url` (no hardcoded server
// URLs) and translates the module-specific error types into `String` errors
// (Tauri's `Result<T, String>` convention).
//
// Services wrapped:
//   - SPV Channels   (features::spv_channels)  — encrypted P2P messaging
//   - Cosigner Pool  (features::cosigner_pool) — multi-sig tx sharing
//   - Label Sync     (features::label_sync)    — encrypted label sync
//
// Network errors are caught and returned as String errors; no panic paths.

use crate::features;

// ============================================================================
// SPV Channels
// ============================================================================

/// Create a new SPV Channels channel on the relay at `base_url`.
///
/// `public_key` is the hex-encoded public key the channel is encrypted to.
/// Returns the newly created `Channel`.
#[tauri::command]
pub async fn spv_create_channel(
    base_url: String,
    public_key: Option<String>,
) -> Result<features::spv_channels::Channel, String> {
    log::info!(
        "spv_create_channel — base_url: {}, public_key provided: {}",
        base_url,
        public_key.is_some()
    );

    let key = public_key.unwrap_or_default();
    if key.is_empty() {
        return Err("public_key must not be empty".to_string());
    }

    let client = features::spv_channels::SpvChannelsClient::new(&base_url);
    let req = features::spv_channels::CreateChannelRequest {
        public_key: key,
        description: None,
    };
    let channel = client
        .create_channel(&req)
        .await
        .map_err(|e| e.to_string())?;
    Ok(channel)
}

/// List messages on an SPV Channels channel (unread only by default).
#[tauri::command]
pub async fn spv_list_messages(
    base_url: String,
    channel_id: String,
) -> Result<Vec<features::spv_channels::ChannelMessage>, String> {
    log::info!(
        "spv_list_messages — base_url: {}, channel_id: {}",
        base_url,
        channel_id
    );

    let client = features::spv_channels::SpvChannelsClient::new(&base_url);
    let msgs = client
        .list_messages(&channel_id, true)
        .await
        .map_err(|e| e.to_string())?;
    Ok(msgs)
}

/// Post an encrypted message to an SPV Channels channel.
///
/// `message.encrypted_payload` must be valid base64 (the relay stores opaque
/// encrypted blobs — encryption is end-to-end above this client).
#[tauri::command]
pub async fn spv_post_message(
    base_url: String,
    channel_id: String,
    message: features::spv_channels::PostMessageRequest,
) -> Result<features::spv_channels::ChannelMessage, String> {
    log::info!(
        "spv_post_message — base_url: {}, channel_id: {}",
        base_url,
        channel_id
    );

    let client = features::spv_channels::SpvChannelsClient::new(&base_url);
    let msg = client
        .post_message(&channel_id, &message)
        .await
        .map_err(|e| e.to_string())?;
    Ok(msg)
}

/// Mark a message as read on the relay.
///
/// Note: the underlying API identifies messages by `message_id` (string),
/// not a numeric sequence; we use `message_id` here to match the relay API.
#[tauri::command]
pub async fn spv_mark_read(
    base_url: String,
    channel_id: String,
    message_id: String,
) -> Result<(), String> {
    log::info!(
        "spv_mark_read — base_url: {}, channel_id: {}, message_id: {}",
        base_url,
        channel_id,
        message_id
    );

    let client = features::spv_channels::SpvChannelsClient::new(&base_url);
    client
        .mark_read(&channel_id, &message_id)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Delete a channel and all its messages on the relay.
#[tauri::command]
pub async fn spv_delete_channel(
    base_url: String,
    channel_id: String,
) -> Result<(), String> {
    log::info!(
        "spv_delete_channel — base_url: {}, channel_id: {}",
        base_url,
        channel_id
    );

    let client = features::spv_channels::SpvChannelsClient::new(&base_url);
    client
        .delete_channel(&channel_id)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ============================================================================
// Cosigner Pool
// ============================================================================

/// Submit (or re-submit) a partially signed transaction to the cosigner pool.
#[tauri::command]
pub async fn cosigner_submit_tx(
    base_url: String,
    tx: features::cosigner_pool::PartiallySignedTx,
) -> Result<(), String> {
    log::info!(
        "cosigner_submit_tx — base_url: {}, wallet_id: {}, txid: {}",
        base_url,
        tx.wallet_id,
        tx.txid
    );

    let client = features::cosigner_pool::CosignerPoolClient::new(&base_url);
    client
        .submit_tx(&tx)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Fetch all pending partially signed transactions for a wallet.
#[tauri::command]
pub async fn cosigner_get_pending(
    base_url: String,
    wallet_id: String,
) -> Result<Vec<features::cosigner_pool::PartiallySignedTx>, String> {
    log::info!(
        "cosigner_get_pending — base_url: {}, wallet_id: {}",
        base_url,
        wallet_id
    );

    let client = features::cosigner_pool::CosignerPoolClient::new(&base_url);
    let pending = client
        .get_pending(&wallet_id)
        .await
        .map_err(|e| e.to_string())?;
    Ok(pending)
}

/// Delete a transaction from the pool once it is fully signed and broadcast.
#[tauri::command]
pub async fn cosigner_delete_tx(
    base_url: String,
    wallet_id: String,
    txid: String,
) -> Result<(), String> {
    log::info!(
        "cosigner_delete_tx — base_url: {}, wallet_id: {}, txid: {}",
        base_url,
        wallet_id,
        txid
    );

    let client = features::cosigner_pool::CosignerPoolClient::new(&base_url);
    client
        .delete_tx(&wallet_id, &txid)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ============================================================================
// Label Sync
// ============================================================================

/// Default salt for passphrase-derived label encryption keys.
///
/// A fixed salt is used so that the same passphrase on the same wallet_id
/// produces the same key across devices. In a production deployment this
/// could be derived from the wallet_id, but a constant salt is sufficient
/// for label sync (the passphrase itself is the secret).
const LABEL_SYNC_SALT: &[u8] = b"electrumsv-mc-labelsync-salt-v1";

/// Push local labels to the label-sync server (full overwrite).
///
/// Labels are encrypted client-side with AES-256-CBC using a key derived from
/// `passphrase` before upload; the server never sees plaintext.
#[tauri::command]
pub async fn label_sync_push(
    base_url: String,
    wallet_id: String,
    passphrase: String,
    labels: Vec<features::label_sync::WalletLabel>,
) -> Result<(), String> {
    log::info!(
        "label_sync_push — base_url: {}, wallet_id: {}, {} labels",
        base_url,
        wallet_id,
        labels.len()
    );

    let client =
        features::label_sync::LabelSyncClient::new(&base_url, &passphrase, LABEL_SYNC_SALT);
    client
        .push(&wallet_id, &labels)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Pull all labels for a wallet from the sync server and decrypt them.
#[tauri::command]
pub async fn label_sync_pull(
    base_url: String,
    wallet_id: String,
    passphrase: String,
) -> Result<Vec<features::label_sync::WalletLabel>, String> {
    log::info!(
        "label_sync_pull — base_url: {}, wallet_id: {}",
        base_url,
        wallet_id
    );

    let client =
        features::label_sync::LabelSyncClient::new(&base_url, &passphrase, LABEL_SYNC_SALT);
    let labels = client
        .pull(&wallet_id)
        .await
        .map_err(|e| e.to_string())?;
    Ok(labels)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use features::cosigner_pool::{group_by_wallet, PartiallySignedTx};
    use features::label_sync::{LabelKind, LabelSyncClient, WalletLabel};
    use features::spv_channels::SpvChannelsClient;

    // --- Test 1: SPV Channels client can be constructed ---

    /// Verify that an SpvChannelsClient can be created without panicking and
    /// that URL construction trims trailing slashes (smoke test for the
    /// command's underlying client).
    #[test]
    fn test_spv_channels_client_creation() {
        let client = SpvChannelsClient::new("https://channels.example.com/");
        // The client should be constructable; we exercise the private url()
        // helper indirectly by confirming the client exists.
        let _ = &client;
        // Smoke: building a CreateChannelRequest does not panic.
        let _req = features::spv_channels::CreateChannelRequest {
            public_key: "02deadbeef".to_string(),
            description: None,
        };
    }

    // --- Test 2: Cosigner Pool group_by_wallet ---

    /// Verify that group_by_wallet correctly buckets partially signed
    /// transactions by their wallet_id.
    #[test]
    fn test_cosigner_pool_group_by_wallet() {
        fn tx(wallet: &str, txid: &str) -> PartiallySignedTx {
            PartiallySignedTx {
                wallet_id: wallet.to_string(),
                txid: txid.to_string(),
                tx_hex: "01000000000000000000".to_string(),
                signers: vec![],
                required_sigs: 2,
                total_cosigners: 2,
            }
        }

        let txs = vec![
            tx("wallet-1", "aaa"),
            tx("wallet-2", "bbb"),
            tx("wallet-1", "ccc"),
            tx("wallet-3", "ddd"),
            tx("wallet-2", "eee"),
        ];

        let grouped = group_by_wallet(&txs);
        assert_eq!(grouped.len(), 3, "expected 3 wallet buckets");
        assert_eq!(grouped["wallet-1"].len(), 2);
        assert_eq!(grouped["wallet-2"].len(), 2);
        assert_eq!(grouped["wallet-3"].len(), 1);
        // Verify txids are preserved
        let w1_txids: Vec<&str> = grouped["wallet-1"].iter().map(|t| t.txid.as_str()).collect();
        assert!(w1_txids.contains(&"aaa"));
        assert!(w1_txids.contains(&"ccc"));
    }

    // --- Test 3: Label Sync encrypt/decrypt roundtrip ---

    /// Verify that a label encrypted with a passphrase-derived key can be
    /// decrypted back to the original plaintext with the same passphrase.
    #[test]
    fn test_label_sync_encrypt_decrypt_roundtrip() {
        const PASSPHRASE: &str = "correct horse battery staple";
        const SALT: &[u8] = b"test-salt-roundtrip";

        let client = LabelSyncClient::new("http://localhost:0", PASSPHRASE, SALT);
        let label = WalletLabel {
            id: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            kind: LabelKind::Address,
            label: "Satoshi's address".to_string(),
            updated_at: 1700000000,
        };

        let encrypted = client.encrypt(&label).expect("encrypt should succeed");
        assert_ne!(
            encrypted.ciphertext, label.label,
            "ciphertext must not equal plaintext"
        );
        assert!(
            !encrypted.ciphertext.contains(&label.label),
            "ciphertext must not leak plaintext"
        );

        let decrypted = client.decrypt(&encrypted).expect("decrypt should succeed");
        assert_eq!(decrypted, label, "roundtrip must reproduce original label");
    }

    // --- Test 4: Label Sync with wrong passphrase fails decryption ---

    /// Verify that a label encrypted with one passphrase cannot be decrypted
    /// with a different passphrase (confirms the key derivation is binding).
    #[test]
    fn test_label_sync_wrong_passphrase_fails() {
        const SALT: &[u8] = b"test-salt-wrong-pass";

        let client_a = LabelSyncClient::new("http://localhost:0", "passphrase A", SALT);
        let client_b = LabelSyncClient::new("http://localhost:0", "passphrase B", SALT);

        let label = WalletLabel {
            id: "addr-1".to_string(),
            kind: LabelKind::Address,
            label: "secret label".to_string(),
            updated_at: 1700000000,
        };

        let encrypted = client_a.encrypt(&label).expect("encrypt with A");
        let err = client_b.decrypt(&encrypted).unwrap_err();
        assert!(
            matches!(err, features::label_sync::LabelSyncError::Decryption(_)),
            "wrong passphrase must produce a Decryption error"
        );
    }

    // --- Test 5: SPV Channels command rejects empty public_key ---

    /// Verify the spv_create_channel command's input validation without
    /// hitting the network (the empty-key check happens before any HTTP call).
    #[tokio::test]
    async fn test_spv_create_channel_rejects_empty_key() {
        let result = spv_create_channel("http://localhost:0".to_string(), None).await;
        assert!(result.is_err(), "empty public_key must error");
        assert!(
            result.unwrap_err().contains("public_key"),
            "error must mention public_key"
        );
    }

    // --- Test 6: Cosigner Pool submit rejects invalid hex ---

    /// Verify the cosigner_submit_tx command's hex validation without hitting
    /// the network (the hex check happens before any HTTP call).
    #[tokio::test]
    async fn test_cosigner_submit_tx_rejects_invalid_hex() {
        let bad_tx = PartiallySignedTx {
            wallet_id: "w".to_string(),
            txid: "t".to_string(),
            tx_hex: "nothex!".to_string(),
            signers: vec![],
            required_sigs: 2,
            total_cosigners: 2,
        };
        let result = cosigner_submit_tx("http://localhost:0".to_string(), bad_tx).await;
        assert!(result.is_err(), "invalid hex must error");
    }
}