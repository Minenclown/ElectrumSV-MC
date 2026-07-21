// commands/events.rs — Tauri event emission for ElectrumX notifications
//
// Spawns a background task that subscribes to the ElectrumXClient's notification
// broadcast channel and emits Tauri events to the frontend:
//   - "new_block"         — when blockchain.headers.subscribe fires
//   - "balance_changed"   — when blockchain.scripthash.subscribe fires
//
// The frontend listens to these events via Tauri's `listen()` API.
// This replaces the Python SSE (Server-Sent Events) approach.

use crate::network::electrumx::{ElectrumNotification, ElectrumXClient};
use tauri::{AppHandle, Emitter};

/// Event payload for "new_block" — sent to the frontend when a new block
/// header notification arrives from the ElectrumX server.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NewBlockEvent {
    /// Block height of the new block.
    pub height: u64,
    /// Raw 80-byte block header in hex.
    pub header_hex: String,
}

/// Event payload for "balance_changed" — sent to the frontend when a
/// scripthash status changes (new transaction or balance update).
#[derive(Debug, Clone, serde::Serialize)]
pub struct BalanceChangedEvent {
    /// The ElectrumX scripthash that changed.
    pub scripthash: String,
    /// New status string (changes when balance/history changes).
    pub status: String,
}

/// Start forwarding ElectrumX notifications to Tauri frontend events.
///
/// This spawns a background tokio task that:
/// 1. Subscribes to the ElectrumXClient's notification broadcast channel
/// 2. For each notification, emits the appropriate Tauri event
///
/// The task runs until the client disconnects (channel closes).
/// Call this after a successful `connect_server`.
pub fn start_notification_forwarder(app: AppHandle, client: ElectrumXClient) {
    let mut rx = client.subscribe_notifications();

    tokio::spawn(async move {
        log::info!("ElectrumX notification forwarder started");

        loop {
            match rx.recv().await {
                Ok(notification) => {
                    let (event_name, payload) = match &notification {
                        ElectrumNotification::NewBlock { height, header_hex } => {
                            log::info!("ElectrumX notification: new_block height={height}");
                            (
                                "new_block",
                                serde_json::to_value(NewBlockEvent {
                                    height: *height,
                                    header_hex: header_hex.clone(),
                                })
                                .ok(),
                            )
                        }
                        ElectrumNotification::ScripthashStatus { scripthash, status } => {
                            log::debug!(
                                "ElectrumX notification: scripthash status changed: {scripthash}"
                            );
                            (
                                "balance_changed",
                                serde_json::to_value(BalanceChangedEvent {
                                    scripthash: scripthash.clone(),
                                    status: status.clone(),
                                })
                                .ok(),
                            )
                        }
                    };

                    if let Some(payload) = payload {
                        if let Err(e) = app.emit(event_name, payload) {
                            log::warn!("Failed to emit Tauri event '{event_name}': {e}");
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    log::warn!(
                        "ElectrumX notification forwarder: lagged, missed {n} notifications"
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    log::info!("ElectrumX notification forwarder: channel closed, stopping");
                    break;
                }
            }
        }
    });
}
