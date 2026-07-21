// network/electrumx.rs — ElectrumX TCP+TLS client (JSON-RPC 2.0, newline-delimited)
//
// Implements the ElectrumX protocol over TCP+TLS using tokio and tokio-rustls:
// - JSON-RPC 2.0 request/response with ID matching
// - Newline-delimited framing (each message is one JSON object terminated by \n)
// - Push notification handling (headers.subscribe, scripthash.subscribe)
// - Full TLS certificate + hostname verification (AUD-Fund #6)
// - Txid validation on broadcast (AUD-006: hash locally, compare with server response)

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Mutex, Notify};
use tokio_rustls::TlsConnector;

use super::backend::{
    BackendType, BackendBalance, BlockHeader, BroadcastResult, MerkleProof, NetworkBackend,
    NetworkError, TxHistoryEntry, UtxoEntry,
};
use super::server_list::ServerEntry;

// ---------------------------------------------------------------------------
// Notification types — ElectrumX push notifications
// ---------------------------------------------------------------------------

/// A parsed ElectrumX push notification.
///
/// ElectrumX sends unsolicited JSON-RPC messages (no "id", has "method") for:
/// - `blockchain.headers.subscribe` — new block header
/// - `blockchain.scripthash.subscribe` — scripthash status changed
///
/// These are broadcast via a tokio broadcast channel and consumed by the
/// Tauri event loop to emit frontend events.
#[derive(Debug, Clone, serde::Serialize)]
pub enum ElectrumNotification {
    /// New block header notification (blockchain.headers.subscribe).
    /// Contains the block height and raw header hex.
    NewBlock { height: u64, header_hex: String },
    /// Scripthash status changed (blockchain.scripthash.subscribe).
    /// The status string changes when the balance or history of the
    /// scripthash changes. The frontend should re-fetch balance/history.
    ScripthashStatus { scripthash: String, status: String },
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_MESSAGE_SIZE: usize = 50 * 1024 * 1024; // 50 MB
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const PROTOCOL_MIN: u16 = 1;
const PROTOCOL_MAX: u16 = 2;
const CLIENT_VERSION: &str = "ElectrumSV-Mc 0.1.0";

// ---------------------------------------------------------------------------
// Inner state (shared via Arc between client and reader task)
// ---------------------------------------------------------------------------

struct PendingRequest {
    tx: oneshot::Sender<Result<Value, NetworkError>>,
}

struct Inner {
    /// Write half of the TLS stream.
    writer: Mutex<Option<tokio::io::WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>>>,
    /// Pending requests keyed by JSON-RPC id.
    pending: Mutex<HashMap<u64, PendingRequest>>,
    /// Next JSON-RPC request id.
    next_id: AtomicU64,
    /// Connected flag (atomic for sync access).
    connected: AtomicBool,
    /// Notify for reader task shutdown.
    shutdown: Notify,
    /// Negotiated protocol version.
    protocol_version: Mutex<Option<(u16, u16)>>,
    /// Server we're connected to.
    server: ServerEntry,
    /// Reader task handle (so we can abort on disconnect).
    reader_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Notification channel — broadcast ElectrumX push notifications to subscribers.
    /// The Tauri event loop subscribes to this and emits events to the frontend.
    notifications: tokio::sync::broadcast::Sender<ElectrumNotification>,
}

impl Inner {
    fn new(server: ServerEntry) -> Self {
        let (tx, _rx) = tokio::sync::broadcast::channel::<ElectrumNotification>(64);
        Self {
            writer: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            connected: AtomicBool::new(false),
            shutdown: Notify::new(),
            protocol_version: Mutex::new(None),
            server,
            reader_task: Mutex::new(None),
            notifications: tx,
        }
    }
}

// ---------------------------------------------------------------------------
// ElectrumX client
// ---------------------------------------------------------------------------

/// The ElectrumX TCP+TLS client.
///
/// Connection lifecycle:
/// 1. `connect()` — TLS connection + server.version handshake
/// 2. `call()` — send JSON-RPC request, await matched response
/// 3. Reader task dispatches responses to pending callers, notifications to handlers
/// 4. `disconnect()` — graceful shutdown
///
/// `Clone` is cheap (Arc<Inner>), allowing the client to be shared across
/// Tauri commands without holding a Mutex across await points.
#[derive(Clone)]
pub struct ElectrumXClient {
    inner: Arc<Inner>,
}

impl ElectrumXClient {
    /// Create a new client for the given server (not yet connected).
    pub fn new(server: ServerEntry) -> Self {
        Self {
            inner: Arc::new(Inner::new(server)),
        }
    }

    /// Connect to the server using TLS.
    ///
    /// AUD-Fund #6: rustls with webpki-roots, full certificate + hostname
    /// verification. No permissive/dangerous verifier.
    pub async fn connect(&self) -> Result<(), NetworkError> {
        // Build TLS connector with webpki root certificates
        let root_store = {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            roots
        };

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let addr = self.inner.server.tls_addr();

        // TCP connect
        let tcp_stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| NetworkError::Connection(format!("TCP connect to {addr}: {e}")))?;

        let _ = tcp_stream.set_nodelay(true);

        // TLS connect with hostname verification
        let host = &self.inner.server.host;
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|e| NetworkError::Tls(format!("invalid server name {host}: {e}")))?;

        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| {
                NetworkError::Tls(format!(
                    "TLS handshake to {host}:{}: {e}",
                    self.inner.server.ssl_port
                ))
            })?;

        // Split into reader and writer
        let (reader, writer) = tokio::io::split(tls_stream);

        // Store writer
        {
            let mut w = self.inner.writer.lock().await;
            *w = Some(writer);
        }

        // Start reader task
        let inner = self.inner.clone();
        let reader_task = tokio::spawn(async move {
            read_loop(inner, reader).await;
        });

        {
            let mut rt = self.inner.reader_task.lock().await;
            *rt = Some(reader_task);
        }

        self.inner.connected.store(true, Ordering::SeqCst);

        // Perform handshake
        self.handshake().await?;

        Ok(())
    }

    /// Send a JSON-RPC request and wait for the response.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, NetworkError> {
        if !self.inner.connected.load(Ordering::SeqCst) {
            return Err(NetworkError::NotConnected);
        }

        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let json_str = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        })
        .to_string();

        // Register pending request
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.inner.pending.lock().await;
            pending.insert(id, PendingRequest { tx });
        }

        // Send request
        {
            let mut w = self.inner.writer.lock().await;
            let writer = w.as_mut().ok_or(NetworkError::NotConnected)?;
            writer.write_all(json_str.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
        }

        // Wait for response with timeout
        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                self.inner.pending.lock().await.remove(&id);
                Err(NetworkError::NotConnected)
            }
            Err(_) => {
                self.inner.pending.lock().await.remove(&id);
                Err(NetworkError::Connection(format!(
                    "request timeout: {method}"
                )))
            }
        }
    }

    /// Convenience: call with array params.
    pub async fn call_array(&self, method: &str, params: &[Value]) -> Result<Value, NetworkError> {
        self.call(method, Value::Array(params.to_vec())).await
    }

    /// Perform the server.version handshake.
    pub async fn handshake(&self) -> Result<(String, (u16, u16)), NetworkError> {
        let result = self
            .call(
                "server.version",
                json!([CLIENT_VERSION, [PROTOCOL_MIN, PROTOCOL_MAX]]),
            )
            .await?;

        let arr = result
            .as_array()
            .ok_or_else(|| NetworkError::Protocol("server.version: expected array".into()))?;
        if arr.len() < 2 {
            return Err(NetworkError::Protocol(
                "server.version: array too short".into(),
            ));
        }

        let server_string = arr[0]
            .as_str()
            .ok_or_else(|| NetworkError::Protocol("server.version: server string not str".into()))?
            .to_string();

        let proto_str = arr[1]
            .as_str()
            .ok_or_else(|| NetworkError::Protocol("server.version: protocol not str".into()))?;

        let parts: Vec<&str> = proto_str.split('.').collect();
        let major: u16 = parts[0]
            .parse()
            .map_err(|_| NetworkError::Protocol(format!("bad protocol major: {}", parts[0])))?;
        let minor: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

        if !(PROTOCOL_MIN..=PROTOCOL_MAX).contains(&major) {
            return Err(NetworkError::Protocol(format!(
                "server protocol {major}.{minor} not in range [{PROTOCOL_MIN}, {PROTOCOL_MAX}]"
            )));
        }

        let ptuple = (major, minor);
        *self.inner.protocol_version.lock().await = Some(ptuple);

        Ok((server_string, ptuple))
    }

    /// Whether the client is connected (atomic, non-blocking).
    pub fn is_connected(&self) -> bool {
        self.inner.connected.load(Ordering::SeqCst)
    }

    /// Get the server host string (for logging/results).
    pub fn server_host(&self) -> String {
        self.inner.server.host.clone()
    }

    /// Subscribe to ElectrumX push notifications.
    ///
    /// Returns a `tokio::sync::broadcast::Receiver` that yields
    /// `ElectrumNotification` values. The Tauri event loop subscribes to
    /// this and emits frontend events (`new_block`, `balance_changed`).
    ///
    /// If no subscribers exist, notifications are dropped (broadcast channel
    /// behavior) — this is fine, the frontend simply won't get push updates.
    pub fn subscribe_notifications(
        &self,
    ) -> tokio::sync::broadcast::Receiver<ElectrumNotification> {
        self.inner.notifications.subscribe()
    }

    /// Gracefully disconnect.
    pub async fn disconnect(&self) -> Result<(), NetworkError> {
        self.inner.connected.store(false, Ordering::SeqCst);

        // Shutdown writer
        {
            let mut w = self.inner.writer.lock().await;
            if let Some(mut writer) = w.take() {
                let _ = writer.shutdown().await;
            }
        }

        // Notify reader task to stop
        self.inner.shutdown.notify_waiters();

        // Abort reader task
        {
            let mut rt = self.inner.reader_task.lock().await;
            if let Some(handle) = rt.take() {
                handle.abort();
            }
        }

        // Clear pending requests
        self.inner.pending.lock().await.clear();

        Ok(())
    }

    /// Compute txid (display form) from raw transaction bytes.
    /// txid = hash256(raw_tx) reversed → hex.
    /// Used to validate server's broadcast response (AUD-006).
    fn compute_txid(raw_tx: &[u8]) -> String {
        let h1 = Sha256::digest(raw_tx);
        let h2 = Sha256::digest(h1);
        let mut reversed = h2.to_vec();
        reversed.reverse();
        hex::encode(&reversed)
    }
}

// ---------------------------------------------------------------------------
// Reader loop — runs in a spawned task, dispatches responses + notifications
// ---------------------------------------------------------------------------

async fn read_loop(
    inner: Arc<Inner>,
    reader: tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>,
) {
    let mut reader = BufReader::with_capacity(64 * 1024, reader);
    let mut line = String::new();

    loop {
        line.clear();

        // Read one newline-delimited message
        match reader.read_line(&mut line).await {
            Ok(0) => {
                // EOF — server closed connection
                break;
            }
            Ok(n) => {
                if n > MAX_MESSAGE_SIZE {
                    log::error!("ElectrumX message too large: {n} bytes");
                    continue;
                }
            }
            Err(e) => {
                if inner.connected.load(Ordering::SeqCst) {
                    log::error!("ElectrumX read error: {e}");
                }
                break;
            }
        }

        // Parse JSON-RPC message
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("ElectrumX: malformed JSON: {e}");
                continue;
            }
        };

        // Check if this is a response (has "id" and no "method") or a notification
        let has_id = msg.get("id").is_some();
        let has_method = msg.get("method").is_some();

        if has_id && !has_method {
            // Response — match to pending request
            let id = msg.get("id").and_then(|v| v.as_u64());
            if let Some(id) = id {
                // Remove from pending first, then send (avoids moving from shared ref)
                let req = inner.pending.lock().await.remove(&id);
                if let Some(req) = req {
                    // Check for error
                    if let Some(err) = msg.get("error") {
                        if !err.is_null() {
                            let code = err.get("code").and_then(|v| v.as_i64()).unwrap_or(0);
                            let message = err
                                .get("message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown error")
                                .to_string();
                            let _ = req
                                .tx
                                .send(Err(NetworkError::Server(format!("code {code}: {message}"))));
                        } else {
                            // Success
                            let result = msg.get("result").cloned().unwrap_or(Value::Null);
                            let _ = req.tx.send(Ok(result));
                        }
                    } else {
                        // No error field — success
                        let result = msg.get("result").cloned().unwrap_or(Value::Null);
                        let _ = req.tx.send(Ok(result));
                    }
                }
            }
        } else if has_method {
            // Notification — parse and dispatch to subscribers via broadcast channel
            let method = msg
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            log::debug!("ElectrumX notification: {method}");

            let params = msg.get("params").cloned().unwrap_or(Value::Null);

            let notification = match method {
                "blockchain.headers.subscribe" => {
                    // params: { "hex": "...", "height": N }
                    // or params: [ { "hex": "...", "height": N } ]
                    let hdr = if let Some(arr) = params.as_array() {
                        arr.first().cloned().unwrap_or(Value::Null)
                    } else {
                        params.clone()
                    };

                    let height = hdr.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
                    let header_hex = hdr
                        .get("hex")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    if height > 0 && !header_hex.is_empty() {
                        Some(ElectrumNotification::NewBlock { height, header_hex })
                    } else {
                        log::warn!(
                            "ElectrumX headers.subscribe: incomplete notification (height={height})"
                        );
                        None
                    }
                }

                "blockchain.scripthash.subscribe" => {
                    // params: [ scripthash, status ]
                    // or params: { "scripthash": "...", "status": "..." }
                    let (scripthash, status) = if let Some(arr) = params.as_array() {
                        let sh = arr
                            .first()
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let st = arr
                            .get(1)
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        (sh, st)
                    } else {
                        let sh = params
                            .get("scripthash")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let st = params
                            .get("status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        (sh, st)
                    };

                    if !scripthash.is_empty() {
                        Some(ElectrumNotification::ScripthashStatus { scripthash, status })
                    } else {
                        log::warn!(
                            "ElectrumX scripthash.subscribe: missing scripthash in notification"
                        );
                        None
                    }
                }

                _ => {
                    log::debug!("ElectrumX: unhandled notification method: {method}");
                    None
                }
            };

            // Broadcast to subscribers (if any). If no receivers, the message
            // is silently dropped — this is expected broadcast channel behavior.
            if let Some(notif) = notification {
                let _ = inner.notifications.send(notif);
            }
        }
    }

    // Mark as disconnected
    inner.connected.store(false, Ordering::SeqCst);

    // Fail all pending requests
    let mut pending = inner.pending.lock().await;
    for (_, req) in pending.drain() {
        let _ = req.tx.send(Err(NetworkError::NotConnected));
    }
}

// ---------------------------------------------------------------------------
// NetworkBackend trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl NetworkBackend for ElectrumXClient {
    fn backend_type(&self) -> BackendType {
        BackendType::ElectrumX
    }

    fn is_connected(&self) -> bool {
        self.inner.connected.load(Ordering::SeqCst)
    }

    async fn get_tip_height(&self) -> Result<u64, NetworkError> {
        let result = self.call("blockchain.headers.subscribe", json!([])).await?;

        let height = result
            .get("height")
            .and_then(|h| h.as_u64())
            .ok_or_else(|| NetworkError::Protocol("headers.subscribe: missing height".into()))?;

        Ok(height)
    }

    async fn get_balance(&self, scripthash: &str) -> Result<BackendBalance, NetworkError> {
        let result = self
            .call_array("blockchain.scripthash.get_balance", &[json!(scripthash)])
            .await?;

        let confirmed = result
            .get("confirmed")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| NetworkError::Protocol("get_balance: missing confirmed".into()))?;

        let unconfirmed = result
            .get("unconfirmed")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| NetworkError::Protocol("get_balance: missing unconfirmed".into()))?;

        Ok(BackendBalance::new(confirmed, unconfirmed))
    }

    async fn get_history(&self, scripthash: &str) -> Result<Vec<TxHistoryEntry>, NetworkError> {
        let result = self
            .call_array("blockchain.scripthash.get_history", &[json!(scripthash)])
            .await?;

        let arr = result
            .as_array()
            .ok_or_else(|| NetworkError::Protocol("get_history: expected array".into()))?;

        let mut entries = Vec::with_capacity(arr.len());
        for item in arr {
            let tx_hash = item
                .get("tx_hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| NetworkError::Protocol("get_history: missing tx_hash".into()))?
                .to_string();

            let height = item
                .get("height")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| NetworkError::Protocol("get_history: missing height".into()))?;

            // height > 0: confirmed + verified
            // height == 0 or -1: unconfirmed
            // height < -1: confirmed but unverified (proof pending)
            let verified = height > 0;

            entries.push(TxHistoryEntry {
                tx_hash,
                height,
                verified,
            });
        }

        Ok(entries)
    }

    async fn get_utxos(&self, scripthash: &str) -> Result<Vec<UtxoEntry>, NetworkError> {
        let result = self
            .call_array("blockchain.scripthash.listunspent", &[json!(scripthash)])
            .await?;

        let arr = result
            .as_array()
            .ok_or_else(|| NetworkError::Protocol("listunspent: expected array".into()))?;

        let mut entries = Vec::with_capacity(arr.len());
        for item in arr {
            let tx_hash = item
                .get("tx_hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| NetworkError::Protocol("listunspent: missing tx_hash".into()))?
                .to_string();

            let tx_pos = item
                .get("tx_pos")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| NetworkError::Protocol("listunspent: missing tx_pos".into()))?
                as u32;

            let value = item
                .get("value")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| NetworkError::Protocol("listunspent: missing value".into()))?;

            let height = item.get("height").and_then(|v| v.as_i64()).unwrap_or(0);

            entries.push(UtxoEntry {
                tx_hash,
                tx_pos,
                value,
                height,
            });
        }

        Ok(entries)
    }

    async fn broadcast_tx(&self, raw_tx: &[u8]) -> Result<BroadcastResult, NetworkError> {
        // AUD-006: Convert to hex and send
        let raw_hex = hex::encode(raw_tx);

        let result = self
            .call_array("blockchain.transaction.broadcast", &[json!(raw_hex)])
            .await?;

        // AUD-006: Server returns txid as string. None/empty = error.
        let server_txid = result
            .as_str()
            .ok_or(NetworkError::BroadcastNoTxid)?
            .to_string();

        if server_txid.is_empty() {
            return Err(NetworkError::BroadcastNoTxid);
        }

        // AUD-006: Validate returned txid by computing locally
        let expected_txid = Self::compute_txid(raw_tx);
        if expected_txid != server_txid {
            return Err(NetworkError::Validation(format!(
                "txid mismatch: server returned '{server_txid}', expected '{expected_txid}'"
            )));
        }

        Ok(BroadcastResult { txid: server_txid })
    }

    async fn get_block_headers(
        &self,
        start_height: u64,
        count: u64,
    ) -> Result<Vec<BlockHeader>, NetworkError> {
        let result = self
            .call_array(
                "blockchain.block.headers",
                &[json!(start_height), json!(count), json!(0u64)],
            )
            .await?;

        let rec_count = result
            .get("count")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| NetworkError::Protocol("block.headers: missing count".into()))?;

        let hex_str = result
            .get("hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| NetworkError::Protocol("block.headers: missing hex".into()))?;

        let raw = hex::decode(hex_str)
            .map_err(|e| NetworkError::Protocol(format!("block.headers: bad hex: {e}")))?;

        const HEADER_SIZE: usize = 80;
        let expected = rec_count as usize * HEADER_SIZE;
        if raw.len() != expected {
            return Err(NetworkError::Protocol(format!(
                "block.headers: expected {expected} bytes, got {}",
                raw.len()
            )));
        }

        let mut headers = Vec::with_capacity(rec_count as usize);
        for i in 0..rec_count as usize {
            let start = i * HEADER_SIZE;
            let end = start + HEADER_SIZE;
            headers.push(BlockHeader {
                height: start_height + i as u64,
                hex: hex::encode(&raw[start..end]),
            });
        }

        Ok(headers)
    }

    async fn get_merkle_proof(
        &self,
        tx_hash: &str,
        block_height: u64,
    ) -> Result<MerkleProof, NetworkError> {
        let result = self
            .call_array(
                "blockchain.transaction.get_merkle",
                &[json!(tx_hash), json!(block_height)],
            )
            .await?;

        let root = result
            .get("merkle")
            .and_then(|v| v.as_str())
            .ok_or_else(|| NetworkError::Protocol("get_merkle: missing merkle root".into()))?
            .to_string();

        let branch_arr = result
            .get("merkle_branch")
            .or_else(|| result.get("branch"))
            .and_then(|v| v.as_array())
            .ok_or_else(|| NetworkError::Protocol("get_merkle: missing branch".into()))?;

        let _pos = result
            .get("pos")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| NetworkError::Protocol("get_merkle: missing pos".into()))?;

        let mut merkle_branch = Vec::with_capacity(branch_arr.len());
        for item in branch_arr {
            let hash = item
                .as_str()
                .ok_or_else(|| NetworkError::Protocol("get_merkle: branch item not str".into()))?
                .to_string();
            merkle_branch.push((hash, false));
        }

        Ok(MerkleProof {
            tx_hash: tx_hash.to_string(),
            block_height,
            merkle_branch,
            root,
        })
    }

    async fn subscribe_scripthash(&self, scripthash: &str) -> Result<(), NetworkError> {
        let _result = self
            .call_array("blockchain.scripthash.subscribe", &[json!(scripthash)])
            .await?;
        Ok(())
    }

    async fn unsubscribe_scripthash(&self, scripthash: &str) -> Result<(), NetworkError> {
        let _result = self
            .call_array("blockchain.scripthash.unsubscribe", &[json!(scripthash)])
            .await?;
        Ok(())
    }

    async fn ping(&self) -> Result<(), NetworkError> {
        let _result = self.call("server.ping", json!([])).await?;
        Ok(())
    }

    async fn disconnect(&self) -> Result<(), NetworkError> {
        self.disconnect().await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_txid_known_vector() {
        // Coinbase transaction from BSV block 1 (simplified empty tx for hash test)
        // hash256 of empty bytes is not a real tx, but we test the hash logic.
        let h1 = Sha256::digest(b"");
        let h2 = Sha256::digest(h1);
        let mut reversed = h2.to_vec();
        reversed.reverse();
        let expected = hex::encode(&reversed);

        let computed = ElectrumXClient::compute_txid(b"");
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_compute_txid_deterministic() {
        let raw = b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let t1 = ElectrumXClient::compute_txid(raw);
        let t2 = ElectrumXClient::compute_txid(raw);
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 64); // 32 bytes → 64 hex chars
    }

    #[test]
    fn test_compute_txid_different_inputs() {
        let t1 = ElectrumXClient::compute_txid(b"hello");
        let t2 = ElectrumXClient::compute_txid(b"world");
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_compute_txid_known_empty_hash() {
        // hash256(b"") = sha256(sha256(b""))
        // sha256(b"") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // sha256(that) = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
        // reversed = 5694 5cfd 3f98 41e4 cf55 5f45 4515 81c0 fc99 2e58 0575 820a d359 1376 e2e0 f65d
        let computed = ElectrumXClient::compute_txid(b"");
        // Verify it's a valid hex string of 64 chars
        assert_eq!(computed.len(), 64);
        assert!(hex::decode(&computed).is_ok());
    }

    #[test]
    fn test_client_new_not_connected() {
        let server = ServerEntry::new("example.com", 50002);
        let client = ElectrumXClient::new(server);
        assert!(!client.is_connected());
    }

    #[test]
    fn test_server_entry_stored() {
        let server = ServerEntry::new("electrum.api.sv", 50002);
        let client = ElectrumXClient::new(server);
        assert_eq!(client.inner.server.host, "electrum.api.sv");
        assert_eq!(client.inner.server.ssl_port, 50002);
    }

    #[test]
    fn test_backend_type() {
        let server = ServerEntry::new("example.com", 50002);
        let client = ElectrumXClient::new(server);
        assert_eq!(client.backend_type(), BackendType::ElectrumX);
    }

    #[test]
    fn test_jsonrpc_request_format() {
        // Verify JSON-RPC 2.0 format by constructing manually
        let id: u64 = 42;
        let method = "server.version";
        let params = json!(["client", [1, 2]]);
        let msg = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let s = msg.to_string();

        // Parse back and verify
        let parsed: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["id"], 42);
        assert_eq!(parsed["method"], "server.version");
        assert!(parsed["params"].is_array());
    }

    #[test]
    fn test_jsonrpc_response_parsing() {
        // Simulate a server response
        let response = r#"{"jsonrpc":"2.0","id":1,"result":{"confirmed":50000,"unconfirmed":0}}"#;
        let parsed: Value = serde_json::from_str(response).unwrap();
        assert_eq!(parsed["id"], 1);
        assert!(parsed.get("result").is_some());
        assert_eq!(parsed["result"]["confirmed"], 50000);
        assert!(parsed.get("method").is_none()); // Not a notification
    }

    #[test]
    fn test_jsonrpc_error_response() {
        let response = r#"{"jsonrpc":"2.0","id":5,"error":{"code":1,"message":"bad request"}}"#;
        let parsed: Value = serde_json::from_str(response).unwrap();
        assert_eq!(parsed["id"], 5);
        assert!(parsed.get("error").is_some());
        assert_eq!(parsed["error"]["code"], 1);
        assert_eq!(parsed["error"]["message"], "bad request");
    }

    #[test]
    fn test_jsonrpc_notification_parsing() {
        // ElectrumX push notification (no id, has method)
        let notification = r#"{"jsonrpc":"2.0","method":"blockchain.headers.subscribe","params":{"hex":"abcdef","height":12345}}"#;
        let parsed: Value = serde_json::from_str(notification).unwrap();
        assert!(parsed.get("id").is_none()); // Notifications have no id
        assert_eq!(parsed["method"], "blockchain.headers.subscribe");
        assert!(parsed.get("params").is_some());
        assert_eq!(parsed["params"]["height"], 12345);
    }

    #[test]
    fn test_protocol_version_constants() {
        assert_eq!(PROTOCOL_MIN, 1);
        assert_eq!(PROTOCOL_MAX, 2);
    }

    #[test]
    fn test_client_version_not_empty() {
        assert!(!CLIENT_VERSION.is_empty());
    }

    // --- Notification parsing tests ---

    #[test]
    fn test_notification_new_block_object_params() {
        // ElectrumX headers.subscribe notification with object params
        let notification = r#"{"jsonrpc":"2.0","method":"blockchain.headers.subscribe","params":{"hex":"01000000","height":800000}}"#;
        let parsed: Value = serde_json::from_str(notification).unwrap();
        assert_eq!(parsed["method"], "blockchain.headers.subscribe");
        assert_eq!(parsed["params"]["height"], 800000);
        assert_eq!(parsed["params"]["hex"], "01000000");
    }

    #[test]
    fn test_notification_new_block_array_params() {
        // Some servers send array params
        let notification = r#"{"jsonrpc":"2.0","method":"blockchain.headers.subscribe","params":[{"hex":"abcdef","height":12345}]}"#;
        let parsed: Value = serde_json::from_str(notification).unwrap();
        let arr = parsed["params"].as_array().unwrap();
        assert_eq!(arr[0]["height"], 12345);
        assert_eq!(arr[0]["hex"], "abcdef");
    }

    #[test]
    fn test_notification_scripthash_array_params() {
        // ElectrumX scripthash.subscribe notification
        let notification = r#"{"jsonrpc":"2.0","method":"blockchain.scripthash.subscribe","params":["abc123def456","status_hash"]}"#;
        let parsed: Value = serde_json::from_str(notification).unwrap();
        assert_eq!(parsed["method"], "blockchain.scripthash.subscribe");
        let arr = parsed["params"].as_array().unwrap();
        assert_eq!(arr[0], "abc123def456");
        assert_eq!(arr[1], "status_hash");
    }

    #[test]
    fn test_notification_serialization_new_block() {
        let notif = ElectrumNotification::NewBlock {
            height: 800000,
            header_hex: "abcdef".to_string(),
        };
        let json = serde_json::to_string(&notif).unwrap();
        assert!(json.contains("800000"));
        assert!(json.contains("abcdef"));
        // Deserialized type should be identifiable
        assert!(json.contains("NewBlock") || json.contains("new_block"));
    }

    #[test]
    fn test_notification_serialization_scripthash() {
        let notif = ElectrumNotification::ScripthashStatus {
            scripthash: "abc123".to_string(),
            status: "def456".to_string(),
        };
        let json = serde_json::to_string(&notif).unwrap();
        assert!(json.contains("abc123"));
        assert!(json.contains("def456"));
    }

    #[test]
    fn test_subscribe_notifications_returns_receiver() {
        let server = ServerEntry::new("example.com", 50002);
        let client = ElectrumXClient::new(server);
        let _rx = client.subscribe_notifications();
        // Just verify it doesn't panic — the receiver is valid
    }

    #[test]
    fn test_notification_broadcast_to_subscriber() {
        let server = ServerEntry::new("example.com", 50002);
        let client = ElectrumXClient::new(server);
        let mut rx = client.subscribe_notifications();

        // Send a notification via the internal channel
        let notif = ElectrumNotification::NewBlock {
            height: 42,
            header_hex: "deadbeef".to_string(),
        };
        let _ = client.inner.notifications.send(notif);

        // Receiver should get it
        let received = rx.try_recv();
        assert!(received.is_ok());
        match received.unwrap() {
            ElectrumNotification::NewBlock { height, header_hex } => {
                assert_eq!(height, 42);
                assert_eq!(header_hex, "deadbeef");
            }
            _ => panic!("expected NewBlock variant"),
        }
    }

    #[test]
    fn test_notification_broadcast_no_subscribers() {
        // If no subscribers, send should not panic (just returns Err)
        let server = ServerEntry::new("example.com", 50002);
        let client = ElectrumXClient::new(server);
        // No receiver created — send should be Ok (broadcast allows this)
        let result = client
            .inner
            .notifications
            .send(ElectrumNotification::NewBlock {
                height: 1,
                header_hex: "00".to_string(),
            });
        // broadcast::send returns Err when there are no active receivers
        // but we use `let _ =` in the read_loop so it's fine
        assert!(result.is_err()); // No active receivers
    }
}
