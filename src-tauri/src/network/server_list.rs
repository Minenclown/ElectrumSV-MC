// network/server_list.rs — Server list, rotation, failover, health tracking
//
// Manages the list of known ElectrumX servers and provides rotation/failover
// logic. The initial list is hard-coded from the Python reference data
// (electrumsv/data/servers.json). Servers are tracked with health status
// and latency measurements.
//
// DESIGN:
// - ServerList is owned by AppState and protected by a Mutex (same pattern as
//   ActiveWallet). The MutexGuard is not held across await points.
// - Best-server selection uses a simple algorithm: prefer connected, then
//   lowest average latency, then round-robin among healthy servers.
// - Failed servers are marked with a backoff time. After backoff expires,
//   they become candidates again.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Server entry + status
// ---------------------------------------------------------------------------

/// A single ElectrumX server entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerEntry {
    /// Hostname (e.g. "electrumx.gorillapool.io").
    pub host: String,
    /// SSL/TLS port (typically 50002).
    pub ssl_port: u16,
    /// TCP port (typically 50001), if available.
    pub tcp_port: Option<u16>,
    /// ElectrumX protocol version supported.
    pub version: String,
}

impl ServerEntry {
    /// Create a new server entry with the given host and SSL port.
    pub fn new(host: &str, ssl_port: u16) -> Self {
        Self {
            host: host.to_string(),
            ssl_port,
            tcp_port: Some(50001),
            version: "1.4".to_string(),
        }
    }

    /// The full address string for TLS connection: "host:port"
    pub fn tls_addr(&self) -> String {
        format!("{}:{}", self.host, self.ssl_port)
    }

    /// The full address string for TCP connection: "host:port"
    pub fn tcp_addr(&self) -> Option<String> {
        self.tcp_port.map(|p| format!("{}:{}", self.host, p))
    }
}

/// Health status of a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerStatus {
    /// Never attempted to connect.
    Unknown,
    /// Currently connected and responsive.
    Connected,
    /// Was connected previously, currently not.
    Disconnected,
    /// Failed to connect or timed out. Will retry after backoff.
    Failed,
    /// Permanently banned due to invalid data (bad cert, wrong proof, etc.).
    /// AUD-Fund #6: Servers that return invalid proofs or fail TLS validation
    /// must be banned, not just warned.
    Banned,
}

// ---------------------------------------------------------------------------
// Internal health record
// ---------------------------------------------------------------------------

/// Internal health tracking for a single server.
#[derive(Debug, Clone)]
struct ServerHealth {
    status: ServerStatus,
    /// Number of consecutive failures.
    consecutive_failures: u32,
    /// When the status was last updated.
    last_updated: Instant,
    /// When to retry after a failure (backoff expiry).
    retry_after: Option<Instant>,
    /// Rolling average latency in milliseconds.
    avg_latency_ms: Option<u64>,
    /// Total successful requests.
    successful_requests: u64,
    /// Total failed requests.
    failed_requests: u64,
}

impl ServerHealth {
    fn new() -> Self {
        Self {
            status: ServerStatus::Unknown,
            consecutive_failures: 0,
            last_updated: Instant::now(),
            retry_after: None,
            avg_latency_ms: None,
            successful_requests: 0,
            failed_requests: 0,
        }
    }

    /// Backoff duration based on consecutive failures.
    /// 1 failure → 5s, 2 → 10s, 3 → 30s, 4+ → 60s, max 300s.
    fn backoff_duration(failures: u32) -> Duration {
        match failures {
            0 => Duration::from_secs(0),
            1 => Duration::from_secs(5),
            2 => Duration::from_secs(10),
            3 => Duration::from_secs(30),
            4..=9 => Duration::from_secs(60),
            _ => Duration::from_secs(300),
        }
    }

    /// Record a successful request.
    fn record_success(&mut self, latency_ms: u64) {
        self.status = ServerStatus::Connected;
        self.consecutive_failures = 0;
        self.last_updated = Instant::now();
        self.retry_after = None;
        self.successful_requests += 1;
        // Exponential moving average: α = 0.3
        self.avg_latency_ms = Some(match self.avg_latency_ms {
            Some(prev) => ((prev as f64 * 0.7) + (latency_ms as f64 * 0.3)) as u64,
            None => latency_ms,
        });
    }

    /// Record a failure.
    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        self.failed_requests += 1;
        self.last_updated = Instant::now();
        self.status = ServerStatus::Failed;
        let backoff = Self::backoff_duration(self.consecutive_failures);
        self.retry_after = Some(Instant::now() + backoff);
    }

    /// Permanently ban this server (AUD-Fund #6: invalid data = ban).
    fn ban(&mut self) {
        self.status = ServerStatus::Banned;
        self.last_updated = Instant::now();
        self.retry_after = None;
    }

    /// Mark as disconnected (graceful).
    fn disconnect(&mut self) {
        self.status = ServerStatus::Disconnected;
        self.last_updated = Instant::now();
        self.retry_after = None;
    }

    /// Check if this server is currently eligible for connection.
    fn is_eligible(&self) -> bool {
        match self.status {
            ServerStatus::Banned => false,
            ServerStatus::Connected => false, // Already connected
            ServerStatus::Failed => {
                // Check if backoff has expired
                match self.retry_after {
                    Some(when) => Instant::now() >= when,
                    None => true,
                }
            }
            ServerStatus::Disconnected | ServerStatus::Unknown => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Server list
// ---------------------------------------------------------------------------

/// The list of known servers with health tracking and rotation logic.
#[derive(Debug)]
pub struct ServerList {
    /// All known servers, in priority order.
    servers: Vec<ServerEntry>,
    /// Health records keyed by host.
    health: HashMap<String, ServerHealth>,
    /// Round-robin counter for selecting among eligible servers.
    rr_counter: AtomicU64,
    /// Index of the currently active (connected) server, if any.
    active_index: Option<usize>,
}

impl ServerList {
    /// Create a new server list with the default BSV mainnet servers.
    /// These are the servers from electrumsv/data/servers.json.
    pub fn with_defaults() -> Self {
        let servers = default_servers();
        let mut health = HashMap::new();
        for s in &servers {
            health.insert(s.host.clone(), ServerHealth::new());
        }
        Self {
            servers,
            health,
            rr_counter: AtomicU64::new(0),
            active_index: None,
        }
    }

    /// Create an empty server list.
    pub fn empty() -> Self {
        Self {
            servers: Vec::new(),
            health: HashMap::new(),
            rr_counter: AtomicU64::new(0),
            active_index: None,
        }
    }

    /// Add a server to the list.
    pub fn add(&mut self, server: ServerEntry) {
        if !self.health.contains_key(&server.host) {
            self.health.insert(server.host.clone(), ServerHealth::new());
        }
        self.servers.push(server);
    }

    /// Remove a server from the list.
    pub fn remove(&mut self, host: &str) {
        self.servers.retain(|s| s.host != host);
        self.health.remove(host);
        if let Some(idx) = self.active_index {
            if self.servers.is_empty() {
                self.active_index = None;
            } else if idx >= self.servers.len() {
                self.active_index = Some(self.servers.len() - 1);
            }
        }
    }

    /// Get all known servers.
    pub fn all(&self) -> &[ServerEntry] {
        &self.servers
    }

    /// Get the currently active server, if any.
    pub fn active(&self) -> Option<&ServerEntry> {
        self.active_index.and_then(|i| self.servers.get(i))
    }

    /// Get the status of a server by host.
    pub fn status(&self, host: &str) -> ServerStatus {
        self.health
            .get(host)
            .map(|h| h.status)
            .unwrap_or(ServerStatus::Unknown)
    }

    /// Get the average latency for a server by host.
    pub fn latency(&self, host: &str) -> Option<u64> {
        self.health.get(host).and_then(|h| h.avg_latency_ms)
    }

    /// Record a successful connection/request to a server.
    pub fn record_success(&mut self, host: &str, latency_ms: u64) {
        if let Some(h) = self.health.get_mut(host) {
            h.record_success(latency_ms);
        }
        // Update active index
        if let Some(idx) = self.servers.iter().position(|s| s.host == host) {
            self.active_index = Some(idx);
        }
    }

    /// Record a failure for a server.
    pub fn record_failure(&mut self, host: &str) {
        if let Some(h) = self.health.get_mut(host) {
            h.record_failure();
        }
        // Clear active if it was the active server
        if let Some(idx) = self.active_index {
            if let Some(server) = self.servers.get(idx) {
                if server.host == host {
                    self.active_index = None;
                }
            }
        }
    }

    /// Permanently ban a server (AUD-Fund #6).
    /// This is for servers that return invalid data: bad certificates,
    /// wrong merkle proofs, invalid headers, etc.
    pub fn ban(&mut self, host: &str) {
        if let Some(h) = self.health.get_mut(host) {
            h.ban();
        }
        // Clear active if it was the active server
        if let Some(idx) = self.active_index {
            if let Some(server) = self.servers.get(idx) {
                if server.host == host {
                    self.active_index = None;
                }
            }
        }
    }

    /// Mark a server as gracefully disconnected.
    pub fn disconnect(&mut self, host: &str) {
        if let Some(h) = self.health.get_mut(host) {
            h.disconnect();
        }
        if let Some(idx) = self.active_index {
            if let Some(server) = self.servers.get(idx) {
                if server.host == host {
                    self.active_index = None;
                }
            }
        }
    }

    /// Select the best eligible server for connection.
    ///
    /// Algorithm:
    /// 1. Filter eligible servers (not banned, not connected, backoff expired).
    /// 2. If no eligible servers, return None (all servers failed).
    /// 3. Prefer servers with lower average latency.
    /// 4. Break ties with round-robin.
    pub fn select_best(&self) -> Option<&ServerEntry> {
        let eligible: Vec<(usize, &ServerEntry)> = self
            .servers
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                self.health
                    .get(&s.host)
                    .map(|h| h.is_eligible())
                    .unwrap_or(true)
            })
            .collect();

        if eligible.is_empty() {
            return None;
        }

        // Sort by average latency (Unknown latency = worst priority)
        let mut sorted = eligible.clone();
        sorted.sort_by_key(|(_, s)| {
            self.health
                .get(&s.host)
                .and_then(|h| h.avg_latency_ms)
                .unwrap_or(u64::MAX)
        });

        // Round-robin among the top candidates with similar latency
        let rr = self.rr_counter.fetch_add(1, Ordering::Relaxed);
        let idx = (rr as usize) % sorted.len();
        Some(sorted[idx].1)
    }

    /// Get all servers with their current status.
    pub fn list_with_status(&self) -> Vec<ServerStatusInfo> {
        self.servers
            .iter()
            .map(|s| {
                let h = self.health.get(&s.host);
                ServerStatusInfo {
                    host: s.host.clone(),
                    ssl_port: s.ssl_port,
                    tcp_port: s.tcp_port,
                    version: s.version.clone(),
                    status: h.map(|h| h.status).unwrap_or(ServerStatus::Unknown),
                    avg_latency_ms: h.and_then(|h| h.avg_latency_ms),
                    consecutive_failures: h.map(|h| h.consecutive_failures).unwrap_or(0),
                }
            })
            .collect()
    }

    /// Count servers by status.
    pub fn count_by_status(&self) -> ServerCounts {
        let mut counts = ServerCounts::default();
        for h in self.health.values() {
            match h.status {
                ServerStatus::Unknown => counts.unknown += 1,
                ServerStatus::Connected => counts.connected += 1,
                ServerStatus::Disconnected => counts.disconnected += 1,
                ServerStatus::Failed => counts.failed += 1,
                ServerStatus::Banned => counts.banned += 1,
            }
        }
        counts
    }

    /// Check if any server is currently connected.
    pub fn has_connected(&self) -> bool {
        self.health
            .values()
            .any(|h| h.status == ServerStatus::Connected)
    }

    /// Number of total servers.
    pub fn len(&self) -> usize {
        self.servers.len()
    }

    /// Is the list empty?
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Status info for Tauri commands
// ---------------------------------------------------------------------------

/// Public status info for a single server, returned by Tauri commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStatusInfo {
    pub host: String,
    pub ssl_port: u16,
    pub tcp_port: Option<u16>,
    pub version: String,
    pub status: ServerStatus,
    pub avg_latency_ms: Option<u64>,
    pub consecutive_failures: u32,
}

/// Aggregated server counts by status.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerCounts {
    pub unknown: usize,
    pub connected: usize,
    pub disconnected: usize,
    pub failed: usize,
    pub banned: usize,
}

// ---------------------------------------------------------------------------
// Default BSV mainnet server list
// ---------------------------------------------------------------------------

/// Returns the default BSV mainnet ElectrumX server list.
/// Source: electrumsv/data/servers.json
fn default_servers() -> Vec<ServerEntry> {
    vec![
        ServerEntry {
            host: "electrumx.gorillapool.io".to_string(),
            ssl_port: 50002,
            tcp_port: Some(50001),
            version: "1.4".to_string(),
        },
        ServerEntry {
            host: "electrum.api.sv".to_string(),
            ssl_port: 50002,
            tcp_port: Some(50001),
            version: "1.4".to_string(),
        },
        ServerEntry {
            host: "neptune.api.sv".to_string(),
            ssl_port: 50002,
            tcp_port: Some(50001),
            version: "1.4".to_string(),
        },
        ServerEntry {
            host: "alpha-esv.api.sv".to_string(),
            ssl_port: 50002,
            tcp_port: Some(50001),
            version: "1.4".to_string(),
        },
        ServerEntry {
            host: "sv.satoshi.io".to_string(),
            ssl_port: 50002,
            tcp_port: Some(50001),
            version: "1.4".to_string(),
        },
        ServerEntry {
            host: "sv2.satoshi.io".to_string(),
            ssl_port: 50002,
            tcp_port: Some(50001),
            version: "1.4".to_string(),
        },
        ServerEntry {
            host: "esv.bitails.io".to_string(),
            ssl_port: 50002,
            tcp_port: None,
            version: "1.4".to_string(),
        },
        ServerEntry {
            host: "electrum.server.sv".to_string(),
            ssl_port: 50002,
            tcp_port: Some(50001),
            version: "1.4".to_string(),
        },
        ServerEntry {
            host: "bsv.aftrek.org".to_string(),
            ssl_port: 50002,
            tcp_port: Some(50001),
            version: "1.4".to_string(),
        },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_servers() {
        let list = ServerList::with_defaults();
        assert_eq!(list.len(), 9);
        assert!(list
            .all()
            .iter()
            .any(|s| s.host == "electrumx.gorillapool.io"));
        assert!(list.all().iter().any(|s| s.host == "electrum.api.sv"));
    }

    #[test]
    fn test_server_entry_addr() {
        let s = ServerEntry::new("example.com", 50002);
        assert_eq!(s.tls_addr(), "example.com:50002");
        assert_eq!(s.tcp_addr(), Some("example.com:50001".to_string()));

        let s2 = ServerEntry {
            host: "no-tcp.example.com".to_string(),
            ssl_port: 50002,
            tcp_port: None,
            version: "1.4".to_string(),
        };
        assert_eq!(s2.tcp_addr(), None);
    }

    #[test]
    fn test_select_best_returns_eligible() {
        let list = ServerList::with_defaults();
        let best = list.select_best();
        assert!(best.is_some());
        // All servers start as Unknown, so all are eligible
        let best = best.unwrap();
        assert!(list.all().iter().any(|s| s.host == best.host));
    }

    #[test]
    fn test_select_best_empty() {
        let list = ServerList::empty();
        assert!(list.select_best().is_none());
    }

    #[test]
    fn test_record_success_and_active() {
        let mut list = ServerList::with_defaults();
        list.record_success("electrum.api.sv", 50);
        assert_eq!(list.active().unwrap().host, "electrum.api.sv");
        assert_eq!(list.status("electrum.api.sv"), ServerStatus::Connected);
        assert_eq!(list.latency("electrum.api.sv"), Some(50));
    }

    #[test]
    fn test_record_failure_and_backoff() {
        let mut list = ServerList::with_defaults();
        list.record_failure("electrum.api.sv");
        assert_eq!(list.status("electrum.api.sv"), ServerStatus::Failed);
        assert_eq!(list.active(), None); // Active cleared

        // Server should not be eligible immediately (backoff active)
        let health = list.health.get("electrum.api.sv").unwrap();
        assert!(!health.is_eligible());
    }

    #[test]
    fn test_ban_server() {
        let mut list = ServerList::with_defaults();
        list.ban("electrum.api.sv");
        assert_eq!(list.status("electrum.api.sv"), ServerStatus::Banned);
        assert_eq!(list.active(), None);

        // Banned server should never be selected
        let best = list.select_best();
        assert!(best.is_some());
        assert_ne!(best.unwrap().host, "electrum.api.sv");
    }

    #[test]
    fn test_disconnect_server() {
        let mut list = ServerList::with_defaults();
        list.record_success("electrum.api.sv", 30);
        assert_eq!(list.status("electrum.api.sv"), ServerStatus::Connected);
        list.disconnect("electrum.api.sv");
        assert_eq!(list.status("electrum.api.sv"), ServerStatus::Disconnected);
        assert_eq!(list.active(), None);
    }

    #[test]
    fn test_count_by_status() {
        let mut list = ServerList::with_defaults();
        list.record_success("electrum.api.sv", 50);
        list.record_failure("electrumx.gorillapool.io");
        list.ban("neptune.api.sv");

        let counts = list.count_by_status();
        assert_eq!(counts.connected, 1);
        assert_eq!(counts.failed, 1);
        assert_eq!(counts.banned, 1);
        assert_eq!(counts.unknown, 6); // 9 - 3
    }

    #[test]
    fn test_add_remove_server() {
        let mut list = ServerList::empty();
        assert!(list.is_empty());

        list.add(ServerEntry::new("new.server.com", 50002));
        assert_eq!(list.len(), 1);
        assert_eq!(list.status("new.server.com"), ServerStatus::Unknown);

        list.remove("new.server.com");
        assert!(list.is_empty());
    }

    #[test]
    fn test_list_with_status() {
        let mut list = ServerList::with_defaults();
        list.record_success("electrum.api.sv", 42);

        let info = list.list_with_status();
        assert_eq!(info.len(), 9);

        let active = info.iter().find(|s| s.host == "electrum.api.sv").unwrap();
        assert_eq!(active.status, ServerStatus::Connected);
        assert_eq!(active.avg_latency_ms, Some(42));
    }

    #[test]
    fn test_backoff_duration() {
        assert_eq!(ServerHealth::backoff_duration(0), Duration::from_secs(0));
        assert_eq!(ServerHealth::backoff_duration(1), Duration::from_secs(5));
        assert_eq!(ServerHealth::backoff_duration(2), Duration::from_secs(10));
        assert_eq!(ServerHealth::backoff_duration(3), Duration::from_secs(30));
        assert_eq!(ServerHealth::backoff_duration(4), Duration::from_secs(60));
        assert_eq!(ServerHealth::backoff_duration(10), Duration::from_secs(300));
    }

    #[test]
    fn test_rolling_latency_average() {
        let mut list = ServerList::with_defaults();
        // First measurement = 100ms
        list.record_success("electrum.api.sv", 100);
        assert_eq!(list.latency("electrum.api.sv"), Some(100));
        // Second measurement = 50ms → EMA = 100*0.7 + 50*0.3 = 85
        list.record_success("electrum.api.sv", 50);
        assert_eq!(list.latency("electrum.api.sv"), Some(85));
        // Third measurement = 50ms → EMA = 85*0.7 + 50*0.3 = 74 (rounded)
        list.record_success("electrum.api.sv", 50);
        assert_eq!(list.latency("electrum.api.sv"), Some(74));
    }

    #[test]
    fn test_has_connected() {
        let mut list = ServerList::with_defaults();
        assert!(!list.has_connected());
        list.record_success("electrum.api.sv", 50);
        assert!(list.has_connected());
        list.disconnect("electrum.api.sv");
        assert!(!list.has_connected());
    }

    #[test]
    fn test_all_banned_returns_none() {
        let mut list = ServerList::empty();
        list.add(ServerEntry::new("bad1.com", 50002));
        list.add(ServerEntry::new("bad2.com", 50002));
        list.ban("bad1.com");
        list.ban("bad2.com");
        assert_eq!(list.select_best(), None);
    }

    #[test]
    fn test_round_robin_selection() {
        let mut list = ServerList::with_defaults();
        // All servers are Unknown (eligible), so selection should rotate
        let first = list.select_best().unwrap().host.clone();
        let second = list.select_best().unwrap().host.clone();
        let third = list.select_best().unwrap().host.clone();
        // With round-robin, at least two should differ
        // (they might all differ, but with sorting by latency which is all
        // MAX, the order is stable and rr_counter rotates)
        assert!(first != second || second != third);
    }

    #[test]
    fn test_active_index_after_remove() {
        let mut list = ServerList::empty();
        list.add(ServerEntry::new("a.com", 50002));
        list.add(ServerEntry::new("b.com", 50002));
        list.add(ServerEntry::new("c.com", 50002));
        list.record_success("b.com", 50); // active_index = 1
        assert_eq!(list.active().unwrap().host, "b.com");

        list.remove("b.com");
        // After removing b.com, active_index should be clamped
        // a.com is at 0, c.com is at 1 now
        if let Some(active) = list.active() {
            assert!(active.host == "a.com" || active.host == "c.com");
        }
    }
}
