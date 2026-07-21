// db/cache.rs — Transaction data cache with LRU eviction
//
// Ported from archive/electrumsv/wallet_database/cache.py.
// Provides an in-memory cache for transaction metadata and bytedata that sits
// above the SQLite store. This reduces database reads and latency.
//
// Design (matching the Python reference):
// - All transaction *metadata* (height, position, fee, flags) is cached in a HashMap.
// - Transaction *bytedata* (raw serialized transactions) is cached in a separate
//   LRU cache with a configurable byte-size limit.
// - Thread-safe via a RwLock (the Python uses threading.RLock; we use RwLock for
//   better read concurrency since metadata reads dominate).
//
// This module does NOT modify any existing files. It is standalone and uses only
// std + serde + thiserror (already in Cargo.toml).

use std::collections::HashMap;
use std::ops::{BitAnd, BitOr, BitOrAssign};
use std::sync::RwLock;
use std::time::Instant;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default maximum bytedata cache size: 256 MB (matches MAXIMUM_TXDATA_CACHE_SIZE_MB).
pub const DEFAULT_MAX_CACHE_SIZE_BYTES: usize = 256 * 1024 * 1024;

// ---------------------------------------------------------------------------
// TxFlags — bitmask implemented as a plain u32 newtype (no bitflags crate)
// ---------------------------------------------------------------------------

/// Transaction state and metadata flags (bitmask).
///
/// Matches the Python `TxFlags` enum from `constants.py`. Implemented as a
/// `u32` newtype to avoid adding the `bitflags` crate as a dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxFlags(pub u32);

impl TxFlags {
    // No flags set.
    pub const UNSET: Self = Self(0);

    // Metadata field flags.
    pub const HAS_FEE: Self = Self(1 << 0);
    pub const HAS_HEIGHT: Self = Self(1 << 1);
    pub const HAS_POSITION: Self = Self(1 << 2);
    pub const HAS_BYTEDATA: Self = Self(1 << 3);
    pub const HAS_PROOF_DATA: Self = Self(1 << 4);

    // State flags.
    pub const STATE_CLEAR: Self = Self(1 << 16);
    pub const STATE_SETTLED: Self = Self(1 << 17);
    pub const STATE_RECEIVED: Self = Self(1 << 18);
    pub const STATE_MEMPOOL: Self = Self(1 << 19);

    // Masks.
    pub const METADATA_FIELD_MASK: Self = Self(
        Self::HAS_FEE.0 | Self::HAS_HEIGHT.0 | Self::HAS_POSITION.0
            | Self::HAS_BYTEDATA.0 | Self::HAS_PROOF_DATA.0,
    );
    pub const STATE_MASK: Self = Self(
        Self::STATE_CLEAR.0 | Self::STATE_SETTLED.0 | Self::STATE_RECEIVED.0
            | Self::STATE_MEMPOOL.0,
    );

    /// Whether any of the bits in `other` are set.
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    /// Whether all bits in `other` are set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Whether no bits are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Display string (for logging).
    pub fn to_repr(self) -> String {
        if self.is_empty() {
            return "Unset".to_string();
        }
        let mut parts = Vec::new();
        if self.contains(Self::HAS_FEE) {
            parts.push("HasFee");
        }
        if self.contains(Self::HAS_HEIGHT) {
            parts.push("HasHeight");
        }
        if self.contains(Self::HAS_POSITION) {
            parts.push("HasPosition");
        }
        if self.contains(Self::HAS_BYTEDATA) {
            parts.push("HasByteData");
        }
        if self.contains(Self::HAS_PROOF_DATA) {
            parts.push("HasProofData");
        }
        if self.contains(Self::STATE_SETTLED) {
            parts.push("StateSettled");
        }
        if self.contains(Self::STATE_CLEAR) {
            parts.push("StateCleared");
        }
        if self.contains(Self::STATE_RECEIVED) {
            parts.push("StateReceived");
        }
        if self.contains(Self::STATE_MEMPOOL) {
            parts.push("StateMempool");
        }
        if parts.is_empty() {
            "Unset".to_string()
        } else {
            parts.join("|")
        }
    }
}

impl BitAnd for TxFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl BitOr for TxFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for TxFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

// ---------------------------------------------------------------------------
// TxData — transaction metadata (matches Python TxData)
// ---------------------------------------------------------------------------

/// Transaction metadata: height, position, fee, timestamps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxData {
    /// Block height (None if unconfirmed).
    pub height: Option<i64>,
    /// Position within the block (None if unconfirmed).
    pub position: Option<i64>,
    /// Fee in satoshis (None if unknown).
    pub fee: Option<i64>,
    /// Timestamp when the transaction was first seen (Unix epoch seconds).
    pub date_added: i64,
    /// Timestamp when the transaction was last updated.
    pub date_updated: i64,
}

impl TxData {
    /// Create new metadata with the given timestamps.
    pub fn new(date_added: i64, date_updated: i64) -> Self {
        Self {
            height: None,
            position: None,
            fee: None,
            date_added,
            date_updated,
        }
    }
}

// ---------------------------------------------------------------------------
// LRU cache for bytedata
// ---------------------------------------------------------------------------

/// A simple LRU cache with a byte-size limit.
///
/// Tracks total bytes stored and evicts least-recently-used entries when
/// the limit is exceeded.
struct LruCache {
    /// Ordered map: front = least recently used, back = most recently used.
    entries: Vec<(Vec<u8>, Vec<u8>)>, // (tx_hash, bytedata)
    /// Total size of all cached bytedata in bytes.
    total_size: usize,
    /// Maximum size in bytes.
    max_size: usize,
}

impl LruCache {
    fn new(max_size: usize) -> Self {
        Self {
            entries: Vec::new(),
            total_size: 0,
            max_size,
        }
    }

    /// Get the index of a tx_hash, if present.
    fn index_of(&self, tx_hash: &[u8]) -> Option<usize> {
        self.entries.iter().position(|(h, _)| h.as_slice() == tx_hash)
    }

    /// Insert or update bytedata for a tx_hash. Moves to MRU position.
    fn set(&mut self, tx_hash: Vec<u8>, bytedata: Vec<u8>) {
        // Remove existing entry if present.
        if let Some(idx) = self.index_of(&tx_hash) {
            let (_, old_data) = self.entries.remove(idx);
            self.total_size = self.total_size.saturating_sub(old_data.len());
        }

        let entry_size = bytedata.len();
        self.entries.push((tx_hash, bytedata));
        self.total_size += entry_size;

        // Evict LRU entries until under the limit.
        while self.total_size > self.max_size && self.entries.len() > 1 {
            let (_, old_data) = self.entries.remove(0);
            self.total_size = self.total_size.saturating_sub(old_data.len());
        }
    }

    /// Get bytedata for a tx_hash, moving it to MRU.
    fn get(&mut self, tx_hash: &[u8]) -> Option<&[u8]> {
        if let Some(idx) = self.index_of(tx_hash) {
            let entry = self.entries.remove(idx);
            self.entries.push(entry);
            self.entries.last().map(|(_, d)| d.as_slice())
        } else {
            None
        }
    }

    /// Remove a tx_hash from the cache.
    fn remove(&mut self, tx_hash: &[u8]) {
        if let Some(idx) = self.index_of(tx_hash) {
            let (_, old_data) = self.entries.remove(idx);
            self.total_size = self.total_size.saturating_sub(old_data.len());
        }
    }

    /// Number of cached entries.
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Total bytes currently cached.
    fn size(&self) -> usize {
        self.total_size
    }

    /// Check if a tx_hash is cached.
    fn contains(&self, tx_hash: &[u8]) -> bool {
        self.index_of(tx_hash).is_some()
    }

    /// Change the maximum size, evicting as needed.
    fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
        while self.total_size > self.max_size && !self.entries.is_empty() {
            let (_, old_data) = self.entries.remove(0);
            self.total_size = self.total_size.saturating_sub(old_data.len());
        }
    }
}

// ---------------------------------------------------------------------------
// TransactionCacheEntry
// ---------------------------------------------------------------------------

/// A cached transaction entry: metadata + flags + load time.
#[derive(Debug, Clone)]
pub struct TransactionCacheEntry {
    /// Transaction metadata.
    pub metadata: TxData,
    /// State/metadata flags.
    pub flags: TxFlags,
    /// When the entry was loaded into the cache.
    pub time_loaded: Instant,
}

impl TransactionCacheEntry {
    /// Create a new cache entry.
    pub fn new(metadata: TxData, flags: TxFlags) -> Self {
        Self {
            metadata,
            flags,
            time_loaded: Instant::now(),
        }
    }
}

// ---------------------------------------------------------------------------
// TransactionCache — the main cache type
// ---------------------------------------------------------------------------

/// An in-memory transaction cache with LRU bytedata eviction.
///
/// Thread-safe via `RwLock`. All metadata is cached in a `HashMap`; bytedata
/// is cached in a size-limited LRU.
///
/// This is the Rust equivalent of the Python `TransactionCache` class.
pub struct TransactionCache {
    /// Metadata cache: tx_hash -> entry.
    metadata_cache: RwLock<HashMap<Vec<u8>, TransactionCacheEntry>>,
    /// Bytedata LRU cache (tx_hash -> raw bytes).
    bytedata_cache: RwLock<LruCache>,
}

impl TransactionCache {
    /// Create a new cache with the default 256 MB bytedata limit.
    pub fn new() -> Self {
        Self::with_size(DEFAULT_MAX_CACHE_SIZE_BYTES)
    }

    /// Create a new cache with a custom bytedata size limit (in bytes).
    pub fn with_size(max_bytedata_size: usize) -> Self {
        Self {
            metadata_cache: RwLock::new(HashMap::new()),
            bytedata_cache: RwLock::new(LruCache::new(max_bytedata_size)),
        }
    }

    // -- Metadata operations -------------------------------------------------

    /// Add or update a metadata entry.
    pub fn add_metadata(&self, tx_hash: &[u8], metadata: TxData, flags: TxFlags) {
        let mut cache = self.metadata_cache.write().expect("metadata lock poisoned");
        cache.insert(tx_hash.to_vec(), TransactionCacheEntry::new(metadata, flags));
    }

    /// Get the metadata for a tx_hash (does not touch bytedata cache).
    pub fn get_metadata(&self, tx_hash: &[u8]) -> Option<TxData> {
        let cache = self.metadata_cache.read().expect("metadata lock poisoned");
        cache.get(tx_hash).map(|e| e.metadata.clone())
    }

    /// Get the flags for a tx_hash.
    pub fn get_flags(&self, tx_hash: &[u8]) -> Option<TxFlags> {
        let cache = self.metadata_cache.read().expect("metadata lock poisoned");
        cache.get(tx_hash).map(|e| e.flags)
    }

    /// Update flags for a tx_hash (no-op if not cached).
    pub fn update_flags(&self, tx_hash: &[u8], flags: TxFlags) {
        let mut cache = self.metadata_cache.write().expect("metadata lock poisoned");
        if let Some(entry) = cache.get_mut(tx_hash) {
            entry.flags = flags;
        }
    }

    /// Check if a tx_hash is in the metadata cache.
    pub fn is_cached(&self, tx_hash: &[u8]) -> bool {
        let cache = self.metadata_cache.read().expect("metadata lock poisoned");
        cache.contains_key(tx_hash)
    }

    /// Get the number of cached metadata entries.
    pub fn metadata_count(&self) -> usize {
        let cache = self.metadata_cache.read().expect("metadata lock poisoned");
        cache.len()
    }

    /// Delete a tx_hash from both metadata and bytedata caches.
    pub fn delete(&self, tx_hash: &[u8]) {
        let mut meta = self.metadata_cache.write().expect("metadata lock poisoned");
        meta.remove(tx_hash);
        let mut bd = self.bytedata_cache.write().expect("bytedata lock poisoned");
        bd.remove(tx_hash);
    }

    // -- Bytedata operations -------------------------------------------------

    /// Add bytedata for a tx_hash to the LRU cache.
    pub fn add_bytedata(&self, tx_hash: &[u8], bytedata: Vec<u8>) {
        let mut bd = self.bytedata_cache.write().expect("bytedata lock poisoned");
        bd.set(tx_hash.to_vec(), bytedata);
    }

    /// Get bytedata for a tx_hash (updates LRU order).
    pub fn get_bytedata(&self, tx_hash: &[u8]) -> Option<Vec<u8>> {
        let mut bd = self.bytedata_cache.write().expect("bytedata lock poisoned");
        bd.get(tx_hash).map(|s| s.to_vec())
    }

    /// Check if bytedata is cached for a tx_hash (does not update LRU).
    pub fn has_bytedata_cached(&self, tx_hash: &[u8]) -> bool {
        let bd = self.bytedata_cache.read().expect("bytedata lock poisoned");
        bd.contains(tx_hash)
    }

    /// Check if the metadata flags indicate bytedata is available.
    pub fn has_transaction_data(&self, tx_hash: &[u8]) -> bool {
        let cache = self.metadata_cache.read().expect("metadata lock poisoned");
        cache
            .get(tx_hash)
            .map(|e| e.flags.contains(TxFlags::HAS_BYTEDATA))
            .unwrap_or(false)
    }

    /// Current total bytedata cache size in bytes.
    pub fn bytedata_size(&self) -> usize {
        let bd = self.bytedata_cache.read().expect("bytedata lock poisoned");
        bd.size()
    }

    /// Number of bytedata entries cached.
    pub fn bytedata_count(&self) -> usize {
        let bd = self.bytedata_cache.read().expect("bytedata lock poisoned");
        bd.len()
    }

    /// Adjust the maximum bytedata cache size (evicts as needed).
    pub fn set_maximum_cache_size(&self, max_size: usize) {
        let mut bd = self.bytedata_cache.write().expect("bytedata lock poisoned");
        bd.set_max_size(max_size);
    }

    // -- Entry visibility / filtering ----------------------------------------

    /// Check if an entry's flags match the given filter (flags + mask).
    ///
    /// Matching logic (from Python `_entry_visible`):
    /// - No flags, no mask: always visible.
    /// - No flags, mask: visible if any masked bits are set.
    /// - Flags, no mask: visible if any of the flag bits are set.
    /// - Flags, mask: visible if the masked bits equal the flags.
    pub fn entry_visible(entry_flags: TxFlags, flags: Option<TxFlags>, mask: Option<TxFlags>) -> bool {
        match (flags, mask) {
            (None, None) => true,
            (None, Some(m)) => entry_flags.intersects(m),
            (Some(f), None) => entry_flags.intersects(f),
            (Some(f), Some(m)) => (entry_flags & m) == f,
        }
    }

    /// Get all cached entries matching the given flag filter.
    pub fn get_entries(
        &self,
        flags: Option<TxFlags>,
        mask: Option<TxFlags>,
    ) -> Vec<(Vec<u8>, TransactionCacheEntry)> {
        let cache = self.metadata_cache.read().expect("metadata lock poisoned");
        cache
            .iter()
            .filter(|(_, e)| Self::entry_visible(e.flags, flags, mask))
            .map(|(h, e)| (h.clone(), e.clone()))
            .collect()
    }

    /// Get the block height for a settled or cleared transaction.
    pub fn get_height(&self, tx_hash: &[u8]) -> Option<i64> {
        let cache = self.metadata_cache.read().expect("metadata lock poisoned");
        cache.get(tx_hash).and_then(|e| {
            if e.flags.intersects(TxFlags::STATE_SETTLED | TxFlags::STATE_CLEAR) {
                e.metadata.height
            } else {
                None
            }
        })
    }

    /// Get metadata for all entries that have bytedata but are unsynced
    /// (no height/position).
    pub fn get_unsynced_hashes(&self) -> Vec<Vec<u8>> {
        let cache = self.metadata_cache.read().expect("metadata lock poisoned");
        cache
            .iter()
            .filter(|(_, e)| {
                e.flags.contains(TxFlags::HAS_BYTEDATA) && !e.flags.contains(TxFlags::HAS_HEIGHT)
            })
            .map(|(h, _)| h.clone())
            .collect()
    }

    /// Clear all cached data (metadata + bytedata).
    pub fn clear(&self) {
        let mut meta = self.metadata_cache.write().expect("metadata lock poisoned");
        meta.clear();
        let mut bd = self.bytedata_cache.write().expect("bytedata lock poisoned");
        bd.entries.clear();
        bd.total_size = 0;
    }
}

impl Default for TransactionCache {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tx_hash(n: u8) -> Vec<u8> {
        vec![n; 32]
    }

    // --- TxFlags tests ---

    #[test]
    fn test_tx_flags_to_repr() {
        assert_eq!(TxFlags::UNSET.to_repr(), "Unset");
        let flags = TxFlags::HAS_FEE | TxFlags::HAS_BYTEDATA | TxFlags::STATE_SETTLED;
        let repr = flags.to_repr();
        assert!(repr.contains("HasFee"));
        assert!(repr.contains("HasByteData"));
        assert!(repr.contains("StateSettled"));
    }

    #[test]
    fn test_tx_flags_bitmask() {
        let flags = TxFlags::HAS_FEE | TxFlags::HAS_HEIGHT;
        assert!(flags.contains(TxFlags::HAS_FEE));
        assert!(flags.contains(TxFlags::HAS_HEIGHT));
        assert!(!flags.contains(TxFlags::HAS_BYTEDATA));
    }

    #[test]
    fn test_tx_flags_intersects() {
        let flags = TxFlags::HAS_BYTEDATA | TxFlags::STATE_SETTLED;
        assert!(flags.intersects(TxFlags::HAS_BYTEDATA));
        assert!(flags.intersects(TxFlags::STATE_SETTLED));
        assert!(!flags.intersects(TxFlags::HAS_FEE));
    }

    // --- LRU cache tests ---

    #[test]
    fn test_lru_eviction() {
        let mut lru = LruCache::new(100); // 100 bytes max
        lru.set(vec![1u8; 32], vec![0xAA; 50]);
        assert_eq!(lru.len(), 1);
        assert_eq!(lru.size(), 50);

        // Second entry would push total to 100, still fits.
        lru.set(vec![2u8; 32], vec![0xBB; 50]);
        assert_eq!(lru.len(), 2);

        // Third entry exceeds limit; first entry should be evicted.
        lru.set(vec![3u8; 32], vec![0xCC; 50]);
        assert_eq!(lru.len(), 2);
        assert!(!lru.contains(&vec![1u8; 32]));
        assert!(lru.contains(&vec![2u8; 32]));
        assert!(lru.contains(&vec![3u8; 32]));
    }

    #[test]
    fn test_lru_get_updates_order() {
        let mut lru = LruCache::new(100);
        lru.set(vec![1u8; 32], vec![0xAA; 50]);
        lru.set(vec![2u8; 32], vec![0xBB; 50]);

        // Access entry 1 — should move to MRU.
        let data = lru.get(&vec![1u8; 32]);
        assert_eq!(data, Some(&vec![0xAAu8; 50][..]));

        // Add a third entry that would evict the LRU (entry 2).
        lru.set(vec![3u8; 32], vec![0xCC; 50]);
        assert!(lru.contains(&vec![1u8; 32]));
        assert!(!lru.contains(&vec![2u8; 32]));
    }

    // --- TransactionCache metadata tests ---

    #[test]
    fn test_add_and_get_metadata() {
        let cache = TransactionCache::new();
        let hash = make_tx_hash(1);
        let data = TxData {
            height: Some(100),
            position: Some(0),
            fee: Some(500),
            date_added: 1000,
            date_updated: 2000,
        };
        cache.add_metadata(&hash, data.clone(), TxFlags::HAS_HEIGHT | TxFlags::HAS_BYTEDATA);
        let retrieved = cache.get_metadata(&hash).expect("should be cached");
        assert_eq!(retrieved, data);
        let flags = cache.get_flags(&hash).expect("flags");
        assert!(flags.contains(TxFlags::HAS_HEIGHT));
        assert!(flags.contains(TxFlags::HAS_BYTEDATA));
    }

    #[test]
    fn test_is_cached() {
        let cache = TransactionCache::new();
        let h1 = make_tx_hash(1);
        let h2 = make_tx_hash(2);
        cache.add_metadata(&h1, TxData::new(0, 0), TxFlags::UNSET);
        assert!(cache.is_cached(&h1));
        assert!(!cache.is_cached(&h2));
    }

    #[test]
    fn test_delete_removes_both_caches() {
        let cache = TransactionCache::new();
        let hash = make_tx_hash(1);
        cache.add_metadata(&hash, TxData::new(0, 0), TxFlags::HAS_BYTEDATA);
        cache.add_bytedata(&hash, vec![0xAA; 100]);
        assert!(cache.is_cached(&hash));
        assert!(cache.has_bytedata_cached(&hash));
        cache.delete(&hash);
        assert!(!cache.is_cached(&hash));
        assert!(!cache.has_bytedata_cached(&hash));
    }

    // --- Bytedata tests ---

    #[test]
    fn test_bytedata_add_and_get() {
        let cache = TransactionCache::new();
        let hash = make_tx_hash(1);
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        cache.add_bytedata(&hash, data.clone());
        let retrieved = cache.get_bytedata(&hash).expect("should be cached");
        assert_eq!(retrieved, data);
    }

    #[test]
    fn test_bytedata_size_tracking() {
        let cache = TransactionCache::new();
        let hash = make_tx_hash(1);
        let data = vec![0xAA; 1000];
        cache.add_bytedata(&hash, data);
        assert_eq!(cache.bytedata_size(), 1000);
        assert_eq!(cache.bytedata_count(), 1);
    }

    #[test]
    fn test_set_maximum_cache_size_evicts() {
        let cache = TransactionCache::with_size(1000);
        let h1 = make_tx_hash(1);
        let h2 = make_tx_hash(2);
        cache.add_bytedata(&h1, vec![0xAA; 500]);
        cache.add_bytedata(&h2, vec![0xBB; 500]);
        assert_eq!(cache.bytedata_size(), 1000);
        // Reduce to 600 — should evict one entry.
        cache.set_maximum_cache_size(600);
        assert!(cache.bytedata_size() <= 600);
        assert_eq!(cache.bytedata_count(), 1);
    }

    // --- Entry visibility tests ---

    #[test]
    fn test_entry_visible_no_filter() {
        assert!(TransactionCache::entry_visible(TxFlags::HAS_BYTEDATA, None, None));
    }

    #[test]
    fn test_entry_visible_mask_only() {
        assert!(TransactionCache::entry_visible(
            TxFlags::HAS_BYTEDATA,
            None,
            Some(TxFlags::HAS_BYTEDATA)
        ));
        assert!(!TransactionCache::entry_visible(
            TxFlags::UNSET,
            None,
            Some(TxFlags::HAS_BYTEDATA)
        ));
    }

    #[test]
    fn test_entry_visible_flags_and_mask() {
        assert!(TransactionCache::entry_visible(
            TxFlags::HAS_BYTEDATA | TxFlags::HAS_HEIGHT,
            Some(TxFlags::HAS_BYTEDATA),
            Some(TxFlags::HAS_BYTEDATA)
        ));
        assert!(!TransactionCache::entry_visible(
            TxFlags::HAS_HEIGHT,
            Some(TxFlags::HAS_BYTEDATA),
            Some(TxFlags::HAS_BYTEDATA)
        ));
    }

    #[test]
    fn test_get_entries_filtered() {
        let cache = TransactionCache::new();
        let h1 = make_tx_hash(1);
        let h2 = make_tx_hash(2);
        cache.add_metadata(&h1, TxData::new(0, 0), TxFlags::HAS_BYTEDATA | TxFlags::STATE_SETTLED);
        cache.add_metadata(&h2, TxData::new(0, 0), TxFlags::HAS_BYTEDATA);
        let settled = cache.get_entries(Some(TxFlags::STATE_SETTLED), Some(TxFlags::STATE_SETTLED));
        assert_eq!(settled.len(), 1);
        assert_eq!(settled[0].0, h1);
    }

    #[test]
    fn test_get_height_settled() {
        let cache = TransactionCache::new();
        let hash = make_tx_hash(1);
        let data = TxData {
            height: Some(42),
            position: None,
            fee: None,
            date_added: 0,
            date_updated: 0,
        };
        cache.add_metadata(&hash, data, TxFlags::STATE_SETTLED | TxFlags::HAS_HEIGHT);
        assert_eq!(cache.get_height(&hash), Some(42));
    }

    #[test]
    fn test_get_height_unconfirmed() {
        let cache = TransactionCache::new();
        let hash = make_tx_hash(1);
        let data = TxData {
            height: Some(42),
            position: None,
            fee: None,
            date_added: 0,
            date_updated: 0,
        };
        // No state flags — height should not be returned.
        cache.add_metadata(&hash, data, TxFlags::HAS_HEIGHT);
        assert_eq!(cache.get_height(&hash), None);
    }

    #[test]
    fn test_get_unsynced_hashes() {
        let cache = TransactionCache::new();
        let h1 = make_tx_hash(1);
        let h2 = make_tx_hash(2);
        cache.add_metadata(&h1, TxData::new(0, 0), TxFlags::HAS_BYTEDATA);
        cache.add_metadata(&h2, TxData::new(0, 0), TxFlags::HAS_BYTEDATA | TxFlags::HAS_HEIGHT);
        let unsynced = cache.get_unsynced_hashes();
        assert_eq!(unsynced.len(), 1);
        assert_eq!(unsynced[0], h1);
    }

    #[test]
    fn test_clear() {
        let cache = TransactionCache::new();
        let hash = make_tx_hash(1);
        cache.add_metadata(&hash, TxData::new(0, 0), TxFlags::HAS_BYTEDATA);
        cache.add_bytedata(&hash, vec![0xAA; 100]);
        cache.clear();
        assert_eq!(cache.metadata_count(), 0);
        assert_eq!(cache.bytedata_count(), 0);
    }
}