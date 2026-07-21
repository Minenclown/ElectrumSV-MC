// network/header_store.rs — Block header storage, SPV verification, reorg detection
//
// This module provides persistent storage for BSV block headers in SQLite,
// validation of the header chain (Proof-of-Work + prev_hash linkage), and
// SPV merkle-proof verification for trustless transaction verification.
//
// BSV block headers are 80 bytes:
//   version (4 LE) | prev_hash (32 LE) | merkle_root (32 LE) | timestamp (4 LE) | bits (4 LE) | nonce (4 LE)
//
// Header hash = hash256(80 bytes), stored/displayed in reversed (big-endian) form.
// PoW check: hash256(header) as LE 256-bit number < target (from compact bits format).

use std::path::Path;

use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};

use super::backend::NetworkError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const HEADER_SIZE: usize = 80;

/// BSV mainnet genesis block header (block 0) — raw 80 bytes in hex.
/// Hash (display): 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
const BSV_GENESIS_HEADER_HEX: &str =
    "010000000000000000000000000000000000000000000000000000000000000000000000\
     3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a\
     29ab5f49ffff001d1dac2b7c";

// ---------------------------------------------------------------------------
// Parsed header struct
// ---------------------------------------------------------------------------

/// A parsed BSV block header (80 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHeader {
    /// Block version (4 bytes, LE).
    pub version: u32,
    /// Previous block hash in display (reversed) hex.
    pub prev_hash: String,
    /// Merkle root in display (reversed) hex.
    pub merkle_root: String,
    /// Block timestamp (Unix epoch, 4 bytes LE).
    pub timestamp: u32,
    /// Compact difficulty bits (4 bytes LE).
    pub bits: u32,
    /// Nonce (4 bytes LE).
    pub nonce: u32,
    /// Block height (provided externally, not stored in the header itself).
    pub height: u64,
    /// This block's hash in display (reversed) hex.
    pub hash: String,
}

impl ParsedHeader {
    /// Parse a raw 80-byte header at a given height.
    pub fn from_raw(raw: &[u8], height: u64) -> Result<Self, NetworkError> {
        if raw.len() != HEADER_SIZE {
            return Err(NetworkError::Protocol(format!(
                "header must be {HEADER_SIZE} bytes, got {}",
                raw.len()
            )));
        }

        let version = u32::from_le_bytes(raw[0..4].try_into().unwrap());
        let prev_hash = hex::encode(&reverse_bytes(&raw[4..36]));
        let merkle_root = hex::encode(&reverse_bytes(&raw[36..68]));
        let timestamp = u32::from_le_bytes(raw[68..72].try_into().unwrap());
        let bits = u32::from_le_bytes(raw[72..76].try_into().unwrap());
        let nonce = u32::from_le_bytes(raw[76..80].try_into().unwrap());

        // Compute hash: hash256(raw) reversed
        let hash = header_hash_display(raw);

        Ok(Self {
            version,
            prev_hash,
            merkle_root,
            timestamp,
            bits,
            nonce,
            height,
            hash,
        })
    }

    /// Parse from hex string.
    pub fn from_hex(hex_str: &str, height: u64) -> Result<Self, NetworkError> {
        let raw = hex::decode(hex_str)
            .map_err(|e| NetworkError::Protocol(format!("invalid header hex: {e}")))?;
        Self::from_raw(&raw, height)
    }

    /// Serialize back to raw 80 bytes.
    pub fn to_raw(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(HEADER_SIZE);
        raw.extend_from_slice(&self.version.to_le_bytes());
        // prev_hash is display hex → reverse for internal LE storage
        let prev = hex::decode(&self.prev_hash).unwrap_or_default();
        raw.extend_from_slice(&reverse_bytes(&prev));
        let merkle = hex::decode(&self.merkle_root).unwrap_or_default();
        raw.extend_from_slice(&reverse_bytes(&merkle));
        raw.extend_from_slice(&self.timestamp.to_le_bytes());
        raw.extend_from_slice(&self.bits.to_le_bytes());
        raw.extend_from_slice(&self.nonce.to_le_bytes());
        raw
    }
}

// ---------------------------------------------------------------------------
// Hashing helpers
// ---------------------------------------------------------------------------

/// Compute hash256 = SHA256(SHA256(data)).
pub fn hash256(data: &[u8]) -> [u8; 32] {
    let h1 = Sha256::digest(data);
    let h2 = Sha256::digest(h1);
    h2.into()
}

/// Compute the block hash in display (reversed) hex from raw 80-byte header.
pub fn header_hash_display(raw: &[u8]) -> String {
    let hash = hash256(raw);
    hex::encode(&reverse_bytes(&hash))
}

/// Compute the block hash in internal (LE) hex from raw 80-byte header.
pub fn header_hash_internal(raw: &[u8]) -> String {
    let hash = hash256(raw);
    hex::encode(&hash)
}

/// Reverse a byte slice (for endianness conversion).
fn reverse_bytes(data: &[u8]) -> Vec<u8> {
    let mut v = data.to_vec();
    v.reverse();
    v
}

// ---------------------------------------------------------------------------
// Difficulty / PoW
// ---------------------------------------------------------------------------

/// Decode compact difficulty bits into a 32-byte big-endian target.
///
/// Compact format: first byte = exponent, next 3 bytes = mantissa.
/// target = mantissa * 256^(exponent - 3)
pub fn target_from_bits(bits: u32) -> [u8; 32] {
    let exponent = (bits >> 24) as usize;
    let mantissa = (bits & 0x007fffff) as u32;

    let mut target = [0u8; 32];

    // Mantissa is 3 bytes (big-endian within the u32).
    let m = [
        ((mantissa >> 16) & 0xff) as u8,
        ((mantissa >> 8) & 0xff) as u8,
        (mantissa & 0xff) as u8,
    ];

    // Place mantissa bytes in the 32-byte big-endian target array.
    // The mantissa's MSB goes at index (32 - exponent).
    if exponent >= 3 && exponent <= 32 {
        let start = 32 - exponent;
        if start < 32 {
            target[start] = m[0];
        }
        if start + 1 < 32 {
            target[start + 1] = m[1];
        }
        if start + 2 < 32 {
            target[start + 2] = m[2];
        }
    } else if exponent < 3 {
        // Shift right (rare, only in testnet/regtest)
        let shift = 3 - exponent;
        for i in 0..3 {
            if i + shift < 3 {
                let pos = 29 + i + shift; // near the end of the array
                if pos < 32 {
                    target[pos] = m[i];
                }
            }
        }
    }

    target
}

/// Check Proof-of-Work: hash256(header) as LE number < target.
///
/// hash256 gives us 32 bytes. In Bitcoin/BSV, these bytes are interpreted
/// as a 256-bit little-endian number for PoW comparison. To compare with
/// the big-endian target array, we reverse the hash bytes and compare
/// as big-endian.
pub fn check_pow(raw: &[u8]) -> bool {
    if raw.len() != HEADER_SIZE {
        return false;
    }

    let bits = u32::from_le_bytes(raw[72..76].try_into().unwrap());
    let target = target_from_bits(bits);

    // hash256(header) → 32 bytes. Reverse for big-endian comparison.
    let hash = hash256(raw);
    let hash_be = reverse_bytes(&hash);

    // hash_be < target (both big-endian 32-byte arrays)
    hash_be.as_slice() < target.as_slice()
}

// ---------------------------------------------------------------------------
// Merkle proof verification (SPV)
// ---------------------------------------------------------------------------

/// Verify a merkle proof for SPV transaction verification.
///
/// `tx_hash` is in display (reversed) hex.
/// `branch` is a list of partner hashes in display (reversed) hex.
/// `pos` is the 0-based position of the transaction in the block.
/// `expected_root` is the merkle root from the block header, in display (reversed) hex.
///
/// Returns true if the proof is valid (the transaction is included in the block).
pub fn verify_merkle_proof(
    tx_hash: &str,
    branch: &[String],
    pos: u64,
    expected_root: &str,
) -> bool {
    // Convert tx_hash from display hex to internal (LE) bytes
    let mut current = match hex::decode(tx_hash) {
        Ok(bytes) => reverse_bytes(&bytes), // display → internal LE
        Err(_) => return false,
    };

    // Iteratively combine with branch hashes
    for (level, branch_hash_display) in branch.iter().enumerate() {
        let partner = match hex::decode(branch_hash_display) {
            Ok(bytes) => reverse_bytes(&bytes), // display → internal LE
            Err(_) => return false,
        };

        // Determine direction from pos bit at this level.
        // If bit is 0, current is on the left → hash256(current || partner)
        // If bit is 1, current is on the right → hash256(partner || current)
        let on_left = (pos >> level) & 1 == 0;

        let combined = if on_left {
            let mut data = Vec::with_capacity(current.len() + partner.len());
            data.extend_from_slice(&current);
            data.extend_from_slice(&partner);
            data
        } else {
            let mut data = Vec::with_capacity(partner.len() + current.len());
            data.extend_from_slice(&partner);
            data.extend_from_slice(&current);
            data
        };

        current = hash256(&combined).to_vec();
    }

    // Convert result back to display hex for comparison
    let computed_root_display = hex::encode(&reverse_bytes(&current));

    // Case-insensitive comparison (both should be lowercase hex)
    computed_root_display.eq_ignore_ascii_case(expected_root)
}

// ---------------------------------------------------------------------------
// SQLite header store
// ---------------------------------------------------------------------------

/// Persistent block header storage backed by SQLite.
///
/// Stores raw 80-byte headers indexed by height. The store validates the
/// PoW and chain linkage before accepting new headers.
pub struct HeaderStore {
    pool: SqlitePool,
}

impl HeaderStore {
    /// Open or create a header store at the given SQLite database path.
    pub async fn open(db_path: &str) -> Result<Self, NetworkError> {
        // Ensure parent directory exists
        if let Some(parent) = Path::new(db_path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                NetworkError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("create headers dir: {e}"),
                ))
            })?;
        }

        let options = SqliteConnectOptions::new()
            .filename(db_path)
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .map_err(|e| NetworkError::Connection(format!("header store open: {e}")))?;

        // Create schema
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS headers (
                height INTEGER PRIMARY KEY,
                header_hex TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .map_err(|e| NetworkError::Connection(format!("header store schema: {e}")))?;

        Ok(Self { pool })
    }

    /// Create an in-memory header store (for testing).
    pub async fn in_memory() -> Result<Self, NetworkError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .map_err(|e| NetworkError::Connection(format!("header store memory: {e}")))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS headers (
                height INTEGER PRIMARY KEY,
                header_hex TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .map_err(|e| NetworkError::Connection(format!("header store schema: {e}")))?;

        Ok(Self { pool })
    }

    /// Insert a single header at a given height.
    /// Validates PoW before storing. Does NOT check chain linkage
    /// (use `connect_header` for that).
    pub async fn insert_header(&self, height: u64, header_hex: &str) -> Result<(), NetworkError> {
        let raw = hex::decode(header_hex)
            .map_err(|e| NetworkError::Protocol(format!("invalid header hex: {e}")))?;

        if raw.len() != HEADER_SIZE {
            return Err(NetworkError::Protocol(format!(
                "header must be {HEADER_SIZE} bytes, got {}",
                raw.len()
            )));
        }

        // Validate PoW
        if !check_pow(&raw) {
            return Err(NetworkError::Validation(format!(
                "PoW check failed for header at height {height}"
            )));
        }

        sqlx::query("INSERT OR REPLACE INTO headers (height, header_hex) VALUES (?, ?)")
            .bind(height as i64)
            .bind(header_hex)
            .execute(&self.pool)
            .await
            .map_err(|e| NetworkError::Connection(format!("insert header: {e}")))?;

        Ok(())
    }

    /// Connect a new header to the chain.
    /// Validates PoW AND prev_hash linkage to the existing tip.
    /// If the header doesn't connect to the current tip, returns an error
    /// indicating a potential reorg.
    pub async fn connect_header(
        &self,
        height: u64,
        header_hex: &str,
    ) -> Result<ConnectResult, NetworkError> {
        let parsed = ParsedHeader::from_hex(header_hex, height)?;

        // Validate PoW
        if !check_pow(&hex::decode(header_hex).unwrap()) {
            return Err(NetworkError::Validation(format!(
                "PoW check failed for header at height {height}"
            )));
        }

        // Check genesis case
        if height == 0 {
            // Check if genesis already stored
            if let Ok(Some(existing)) = self.get_header(0).await {
                if existing == header_hex {
                    return Ok(ConnectResult::AlreadyExists { height: 0 });
                }
            }
            // Verify this is the known BSV genesis header
            let genesis = ParsedHeader::from_hex(BSV_GENESIS_HEADER_HEX, 0)?;
            if parsed.hash != genesis.hash {
                return Err(NetworkError::Validation(
                    "genesis header hash does not match known BSV mainnet genesis".into(),
                ));
            }
            self.insert_header(0, header_hex).await?;
            return Ok(ConnectResult::Connected { height: 0 });
        }

        // Get current tip
        let tip = self.get_tip().await?;

        match tip {
            None => {
                // No headers stored yet — can't connect without genesis
                return Err(NetworkError::Validation(
                    "cannot connect header without genesis (height 0) first".into(),
                ));
            }
            Some((tip_height, tip_hex)) => {
                let tip_parsed = ParsedHeader::from_hex(&tip_hex, tip_height)?;

                // Normal case: new header extends the current chain
                if height == tip_height + 1 && parsed.prev_hash == tip_parsed.hash {
                    self.insert_header(height, header_hex).await?;
                    return Ok(ConnectResult::Connected { height });
                }

                // Header already stored at this height?
                if let Ok(Some(existing)) = self.get_header(height).await {
                    if existing == header_hex {
                        return Ok(ConnectResult::AlreadyExists { height });
                    }
                }

                // Check if this header connects to a previous header (reorg)
                if height > 0 {
                    if let Ok(Some(prev_hex)) = self.get_header(height - 1).await {
                        let prev_parsed = ParsedHeader::from_hex(&prev_hex, height - 1)?;
                        if parsed.prev_hash == prev_parsed.hash {
                            // This header connects to height-1 but tip was different.
                            // This is a reorg: the new chain forks at height-1.
                            self.insert_header(height, header_hex).await?;
                            return Ok(ConnectResult::Reorg {
                                fork_point: height - 1,
                                new_tip: height,
                            });
                        }
                    }
                }

                // Header doesn't connect to anything
                Err(NetworkError::Validation(format!(
                    "header at height {height} does not connect to chain \
                     (tip at {tip_height}, prev_hash={})",
                    parsed.prev_hash
                )))
            }
        }
    }

    /// Connect multiple headers in sequence.
    /// Validates each header's PoW and chain linkage.
    pub async fn connect_headers(
        &self,
        headers: &[(u64, String)],
    ) -> Result<ConnectBatchResult, NetworkError> {
        let mut connected = 0u64;
        let mut reorgs = Vec::new();

        for (height, hex) in headers {
            match self.connect_header(*height, hex).await? {
                ConnectResult::Connected { .. } | ConnectResult::AlreadyExists { .. } => {
                    connected += 1;
                }
                ConnectResult::Reorg {
                    fork_point,
                    new_tip,
                } => {
                    reorgs.push((fork_point, new_tip));
                    connected += 1;
                }
            }
        }

        Ok(ConnectBatchResult { connected, reorgs })
    }

    /// Get a header by height.
    pub async fn get_header(&self, height: u64) -> Result<Option<String>, NetworkError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT header_hex FROM headers WHERE height = ?")
                .bind(height as i64)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| NetworkError::Connection(format!("get_header: {e}")))?;

        Ok(row.map(|(hex,)| hex))
    }

    /// Get the current chain tip (highest height + its header hex).
    pub async fn get_tip(&self) -> Result<Option<(u64, String)>, NetworkError> {
        let row: Option<(i64, String)> =
            sqlx::query_as("SELECT height, header_hex FROM headers ORDER BY height DESC LIMIT 1")
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| NetworkError::Connection(format!("get_tip: {e}")))?;

        Ok(row.map(|(h, hex)| (h as u64, hex)))
    }

    /// Get headers in a range [start_height, start_height + count).
    pub async fn get_header_range(
        &self,
        start_height: u64,
        count: u64,
    ) -> Result<Vec<(u64, String)>, NetworkError> {
        let rows: Vec<(i64, String)> = sqlx::query_as(
            "SELECT height, header_hex FROM headers \
             WHERE height >= ? AND height < ? \
             ORDER BY height ASC",
        )
        .bind(start_height as i64)
        .bind((start_height + count) as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| NetworkError::Connection(format!("get_header_range: {e}")))?;

        Ok(rows.into_iter().map(|(h, hex)| (h as u64, hex)).collect())
    }

    /// Get the total number of stored headers.
    pub async fn header_count(&self) -> Result<u64, NetworkError> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM headers")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| NetworkError::Connection(format!("header_count: {e}")))?;

        Ok(row.0 as u64)
    }

    /// Rollback the chain to a given height (delete all headers above it).
    /// Used during reorg handling to discard the old chain.
    pub async fn rollback_to(&self, height: u64) -> Result<u64, NetworkError> {
        let result = sqlx::query("DELETE FROM headers WHERE height > ?")
            .bind(height as i64)
            .execute(&self.pool)
            .await
            .map_err(|e| NetworkError::Connection(format!("rollback_to: {e}")))?;

        Ok(result.rows_affected())
    }

    /// Initialize with the BSV mainnet genesis header if empty.
    pub async fn ensure_genesis(&self) -> Result<(), NetworkError> {
        let count = self.header_count().await?;
        if count == 0 {
            self.insert_header(0, BSV_GENESIS_HEADER_HEX).await?;
        }
        Ok(())
    }

    /// Verify the full chain in storage (PoW + linkage for every header).
    /// Returns the first error if any header is invalid.
    pub async fn verify_chain(&self) -> Result<u64, NetworkError> {
        let count = self.header_count().await?;
        if count == 0 {
            return Ok(0);
        }

        let headers = self.get_header_range(0, count).await?;
        let mut prev_hash: Option<String> = None;

        for (height, hex) in &headers {
            let parsed = ParsedHeader::from_hex(hex, *height)?;
            let raw = hex::decode(hex).unwrap();

            // Check PoW
            if !check_pow(&raw) {
                return Err(NetworkError::Validation(format!(
                    "PoW check failed at height {height}"
                )));
            }

            // Check genesis
            if *height == 0 {
                let genesis = ParsedHeader::from_hex(BSV_GENESIS_HEADER_HEX, 0)?;
                if parsed.hash != genesis.hash {
                    return Err(NetworkError::Validation(
                        "genesis header hash mismatch".into(),
                    ));
                }
            } else if let Some(ref prev) = prev_hash {
                // Check prev_hash linkage
                if parsed.prev_hash != *prev {
                    return Err(NetworkError::Validation(format!(
                        "chain break at height {height}: prev_hash={} expected={}",
                        parsed.prev_hash, prev
                    )));
                }
            }

            prev_hash = Some(parsed.hash);
        }

        Ok(count)
    }

    /// Verify a merkle proof against a stored block header.
    ///
    /// Looks up the header at `block_height`, extracts the merkle root,
    /// and verifies that the transaction is included in that block.
    pub async fn verify_spv_proof(
        &self,
        tx_hash: &str,
        block_height: u64,
        merkle_branch: &[String],
        pos: u64,
    ) -> Result<bool, NetworkError> {
        let header_hex = self.get_header(block_height).await?.ok_or_else(|| {
            NetworkError::NotFound(format!("no header stored at height {block_height}"))
        })?;

        let parsed = ParsedHeader::from_hex(&header_hex, block_height)?;
        let merkle_root = &parsed.merkle_root;

        Ok(verify_merkle_proof(
            tx_hash,
            merkle_branch,
            pos,
            merkle_root,
        ))
    }
}

/// Drop the pool (implicit on Drop).
impl Drop for HeaderStore {
    fn drop(&mut self) {
        // sqlx pools close connections on drop
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Result of connecting a single header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectResult {
    /// Header was connected to the chain.
    Connected { height: u64 },
    /// Header was already present (duplicate, no-op).
    AlreadyExists { height: u64 },
    /// Reorg detected: the new header forks from `fork_point` and becomes the new tip.
    Reorg { fork_point: u64, new_tip: u64 },
}

/// Result of connecting a batch of headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectBatchResult {
    /// Number of headers successfully connected (including reorgs).
    pub connected: u64,
    /// Reorg events: (fork_point, new_tip) for each reorg.
    pub reorgs: Vec<(u64, u64)>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Header parsing tests --

    #[test]
    fn test_parse_genesis_header() {
        let parsed = ParsedHeader::from_hex(BSV_GENESIS_HEADER_HEX, 0).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(
            parsed.prev_hash,
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(parsed.timestamp, 1231006505);
        assert_eq!(parsed.bits, 0x1d00ffff);
        assert_eq!(parsed.nonce, 2083236893);
        // Genesis hash (display, reversed)
        assert_eq!(
            parsed.hash,
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn test_parse_genesis_merkle_root() {
        let parsed = ParsedHeader::from_hex(BSV_GENESIS_HEADER_HEX, 0).unwrap();
        // Genesis merkle root (display form = reversed)
        assert_eq!(
            parsed.merkle_root,
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
    }

    #[test]
    fn test_parse_header_wrong_size() {
        let result = ParsedHeader::from_raw(b"too short", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_header_invalid_hex() {
        let result = ParsedHeader::from_hex("not_valid_hex", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_header_roundtrip() {
        let raw = hex::decode(BSV_GENESIS_HEADER_HEX).unwrap();
        let parsed = ParsedHeader::from_raw(&raw, 0).unwrap();
        let re_raw = parsed.to_raw();
        assert_eq!(re_raw, raw);
    }

    // -- Hashing tests --

    #[test]
    fn test_hash256_empty() {
        let h = hash256(b"");
        // hash256(b"") = sha256(sha256(b""))
        // sha256(b"") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // sha256(that) = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
        let expected =
            hex::decode("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")
                .unwrap();
        assert_eq!(h.to_vec(), expected);
    }

    #[test]
    fn test_header_hash_genesis() {
        let raw = hex::decode(BSV_GENESIS_HEADER_HEX).unwrap();
        let hash_display = header_hash_display(&raw);
        assert_eq!(
            hash_display,
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn test_header_hash_internal_vs_display() {
        let raw = hex::decode(BSV_GENESIS_HEADER_HEX).unwrap();
        let internal = header_hash_internal(&raw);
        let display = header_hash_display(&raw);
        // Internal = reversed of display
        let internal_bytes = hex::decode(&internal).unwrap();
        let display_bytes = hex::decode(&display).unwrap();
        let mut reversed = display_bytes.clone();
        reversed.reverse();
        assert_eq!(internal_bytes, reversed);
    }

    // -- Difficulty / PoW tests --

    #[test]
    fn test_target_from_bits_genesis() {
        // Genesis bits = 0x1d00ffff
        let target = target_from_bits(0x1d00ffff);
        // Target should be 0x00000000FFFF0000000000000000000000000000000000000000000000000000
        // In big-endian bytes:
        let expected =
            hex::decode("00000000FFFF0000000000000000000000000000000000000000000000000000")
                .unwrap();
        assert_eq!(target.to_vec(), expected);
    }

    #[test]
    fn test_target_from_bits_high_difficulty() {
        // A higher difficulty bits value
        let target = target_from_bits(0x1d00ffff);
        // The target must be a valid 32-byte array
        assert_eq!(target.len(), 32);
        // Higher bits → lower target → harder.
        // 0x207fffff has exponent 32 → easier (larger target)
        // 0x1d00ffff has exponent 29 → harder (smaller target)
        // So target2 (easier) > target (harder)
        let target2 = target_from_bits(0x207fffff);
        assert!(target2.as_slice() > target.as_slice());
    }

    #[test]
    fn test_check_pow_genesis_passes() {
        let raw = hex::decode(BSV_GENESIS_HEADER_HEX).unwrap();
        assert!(check_pow(&raw));
    }

    #[test]
    fn test_check_pow_invalid_header_fails() {
        // A header with a bad nonce (doesn't meet target)
        let mut raw = hex::decode(BSV_GENESIS_HEADER_HEX).unwrap();
        // Change nonce to something invalid
        raw[79] = 0x00; // was 0x7c
        assert!(!check_pow(&raw));
    }

    #[test]
    fn test_check_pow_wrong_size() {
        assert!(!check_pow(b"too short"));
    }

    // -- Merkle proof tests --

    #[test]
    fn test_merkle_proof_single_tx() {
        // For a block with a single transaction (like genesis),
        // the merkle root = txid (no branch needed).
        // Genesis coinbase txid (display): 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
        let tx_hash = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
        let merkle_root = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

        let valid = verify_merkle_proof(tx_hash, &[], 0, merkle_root);
        assert!(valid);
    }

    #[test]
    fn test_merkle_proof_wrong_root() {
        let tx_hash = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
        let wrong_root = "0000000000000000000000000000000000000000000000000000000000000000";

        let valid = verify_merkle_proof(tx_hash, &[], 0, wrong_root);
        assert!(!valid);
    }

    #[test]
    fn test_merkle_proof_invalid_tx_hash() {
        let valid = verify_merkle_proof("not_hex", &[], 0, "some_root");
        assert!(!valid);
    }

    #[test]
    fn test_merkle_proof_invalid_branch() {
        let tx_hash = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
        let branch = vec!["not_hex".to_string()];
        let valid = verify_merkle_proof(tx_hash, &branch, 0, "some_root");
        assert!(!valid);
    }

    #[test]
    fn test_merkle_proof_two_txs() {
        // Simulate a block with 2 transactions.
        // tx0 hash: aaaa... (32 bytes)
        // tx1 hash: bbbb... (32 bytes)
        // merkle = hash256(tx0_internal || tx1_internal)
        let tx0_display = "aa0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let tx1_display = "bb0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

        // Convert to internal (LE) for hashing
        let tx0_internal = reverse_bytes(&hex::decode(tx0_display).unwrap());
        let tx1_internal = reverse_bytes(&hex::decode(tx1_display).unwrap());

        let mut combined = Vec::new();
        combined.extend_from_slice(&tx0_internal);
        combined.extend_from_slice(&tx1_internal);
        let merkle_internal = hash256(&combined);
        let merkle_display = hex::encode(&reverse_bytes(&merkle_internal));

        // Verify proof for tx0 (pos=0, branch=[tx1])
        let valid0 =
            verify_merkle_proof(tx0_display, &[tx1_display.to_string()], 0, &merkle_display);
        assert!(valid0);

        // Verify proof for tx1 (pos=1, branch=[tx0])
        let valid1 =
            verify_merkle_proof(tx1_display, &[tx0_display.to_string()], 1, &merkle_display);
        assert!(valid1);
    }

    // -- HeaderStore SQLite tests --

    #[tokio::test]
    async fn test_header_store_open_in_memory() {
        let store = HeaderStore::in_memory().await.unwrap();
        assert_eq!(store.header_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_header_store_insert_genesis() {
        let store = HeaderStore::in_memory().await.unwrap();
        store
            .insert_header(0, BSV_GENESIS_HEADER_HEX)
            .await
            .unwrap();
        assert_eq!(store.header_count().await.unwrap(), 1);

        let header = store.get_header(0).await.unwrap();
        assert!(header.is_some());
        assert_eq!(header.unwrap(), BSV_GENESIS_HEADER_HEX);
    }

    #[tokio::test]
    async fn test_header_store_insert_invalid_pow() {
        let store = HeaderStore::in_memory().await.unwrap();
        // Create a header with invalid PoW
        let mut raw = hex::decode(BSV_GENESIS_HEADER_HEX).unwrap();
        raw[79] = 0x00; // Break the nonce
        let bad_hex = hex::encode(&raw);

        let result = store.insert_header(0, &bad_hex).await;
        assert!(result.is_err());
        assert_eq!(store.header_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_header_store_get_tip() {
        let store = HeaderStore::in_memory().await.unwrap();
        store
            .insert_header(0, BSV_GENESIS_HEADER_HEX)
            .await
            .unwrap();

        let tip = store.get_tip().await.unwrap();
        assert!(tip.is_some());
        let (height, hex) = tip.unwrap();
        assert_eq!(height, 0);
        assert_eq!(hex, BSV_GENESIS_HEADER_HEX);
    }

    #[tokio::test]
    async fn test_header_store_get_range() {
        let store = HeaderStore::in_memory().await.unwrap();
        store
            .insert_header(0, BSV_GENESIS_HEADER_HEX)
            .await
            .unwrap();

        let range = store.get_header_range(0, 10).await.unwrap();
        assert_eq!(range.len(), 1);
        assert_eq!(range[0].0, 0);
    }

    #[tokio::test]
    async fn test_header_store_rollback() {
        let store = HeaderStore::in_memory().await.unwrap();
        store
            .insert_header(0, BSV_GENESIS_HEADER_HEX)
            .await
            .unwrap();

        // Insert a fake header at height 1 (won't validate PoW, so use insert_header directly)
        // Actually insert_header validates PoW, so we need a valid PoW header.
        // For testing, let's use a raw SQL insert.
        sqlx::query("INSERT INTO headers (height, header_hex) VALUES (1, 'fake')")
            .execute(&store.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO headers (height, header_hex) VALUES (2, 'fake2')")
            .execute(&store.pool)
            .await
            .unwrap();

        assert_eq!(store.header_count().await.unwrap(), 3);

        let deleted = store.rollback_to(0).await.unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(store.header_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_header_store_ensure_genesis() {
        let store = HeaderStore::in_memory().await.unwrap();
        store.ensure_genesis().await.unwrap();
        assert_eq!(store.header_count().await.unwrap(), 1);

        // Calling again should be a no-op
        store.ensure_genesis().await.unwrap();
        assert_eq!(store.header_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_connect_genesis() {
        let store = HeaderStore::in_memory().await.unwrap();
        let result = store
            .connect_header(0, BSV_GENESIS_HEADER_HEX)
            .await
            .unwrap();
        assert_eq!(result, ConnectResult::Connected { height: 0 });
    }

    #[tokio::test]
    async fn test_connect_without_genesis_fails() {
        let store = HeaderStore::in_memory().await.unwrap();
        // Try to connect a header at height 1 without genesis
        let result = store.connect_header(1, BSV_GENESIS_HEADER_HEX).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_wrong_genesis_fails() {
        let store = HeaderStore::in_memory().await.unwrap();
        // Modify the genesis header slightly
        let mut raw = hex::decode(BSV_GENESIS_HEADER_HEX).unwrap();
        raw[0] = 0x02; // Change version
                       // This will likely fail PoW check, so let's bypass and test the hash check
                       // by using a header that passes PoW but has wrong hash.
                       // Actually, changing version will change the hash and likely fail PoW.
                       // The error will be PoW failure, not genesis mismatch.
        let result = store.connect_header(0, &hex::encode(&raw)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_duplicate() {
        let store = HeaderStore::in_memory().await.unwrap();
        store
            .connect_header(0, BSV_GENESIS_HEADER_HEX)
            .await
            .unwrap();

        // Connecting the same genesis again should return AlreadyExists
        let result = store
            .connect_header(0, BSV_GENESIS_HEADER_HEX)
            .await
            .unwrap();
        assert_eq!(result, ConnectResult::AlreadyExists { height: 0 });
    }

    #[tokio::test]
    async fn test_verify_chain_genesis_only() {
        let store = HeaderStore::in_memory().await.unwrap();
        store
            .insert_header(0, BSV_GENESIS_HEADER_HEX)
            .await
            .unwrap();

        let count = store.verify_chain().await.unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_verify_chain_empty() {
        let store = HeaderStore::in_memory().await.unwrap();
        let count = store.verify_chain().await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_verify_spv_proof_genesis() {
        let store = HeaderStore::in_memory().await.unwrap();
        store
            .insert_header(0, BSV_GENESIS_HEADER_HEX)
            .await
            .unwrap();

        // Genesis coinbase txid (display)
        let tx_hash = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

        let valid = store.verify_spv_proof(tx_hash, 0, &[], 0).await.unwrap();
        assert!(valid);
    }

    #[tokio::test]
    async fn test_verify_spv_proof_missing_header() {
        let store = HeaderStore::in_memory().await.unwrap();
        let result = store.verify_spv_proof("some_hash", 100, &[], 0).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_connect_result_equality() {
        let a = ConnectResult::Connected { height: 42 };
        let b = ConnectResult::Connected { height: 42 };
        let c = ConnectResult::Connected { height: 41 };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_connect_batch_result() {
        let r = ConnectBatchResult {
            connected: 5,
            reorgs: vec![(3, 10)],
        };
        assert_eq!(r.connected, 5);
        assert_eq!(r.reorgs.len(), 1);
        assert_eq!(r.reorgs[0], (3, 10));
    }

    #[test]
    fn test_reverse_bytes() {
        assert_eq!(reverse_bytes(&[1, 2, 3]), vec![3u8, 2, 1]);
        let empty: [u8; 0] = [];
        assert_eq!(reverse_bytes(&empty), Vec::<u8>::new());
        assert_eq!(reverse_bytes(&[42u8]), vec![42u8]);
    }

    #[test]
    fn test_genesis_header_hex_length() {
        // 80 bytes = 160 hex chars
        assert_eq!(BSV_GENESIS_HEADER_HEX.len(), 160);
    }
}
