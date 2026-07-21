// features/bip276.rs — BIP276 bitcoin-script:// URI parser with checksum
//
// Ported from archive/electrumsv/bip276.py
//
// BIP276 defines a URI format for encoding Bitcoin script data with a
// double-SHA256 checksum and network tagging:
//   bitcoin-script:<version><network><data><checksum>
//
// All payload bytes (version + network + data + checksum) are hex-encoded
// and appended after the prefix. The checksum is the first 4 bytes of
// SHA256(SHA256(prefix + ":" + payload_hex_without_checksum)).
//
// Reference: BIP276

use sha2::{Digest, Sha256};

// ============================================================================
// Constants
// ============================================================================

pub const PREFIX_BIP276_SCRIPT: &str = "bitcoin-script";
pub const PREFIX_TEMPLATE: &str = "bitcoin-template";
pub const CURRENT_VERSION: u8 = 1;

/// BIP276 network identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[repr(u8)]
pub enum Bip276Network {
    Mainnet = 1,
    Testnet = 2,
    ScalingTestnet = 3,
    Regtest = 4,
}

impl Bip276Network {
    /// Try to convert a raw byte to a known network.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Mainnet),
            2 => Some(Self::Testnet),
            3 => Some(Self::ScalingTestnet),
            4 => Some(Self::Regtest),
            _ => None,
        }
    }
}

// ============================================================================
// Error types
// ============================================================================

/// Errors that can occur during BIP276 encoding/decoding.
#[derive(Debug, thiserror::Error)]
pub enum Bip276Error {
    #[error("invalid prefix: expected one of {expected:?}, got {got:?}")]
    InvalidPrefix { expected: &'static [&'static str], got: String },
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    #[error("unsupported version: expected {expected}, got {got}")]
    UnsupportedVersion { expected: u8, got: u8 },
    #[error("checksum failure: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },
    #[error("unrecognized network byte: {0}")]
    UnknownNetwork(u8),
    #[error("incompatible network: expected {expected}, got {got}")]
    NetworkMismatch { expected: u8, got: u8 },
    #[error("payload too short: need at least 6 bytes (version+network+checksum), got {0}")]
    PayloadTooShort(usize),
}

// ============================================================================
// Decoded result
// ============================================================================

/// A decoded BIP276 URI.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DecodedBip276 {
    /// URI scheme prefix (e.g. "bitcoin-script")
    pub prefix: String,
    /// BIP276 version byte (currently always 1)
    pub version: u8,
    /// Network byte
    pub network: u8,
    /// Decoded data payload (between version/network and checksum)
    pub data: Vec<u8>,
}

// ============================================================================
// Checksum
// ============================================================================

/// Compute the BIP276 checksum: first 4 bytes of double-SHA256 of the
/// full URI string *without* the checksum suffix (i.e. "prefix:payload_hex"
/// excluding the last 8 hex chars).
fn checksum(data: &[u8]) -> [u8; 4] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    let mut out = [0u8; 4];
    out.copy_from_slice(&second[..4]);
    out
}

// ============================================================================
// Encode
// ============================================================================

/// Encode data as a BIP276 URI string.
///
/// # Arguments
/// * `prefix` - URI prefix ("bitcoin-script" or "bitcoin-template")
/// * `data` - raw data bytes to encode
/// * `network` - network identifier byte
/// * `version` - BIP276 version (currently must be 1)
pub fn bip276_encode(
    prefix: &str,
    data: &[u8],
    network: Bip276Network,
    version: u8,
) -> Result<String, Bip276Error> {
    if version != CURRENT_VERSION {
        return Err(Bip276Error::UnsupportedVersion {
            expected: CURRENT_VERSION,
            got: version,
        });
    }

    let mut payload_bytes = Vec::with_capacity(2 + data.len());
    payload_bytes.push(version);
    payload_bytes.push(network as u8);
    payload_bytes.extend_from_slice(data);
    let payload_hex = hex::encode(&payload_bytes);

    let uri_without_checksum = format!("{prefix}:{payload_hex}");
    let cs = checksum(uri_without_checksum.as_bytes());
    let cs_hex = hex::encode(&cs);

    Ok(format!("{uri_without_checksum}{cs_hex}"))
}

/// Convenience: encode with defaults (mainnet, version 1).
pub fn bip276_encode_default(prefix: &str, data: &[u8]) -> Result<String, Bip276Error> {
    bip276_encode(prefix, data, Bip276Network::Mainnet, CURRENT_VERSION)
}

// ============================================================================
// Decode
// ============================================================================

/// Decode a BIP276 URI string.
///
/// If `expected_network` is provided, validates that the encoded network
/// matches; otherwise returns an error.
pub fn bip276_decode(
    text: &str,
    expected_network: Option<Bip276Network>,
) -> Result<DecodedBip276, Bip276Error> {
    let text = text.trim();

    // Split prefix:payload
    let colon_pos = text.find(':').ok_or_else(|| Bip276Error::InvalidPrefix {
        expected: &[PREFIX_BIP276_SCRIPT, PREFIX_TEMPLATE],
        got: text.to_string(),
    })?;
    let prefix = &text[..colon_pos];
    let payload_hex = &text[colon_pos + 1..];

    // Validate prefix
    if prefix != PREFIX_BIP276_SCRIPT && prefix != PREFIX_TEMPLATE {
        return Err(Bip276Error::InvalidPrefix {
            expected: &[PREFIX_BIP276_SCRIPT, PREFIX_TEMPLATE],
            got: prefix.to_string(),
        });
    }

    // Decode payload hex to bytes
    let payload_bytes = hex::decode(payload_hex).map_err(|e| Bip276Error::InvalidHex(e.to_string()))?;

    // Need at least: version(1) + network(1) + checksum(4) = 6 bytes
    if payload_bytes.len() < 6 {
        return Err(Bip276Error::PayloadTooShort(payload_bytes.len()));
    }

    let checksum_bytes = &payload_bytes[payload_bytes.len() - 4..];
    let version = payload_bytes[0];
    let data_network = payload_bytes[1];
    let data = payload_bytes[2..payload_bytes.len() - 4].to_vec();

    // Validate version
    if version != CURRENT_VERSION {
        return Err(Bip276Error::UnsupportedVersion {
            expected: CURRENT_VERSION,
            got: version,
        });
    }

    // Validate checksum: recompute over text minus last 8 hex chars
    let uri_without_checksum = &text[..text.len() - 8];
    let local_checksum = checksum(uri_without_checksum.as_bytes());
    if checksum_bytes != local_checksum {
        return Err(Bip276Error::ChecksumMismatch {
            expected: hex::encode(checksum_bytes),
            actual: hex::encode(&local_checksum),
        });
    }

    // Validate network is known
    if Bip276Network::from_byte(data_network).is_none() {
        return Err(Bip276Error::UnknownNetwork(data_network));
    }

    // Validate expected network if provided
    if let Some(expected) = expected_network {
        if data_network != expected as u8 {
            return Err(Bip276Error::NetworkMismatch {
                expected: expected as u8,
                got: data_network,
            });
        }
    }

    Ok(DecodedBip276 {
        prefix: prefix.to_string(),
        version,
        network: data_network,
        data,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Round-trip tests ---

    #[test]
    fn test_encode_decode_roundtrip() {
        let data = b"Hello BSV!";
        let encoded = bip276_encode_default(PREFIX_BIP276_SCRIPT, data).expect("encode failed");
        let decoded = bip276_decode(&encoded, None).expect("decode failed");

        assert_eq!(decoded.prefix, PREFIX_BIP276_SCRIPT);
        assert_eq!(decoded.version, CURRENT_VERSION);
        assert_eq!(decoded.network, Bip276Network::Mainnet as u8);
        assert_eq!(decoded.data, data);
    }

    #[test]
    fn test_encode_decode_testnet() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let encoded =
            bip276_encode(PREFIX_BIP276_SCRIPT, &data, Bip276Network::Testnet, CURRENT_VERSION)
                .expect("encode failed");
        let decoded = bip276_decode(&encoded, Some(Bip276Network::Testnet))
            .expect("decode failed");

        assert_eq!(decoded.network, Bip276Network::Testnet as u8);
        assert_eq!(decoded.data, data);
    }

    // --- Checksum validation ---

    #[test]
    fn test_checksum_mismatch_detected() {
        let data = b"test data";
        let encoded = bip276_encode_default(PREFIX_BIP276_SCRIPT, data).expect("encode failed");

        // Corrupt the last checksum byte (flip last hex char)
        let mut corrupted = encoded.clone();
        let last_char = corrupted.chars().last().expect("non-empty");
        let new_char = if last_char == '0' { '1' } else { '0' };
        corrupted.pop();
        corrupted.push(new_char);

        let result = bip276_decode(&corrupted, None);
        assert!(matches!(result, Err(Bip276Error::ChecksumMismatch { .. })));
    }

    // --- Network mismatch ---

    #[test]
    fn test_network_mismatch_detected() {
        let data = b"payload";
        let encoded =
            bip276_encode(PREFIX_BIP276_SCRIPT, data, Bip276Network::Testnet, CURRENT_VERSION)
                .expect("encode failed");

        // Decode expecting mainnet → should fail
        let result = bip276_decode(&encoded, Some(Bip276Network::Mainnet));
        assert!(matches!(result, Err(Bip276Error::NetworkMismatch { .. })));
    }

    // --- Invalid prefix ---

    #[test]
    fn test_invalid_prefix_rejected() {
        let data = b"payload";
        let encoded = bip276_encode_default(PREFIX_BIP276_SCRIPT, data).expect("encode failed");
        // Replace prefix with bogus one
        let bogus = encoded.replacen(PREFIX_BIP276_SCRIPT, "bitcoin-bogus", 1);
        let result = bip276_decode(&bogus, None);
        assert!(matches!(result, Err(Bip276Error::InvalidPrefix { .. })));
    }

    // --- Unsupported version ---

    #[test]
    fn test_unsupported_version_rejected() {
        let result = bip276_encode(PREFIX_BIP276_SCRIPT, b"x", Bip276Network::Mainnet, 99);
        assert!(matches!(result, Err(Bip276Error::UnsupportedVersion { .. })));
    }

    // --- Template prefix works ---

    #[test]
    fn test_template_prefix_roundtrip() {
        let data = [0x76, 0xa9, 0x14]; // fragment of a P2PKH script
        let encoded =
            bip276_encode_default(PREFIX_TEMPLATE, &data).expect("encode failed");
        let decoded = bip276_decode(&encoded, None).expect("decode failed");
        assert_eq!(decoded.prefix, PREFIX_TEMPLATE);
        assert_eq!(decoded.data, data);
    }

    // --- Empty data ---

    #[test]
    fn test_empty_data_roundtrip() {
        let encoded = bip276_encode_default(PREFIX_BIP276_SCRIPT, &[]).expect("encode failed");
        let decoded = bip276_decode(&encoded, None).expect("decode failed");
        assert!(decoded.data.is_empty());
    }

    // --- Network enum ---

    #[test]
    fn test_network_from_byte() {
        assert_eq!(Bip276Network::from_byte(1), Some(Bip276Network::Mainnet));
        assert_eq!(Bip276Network::from_byte(2), Some(Bip276Network::Testnet));
        assert_eq!(Bip276Network::from_byte(3), Some(Bip276Network::ScalingTestnet));
        assert_eq!(Bip276Network::from_byte(4), Some(Bip276Network::Regtest));
        assert_eq!(Bip276Network::from_byte(0), None);
        assert_eq!(Bip276Network::from_byte(99), None);
    }

    // --- Payload too short ---

    #[test]
    fn test_payload_too_short() {
        // 4 hex chars = 2 bytes, but we need at least 6
        let result = bip276_decode("bitcoin-script:0102", None);
        assert!(matches!(result, Err(Bip276Error::PayloadTooShort(_))));
    }

    // --- Invalid hex ---

    #[test]
    fn test_invalid_hex_rejected() {
        let result = bip276_decode("bitcoin-script:zzzz", None);
        assert!(matches!(result, Err(Bip276Error::InvalidHex(_))));
    }
}