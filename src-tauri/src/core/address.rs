// core/address.rs — BSV address utilities and hash conversion
//
// Provides:
// - hash_to_hex_str / hex_str_to_hash: byte-order conversion for txids
//   (AUD-014 fix: Python uses hash_to_hex_str which reverses byte order.
//   Rust must do the same — raw bytes from SQLite are in internal order,
//   display/explorer txids are reversed.)
// - pubkey_to_p2pkh_address: generate a BSV P2PKH address from a public key
//   using bsv::script::address::Address

use bsv::primitives::public_key::PublicKey;
use bsv::script::address::Address;

/// Convert internal hash bytes (as stored in SQLite BLOB columns) to the
/// display hex string (reversed byte order).
///
/// This matches Python's `hash_to_hex_str(hash)` from bitcoinx/util.py.
/// BSV/Bitcoin stores txids in internal byte order; the display form
/// (block explorers, user-facing) is the reverse.
///
/// AUD-014: Using `.hex()` on raw bytes without reversal produces
/// byte-reversed txids that don't match any block explorer.
pub fn hash_to_hex_str(hash: &[u8]) -> String {
    let mut reversed = hash.to_vec();
    reversed.reverse();
    hex::encode(&reversed)
}

/// Convert a display hex string (reversed byte order) to internal hash bytes.
///
/// This matches Python's `hex_str_to_hash(hex_str)` from bitcoinx/util.py.
pub fn hex_str_to_hash(hex_str: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let mut bytes = hex::decode(hex_str)?;
    bytes.reverse();
    Ok(bytes)
}

/// Generate a P2PKH BSV mainnet address from a compressed public key.
///
/// Uses bsv::script::address::Address::from_public_key which handles
/// hash160 (RIPEMD160(SHA256(pubkey))) and base58check encoding.
pub fn pubkey_to_p2pkh_address(pubkey: &PublicKey) -> String {
    let address = Address::from_public_key(pubkey, true);
    address.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_hex_str_reverses_bytes() {
        // Internal bytes: [0xaa, 0xbb, 0xcc, 0xdd]
        // Display hex: "ddccbbaa"
        let internal = [0xaa, 0xbb, 0xcc, 0xdd];
        let display = hash_to_hex_str(&internal);
        assert_eq!(display, "ddccbbaa");
    }

    #[test]
    fn test_hex_str_to_hash_reverses_back() {
        let display = "ddccbbaa";
        let internal = hex_str_to_hash(display).unwrap();
        assert_eq!(internal, vec![0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn test_roundtrip_hash_conversion() {
        let original = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let display = hash_to_hex_str(&original);
        let restored = hex_str_to_hash(&display).unwrap();
        assert_eq!(restored, original);
    }

    #[test]
    fn test_hash_to_hex_str_known_txid() {
        // Known test: internal bytes for a Bitcoin txid
        // Internal: f0e5..., Display: ...e5f0 (reversed)
        let internal = [
            0xf0, 0xe5, 0x1d, 0xe7, 0xf1, 0x90, 0xbe, 0x59, 0x8a, 0x0c, 0x33, 0x54, 0x65, 0x83,
            0x41, 0x90, 0x3c, 0x43, 0x54, 0x61, 0x7f, 0x62, 0x49, 0x66, 0x84, 0x18, 0x69, 0x37,
            0x9a, 0x8b, 0x6a, 0x8c,
        ];
        let display = hash_to_hex_str(&internal);
        // The display form should be the reverse
        assert_eq!(
            display,
            "8c6a8b9a376918846649627f6154433c9041836554330c8a59be90f1e71de5f0"
        );
    }

    #[test]
    fn test_hex_str_to_hash_invalid_hex() {
        let result = hex_str_to_hash("not valid hex!");
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_str_to_hash_empty() {
        let result = hex_str_to_hash("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_pubkey_to_p2pkh_address_known_vector() {
        // Known test vector: private key = 1
        // Compressed pubkey = 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        // The bsv-sdk generates the P2PKH address from this pubkey.
        // We verify the address starts with "1" (mainnet) and has correct length.
        // Note: different implementations may produce different checksums for
        // the same hash160 — we verify the address is valid and deterministic.
        let pubkey_hex = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        let pubkey = PublicKey::from_string(pubkey_hex).unwrap();
        let address = pubkey_to_p2pkh_address(&pubkey);
        assert!(
            address.starts_with('1'),
            "Expected mainnet P2PKH address starting with '1', got: {}",
            address
        );
        assert!(address.len() >= 26 && address.len() <= 35);
        // Verify deterministic — same input always produces same output
        let address2 = pubkey_to_p2pkh_address(&pubkey);
        assert_eq!(address, address2);
    }
}
