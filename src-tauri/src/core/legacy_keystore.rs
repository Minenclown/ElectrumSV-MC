// core/legacy_keystore.rs — Legacy ElectrumSV (pre-BIP39) key derivation
//
// Implements the old ElectrumSV key derivation algorithm used by ElectrumSV 1.3.x:
// - stretch_key: 100000 rounds of SHA256(x + seed) to derive the secret exponent (secexp)
// - derive_mpk: derive the master public key (uncompressed, without 0x04 prefix)
// - get_sequence: deterministic sequence number for (change, index) derivation
// - derive_pubkey: derive a child public key from the MPK
// - derive_private_key: derive a child private key from the seed + MPK
// - pubkey_to_p2pkh_address_uncompressed: P2PKH address from uncompressed pubkey
// - is_legacy_seed: detect whether a seed string is a legacy ElectrumSV seed
//
// Reference: SPECIFICATION-LEGACY-MIGRATION.md

use bsv::primitives::base_point::BasePoint;
use bsv::primitives::big_number::{BigNumber, Endian};
use bsv::primitives::curve::Curve;
use bsv::primitives::private_key::PrivateKey;
use bsv::primitives::public_key::PublicKey;
use sha2::{Digest, Sha256};

use crate::core::legacy_mnemonic;

/// The secp256k1 curve order n.
///
/// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
pub fn curve_order() -> BigNumber {
    Curve::secp256k1().n.clone()
}

/// Double SHA-256: SHA256(SHA256(data)).
fn sha256d(data: &[u8]) -> Vec<u8> {
    let h1 = Sha256::digest(data);
    let h2 = Sha256::digest(&h1);
    h2.to_vec()
}

/// Stretch a legacy seed through 100000 rounds of SHA256(x + seed).
///
/// This produces the secret exponent (secexp) used as the master private key.
/// Algorithm: x = seed_bytes; repeat 100000 times: x = SHA256(x + seed_bytes).
/// Returns the result as a BigNumber (big-endian interpretation of the final hash).
pub fn stretch_key(seed_bytes: &[u8]) -> BigNumber {
    let mut x = seed_bytes.to_vec();
    for _ in 0..100_000 {
        let mut input = Vec::with_capacity(x.len() + seed_bytes.len());
        input.extend_from_slice(&x);
        input.extend_from_slice(seed_bytes);
        x = Sha256::digest(&input).to_vec();
    }
    BigNumber::from_bytes(&x, Endian::Big)
}

/// Derive the master public key (MPK) from a hex seed string.
///
/// Steps:
/// 1. stretch_key(seed_bytes) -> secexp
/// 2. PrivateKey::from_bytes(secexp_be_32) -> master private key
/// 3. to_public_key() -> master public key (uncompressed)
/// 4. to_der_uncompressed() -> 65 bytes (0x04 + X + Y)
/// 5. Strip the 0x04 prefix -> 64 bytes -> hex string (128 hex chars)
pub fn derive_mpk(hex_seed: &str) -> Result<String, String> {
    let seed_bytes = hex_seed.as_bytes();
    let secexp = stretch_key(seed_bytes);
    let secexp_bytes = secexp.to_array(Endian::Big, Some(32));
    let priv_key = PrivateKey::from_bytes(&secexp_bytes)
        .map_err(|e| format!("failed to create master private key: {}", e))?;
    let pub_key = priv_key.to_public_key();
    let uncompressed = pub_key.to_der_uncompressed(); // 65 bytes: 0x04 + X(32) + Y(32)
    // Strip the 0x04 prefix, return hex of X + Y (128 hex chars = 64 bytes)
    Ok(hex::encode(&uncompressed[1..]))
}

/// Compute the sequence number z for a given (change, index) pair.
///
/// The legacy Electrum derivation reverses the path: (index, change) instead of
/// (change, index). The data hashed is:
///   format!("{}:{}:", index, change).as_bytes() + bytes_from_hex(mpk)
/// Then z = bytes_to_int_be(SHA256d(data)).
pub fn get_sequence(mpk: &str, change: u32, index: u32) -> Result<BigNumber, String> {
    // Legacy Electrum reverses (change, index) to (index, change)
    let prefix = format!("{}:{}:", index, change);
    let mpk_bytes = hex::decode(mpk)
        .map_err(|e| format!("invalid mpk hex: {}", e))?;
    let mut data = Vec::with_capacity(prefix.len() + mpk_bytes.len());
    data.extend_from_slice(prefix.as_bytes());
    data.extend_from_slice(&mpk_bytes);
    let hash = sha256d(&data);
    Ok(BigNumber::from_bytes(&hash, Endian::Big))
}

/// Derive a child public key from the MPK for a given (change, index).
///
/// Steps:
/// 1. z = get_sequence(mpk, change, index)
/// 2. master_pubkey = PublicKey::from_der_bytes("04" + mpk)
/// 3. offset_point = G * z  (base point multiplication)
/// 4. child_pubkey = master_pubkey.point + offset_point
pub fn derive_pubkey(mpk: &str, change: u32, index: u32) -> Result<PublicKey, String> {
    let z = get_sequence(mpk, change, index)?;

    // Parse the master public key: prepend 0x04 to the 64-byte mpk
    let mpk_bytes = hex::decode(mpk)
        .map_err(|e| format!("invalid mpk hex: {}", e))?;
    if mpk_bytes.len() != 64 {
        return Err(format!("invalid mpk length: expected 64 bytes, got {}", mpk_bytes.len()));
    }
    let mut der_bytes = Vec::with_capacity(65);
    der_bytes.push(0x04);
    der_bytes.extend_from_slice(&mpk_bytes);
    let master_pubkey = PublicKey::from_der_bytes(&der_bytes)
        .map_err(|e| format!("failed to parse master public key: {}", e))?;

    // Compute z * G (base point multiplication)
    let base_point = BasePoint::instance();
    let offset_point = base_point.mul(&z);

    // child_pubkey = master_pubkey + offset_point
    let child_point = master_pubkey.point().add(&offset_point);
    Ok(PublicKey::from_point(child_point))
}

/// Derive a child private key from the seed and MPK for a given (change, index).
///
/// Steps:
/// 1. secexp = stretch_key(hex_seed.as_bytes())
/// 2. z = get_sequence(mpk, change, index)
/// 3. priv_int = (secexp + z) % CURVE_ORDER
/// 4. Return priv_int as 32 big-endian bytes
pub fn derive_private_key(
    hex_seed: &str,
    mpk: &str,
    change: u32,
    index: u32,
) -> Result<[u8; 32], String> {
    let secexp = stretch_key(hex_seed.as_bytes());
    let z = get_sequence(mpk, change, index)?;
    let sum = secexp.add(&z);
    let priv_int = sum
        .umod(&curve_order())
        .map_err(|e| format!("mod n failed: {}", e))?;
    let bytes = priv_int.to_array(Endian::Big, Some(32));
    let result: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "failed to convert private key to 32 bytes".to_string())?;
    Ok(result)
}

/// Generate a P2PKH mainnet address from an UNCOMPRESSED public key.
///
/// Legacy ElectrumSV uses uncompressed public keys for P2PKH addresses.
/// This computes hash160(sha256(pubkey_uncompressed)) and encodes it as
/// a Base58Check address with version byte 0x00 (mainnet).
pub fn pubkey_to_p2pkh_address_uncompressed(pubkey: &PublicKey) -> String {
    let uncompressed_der = pubkey.to_der_uncompressed(); // 65 bytes: 0x04 + X + Y
    // hash160 = RIPEMD160(SHA256(pubkey))
    let sha = Sha256::digest(&uncompressed_der);
    // Use bsv-sdk's ripemd160
    let hash160 = bsv::primitives::hash::ripemd160(&sha);
    // Base58Check encode with version byte 0x00 (mainnet P2PKH)
    bsv::primitives::utils::base58_check_encode(&hash160, &[0x00])
}

/// Detect whether a seed string is a legacy ElectrumSV seed.
///
/// A legacy seed is either:
/// - A hex string of 16 or 32 bytes (32 or 64 hex chars), or
/// - A sequence of 12 or 24 words that can be decoded by mn_decode (legacy wordlist)
///
/// BIP39 seeds are NOT legacy seeds (they use a different wordlist and checksums).
pub fn is_legacy_seed(words: &str) -> bool {
    let trimmed = words.trim();
    let word_list: Vec<&str> = trimmed.split_whitespace().collect();

    // Try hex interpretation: 16 bytes (32 hex chars) or 32 bytes (64 hex chars)
    let is_hex = hex::decode(trimmed)
        .map(|bytes| bytes.len() == 16 || bytes.len() == 32)
        .unwrap_or(false);

    if is_hex {
        return true;
    }

    // Try legacy mn_decode: word count must be 12 or 24, and mn_decode must succeed
    let uses_electrum_words = (word_list.len() == 12 || word_list.len() == 24)
        && legacy_mnemonic::mn_decode(&word_list).is_ok();

    uses_electrum_words
}

/// Decode a legacy seed string (words or hex) into a hex seed string.
///
/// If the input is a valid hex string of the right length, returns it directly.
/// Otherwise, tries mn_decode on the word list.
pub fn decode_legacy_seed(seed_words: &str) -> Result<String, String> {
    let trimmed = seed_words.trim();

    // Try hex first
    if let Ok(bytes) = hex::decode(trimmed) {
        if bytes.len() == 16 || bytes.len() == 32 {
            return Ok(trimmed.to_string());
        }
    }

    // Try legacy mn_decode
    let word_list: Vec<&str> = trimmed.split_whitespace().collect();
    if word_list.is_empty() {
        return Err("empty seed string".to_string());
    }
    let hex_seed = legacy_mnemonic::mn_decode(&word_list)
        .map_err(|e| format!("legacy mn_decode failed: {}", e))?;
    Ok(hex_seed)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Test vector: 16-byte seed (32 hex chars)
    const TEST_HEX_SEED: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn test_stretch_key_known_vector() {
        // stretch_key is deterministic — same input always produces same output
        let seed_bytes = TEST_HEX_SEED.as_bytes();
        let result1 = stretch_key(seed_bytes);
        let result2 = stretch_key(seed_bytes);

        // Both should be the same (deterministic)
        assert_eq!(result1.cmp(&result2), 0);

        // The result should be a 256-bit number (32 bytes)
        let bytes = result1.to_array(Endian::Big, Some(32));
        assert_eq!(bytes.len(), 32);

        // Different seeds should produce different results
        let different_seed = b"ffffffffffffffffffffffffffffffff";
        let result3 = stretch_key(different_seed);
        assert_ne!(result1.cmp(&result3), 0);
    }

    #[test]
    fn test_derive_mpk_returns_64_byte_hex() {
        let mpk = derive_mpk(TEST_HEX_SEED).expect("derive_mpk should succeed");

        // MPK should be 128 hex chars (64 bytes = X + Y without 0x04 prefix)
        assert_eq!(mpk.len(), 128);
        // Should be valid hex
        assert!(hex::decode(&mpk).is_ok());
        // Should be deterministic
        let mpk2 = derive_mpk(TEST_HEX_SEED).expect("second derive_mpk");
        assert_eq!(mpk, mpk2);
    }

    #[test]
    fn test_get_sequence_deterministic() {
        let mpk = derive_mpk(TEST_HEX_SEED).unwrap();

        // Same inputs should produce the same sequence
        let seq1 = get_sequence(&mpk, 0, 0).unwrap();
        let seq2 = get_sequence(&mpk, 0, 0).unwrap();
        assert_eq!(seq1.cmp(&seq2), 0);

        // Different indices should produce different sequences
        let seq3 = get_sequence(&mpk, 0, 1).unwrap();
        assert_ne!(seq1.cmp(&seq3), 0);

        // Different change should produce different sequences
        let seq4 = get_sequence(&mpk, 1, 0).unwrap();
        assert_ne!(seq1.cmp(&seq4), 0);
    }

    #[test]
    fn test_derive_pubkey_and_address() {
        let mpk = derive_mpk(TEST_HEX_SEED).expect("derive_mpk");

        // Derive a public key at change=0, index=0
        let pubkey = derive_pubkey(&mpk, 0, 0).expect("derive_pubkey");

        // The derived pubkey should be valid (on the curve)
        assert!(pubkey.point().validate());

        // Generate an address from the uncompressed pubkey
        let address = pubkey_to_p2pkh_address_uncompressed(&pubkey);

        // Mainnet P2PKH addresses start with "1"
        assert!(
            address.starts_with('1'),
            "expected mainnet P2PKH address starting with '1', got: {}",
            address
        );
        // Address should be 26-35 chars
        assert!(address.len() >= 26 && address.len() <= 35);

        // Derive the private key for the same path and verify the address matches
        let priv_bytes = derive_private_key(TEST_HEX_SEED, &mpk, 0, 0).expect("derive_private_key");
        let priv_key = PrivateKey::from_bytes(&priv_bytes).expect("valid private key");
        let derived_pubkey = priv_key.to_public_key();

        // The address from the derived private key's uncompressed pubkey should match
        let address2 = pubkey_to_p2pkh_address_uncompressed(&derived_pubkey);
        assert_eq!(
            address, address2,
            "address from derived pubkey should match address from derived private key"
        );
    }

    #[test]
    fn test_is_legacy_seed_recognizes_old_words() {
        // Encode a known hex seed into legacy words
        let hex_seed = "0123456789abcdef0123456789abcdef"; // 16 bytes = 12 words
        let words = legacy_mnemonic::mn_encode(hex_seed).expect("mn_encode");
        let word_str: String = words
            .iter()
            .map(|w| w.to_string())
            .collect::<Vec<_>>()
            .join(" ");

        assert!(
            is_legacy_seed(&word_str),
            "12 legacy words should be detected as legacy seed"
        );

        // 24-word legacy seed (32 bytes)
        let hex_seed_32 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let words_24 = legacy_mnemonic::mn_encode(hex_seed_32).expect("mn_encode 32");
        let word_str_24: String = words_24
            .iter()
            .map(|w| w.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(words_24.len(), 24);
        assert!(
            is_legacy_seed(&word_str_24),
            "24 legacy words should be detected as legacy seed"
        );
    }

    #[test]
    fn test_is_legacy_seed_recognizes_hex() {
        // 16-byte hex seed (32 hex chars)
        assert!(is_legacy_seed("0123456789abcdef0123456789abcdef"));
        // 32-byte hex seed (64 hex chars)
        assert!(
            is_legacy_seed("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn test_is_legacy_seed_rejects_bip39() {
        // BIP39 test vector — 12 words from the BIP39 wordlist.
        // "abandon abandon ... about" is a valid BIP39 mnemonic.
        // The word "abandon" is NOT in the legacy 1626-word wordlist, so mn_decode
        // should fail. Even if some BIP39 words happen to be in the legacy list,
        // the mn_decode result would be wrong length or fail the 12/24 word check.
        let bip39 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(
            !is_legacy_seed(bip39),
            "BIP39 mnemonic should not be detected as legacy seed"
        );

        // A random non-seed string
        assert!(!is_legacy_seed("hello world this is not a seed"));
        // Too few words
        assert!(!is_legacy_seed("like just love"));
        // Empty
        assert!(!is_legacy_seed(""));
    }

    #[test]
    fn test_legacy_address_uncompressed() {
        // Derive from a known seed and check the address format
        let mpk = derive_mpk(TEST_HEX_SEED).expect("derive_mpk");
        let pubkey = derive_pubkey(&mpk, 0, 0).expect("derive_pubkey");
        let address = pubkey_to_p2pkh_address_uncompressed(&pubkey);

        // Address must start with "1" (mainnet)
        assert!(address.starts_with('1'));

        // Verify the address is a valid base58check string (decodable)
        let decoded = bs58::decode(&address).into_vec();
        assert!(decoded.is_ok(), "address should be valid base58");

        // The decoded address should be 25 bytes: version(1) + hash160(20) + checksum(4)
        let bytes = decoded.unwrap();
        assert_eq!(bytes.len(), 25);
        assert_eq!(bytes[0], 0x00, "version byte should be 0x00 for mainnet");

        // The address should be deterministic
        let address2 = pubkey_to_p2pkh_address_uncompressed(&pubkey);
        assert_eq!(address, address2);
    }

    #[test]
    fn test_derive_private_key_produces_valid_key() {
        let mpk = derive_mpk(TEST_HEX_SEED).expect("derive_mpk");
        let priv_bytes = derive_private_key(TEST_HEX_SEED, &mpk, 0, 0).expect("derive_private_key");

        // Should be 32 bytes
        assert_eq!(priv_bytes.len(), 32);

        // Should be a valid private key (in range [1, n-1])
        let priv_key = PrivateKey::from_bytes(&priv_bytes).expect("should be valid private key");

        // The public key from this private key should match the derived pubkey
        let derived_pub = priv_key.to_public_key();
        let expected_pub = derive_pubkey(&mpk, 0, 0).expect("derive_pubkey");

        // Compare compressed DER — they should match
        assert_eq!(
            derived_pub.to_der_hex(),
            expected_pub.to_der_hex(),
            "public key from derived private key should match derived public key"
        );
    }

    #[test]
    fn test_decode_legacy_seed_hex() {
        // Hex input should be returned directly
        let hex = "0123456789abcdef0123456789abcdef";
        let result = decode_legacy_seed(hex).expect("decode hex seed");
        assert_eq!(result, hex);
    }

    #[test]
    fn test_decode_legacy_seed_words() {
        // Words should decode to hex
        let hex_seed = "0123456789abcdef0123456789abcdef";
        let words = legacy_mnemonic::mn_encode(hex_seed).expect("mn_encode");
        let word_str: String = words
            .iter()
            .map(|w| w.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let result = decode_legacy_seed(&word_str).expect("decode word seed");
        assert_eq!(result, hex_seed);
    }

}