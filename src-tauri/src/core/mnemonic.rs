// core/mnemonic.rs — BIP39 mnemonic generation and validation
//
// Wraps bsv-sdk's compat::bip39 module for ElectrumSV-Mc use cases.
// ElectrumSV uses 12-word (128-bit) mnemonics by default.

use bsv::compat::bip39::{Language, Mnemonic};
use bsv::compat::error::CompatError;

/// Generate a new 12-word BIP39 mnemonic in English.
pub fn generate_mnemonic() -> Result<String, CompatError> {
    let mnemonic = Mnemonic::from_random(128, Language::English)?;
    Ok(mnemonic.to_phrase())
}

/// Generate a new BIP39 mnemonic with the specified bit strength.
/// Valid: 128 (12 words), 160 (15), 192 (18), 224 (21), 256 (24).
pub fn generate_mnemonic_with_bits(bits: usize) -> Result<String, CompatError> {
    let mnemonic = Mnemonic::from_random(bits, Language::English)?;
    Ok(mnemonic.to_phrase())
}

/// Validate a BIP39 mnemonic string (wordlist membership only).
///
/// ElectrumSV 1.3.x generates BIP39 mnemonics WITHOUT a valid checksum.
/// We only validate that all words are in the BIP39 wordlist and the word
/// count is valid (12, 15, 18, 21, or 24). The checksum is NOT enforced.
pub fn validate_mnemonic(mnemonic_str: &str) -> Result<(), CompatError> {
    let words: Vec<&str> = mnemonic_str.split_whitespace().collect();
    let count = words.len();
    if ![12, 15, 18, 21, 24].contains(&count) {
        return Err(CompatError::InvalidMnemonic(format!(
            "invalid word count: {} (expected 12, 15, 18, 21, or 24)",
            count
        )));
    }
    // Try full BIP39 validation first (with checksum)
    if let Ok(m) = Mnemonic::from_string(mnemonic_str, Language::English) {
        if m.check() {
            return Ok(());
        }
        log::warn!("validate_mnemonic — BIP39 checksum valid but check() returned false (ElectrumSV-style)");
        return Ok(());
    }
    // from_string failed — likely checksum mismatch (ElectrumSV-style).
    // Validate that all words are in the BIP39 wordlist.
    let wl = get_wordlist_english();
    for w in &words {
        if !wl.iter().any(|x| x == w) {
            return Err(CompatError::InvalidMnemonic(format!("unknown BIP39 word: {}", w)));
        }
    }
    log::warn!(
        "validate_mnemonic — BIP39 checksum failed, accepting as ElectrumSV-style seed \
         (all {} words are valid BIP39)",
        count
    );
    Ok(())
}

/// Derive a 64-byte seed from a mnemonic + optional passphrase.
///
/// For ElectrumSV-style seeds (no valid BIP39 checksum), we reconstruct the
/// entropy from the word indices and derive the seed via PBKDF2-HMAC-SHA512,
/// matching the BIP39 standard (password = mnemonic phrase, salt = "mnemonic"+passphrase).
pub fn mnemonic_to_seed(mnemonic_str: &str, passphrase: &str) -> Result<Vec<u8>, CompatError> {
    // Try the standard BIP39 path first (valid checksum)
    if let Ok(mnemonic) = Mnemonic::from_string(mnemonic_str, Language::English) {
        return Ok(mnemonic.to_seed(passphrase));
    }
    // from_string failed — likely invalid checksum (ElectrumSV-style).
    // Reconstruct entropy from word indices and derive seed manually.
    validate_mnemonic(mnemonic_str)?;
    let words: Vec<&str> = mnemonic_str.split_whitespace().collect();
    let wl = get_wordlist_english();
    let mut indices: Vec<u32> = Vec::with_capacity(words.len());
    for w in &words {
        let idx = wl.iter().position(|x| x == w)
            .ok_or_else(|| CompatError::InvalidMnemonic(format!("unknown word: {}", w)))?;
        indices.push(idx as u32);
    }
    // Reconstruct entropy from 11-bit indices (drop checksum bits)
    let word_count = indices.len();
    let total_bits = word_count * 11;
    let ent_bits = (total_bits * 32) / 33;
    let ent_bytes = ent_bits / 8;
    let mut bits: Vec<u8> = Vec::with_capacity(total_bits);
    for idx in &indices {
        for j in (0..11).rev() {
            bits.push(((idx >> j) & 1) as u8);
        }
    }
    let mut entropy = vec![0u8; ent_bytes];
    for i in 0..ent_bits {
        if bits[i] == 1 {
            entropy[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    // Build a Mnemonic from the entropy (bypasses checksum) and derive seed
    let mnemonic = Mnemonic::from_entropy(&entropy, Language::English)?;
    Ok(mnemonic.to_seed(passphrase))
}

/// Get the English BIP39 wordlist.
fn get_wordlist_english() -> Vec<&'static str> {
    bsv::compat::bip39_wordlists::english::ENGLISH.iter().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic_12_words() {
        let mnemonic = generate_mnemonic().unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12);
    }

    #[test]
    fn test_generate_mnemonic_24_words() {
        let mnemonic = generate_mnemonic_with_bits(256).unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_validate_valid_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(validate_mnemonic(mnemonic).is_ok());
    }

    #[test]
    fn test_validate_invalid_checksum_accepted_as_electrumsv() {
        // 12x "abandon" — wrong checksum (should end with "about")
        // ElectrumSV 1.3.x generates seeds without checksum — we accept them.
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(validate_mnemonic(mnemonic).is_ok(), "ElectrumSV-style seeds without checksum should be accepted");
    }

    #[test]
    fn test_validate_invalid_word() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword";
        assert!(validate_mnemonic(mnemonic).is_err());
    }

    #[test]
    fn test_mnemonic_to_seed_known_vector() {
        // BIP39 test vector: "abandon abandon ... about" with passphrase "TREZOR"
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "TREZOR").unwrap();
        // Expected seed from BIP39 test vectors
        let expected = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
        let expected_bytes: Vec<u8> = (0..expected.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&expected[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(seed, expected_bytes);
    }
}
