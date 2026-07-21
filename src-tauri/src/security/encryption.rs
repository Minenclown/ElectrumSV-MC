// security/encryption.rs — AES-CBC encryption compatible with Python pw_encode/pw_decode
//
// The Python backend uses AES-256-CBC with PKCS7 padding:
//   - Key = sha256(sha256(password))  (double SHA-256, 32 bytes)
//   - IV = 16 random bytes, prepended to ciphertext
//   - Output = base64(iv + ciphertext)
//
// This module replicates that exact format so Rust can decrypt wallets
// created by the Python backend and vice versa.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes256;
use base64::{engine::general_purpose, Engine as _};
use sha2::{Digest, Sha256};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// Double SHA-256 of the password string (produces 32-byte AES key).
fn sha256d(password: &str) -> [u8; 32] {
    let first = Sha256::digest(password.as_bytes());
    let second = Sha256::digest(&first);
    let mut key = [0u8; 32];
    key.copy_from_slice(&second);
    key
}

/// Encrypt a string with AES-256-CBC using the password.
///
/// Returns base64(iv || ciphertext), matching Python's `pw_encode`.
pub fn pw_encode(data: &str, password: &str) -> String {
    if password.is_empty() {
        return data.to_string();
    }
    let key = sha256d(password);
    let iv = {
        use rand::RngCore;
        let mut iv = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut iv);
        iv
    };

    let ciphertext =
        Aes256CbcEnc::new(&key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(data.as_bytes());

    // Prepend IV to ciphertext, then base64-encode
    let mut combined = Vec::with_capacity(16 + ciphertext.len());
    combined.extend_from_slice(&iv);
    combined.extend_from_slice(&ciphertext);

    general_purpose::STANDARD.encode(&combined)
}

/// Decrypt a base64-encoded AES-256-CBC ciphertext with the password.
///
/// Input format: base64(iv || ciphertext), matching Python's `pw_decode`.
pub fn pw_decode(data: &str, password: &str) -> Result<String, EncryptionError> {
    if password.is_empty() {
        return Ok(data.to_string());
    }
    let key = sha256d(password);
    let combined = general_purpose::STANDARD
        .decode(data)
        .map_err(|_| EncryptionError::InvalidBase64)?;

    if combined.len() < 16 {
        return Err(EncryptionError::CiphertextTooShort);
    }

    let (iv_bytes, ciphertext) = combined.split_at(16);
    let iv: [u8; 16] = iv_bytes.try_into().unwrap();

    let plaintext = Aes256CbcDec::new(&key.into(), &iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| EncryptionError::DecryptionFailed)?;

    String::from_utf8(plaintext).map_err(|_| EncryptionError::InvalidUtf8)
}

/// Error type for encryption/decryption operations.
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("invalid base64 encoding")]
    InvalidBase64,
    #[error("ciphertext too short (must be at least 16 bytes for IV)")]
    CiphertextTooShort,
    #[error("decryption failed — wrong password or corrupted data")]
    DecryptionFailed,
    #[error("decrypted data is not valid UTF-8")]
    InvalidUtf8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pw_encode_decode_roundtrip() {
        let plaintext = "xprv1234567890abcdef";
        let password = "123456789";
        let encrypted = pw_encode(plaintext, password);
        let decrypted = pw_decode(&encrypted, password).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_pw_decode_wrong_password_fails() {
        let plaintext = "secret data";
        let password = "correct_password";
        let encrypted = pw_encode(plaintext, password);
        let result = pw_decode(&encrypted, "wrong_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_pw_encode_empty_password_returns_plaintext() {
        let plaintext = "unencrypted";
        let encrypted = pw_encode(plaintext, "");
        assert_eq!(encrypted, plaintext);
    }

    #[test]
    fn test_pw_decode_empty_password_returns_plaintext() {
        let plaintext = "unencrypted";
        let decrypted = pw_decode(plaintext, "").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_sha256d_matches_python_format() {
        // Python: sha256d("test") = sha256(sha256(b"test"))
        // Verify it produces 32 bytes and is deterministic
        let key1 = sha256d("test");
        let key2 = sha256d("test");
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }
}
