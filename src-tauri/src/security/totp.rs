// security/totp.rs — TOTP (RFC 6238) generation and verification
//
// Provides TOTP code generation, validation with ±1 window (clock skew),
// secret generation, and serialization for encrypted storage in the
// TotpSecrets database table (migration 0027).
//
// AUD-007: TOTP is mandatory for transaction signing. Every sign_tx call
// must verify a TOTP code against the wallet's secret before signing.

use thiserror::Error;

/// TOTP configuration errors.
#[derive(Debug, Error)]
pub enum TotpError {
    #[error("TOTP secret is invalid: {0}")]
    InvalidSecret(String),
    #[error("TOTP code verification failed")]
    VerificationFailed,
    #[error("TOTP generation error: {0}")]
    Generation(String),
    #[error("system time error: {0}")]
    SystemTime(String),
}

/// TOTP configuration — standard RFC 6238 settings.
///
/// Algorithm: SHA-1 (most widely supported by authenticator apps)
/// Digits: 6 (standard)
/// Skew: 1 (±1 window = ±30s for clock skew, per RFC 6238 §5.2)
/// Step: 30 seconds
const TOTP_DIGITS: usize = 6;
const TOTP_SKEW: u8 = 1;
const TOTP_STEP: u64 = 30;

/// A TOTP instance bound to a secret and account name.
///
/// The secret is stored as raw bytes (not base32-encoded).
/// Use `generate_secret()` to create a new random secret.
/// Use `from_secret_bytes()` to reconstruct from stored bytes.
#[derive(Debug, Clone)]
pub struct TotpInstance {
    inner: totp_rs::TOTP,
}

impl TotpInstance {
    /// Create a new TOTP instance from a raw secret bytes.
    ///
    /// `account_name` is used for the otpauth:// URL (displayed in authenticator apps).
    /// `issuer` is the service name (e.g. "ElectrumSV-Mc").
    pub fn from_secret_bytes(
        secret: &[u8],
        issuer: &str,
        account_name: &str,
    ) -> Result<Self, TotpError> {
        let totp = totp_rs::TOTP::new(
            totp_rs::Algorithm::SHA1,
            TOTP_DIGITS,
            TOTP_SKEW,
            TOTP_STEP,
            secret.to_vec(),
            Some(issuer.to_string()),
            account_name.to_string(),
        )
        .map_err(|e| TotpError::InvalidSecret(e.to_string()))?;

        Ok(TotpInstance { inner: totp })
    }

    /// Generate a new random TOTP secret (160 bits = 20 bytes, RFC recommended).
    pub fn generate_secret() -> Vec<u8> {
        use rand::RngCore;
        let mut buf = [0u8; 20]; // 160 bits
        rand::rngs::OsRng.fill_bytes(&mut buf);
        buf.to_vec()
    }

    /// Create a new TOTP instance with a freshly generated secret.
    pub fn new(issuer: &str, account_name: &str) -> Result<Self, TotpError> {
        let secret = Self::generate_secret();
        Self::from_secret_bytes(&secret, issuer, account_name)
    }

    /// Generate the current TOTP code.
    pub fn generate_current(&self) -> Result<String, TotpError> {
        self.inner
            .generate_current()
            .map_err(|e| TotpError::SystemTime(e.to_string()))
    }

    /// Verify a TOTP code against the current time window.
    ///
    /// Returns true if the code is valid within the ±1 skew window.
    /// AUD-007: This must be called before every transaction signing operation.
    pub fn verify_current(&self, code: &str) -> Result<bool, TotpError> {
        self.inner
            .check_current(code)
            .map_err(|e| TotpError::SystemTime(e.to_string()))
    }

    /// Verify a TOTP code at a specific timestamp (for testing).
    pub fn verify_at(&self, code: &str, timestamp: u64) -> bool {
        self.inner.check(code, timestamp)
    }

    /// Generate a TOTP code at a specific timestamp (for testing).
    pub fn generate_at(&self, timestamp: u64) -> String {
        self.inner.generate(timestamp)
    }

    /// Get the raw secret bytes (for encrypted storage).
    pub fn secret_bytes(&self) -> &[u8] {
        &self.inner.secret
    }

    /// Get the base32-encoded secret (for display/QR code).
    pub fn secret_base32(&self) -> String {
        self.inner.get_secret_base32()
    }

    /// Get the otpauth:// URL (for QR code generation).
    pub fn otpauth_url(&self) -> String {
        self.inner.get_url()
    }

    /// Get the time remaining until the next TOTP window (TTL in seconds).
    pub fn ttl(&self) -> Result<u64, TotpError> {
        self.inner
            .ttl()
            .map_err(|e| TotpError::SystemTime(e.to_string()))
    }
}

// ============================================================================
// Recovery codes (Milestone 8-C)
// ============================================================================

/// Charset for recovery codes: uppercase alphanumeric (no ambiguous chars).
const RECOVERY_CODE_CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Generate `count` random recovery codes in format "XXXX-XXXX".
///
/// Each code is 8 characters (uppercase alphanumeric, no ambiguous chars like
/// 0/O/1/I) split by a dash in the middle. Uses `OsRng` for cryptographic randomness.
pub fn generate_recovery_codes(count: usize) -> Vec<String> {
    use rand::Rng;

    let mut rng = rand::rngs::OsRng;
    let charset_len = RECOVERY_CODE_CHARSET.len();

    (0..count)
        .map(|_| {
            let mut chars = [0u8; 8];
            for i in 0..8 {
                chars[i] = RECOVERY_CODE_CHARSET[rng.gen_range(0..charset_len)];
            }
            let part1 = std::str::from_utf8(&chars[0..4]).unwrap();
            let part2 = std::str::from_utf8(&chars[4..8]).unwrap();
            format!("{}-{}", part1, part2)
        })
        .collect()
}

/// Hash a recovery code with SHA256 and return the hex digest.
///
/// Used to store recovery codes securely — only the hash is persisted,
/// the plaintext code is shown to the user exactly once.
pub fn hash_recovery_code(code: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 test vector: secret = "12345678901234567890" (ASCII)
    // Time = 59 → TOTP = 94287082 (8 digits with SHA-1)
    // Our config uses 6 digits, so we verify the generation/verification logic
    // rather than exact RFC values (which use 8 digits).

    const TEST_SECRET: &[u8] = b"12345678901234567890";

    fn make_test_totp() -> TotpInstance {
        TotpInstance::from_secret_bytes(TEST_SECRET, "TestWallet", "test@example.com").unwrap()
    }

    #[test]
    fn test_generate_and_verify_same_window() {
        let totp = make_test_totp();
        let timestamp = 1_000_000;
        let code = totp.generate_at(timestamp);
        assert_eq!(code.len(), 6);
        assert!(totp.verify_at(&code, timestamp));
    }

    #[test]
    fn test_verify_wrong_code() {
        let totp = make_test_totp();
        let timestamp = 1_000_000;
        assert!(!totp.verify_at("000000", timestamp));
    }

    #[test]
    fn test_verify_within_skew_window() {
        let totp = make_test_totp();
        let timestamp = 1_000_000;
        let code = totp.generate_at(timestamp);

        // ±1 window (±30s) should be valid
        assert!(totp.verify_at(&code, timestamp + 30)); // next window
        assert!(totp.verify_at(&code, timestamp - 30)); // previous window
    }

    #[test]
    fn test_verify_outside_skew_window() {
        let totp = make_test_totp();
        let timestamp = 1_000_000;
        let code = totp.generate_at(timestamp);

        // ±2 windows (±60s) should be invalid
        assert!(!totp.verify_at(&code, timestamp + 60));
        assert!(!totp.verify_at(&code, timestamp - 60));
    }

    #[test]
    fn test_generate_secret_is_20_bytes() {
        let secret = TotpInstance::generate_secret();
        assert_eq!(secret.len(), 20); // 160 bits
    }

    #[test]
    fn test_generate_secret_is_random() {
        let s1 = TotpInstance::generate_secret();
        let s2 = TotpInstance::generate_secret();
        assert_ne!(s1, s2, "secrets should be random");
    }

    #[test]
    fn test_new_totp_with_generated_secret() {
        let totp = TotpInstance::new("ElectrumSV-Mc", "user@wallet").unwrap();
        let code = totp.generate_current().unwrap();
        assert_eq!(code.len(), 6);
        assert!(totp.verify_current(&code).unwrap());
    }

    #[test]
    fn test_secret_base32_roundtrip() {
        let totp = make_test_totp();
        let b32 = totp.secret_base32();
        assert!(!b32.is_empty());

        // Decode base32 back to raw bytes
        let decoded = totp_rs::Secret::Encoded(b32).to_bytes().unwrap();
        assert_eq!(decoded, TEST_SECRET);
    }

    #[test]
    fn test_otpauth_url_format() {
        let totp = make_test_totp();
        let url = totp.otpauth_url();
        assert!(url.starts_with("otpauth://totp/"));
        assert!(url.contains("issuer=TestWallet"));
    }

    #[test]
    fn test_secret_bytes_match_input() {
        let totp = make_test_totp();
        assert_eq!(totp.secret_bytes(), TEST_SECRET);
    }

    #[test]
    fn test_code_is_numeric() {
        let totp = make_test_totp();
        let code = totp.generate_at(1234567890);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_ttl_is_within_step() {
        let totp = make_test_totp();
        let ttl = totp.ttl().unwrap();
        assert!(ttl <= 30, "TTL should be <= 30 seconds, got {}", ttl);
    }

    #[test]
    fn test_invalid_secret_too_short() {
        // Secret must be at least 128 bits (16 bytes)
        let result = TotpInstance::from_secret_bytes(&[0u8; 10], "test", "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_empty_code() {
        let totp = make_test_totp();
        assert!(!totp.verify_at("", 1_000_000));
    }
}
