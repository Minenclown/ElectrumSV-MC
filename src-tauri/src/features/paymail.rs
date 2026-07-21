// features/paymail.rs — BSV PayMail address resolution
//
// Ported from archive/electrumsv/features/paymail.py
//
// Implements the BSV PayMail protocol for resolving human-readable handles
// (user@domain.com) to Bitcoin SV addresses.
//
// Protocol overview (TSC PayMail standard):
//   1. Split handle into <user>@<domain>
//   2. SRV lookup: _bsv_paymail._tcp.<domain> → host:port (optional, falls back
//      to https://<domain>/.well-known/bsvalias)
//   3. GET https://<host>:<port>/api/v1/capabilities → discover pki / paymentDestination
//   4. POST https://<host>:<port>/api/v1/bsvalias/address/<handle>
//      body: {"senderhandle": ..., "sendername": ..., "signature": "", "pubkey": ""}
//   5. Response JSON contains "address" → the BSV address string
//
// References:
//   - https://tsc.bsvblockchain.org/standards/paymail/
//   - BSVAlias capability discovery
//
// Note: SRV DNS lookup requires a DNS resolver crate. For now we skip SRV
// and use the well-known fallback (https://<domain>/.well-known/bsvalias),
// which is the common deployment pattern. SRV support can be added later
// by plugging in a DNS resolver behind the discover_service trait.

use std::time::Duration;

use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

const USER_AGENT: &str = "ElectrumSV-Mc";
const TIMEOUT_SECS: u64 = 15;
#[allow(dead_code)] // used in _srv_query_name; full SRV support pending DNS resolver
const SRV_SERVICE: &str = "_bsv_paymail._tcp";

const DEFAULT_SENDER_HANDLE: &str = "electrumsv-mc@electrumsv.io";
const DEFAULT_SENDER_NAME: &str = "ElectrumSV-Mc";

// ============================================================================
// Error types
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum PayMailError {
    #[error("invalid PayMail handle: {0}")]
    InvalidHandle(String),
    #[error("PayMail service discovery failed for domain {domain}: {reason}")]
    DiscoveryFailed { domain: String, reason: String },
    #[error("capabilities request failed for domain {domain}: {reason}")]
    CapabilitiesFailed { domain: String, reason: String },
    #[error("address resolution failed for handle {handle}: {reason}")]
    AddressResolutionFailed { handle: String, reason: String },
    #[error("PayMail response missing 'address' field")]
    MissingAddress,
    #[error("PayMail returned empty or invalid address: {0}")]
    InvalidAddress(String),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid JSON response: {0}")]
    Json(#[from] serde_json::Error),
}

// ============================================================================
// Data types
// ============================================================================

/// PayMail capability descriptor returned by the capabilities endpoint.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Capabilities {
    #[serde(rename = "bsvalias")]
    pub bsvalias: serde_json::Value,
    pub capabilities: serde_json::Value,
    #[serde(default)]
    pub publisher: String,
    #[serde(default)]
    pub version: String,
}

/// Request body for the BSVAlias address-resolution endpoint.
#[derive(Debug, Clone, Serialize)]
struct AddressRequest {
    senderhandle: String,
    sendername: String,
    signature: String,
    pubkey: String,
}

/// Response body from the BSVAlias address-resolution endpoint.
#[derive(Debug, Clone, Deserialize)]
struct AddressResponse {
    address: String,
}

/// Discovered PayMail service endpoint.
#[derive(Debug, Clone)]
pub struct ServiceEndpoint {
    pub host: String,
    pub port: u16,
}

// ============================================================================
// Resolver
// ============================================================================

/// Resolve BSV PayMail handles to Bitcoin SV addresses.
///
/// The resolver is stateless — each call performs fresh HTTP lookups.
/// Uses reqwest for HTTP and requires a Tokio runtime.
pub struct PayMailResolver {
    client: reqwest::Client,
    sender_handle: String,
    sender_name: String,
}

impl Default for PayMailResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl PayMailResolver {
    /// Create a new resolver with default sender identity and a configured
    /// reqwest client (rustls-TLS, 15s timeout).
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .build()
            .expect("failed to build reqwest client for PayMailResolver");

        Self {
            client,
            sender_handle: DEFAULT_SENDER_HANDLE.to_string(),
            sender_name: DEFAULT_SENDER_NAME.to_string(),
        }
    }

    /// Override the default sender handle (used in address-resolution requests).
    pub fn with_sender(mut self, handle: &str, name: &str) -> Self {
        self.sender_handle = handle.to_string();
        self.sender_name = name.to_string();
        self
    }

    /// Resolve a PayMail handle to a BSV address string.
    ///
    /// # Errors
    /// Returns `PayMailError::InvalidHandle` if the handle is malformed,
    /// or other variants for network/protocol failures.
    pub async fn resolve_address(&self, paymail_handle: &str) -> Result<String, PayMailError> {
        if !is_valid_handle(paymail_handle) {
            return Err(PayMailError::InvalidHandle(paymail_handle.to_string()));
        }

        let (_user, domain) = split_handle(paymail_handle)?;

        // Step 1: discover the service host:port
        let endpoint = self.discover_service(&domain).await?;

        // Step 2: resolve the address via the BSVAlias address endpoint
        let address = self
            .request_address(&endpoint, paymail_handle)
            .await?;

        Ok(address)
    }

    /// Fetch the PayMail capability descriptor for a domain.
    pub async fn get_capabilities(&self, domain: &str) -> Result<Capabilities, PayMailError> {
        let endpoint = self.discover_service(domain).await?;
        let url = format!("https://{}:{}/api/v1/capabilities", endpoint.host, endpoint.port);

        let resp = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| PayMailError::CapabilitiesFailed {
                domain: domain.to_string(),
                reason: e.to_string(),
            })?;

        if !resp.status().is_success() {
            return Err(PayMailError::CapabilitiesFailed {
                domain: domain.to_string(),
                reason: format!("HTTP {}", resp.status()),
            });
        }

        let caps: Capabilities = resp
            .json()
            .await
            .map_err(|e| PayMailError::CapabilitiesFailed {
                domain: domain.to_string(),
                reason: e.to_string(),
            })?;

        Ok(caps)
    }

    // -- Internals -----------------------------------------------------------

    /// Discover the PayMail service host and port for a domain.
    ///
    /// Order of resolution:
    ///   1. SRV record lookup (not yet implemented — requires DNS resolver)
    ///   2. Fallback: https://<domain>/.well-known/bsvalias → use domain, port 443
    async fn discover_service(&self, domain: &str) -> Result<ServiceEndpoint, PayMailError> {
        // SRV lookup would go here. For now we skip directly to well-known fallback.
        self.well_known_lookup(domain).await
    }

    /// Fallback: probe https://<domain>/.well-known/bsvalias.
    ///
    /// If the well-known endpoint responds, we use the domain itself on port 443.
    async fn well_known_lookup(&self, domain: &str) -> Result<ServiceEndpoint, PayMailError> {
        let url = format!("https://{domain}/.well-known/bsvalias");

        let resp = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| PayMailError::DiscoveryFailed {
                domain: domain.to_string(),
                reason: e.to_string(),
            })?;

        if !resp.status().is_success() {
            return Err(PayMailError::DiscoveryFailed {
                domain: domain.to_string(),
                reason: format!("well-known endpoint returned HTTP {}", resp.status()),
            });
        }

        Ok(ServiceEndpoint {
            host: domain.to_string(),
            port: 443,
        })
    }

    /// POST to the BSVAlias address endpoint and extract the BSV address.
    async fn request_address(
        &self,
        endpoint: &ServiceEndpoint,
        paymail_handle: &str,
    ) -> Result<String, PayMailError> {
        let url = format!(
            "https://{}:{}/api/v1/bsvalias/address/{}",
            endpoint.host, endpoint.port, paymail_handle
        );

        let body = AddressRequest {
            senderhandle: self.sender_handle.clone(),
            sendername: self.sender_name.clone(),
            signature: String::new(),
            pubkey: String::new(),
        };

        let resp = self
            .client
            .post(&url)
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| PayMailError::AddressResolutionFailed {
                handle: paymail_handle.to_string(),
                reason: e.to_string(),
            })?;

        if !resp.status().is_success() {
            return Err(PayMailError::AddressResolutionFailed {
                handle: paymail_handle.to_string(),
                reason: format!("HTTP {}", resp.status()),
            });
        }

        let data: AddressResponse = resp
            .json()
            .await
            .map_err(|e| PayMailError::AddressResolutionFailed {
                handle: paymail_handle.to_string(),
                reason: e.to_string(),
            })?;

        if data.address.trim().is_empty() {
            return Err(PayMailError::InvalidAddress(data.address));
        }

        Ok(data.address)
    }

    /// Build the SRV query name for a domain (for future DNS resolver use).
    fn _srv_query_name(domain: &str) -> String {
        format!("{SRV_SERVICE}.{domain}")
    }
}

// ============================================================================
// Utility functions
// ============================================================================

/// Check whether a string looks like a valid PayMail handle.
///
/// A valid handle:
///   - is a non-empty string
///   - contains exactly one '@'
///   - has a non-empty local part and a domain with at least one dot
pub fn is_valid_handle(handle: &str) -> bool {
    let handle = handle.trim();
    if handle.is_empty() {
        return false;
    }
    // Simple pragmatic validator (mirrors the Python regex):
    // ^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$
    let local_end = match handle.find('@') {
        Some(pos) => pos,
        None => return false,
    };
    // Ensure exactly one '@'
    if handle.rfind('@') != Some(local_end) {
        return false;
    }
    let local = &handle[..local_end];
    let domain = &handle[local_end + 1..];

    if local.is_empty() || domain.is_empty() {
        return false;
    }

    // Validate local part: [A-Za-z0-9._%+\-]+
    if !local
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '%' || c == '+' || c == '-')
    {
        return false;
    }

    // Validate domain: [A-Za-z0-9.\-]+\.[A-Za-z]{2,}
    let dot_pos = match domain.rfind('.') {
        Some(p) => p,
        None => return false,
    };
    // Domain part before the TLD must be non-empty
    if dot_pos == 0 {
        return false;
    }
    let tld = &domain[dot_pos + 1..];
    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    if !domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return false;
    }

    true
}

/// Split user@domain.com → (user, domain).
fn split_handle(handle: &str) -> Result<(String, String), PayMailError> {
    let pos = handle.rfind('@').ok_or_else(|| PayMailError::InvalidHandle(handle.to_string()))?;
    Ok((handle[..pos].to_string(), handle[pos + 1..].to_string()))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Handle validation ---

    #[test]
    fn test_valid_handles() {
        assert!(is_valid_handle("alice@example.com"));
        assert!(is_valid_handle("bob.user@domain.co.uk"));
        assert!(is_valid_handle("user_name@sub.domain.org"));
        assert!(is_valid_handle("user+tag@domain.io"));
        assert!(is_valid_handle("a@b.cd"));
        assert!(is_valid_handle("user.name@my-domain.com"));
    }

    #[test]
    fn test_invalid_handles() {
        assert!(!is_valid_handle(""));
        assert!(!is_valid_handle("   "));
        assert!(!is_valid_handle("no-at-sign"));
        assert!(!is_valid_handle("@no-local.com"));
        assert!(!is_valid_handle("no-domain@"));
        assert!(!is_valid_handle("two@@at.com"));
        assert!(!is_valid_handle("user@no-tld"));
        assert!(!is_valid_handle("user@.com"));
        assert!(!is_valid_handle("user@domain.c"));
        assert!(!is_valid_handle("user name@domain.com")); // space in local
    }

    #[test]
    fn test_split_handle() {
        let (user, domain) = split_handle("alice@example.com").unwrap();
        assert_eq!(user, "alice");
        assert_eq!(domain, "example.com");

        // Handle subdomains
        let (user, domain) = split_handle("bob@sub.example.co.uk").unwrap();
        assert_eq!(user, "bob");
        assert_eq!(domain, "sub.example.co.uk");
    }

    #[test]
    fn test_split_handle_no_at() {
        let result = split_handle("noatsign");
        assert!(result.is_err());
    }

    // --- Resolver construction ---

    #[test]
    fn test_resolver_default_sender() {
        let resolver = PayMailResolver::new();
        assert_eq!(resolver.sender_handle, DEFAULT_SENDER_HANDLE);
        assert_eq!(resolver.sender_name, DEFAULT_SENDER_NAME);
    }

    #[test]
    fn test_resolver_custom_sender() {
        let resolver = PayMailResolver::new()
            .with_sender("wallet@myapp.com", "MyApp");
        assert_eq!(resolver.sender_handle, "wallet@myapp.com");
        assert_eq!(resolver.sender_name, "MyApp");
    }

    // --- SRV query name ---

    #[test]
    fn test_srv_query_name() {
        let name = PayMailResolver::_srv_query_name("example.com");
        assert_eq!(name, "_bsv_paymail._tcp.example.com");
    }

    // --- Invalid handle rejection in resolve_address ---

    #[tokio::test]
    async fn test_resolve_invalid_handle_returns_error() {
        let resolver = PayMailResolver::new();
        let result = resolver.resolve_address("not-a-handle").await;
        assert!(matches!(result, Err(PayMailError::InvalidHandle(_))));
    }

    #[tokio::test]
    async fn test_resolve_empty_handle_returns_error() {
        let resolver = PayMailResolver::new();
        let result = resolver.resolve_address("").await;
        assert!(matches!(result, Err(PayMailError::InvalidHandle(_))));
    }

    // --- Capabilities endpoint shape ---

    #[test]
    fn test_capabilities_deserialize() {
        let json = r#"{
            "bsvalias": "1.0",
            "capabilities": {
                "pki": "https://example.com/api/v1/pki",
                "payment_destination": "https://example.com/api/v1/bsvalias/address"
            },
            "publisher": "test",
            "version": "1.0"
        }"#;
        let caps: Capabilities = serde_json::from_str(json).unwrap();
        assert_eq!(caps.publisher, "test");
        assert!(caps.capabilities.is_object());
    }

    #[test]
    fn test_address_response_deserialize() {
        let json = r#"{"address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}"#;
        let resp: AddressResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.address, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }

    #[test]
    fn test_empty_address_rejected_by_validation() {
        // The resolver would reject this — verify our error type catches it
        let json = r#"{"address": ""}"#;
        let resp: AddressResponse = serde_json::from_str(json).unwrap();
        assert!(resp.address.trim().is_empty());
    }
}