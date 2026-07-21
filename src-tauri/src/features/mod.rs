// features/mod.rs — BSV on-chain data protocol detection
//
// Controller+Handle architecture:
// - OnChainDataDetector trait = Handle interface
// - DetectorController = Registry with register/get/has + detect_all (fallback chain)
// - OrdinalDetector, OpReturnDetector, StasTokenDetector = concrete handles
// - init_detectors() = Composition Root (idempotent)
//
// Ported from Python archive:
// - features/ordinals.py -> features/ordinals.rs (detection logic)
// - features/op_return_decode.py -> features/op_return_decode.rs (detection logic)
// - feature_controller.py STASTokenFeature -> features/stas_tokens.rs (detection logic)

// Standalone feature modules (not OnChainDataDetectors — they don't classify
// script outputs. These are services / parsers used elsewhere in the app.)
pub mod bip276;       // BIP276 bitcoin-script:// URI parser with checksum
pub mod cosigner_pool; // Cosigner transaction pool for multi-sig
pub mod exchange_rate; // Multi-provider BSV fiat exchange rates
pub mod label_sync;   // Wallet label synchronization across devices
pub mod mapi;         // BSV Merchant API (fee quotes, merkle proofs, ds-check)
pub mod ordinals;
pub mod op_return_decode;
pub mod paymail;      // BSV PayMail address resolution
pub mod spv_channels; // SPV Channels protocol (encrypted P2P)
pub mod stas_tokens;

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// ============================================================================
// Handle Interface — OnChainDataDetector trait
// ============================================================================

/// A detector that classifies a transaction output's on-chain data.
///
/// Each detector tries to identify a specific category of BSV on-chain data
/// (1Sat Ordinals, OP_RETURN protocols, STAS tokens, etc.). The controller
/// runs all registered detectors in insertion order (fallback chain) and
/// returns the first match.
pub trait OnChainDataDetector: Send + Sync {
    /// Stable unique identifier for this detector (e.g. "ordinal", "op_return", "stas").
    fn get_id(&self) -> &'static str;

    /// Try to decode on-chain data from a scriptPubKey.
    ///
    /// Returns Some(DecodedKind) if this detector recognizes the pattern,
    /// None otherwise. The controller calls detectors in insertion order
    /// and uses the first match.
    fn detect(&self, value: u64, script_hex: &str) -> Option<DecodedKind>;
}

// ============================================================================
// Data types — decoded output classification
// ============================================================================

/// A decoded on-chain data item attached to a transaction output.
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct DecodedOutput {
    /// Output index in the transaction
    pub output_index: usize,
    /// Value in satoshis
    pub value: u64,
    /// ScriptPubKey hex
    pub script_pubkey_hex: String,
    /// What kind of on-chain data this output carries
    pub kind: DecodedKind,
}

/// The category of decoded on-chain data.
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DecodedKind {
    /// 1Sat Ordinal inscription (NFT)
    Ordinal(OrdinalInscription),
    /// OP_RETURN protocol data (B, MAP, Bcat, BAP, 21E8)
    OpReturnProtocol(OpReturnProtocol),
    /// STAS token transfer
    StasToken(StasTokenTransfer),
    /// Standard P2PKH output — no special on-chain data
    Plain,
}

/// A 1Sat Ordinal inscription detected in a 1-satoshi output.
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct OrdinalInscription {
    pub protocol: String,
    pub content_type: String,
    pub content_hex: String,
    pub content_text: Option<String>,
}

/// An OP_RETURN protocol data payload.
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct OpReturnProtocol {
    pub protocol: String,
    pub data: serde_json::Value,
}

/// A STAS token transfer detected in a transaction output.
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct StasTokenTransfer {
    pub symbol: Option<String>,
    pub contract_txid: Option<String>,
    pub amount: Option<u64>,
    pub script_hex: String,
}

// ============================================================================
// Controller — DetectorController
// ============================================================================

/// Registry for on-chain data detectors.
///
/// Uses insertion-ordered storage for deterministic fallback chains.
/// The first registered detector that matches wins.
///
/// Thread-safe via Mutex. The controller is a singleton behind OnceLock.
pub struct DetectorController {
    detectors: Mutex<Vec<Box<dyn OnChainDataDetector>>>,
    ids: Mutex<HashMap<&'static str, usize>>, // id -> index in detectors vec
}

impl DetectorController {
    fn new() -> Self {
        Self {
            detectors: Mutex::new(Vec::new()),
            ids: Mutex::new(HashMap::new()),
        }
    }

    /// Register a detector. Returns an error on duplicate IDs instead of
    /// panicking, so callers can handle the failure gracefully.
    pub fn register(&self, detector: Box<dyn OnChainDataDetector>) -> Result<(), String> {
        let id = detector.get_id();
        let mut ids = self.ids.lock().unwrap();
        if ids.contains_key(id) {
            return Err(format!(
                "DetectorController: duplicate detector ID '{}' — already registered",
                id
            ));
        }
        let mut detectors = self.detectors.lock().unwrap();
        let idx = detectors.len();
        detectors.push(detector);
        ids.insert(id, idx);
        Ok(())
    }

    /// Check if a detector with the given ID is registered.
    pub fn has_handle(&self, id: &str) -> bool {
        self.ids.lock().unwrap().contains_key(id)
    }

    /// Get a detector by ID. Panics if not found (Fail-Fast, Prinzip 7).
    pub fn get_handle(&self, id: &str) -> Option<usize> {
        self.ids.lock().unwrap().get(id).copied()
    }

    /// Run all detectors in insertion order (fallback chain).
    ///
    /// Returns the first match, or `DecodedKind::Plain` if no detector matches.
    /// `Plain` is the explicit "no on-chain data" sentinel — not a silent null.
    pub fn detect_all(&self, value: u64, script_hex: &str) -> DecodedKind {
        let detectors = self.detectors.lock().unwrap();
        for detector in detectors.iter() {
            if let Some(kind) = detector.detect(value, script_hex) {
                return kind;
            }
        }
        DecodedKind::Plain
    }

    /// Number of registered detectors.
    pub fn len(&self) -> usize {
        self.detectors.lock().unwrap().len()
    }

    /// Whether no detectors are registered.
    pub fn is_empty(&self) -> bool {
        self.detectors.lock().unwrap().is_empty()
    }
}

// ============================================================================
// Singleton — Composition Root entrypoint
// ============================================================================

/// Global singleton controller instance.
static CONTROLLER: OnceLock<DetectorController> = OnceLock::new();

/// Get the global DetectorController, initializing it on first call.
///
/// Idempotent: subsequent calls return the same instance without
/// re-registering detectors.
pub fn controller() -> &'static DetectorController {
    CONTROLLER.get_or_init(|| {
        let ctrl = DetectorController::new();
        init_detectors(&ctrl);
        ctrl
    })
}

/// Composition Root — registers all known detectors in priority order.
///
/// Order matters: Ordinal detection runs first (most specific pattern:
/// 1-satoshi envelope), then OP_RETURN (protocol prefix matching), then
/// STAS (heuristic pattern matching). New detectors are added here without
/// modifying any dispatch logic.
fn init_detectors(ctrl: &DetectorController) {
    // Ignore errors if a detector is already registered (idempotent init).
    let _ = ctrl.register(Box::new(OrdinalDetector));
    let _ = ctrl.register(Box::new(OpReturnDetector));
    let _ = ctrl.register(Box::new(StasTokenDetector));
}

// ============================================================================
// Concrete Handles — wrap the detection logic modules
// ============================================================================

/// Detector for 1Sat Ordinal inscriptions (NFTs).
struct OrdinalDetector;

impl OnChainDataDetector for OrdinalDetector {
    fn get_id(&self) -> &'static str {
        "ordinal"
    }

    fn detect(&self, value: u64, script_hex: &str) -> Option<DecodedKind> {
        ordinals::detect_ordinal_inscription(script_hex, value)
            .map(DecodedKind::Ordinal)
    }
}

/// Detector for OP_RETURN protocol data (B, MAP, Bcat, BAP, 21E8).
struct OpReturnDetector;

impl OnChainDataDetector for OpReturnDetector {
    fn get_id(&self) -> &'static str {
        "op_return"
    }

    fn detect(&self, _value: u64, script_hex: &str) -> Option<DecodedKind> {
        op_return_decode::parse_op_return(script_hex)
            .map(DecodedKind::OpReturnProtocol)
    }
}

/// Detector for STAS token transfers.
struct StasTokenDetector;

impl OnChainDataDetector for StasTokenDetector {
    fn get_id(&self) -> &'static str {
        "stas"
    }

    fn detect(&self, value: u64, script_hex: &str) -> Option<DecodedKind> {
        stas_tokens::detect_stas_transfer(script_hex, value)
            .map(DecodedKind::StasToken)
    }
}

// ============================================================================
// Public API — uses the controller
// ============================================================================

/// Decode all outputs of a transaction, classifying each output.
///
/// Returns a Vec<DecodedOutput> with one entry per output.
pub fn decode_outputs(outputs: &[(u64, String)]) -> Vec<DecodedOutput> {
    let ctrl = controller();
    outputs
        .iter()
        .enumerate()
        .map(|(i, (value, script_hex))| {
            let kind = ctrl.detect_all(*value, script_hex);
            DecodedOutput {
                output_index: i,
                value: *value,
                script_pubkey_hex: script_hex.clone(),
                kind,
            }
        })
        .collect()
}

/// Classify a single scriptPubKey using the detector controller.
pub fn decode_script(value: u64, script_hex: &str) -> DecodedKind {
    controller().detect_all(value, script_hex)
}

// ============================================================================
// Tests — Controller+Handle conformance
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Fake detector for controller tests ---

    struct FakeDetector {
        id: &'static str,
        result: Option<DecodedKind>,
    }

    impl OnChainDataDetector for FakeDetector {
        fn get_id(&self) -> &'static str {
            self.id
        }
        fn detect(&self, _value: u64, _script_hex: &str) -> Option<DecodedKind> {
            self.result.clone()
        }
    }

    fn make_plain() -> DecodedKind {
        DecodedKind::Plain
    }

    fn make_fake_kind(id: &str) -> DecodedKind {
        DecodedKind::OpReturnProtocol(OpReturnProtocol {
            protocol: id.to_string(),
            data: serde_json::Value::Null,
        })
    }

    // --- Controller registry tests ---

    fn fresh_controller() -> DetectorController {
        DetectorController::new()
    }

    #[test]
    fn test_register_and_detect() {
        let ctrl = fresh_controller();
        ctrl.register(Box::new(FakeDetector {
            id: "fake",
            result: Some(make_fake_kind("fake")),
        })).unwrap();
        let kind = ctrl.detect_all(0, "deadbeef");
        assert!(matches!(kind, DecodedKind::OpReturnProtocol(_)));
    }

    #[test]
    fn test_duplicate_register_returns_error() {
        let ctrl = fresh_controller();
        ctrl.register(Box::new(FakeDetector {
            id: "dup",
            result: None,
        })).unwrap();
        // Second register with same ID must return an error (no panic).
        let result = ctrl.register(Box::new(FakeDetector {
            id: "dup",
            result: None,
        }));
        assert!(result.is_err(), "duplicate register must return an error");
        assert!(
            result.unwrap_err().contains("duplicate detector ID"),
            "error message must mention duplicate detector ID"
        );
    }

    #[test]
    fn test_fallback_chain_order() {
        // First detector returns None -> second wins
        let ctrl = fresh_controller();
        ctrl.register(Box::new(FakeDetector {
            id: "first",
            result: None,
        })).unwrap();
        ctrl.register(Box::new(FakeDetector {
            id: "second",
            result: Some(make_fake_kind("second")),
        })).unwrap();
        let kind = ctrl.detect_all(0, "test");
        match kind {
            DecodedKind::OpReturnProtocol(p) => assert_eq!(p.protocol, "second"),
            _ => panic!("expected second detector to win"),
        }
    }

    #[test]
    fn test_first_match_wins() {
        // Both match -> first in insertion order wins
        let ctrl = fresh_controller();
        ctrl.register(Box::new(FakeDetector {
            id: "first",
            result: Some(make_fake_kind("first")),
        })).unwrap();
        ctrl.register(Box::new(FakeDetector {
            id: "second",
            result: Some(make_fake_kind("second")),
        })).unwrap();
        let kind = ctrl.detect_all(0, "test");
        match kind {
            DecodedKind::OpReturnProtocol(p) => assert_eq!(p.protocol, "first"),
            _ => panic!("expected first detector to win"),
        }
    }

    #[test]
    fn test_no_match_returns_plain() {
        let ctrl = fresh_controller();
        ctrl.register(Box::new(FakeDetector {
            id: "never",
            result: None,
        })).unwrap();
        let kind = ctrl.detect_all(0, "test");
        assert_eq!(kind, make_plain());
    }

    #[test]
    fn test_has_handle() {
        let ctrl = fresh_controller();
        ctrl.register(Box::new(FakeDetector {
            id: "exists",
            result: None,
        })).unwrap();
        assert!(ctrl.has_handle("exists"));
        assert!(!ctrl.has_handle("nonexistent"));
    }

    #[test]
    fn test_len_and_empty() {
        let ctrl = fresh_controller();
        assert!(ctrl.is_empty());
        ctrl.register(Box::new(FakeDetector {
            id: "one",
            result: None,
        })).unwrap();
        assert_eq!(ctrl.len(), 1);
        assert!(!ctrl.is_empty());
    }

    // --- Singleton / Composition Root tests ---

    #[test]
    fn test_controller_singleton_initialized() {
        // The global controller should have 3 detectors registered
        let ctrl = controller();
        assert_eq!(ctrl.len(), 3);
        assert!(ctrl.has_handle("ordinal"));
        assert!(ctrl.has_handle("op_return"));
        assert!(ctrl.has_handle("stas"));
    }

    #[test]
    fn test_controller_idempotent() {
        // Calling controller() multiple times returns the same instance
        let c1 = controller();
        let c2 = controller();
        assert_eq!(c1.len(), c2.len());
        // Both point to the same singleton
        assert!(std::ptr::eq(c1, c2));
    }

    // --- Integration: real detectors via controller ---

    #[test]
    fn test_decode_plain_output_via_controller() {
        let kind = decode_script(50000, "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac");
        assert_eq!(kind, DecodedKind::Plain);
    }

    #[test]
    fn test_decode_empty_script_via_controller() {
        let kind = decode_script(0, "");
        assert_eq!(kind, DecodedKind::Plain);
    }
}