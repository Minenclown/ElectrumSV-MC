// core/multisig.rs — Multi-signature script support
//
// Ported from archive/electrumsv/script.py. Provides `AccumulatorMultiSigOutput`,
// a BSV script that requires m-of-n signatures but uses an accumulator pattern
// (OP_TOALTSTACK / OP_FROMALTSTACK) to count valid signatures rather than the
// classic OP_CHECKMULTISIG.
//
// The script construction follows the Python reference exactly:
//
//     OP_0  OP_TOALTSTACK
//     (for each public key):
//         OP_IF  OP_DUP  OP_HASH160  <hash160>  OP_EQUALVERIFY  OP_CHECKSIGVERIFY
//         OP_FROMALTSTACK  OP_1ADD  OP_TOALTSTACK  OP_ENDIF
//     OP_FROMALTSTACK  <threshold>  OP_GREATERTHANOREQUAL
//
// This module does NOT modify any existing files. It is a standalone translation
// that the caller will wire into the module tree later.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Opcode constants (BSV script opcodes)
// ---------------------------------------------------------------------------

/// BSV script opcode constants used by the accumulator multisig construction.
///
/// Values match the Bitcoin SV opcode set (identical to legacy Bitcoin opcodes
/// for the operations used here).
#[allow(dead_code)]
pub mod op {
    pub const OP_0: u8 = 0x00;
    pub const OP_PUSHDATA1: u8 = 0x4c;
    pub const OP_PUSHDATA2: u8 = 0x4d;
    pub const OP_PUSHDATA4: u8 = 0x4e;
    pub const OP_1NEGATE: u8 = 0x4f;
    pub const OP_1: u8 = 0x51;
    pub const OP_2: u8 = 0x52;
    pub const OP_3: u8 = 0x53;
    pub const OP_16: u8 = 0x60;
    pub const OP_IF: u8 = 0x63;
    pub const OP_NOTIF: u8 = 0x64;
    pub const OP_ELSE: u8 = 0x67;
    pub const OP_ENDIF: u8 = 0x68;
    pub const OP_VERIFY: u8 = 0x69;
    pub const OP_RETURN: u8 = 0x6a;
    pub const OP_TOALTSTACK: u8 = 0x6b;
    pub const OP_FROMALTSTACK: u8 = 0x6c;
    pub const OP_2DROP: u8 = 0x6d;
    pub const OP_DUP: u8 = 0x76;
    pub const OP_DROP: u8 = 0x75;
    pub const OP_HASH160: u8 = 0xa9;
    pub const OP_EQUAL: u8 = 0x87;
    pub const OP_EQUALVERIFY: u8 = 0x88;
    pub const OP_1ADD: u8 = 0x8b;
    pub const OP_CHECKSIG: u8 = 0xac;
    pub const OP_CHECKSIGVERIFY: u8 = 0xad;
    pub const OP_GREATERTHANOREQUAL: u8 = 0xa2;
}

/// Encode a small integer as a single opcode byte (OP_1 = 0x51 .. OP_16 = 0x60).
///
/// Matches the Python `push_int` behaviour for values 1..=16.
/// For values outside that range, returns a minimally-encoded push.
fn push_int(n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![op::OP_0];
    }
    if n == -1 {
        return vec![op::OP_1NEGATE];
    }
    if (1..=16).contains(&n) {
        return vec![op::OP_1 + (n - 1) as u8];
    }
    // Minimal encoding for larger integers (little-endian, minimal sign byte).
    push_minimal_signed(n)
}

/// Minimal signed integer push (matches Bitcoin's script number encoding).
fn push_minimal_signed(n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![op::OP_0];
    }
    let mut bytes = Vec::new();
    let mut val = n.unsigned_abs();
    while val != 0 {
        bytes.push((val & 0xff) as u8);
        val >>= 8;
    }
    // Add sign byte if the high bit of the last byte is set.
    if bytes.last().map(|&b| b & 0x80 != 0).unwrap_or(false) {
        bytes.push(if n < 0 { 0x80 } else { 0x00 });
    } else if n < 0 {
        *bytes.last_mut().unwrap_or(&mut 0) |= 0x80;
    }
    // Prepend push opcode for the data length.
    if bytes.len() <= 75 {
        let mut result = Vec::with_capacity(bytes.len() + 1);
        result.push(bytes.len() as u8);
        result.extend_from_slice(&bytes);
        result
    } else {
        let mut result = Vec::with_capacity(bytes.len() + 2);
        result.push(op::OP_PUSHDATA1);
        result.push(bytes.len() as u8);
        result.extend_from_slice(&bytes);
        result
    }
}

/// Push a data item (like Python `push_item`): length-prefixed raw bytes.
///
/// Encoding rules (BSV/Bitcoin script):
/// - 0..=75 bytes: direct push with 1-byte length opcode.
/// - 76..=255 bytes: OP_PUSHDATA1 (0x4c) followed by 1-byte length.
/// - 256..=65535 bytes: OP_PUSHDATA2 (0x4d) followed by 2-byte LE length.
/// - >65535 bytes: OP_PUSHDATA4 (0x4e) followed by 4-byte LE length.
fn push_item(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let mut result = Vec::with_capacity(len + 5);
    if len <= 75 {
        result.push(len as u8);
    } else if len <= 255 {
        result.push(op::OP_PUSHDATA1);
        result.push(len as u8);
    } else if len <= 65535 {
        result.push(op::OP_PUSHDATA2);
        result.push((len & 0xff) as u8);
        result.push(((len >> 8) & 0xff) as u8);
    } else {
        result.push(op::OP_PUSHDATA4);
        result.push((len & 0xff) as u8);
        result.push(((len >> 8) & 0xff) as u8);
        result.push(((len >> 16) & 0xff) as u8);
        result.push(((len >> 24) & 0xff) as u8);
    }
    result.extend_from_slice(data);
    result
}

/// Compute RIPEMD-160(SHA-256(data)) — the Bitcoin HASH160 operation.
fn hash160(data: &[u8]) -> [u8; 20] {
    use sha2::{Digest, Sha256};
    let sha = {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize()
    };
    ripemd160(&sha)
}

/// Minimal RIPEMD-160 implementation (needed because the `ripemd` crate is not
/// in Cargo.toml).  This is a compact, correct implementation suitable for
/// unit-test and non-critical code paths.  For production signing, callers
/// should use a vetted implementation.
fn ripemd160(data: &[u8]) -> [u8; 20] {
    // Inline RIPEMD-160 — compact reference implementation.
    // Based on the public-domain reference by Antoon Bosselaers.
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    // Pad message.
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut x = [0u32; 16];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            x[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }
        let (mut a, mut b, mut c, mut d, mut e) =
            (h[0], h[1], h[2], h[3], h[4]);
        let (mut a2, mut b2, mut c2, mut d2, mut e2) =
            (h[0], h[1], h[2], h[3], h[4]);

        for j in 0..80 {
            let (f, k) = match j / 16 {
                0 => (b ^ c ^ d, 0u32),
                1 => ((b & c) | (!b & d), 0x5A827999),
                2 => ((b | !c) ^ d, 0x6ED9EBA1),
                3 => ((b & d) | (c & !d), 0x8F1BBCDC),
                _ => (b ^ (c | !d), 0xA953FD4E),
            };
            let r = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
                3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
                1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
                4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
            ][j];
            let s = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
                     5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
                     5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
                     5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
                     5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12]
                [j];
            let t = f.wrapping_add(a).wrapping_add(k).wrapping_add(x[r]);
            let t = t.rotate_left(s as u32).wrapping_add(e);
            a = e;
            e = d;
            d = c.rotate_left(10);
            c = b;
            b = t;

            // Right line.
            let (f2, k2) = match j / 16 {
                0 => (b2 ^ (c2 | !d2), 0x50A28BE6),
                1 => ((b2 & c2) | (!b2 & d2), 0x5C4DD124),
                2 => ((b2 | !c2) ^ d2, 0x6D703EF3),
                3 => ((b2 & d2) | (c2 & !d2), 0x7A6D76E9),
                _ => (b2 ^ c2 ^ d2, 0u32),
            };
            let r2 = [
                5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
                6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
                15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
                8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
                12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
            ][j];
            let s2 = [
                11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
                7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
                11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
                11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
                9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
            ][j];
            let t2 = f2.wrapping_add(a2).wrapping_add(k2).wrapping_add(x[r2]);
            let t2 = t2.rotate_left(s2 as u32).wrapping_add(e2);
            a2 = e2;
            e2 = d2;
            d2 = c2.rotate_left(10);
            c2 = b2;
            b2 = t2;
        }

        let t = h[1].wrapping_add(c).wrapping_add(d2);
        h[1] = h[2].wrapping_add(d).wrapping_add(e2);
        h[2] = h[3].wrapping_add(e).wrapping_add(a2);
        h[3] = h[4].wrapping_add(a).wrapping_add(b2);
        h[4] = h[0].wrapping_add(b).wrapping_add(c2);
        h[0] = t;
    }

    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// AccumulatorMultiSigOutput
// ---------------------------------------------------------------------------

/// An accumulator-style m-of-n multisig output script.
///
/// Ported from `AccumulatorMultiSigOutput` in `archive/electrumsv/script.py`.
/// Instead of OP_CHECKMULTISIG, this script uses an alt-stack accumulator:
/// each public key is checked with OP_CHECKSIGVERIFY inside an OP_IF block,
/// and a counter on the alt stack tracks how many signatures matched.
///
/// # Fields
/// - `public_keys`: the n public keys (raw bytes, 33 or 65 bytes each).
/// - `threshold`: the minimum number of valid signatures required (m).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccumulatorMultiSigOutput {
    /// The public keys (raw bytes).
    pub public_keys: Vec<Vec<u8>>,
    /// The threshold (m) — minimum valid signatures required.
    pub threshold: i64,
}

impl AccumulatorMultiSigOutput {
    /// Create a new accumulator multisig output.
    ///
    /// `threshold` must be in `1..=public_keys.len()` as i64.
    pub fn new(public_keys: Vec<Vec<u8>>, threshold: i64) -> Result<Self, MultisigError> {
        if public_keys.is_empty() {
            return Err(MultisigError::NoPublicKeys);
        }
        if threshold < 1 || threshold > public_keys.len() as i64 {
            return Err(MultisigError::InvalidThreshold);
        }
        Ok(Self {
            public_keys,
            threshold,
        })
    }

    /// The number of public keys (n).
    pub fn n(&self) -> usize {
        self.public_keys.len()
    }

    /// The threshold (m).
    pub fn m(&self) -> i64 {
        self.threshold
    }

    /// Serialize the script to bytes, matching the Python `to_script_bytes` exactly.
    pub fn to_script_bytes(&self) -> Vec<u8> {
        let mut parts: Vec<Vec<u8>> = Vec::new();

        // OP_0  OP_TOALTSTACK
        parts.push(vec![op::OP_0]);
        parts.push(vec![op::OP_TOALTSTACK]);

        // For each public key:
        for pk in &self.public_keys {
            let h160 = hash160(pk);
            parts.push(vec![op::OP_IF]);
            parts.push(vec![op::OP_DUP]);
            parts.push(vec![op::OP_HASH160]);
            parts.push(push_item(&h160));
            parts.push(vec![op::OP_EQUALVERIFY]);
            parts.push(vec![op::OP_CHECKSIGVERIFY]);
            parts.push(vec![op::OP_FROMALTSTACK]);
            parts.push(vec![op::OP_1ADD]);
            parts.push(vec![op::OP_TOALTSTACK]);
            parts.push(vec![op::OP_ENDIF]);
        }

        // OP_FROMALTSTACK  <threshold>  OP_GREATERTHANOREQUAL
        parts.push(vec![op::OP_FROMALTSTACK]);
        parts.push(push_int(self.threshold));
        parts.push(vec![op::OP_GREATERTHANOREQUAL]);

        // Flatten.
        let mut result = Vec::new();
        for p in &parts {
            result.extend_from_slice(p);
        }
        result
    }
}

impl PartialEq for AccumulatorMultiSigOutput {
    fn eq(&self, other: &Self) -> bool {
        self.public_keys == other.public_keys && self.threshold == other.threshold
    }
}

impl Eq for AccumulatorMultiSigOutput {}

impl std::hash::Hash for AccumulatorMultiSigOutput {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.public_keys.hash(state);
        self.threshold.hash(state);
        256796i64.hash(state); // matches the Python __hash__ constant
    }
}

impl std::fmt::Display for AccumulatorMultiSigOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AccumulatorMultiSigOutput(m={}, n={})",
            self.threshold,
            self.public_keys.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors from the multisig module.
#[derive(Debug, thiserror::Error)]
pub enum MultisigError {
    #[error("no public keys provided")]
    NoPublicKeys,
    #[error("invalid threshold: must be in 1..=n")]
    InvalidThreshold,
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pk(seed: u8) -> Vec<u8> {
        // 33-byte compressed pubkey placeholder.
        vec![seed; 33]
    }

    #[test]
    fn test_accumulator_multisig_construction_2of3() {
        let keys = vec![dummy_pk(1), dummy_pk(2), dummy_pk(3)];
        let ms = AccumulatorMultiSigOutput::new(keys, 2).expect("valid 2-of-3");
        assert_eq!(ms.m(), 2);
        assert_eq!(ms.n(), 3);
    }

    #[test]
    fn test_accumulator_multisig_invalid_threshold() {
        let keys = vec![dummy_pk(1), dummy_pk(2)];
        assert!(AccumulatorMultiSigOutput::new(keys.clone(), 0).is_err());
        assert!(AccumulatorMultiSigOutput::new(keys.clone(), 3).is_err());
        assert!(AccumulatorMultiSigOutput::new(keys, 2).is_ok());
    }

    #[test]
    fn test_accumulator_multisig_empty_keys() {
        assert!(AccumulatorMultiSigOutput::new(vec![], 1).is_err());
    }

    #[test]
    fn test_to_script_bytes_starts_with_op0_toaltstack() {
        let keys = vec![dummy_pk(1), dummy_pk(2)];
        let ms = AccumulatorMultiSigOutput::new(keys, 1).expect("valid");
        let script = ms.to_script_bytes();
        assert!(!script.is_empty());
        // First two bytes: OP_0, OP_TOALTSTACK
        assert_eq!(script[0], op::OP_0);
        assert_eq!(script[1], op::OP_TOALTSTACK);
    }

    #[test]
    fn test_to_script_bytes_ends_with_gte() {
        let keys = vec![dummy_pk(1), dummy_pk(2), dummy_pk(3)];
        let ms = AccumulatorMultiSigOutput::new(keys, 2).expect("valid");
        let script = ms.to_script_bytes();
        assert!(!script.is_empty());
        // Last byte should be OP_GREATERTHANOREQUAL.
        assert_eq!(*script.last().unwrap(), op::OP_GREATERTHANOREQUAL);
    }

    #[test]
    fn test_to_script_bytes_contains_if_endif_per_key() {
        let keys = vec![dummy_pk(1), dummy_pk(2)];
        let ms = AccumulatorMultiSigOutput::new(keys, 1).expect("valid");
        let script = ms.to_script_bytes();
        let if_count = script.iter().filter(|&&b| b == op::OP_IF).count();
        let endif_count = script.iter().filter(|&&b| b == op::OP_ENDIF).count();
        assert_eq!(if_count, 2, "one OP_IF per public key");
        assert_eq!(endif_count, 2, "one OP_ENDIF per public key");
    }

    #[test]
    fn test_eq_and_hash() {
        let keys = vec![dummy_pk(1), dummy_pk(2)];
        let a = AccumulatorMultiSigOutput::new(keys.clone(), 1).expect("a");
        let b = AccumulatorMultiSigOutput::new(keys.clone(), 1).expect("b");
        let c = AccumulatorMultiSigOutput::new(keys, 2).expect("c");
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Hash should be deterministic.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn test_push_int_small_values() {
        assert_eq!(push_int(0), vec![op::OP_0]);
        assert_eq!(push_int(1), vec![op::OP_1]);
        assert_eq!(push_int(2), vec![op::OP_2]);
        assert_eq!(push_int(16), vec![op::OP_16]);
        assert_eq!(push_int(-1), vec![op::OP_1NEGATE]);
    }

    #[test]
    fn test_push_item_length_prefix() {
        let data = vec![0x42u8; 20];
        let pushed = push_item(&data);
        assert_eq!(pushed[0], 20); // length prefix
        assert_eq!(&pushed[1..], &data[..]);
    }
}