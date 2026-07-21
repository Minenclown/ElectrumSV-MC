// features/stas_tokens.rs — STAS token transfer detection
//
// STAS (Simplified Asset Token Standard) tokens on BSV use specific
// script patterns in their outputs to represent token transfers.
//
// STAS token scripts typically follow patterns like:
// - OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
//   with an OP_RETURN containing the token contract reference
// - Or a P2PKH-like output with an embedded token symbol/contract ref
//
// The detection is heuristic: we look for known STAS script patterns
// and OP_RETURN references to token contract txids.
//
// References:
// - https://github.com/bitcoin-sv/bips/blob/master/bsp-0042.md
// - https://docs.bsv.bible/stas-token

use super::StasTokenTransfer;

/// STAS token script prefix patterns.
///
/// STAS tokens embed a push of the contract/origin txid (32 bytes)
/// followed by token metadata. We detect the pattern heuristically.
const STAS_PREFIX_BYTES: &[u8] = b"STAS";

/// Detect a STAS token transfer in a scriptPubKey.
///
/// STAS token scripts vary — this is a heuristic detector that checks for:
/// 1. OP_RETURN scripts that reference a 32-byte txid (contract origin)
/// 2. Scripts containing a "STAS" marker
/// 3. Token transfer patterns with embedded contract references
///
/// Returns Some(StasTokenTransfer) if detected, None otherwise.
pub fn detect_stas_transfer(script_hex: &str, value: u64) -> Option<StasTokenTransfer> {
    let script = hex::decode(script_hex).ok()?;

    // Pattern 1: OP_RETURN with STAS marker
    if !script.is_empty() && script[0] == 0x6A {
        return detect_stas_in_op_return(&script, value, script_hex);
    }

    // Pattern 2: P2PKH-like script with embedded STAS data after the standard
    // P2PKH pattern (76a914...88ac) followed by additional pushes
    if script.len() > 26 && script.starts_with(&[0x76, 0xA9, 0x14]) {
        return detect_stas_in_p2pkh(&script, value, script_hex);
    }

    None
}

/// Detect STAS token data in an OP_RETURN script.
fn detect_stas_in_op_return(
    script: &[u8],
    value: u64,
    script_hex: &str,
) -> Option<StasTokenTransfer> {
    // Extract data chunks from OP_RETURN
    let chunks = extract_op_return_data(script);
    if chunks.is_empty() {
        return None;
    }

    let first = &chunks[0];

    // Check for STAS marker
    if first == STAS_PREFIX_BYTES || first.starts_with(STAS_PREFIX_BYTES) {
        // STAS OP_RETURN format: ["STAS"] [symbol] [contract_txid] [amount]
        let symbol = chunks.get(1).map(|c| String::from_utf8_lossy(c).into_owned());
        let contract_txid = chunks.get(2).map(|c| hex::encode(c));
        let amount = chunks
            .get(3)
            .and_then(|c| parse_token_amount(c))
            .or(Some(value));

        return Some(StasTokenTransfer {
            symbol,
            contract_txid,
            amount,
            script_hex: script_hex.to_string(),
        });
    }

    // Check for 32-byte contract txid reference (potential STAS token)
    if first.len() == 32 {
        let contract_txid = hex::encode(first);
        let symbol = chunks.get(1).map(|c| String::from_utf8_lossy(c).into_owned());

        // Only treat as STAS if there's a symbol or amount following
        if symbol.is_some() || chunks.len() >= 2 {
            return Some(StasTokenTransfer {
                symbol,
                contract_txid: Some(contract_txid),
                amount: chunks.get(2).and_then(|c| parse_token_amount(c)),
                script_hex: script_hex.to_string(),
            });
        }
    }

    None
}

/// Detect STAS token data appended to a P2PKH script.
fn detect_stas_in_p2pkh(
    script: &[u8],
    _value: u64,
    script_hex: &str,
) -> Option<StasTokenTransfer> {
    // Standard P2PKH is 25 bytes: OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG
    // STAS may append additional data after the standard pattern
    if script.len() <= 26 {
        return None;
    }

    // Look for STAS marker in the extra data
    let extra = &script[25..];
    if extra.windows(4).any(|w| w == STAS_PREFIX_BYTES) {
        // Found STAS marker in extended P2PKH
        let symbol = extract_stas_symbol(extra);
        return Some(StasTokenTransfer {
            symbol,
            contract_txid: None,
            amount: None,
            script_hex: script_hex.to_string(),
        });
    }

    None
}

/// Extract the STAS token symbol from extended script data.
fn extract_stas_symbol(extra: &[u8]) -> Option<String> {
    // Find STAS marker and try to extract following symbol
    for i in 0..extra.len().saturating_sub(4) {
        if &extra[i..i + 4] == STAS_PREFIX_BYTES {
            // After STAS marker, expect a push of the symbol
            let rest = &extra[i + 4..];
            if !rest.is_empty() {
                let push_len = rest[0] as usize;
                if push_len > 0 && 1 + push_len <= rest.len() {
                    return Some(String::from_utf8_lossy(&rest[1..1 + push_len]).into_owned());
                }
            }
        }
    }
    None
}

/// Parse a token amount from raw bytes (little-endian u64).
fn parse_token_amount(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    // Try as 8-byte LE u64
    if bytes.len() == 8 {
        let val = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        if val > 0 {
            return Some(val);
        }
    }
    // Try as ASCII number
    let s = String::from_utf8_lossy(bytes);
    s.trim().parse::<u64>().ok()
}

/// Extract data chunks from an OP_RETURN script (similar to op_return_decode).
fn extract_op_return_data(script: &[u8]) -> Vec<Vec<u8>> {
    let mut chunks = Vec::new();
    if script.is_empty() || script[0] != 0x6A {
        return chunks;
    }

    let mut i = 1;
    let len = script.len();

    while i < len {
        let opcode = script[i];

        if (1..=0x4B).contains(&opcode) {
            let data_len = opcode as usize;
            if i + 1 + data_len > len {
                break;
            }
            chunks.push(script[i + 1..i + 1 + data_len].to_vec());
            i += 1 + data_len;
            continue;
        }

        if opcode == 0x4C {
            if i + 2 > len {
                break;
            }
            let data_len = script[i + 1] as usize;
            if i + 2 + data_len > len {
                break;
            }
            chunks.push(script[i + 2..i + 2 + data_len].to_vec());
            i += 2 + data_len;
            continue;
        }

        if opcode == 0x4D {
            if i + 3 > len {
                break;
            }
            let data_len = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
            if i + 3 + data_len > len {
                break;
            }
            chunks.push(script[i + 3..i + 3 + data_len].to_vec());
            i += 3 + data_len;
            continue;
        }

        if opcode == 0x00 {
            chunks.push(Vec::new());
            i += 1;
            continue;
        }

        if (0x4F..=0x60).contains(&opcode) {
            i += 1;
            continue;
        }

        i += 1;
    }

    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_stas_op_return(symbol: &[u8], contract_txid: &[u8], amount: &[u8]) -> String {
        let mut script = vec![0x6A]; // OP_RETURN
        // Push "STAS"
        script.push(4);
        script.extend_from_slice(STAS_PREFIX_BYTES);
        // Push symbol
        script.push(symbol.len() as u8);
        script.extend_from_slice(symbol);
        // Push contract txid
        if contract_txid.len() <= 75 {
            script.push(contract_txid.len() as u8);
        } else {
            script.push(0x4C);
            script.push(contract_txid.len() as u8);
        }
        script.extend_from_slice(contract_txid);
        // Push amount
        script.push(amount.len() as u8);
        script.extend_from_slice(amount);
        hex::encode(&script)
    }

    #[test]
    fn test_detect_stas_op_return() {
        let contract = [0xAB; 32];
        let amount = 1000u64.to_le_bytes();
        let script = make_stas_op_return(b"TEST", &contract, &amount);

        let result = detect_stas_transfer(&script, 1000);
        assert!(result.is_some());
        let token = result.unwrap();
        assert_eq!(token.symbol, Some("TEST".to_string()));
        assert_eq!(token.contract_txid, Some(hex::encode(&contract)));
        assert_eq!(token.amount, Some(1000));
    }

    #[test]
    fn test_detect_stas_contract_ref() {
        // OP_RETURN with just a 32-byte contract txid + symbol
        let contract = [0xCD; 32];
        let mut script = vec![0x6A];
        script.push(32);
        script.extend_from_slice(&contract);
        script.push(4);
        script.extend_from_slice(b"COIN");
        let script_hex = hex::encode(&script);

        let result = detect_stas_transfer(&script_hex, 0);
        assert!(result.is_some());
        let token = result.unwrap();
        assert_eq!(token.contract_txid, Some(hex::encode(&contract)));
        assert_eq!(token.symbol, Some("COIN".to_string()));
    }

    #[test]
    fn test_no_stas_in_plain_p2pkh() {
        let script = "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac";
        let result = detect_stas_transfer(script, 50000);
        assert!(result.is_none());
    }

    #[test]
    fn test_no_stas_in_empty_script() {
        let result = detect_stas_transfer("", 0);
        assert!(result.is_none());
    }
}