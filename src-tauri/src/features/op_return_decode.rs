// features/op_return_decode.rs — OP_RETURN protocol decoder
//
// Ported from archive/electrumsv/features/op_return_decode.py
//
// Parses OP_RETURN scriptPubKeys and identifies BSV on-chain data protocols:
// B (file storage), MAP (Magic Attribute Protocol), Bcat (large file chunking),
// BAP (Bitcoin Attestation Protocol), 21E8 (proof-of-work).
//
// Reference: bmap-js (https://github.com/rohenaz/bmap)

use super::OpReturnProtocol;

/// OP_RETURN opcode
const OP_RETURN: u8 = 0x6A;

// Protocol prefix strings (ASCII form pushed as first data chunk)
const B_PREFIX: &[u8] = b"19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut";
const MAP_PREFIX: &[u8] = b"1PuQa7K62MiKCtssSLKy1kh56WWU7MURt";
const BCAT_PREFIX: &[u8] = b"15DHFxWZJT58f9nhyGnsRBqrgwK4W6h4Up";
const BAP_PREFIX: &[u8] = b"1BAP";
const E21_PREFIX: &[u8] = b"21E8";

/// Parse an OP_RETURN script and return detected protocol data.
///
/// Returns None if the script is not OP_RETURN or no known protocol is found.
pub fn parse_op_return(script_hex: &str) -> Option<OpReturnProtocol> {
    let chunks = extract_data_chunks(script_hex);
    if chunks.is_empty() {
        return None;
    }

    // Match first chunk against known protocol prefixes
    let first = &chunks[0];
    let protocol_id = match_protocol(first)?;

    // Decode with the appropriate protocol decoder
    let data = match protocol_id {
        "B" => decode_b(&chunks),
        "MAP" => decode_map(&chunks),
        "Bcat" => decode_bcat(&chunks),
        "BAP" => decode_bap(&chunks),
        "21E8" => decode_21e8(&chunks),
        _ => return None,
    };

    Some(OpReturnProtocol {
        protocol: protocol_id.to_string(),
        data,
    })
}

/// Check if a script is an OP_RETURN script.
pub fn is_op_return(script_hex: &str) -> bool {
    let script = match hex::decode(script_hex) {
        Ok(s) => s,
        Err(_) => return false,
    };
    !script.is_empty() && script[0] == OP_RETURN
}

/// Extract all data chunks from an OP_RETURN script.
///
/// Parses the raw script hex, skipping the OP_RETURN opcode and all
/// push opcodes, returning only the pushed data bytes.
fn extract_data_chunks(script_hex: &str) -> Vec<Vec<u8>> {
    let mut chunks = Vec::new();

    let script = match hex::decode(script_hex) {
        Ok(s) => s,
        Err(_) => return chunks,
    };

    if script.is_empty() || script[0] != OP_RETURN {
        return chunks;
    }

    let mut i = 1;
    let len = script.len();

    while i < len {
        let opcode = script[i];

        // Direct push: 1 to 75 bytes
        if (1..=0x4B).contains(&opcode) {
            let data_len = opcode as usize;
            if i + 1 + data_len > len {
                break;
            }
            chunks.push(script[i + 1..i + 1 + data_len].to_vec());
            i += 1 + data_len;
            continue;
        }

        // OP_PUSHDATA1
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

        // OP_PUSHDATA2
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

        // OP_PUSHDATA4
        if opcode == 0x4E {
            if i + 5 > len {
                break;
            }
            let data_len = u32::from_le_bytes([
                script[i + 1],
                script[i + 2],
                script[i + 3],
                script[i + 4],
            ]) as usize;
            if i + 5 + data_len > len {
                break;
            }
            chunks.push(script[i + 5..i + 5 + data_len].to_vec());
            i += 5 + data_len;
            continue;
        }

        // OP_0 (0x00): empty push
        if opcode == 0x00 {
            chunks.push(Vec::new());
            i += 1;
            continue;
        }

        // OP_1NEGATE (0x4F) .. OP_16 (0x60): small numeric pushes — skip
        if (0x4F..=0x60).contains(&opcode) {
            i += 1;
            continue;
        }

        // Unknown opcode — skip
        i += 1;
    }

    chunks
}

/// Match the first data chunk against known protocol prefixes.
fn match_protocol(first: &[u8]) -> Option<&'static str> {
    if first.is_empty() {
        return None;
    }

    // Exact match (case-insensitive)
    let lower: Vec<u8> = first.iter().map(|b| b.to_ascii_lowercase()).collect();

    let prefixes: &[(&[u8], &str)] = &[
        (B_PREFIX, "B"),
        (MAP_PREFIX, "MAP"),
        (BCAT_PREFIX, "Bcat"),
        (BAP_PREFIX, "BAP"),
        (E21_PREFIX, "21E8"),
    ];

    for (prefix, id) in prefixes {
        let prefix_lower: Vec<u8> = prefix.iter().map(|b| b.to_ascii_lowercase()).collect();
        if lower == prefix_lower {
            return Some(id);
        }
    }

    // Prefix-start match (protocol prefix may be part of longer data)
    for (prefix, id) in prefixes {
        let prefix_lower: Vec<u8> = prefix.iter().map(|b| b.to_ascii_lowercase()).collect();
        if lower.starts_with(&prefix_lower) {
            return Some(id);
        }
    }

    None
}

// ── Protocol-specific decoders ─────────────────────────────────────────

/// B-Protocol: [prefix] [data] [media_type] [encoding] [filename]
fn decode_b(chunks: &[Vec<u8>]) -> serde_json::Value {
    let get = |i: usize| -> String {
        chunks
            .get(i)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .unwrap_or_default()
    };

    serde_json::json!({
        "data": chunks.get(1).map(hex::encode).unwrap_or_default(),
        "media_type": get(2),
        "encoding": get(3),
        "filename": get(4),
    })
}

/// MAP protocol: [prefix] [key] [value] [key] [value] ...
fn decode_map(chunks: &[Vec<u8>]) -> serde_json::Value {
    let mut map = serde_json::Map::new();

    let mut i = 1;
    while i + 1 < chunks.len() {
        let key = String::from_utf8_lossy(&chunks[i]).into_owned();
        let value = String::from_utf8_lossy(&chunks[i + 1]).into_owned();
        map.insert(key, serde_json::Value::String(value));
        i += 2;
    }

    // Trailing key with no value
    if i < chunks.len() {
        let key = String::from_utf8_lossy(&chunks[i]).into_owned();
        map.insert(key, serde_json::Value::String(String::new()));
    }

    serde_json::Value::Object(map)
}

/// Bcat protocol: [prefix] [info] [media_type] [encoding] [filename] [NULL] [txid1] [txid2] ...
fn decode_bcat(chunks: &[Vec<u8>]) -> serde_json::Value {
    let get = |i: usize| -> String {
        chunks
            .get(i)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .unwrap_or_default()
    };

    // After filename (index 4), skip NULL separator, rest are txids
    let txid_start = if chunks.len() > 6 { 6 } else { 5 };
    let txids: Vec<String> = chunks[txid_start.min(chunks.len())..]
        .iter()
        .map(|c| hex::encode(c))
        .filter(|s| !s.is_empty())
        .collect();

    serde_json::json!({
        "media_type": get(2),
        "encoding": get(3),
        "filename": get(4),
        "chunks": txids,
    })
}

/// 21E8 proof-of-work protocol: [prefix] [pow_data...]
fn decode_21e8(chunks: &[Vec<u8>]) -> serde_json::Value {
    let data: Vec<String> = chunks[1..].iter().map(|c| hex::encode(c)).collect();
    serde_json::json!({ "data": data })
}

/// BAP (Bitcoin Attestation Protocol): [prefix] [type] [data...]
fn decode_bap(chunks: &[Vec<u8>]) -> serde_json::Value {
    let typ = chunks
        .get(1)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .unwrap_or_default();
    let data = chunks.get(2).map(hex::encode).unwrap_or_default();

    serde_json::json!({
        "type": typ,
        "data": data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_op_return(chunks: &[&[u8]]) -> String {
        let mut script = vec![OP_RETURN];
        for chunk in chunks {
            if chunk.len() <= 75 {
                script.push(chunk.len() as u8);
            } else if chunk.len() <= 255 {
                script.push(0x4C);
                script.push(chunk.len() as u8);
            } else {
                script.push(0x4D);
                script.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
            }
            script.extend_from_slice(chunk);
        }
        hex::encode(&script)
    }

    #[test]
    fn test_parse_b_protocol() {
        let script = make_op_return(&[
            B_PREFIX,
            b"Hello BSV!",
            b"text/plain",
            b"utf-8",
            b"hello.txt",
        ]);
        let result = parse_op_return(&script);
        assert!(result.is_some());
        let p = result.unwrap();
        assert_eq!(p.protocol, "B");
        assert_eq!(p.data["media_type"], "text/plain");
        assert_eq!(p.data["filename"], "hello.txt");
        assert_eq!(p.data["data"], hex::encode(b"Hello BSV!"));
    }

    #[test]
    fn test_parse_map_protocol() {
        let script = make_op_return(&[MAP_PREFIX, b"app", b"ElectrumSV-Mc", b"type", b"wallet"]);
        let result = parse_op_return(&script);
        assert!(result.is_some());
        let p = result.unwrap();
        assert_eq!(p.protocol, "MAP");
        assert_eq!(p.data["app"], "ElectrumSV-Mc");
        assert_eq!(p.data["type"], "wallet");
    }

    #[test]
    fn test_parse_21e8_protocol() {
        let script = make_op_return(&[E21_PREFIX, &[0xAA, 0xBB, 0xCC]]);
        let result = parse_op_return(&script);
        assert!(result.is_some());
        let p = result.unwrap();
        assert_eq!(p.protocol, "21E8");
    }

    #[test]
    fn test_parse_bap_protocol() {
        let script = make_op_return(&[BAP_PREFIX, b"attest", &[0xDE, 0xAD, 0xBE, 0xEF]]);
        let result = parse_op_return(&script);
        assert!(result.is_some());
        let p = result.unwrap();
        assert_eq!(p.protocol, "BAP");
        assert_eq!(p.data["type"], "attest");
    }

    #[test]
    fn test_unknown_protocol_returns_none() {
        let script = make_op_return(&[b"UNKNOWN_PROTOCOL", b"data"]);
        let result = parse_op_return(&script);
        assert!(result.is_none());
    }

    #[test]
    fn test_non_op_return_returns_none() {
        let script = "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac";
        let result = parse_op_return(script);
        assert!(result.is_none());
    }

    #[test]
    fn test_is_op_return() {
        let script = make_op_return(&[b"test"]);
        assert!(is_op_return(&script));
        assert!(!is_op_return("76a91400ff"));
    }
}