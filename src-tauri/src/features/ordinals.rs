// features/ordinals.rs — 1Sat Ordinals NFT inscription detection
//
// Ported from archive/electrumsv/features/ordinals.py
//
// 1Sat Ordinals inscribe data on individual satoshis using an envelope
// format inside P2PKH scripts:
//   OP_FALSE OP_IF <protocol_id> <content_type> <content...> OP_ENDIF
//
// Reference: https://1satordinals.com/

use super::{OrdinalInscription, DecodedKind};

/// Known protocol IDs for 1Sat Ordinal inscriptions
const ORD_PROTOCOL: &[u8] = b"ord";
const ONE_SAT_PROTOCOL: &[u8] = b"1sat";

/// Detect a 1Sat Ordinal inscription in a scriptPubKey.
///
/// A 1Sat Ordinal is typically a 1-satoshi output with an inscription
/// envelope embedded in the script. The envelope uses:
///   OP_FALSE (0x00) OP_IF (0x63) <pushes> OP_ENDIF (0x68)
///
/// Inside the envelope:
///   - First push: protocol ID (e.g. "ord", "1sat")
///   - Second push: content type (e.g. "image/png")
///   - Remaining pushes: content data (concatenated)
pub fn detect_ordinal_inscription(script_hex: &str, value: u64) -> Option<OrdinalInscription> {
    let script = hex::decode(script_hex).ok()?;

    // Look for the ordinal envelope: OP_FALSE (0x00) OP_IF (0x63)
    let envelope = find_envelope(&script)?;
    let chunks = extract_push_sequence(&script[envelope..]);

    if chunks.len() < 2 {
        return None;
    }

    // First chunk = protocol ID
    let protocol = String::from_utf8_lossy(&chunks[0]).into_owned();
    let is_known = chunks[0] == ORD_PROTOCOL || chunks[0] == ONE_SAT_PROTOCOL || protocol == "ord";
    if !is_known {
        return None;
    }

    // Second chunk = content type
    let content_type = String::from_utf8_lossy(&chunks[1]).into_owned();

    // Remaining chunks = content (concatenated)
    let content: Vec<u8> = chunks[2..].concat();

    // Try to decode text content
    let content_text = if content_type.starts_with("text/") {
        String::from_utf8(content.clone()).ok()
    } else {
        None
    };

    let _ = value; // value is informational — we detect regardless of satoshi count

    Some(OrdinalInscription {
        protocol,
        content_type,
        content_hex: hex::encode(&content),
        content_text,
    })
}

/// Check if a transaction output is a potential ordinal transfer (1 satoshi P2PKH).
pub fn is_ordinal_transfer(value: u64) -> bool {
    value == 1
}

/// Find the start index of the OP_FALSE OP_IF envelope in a script.
fn find_envelope(script: &[u8]) -> Option<usize> {
    let len = script.len();
    if len < 4 {
        return None;
    }
    // Search for OP_FALSE (0x00) followed by OP_IF (0x63)
    let mut i = 0;
    while i < len.saturating_sub(1) {
        if script[i] == 0x00 && script[i + 1] == 0x63 {
            // Found envelope start — return position after OP_FALSE OP_IF
            return Some(i + 2);
        }
        i += 1;
    }
    None
}

/// Extract a sequence of pushed data items until OP_ENDIF (0x68) or end of script.
///
/// Handles standard push opcodes:
///   - 0x01..0x4B: direct push (next N bytes)
///   - 0x4C (OP_PUSHDATA1): 1-byte length prefix
///   - 0x4D (OP_PUSHDATA2): 2-byte LE length prefix
///   - 0x4E (OP_PUSHDATA4): 4-byte LE length prefix
///   - 0x00: empty push
///   - 0x4F..0x60: small number pushes (OP_1NEGATE..OP_16)
fn extract_push_sequence(script: &[u8]) -> Vec<Vec<u8>> {
    let mut chunks = Vec::new();
    let mut i = 0;
    let len = script.len();

    while i < len {
        let opcode = script[i];

        // OP_ENDIF — end of envelope
        if opcode == 0x68 {
            break;
        }

        // OP_0 / OP_FALSE — empty push
        if opcode == 0x00 {
            chunks.push(Vec::new());
            i += 1;
            continue;
        }

        // OP_1NEGATE (0x4F) through OP_16 (0x60) — push small numbers
        if (0x4F..=0x60).contains(&opcode) {
            chunks.push(vec![opcode - 0x50]);
            i += 1;
            continue;
        }

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

        // Unknown opcode — skip
        i += 1;
    }

    chunks
}

/// Convenience: detect ordinal from DecodedKind
pub fn from_kind(kind: &DecodedKind) -> Option<&OrdinalInscription> {
    match kind {
        DecodedKind::Ordinal(insc) => Some(insc),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_envelope(protocol: &[u8], content_type: &[u8], content: &[u8]) -> String {
        let mut script = vec![];
        // OP_FALSE OP_IF
        script.push(0x00);
        script.push(0x63);
        // Push protocol
        script.push(protocol.len() as u8);
        script.extend_from_slice(protocol);
        // Push content_type
        script.push(content_type.len() as u8);
        script.extend_from_slice(content_type);
        // Push content
        if content.len() <= 75 {
            script.push(content.len() as u8);
        } else if content.len() <= 255 {
            script.push(0x4C);
            script.push(content.len() as u8);
        } else {
            script.push(0x4D);
            script.extend_from_slice(&(content.len() as u16).to_le_bytes());
        }
        script.extend_from_slice(content);
        // OP_ENDIF
        script.push(0x68);
        hex::encode(&script)
    }

    #[test]
    fn test_detect_text_inscription() {
        let envelope = build_envelope(b"ord", b"text/plain", b"Hello 1Sat!");
        let result = detect_ordinal_inscription(&envelope, 1);
        assert!(result.is_some());
        let insc = result.unwrap();
        assert_eq!(insc.protocol, "ord");
        assert_eq!(insc.content_type, "text/plain");
        assert_eq!(insc.content_text, Some("Hello 1Sat!".to_string()));
    }

    #[test]
    fn test_detect_image_inscription() {
        let content = [0x89, 0x50, 0x4E, 0x47]; // PNG header
        let envelope = build_envelope(b"ord", b"image/png", &content);
        let result = detect_ordinal_inscription(&envelope, 1);
        assert!(result.is_some());
        let insc = result.unwrap();
        assert_eq!(insc.content_type, "image/png");
        assert_eq!(insc.content_hex, "89504e47");
        assert_eq!(insc.content_text, None);
    }

    #[test]
    fn test_no_inscription_in_plain_p2pkh() {
        let script = "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac";
        let result = detect_ordinal_inscription(script, 50000);
        assert!(result.is_none());
    }

    #[test]
    fn test_unknown_protocol_rejected() {
        let envelope = build_envelope(b"fake", b"text/plain", b"data");
        let result = detect_ordinal_inscription(&envelope, 1);
        assert!(result.is_none());
    }

    #[test]
    fn test_is_ordinal_transfer() {
        assert!(is_ordinal_transfer(1));
        assert!(!is_ordinal_transfer(0));
        assert!(!is_ordinal_transfer(1000));
    }
}