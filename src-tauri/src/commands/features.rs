// commands/features.rs — Tauri IPC commands for BSV on-chain data protocols
//
// Provides:
// - decode_output: classify a single scriptPubKey
// - decode_tx_outputs: decode all outputs of a transaction
// - get_ordinals: detect 1Sat Ordinal inscriptions in a list of outputs
// - get_protocol_data: decode OP_RETURN protocol data
//
// These commands allow the GUI to request on-chain data interpretation
// from the Rust backend.

use crate::features::{self, DecodedOutput};

// ============================================================================
// Response types
// ============================================================================

/// Request to decode a single output.
#[derive(Debug, serde::Deserialize)]
pub struct DecodeOutputRequest {
    /// Output value in satoshis
    pub value: u64,
    /// ScriptPubKey in hex
    pub script_pubkey: String,
}

/// Request to decode multiple outputs (full transaction).
#[derive(Debug, serde::Deserialize)]
pub struct DecodeOutputsRequest {
    /// List of (value, script_hex) pairs
    pub outputs: Vec<DecodeOutputRequest>,
}

// ============================================================================
// Commands
// ============================================================================

/// Decode a single transaction output and classify its on-chain data.
///
/// Returns a DecodedOutput with the kind of data (Ordinal, OP_RETURN, STAS, Plain).
#[tauri::command]
pub async fn decode_output(req: DecodeOutputRequest) -> Result<DecodedOutput, String> {
    log::debug!(
        "decode_output — value: {}, script_len: {}",
        req.value,
        req.script_pubkey.len()
    );

    let kind = features::decode_script(req.value, &req.script_pubkey);

    Ok(DecodedOutput {
        output_index: 0,
        value: req.value,
        script_pubkey_hex: req.script_pubkey.clone(),
        kind,
    })
}

/// Decode all outputs of a transaction.
///
/// Takes a list of (value, script_hex) pairs and returns decoded data for each.
#[tauri::command]
pub async fn decode_tx_outputs(req: DecodeOutputsRequest) -> Result<Vec<DecodedOutput>, String> {
    log::debug!("decode_tx_outputs — {} outputs", req.outputs.len());

    let outputs: Vec<(u64, String)> = req
        .outputs
        .iter()
        .map(|o| (o.value, o.script_pubkey.clone()))
        .collect();

    Ok(features::decode_outputs(&outputs))
}

/// Detect 1Sat Ordinal inscriptions in a list of transaction outputs.
///
/// Convenience command for the Ordinals view — returns only outputs
/// that contain ordinal inscriptions.
#[tauri::command]
pub async fn get_ordinals(req: DecodeOutputsRequest) -> Result<Vec<DecodedOutput>, String> {
    log::debug!("get_ordinals — checking {} outputs", req.outputs.len());

    let outputs: Vec<(u64, String)> = req
        .outputs
        .iter()
        .map(|o| (o.value, o.script_pubkey.clone()))
        .collect();

    let decoded = features::decode_outputs(&outputs);

    Ok(decoded
        .into_iter()
        .filter(|d| {
            matches!(
                d.kind,
                features::DecodedKind::Ordinal(_)
            )
        })
        .collect())
}

/// Decode OP_RETURN protocol data from a list of outputs.
///
/// Convenience command for the protocol data view — returns only outputs
/// that contain recognized OP_RETURN protocols (B, MAP, Bcat, BAP, 21E8).
#[tauri::command]
pub async fn get_protocol_data(req: DecodeOutputsRequest) -> Result<Vec<DecodedOutput>, String> {
    log::debug!("get_protocol_data — checking {} outputs", req.outputs.len());

    let outputs: Vec<(u64, String)> = req
        .outputs
        .iter()
        .map(|o| (o.value, o.script_pubkey.clone()))
        .collect();

    let decoded = features::decode_outputs(&outputs);

    Ok(decoded
        .into_iter()
        .filter(|d| {
            matches!(
                d.kind,
                features::DecodedKind::OpReturnProtocol(_)
            )
        })
        .collect())
}

/// Detect STAS token transfers in a list of outputs.
///
/// Convenience command for the tokens view — returns only outputs
/// that match STAS token patterns.
#[tauri::command]
pub async fn get_token_transfers(req: DecodeOutputsRequest) -> Result<Vec<DecodedOutput>, String> {
    log::debug!("get_token_transfers — checking {} outputs", req.outputs.len());

    let outputs: Vec<(u64, String)> = req
        .outputs
        .iter()
        .map(|o| (o.value, o.script_pubkey.clone()))
        .collect();

    let decoded = features::decode_outputs(&outputs);

    Ok(decoded
        .into_iter()
        .filter(|d| {
            matches!(
                d.kind,
                features::DecodedKind::StasToken(_)
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_op_return_b() -> DecodeOutputRequest {
        // B-Protocol: OP_RETURN "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut" "Hello" "text/plain" "utf-8" "hello.txt"
        let mut script = vec![0x6A];
        let prefix = b"19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut";
        script.push(prefix.len() as u8);
        script.extend_from_slice(prefix);
        let data = b"Hello";
        script.push(data.len() as u8);
        script.extend_from_slice(data);
        let ct = b"text/plain";
        script.push(ct.len() as u8);
        script.extend_from_slice(ct);
        DecodeOutputRequest {
            value: 0,
            script_pubkey: hex::encode(&script),
        }
    }

    #[tokio::test]
    async fn test_decode_output_b_protocol() {
        let req = make_op_return_b();
        let result = decode_output(req).await.unwrap();
        assert!(matches!(
            result.kind,
            features::DecodedKind::OpReturnProtocol(_)
        ));
    }

    #[tokio::test]
    async fn test_decode_outputs_plain() {
        let req = DecodeOutputsRequest {
            outputs: vec![DecodeOutputRequest {
                value: 50000,
                script_pubkey: "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac".to_string(),
            }],
        };
        let result = decode_tx_outputs(req).await.unwrap();
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0].kind, features::DecodedKind::Plain));
    }

    #[tokio::test]
    async fn test_get_ordinals_filters() {
        // Mix of plain and ordinal outputs
        let plain = DecodeOutputRequest {
            value: 50000,
            script_pubkey: "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac".to_string(),
        };
        let req = DecodeOutputsRequest {
            outputs: vec![plain],
        };
        let result = get_ordinals(req).await.unwrap();
        assert!(result.is_empty()); // no ordinals in plain output
    }
}