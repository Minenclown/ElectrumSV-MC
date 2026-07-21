// commands/qrcode.rs — QR code generation via PicQr (standalone, no external QR libs)
//
// IPC command: generate_qr(data, options?) → SVG string
// Replaces the frontend `qrcode` npm package with our own Rust QR engine.

use picqr::{ErrorCorrectionLevel, ModuleShape, QrOptions, RenderFormat};
use serde::{Deserialize, Serialize};

/// Serializable QR options for IPC. All fields optional — defaults match QrOptions::default().
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrRequest {
    pub data: String,
    pub ec_level: Option<String>, // "L" | "M" | "Q" | "H"
    pub scale: Option<u32>,
    pub quiet_zone: Option<u32>,
    pub foreground: Option<String>,  // hex like "#000000"
    pub background: Option<String>, // hex like "#FFFFFF"
    pub module_shape: Option<String>, // "square" | "rounded" | "dots"
}

/// Response: SVG string (ready for dangerouslySetInnerHTML in React).
#[derive(Debug, Clone, Serialize)]
pub struct QrResponse {
    pub svg: String,
}

fn parse_ec_level(s: &str) -> ErrorCorrectionLevel {
    match s.to_uppercase().as_str() {
        "L" => ErrorCorrectionLevel::L,
        "Q" => ErrorCorrectionLevel::Q,
        "H" => ErrorCorrectionLevel::H,
        _ => ErrorCorrectionLevel::M,
    }
}

fn parse_module_shape(s: &str) -> ModuleShape {
    match s.to_lowercase().as_str() {
        "rounded" => ModuleShape::Rounded,
        "dots" => ModuleShape::Dots,
        _ => ModuleShape::Square,
    }
}

#[tauri::command]
pub fn generate_qr(req: QrRequest) -> Result<QrResponse, String> {
    let ec = req
        .ec_level
        .as_deref()
        .map(parse_ec_level)
        .unwrap_or(ErrorCorrectionLevel::M);
    let mut opts = QrOptions {
        ec_level: ec,
        format: RenderFormat::Svg,
        scale: req.scale.unwrap_or(1),
        quiet_zone: req.quiet_zone.unwrap_or(4),
        ..QrOptions::default()
    };

    if let Some(fg) = &req.foreground {
        opts.colors.foreground = fg.clone();
    }
    if let Some(bg) = &req.background {
        opts.colors.background = bg.clone();
    }
    if let Some(shape) = &req.module_shape {
        opts.module_shape = parse_module_shape(shape);
    }

    let bytes = picqr::render(&req.data, &opts).map_err(|e| format!("QR generation failed: {}", e))?;

    let svg = String::from_utf8(bytes).map_err(|e| format!("SVG encoding failed: {}", e))?;

    Ok(QrResponse { svg })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_qr_simple_data() {
        let req = QrRequest {
            data: "hello world".to_string(),
            ec_level: None,
            scale: None,
            quiet_zone: None,
            foreground: None,
            background: None,
            module_shape: None,
        };
        let resp = generate_qr(req).unwrap();
        assert!(resp.svg.contains("<svg"), "should contain SVG tag");
        assert!(!resp.svg.is_empty());
    }

    #[test]
    fn test_generate_qr_ec_level_l() {
        let req = QrRequest {
            data: "test L".to_string(),
            ec_level: Some("L".to_string()),
            scale: None,
            quiet_zone: None,
            foreground: None,
            background: None,
            module_shape: None,
        };
        let resp = generate_qr(req).unwrap();
        assert!(resp.svg.contains("<svg"));
    }

    #[test]
    fn test_generate_qr_ec_level_m() {
        let req = QrRequest {
            data: "test M".to_string(),
            ec_level: Some("M".to_string()),
            scale: None,
            quiet_zone: None,
            foreground: None,
            background: None,
            module_shape: None,
        };
        let resp = generate_qr(req).unwrap();
        assert!(resp.svg.contains("<svg"));
    }

    #[test]
    fn test_generate_qr_ec_level_q() {
        let req = QrRequest {
            data: "test Q".to_string(),
            ec_level: Some("Q".to_string()),
            scale: None,
            quiet_zone: None,
            foreground: None,
            background: None,
            module_shape: None,
        };
        let resp = generate_qr(req).unwrap();
        assert!(resp.svg.contains("<svg"));
    }

    #[test]
    fn test_generate_qr_ec_level_h() {
        let req = QrRequest {
            data: "test H".to_string(),
            ec_level: Some("H".to_string()),
            scale: None,
            quiet_zone: None,
            foreground: None,
            background: None,
            module_shape: None,
        };
        let resp = generate_qr(req).unwrap();
        assert!(resp.svg.contains("<svg"));
    }

    #[test]
    fn test_generate_qr_custom_colors() {
        let req = QrRequest {
            data: "colored".to_string(),
            ec_level: None,
            scale: None,
            quiet_zone: None,
            foreground: Some("#FF0000".to_string()),
            background: Some("#00FF00".to_string()),
            module_shape: None,
        };
        let resp = generate_qr(req).unwrap();
        // The SVG should reference the custom foreground color
        assert!(
            resp.svg.contains("#FF0000") || resp.svg.contains("FF0000"),
            "SVG should contain custom foreground color"
        );
        assert!(
            resp.svg.contains("#00FF00") || resp.svg.contains("00FF00"),
            "SVG should contain custom background color"
        );
    }

    #[test]
    fn test_generate_qr_invalid_ec_falls_back_to_m() {
        // Invalid EC level should fall back to M (default), not error
        let req = QrRequest {
            data: "invalid ec".to_string(),
            ec_level: Some("XYZ".to_string()),
            scale: None,
            quiet_zone: None,
            foreground: None,
            background: None,
            module_shape: None,
        };
        let resp = generate_qr(req).unwrap();
        assert!(resp.svg.contains("<svg"));
    }

    #[test]
    fn test_parse_ec_level_valid() {
        assert_eq!(parse_ec_level("L"), ErrorCorrectionLevel::L);
        assert_eq!(parse_ec_level("M"), ErrorCorrectionLevel::M);
        assert_eq!(parse_ec_level("Q"), ErrorCorrectionLevel::Q);
        assert_eq!(parse_ec_level("H"), ErrorCorrectionLevel::H);
    }

    #[test]
    fn test_parse_ec_level_case_insensitive() {
        assert_eq!(parse_ec_level("l"), ErrorCorrectionLevel::L);
        assert_eq!(parse_ec_level("m"), ErrorCorrectionLevel::M);
        assert_eq!(parse_ec_level("q"), ErrorCorrectionLevel::Q);
        assert_eq!(parse_ec_level("h"), ErrorCorrectionLevel::H);
    }

    #[test]
    fn test_parse_ec_level_invalid_defaults_to_m() {
        assert_eq!(parse_ec_level("Z"), ErrorCorrectionLevel::M);
        assert_eq!(parse_ec_level(""), ErrorCorrectionLevel::M);
        assert_eq!(parse_ec_level("xyz"), ErrorCorrectionLevel::M);
    }

    #[test]
    fn test_parse_module_shape_valid() {
        assert!(matches!(parse_module_shape("square"), ModuleShape::Square));
        assert!(matches!(parse_module_shape("rounded"), ModuleShape::Rounded));
        assert!(matches!(parse_module_shape("dots"), ModuleShape::Dots));
    }

    #[test]
    fn test_parse_module_shape_case_insensitive() {
        assert!(matches!(parse_module_shape("SQUARE"), ModuleShape::Square));
        assert!(matches!(parse_module_shape("ROUNDED"), ModuleShape::Rounded));
        assert!(matches!(parse_module_shape("DOTS"), ModuleShape::Dots));
    }

    #[test]
    fn test_parse_module_shape_invalid_defaults_to_square() {
        assert!(matches!(parse_module_shape("invalid"), ModuleShape::Square));
        assert!(matches!(parse_module_shape(""), ModuleShape::Square));
    }

    #[test]
    fn test_generate_qr_different_data_different_svg() {
        let req1 = QrRequest {
            data: "first".to_string(),
            ec_level: None,
            scale: None,
            quiet_zone: None,
            foreground: None,
            background: None,
            module_shape: None,
        };
        let req2 = QrRequest {
            data: "second".to_string(),
            ec_level: None,
            scale: None,
            quiet_zone: None,
            foreground: None,
            background: None,
            module_shape: None,
        };
        let resp1 = generate_qr(req1).unwrap();
        let resp2 = generate_qr(req2).unwrap();
        assert_ne!(
            resp1.svg, resp2.svg,
            "different data should produce different QR codes"
        );
    }
}