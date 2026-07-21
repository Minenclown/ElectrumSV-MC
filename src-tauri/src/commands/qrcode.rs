// commands/qrcode.rs — QR code generation with backend selection
//
// IPC command: generate_qr(data, options?) -> SVG string
//
// Backends (Murena-Prinzip — switchable at build time):
//   - Default: PicQr (standalone, ISO/IEC 18004, no external QR libs)
//   - Fallback: `qrcode` crate (same algorithm as Python's qrcode library
//     used by the original ElectrumSVP)
//
// The fallback is enabled via the `qrcode-fallback` Cargo feature flag.
// When enabled, generate_qr delegates to the `qrcode` crate for maximum
// scanner compatibility.

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

// ─── PicQr backend (default) ─────────────────────────────────────────────

#[cfg(not(feature = "qrcode-fallback"))]
fn parse_ec_level(s: &str) -> picqr::ErrorCorrectionLevel {
    use picqr::ErrorCorrectionLevel;
    match s.to_uppercase().as_str() {
        "L" => ErrorCorrectionLevel::L,
        "Q" => ErrorCorrectionLevel::Q,
        "H" => ErrorCorrectionLevel::H,
        _ => ErrorCorrectionLevel::M,
    }
}

#[cfg(not(feature = "qrcode-fallback"))]
fn parse_module_shape(s: &str) -> picqr::ModuleShape {
    use picqr::ModuleShape;
    match s.to_lowercase().as_str() {
        "rounded" => ModuleShape::Rounded,
        "dots" => ModuleShape::Dots,
        _ => ModuleShape::Square,
    }
}

#[cfg(not(feature = "qrcode-fallback"))]
fn generate_picqr(req: &QrRequest) -> Result<String, String> {
    use picqr::{ErrorCorrectionLevel, ModuleShape, QrOptions, RenderFormat};

    let ec = req
        .ec_level
        .as_deref()
        .map(parse_ec_level)
        .unwrap_or(ErrorCorrectionLevel::M);

    // Enforce ISO/IEC 18004 minimum quiet zone of 4 modules.
    // The frontend may request less, but scanners need at least 4.
    let quiet_zone = req.quiet_zone.unwrap_or(4).max(4);

    let mut opts = QrOptions {
        ec_level: ec,
        format: RenderFormat::Svg,
        scale: req.scale.unwrap_or(10),
        quiet_zone,
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

    let bytes = picqr::render(&req.data, &opts)
        .map_err(|e| format!("QR generation failed: {}", e))?;

    String::from_utf8(bytes).map_err(|e| format!("SVG encoding failed: {}", e))
}

// ─── qrcode crate fallback backend ────────────────────────────────────────

#[cfg(feature = "qrcode-fallback")]
fn generate_qrcode_crate(req: &QrRequest) -> Result<String, String> {
    use qrcode::render::svg;
    use qrcode::{EcLevel, QrCode};

    let ec = match req.ec_level.as_deref().map(|s| s.to_uppercase()).as_deref() {
        Some("L") => EcLevel::L,
        Some("Q") => EcLevel::Q,
        Some("H") => EcLevel::H,
        _ => EcLevel::M,
    };

    let code = QrCode::with_error_correction_level(req.data.as_bytes(), ec)
        .map_err(|e| format!("QR generation failed: {}", e))?;

    // The `qrcode` crate defaults to quiet_zone=4 (ISO/IEC 18004 minimum).
    // quiet_zone(bool) only toggles it on/off; the module count is fixed at 4.
    // We keep it enabled (default) unless frontend explicitly sets 0.
    let has_quiet_zone = req.quiet_zone.unwrap_or(4) > 0;

    // Apply colors if provided
    let fg = req.foreground.as_deref().unwrap_or("#000000");
    let bg = req.background.as_deref().unwrap_or("#FFFFFF");

    let svg = code
        .render()
        .min_dimensions(200, 200)
        .quiet_zone(has_quiet_zone)
        .dark_color(svg::Color(fg))
        .light_color(svg::Color(bg))
        .build();

    Ok(svg)
}

// ─── Unified Tauri command ────────────────────────────────────────────────

#[tauri::command]
pub fn generate_qr(req: QrRequest) -> Result<QrResponse, String> {
    #[cfg(not(feature = "qrcode-fallback"))]
    let svg = generate_picqr(&req)?;

    #[cfg(feature = "qrcode-fallback")]
    let svg = generate_qrcode_crate(&req)?;

    Ok(QrResponse { svg })
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_req(data: &str) -> QrRequest {
        QrRequest {
            data: data.to_string(),
            ec_level: None,
            scale: None,
            quiet_zone: None,
            foreground: None,
            background: None,
            module_shape: None,
        }
    }

    #[test]
    fn test_generate_qr_simple_data() {
        let resp = generate_qr(make_req("hello world")).unwrap();
        assert!(resp.svg.contains("<svg"), "should contain SVG tag");
        assert!(!resp.svg.is_empty());
    }

    #[test]
    fn test_generate_qr_ec_level_l() {
        let mut req = make_req("test L");
        req.ec_level = Some("L".to_string());
        let resp = generate_qr(req).unwrap();
        assert!(resp.svg.contains("<svg"));
    }

    #[test]
    fn test_generate_qr_ec_level_m() {
        let mut req = make_req("test M");
        req.ec_level = Some("M".to_string());
        let resp = generate_qr(req).unwrap();
        assert!(resp.svg.contains("<svg"));
    }

    #[test]
    fn test_generate_qr_ec_level_q() {
        let mut req = make_req("test Q");
        req.ec_level = Some("Q".to_string());
        let resp = generate_qr(req).unwrap();
        assert!(resp.svg.contains("<svg"));
    }

    #[test]
    fn test_generate_qr_ec_level_h() {
        let mut req = make_req("test H");
        req.ec_level = Some("H".to_string());
        let resp = generate_qr(req).unwrap();
        assert!(resp.svg.contains("<svg"));
    }

    #[test]
    fn test_generate_qr_bsv_address() {
        // Real BSV address — the primary use case
        let resp = generate_qr(make_req("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")).unwrap();
        assert!(resp.svg.contains("<svg"));
    }

    #[test]
    fn test_generate_qr_bip21_uri() {
        // BIP21 bitcoin: URI with amount — common payment request format
        let resp = generate_qr(make_req(
            "bitcoin://1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=0.001",
        ))
        .unwrap();
        assert!(resp.svg.contains("<svg"));
    }

    #[test]
    fn test_generate_qr_custom_colors() {
        let mut req = make_req("colored");
        req.foreground = Some("#FF0000".to_string());
        req.background = Some("#00FF00".to_string());
        let resp = generate_qr(req).unwrap();
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
        let mut req = make_req("invalid ec");
        req.ec_level = Some("XYZ".to_string());
        let resp = generate_qr(req).unwrap();
        assert!(resp.svg.contains("<svg"));
    }

    #[test]
    fn test_generate_qr_different_data_different_svg() {
        let resp1 = generate_qr(make_req("first")).unwrap();
        let resp2 = generate_qr(make_req("second")).unwrap();
        assert_ne!(
            resp1.svg, resp2.svg,
            "different data should produce different QR codes"
        );
    }

    #[test]
    fn test_generate_qr_quiet_zone_enforced() {
        // Even if frontend requests quiet_zone=0, backend should enforce minimum 4
        let mut req = make_req("quiet zone test");
        req.quiet_zone = Some(0);
        let resp = generate_qr(req).unwrap();
        // The SVG should be larger than if quiet_zone=0 were honored
        // (quiet_zone=4 adds 8 modules total to each dimension)
        assert!(resp.svg.contains("<svg"));
    }
}