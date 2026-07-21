// commands/ecosystem.rs — Tauri IPC commands for BSV ecosystem features
//
// Provides commands for:
// - PayMail address resolution (resolve_paymail)
// - Exchange rate lookups (get_exchange_rates, satoshis_to_fiat)
// - mAPI fee quotes (get_mapi_fee_quote)
// - BIP276 URI parsing (parse_bip276_uri)
// - Coin selection strategies (get_coin_selection_strategies)

use crate::features;

// ============================================================================
// PayMail
// ============================================================================

/// Result of resolving a PayMail handle to a BSV address.
#[derive(Debug, serde::Serialize)]
pub struct PayMailResult {
    pub handle: String,
    pub address: String,
}

/// Resolve a PayMail handle (user@domain) to a BSV address.
#[tauri::command]
pub async fn resolve_paymail(handle: String) -> Result<PayMailResult, String> {
    log::info!("resolve_paymail — handle: {}", handle);

    if !features::paymail::is_valid_handle(&handle) {
        return Err(format!("invalid PayMail handle: {}", handle));
    }

    let resolver = features::paymail::PayMailResolver::new();
    let address = resolver
        .resolve_address(&handle)
        .await
        .map_err(|e| e.to_string())?;

    Ok(PayMailResult { handle, address })
}

// ============================================================================
// Exchange Rates
// ============================================================================

/// A single fiat rate entry.
#[derive(Debug, serde::Serialize)]
pub struct FiatRate {
    pub currency: String,
    pub rate: f64,
}

/// Fetch current BSV-to-fiat exchange rates from all providers.
///
/// Returns a list of (currency, rate) pairs aggregated from all providers.
#[tauri::command]
pub async fn get_exchange_rates() -> Result<Vec<FiatRate>, String> {
    log::info!("get_exchange_rates");

    let service = features::exchange_rate::ExchangeRateService::new();
    let rates = service
        .get_rates()
        .await
        .map_err(|e| e.to_string())?;

    Ok(rates
        .into_iter()
        .map(|(currency, rate)| FiatRate { currency, rate })
        .collect())
}

/// Get a single rate quote for a specific currency.
#[tauri::command]
pub async fn get_exchange_rate(currency: String) -> Result<f64, String> {
    log::info!("get_exchange_rate — currency: {}", currency);

    let service = features::exchange_rate::ExchangeRateService::new();
    let quote = service
        .get_rate(&currency)
        .await
        .map_err(|e| e.to_string())?;

    Ok(quote.rate)
}

/// Convert satoshis to a fiat amount using the best available rate.
///
/// Fetches the rate for the given currency, then multiplies by satoshis/1e8.
#[tauri::command]
pub async fn satoshis_to_fiat(satoshis: u64, currency: String) -> Result<f64, String> {
    log::info!("satoshis_to_fiat — {} sat to {}", satoshis, currency);

    let service = features::exchange_rate::ExchangeRateService::new();
    let quote = service
        .get_rate(&currency)
        .await
        .map_err(|e| e.to_string())?;

    Ok(features::exchange_rate::ExchangeRateService::satoshis_to_fiat(satoshis, quote.rate))
}

// ============================================================================
// mAPI Fee Quote
// ============================================================================

/// Fee quote from a BSV Merchant API endpoint.
#[derive(Debug, serde::Serialize)]
pub struct MapiFeeQuote {
    pub mining_fee_satoshis: u64,
    pub relay_fee_satoshis: u64,
    pub raw: serde_json::Value,
}

/// Fetch a fee quote from a BSV mAPI endpoint.
///
/// The URL defaults to the BSV Association mAPI if not provided.
#[tauri::command]
pub async fn get_mapi_fee_quote(url: Option<String>) -> Result<MapiFeeQuote, String> {
    log::info!("get_mapi_fee_quote — url: {:?}", url);

    let default_url = "https://mapi.bsvassociation.org";
    let client = features::mapi::MapiClient::new(url.as_deref().unwrap_or(default_url));
    let quote = client
        .get_fee_quote()
        .await
        .map_err(|e| e.to_string())?;

    let mining_fee = quote.mining_fee().map(|f| f.satoshis).unwrap_or(0);
    let relay_fee = quote.relay_fee().map(|f| f.satoshis).unwrap_or(0);

    Ok(MapiFeeQuote {
        mining_fee_satoshis: mining_fee,
        relay_fee_satoshis: relay_fee,
        raw: serde_json::to_value(&quote).unwrap_or(serde_json::Value::Null),
    })
}

// ============================================================================
// BIP276 URI Parser
// ============================================================================

/// Parsed BIP276 bitcoin-script:// URI.
#[derive(Debug, serde::Serialize)]
pub struct Bip276Result {
    pub valid: bool,
    pub prefix: Option<String>,
    pub version: Option<u8>,
    pub network: Option<u8>,
    pub data_hex: Option<String>,
    pub error: Option<String>,
}

/// Parse a BIP276 bitcoin-script:// URI and extract the script data.
#[tauri::command]
pub fn parse_bip276_uri(uri: String) -> Result<Bip276Result, String> {
    log::info!("parse_bip276_uri — uri: {}", uri);

    match features::bip276::bip276_decode(&uri, None) {
        Ok(decoded) => Ok(Bip276Result {
            valid: true,
            prefix: Some(decoded.prefix),
            version: Some(decoded.version),
            network: Some(decoded.network),
            data_hex: Some(hex::encode(&decoded.data)),
            error: None,
        }),
        Err(e) => Ok(Bip276Result {
            valid: false,
            prefix: None,
            version: None,
            network: None,
            data_hex: None,
            error: Some(e.to_string()),
        }),
    }
}

// ============================================================================
// Coin Selection Strategies
// ============================================================================

/// Available coin selection strategy names.
#[derive(Debug, serde::Serialize)]
pub struct CoinSelectionStrategies {
    pub strategies: Vec<String>,
}

/// List available coin selection strategies.
#[tauri::command]
pub fn get_coin_selection_strategies() -> Result<CoinSelectionStrategies, String> {
    Ok(CoinSelectionStrategies {
        strategies: vec![
            "largest_first".to_string(),
            "branch_and_bound".to_string(),
            "random_subset".to_string(),
            "privacy".to_string(),
        ],
    })
}