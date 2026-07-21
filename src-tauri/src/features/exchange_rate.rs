// features/exchange_rate.rs — Multi-provider BSV fiat exchange rates
//
// Ported from archive/electrumsv/exchange_rate.py
//
// Provides BSV-to-fiat exchange rate lookups via multiple providers:
//   - BitPay, Bitfinex, Coinbase, CoinPaprika, CoinCap, CoinGecko
//
// Each provider implements the `ExchangeRateProvider` trait. The
// `ExchangeRateService` aggregates providers and can query them in
// fallback order.
//
// References:
//   - Python: exchange_rate.py (ExchangeBase subclasses)
//   - ISO 4217 currency precision handling

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

const USER_AGENT: &str = "ElectrumSV";
const TIMEOUT_SECS: u64 = 10;

/// 1 BSV = 100,000,000 satoshis
pub const COIN: u64 = 100_000_000;

/// ISO 4217 non-standard decimal precisions (from Python CCY_PRECISIONS).
/// Currencies not in this map default to 2 decimal places.
pub fn ccy_precision(ccy: &str) -> u32 {
    match ccy {
        "BHD" | "IQD" | "JOD" | "KWD" | "LYD" | "OMR" | "TND" => 3,
        "MGA" | "MRO" => 1,
        "BIF" | "BYR" | "CLP" | "CVE" | "DJF" | "GNF" | "ISK" | "JPY" | "KMF"
        | "KRW" | "PYG" | "RWF" | "UGX" | "UYI" | "VND" | "VUV" | "XAF" | "XOF"
        | "XPF" => 0,
        "CLF" | "XAU" => 4,
        _ => 2,
    }
}

// ============================================================================
// Error types
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum ExchangeRateError {
    #[error("HTTP request failed for {provider}: {reason}")]
    Http { provider: String, reason: String },
    #[error("invalid response from {provider}: {reason}")]
    InvalidResponse { provider: String, reason: String },
    #[error("no rates available from any provider")]
    NoRates,
    #[error("unknown currency: {0}")]
    UnknownCurrency(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

// ============================================================================
// Data types
// ============================================================================

/// A fiat exchange rate quote for BSV.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateQuote {
    /// Currency code (e.g. "USD", "EUR")
    pub currency: String,
    /// Price of 1 BSV in that currency
    pub rate: f64,
    /// Source provider name
    pub source: String,
}

// ============================================================================
// Provider trait
// ============================================================================

/// A BSV exchange rate provider.
#[async_trait::async_trait]
pub trait ExchangeRateProvider: Send + Sync {
    /// Stable identifier (e.g. "coingecko").
    fn id(&self) -> &'static str;

    /// Fetch current BSV-to-fiat rates as a map of currency → rate.
    async fn get_rates(&self, client: &reqwest::Client) -> Result<HashMap<String, f64>, ExchangeRateError>;
}

// ============================================================================
// Helper
// ============================================================================

async fn fetch_json(
    client: &reqwest::Client,
    provider: &str,
    url: &str,
) -> Result<serde_json::Value, ExchangeRateError> {
    let resp = client
        .get(url)
        .header("User-Agent", USER_AGENT)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| ExchangeRateError::Http {
            provider: provider.to_string(),
            reason: e.to_string(),
        })?;

    if !resp.status().is_success() {
        return Err(ExchangeRateError::Http {
            provider: provider.to_string(),
            reason: format!("HTTP {}", resp.status()),
        });
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| ExchangeRateError::InvalidResponse {
            provider: provider.to_string(),
            reason: e.to_string(),
        })?;

    Ok(json)
}

// ============================================================================
// Concrete providers
// ============================================================================

/// BitPay: https://bitpay.com/api/rates/BSV
pub struct BitPay;

#[async_trait::async_trait]
impl ExchangeRateProvider for BitPay {
    fn id(&self) -> &'static str {
        "bitpay"
    }

    async fn get_rates(
        &self,
        client: &reqwest::Client,
    ) -> Result<HashMap<String, f64>, ExchangeRateError> {
        let json = fetch_json(client, self.id(), "https://bitpay.com/api/rates/BSV").await?;
        let arr = json
            .as_array()
            .ok_or_else(|| ExchangeRateError::InvalidResponse {
                provider: self.id().to_string(),
                reason: "expected array".to_string(),
            })?;

        let mut rates = HashMap::new();
        for entry in arr {
            let code = entry["code"].as_str().unwrap_or("");
            let rate = entry["rate"].as_f64();
            if !code.is_empty() {
                if let Some(r) = rate {
                    rates.insert(code.to_string(), r);
                }
            }
        }

        if rates.is_empty() {
            return Err(ExchangeRateError::InvalidResponse {
                provider: self.id().to_string(),
                reason: "no rates in response".to_string(),
            });
        }
        Ok(rates)
    }
}

/// Bitfinex: https://api.bitfinex.com/v2/tickers?symbols=tBSVUSD
pub struct Bitfinex;

#[async_trait::async_trait]
impl ExchangeRateProvider for Bitfinex {
    fn id(&self) -> &'static str {
        "bitfinex"
    }

    async fn get_rates(
        &self,
        client: &reqwest::Client,
    ) -> Result<HashMap<String, f64>, ExchangeRateError> {
        let json = fetch_json(
            client,
            self.id(),
            "https://api.bitfinex.com/v2/tickers?symbols=tBSVUSD",
        )
        .await?;

        let arr = json
            .as_array()
            .ok_or_else(|| ExchangeRateError::InvalidResponse {
                provider: self.id().to_string(),
                reason: "expected array".to_string(),
            })?;

        // Bitfinex ticker: [SYMBOL, BID, BID_SIZE, ASK, ASK_SIZE, ..., LAST_PRICE(7), ...]
        if arr.is_empty() {
            return Err(ExchangeRateError::InvalidResponse {
                provider: self.id().to_string(),
                reason: "empty ticker array".to_string(),
            });
        }

        let entry = &arr[0];
        let last_price = entry
            .get(7)
            .and_then(|v| v.as_f64())
            .ok_or_else(|| ExchangeRateError::InvalidResponse {
                provider: self.id().to_string(),
                reason: "missing last price at index 7".to_string(),
            })?;

        let mut rates = HashMap::new();
        rates.insert("USD".to_string(), last_price);
        Ok(rates)
    }
}

/// Coinbase: https://api.coinbase.com/v2/exchange-rates?currency=BSV
pub struct Coinbase;

#[async_trait::async_trait]
impl ExchangeRateProvider for Coinbase {
    fn id(&self) -> &'static str {
        "coinbase"
    }

    async fn get_rates(
        &self,
        client: &reqwest::Client,
    ) -> Result<HashMap<String, f64>, ExchangeRateError> {
        let json = fetch_json(
            client,
            self.id(),
            "https://api.coinbase.com/v2/exchange-rates?currency=BSV",
        )
        .await?;

        let rates_obj = json["data"]["rates"]
            .as_object()
            .ok_or_else(|| ExchangeRateError::InvalidResponse {
                provider: self.id().to_string(),
                reason: "missing data.rates object".to_string(),
            })?;

        let mut rates = HashMap::new();
        for (ccy, val) in rates_obj {
            if let Some(r) = val.as_f64() {
                rates.insert(ccy.clone(), r);
            }
        }

        if rates.is_empty() {
            return Err(ExchangeRateError::InvalidResponse {
                provider: self.id().to_string(),
                reason: "no rates in response".to_string(),
            });
        }
        Ok(rates)
    }
}

/// CoinPaprika: https://api.coinpaprika.com/v1/tickers/bsv-bitcoin-sv
pub struct CoinPaprika;

#[async_trait::async_trait]
impl ExchangeRateProvider for CoinPaprika {
    fn id(&self) -> &'static str {
        "coinpaprika"
    }

    async fn get_rates(
        &self,
        client: &reqwest::Client,
    ) -> Result<HashMap<String, f64>, ExchangeRateError> {
        let json = fetch_json(
            client,
            self.id(),
            "https://api.coinpaprika.com/v1/tickers/bsv-bitcoin-sv",
        )
        .await?;

        let price = json["quotes"]["USD"]["price"]
            .as_f64()
            .ok_or_else(|| ExchangeRateError::InvalidResponse {
                provider: self.id().to_string(),
                reason: "missing quotes.USD.price".to_string(),
            })?;

        let mut rates = HashMap::new();
        rates.insert("USD".to_string(), price);
        Ok(rates)
    }
}

/// CoinCap: https://api.coincap.io/v2/assets/bitcoin-sv
pub struct CoinCap;

#[async_trait::async_trait]
impl ExchangeRateProvider for CoinCap {
    fn id(&self) -> &'static str {
        "coincap"
    }

    async fn get_rates(
        &self,
        client: &reqwest::Client,
    ) -> Result<HashMap<String, f64>, ExchangeRateError> {
        let json = fetch_json(
            client,
            self.id(),
            "https://api.coincap.io/v2/assets/bitcoin-sv",
        )
        .await?;

        let price = json["data"]["priceUsd"]
            .as_f64()
            .ok_or_else(|| ExchangeRateError::InvalidResponse {
                provider: self.id().to_string(),
                reason: "missing data.priceUsd".to_string(),
            })?;

        let mut rates = HashMap::new();
        rates.insert("USD".to_string(), price);
        Ok(rates)
    }
}

/// CoinGecko: https://api.coingecko.com/api/v3/coins/bitcoin-cash-sv
pub struct CoinGecko;

#[async_trait::async_trait]
impl ExchangeRateProvider for CoinGecko {
    fn id(&self) -> &'static str {
        "coingecko"
    }

    async fn get_rates(
        &self,
        client: &reqwest::Client,
    ) -> Result<HashMap<String, f64>, ExchangeRateError> {
        let json = fetch_json(
            client,
            self.id(),
            "https://api.coingecko.com/api/v3/coins/bitcoin-cash-sv?localization=false&sparkline=false",
        )
        .await?;

        let prices = json["market_data"]["current_price"]
            .as_object()
            .ok_or_else(|| ExchangeRateError::InvalidResponse {
                provider: self.id().to_string(),
                reason: "missing market_data.current_price".to_string(),
            })?;

        let mut rates = HashMap::new();
        for (ccy, val) in prices {
            if let Some(r) = val.as_f64() {
                rates.insert(ccy.to_uppercase(), r);
            }
        }

        if rates.is_empty() {
            return Err(ExchangeRateError::InvalidResponse {
                provider: self.id().to_string(),
                reason: "no rates in response".to_string(),
            });
        }
        Ok(rates)
    }
}

// ============================================================================
// Service — aggregates providers
// ============================================================================

/// Aggregates multiple exchange rate providers and queries them in order
/// until one succeeds.
pub struct ExchangeRateService {
    client: reqwest::Client,
    providers: Vec<Box<dyn ExchangeRateProvider>>,
}

impl Default for ExchangeRateService {
    fn default() -> Self {
        Self::new()
    }
}

impl ExchangeRateService {
    /// Create a new service with all default providers (CoinGecko first,
    /// matching the Python default).
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .build()
            .expect("failed to build reqwest client for ExchangeRateService");

        let providers: Vec<Box<dyn ExchangeRateProvider>> = vec![
            Box::new(CoinGecko),
            Box::new(BitPay),
            Box::new(Coinbase),
            Box::new(Bitfinex),
            Box::new(CoinPaprika),
            Box::new(CoinCap),
        ];

        Self { client, providers }
    }

    /// Create a service with a custom provider list (useful for testing).
    pub fn with_providers(providers: Vec<Box<dyn ExchangeRateProvider>>) -> Self {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .build()
            .expect("failed to build reqwest client for ExchangeRateService");

        Self { client, providers }
    }

    /// Get the list of registered provider IDs.
    pub fn provider_ids(&self) -> Vec<&'static str> {
        self.providers.iter().map(|p| p.id()).collect()
    }

    /// Fetch rates from a specific provider by ID.
    pub async fn get_rates_from(
        &self,
        provider_id: &str,
    ) -> Result<HashMap<String, f64>, ExchangeRateError> {
        let provider = self
            .providers
            .iter()
            .find(|p| p.id() == provider_id)
            .ok_or_else(|| ExchangeRateError::UnknownCurrency(provider_id.to_string()))?;
        provider.get_rates(&self.client).await
    }

    /// Fetch rates from all providers, returning the first successful result.
    pub async fn get_rates(&self) -> Result<HashMap<String, f64>, ExchangeRateError> {
        let mut last_error = ExchangeRateError::NoRates;
        for provider in &self.providers {
            match provider.get_rates(&self.client).await {
                Ok(rates) => return Ok(rates),
                Err(e) => last_error = e,
            }
        }
        Err(last_error)
    }

    /// Get the rate for a specific currency from the first provider that has it.
    pub async fn get_rate(&self, currency: &str) -> Result<RateQuote, ExchangeRateError> {
        let rates = self.get_rates().await?;
        let rate = rates
            .get(currency)
            .ok_or_else(|| ExchangeRateError::UnknownCurrency(currency.to_string()))?;
        Ok(RateQuote {
            currency: currency.to_string(),
            rate: *rate,
            source: "aggregated".to_string(),
        })
    }

    /// Convert satoshis to a fiat amount given a rate.
    pub fn satoshis_to_fiat(satoshis: u64, rate: f64) -> f64 {
        (satoshis as f64) / (COIN as f64) * rate
    }

    /// Format a fiat amount with proper currency precision.
    pub fn format_fiat(amount: f64, currency: &str, commas: bool) -> String {
        let prec = ccy_precision(currency);
        let formatted = format!("{:.*}", prec as usize, amount);
        if commas {
            // Insert thousands separator
            let parts: Vec<&str> = formatted.split('.').collect();
            let int_part = parts[0];
            let dec_part = parts.get(1).copied().unwrap_or("");

            let neg = int_part.starts_with('-');
            let digits = if neg { &int_part[1..] } else { int_part };
            let mut grouped = String::new();
            for (i, c) in digits.chars().rev().enumerate() {
                if i > 0 && i % 3 == 0 {
                    grouped.insert(0, ',');
                }
                grouped.insert(0, c);
            }
            let result = if neg {
                format!("-{grouped}")
            } else {
                grouped
            };
            if prec > 0 && !dec_part.is_empty() {
                format!("{result}.{dec_part}")
            } else {
                result
            }
        } else {
            formatted
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Currency precision ---

    #[test]
    fn test_ccy_precision_defaults() {
        assert_eq!(ccy_precision("USD"), 2);
        assert_eq!(ccy_precision("EUR"), 2);
        assert_eq!(ccy_precision("GBP"), 2);
        assert_eq!(ccy_precision("JPY"), 0);
        assert_eq!(ccy_precision("KRW"), 0);
        assert_eq!(ccy_precision("BHD"), 3);
        assert_eq!(ccy_precision("XAU"), 4);
        assert_eq!(ccy_precision("XXX"), 2); // unknown → 2
    }

    // --- Satoshis to fiat ---

    #[test]
    fn test_satoshis_to_fiat() {
        // 1 BSV = 100M sats, rate $50 → $50
        assert!((ExchangeRateService::satoshis_to_fiat(COIN, 50.0) - 50.0).abs() < 1e-6);
        // 0.5 BSV → $25
        assert!(
            (ExchangeRateService::satoshis_to_fiat(COIN / 2, 50.0) - 25.0).abs()
                < 1e-6
        );
        // 0 sats → $0
        assert_eq!(ExchangeRateService::satoshis_to_fiat(0, 100.0), 0.0);
    }

    // --- Fiat formatting ---

    #[test]
    fn test_format_fiat_usd() {
        let s = ExchangeRateService::format_fiat(1234.56, "USD", false);
        assert_eq!(s, "1234.56");
    }

    #[test]
    fn test_format_fiat_jpy_no_decimals() {
        let s = ExchangeRateService::format_fiat(1234.0, "JPY", false);
        assert_eq!(s, "1234");
    }

    #[test]
    fn test_format_fiat_bhd_three_decimals() {
        let s = ExchangeRateService::format_fiat(1.234, "BHD", false);
        assert_eq!(s, "1.234");
    }

    #[test]
    fn test_format_fiat_with_commas() {
        let s = ExchangeRateService::format_fiat(1234567.89, "USD", true);
        assert_eq!(s, "1,234,567.89");
    }

    // --- Service construction ---

    #[test]
    fn test_service_default_providers() {
        let svc = ExchangeRateService::new();
        let ids = svc.provider_ids();
        assert!(ids.contains(&"coingecko"));
        assert!(ids.contains(&"bitpay"));
        assert!(ids.contains(&"coinbase"));
        assert_eq!(ids.len(), 6);
    }

    // --- Fake provider for aggregation test ---

    struct FakeProvider {
        id: &'static str,
        rates: Option<HashMap<String, f64>>,
    }

    #[async_trait::async_trait]
    impl ExchangeRateProvider for FakeProvider {
        fn id(&self) -> &'static str {
            self.id
        }

        async fn get_rates(
            &self,
            _client: &reqwest::Client,
        ) -> Result<HashMap<String, f64>, ExchangeRateError> {
            match &self.rates {
                Some(r) => Ok(r.clone()),
                None => Err(ExchangeRateError::InvalidResponse {
                    provider: self.id.to_string(),
                    reason: "no rates".to_string(),
                }),
            }
        }
    }

    #[tokio::test]
    async fn test_aggregation_first_provider_wins() {
        let mut rates = HashMap::new();
        rates.insert("USD".to_string(), 50.0);

        let svc = ExchangeRateService::with_providers(vec![
            Box::new(FakeProvider {
                id: "good",
                rates: Some(rates.clone()),
            }),
            Box::new(FakeProvider {
                id: "bad",
                rates: None,
            }),
        ]);

        let result = svc.get_rates().await.unwrap();
        assert_eq!(result.get("USD"), Some(&50.0));
    }

    #[tokio::test]
    async fn test_aggregation_fallback_to_second() {
        let svc = ExchangeRateService::with_providers(vec![
            Box::new(FakeProvider {
                id: "bad",
                rates: None,
            }),
            Box::new(FakeProvider {
                id: "good",
                rates: Some({
                    let mut m = HashMap::new();
                    m.insert("EUR".to_string(), 45.0);
                    m
                }),
            }),
        ]);

        let result = svc.get_rates().await.unwrap();
        assert_eq!(result.get("EUR"), Some(&45.0));
    }

    #[tokio::test]
    async fn test_aggregation_all_fail_returns_error() {
        let svc = ExchangeRateService::with_providers(vec![
            Box::new(FakeProvider {
                id: "bad1",
                rates: None,
            }),
            Box::new(FakeProvider {
                id: "bad2",
                rates: None,
            }),
        ]);

        let result = svc.get_rates().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_rate_for_specific_currency() {
        let svc = ExchangeRateService::with_providers(vec![Box::new(FakeProvider {
            id: "test",
            rates: Some({
                let mut m = HashMap::new();
                m.insert("USD".to_string(), 42.0);
                m
            }),
        })]);

        let quote = svc.get_rate("USD").await.unwrap();
        assert_eq!(quote.currency, "USD");
        assert!((quote.rate - 42.0).abs() < 1e-6);
    }

    #[tokio::test]
    async fn test_get_rate_unknown_currency() {
        let svc = ExchangeRateService::with_providers(vec![Box::new(FakeProvider {
            id: "test",
            rates: Some({
                let mut m = HashMap::new();
                m.insert("USD".to_string(), 42.0);
                m
            }),
        })]);

        let result = svc.get_rate("XYZ").await;
        assert!(matches!(result, Err(ExchangeRateError::UnknownCurrency(_))));
    }
}