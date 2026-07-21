// core/transaction.rs — Transaction building, coin selection, and fee estimation
//
// Provides:
// - TxBuilder: constructs unsigned BSV transactions from UTXOs and outputs
// - CoinSelector: selects UTXOs for spending (largest-first strategy)
// - FeeEstimator: estimates transaction fees in satoshis
// - TxPlan: a serializable unsigned transaction plan with metadata
//
// Uses bsv-sdk Transaction, TransactionInput, TransactionOutput, and P2PKH
// script templates for construction. Signing is handled by the Signer trait
// in core/signer.rs.

use crate::core::coinchooser;
use crate::db::repositories::{TransactionOutputRow, UtxoInfo};
use bsv::script::inscriptions::op_return_data;
use bsv::script::templates::p2pkh::P2PKH;
use bsv::script::templates::ScriptTemplateLock;
use bsv::transaction::transaction::Transaction;
use bsv::transaction::transaction_input::TransactionInput;
use bsv::transaction::transaction_output::TransactionOutput;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Transaction building errors.
#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("insufficient funds: needed {needed} sat, available {available} sat")]
    InsufficientFunds { needed: u64, available: u64 },
    #[error("no UTXOs available")]
    NoUtxos,
    #[error("invalid output: {0}")]
    InvalidOutput(String),
    #[error("BSV SDK error: {0}")]
    BsvSdk(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

impl From<bsv::transaction::error::TransactionError> for TransactionError {
    fn from(e: bsv::transaction::error::TransactionError) -> Self {
        TransactionError::BsvSdk(e.to_string())
    }
}

impl From<bsv::script::error::ScriptError> for TransactionError {
    fn from(e: bsv::script::error::ScriptError) -> Self {
        TransactionError::BsvSdk(e.to_string())
    }
}

/// A payment output specification (address + amount in satoshis).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentOutput {
    /// BSV P2PKH address (e.g. "1A1zP1eP5...")
    pub address: String,
    /// Amount in satoshis
    pub satoshis: u64,
}

/// A UTXO selected for spending (simplified for TX building).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedUtxo {
    /// Display hex txid (reversed byte order)
    pub tx_hash_hex: String,
    /// Output index
    pub tx_index: u32,
    /// Value in satoshis
    pub satoshis: u64,
    /// KeyInstance ID that owns this UTXO
    pub keyinstance_id: i64,
    /// Derivation subpath for the key that owns this UTXO (e.g. [0, 3])
    pub subpath: [u32; 2],
}

impl SelectedUtxo {
    /// Create from a UtxoInfo (from DB) + subpath.
    pub fn from_utxo_info(info: &UtxoInfo, subpath: [u32; 2]) -> Self {
        SelectedUtxo {
            tx_hash_hex: info.tx_hash_hex.clone(),
            tx_index: info.tx_index as u32,
            satoshis: info.value as u64,
            keyinstance_id: info.keyinstance_id,
            subpath,
        }
    }

    /// Create from a TransactionOutputRow (from DB) + subpath.
    pub fn from_output_row(row: &TransactionOutputRow, subpath: [u32; 2]) -> Self {
        SelectedUtxo {
            tx_hash_hex: crate::core::address::hash_to_hex_str(&row.tx_hash),
            tx_index: row.tx_index as u32,
            satoshis: row.value as u64,
            keyinstance_id: row.keyinstance_id,
            subpath,
        }
    }
}

/// Result of coin selection.
#[derive(Debug, Clone)]
pub struct CoinSelectionResult {
    /// Selected UTXOs to spend
    pub selected: Vec<SelectedUtxo>,
    /// Total input value in satoshis
    pub total_input: u64,
    /// Total output value in satoshis (payments + change)
    pub total_output: u64,
    /// Fee in satoshis
    pub fee: u64,
    /// Change amount in satoshis (0 if no change output)
    pub change: u64,
}

/// Coin selector — largest-first strategy.
///
/// Selects UTXOs starting from the largest until the target amount + fee is covered.
/// This is a simple, deterministic strategy that minimizes the number of inputs.
pub struct CoinSelector;

impl CoinSelector {
    /// Select UTXOs to cover `target_amount + fee`.
    ///
    /// `available_utxos` is sorted descending by value before selection.
    /// Returns `InsufficientFunds` if the UTXOs cannot cover the target.
    pub fn select(
        available_utxos: &[SelectedUtxo],
        target_amount: u64,
        fee: u64,
    ) -> Result<CoinSelectionResult, TransactionError> {
        if available_utxos.is_empty() {
            return Err(TransactionError::NoUtxos);
        }

        let needed = target_amount
            .checked_add(fee)
            .ok_or_else(|| TransactionError::InvalidOutput("overflow in target + fee".into()))?;

        // Sort descending by satoshis (largest first)
        let mut sorted: Vec<&SelectedUtxo> = available_utxos.iter().collect();
        sorted.sort_by(|a, b| b.satoshis.cmp(&a.satoshis));

        let mut selected = Vec::new();
        let mut accumulated = 0u64;

        for utxo in &sorted {
            selected.push((*utxo).clone());
            accumulated = accumulated.checked_add(utxo.satoshis).ok_or_else(|| {
                TransactionError::InvalidOutput("overflow in accumulation".into())
            })?;
            if accumulated >= needed {
                break;
            }
        }

        if accumulated < needed {
            return Err(TransactionError::InsufficientFunds {
                needed,
                available: accumulated,
            });
        }

        let change = accumulated - needed;
        let total_input = accumulated;
        let total_output = target_amount + change;
        let actual_fee = fee;

        Ok(CoinSelectionResult {
            selected,
            total_input,
            total_output,
            fee: actual_fee,
            change,
        })
    }
}

/// Fee estimator — calculates fees based on transaction size.
///
/// BSV fee model: satoshis per byte. Default fee rate is 1 sat/byte
/// (0.001 sat/byte on the network, but 1 is a safe minimum for relay).
pub struct FeeEstimator;

impl FeeEstimator {
    /// Default fee rate: 1 sat/byte (BSV standard).
    pub const DEFAULT_FEE_RATE: u64 = 1; // sat/byte

    /// Estimate the fee for a transaction.
    ///
    /// `num_inputs`: number of inputs (UTXOs being spent)
    /// `num_outputs`: number of outputs (payments + change)
    /// `fee_rate`: satoshis per byte
    ///
    /// Transaction size estimate:
    /// - Base: 10 bytes (version + locktime + varint overhead)
    /// - Per input: 148 bytes (36 outpoint + ~108 unlocking script + 4 sequence)
    /// - Per output: 34 bytes (8 value + 1 varint + 25 P2PKH script)
    pub fn estimate_fee(num_inputs: usize, num_outputs: usize, fee_rate: u64) -> u64 {
        let base_size = 10u64;
        let input_size = 148u64 * num_inputs as u64;
        let output_size = 34u64 * num_outputs as u64;
        let total_size = base_size + input_size + output_size;
        total_size * fee_rate
    }

    /// Estimate fee with default fee rate (1 sat/byte).
    pub fn estimate_fee_default(num_inputs: usize, num_outputs: usize) -> u64 {
        Self::estimate_fee(num_inputs, num_outputs, Self::DEFAULT_FEE_RATE)
    }
}

/// A transaction plan — unsigned TX with metadata for AUD-007 binding.
///
/// The plan is:
/// 1. Created by `prepare_tx` (unsigned)
/// 2. Signed by `sign_tx` (requires TOTP verification)
/// 3. Broadcast by `broadcast_tx` (validates txid via AUD-006)
///
/// The plan is bound to a specific wallet by `wallet_path` to prevent
/// cross-wallet replay attacks (AUD-007).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxPlan {
    /// The unsigned transaction in hex format
    pub unsigned_tx_hex: String,
    /// Payment outputs
    pub outputs: Vec<PaymentOutput>,
    /// Selected UTXOs (inputs)
    pub inputs: Vec<SelectedUtxo>,
    /// Fee in satoshis
    pub fee: u64,
    /// Change amount in satoshis
    pub change: u64,
    /// Change address (if change > 0)
    pub change_address: Option<String>,
    /// Total input value in satoshis
    pub total_input: u64,
    /// Total output value in satoshis
    pub total_output: u64,
    /// Wallet path binding (AUD-007: plan can only be signed by this wallet)
    pub wallet_path: String,
    /// Account ID
    pub account_id: i64,
    /// Creation timestamp (Unix epoch)
    pub created_at: i64,
    /// Expiration timestamp (Unix epoch) — plan expires after this time
    pub expires_at: i64,
    /// Whether this plan has been signed
    pub signed: bool,
    /// Signed transaction hex (None until signed)
    pub signed_tx_hex: Option<String>,
    /// Transaction ID (None until signed)
    pub txid: Option<String>,
    /// OP_RETURN data embedded in the transaction (None if no OP_RETURN output)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_return: Option<Vec<u8>>,
}

/// Convert a `SelectedUtxo` into a `coinchooser::Coin` for use by the
/// advanced coin-selection strategies.
fn utxo_to_coin(utxo: &SelectedUtxo) -> coinchooser::Coin {
    coinchooser::Coin::new(
        utxo.tx_hash_hex.clone(),
        utxo.tx_index,
        utxo.satoshis,
        utxo.keyinstance_id,
    )
}

/// Transaction builder — constructs unsigned transactions.
pub struct TxBuilder;

impl TxBuilder {
    /// Build an unsigned transaction from selected UTXOs and payment outputs.
    ///
    /// `change_address`: P2PKH address for change output (if any change remains).
    /// `strategy`: optional coin-selection strategy. `None` keeps the default
    ///   largest-first `CoinSelector`. `Some(strategy)` delegates selection to
    ///   the `CoinChooser` module (BranchAndBound / RandomSubset / Privacy).
    /// Returns an unsigned Transaction and the CoinSelectionResult.
    pub fn build_unsigned(
        utxos: &[SelectedUtxo],
        outputs: &[PaymentOutput],
        change_address: Option<&str>,
        fee_rate: u64,
        op_return: Option<&[u8]>,
        strategy: Option<coinchooser::Strategy>,
    ) -> Result<(Transaction, CoinSelectionResult), TransactionError> {
        // Calculate total payment amount
        let total_payment: u64 = outputs
            .iter()
            .map(|o| o.satoshis)
            .sum::<u64>()
            .try_into()
            .map_err(|_| TransactionError::InvalidOutput("payment amount overflow".into()))?;

        if total_payment == 0 {
            return Err(TransactionError::InvalidOutput(
                "total payment is zero".into(),
            ));
        }

        // Estimate fee: we don't know the exact number of inputs yet, so we
        // estimate with all available UTXOs first, then select.
        // OP_RETURN output adds 1 extra output (0 satoshis, doesn't count toward payment)
        let op_return_extra_outputs = if op_return.is_some() { 1 } else { 0 };
        let num_outputs =
            outputs.len() + op_return_extra_outputs + if change_address.is_some() { 1 } else { 0 };

        // --- Coin selection -------------------------------------------------
        // Two code paths:
        //   * strategy == None  -> existing largest-first CoinSelector (default)
        //   * strategy == Some  -> CoinChooser with the requested Strategy
        //
        // Both paths produce a `CoinSelectionResult` with the selected UTXOs,
        // total input, fee, and change. The iterative fee recalculation below
        // converges for both paths because the fee depends on the number of
        // inputs, which can change between iterations.
        let selection = match strategy {
            None => {
                // Default path: largest-first CoinSelector with iterative fee.
                let mut fee = FeeEstimator::estimate_fee(1, num_outputs, fee_rate);

                loop {
                    let result = CoinSelector::select(utxos, total_payment, fee)?;

                    // Recalculate fee with actual number of inputs
                    let actual_fee =
                        FeeEstimator::estimate_fee(result.selected.len(), num_outputs, fee_rate);

                    if actual_fee == fee {
                        break result;
                    }

                    // Re-select with the updated fee
                    fee = actual_fee;
                }
            }
            Some(strategy) => {
                // CoinChooser path: convert UTXOs to Coins, run the chosen
                // strategy, then map the selected Coins back to SelectedUtxos.
                let coins: Vec<coinchooser::Coin> =
                    utxos.iter().map(utxo_to_coin).collect();

                let chooser = coinchooser::CoinChooser::new(strategy, fee_rate);
                let result = chooser
                    .select(&coins, total_payment)
                    .map_err(|e| match e {
                        coinchooser::CoinChooserError::InsufficientFunds { needed, available } => {
                            TransactionError::InsufficientFunds { needed, available }
                        }
                        coinchooser::CoinChooserError::NoCoins => TransactionError::NoUtxos,
                        other => TransactionError::InvalidOutput(other.to_string()),
                    })?;

                // Map selected Coins back to SelectedUtxos by (tx_hash_hex, tx_index).
                let mut lookup: std::collections::HashMap<(String, u32), &SelectedUtxo> =
                    std::collections::HashMap::new();
                for u in utxos {
                    lookup.insert((u.tx_hash_hex.clone(), u.tx_index), u);
                }
                let mut selected: Vec<SelectedUtxo> = Vec::with_capacity(result.coins.len());
                for c in &result.coins {
                    let utxo = lookup
                        .get(&(c.tx_hash_hex.clone(), c.tx_index))
                        .ok_or_else(|| {
                            TransactionError::InvalidOutput(format!(
                                "CoinChooser selected an unknown UTXO {}:{}",
                                c.tx_hash_hex, c.tx_index
                            ))
                        })?;
                    selected.push((*utxo).clone());
                }

                // Recalculate the fee with the proper FeeEstimator so the
                // change amount is consistent with the largest-first path.
                // The CoinChooser's internal fee only accounts for inputs +
                // base size; we add the output byte cost here so the
                // transaction's actual fee matches the FeeEstimator formula.
                let actual_fee = FeeEstimator::estimate_fee(
                    selected.len(),
                    num_outputs,
                    fee_rate,
                );
                let total_input = result.total_input;
                let needed = total_payment
                    .checked_add(actual_fee)
                    .ok_or_else(|| TransactionError::InvalidOutput("overflow".into()))?;
                if total_input < needed {
                    return Err(TransactionError::InsufficientFunds {
                        needed,
                        available: total_input,
                    });
                }
                let change = total_input - needed;
                let total_output = total_payment + change;

                CoinSelectionResult {
                    selected,
                    total_input,
                    total_output,
                    fee: actual_fee,
                    change,
                }
            }
        };

        // Build the transaction
        let mut tx = Transaction::new();

        // Add inputs (unsigned — no unlocking script)
        for utxo in &selection.selected {
            let input = TransactionInput {
                source_txid: Some(utxo.tx_hash_hex.clone()),
                source_output_index: utxo.tx_index,
                sequence: 0xFFFFFFFF,
                ..Default::default()
            };
            tx.add_input(input);
        }

        // Add payment outputs
        for output in outputs {
            let p2pkh = P2PKH::from_address(&output.address)?;
            let lock_script = p2pkh.lock()?;
            tx.add_output(TransactionOutput {
                satoshis: Some(output.satoshis),
                locking_script: lock_script,
                change: false,
            });
        }

        // Add OP_RETURN output if provided (0 satoshis, unspendable)
        if let Some(data) = op_return {
            let op_return_script = op_return_data(data);
            tx.add_output(TransactionOutput {
                satoshis: Some(0),
                locking_script: op_return_script,
                change: false,
            });
        }

        // Add change output if change > 0 and change address provided
        if selection.change > 0 {
            if let Some(addr) = change_address {
                let p2pkh = P2PKH::from_address(addr)?;
                let lock_script = p2pkh.lock()?;
                tx.add_output(TransactionOutput {
                    satoshis: Some(selection.change),
                    locking_script: lock_script,
                    change: true,
                });
            }
        }

        Ok((tx, selection))
    }

    /// Create a TxPlan from the built transaction.
    pub fn create_plan(
        tx: Transaction,
        outputs: Vec<PaymentOutput>,
        selection: CoinSelectionResult,
        change_address: Option<String>,
        wallet_path: String,
        account_id: i64,
        ttl_seconds: i64,
        op_return: Option<Vec<u8>>,
    ) -> Result<TxPlan, TransactionError> {
        let now = chrono::Utc::now().timestamp();
        let unsigned_tx_hex = tx.to_hex()?;

        Ok(TxPlan {
            unsigned_tx_hex,
            outputs,
            inputs: selection.selected.clone(),
            fee: selection.fee,
            change: selection.change,
            change_address,
            total_input: selection.total_input,
            total_output: selection.total_output,
            wallet_path,
            account_id,
            created_at: now,
            expires_at: now + ttl_seconds,
            signed: false,
            signed_tx_hex: None,
            txid: None,
            op_return,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known address for private key = 1: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
    const TEST_ADDRESS_A: &str = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
    // Known address for private key = ff: 1CCCCZ8Z4m5jvFp2F2Kp6wQ4q2N6vL8mZ (example)
    const TEST_ADDRESS_B: &str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"; // genesis address

    fn make_utxos() -> Vec<SelectedUtxo> {
        vec![
            SelectedUtxo {
                tx_hash_hex: "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458"
                    .to_string(),
                tx_index: 0,
                satoshis: 100_000,
                keyinstance_id: 1,
                subpath: [0, 0],
            },
            SelectedUtxo {
                tx_hash_hex: "b477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58459"
                    .to_string(),
                tx_index: 1,
                satoshis: 50_000,
                keyinstance_id: 2,
                subpath: [0, 1],
            },
            SelectedUtxo {
                tx_hash_hex: "c477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe5845a"
                    .to_string(),
                tx_index: 0,
                satoshis: 25_000,
                keyinstance_id: 3,
                subpath: [1, 0],
            },
        ]
    }

    // --- CoinSelector tests ---

    #[test]
    fn test_coin_selector_largest_first() {
        let utxos = make_utxos();
        let result = CoinSelector::select(&utxos, 80_000, 500).unwrap();

        // Should select the 100k UTXO first (largest)
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.selected[0].satoshis, 100_000);
        assert_eq!(result.total_input, 100_000);
    }

    #[test]
    fn test_coin_selector_needs_multiple() {
        let utxos = make_utxos();
        // Need 140k + 500 fee = 140500 — the 100k alone is not enough
        let result = CoinSelector::select(&utxos, 140_000, 500).unwrap();

        assert_eq!(result.selected.len(), 2);
        assert_eq!(result.selected[0].satoshis, 100_000);
        assert_eq!(result.selected[1].satoshis, 50_000);
        assert_eq!(result.total_input, 150_000);
        assert_eq!(result.change, 150_000 - 140_500);
    }

    #[test]
    fn test_coin_selector_insufficient() {
        let utxos = make_utxos();
        // Total available = 175000, need 200000
        let result = CoinSelector::select(&utxos, 200_000, 500);
        assert!(result.is_err());
        match result.unwrap_err() {
            TransactionError::InsufficientFunds { needed, available } => {
                assert_eq!(needed, 200_500);
                assert_eq!(available, 175_000);
            }
            _ => panic!("expected InsufficientFunds"),
        }
    }

    #[test]
    fn test_coin_selector_empty_utxos() {
        let result = CoinSelector::select(&[], 1000, 100);
        assert!(matches!(result.unwrap_err(), TransactionError::NoUtxos));
    }

    #[test]
    fn test_coin_selector_exact_amount() {
        let utxos = make_utxos();
        // 100k UTXO, need 99500 + 500 fee = 100000 exactly
        let result = CoinSelector::select(&utxos, 99_500, 500).unwrap();
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.change, 0);
    }

    // --- FeeEstimator tests ---

    #[test]
    fn test_fee_estimator_1_in_2_out() {
        let fee = FeeEstimator::estimate_fee(1, 2, 1);
        // 10 + 148*1 + 34*2 = 10 + 148 + 68 = 226
        assert_eq!(fee, 226);
    }

    #[test]
    fn test_fee_estimator_3_in_2_out() {
        let fee = FeeEstimator::estimate_fee(3, 2, 1);
        // 10 + 148*3 + 34*2 = 10 + 444 + 68 = 522
        assert_eq!(fee, 522);
    }

    #[test]
    fn test_fee_estimator_custom_rate() {
        let fee = FeeEstimator::estimate_fee(1, 1, 2);
        // 10 + 148 + 34 = 192, * 2 = 384
        assert_eq!(fee, 384);
    }

    // --- TxBuilder tests ---

    #[test]
    fn test_build_unsigned_single_input() {
        let utxos = make_utxos();
        let outputs = vec![PaymentOutput {
            address: TEST_ADDRESS_B.to_string(),
            satoshis: 50_000,
        }];

        let (tx, selection) =
            TxBuilder::build_unsigned(&utxos, &outputs, Some(TEST_ADDRESS_A), 1, None, None).unwrap();

        // Should select 1 input (100k covers 50k + fee + change)
        assert_eq!(selection.selected.len(), 1);
        assert_eq!(tx.inputs.len(), 1);
        // 2 outputs: payment + change
        assert_eq!(tx.outputs.len(), 2);
        // First output is the payment
        assert_eq!(tx.outputs[0].satoshis, Some(50_000));
        assert!(!tx.outputs[0].change);
        // Second output is change
        assert!(tx.outputs[1].change);
    }

    #[test]
    fn test_build_unsigned_no_change() {
        let utxos = make_utxos();
        // Send exact amount that leaves no change after fee
        let outputs = vec![PaymentOutput {
            address: TEST_ADDRESS_B.to_string(),
            satoshis: 99_774, // 100000 - 226 fee (1 input, 2 outputs)
        }];

        let (tx, selection) =
            TxBuilder::build_unsigned(&utxos, &outputs, Some(TEST_ADDRESS_A), 1, None, None).unwrap();

        assert_eq!(selection.change, 0);
        // Only 1 output (payment), no change
        assert_eq!(tx.outputs.len(), 1);
    }

    #[test]
    fn test_build_unsigned_no_change_address() {
        let utxos = make_utxos();
        let outputs = vec![PaymentOutput {
            address: TEST_ADDRESS_B.to_string(),
            satoshis: 50_000,
        }];

        // No change address provided — change goes to fee
        let (tx, selection) = TxBuilder::build_unsigned(&utxos, &outputs, None, 1, None, None).unwrap();

        // 1 output only (no change)
        assert_eq!(tx.outputs.len(), 1);
        // Change is "lost" (becomes extra fee)
        assert!(selection.change > 0);
    }

    #[test]
    fn test_build_unsigned_multiple_outputs() {
        let utxos = make_utxos();
        let outputs = vec![
            PaymentOutput {
                address: TEST_ADDRESS_B.to_string(),
                satoshis: 30_000,
            },
            PaymentOutput {
                address: TEST_ADDRESS_A.to_string(),
                satoshis: 40_000,
            },
        ];

        let (tx, selection) =
            TxBuilder::build_unsigned(&utxos, &outputs, Some(TEST_ADDRESS_A), 1, None, None).unwrap();

        // 3 outputs: 2 payments + change
        assert_eq!(tx.outputs.len(), 3);
        assert_eq!(tx.outputs[0].satoshis, Some(30_000));
        assert_eq!(tx.outputs[1].satoshis, Some(40_000));
        assert!(tx.outputs[2].change);
    }

    #[test]
    fn test_build_unsigned_zero_payment() {
        let utxos = make_utxos();
        let outputs = vec![PaymentOutput {
            address: TEST_ADDRESS_B.to_string(),
            satoshis: 0,
        }];

        let result = TxBuilder::build_unsigned(&utxos, &outputs, Some(TEST_ADDRESS_A), 1, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_unsigned_serializes_to_hex() {
        let utxos = make_utxos();
        let outputs = vec![PaymentOutput {
            address: TEST_ADDRESS_B.to_string(),
            satoshis: 50_000,
        }];

        let (tx, _) =
            TxBuilder::build_unsigned(&utxos, &outputs, Some(TEST_ADDRESS_A), 1, None, None).unwrap();

        let hex = tx.to_hex().unwrap();
        assert!(!hex.is_empty());
        assert!(hex.len() % 2 == 0); // valid hex
    }

    // --- TxPlan tests ---

    #[test]
    fn test_create_plan_fields() {
        let utxos = make_utxos();
        let outputs = vec![PaymentOutput {
            address: TEST_ADDRESS_B.to_string(),
            satoshis: 50_000,
        }];

        let (tx, selection) =
            TxBuilder::build_unsigned(&utxos, &outputs, Some(TEST_ADDRESS_A), 1, None, None).unwrap();

        let plan = TxBuilder::create_plan(
            tx,
            outputs.clone(),
            selection,
            Some(TEST_ADDRESS_A.to_string()),
            "/path/to/wallet.sqlite".to_string(),
            1,
            300, // 5 minute TTL
            None,
        )
        .unwrap();

        assert!(!plan.unsigned_tx_hex.is_empty());
        assert_eq!(plan.outputs.len(), 1);
        assert_eq!(plan.inputs.len(), 1);
        assert_eq!(plan.wallet_path, "/path/to/wallet.sqlite");
        assert_eq!(plan.account_id, 1);
        assert!(!plan.signed);
        assert!(plan.signed_tx_hex.is_none());
        assert!(plan.txid.is_none());
        assert!(plan.expires_at > plan.created_at);
        assert_eq!(plan.expires_at - plan.created_at, 300);
    }

    #[test]
    fn test_plan_serialization_roundtrip() {
        let utxos = make_utxos();
        let outputs = vec![PaymentOutput {
            address: TEST_ADDRESS_B.to_string(),
            satoshis: 50_000,
        }];

        let (tx, selection) =
            TxBuilder::build_unsigned(&utxos, &outputs, Some(TEST_ADDRESS_A), 1, None, None).unwrap();

        let plan = TxBuilder::create_plan(
            tx,
            outputs,
            selection,
            Some(TEST_ADDRESS_A.to_string()),
            "/wallet.sqlite".to_string(),
            1,
            300,
            None,
        )
        .unwrap();

        let json = serde_json::to_string(&plan).unwrap();
        let restored: TxPlan = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.wallet_path, plan.wallet_path);
        assert_eq!(restored.fee, plan.fee);
        assert_eq!(restored.inputs.len(), plan.inputs.len());
        assert_eq!(restored.unsigned_tx_hex, plan.unsigned_tx_hex);
    }

    // --- CoinChooser strategy tests ---

    /// TxBuilder with strategy=None must produce the same largest-first selection
    /// as before (backward compatible). Existing tests already cover this; here we
    /// explicitly verify the strategy parameter wiring.
    #[test]
    fn test_build_unsigned_strategy_none_uses_largest_first() {
        let utxos = make_utxos();
        let outputs = vec![PaymentOutput {
            address: TEST_ADDRESS_B.to_string(),
            satoshis: 50_000,
        }];

        let (tx, selection) =
            TxBuilder::build_unsigned(&utxos, &outputs, Some(TEST_ADDRESS_A), 1, None, None)
                .unwrap();

        // Largest-first picks the 100k UTXO first → exactly 1 input.
        assert_eq!(selection.selected.len(), 1);
        assert_eq!(selection.selected[0].satoshis, 100_000);
        assert_eq!(tx.inputs.len(), 1);
    }

    /// TxBuilder with Strategy::Privacy must build a valid transaction that
    /// covers the payment + fee from the available UTXOs.
    #[test]
    fn test_build_unsigned_strategy_privacy() {
        let utxos = make_utxos();
        let outputs = vec![PaymentOutput {
            address: TEST_ADDRESS_B.to_string(),
            satoshis: 50_000,
        }];

        let (tx, selection) = TxBuilder::build_unsigned(
            &utxos,
            &outputs,
            Some(TEST_ADDRESS_A),
            1,
            None,
            Some(crate::core::coinchooser::Strategy::Privacy),
        )
        .unwrap();

        // Selection must cover payment + fee.
        let expected_fee =
            FeeEstimator::estimate_fee(selection.selected.len(), 2, 1);
        assert!(
            selection.total_input >= 50_000 + expected_fee,
            "total_input {} must cover payment + fee {}",
            selection.total_input,
            50_000 + expected_fee
        );
        assert_eq!(tx.inputs.len(), selection.selected.len());
        // At least 1 payment output + 1 change output.
        assert!(tx.outputs.len() >= 1);
        // Fee must match the FeeEstimator formula.
        assert_eq!(selection.fee, expected_fee);
        // Change = total_input - payment - fee.
        assert_eq!(
            selection.change,
            selection.total_input - 50_000 - expected_fee
        );
    }
}
