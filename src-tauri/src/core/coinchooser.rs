// core/coinchooser.rs — Advanced coin selection algorithms
//
// Ported from archive/electrumsv/coinchooser.py. Provides three strategies:
//   1. Branch-and-Bound (BnB) — exact-match search to minimise change (and thus fee + privacy leak)
//   2. Random-Subset    — deterministic random bucket combination (CoinChooserRandom)
//   3. Privacy          — penalises change that differs from payment amounts (CoinChooserPrivacy)
//
// The existing CoinSelector in core/transaction.rs uses a simple largest-first strategy.
// This module is intended to replace it *without* modifying transaction.rs — the caller
// will switch to these types in a later milestone.
//
// All public types are self-contained and do not depend on bsv-sdk so they can be unit-tested
// in isolation. The `Coin` struct mirrors the fields the caller already has in
// `SelectedUtxo` (tx_hash_hex, tx_index, satoshis, keyinstance_id) plus an `estimated_size`
// field used for fee calculation.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// 1 BSV in satoshis (matches COIN in the Python `bitcoin` module).
pub const COIN: u64 = 100_000_000;

/// Cost in satoshis of an additional change output (P2PKH ≈ 34 bytes at 1 sat/byte).
pub const CHANGE_OUTPUT_COST: u64 = 34;

/// Maximum number of BnB rounds before falling back.
const BNB_MAX_ROUNDS: usize = 100_000;

// ---------------------------------------------------------------------------
// Coin / Bucket
// ---------------------------------------------------------------------------

/// A spendable coin (UTXO) as seen by the coin chooser.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Coin {
    /// Display hex txid (reversed byte order, same convention as `SelectedUtxo`).
    pub tx_hash_hex: String,
    /// Output index within the funding transaction.
    pub tx_index: u32,
    /// Value in satoshis.
    pub value: u64,
    /// KeyInstance ID that owns this UTXO (used for privacy bucketing).
    pub keyinstance_id: i64,
    /// Estimated serialized size of this input in bytes (≈148 for P2PKH).
    pub estimated_size: u64,
}

impl Coin {
    /// Create a coin with the default P2PKH input size (148 bytes).
    pub fn new(tx_hash_hex: String, tx_index: u32, value: u64, keyinstance_id: i64) -> Self {
        Self {
            tx_hash_hex,
            tx_index,
            value,
            keyinstance_id,
            estimated_size: 148,
        }
    }

    /// Bytes that uniquely identify this coin's prevout — used as PRNG seed material.
    fn prevout_bytes(&self) -> Vec<u8> {
        let mut out = self.tx_hash_hex.as_bytes().to_vec();
        out.extend_from_slice(&self.tx_index.to_le_bytes());
        out
    }
}

/// A group of coins sharing a common key (privacy bucket).
#[derive(Debug, Clone)]
pub struct Bucket {
    /// The key used to group coins (keyinstance_id as i64).
    pub desc: i64,
    /// Sum of estimated_size across all coins in the bucket.
    pub size: u64,
    /// Sum of value across all coins in the bucket.
    pub value: u64,
    /// The coins in this bucket.
    pub coins: Vec<Coin>,
}

impl Bucket {
    fn new(desc: i64, coins: Vec<Coin>) -> Self {
        let size = coins.iter().map(|c| c.estimated_size).sum();
        let value = coins.iter().map(|c| c.value).sum();
        Self {
            desc,
            size,
            value,
            coins,
        }
    }
}

// ---------------------------------------------------------------------------
// Deterministic PRNG (SHA-256 based, matching the Python PRNG class)
// ---------------------------------------------------------------------------

/// A simple deterministic PRNG seeded from coin prevout bytes.
///
/// The same set of coins always produces the same shuffle, preventing
/// malicious/stale-server attacks that exploit non-deterministic selection.
pub struct Prng {
    state: [u8; 32],
    pool: Vec<u8>,
}

impl Prng {
    /// Create a PRNG seeded from the sorted prevout bytes of all coins.
    pub fn from_coins(coins: &[Coin]) -> Self {
        let mut seed_material: Vec<Vec<u8>> = coins
            .iter()
            .map(|c| c.prevout_bytes())
            .collect();
        seed_material.sort();
        let mut seed = Vec::new();
        for part in &seed_material {
            seed.extend_from_slice(part);
        }
        let state = sha256(&seed);
        Self {
            state,
            pool: Vec::new(),
        }
    }

    /// Create a PRNG from an explicit seed (useful for testing).
    pub fn from_seed(seed: &[u8]) -> Self {
        Self {
            state: sha256(seed),
            pool: Vec::new(),
        }
    }

    /// Return `n` random bytes.
    pub fn get_bytes(&mut self, n: usize) -> Vec<u8> {
        while self.pool.len() < n {
            self.pool.extend_from_slice(&self.state);
            self.state = sha256(&self.state);
        }
        let result: Vec<u8> = self.pool.drain(..n).collect();
        result
    }

    /// Random integer in [start, end).
    pub fn randint(&mut self, start: usize, end: usize) -> usize {
        let n = end - start;
        let mut r: usize = 0;
        let mut p: usize = 1;
        while p < n {
            let b = self.get_bytes(1)[0] as usize;
            r = b + (r << 8);
            p <<= 8;
        }
        start + (r % n)
    }

    /// Fisher-Yates shuffle (in place).
    pub fn shuffle<T>(&mut self, slice: &mut [T]) {
        if slice.len() < 2 {
            return;
        }
        for i in (1..slice.len()).rev() {
            let j = self.randint(0, i + 1);
            slice.swap(i, j);
        }
    }
}

/// Minimal SHA-256 wrapper so the module is self-contained and testable
/// without pulling in the `sha2` crate at the module level.
fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ---------------------------------------------------------------------------
// Selection result
// ---------------------------------------------------------------------------

/// Result of a coin selection run.
#[derive(Debug, Clone)]
pub struct SelectionResult {
    /// Selected coins (in selection order).
    pub coins: Vec<Coin>,
    /// Total input value.
    pub total_input: u64,
    /// Estimated fee for the selected inputs.
    pub fee: u64,
    /// Change amount (0 for exact-match BnB).
    pub change: u64,
}

// ---------------------------------------------------------------------------
// Strategy enum
// ---------------------------------------------------------------------------

/// Coin selection strategy to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Branch-and-bound exact match (minimises change).
    BranchAndBound,
    /// Random-subset combination (CoinChooserRandom).
    RandomSubset,
    /// Privacy-optimised random subset (CoinChooserPrivacy).
    Privacy,
}

// ---------------------------------------------------------------------------
// CoinChooser — the main entry point
// ---------------------------------------------------------------------------

/// Advanced coin chooser with pluggable strategies.
///
/// Usage:
/// ```ignore
/// use electrumsv_mc_lib::core::coinchooser::{CoinChooser, Strategy, Coin};
///
/// let coins = vec![Coin::new("aa".into(), 0, 5000, 1)];
/// let chooser = CoinChooser::new(Strategy::Privacy, 1); // 1 sat/byte
/// let result = chooser.select(&coins, 3000).expect("enough funds");
/// assert!(result.change < 1000);
/// ```
pub struct CoinChooser {
    /// Selection strategy.
    pub strategy: Strategy,
    /// Fee rate in satoshis per byte.
    pub fee_rate: u64,
}

impl CoinChooser {
    /// Create a new chooser with the given strategy and fee rate (sat/byte).
    pub fn new(strategy: Strategy, fee_rate: u64) -> Self {
        Self {
            strategy,
            fee_rate,
        }
    }

    /// Default chooser: Privacy strategy at 1 sat/byte.
    pub fn default_privacy() -> Self {
        Self::new(Strategy::Privacy, 1)
    }

    /// Select coins to cover `target_amount` (in satoshis, excluding fee).
    ///
    /// Returns an error if the available coins cannot cover the target + fee.
    pub fn select(
        &self,
        coins: &[Coin],
        target_amount: u64,
    ) -> Result<SelectionResult, CoinChooserError> {
        if coins.is_empty() {
            return Err(CoinChooserError::NoCoins);
        }
        match self.strategy {
            Strategy::BranchAndBound => self.select_bnb(coins, target_amount),
            Strategy::RandomSubset => self.select_random(coins, target_amount, false),
            Strategy::Privacy => self.select_random(coins, target_amount, true),
        }
    }

    // -- Branch and Bound ---------------------------------------------------

    fn select_bnb(
        &self,
        coins: &[Coin],
        target_amount: u64,
    ) -> Result<SelectionResult, CoinChooserError> {
        // Sort descending by value (largest first) for better pruning.
        let mut sorted: Vec<&Coin> = coins.iter().collect();
        sorted.sort_by(|a, b| b.value.cmp(&a.value));

        // Target = payment + cost of a single change output (we want no change).
        let cost_of_change = CHANGE_OUTPUT_COST * self.fee_rate;
        let target_with_change = target_amount
            .checked_add(cost_of_change)
            .ok_or(CoinChooserError::Overflow)?;

        let mut best: Option<Vec<usize>> = None;
        let mut best_excess = u64::MAX;

        // Depth-first search with pruning.
        let mut current: Vec<usize> = Vec::new();
        let mut current_value: u64 = 0;
        let mut rounds: usize = 0;

        self.bnb_recursive(
            &sorted,
            0,
            &mut current,
            &mut current_value,
            target_amount,
            target_with_change,
            &mut best,
            &mut best_excess,
            &mut rounds,
        );

        match best {
            Some(indices) => {
                let selected_coins: Vec<Coin> =
                    indices.iter().map(|&i| sorted[i].clone()).collect();
                let total_input: u64 = selected_coins.iter().map(|c| c.value).sum();
                let input_size: u64 = selected_coins.iter().map(|c| c.estimated_size).sum();
                // Base tx size ~10 bytes + outputs (~34 per output) — we only
                // account inputs here for the selection fee; the caller adds
                // output fees when recalculating with FeeEstimator.  This means
                // the `fee` and `change` fields are estimates that are
                // reconciled by the caller (see TxBuilder::build_unsigned).
                // The caller must pass the real `num_outputs` to
                // FeeEstimator::estimate_fee for the final fee.
                let fee = (10 + input_size) * self.fee_rate;
                let change = total_input.saturating_sub(target_amount + fee);
                Ok(SelectionResult {
                    coins: selected_coins,
                    total_input,
                    fee,
                    change,
                })
            }
            None => {
                // BnB failed — fall back to largest-first.
                self.fallback_largest_first(coins, target_amount)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn bnb_recursive(
        &self,
        sorted: &[&Coin],
        start: usize,
        current: &mut Vec<usize>,
        current_value: &mut u64,
        target: u64,
        target_with_change: u64,
        best: &mut Option<Vec<usize>>,
        best_excess: &mut u64,
        rounds: &mut usize,
    ) {
        if *rounds >= BNB_MAX_ROUNDS {
            return;
        }
        *rounds += 1;

        // If we exceeded the target-with-change, this branch is pruned.
        if *current_value > target_with_change {
            return;
        }

        // If current value >= target (without change) we have an exact-ish match.
        if *current_value >= target {
            let excess = *current_value - target;
            if excess < *best_excess {
                *best_excess = excess;
                *best = Some(current.clone());
            }
            // Don't return — there might be a closer match deeper, but pruning will cut it.
        }

        if start >= sorted.len() {
            return;
        }

        // Prune: remaining coins can't reach the target.
        let remaining: u64 = sorted[start..].iter().map(|c| c.value).sum();
        if *current_value + remaining < target {
            return;
        }

        // Branch 1: include coin at `start`.
        current.push(start);
        let prev = *current_value;
        *current_value = prev + sorted[start].value;
        self.bnb_recursive(
            sorted,
            start + 1,
            current,
            current_value,
            target,
            target_with_change,
            best,
            best_excess,
            rounds,
        );
        current.pop();
        *current_value = prev;

        // Branch 2: skip coin at `start`.
        self.bnb_recursive(
            sorted,
            start + 1,
            current,
            current_value,
            target,
            target_with_change,
            best,
            best_excess,
            rounds,
        );
    }

    // -- Random subset / Privacy --------------------------------------------

    fn select_random(
        &self,
        coins: &[Coin],
        target_amount: u64,
        privacy: bool,
    ) -> Result<SelectionResult, CoinChooserError> {
        let mut prng = Prng::from_coins(coins);

        // Bucket coins by keyinstance_id.
        let buckets = bucketize(coins);
        let base_size: u64 = 10; // base tx overhead
        let output_size: u64 = 34; // per output

        let sufficient_funds = |bks: &[Bucket]| -> bool {
            let total_input: u64 = bks.iter().map(|b| b.value).sum();
            let total_size = base_size + bks.iter().map(|b| b.size).sum::<u64>();
            let fee = total_size * self.fee_rate;
            total_input >= target_amount + fee
        };

        // Generate candidates.
        let candidates = bucket_candidates(&buckets, &sufficient_funds, &mut prng);

        if candidates.is_empty() {
            // Check if all coins together are sufficient.
            if !sufficient_funds(&buckets) {
                let total: u64 = buckets.iter().map(|b| b.value).sum();
                // needed = target_amount + fee (the total that must be covered)
                let needed = target_amount
                    + buckets.iter().map(|b| b.size).sum::<u64>() * self.fee_rate;
                return Err(CoinChooserError::InsufficientFunds {
                    needed,
                    available: total,
                });
            }
            // All coins are the only candidate.
            return self.assemble_result(&buckets, target_amount, base_size, output_size);
        }

        // Score candidates and pick the best.
        let spent = target_amount;
        let out_values: Vec<u64> = vec![target_amount];
        let max_change = out_values.iter().max().copied().unwrap_or(0) * 3 / 2;

        let mut best_idx = 0;
        let mut best_penalty = u64::MAX;
        for (i, cand) in candidates.iter().enumerate() {
            let penalty = if privacy {
                penalty_privacy(cand, spent, max_change)
            } else {
                penalty_simple(cand)
            };
            if penalty < best_penalty {
                best_penalty = penalty;
                best_idx = i;
            }
        }

        let winner = &candidates[best_idx];
        self.assemble_result(winner, target_amount, base_size, output_size)
    }

    // -- Shared helpers ------------------------------------------------------

    fn assemble_result(
        &self,
        buckets: &[Bucket],
        target_amount: u64,
        base_size: u64,
        _output_size: u64,
    ) -> Result<SelectionResult, CoinChooserError> {
        let mut selected_coins: Vec<Coin> = Vec::new();
        for b in buckets {
            selected_coins.extend_from_slice(&b.coins);
        }
        if selected_coins.is_empty() {
            return Err(CoinChooserError::NoCoins);
        }
        let total_input: u64 = selected_coins.iter().map(|c| c.value).sum();
        let input_size: u64 = selected_coins.iter().map(|c| c.estimated_size).sum();
        let fee = (base_size + input_size) * self.fee_rate;
        if total_input < target_amount + fee {
            return Err(CoinChooserError::InsufficientFunds {
                needed: target_amount + fee,
                available: total_input,
            });
        }
        let change = total_input - target_amount - fee;
        Ok(SelectionResult {
            coins: selected_coins,
            total_input,
            fee,
            change,
        })
    }

    fn fallback_largest_first(
        &self,
        coins: &[Coin],
        target_amount: u64,
    ) -> Result<SelectionResult, CoinChooserError> {
        let mut sorted: Vec<&Coin> = coins.iter().collect();
        sorted.sort_by(|a, b| b.value.cmp(&a.value));

        let base_size: u64 = 10;
        let mut selected: Vec<Coin> = Vec::new();
        let mut accumulated: u64 = 0;
        let mut input_size: u64 = 0;

        for c in &sorted {
            selected.push((*c).clone());
            accumulated = accumulated
                .checked_add(c.value)
                .ok_or(CoinChooserError::Overflow)?;
            input_size += c.estimated_size;
            let fee = (base_size + input_size) * self.fee_rate;
            if accumulated >= target_amount + fee {
                let fee = (base_size + input_size) * self.fee_rate;
                let change = accumulated - target_amount - fee;
                return Ok(SelectionResult {
                    coins: selected,
                    total_input: accumulated,
                    fee,
                    change,
                });
            }
        }
        let fee = (base_size + input_size) * self.fee_rate;
        Err(CoinChooserError::InsufficientFunds {
            needed: target_amount + fee,
            available: accumulated,
        })
    }
}

// ---------------------------------------------------------------------------
// Free functions — bucketize, candidates, penalties
// ---------------------------------------------------------------------------

/// Group coins into buckets by `keyinstance_id`.
fn bucketize(coins: &[Coin]) -> Vec<Bucket> {
    let mut map: HashMap<i64, Vec<Coin>> = HashMap::new();
    for c in coins {
        map.entry(c.keyinstance_id).or_default().push(c.clone());
    }
    map.into_iter()
        .map(|(key, group)| Bucket::new(key, group))
        .collect()
}

/// Generate candidate bucket sets by random permutation (matching Python `bucket_candidates`).
fn bucket_candidates(
    buckets: &[Bucket],
    sufficient: &dyn Fn(&[Bucket]) -> bool,
    prng: &mut Prng,
) -> Vec<Vec<Bucket>> {
    let mut candidates: Vec<Vec<Bucket>> = Vec::new();
    let n = buckets.len();
    if n == 0 {
        return candidates;
    }

    // Singletons.
    for (i, b) in buckets.iter().enumerate() {
        if sufficient(std::slice::from_ref(b)) {
            candidates.push(vec![b.clone()]);
        }
    }

    // Random subsets.
    let attempts = std::cmp::min(100, (n - 1) * 10 + 1);
    let mut perm: Vec<usize> = (0..n).collect();
    for _ in 0..attempts {
        prng.shuffle(&mut perm);
        let mut bkts: Vec<Bucket> = Vec::new();
        let mut found = false;
        for &idx in &perm {
            bkts.push(buckets[idx].clone());
            if sufficient(&bkts) {
                candidates.push(strip_unneeded(bkts, sufficient));
                found = true;
                break;
            }
        }
        if !found {
            // No sufficient combination in this permutation — skip.
        }
    }

    candidates
}

/// Remove buckets that are unnecessary to reach the target (matching Python `strip_unneeded`).
fn strip_unneeded(mut bkts: Vec<Bucket>, sufficient: &dyn Fn(&[Bucket]) -> bool) -> Vec<Bucket> {
    bkts.sort_by(|a, b| a.value.cmp(&b.value));
    for i in 0..bkts.len() {
        let rest: Vec<Bucket> = bkts[i + 1..].to_vec();
        if !sufficient(&rest) {
            return bkts[i..].to_vec();
        }
    }
    bkts
}

/// Simple penalty: number of buckets − 1 (minimise input count).
fn penalty_simple(buckets: &[Bucket]) -> u64 {
    (buckets.len().saturating_sub(1)) as u64
}

/// Privacy penalty: penalise large or anomalous change (matching Python `penalty_func`).
fn penalty_privacy(buckets: &[Bucket], spent: u64, max_change: u64) -> u64 {
    let mut badness = (buckets.len().saturating_sub(1)) as u64;
    let total_input: u64 = buckets.iter().map(|b| b.value).sum();
    let change = total_input.saturating_sub(spent);
    if change > max_change {
        // Penalize change not roughly in output range.
        let diff = change - max_change;
        badness = badness.saturating_add(diff / (max_change + 10000));
        // Penalize large change; 5 BSV excess ≈ using 1 more input.
        badness = badness.saturating_add(change / (COIN * 5));
    }
    badness
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the coin chooser.
#[derive(Debug, thiserror::Error)]
pub enum CoinChooserError {
    #[error("no coins available for selection")]
    NoCoins,
    #[error("insufficient funds: needed {needed} sat, available {available} sat")]
    InsufficientFunds { needed: u64, available: u64 },
    #[error("arithmetic overflow during selection")]
    Overflow,
}

// ---------------------------------------------------------------------------
// TransactionCache placeholder — removed; see db/cache.rs for the real cache.
// ---------------------------------------------------------------------------

// (Cache lives in db/cache.rs, not here.)

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_coin(value: u64, key: i64) -> Coin {
        Coin::new(format!("tx{}", value), 0, value, key)
    }

    // --- Prng tests ---

    #[test]
    fn test_prng_deterministic() {
        let mut a = Prng::from_seed(b"hello");
        let mut b = Prng::from_seed(b"hello");
        let ra = a.get_bytes(32);
        let rb = b.get_bytes(32);
        assert_eq!(ra, rb);
    }

    #[test]
    fn test_prng_shuffle_deterministic_from_coins() {
        let coins: Vec<Coin> = (0..10).map(|i| make_coin(1000 + i, 1)).collect();
        let mut a = Prng::from_coins(&coins);
        let mut b = Prng::from_coins(&coins);
        let mut sa: Vec<u64> = (0..10).collect();
        let mut sb: Vec<u64> = (0..10).collect();
        a.shuffle(&mut sa);
        b.shuffle(&mut sb);
        assert_eq!(sa, sb);
    }

    #[test]
    fn test_prng_randint_in_range() {
        let mut prng = Prng::from_seed(b"test seed");
        for _ in 0..100 {
            let r = prng.randint(5, 10);
            assert!((5..10).contains(&r));
        }
    }

    // --- BnB tests ---

    #[test]
    fn test_bnb_exact_match() {
        // Coins: 1000, 2000, 3000 → exact match for 3000.
        let coins = vec![
            make_coin(1000, 1),
            make_coin(2000, 1),
            make_coin(3000, 1),
        ];
        let chooser = CoinChooser::new(Strategy::BranchAndBound, 1);
        let result = chooser.select(&coins, 3000).expect("select");
        let total: u64 = result.coins.iter().map(|c| c.value).sum();
        assert_eq!(total, 3000);
        assert!(result.change < 34, "change should be near zero");
    }

    #[test]
    fn test_bnb_fallback_on_no_exact() {
        // No combination gives exact match; BnB falls back to largest-first.
        let coins = vec![make_coin(7777, 1), make_coin(3333, 1)];
        let chooser = CoinChooser::new(Strategy::BranchAndBound, 1);
        let result = chooser.select(&coins, 5000).expect("select");
        assert!(result.total_input >= 5000);
        assert!(result.change > 0);
    }

    // --- Random subset / Privacy tests ---

    #[test]
    fn test_random_subset_covers_target() {
        let coins: Vec<Coin> = (0..20).map(|i| make_coin(500 + i * 100, i as i64)).collect();
        let chooser = CoinChooser::new(Strategy::RandomSubset, 1);
        let result = chooser.select(&coins, 2000).expect("select");
        let total: u64 = result.coins.iter().map(|c| c.value).sum();
        assert!(total >= 2000, "selected coins must cover target");
    }

    #[test]
    fn test_privacy_prefers_single_key() {
        // Two keys: key 1 has 3000, key 2 has 2000+2000.
        // Privacy should prefer spending from a single key.
        let coins = vec![
            make_coin(3000, 1),
            make_coin(2000, 2),
            make_coin(2000, 2),
        ];
        let chooser = CoinChooser::new(Strategy::Privacy, 1);
        let result = chooser.select(&coins, 2500).expect("select");
        let keys: std::collections::HashSet<i64> =
            result.coins.iter().map(|c| c.keyinstance_id).collect();
        // Privacy optimisation should ideally use 1 key.
        assert_eq!(keys.len(), 1, "privacy should select from a single key");
    }

    #[test]
    fn test_insufficient_funds_error() {
        let coins = vec![make_coin(100, 1)];
        let chooser = CoinChooser::new(Strategy::RandomSubset, 1);
        let err = chooser.select(&coins, 500).unwrap_err();
        assert!(matches!(err, CoinChooserError::InsufficientFunds { .. }));
    }

    #[test]
    fn test_no_coins_error() {
        let chooser = CoinChooser::new(Strategy::BranchAndBound, 1);
        let err = chooser.select(&[], 100).unwrap_err();
        assert!(matches!(err, CoinChooserError::NoCoins));
    }

    // --- Bucketize tests ---

    #[test]
    fn test_bucketize_groups_by_key() {
        let coins = vec![
            make_coin(100, 1),
            make_coin(200, 1),
            make_coin(300, 2),
        ];
        let buckets = bucketize(&coins);
        assert_eq!(buckets.len(), 2);
        let key1 = buckets.iter().find(|b| b.desc == 1).expect("key 1");
        assert_eq!(key1.coins.len(), 2);
        assert_eq!(key1.value, 300);
    }

    #[test]
    fn test_strip_unneeded_removes_smallest() {
        let coins = vec![
            make_coin(100, 1),
            make_coin(200, 2),
            make_coin(300, 3),
        ];
        let buckets = bucketize(&coins);
        let sufficient = |bks: &[Bucket]| -> bool {
            bks.iter().map(|b| b.value).sum::<u64>() >= 300
        };
        let stripped = strip_unneeded(buckets.clone(), &sufficient);
        let total: u64 = stripped.iter().map(|b| b.value).sum();
        assert!(total >= 300);
        // Should have removed the smallest unnecessary bucket.
        assert!(stripped.len() <= buckets.len());
    }
}