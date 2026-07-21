-- Migration 0026: TXO coinbase flag
-- Ported from migration_0026_txo_coinbase_flag.py
-- Sets IS_COINBASE flag on all outputs of transactions with block_position = 0.

-- TransactionOutputFlag.IS_COINBASE = 1 (bit 0)
UPDATE TransactionOutputs
    SET flags=flags|1
    WHERE tx_hash in (SELECT tx_hash FROM Transactions WHERE block_position = 0);