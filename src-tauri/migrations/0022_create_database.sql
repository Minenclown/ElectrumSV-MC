-- Migration 0022: Create database
-- Ported from migration_0022_create_database.py
-- Creates all base tables for the wallet.

CREATE TABLE IF NOT EXISTS MasterKeys (
    masterkey_id INTEGER PRIMARY KEY,
    parent_masterkey_id INTEGER DEFAULT NULL,
    derivation_type INTEGER NOT NULL,
    derivation_data BLOB NOT NULL,
    date_created INTEGER NOT NULL,
    date_updated INTEGER NOT NULL,
    FOREIGN KEY(parent_masterkey_id) REFERENCES MasterKeys (masterkey_id)
);

CREATE TABLE IF NOT EXISTS Accounts (
    account_id INTEGER PRIMARY KEY,
    default_masterkey_id INTEGER DEFAULT NULL,
    default_script_type INTEGER NOT NULL,
    account_name TEXT NOT NULL,
    date_created INTEGER NOT NULL,
    date_updated INTEGER NOT NULL,
    FOREIGN KEY(default_masterkey_id) REFERENCES MasterKeys (masterkey_id)
);

CREATE TABLE IF NOT EXISTS KeyInstances (
    keyinstance_id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL,
    masterkey_id INTEGER DEFAULT NULL,
    derivation_type INTEGER NOT NULL,
    derivation_data BLOB NOT NULL,
    script_type INTEGER NOT NULL,
    flags INTEGER NOT NULL,
    description TEXT DEFAULT NULL,
    date_created INTEGER NOT NULL,
    date_updated INTEGER NOT NULL,
    FOREIGN KEY(account_id) REFERENCES Accounts (account_id)
    FOREIGN KEY(masterkey_id) REFERENCES MasterKeys (masterkey_id)
);

CREATE TABLE IF NOT EXISTS Transactions (
    tx_hash BLOB PRIMARY KEY,
    tx_data BLOB DEFAULT NULL,
    proof_data BLOB DEFAULT NULL,
    block_height INTEGER DEFAULT NULL,
    block_position INTEGER DEFAULT NULL,
    fee_value INTEGER DEFAULT NULL,
    flags INTEGER NOT NULL DEFAULT 0,
    description TEXT DEFAULT NULL,
    date_created INTEGER NOT NULL,
    date_updated INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS TransactionOutputs (
    tx_hash BLOB NOT NULL,
    tx_index INTEGER NOT NULL,
    value INTEGER NOT NULL,
    keyinstance_id INTEGER NOT NULL,
    flags INTEGER NOT NULL,
    date_created INTEGER NOT NULL,
    date_updated INTEGER NOT NULL,
    FOREIGN KEY (tx_hash) REFERENCES Transactions (tx_hash),
    FOREIGN KEY (keyinstance_id) REFERENCES KeyInstances (keyinstance_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_TransactionOutputs_unique
    ON TransactionOutputs(tx_hash, tx_index);

CREATE TABLE IF NOT EXISTS TransactionDeltas (
    keyinstance_id INTEGER NOT NULL,
    tx_hash BLOB NOT NULL,
    value_delta INTEGER NOT NULL,
    date_created INTEGER NOT NULL,
    date_updated INTEGER NOT NULL,
    FOREIGN KEY(tx_hash) REFERENCES Transactions (tx_hash),
    FOREIGN KEY(keyinstance_id) REFERENCES KeyInstances (keyinstance_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_TransactionDeltas_unique
    ON TransactionDeltas(keyinstance_id, tx_hash);

CREATE TABLE IF NOT EXISTS WalletData (
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    date_created INTEGER NOT NULL,
    date_updated INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS PaymentRequests (
    paymentrequest_id INTEGER PRIMARY KEY,
    keyinstance_id INTEGER NOT NULL,
    state INTEGER NOT NULL,
    description TEXT DEFAULT NULL,
    expiration INTEGER DEFAULT NULL,
    value INTEGER DEFAULT NULL,
    date_created INTEGER NOT NULL,
    date_updated INTEGER NOT NULL,
    FOREIGN KEY(keyinstance_id) REFERENCES KeyInstances (keyinstance_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_WalletData_unique ON WalletData(key);

-- Initial WalletData entries
-- migration, next_masterkey_id, next_account_id, next_keyinstance_id, next_paymentrequest_id
-- Set during create_wallet (Milestone 2), not here.