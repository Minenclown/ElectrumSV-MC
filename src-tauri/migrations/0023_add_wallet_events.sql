-- Migration 0023: Add wallet events table
-- Ported from migration_0023_add_wallet_events.py

CREATE TABLE IF NOT EXISTS WalletEvents (
    event_id INTEGER PRIMARY KEY,
    event_type INTEGER NOT NULL,
    event_flags INTEGER NOT NULL,
    account_id INTEGER,
    date_created INTEGER NOT NULL,
    date_updated INTEGER NOT NULL,
    FOREIGN KEY(account_id) REFERENCES Accounts (account_id)
);