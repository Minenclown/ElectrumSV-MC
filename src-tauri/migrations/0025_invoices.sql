-- Migration 0025: Add invoices table
-- Ported from migration_0025_invoices.py

CREATE TABLE IF NOT EXISTS Invoices (
    invoice_id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL,
    tx_hash BLOB DEFAULT NULL,
    payment_uri TEXT NOT NULL,
    description TEXT NULL,
    invoice_flags INTEGER NOT NULL,
    value INTEGER NOT NULL,
    invoice_data BLOB NOT NULL,
    date_expires INTEGER DEFAULT NULL,
    date_created INTEGER NOT NULL,
    date_updated INTEGER NOT NULL,
    FOREIGN KEY (account_id) REFERENCES Accounts (account_id),
    FOREIGN KEY (tx_hash) REFERENCES Transactions (tx_hash)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_Invoices_unique ON Invoices(payment_uri);