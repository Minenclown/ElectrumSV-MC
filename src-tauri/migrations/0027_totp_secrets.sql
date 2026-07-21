-- Migration 0027: Add TOTP secrets table
-- Ported from migration_0027_totp_secrets.py
-- Per-wallet TOTP — secret is AES-256-GCM encrypted with the wallet password.

CREATE TABLE IF NOT EXISTS TotpSecrets (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    secret_encrypted BLOB NOT NULL,
    nonce BLOB NOT NULL,
    scope TEXT NOT NULL DEFAULT 'login',
    date_created INTEGER NOT NULL,
    date_updated INTEGER NOT NULL
);