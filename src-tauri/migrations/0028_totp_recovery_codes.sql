-- Migration 0028: Add TOTP recovery codes table
-- Ported from migration_0028_totp_recovery_codes.py
-- Single-use codes for TOTP recovery (lost device).
-- Codes are PBKDF2-hashed, single-use.

CREATE TABLE IF NOT EXISTS TotpRecoveryCodes (
    code_hash TEXT PRIMARY KEY,
    used INTEGER NOT NULL DEFAULT 0,
    date_created INTEGER NOT NULL,
    date_used INTEGER DEFAULT NULL
);