-- Migration 0029: Add contacts tables
-- Contacts are stored per-wallet (in the wallet's SQLite storage).
-- Each contact has a label and one or more identities (OnChain address, Paymail, etc.).

CREATE TABLE IF NOT EXISTS Contacts (
    contact_id INTEGER PRIMARY KEY,
    label TEXT NOT NULL,
    date_created INTEGER NOT NULL,
    date_updated INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ContactIdentities (
    identity_id BLOB PRIMARY KEY,
    contact_id INTEGER NOT NULL,
    system_id INTEGER NOT NULL,
    system_data TEXT NOT NULL,
    last_verified INTEGER DEFAULT NULL,
    date_created INTEGER NOT NULL,
    date_updated INTEGER NOT NULL,
    FOREIGN KEY(contact_id) REFERENCES Contacts (contact_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ContactIdentities_contact
    ON ContactIdentities(contact_id);