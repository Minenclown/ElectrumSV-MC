-- Migration 0030: Add MultisigConfigs table for m-of-n multisig accounts.
-- Each row stores the threshold (m) and the list of public keys (n) for a
-- multisig account. The public_keys column holds a JSON array of hex-encoded
-- public keys. The account_id references Accounts(account_id).

CREATE TABLE IF NOT EXISTS MultisigConfigs (
    account_id INTEGER PRIMARY KEY,
    threshold INTEGER NOT NULL,
    public_keys TEXT NOT NULL,  -- JSON array of hex-encoded public keys
    date_created INTEGER NOT NULL,
    date_updated INTEGER NOT NULL,
    FOREIGN KEY (account_id) REFERENCES Accounts(account_id)
);