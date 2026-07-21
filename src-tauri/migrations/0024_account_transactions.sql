-- Migration 0024: Account transactions view + payment request state constants
-- Ported from migration_0024_account_transactions.py

CREATE VIEW IF NOT EXISTS AccountTransactions (account_id, tx_hash) AS
    SELECT DISTINCT KI.account_id, TD.tx_hash
    FROM TransactionDeltas TD
    INNER JOIN KeyInstances KI USING(keyinstance_id);

-- State constant migration (0->1, 1->2, 2->4, 3->8)
-- Only relevant for existing PaymentRequests — new wallets have none.
UPDATE PaymentRequests SET state=8 WHERE state=3;
UPDATE PaymentRequests SET state=4 WHERE state=2;
UPDATE PaymentRequests SET state=2 WHERE state=1;
UPDATE PaymentRequests SET state=1 WHERE state=0;