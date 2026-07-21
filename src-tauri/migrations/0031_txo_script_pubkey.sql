-- Migration 0031 — Add script_pubkey column to TransactionOutputs
--
-- The TransactionOutputs table previously did not store the locking script
-- (script_pubkey). This meant the GUI's OrdinalsView and TokensView could
-- not decode outputs because they had no script data to pass to the
-- decode_output / get_ordinals / get_token_transfers backend commands.
--
-- This migration adds the column so that the locking script hex can be
-- stored when transaction outputs are upserted during wallet sync.

ALTER TABLE TransactionOutputs ADD COLUMN script_pubkey TEXT;