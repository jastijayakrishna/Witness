CREATE INDEX IF NOT EXISTS idx_action_ledger_expires_at
    ON action_ledger (expires_at);
