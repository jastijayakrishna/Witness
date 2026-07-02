ALTER TABLE wal_records ADD COLUMN IF NOT EXISTS actor                TEXT NOT NULL DEFAULT '';
ALTER TABLE wal_records ADD COLUMN IF NOT EXISTS human_delegator      TEXT NOT NULL DEFAULT '';
ALTER TABLE wal_records ADD COLUMN IF NOT EXISTS action               TEXT NOT NULL DEFAULT '';
ALTER TABLE wal_records ADD COLUMN IF NOT EXISTS target               TEXT NOT NULL DEFAULT '';
ALTER TABLE wal_records ADD COLUMN IF NOT EXISTS environment          TEXT NOT NULL DEFAULT '';
ALTER TABLE wal_records ADD COLUMN IF NOT EXISTS intent_hash          TEXT NOT NULL DEFAULT '';
ALTER TABLE wal_records ADD COLUMN IF NOT EXISTS evidence_hashes      JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE wal_records ADD COLUMN IF NOT EXISTS blast_radius         TEXT NOT NULL DEFAULT '';
ALTER TABLE wal_records ADD COLUMN IF NOT EXISTS risk_score           INT NOT NULL DEFAULT 0;
ALTER TABLE wal_records ADD COLUMN IF NOT EXISTS decision             TEXT NOT NULL DEFAULT '';
ALTER TABLE wal_records ADD COLUMN IF NOT EXISTS required_approvers   JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE wal_records ADD COLUMN IF NOT EXISTS approvals            JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS idx_wal_records_engineering_action
    ON wal_records (project, action, environment, time)
    WHERE action <> '';

CREATE INDEX IF NOT EXISTS idx_wal_records_engineering_decision
    ON wal_records (project, decision, time)
    WHERE decision <> '';
