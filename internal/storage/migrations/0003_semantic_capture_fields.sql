-- Capture-time semantic categories for the data moat.
-- These low-cardinality fields cannot be reconstructed from fingerprints after the
-- fact, so they must be captured when the decision is made. Nullable: empty means
-- "not captured". Values are constrained to canonical taxonomy tokens by the writer.

ALTER TABLE action_decision_outcomes ADD COLUMN IF NOT EXISTS environment TEXT;
ALTER TABLE action_decision_outcomes ADD COLUMN IF NOT EXISTS recipient_type TEXT;
ALTER TABLE action_decision_outcomes ADD COLUMN IF NOT EXISTS operation_type TEXT;

-- Index environment so "production-only" learning queries stay cheap.
CREATE INDEX IF NOT EXISTS idx_action_decision_outcomes_project_environment
    ON action_decision_outcomes (project, environment)
    WHERE environment IS NOT NULL;
