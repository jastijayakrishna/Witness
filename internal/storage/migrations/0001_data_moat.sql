-- Minimal privacy-safe data moat schema.
-- Reviewed action-decision intelligence is the moat; raw traces are not.

CREATE TABLE IF NOT EXISTS action_decision_outcomes (
    id                       BIGSERIAL PRIMARY KEY,
    project                  TEXT NOT NULL,
    session_id               TEXT NOT NULL,
    trajectory_id            TEXT,
    decision_id              TEXT NOT NULL UNIQUE,
    receipt_id               TEXT,
    action_name              TEXT NOT NULL,
    action_type              TEXT NOT NULL,
    action_risk              TEXT NOT NULL,
    tool_signature_hash      TEXT,
    idempotency_key_hash     TEXT,
    resource_fingerprint     TEXT,
    args_fingerprint         TEXT,
    result_fingerprint       TEXT,
    result_class             TEXT NOT NULL DEFAULT '',
    state_delta_hash         TEXT,
    hubbleops_action           TEXT NOT NULL CHECK (hubbleops_action IN ('allow', 'shadow', 'warn', 'block')),
    decision_reason          TEXT NOT NULL DEFAULT '',
    evidence_json            JSONB NOT NULL DEFAULT '[]'::jsonb,
    policy_version           TEXT NOT NULL DEFAULT '',
    detector_version         TEXT NOT NULL DEFAULT '',
    estimated_cost_usd       NUMERIC(12,8),
    estimated_risk_prevented NUMERIC(12,8),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT action_decision_outcomes_project_decision_unique UNIQUE (project, decision_id)
);

CREATE INDEX IF NOT EXISTS idx_action_decision_outcomes_project_created_at
    ON action_decision_outcomes (project, created_at);
CREATE INDEX IF NOT EXISTS idx_action_decision_outcomes_project_action_name
    ON action_decision_outcomes (project, action_name);
CREATE INDEX IF NOT EXISTS idx_action_decision_outcomes_project_result_class
    ON action_decision_outcomes (project, result_class);
CREATE INDEX IF NOT EXISTS idx_action_decision_outcomes_project_hubbleops_action
    ON action_decision_outcomes (project, hubbleops_action);

CREATE TABLE IF NOT EXISTS action_decision_reviews (
    id                       BIGSERIAL PRIMARY KEY,
    project                  TEXT NOT NULL,
    decision_id              TEXT NOT NULL,
    label                    TEXT NOT NULL CHECK (label IN (
                                 'true_positive',
                                 'false_positive',
                                 'benign_retry',
                                 'needs_review',
                                 'unsafe_but_allowed',
                                 'missed_runaway'
                             )),
    reviewer_source          TEXT NOT NULL CHECK (reviewer_source IN ('human', 'api', 'import', 'system')),
    reviewer_role            TEXT,
    notes_fingerprint        TEXT,
    policy_change_suggested  BOOLEAN NOT NULL DEFAULT FALSE,
    reviewed_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_action_decision_reviews_outcome
        FOREIGN KEY (project, decision_id)
        REFERENCES action_decision_outcomes (project, decision_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_action_decision_reviews_project_label
    ON action_decision_reviews (project, label);
CREATE INDEX IF NOT EXISTS idx_action_decision_reviews_decision_id
    ON action_decision_reviews (decision_id);
CREATE INDEX IF NOT EXISTS idx_action_decision_reviews_project_reviewed_at
    ON action_decision_reviews (project, reviewed_at);

CREATE TABLE IF NOT EXISTS policy_learning_events (
    id                       BIGSERIAL PRIMARY KEY,
    project                  TEXT NOT NULL,
    source_decision_id       TEXT NOT NULL,
    tool_template            TEXT,
    old_policy_hash          TEXT,
    new_policy_hash          TEXT,
    change_type              TEXT NOT NULL CHECK (change_type IN (
                                 'threshold_change',
                                 'idempotency_key_change',
                                 'risk_reclass',
                                 'allowlist',
                                 'blocklist',
                                 'duplicate_window_change'
                             )),
    reason                   TEXT NOT NULL DEFAULT '',
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_policy_learning_events_outcome
        FOREIGN KEY (project, source_decision_id)
        REFERENCES action_decision_outcomes (project, decision_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_policy_learning_events_project_created_at
    ON policy_learning_events (project, created_at);
CREATE INDEX IF NOT EXISTS idx_policy_learning_events_source_decision_id
    ON policy_learning_events (source_decision_id);
