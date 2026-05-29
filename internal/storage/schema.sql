-- Witness Proxy Schema
-- Phase 0: Table definitions (empty, no triggers or functions)

CREATE TABLE IF NOT EXISTS projects (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    slug            TEXT NOT NULL UNIQUE,
    timezone        TEXT NOT NULL DEFAULT 'UTC',
    report_hour     INT NOT NULL DEFAULT 9,
    cache_ttl_sec   INT NOT NULL DEFAULT 3600,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_keys (
    id              BIGSERIAL PRIMARY KEY,
    project_id      BIGINT NOT NULL REFERENCES projects(id),
    key_hash        TEXT NOT NULL UNIQUE,
    label           TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS prompts (
    id              BIGSERIAL PRIMARY KEY,
    project_id      BIGINT REFERENCES projects(id),
    prompt_hash     TEXT NOT NULL,
    sample_prefix   TEXT NOT NULL DEFAULT '',
    total_calls     BIGINT NOT NULL DEFAULT 1,
    total_cost      NUMERIC(12, 8) NOT NULL DEFAULT 0,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, prompt_hash)
);

CREATE TABLE IF NOT EXISTS budgets (
    id              BIGSERIAL PRIMARY KEY,
    project_id      BIGINT NOT NULL REFERENCES projects(id) UNIQUE,
    daily_soft      NUMERIC(10, 2),
    daily_hard      NUMERIC(10, 2),
    monthly_soft    NUMERIC(10, 2),
    monthly_hard    NUMERIC(10, 2),
    rpm_limit       INT,
    tpm_limit       INT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS anomalies (
    id              BIGSERIAL PRIMARY KEY,
    project_id      BIGINT NOT NULL REFERENCES projects(id),
    rule            TEXT NOT NULL,
    description     TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'warning',
    muted_until     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Phase 2: WAL records table (drained from WAL files)
CREATE TABLE IF NOT EXISTS wal_records (
    id              BIGSERIAL PRIMARY KEY,
    ulid            TEXT NOT NULL DEFAULT '',
    time            TIMESTAMPTZ NOT NULL,
    project         TEXT NOT NULL,
    provider        TEXT NOT NULL,
    model           TEXT NOT NULL,
    prompt_hash     TEXT NOT NULL,
    input_tokens    INT NOT NULL DEFAULT 0,
    output_tokens   INT NOT NULL DEFAULT 0,
    total_tokens    INT NOT NULL DEFAULT 0,
    cost            NUMERIC(12, 8) NOT NULL DEFAULT 0,
    latency_ms      BIGINT NOT NULL DEFAULT 0,
    status_code     INT NOT NULL DEFAULT 0,
    cache_hit       BOOLEAN NOT NULL DEFAULT FALSE,
    stream          BOOLEAN NOT NULL DEFAULT FALSE,
    session_id      TEXT NOT NULL DEFAULT '',
    tool_signature  TEXT NOT NULL DEFAULT '',
    args_fingerprint TEXT NOT NULL DEFAULT '',
    loop_signals_fired TEXT NOT NULL DEFAULT '',
    loop_confidence NUMERIC(5,4) NOT NULL DEFAULT 0,
    loop_action     TEXT NOT NULL DEFAULT '',
    prev_hash       TEXT NOT NULL,
    record_hash     TEXT NOT NULL UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_prompts_project_hash ON prompts (project_id, prompt_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys (key_hash);

-- Phase 2: WAL records indexes for reconciliation queries
CREATE INDEX IF NOT EXISTS idx_wal_records_time ON wal_records (time);
CREATE INDEX IF NOT EXISTS idx_wal_records_project ON wal_records (project, time);
CREATE INDEX IF NOT EXISTS idx_wal_records_hash ON wal_records (record_hash);

-- v5.2: moat columns on wal_records
-- trajectory_id groups all requests in one agent session into a single replayable unit
ALTER TABLE wal_records ADD COLUMN IF NOT EXISTS trajectory_id      TEXT NOT NULL DEFAULT '';
-- detector_version lets future replay pipelines know which algorithm made each decision
ALTER TABLE wal_records ADD COLUMN IF NOT EXISTS detector_version   TEXT NOT NULL DEFAULT '';
-- framework fingerprint (langchain / crewai / unknown) for cross-framework learning
ALTER TABLE wal_records ADD COLUMN IF NOT EXISTS framework          TEXT NOT NULL DEFAULT 'unknown';
-- near_miss: confidence 0.50-0.69 — the most valuable training signal you have
ALTER TABLE wal_records ADD COLUMN IF NOT EXISTS near_miss          BOOLEAN NOT NULL DEFAULT FALSE;
-- immediate_outcome: success / blocked / error — set by handler at response time
ALTER TABLE wal_records ADD COLUMN IF NOT EXISTS immediate_outcome  TEXT NOT NULL DEFAULT 'unknown';

CREATE INDEX IF NOT EXISTS idx_wal_records_trajectory ON wal_records (trajectory_id);
CREATE INDEX IF NOT EXISTS idx_wal_records_near_miss  ON wal_records (near_miss) WHERE near_miss = TRUE;

-- v5.2: trajectory labels — the most valuable table in the whole system.
-- Every override token redemption writes a row automatically (source='override_token').
-- Human reviews write source='human'. This becomes your training corpus.
CREATE TABLE IF NOT EXISTS trajectory_labels (
    id              BIGSERIAL PRIMARY KEY,
    trajectory_id   TEXT NOT NULL,
    project         TEXT NOT NULL,
    label           TEXT NOT NULL,        -- true_runaway / false_positive / legit_batch
    source          TEXT NOT NULL,        -- override_token / human / replay
    reason          TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_traj_labels_trajectory ON trajectory_labels (trajectory_id);

-- v5.2: feedback table — human verdicts on enforcement decisions via Slack buttons
-- or POST /feedback/{token}. Linked to trajectory, enriches trajectory_labels.
CREATE TABLE IF NOT EXISTS feedback (
    id              BIGSERIAL PRIMARY KEY,
    trajectory_id   TEXT NOT NULL,
    override_token  TEXT NOT NULL DEFAULT '',
    verdict         TEXT NOT NULL,        -- correct_block / false_positive / correct_pass
    reason          TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_feedback_trajectory ON feedback (trajectory_id);

-- v5.2: economic profiles — per-session signatures computed by drain worker.
-- cost_velocity, token_burn_accel, tool_amplification drive future adaptive thresholds.
CREATE TABLE IF NOT EXISTS economic_profiles (
    id                       BIGSERIAL PRIMARY KEY,
    trajectory_id            TEXT NOT NULL UNIQUE,
    project                  TEXT NOT NULL,
    session_id               TEXT NOT NULL,
    marginal_cost_velocity   NUMERIC(12,8) NOT NULL DEFAULT 0,
    token_burn_accel         NUMERIC(8,4)  NOT NULL DEFAULT 0,
    tool_amplification       NUMERIC(8,4)  NOT NULL DEFAULT 0,
    total_cost               NUMERIC(12,8) NOT NULL DEFAULT 0,
    total_calls              INT           NOT NULL DEFAULT 0,
    computed_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- v5.2: policy baselines — per-project nightly averages that seed future adaptive thresholds.
-- Computed by reporter, never written by the hot path.
CREATE TABLE IF NOT EXISTS policy_baselines (
    id                   BIGSERIAL PRIMARY KEY,
    project              TEXT NOT NULL,
    baseline_date        DATE NOT NULL,
    avg_confidence       NUMERIC(5,4) NOT NULL DEFAULT 0,
    avg_cost_velocity    NUMERIC(12,8) NOT NULL DEFAULT 0,
    p95_cost_velocity    NUMERIC(12,8) NOT NULL DEFAULT 0,
    near_miss_rate       NUMERIC(5,4)  NOT NULL DEFAULT 0,
    true_runaway_rate    NUMERIC(5,4)  NOT NULL DEFAULT 0,
    sample_count         INT           NOT NULL DEFAULT 0,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project, baseline_date)
);