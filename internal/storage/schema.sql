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
