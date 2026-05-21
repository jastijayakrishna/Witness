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

CREATE TABLE IF NOT EXISTS requests (
    id              BIGSERIAL PRIMARY KEY,
    project_id      BIGINT REFERENCES projects(id),
    provider        TEXT NOT NULL,
    model           TEXT NOT NULL,
    prompt_hash     TEXT NOT NULL,
    input_tokens    INT NOT NULL DEFAULT 0,
    output_tokens   INT NOT NULL DEFAULT 0,
    total_tokens    INT NOT NULL DEFAULT 0,
    cost            NUMERIC(12, 8) NOT NULL DEFAULT 0,
    latency_ms      INT NOT NULL DEFAULT 0,
    status_code     INT NOT NULL DEFAULT 0,
    cache_hit       BOOLEAN NOT NULL DEFAULT FALSE,
    stream          BOOLEAN NOT NULL DEFAULT FALSE,
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

-- Indexes (will be created concurrently in Phase 2, defined here for reference)
CREATE INDEX IF NOT EXISTS idx_requests_project_created ON requests (project_id, created_at);
CREATE INDEX IF NOT EXISTS idx_requests_prompt_hash ON requests (prompt_hash);
CREATE INDEX IF NOT EXISTS idx_requests_provider_model ON requests (provider, model);
CREATE INDEX IF NOT EXISTS idx_prompts_project_hash ON prompts (project_id, prompt_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys (key_hash);
