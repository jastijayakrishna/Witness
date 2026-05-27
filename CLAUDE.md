# Witness Proxy

LLM cost proxy with usage tracking, tamper-evident WAL, and budget enforcement. Go 1.25, Apache 2.0.

## File map

```
cmd/proxy/main.go           → Main binary. Config→zerolog→pgx→redis→WAL→chi→serve. Port 8080.
cmd/waldrain/main.go         → WAL drain worker. Polls WAL dir, batches 100, tx insert. Port 9090.
internal/config/config.go    → Config struct + Load(yamlPath) + applyEnvOverrides. WITNESS_* env vars.
internal/providers/provider.go → Provider struct + Registry map + Lookup(path). SSEEvent struct.
internal/providers/openai.go   → /openai → api.openai.com. Injects stream_options.include_usage.
internal/providers/anthropic.go → /anthropic → api.anthropic.com. message_start + message_delta.
internal/providers/pricing.go  → PricingTable map + ComputeCost(model, in, out) float64.
internal/proxy/handler.go     → Handler.ServeHTTP → handleNonStream/handleStream. WAL write before response.
internal/proxy/streaming.go   → SSE accumulator. Only keeps usage-relevant events. Conditional chunk suppression.
internal/proxy/attribution.go → ResolveProject: X-Project → SHA256(auth)[:16] → "unknown".
internal/wal/writer.go        → Writer + Record struct. Batched fsync (50 records / 100ms). ULID generation.
internal/wal/chain.go         → Chain() + VerifyChain() + saveChainHead(). genesis on first boot.
internal/attribution/normalizer.go → NormalizePrompt + HashNormalizedPrompt (SHA256, 16 hex chars).
internal/storage/schema.sql   → 6 tables: projects, api_keys, prompts, budgets, anomalies, wal_records.
internal/storage/migrate.go   → Embeds schema.sql, runs on boot via pgxpool.Exec.
deploy/docker-compose.yml     → postgres:16 + redis:7 + proxy + waldrain. Ports: 5433, 6380, 8080, 9090.
configs/proxy.yaml            → server/postgres/redis/wal config. sync_mode: batch|sync.
```

## Key types

```go
// internal/wal/writer.go
type Record struct {
    ID, Project, Provider, Model, PromptHash string
    InputTokens, OutputTokens, TotalTokens   int
    Cost float64; LatencyMs int64; StatusCode int
    CacheHit, Stream bool
    SessionID, ToolSignature, ArgsFingerprint string  // Phase 1-2
    LoopSignalsFired string; LoopConfidence float64; LoopAction string // Phase 3 (empty until wired)
    PrevHash, RecordHash string      // hash chain
    ChainRestart bool                // crash recovery marker (omitempty)
    Time time.Time
}

// internal/providers/provider.go
type Provider struct {
    Name, PathPrefix string; Target *url.URL
    ExtractUsage            func(body []byte) (Usage, error)
    ExtractStreamUsage      func(events []SSEEvent) (Usage, error)
    IsStreamRequest         func(body []byte) bool
    PrepareStreamBody       func(body []byte) ([]byte, error)  // nil for Anthropic
    ExtractToolCalls        func(body []byte) []ToolCall
    ExtractStreamToolCalls  func(events []SSEEvent) []ToolCall
}
type ToolCall struct { Name, Arguments string }
type Usage struct { InputTokens, OutputTokens, TotalTokens int; Model string }
```

## Postgres tables

projects(id,name,slug,timezone,report_hour), api_keys(id,project_id,key_hash), prompts(id,project_id,prompt_hash,total_calls,total_cost,first_seen,last_seen), budgets(id,project_id,daily_soft/hard,monthly_soft/hard,rpm_limit,tpm_limit), anomalies(id,project_id,rule,description,severity,muted_until), wal_records(id,ulid,time,project,provider,model,prompt_hash,tokens,cost,latency_ms,status_code,cache_hit,stream,session_id,tool_signature,args_fingerprint,loop_signals_fired,loop_confidence,loop_action,prev_hash,record_hash)

## Invariants

- WAL write BEFORE response returns. Non-negotiable.
- Hash chain: prev_hash == previous record_hash. Break → drain halts + llmproxy_wal_chain_violation_total.
- Usage chunks suppressed ONLY when proxy injected include_usage (clientHasIncludeUsage check).
- Streaming keeps only usage-relevant events, not all content deltas.
- WAL failures → walWriteFailures.Inc() + log "reconciliation gap".
- Drain worker: separate binary. Never merge into proxy.
- Config: plain YAML + env overrides. No Viper, no Cobra.

## Build / test / run

```bash
go build ./...
go test ./...                        # 123 tests, 0 failures required
go test ./internal/proxy/... -v      # proxy tests only
go test ./... -bench=. -benchmem     # benchmarks
docker compose -f deploy/docker-compose.yml up --build  # full stack
```

## Conventions

- Tests use httptest.NewServer for fake upstreams, swap provider.Target, restore in defer.
- WAL tests use t.TempDir() for isolation.
- Error handling: log.Error + continue for non-fatal (WAL write), log.Fatal for startup failures.
- Metrics prefix: `llmproxy_` for domain metrics, `witness_` for HTTP infra metrics.
- New providers: add internal/providers/{name}.go with init() that calls Register().

## Implementation status

Phases 0-2 complete. See `implementation.txt` for the full plan. Phase 3 is next: Redis cache, loop detection, budget enforcement, rate limiter.

## Context management

- Read THIS file first. It has everything you need to understand the repo.
- Use targeted file reads (specific paths from the file map above), not recursive searches.
- When you need to find something, grep for it by name — don't glob `**/*.go` and read everything.
- For multi-file edits, read only the files you're changing, not their neighbors.
- Autocompact is set to 70% — the session will compact early to preserve cache and reduce cost.
- Bash output is capped at 20k chars — pipe long output through `head` or `tail` if needed.
- Keep sessions focused on one phase/feature. Start a new session for unrelated work.

## Don't

- Don't scan the whole repo to understand it. This file has everything you need.
- Don't add Viper, Cobra, or config frameworks.
- Don't build a web dashboard. Slack is the v1 UI.
- Don't add Phase 3+ features without completing the current phase.
- Don't change WAL field names (input_tokens/output_tokens/cost).
- Don't add comments, docstrings, or type annotations to code you didn't change.
- Don't read log files, vendor dirs, or .git internals — they're denied in settings.
- Don't switch models mid-session (breaks prompt cache, wastes tokens).
