# Witness Proxy

Open-source LLM cost proxy with usage tracking, budget enforcement, and Slack reporting.

## Features (Phase 0 + Phase 1)

- **Multi-provider support**: OpenAI, Anthropic (Gemini + Cohere in Phase 5)
- **Streaming & non-streaming**: Full SSE streaming support with usage capture
- **Write-ahead log (WAL)**: Durable usage tracking with batched fsync (every 50 records or 100ms)
- **Cost calculation**: Real-time cost tracking with hardcoded per-token pricing
- **Attribution**: Project resolution via `X-Project` header or SHA256(Authorization) fallback
- **Health & metrics**: `/healthz` endpoint and Prometheus `/metrics`

## Quick Start

### Prerequisites

- Docker & Docker Compose
- (Optional) Go 1.23+ for local development

### Run with Docker Compose

```bash
cd deploy
docker compose up --build
```

Services:
- Proxy: `http://localhost:8080`
- Postgres: `localhost:5432` (user: witness, db: witness)
- Redis: `localhost:6379`

### Verify

```bash
# Health check
curl http://localhost:8080/healthz
# {"status":"healthy"}

# Prometheus metrics
curl http://localhost:8080/metrics
```

## Usage

### OpenAI (non-streaming)

```bash
curl http://localhost:8080/openai/v1/chat/completions \
  -H "Authorization: Bearer YOUR_OPENAI_KEY" \
  -H "X-Project: my-project" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

### OpenAI (streaming)

```bash
curl http://localhost:8080/openai/v1/chat/completions \
  -H "Authorization: Bearer YOUR_OPENAI_KEY" \
  -H "X-Project: my-project" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Hello!"}],
    "stream": true
  }'
```

### Anthropic

```bash
curl http://localhost:8080/anthropic/v1/messages \
  -H "x-api-key: YOUR_ANTHROPIC_KEY" \
  -H "X-Project: my-project" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "claude-3-5-sonnet-20241022",
    "messages": [{"role": "user", "content": "Hello!"}],
    "max_tokens": 100
  }'
```

### Using the Python SDK

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/openai/v1",
    api_key="YOUR_OPENAI_KEY",
    default_headers={"X-Project": "my-python-app"}
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello!"}],
    stream=True
)

for chunk in response:
    print(chunk.choices[0].delta.content or "", end="")
```

## Architecture

```
Client → Proxy (port 8080)
          ├─→ Resolve project (X-Project or SHA256(auth))
          ├─→ Forward to OpenAI/Anthropic
          ├─→ Extract usage from response
          ├─→ Compute cost from hardcoded pricing
          ├─→ Write to WAL (fsync before return)
          └─→ Return response to client

WAL → data/wal/wal-YYYY-MM-DD.jsonl (append-only, fsynced)
```

## Configuration

Environment variables (all optional, defaults shown):

```bash
WITNESS_SERVER_HOST=0.0.0.0
WITNESS_SERVER_PORT=8080
WITNESS_POSTGRES_HOST=localhost
WITNESS_POSTGRES_PORT=5432
WITNESS_POSTGRES_USER=witness
WITNESS_POSTGRES_PASSWORD=witness
WITNESS_POSTGRES_DBNAME=witness
WITNESS_POSTGRES_SSLMODE=disable
WITNESS_REDIS_HOST=localhost
WITNESS_REDIS_PORT=6379
WITNESS_REDIS_PASSWORD=
WITNESS_REDIS_DB=0
WITNESS_WAL_DIR=data/wal
```

Or use `configs/proxy.yaml`:

```yaml
server:
  host: "0.0.0.0"
  port: 8080

postgres:
  host: "postgres"
  port: 5432
  user: "witness"
  password: "witness"
  dbname: "witness"
  sslmode: "disable"

redis:
  host: "redis"
  port: 6379
  password: ""
  db: 0
```

## Database Schema

Tables created on first boot:

- `projects` - Project definitions with timezone, report settings
- `api_keys` - API key hashes mapped to projects
- `requests` - Every proxied request with tokens, cost, latency
- `prompts` - Prompt hash aggregations (total calls, total cost)
- `budgets` - Per-project budget limits (soft/hard, daily/monthly)
- `anomalies` - Detected anomalies for alerting

## WAL Format

Append-only JSONL (one record per line):

```json
{"time":"2025-01-15T10:30:45.123Z","project":"my-project","provider":"openai","model":"gpt-4o-mini","prompt_hash":"a1b2c3d4e5f6g7h8","input_tokens":10,"output_tokens":25,"total_tokens":35,"cost":0.0000105,"latency_ms":342,"status_code":200,"cache_hit":false,"stream":false}
```

## Development

### Build

```bash
go build ./cmd/proxy
```

### Test

```bash
# Run all tests
go test ./...

# Run with coverage
go test ./... -cover

# Run specific package
go test ./internal/providers -v

# Run benchmarks
go test ./internal/providers -bench=. -benchmem

# Run fuzz tests (30 seconds each)
go test ./internal/providers -fuzz=FuzzExtractOpenAIUsage -fuzztime=30s
```

### Test Categories

- **Unit tests** (37): Pure functions, no I/O
- **Integration tests** (19): Full proxy roundtrip with fake HTTP servers
- **Regression tests** (9): Real captured API payloads from Jan 2025
- **Fault injection** (11): Upstream failures, timeouts, malformed responses
- **Durability tests** (6): WAL recovery, 5000 concurrent writes
- **Fuzz tests** (6): Random garbage at all JSON parsers
- **Benchmarks** (13): Performance regression detection

Total: **114 tests**, all passing

### Performance

Measured on Go 1.25, Windows 11:

- Usage extraction: **3µs** (OpenAI), **2µs** (Anthropic)
- Cost computation: **7ns**
- WAL write: **14µs** (marshal + append + batched fsync)
- Full proxy roundtrip: **240µs** (median, including upstream)

## Project Structure

```
witness-proxy/
├── cmd/proxy/main.go           # Main entry point
├── internal/
│   ├── config/                 # YAML config loader with env overrides
│   ├── providers/              # OpenAI + Anthropic adapters
│   │   ├── provider.go         # Provider interface & registry
│   │   ├── openai.go           # OpenAI usage extraction
│   │   ├── anthropic.go        # Anthropic usage extraction
│   │   └── pricing.go          # Hardcoded per-token pricing
│   ├── proxy/                  # HTTP proxy logic
│   │   ├── handler.go          # Non-streaming requests
│   │   ├── streaming.go        # SSE streaming with accumulator
│   │   └── attribution.go      # Project resolution
│   ├── wal/                    # Write-ahead log
│   │   └── writer.go           # Append-only JSONL with batched fsync
│   └── storage/
│       ├── schema.sql          # Postgres schema
│       └── migrate.go          # Embedded migration runner
├── configs/
│   ├── proxy.yaml              # Active config
│   └── proxy.yaml.example      # Example config
├── deploy/
│   └── docker-compose.yml      # 3-service stack
├── Dockerfile                  # Multi-stage Go build
└── README.md
```

## Roadmap

- [x] **Phase 0**: Skeleton boots (healthz, metrics, empty DB)
- [x] **Phase 1**: OpenAI + Anthropic proxying with WAL
- [ ] **Phase 2**: WAL drain worker, prompt normalization, Postgres reconciliation
- [ ] **Phase 3**: Redis cache, retry+fallback, budget caps, rate limiting
- [ ] **Phase 4**: Slack daily reports, anomaly detection
- [ ] **Phase 5**: Gemini + Cohere, Grafana dashboard, Docker image <20MB
- [ ] **Phase 6**: 1 paying customer, OSS launch, YC application

## License

Apache 2.0

## Contributing

This is pre-launch. No external contributions yet. Follow the repo for updates.
