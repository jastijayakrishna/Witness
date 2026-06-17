# Quickstart

Run HubbleOps locally and confirm the full action-firewall path works, without any
paid provider API keys.

## One Command

```bash
make quickstart
```

This runs:

```bash
docker compose -f deploy/docker-compose.yml up --build -d
go run ./cmd/hubbleops doctor -base-url http://localhost:8080
```

Expected `doctor` shape:

```text
HubbleOps doctor
[ok] proxy_reachable: {"status":"alive"}
[ok] postgres_reachable: status=ok
[ok] redis_reachable: status=ok
[ok] wal_writable: status=ok
[ok] action_check: action=allow
[ok] action_result: action=allow
```

`doctor` performs a real pre-tool check and result round-trip against the proxy, so a
green run confirms Postgres, Redis, the WAL, and signing are all wired correctly.

The local Docker stack uses `HUBBLEOPS_ENV=dev`, dev auth bypass, and public
metrics so it is easy to try. Production defaults remain locked down by startup
validation.

## See it catch something

Point your agent's SDK at `http://localhost:8080` (set `HUBBLEOPS_BASE_URL`) and run a
workload — a runaway loop, a repeated side effect, an action over its declared limit.
In the local default `shadow` mode, HubbleOps allows each call but records what it
*would* have enforced. Then read the ranked report straight off the WAL:

```bash
go run ./cmd/hubbleops shadow-report ./path/to/wal-YYYY-MM-DD.jsonl
```

To read the WAL the Docker proxy wrote, copy it out of the container volume first:

```bash
docker cp "$(docker compose -f deploy/docker-compose.yml ps -q proxy):/data/wal/." ./wal/
go run ./cmd/hubbleops shadow-report ./wal/wal-*.jsonl
```

## Useful Commands

```bash
make doctor
make test
```

## What `doctor` checks

- proxy reachability
- Postgres reachability
- Redis reachability
- WAL writability
- local auth expectation
- receipt signing expectation
- `/v1/action/check`
- `/v1/action/result`
