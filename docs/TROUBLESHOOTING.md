# Troubleshooting

## Docker Is Not Running

Symptom:

```text
[fail] Docker is installed but the daemon is not reachable.
```

Fix: start Docker Desktop, then rerun `make quickstart`.

## Proxy Is Not Ready Yet

Symptom:

```text
connect: connection refused; is HubbleOps running?
```

Fix:

```bash
docker compose -f deploy/docker-compose.yml logs proxy
docker compose -f deploy/docker-compose.yml up --build -d
make doctor
```

## Postgres Or Redis Is Unhealthy

Symptom:

```text
[fail] postgres_reachable: status=error
[fail] redis_reachable: status=error
```

Fix:

```bash
docker compose -f deploy/docker-compose.yml ps
docker compose -f deploy/docker-compose.yml logs postgres redis
```

If ports are already used locally, stop the conflicting services or edit the
host ports in `deploy/docker-compose.yml`.

## WAL Is Not Writable

Symptom:

```text
[fail] wal_writable: status=error
```

Fix: check the proxy logs and Docker volume permissions:

```bash
docker compose -f deploy/docker-compose.yml logs proxy
docker compose -f deploy/docker-compose.yml down
docker compose -f deploy/docker-compose.yml up --build -d
```

## Auth Failure

Symptom:

```text
status 401 ... provide -api-key or set HUBBLEOPS_API_KEY
```

Fix for the local stack: make sure the proxy container is running with
`HUBBLEOPS_ENV=dev` and `HUBBLEOPS_DEV_AUTH_BYPASS=true`, then rerun `make doctor`.

Fix for production-like runs: create an API key, set `HUBBLEOPS_API_KEY`, and pass
the matching `X-Project`. See [AUTH.md](AUTH.md).

## Receipt Signing Failure

Symptom:

```text
[fail] receipt_signing_config: receipt missing signature
```

Fix for production:

```bash
export HUBBLEOPS_RECEIPT_SIGNING_SECRET=replace-with-random-secret
export HUBBLEOPS_RECEIPT_KEY_ID=prod-2026-06
```

Unsigned receipts are allowed only for local/dev startup.

## Duplicate Demo Does Not Shadow Or Block

Symptom:

```text
outcome: duplicate refund was not blocked or shadowed
```

Fix: run `make doctor` first. If doctor passes, inspect proxy logs and confirm
the action firewall is connected to Postgres:

```bash
docker compose -f deploy/docker-compose.yml logs proxy
```

The local stack and `make doctor` do not need OpenAI, Anthropic, Gemini, or any
paid provider key.
