# API Key Authentication

HubbleOps requires `X-HubbleOps-API-Key` on every production endpoint that records
or changes customer state. Only `/healthz`, `/livez`, and `/readyz` are always
public. `/metrics` is private by default.

## Defaults

Production-safe defaults:

```env
HUBBLEOPS_ENV=prod
HUBBLEOPS_AUTH_ENABLED=true
HUBBLEOPS_DEV_AUTH_BYPASS=false
HUBBLEOPS_METRICS_PUBLIC=false
```

Local development may bypass auth only when both are set:

```env
HUBBLEOPS_ENV=dev
HUBBLEOPS_DEV_AUTH_BYPASS=true
```

Do not use dev bypass in customer or production deployments.

## Create an API Key

Generate a random key outside the repo and store only its hash in Postgres:

```bash
export HUBBLEOPS_API_KEY="replace-with-random-hubbleops-key"
export HUBBLEOPS_API_KEY_HASH="$(python -c 'import hashlib, os; print("sha256:" + hashlib.sha256(os.environ["HUBBLEOPS_API_KEY"].encode()).hexdigest())')"
```

Bind the key to one project with `psql -v api_key_hash="$HUBBLEOPS_API_KEY_HASH"`:

```sql
INSERT INTO projects (name, slug)
VALUES ('Acme', 'acme')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO api_keys (project_id, key_hash, label, expires_at)
SELECT id, :'api_key_hash', 'shadow-mode pilot', NOW() + INTERVAL '90 days'
FROM projects
WHERE slug = 'acme';
```

Keys are rejected when missing, invalid, disabled, expired, or used with a
different `X-Project` value.

Disable a key:

```sql
UPDATE api_keys
SET disabled_at = NOW()
WHERE key_hash = :'api_key_hash';
```

## Request Headers

Production proxy requests:

```bash
curl http://localhost:8080/openai/v1/chat/completions \
  -H "X-HubbleOps-API-Key: $HUBBLEOPS_API_KEY" \
  -H "X-Project: acme" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}'
```

Action/tool event requests:

```bash
curl http://localhost:8080/v1/action/check \
  -H "X-HubbleOps-API-Key: $HUBBLEOPS_API_KEY" \
  -H "X-Project: acme" \
  -H "Content-Type: application/json" \
  -d '{"session_id":"sess-123","action_name":"search_docs","args":{"q":"auth"}}'
```

If `X-Project` is omitted, HubbleOps binds the request to the authenticated
project. If it is present and does not match the key's project, HubbleOps returns
`403`.

## Session identity

When a request is authenticated, the session that loop-detector state, the
action ledger, and receipts key on is scoped under the API key's identity:
`key:<key-id>:<session_id>` (or `key:<key-id>` when no session is supplied).
The key ID is a short hash of the API key — it identifies the key without
revealing it. This means:

- Rotating or omitting `X-Session-ID` / `session_id` does not shed detector
  state across keys, and cannot dodge block enforcement by omission.
- Two agents using different keys can never collide on (or pollute) each
  other's session state, even if they pick the same session label.

## Metrics

`/metrics` requires `X-HubbleOps-API-Key` by default. Make it public only for
trusted local networks or when another layer already protects it:

```env
HUBBLEOPS_METRICS_PUBLIC=true
```
