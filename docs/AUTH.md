# Preflight Identity

HubbleOps captures identity on every preflight receipt so later review labels can
be tied back to the agent action. The local CLI takes identity from flags. The
gate server takes identity from the JSON action request or from a verified
GitHub pull request webhook.

Required receipt identifiers:

- `project`
- `session`
- `actor`
- `action`

Recommended:

- `human_delegator`
- `environment`
- `idempotency_key`

Example:

```bash
go run ./cmd/hubbleops preflight terraform plan.json \
  -project acme \
  -session "$GITHUB_RUN_ID" \
  -actor agent:claude-code \
  -human-delegator "$GITHUB_ACTOR" \
  -env production
```

GitHub webhook authentication:

- Set `GITHUB_WEBHOOK_SECRET`.
- GitHub sends `X-Hub-Signature-256`.
- `cmd/gate` rejects pull request webhooks when the HMAC does not match.

GitHub App authentication:

- Set `GITHUB_APP_ID`.
- Set `GITHUB_APP_PRIVATE_KEY_FILE` or `GITHUB_APP_PRIVATE_KEY`.
- The App exchanges an RS256 JWT for an installation token, reads changed files
  and CODEOWNERS, and writes a check run.

Raw secrets and raw tool args do not belong in these fields. Use stable labels
and let HubbleOps fingerprint intent, target, evidence, and idempotency values
on the receipt path.
