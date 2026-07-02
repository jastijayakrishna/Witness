# Preflight Redteam Gates

HubbleOps preflight detectors are gated by local corpora under:

- `internal/preflight/migration/testdata/redteam`
- `internal/preflight/terraform/testdata/redteam`

The tests report false negatives on destructive fixtures and false positives on known-safe
fixtures. CI fails if destructive false negatives are greater than zero or if safe false
positives exceed the committed budget.

## Current Measurement

| Detector | Destructive fixtures | FN | Safe fixtures | FP | FP budget |
| --- | ---: | ---: | ---: | ---: | ---: |
| Migration | 7 | 0 | 4 | 0 | 0 |
| Terraform | 4 | 0 | 3 | 0 | 0 |

## Migration Coverage

The migration corpus covers the proven bypasses:

- `DELETE FROM users WHERE 1=1;` is classified as unbounded destructive DML.
- `UPDATE accounts SET x=0 WHERE 1=1;` is classified as unbounded risky DML.
- `/*! DROP TABLE users */;` is expanded as MySQL executable SQL before comment
  scrubbing and classified as destructive DDL.
- Rails-style migration DSL is not silently skipped; it emits
  `unanalyzable_migration` and requires approval.

Claimed Squawk-parity classes currently covered:

- destructive DDL: `DROP`, `TRUNCATE`, and dangerous `ALTER TABLE` clauses
- unbounded or tautological `DELETE` / `UPDATE`
- lock-taking index creation
- `ADD COLUMN ... NOT NULL` without a safe default
- validated foreign key/check constraints and unique/primary key additions
- bulk DML forms requiring review: CTE DML, `MERGE`, and `INSERT ... SELECT`

## Terraform Coverage

The Terraform corpus covers:

- replace of stateful resources scored as destroy-grade risk
- guarded `after_unknown` attributes escalated with `risk_unknown=true`
- stateful destroys
- public ingress exposure
- safe tag/storage growth, harmless deletes, and private ingress

Detector evidence remains privacy-safe: raw SQL, ORM content, Terraform state values, and
resource internals are not emitted in CLI/API findings.
