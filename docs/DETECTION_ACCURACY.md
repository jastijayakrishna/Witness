# Detection Accuracy

This report is generated from the committed redteam corpora under:

- `internal/preflight/terraform/testdata/redteam`
- `internal/preflight/migration/testdata/redteam`

Run:

```bash
go test -v ./internal/preflight/terraform ./internal/preflight/migration -run Redteam
```

Current committed measurement:

| Detector | Total cases | Destructive cases | False negatives | Safe cases | False positives | FP budget |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Terraform plan | 196 | 105 | 0 (0.00%) | 91 | 0 (0.00%) | 5 |
| SQL/ORM migration | 188 | 105 | 0 (0.00%) | 83 | 0 (0.00%) | 5 |

The destructive sets include cases that must block or require approval; FN means the
highest emitted risk was below that fixture's required threshold. The safe sets are
expected to emit no findings; FP means at least one finding was emitted.

Terraform coverage includes stateful destroy and replace, count/for_each-style fan-out,
guarded `after_unknown`, deletion protection changes, storage shrink, final snapshot
skips, `force_destroy`, public security group ingress, IAM wildcard policies, S3 public
access, and S3 versioning rollback.

Migration coverage includes Squawk-style DDL/locking classes, MySQL executable comments,
tautological `DELETE`/`UPDATE`, CTE and bulk DML, quoted identifiers, dollar-quoted
literals, ORM migration fail-closed files, bounded DML, concurrent indexes, temporary
table cleanup, and safe alter-table patterns.
