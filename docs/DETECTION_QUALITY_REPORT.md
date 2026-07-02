# HubbleOps Detection Quality Study - 2026-07-01

## A. Headline Numbers

Measured fact, not vibes:

- SQL migration detector, full real SQL corpus: 1430 UTF-8 SQL files, 70785 statements, 4559 HubbleOps flags. Raw HubbleOps flag rate: 6.4% per statement and 34.5% per file.
- SQL routine-migration subset: 699 files, 2737 statements, 618 HubbleOps flags. Semantic review found at least 239 false-positive flags (38.7% of HubbleOps routine positives; 8.7% of routine statements; 84/699 files). At that per-file FP rate, a team sees a false approval/block roughly every 8.3 migration PRs.
- SQL false-negative rate vs Squawk safety-rule subset: 1218/(630+1218) = 65.9%. This excludes Squawk `syntax-error` and broad style-only rules from the denominator.
- Terraform plan detector: 52 real plan JSON files, 408 resources, only 2 HubbleOps findings. Checkov found 1414 comparable failed checks; HubbleOps agreed on 4 and missed 1410. FN rate vs Checkov failed checks: 99.7%. FP rate on shared Checkov corpus is effectively low because HubbleOps almost never fires; that is not a win.
- GitHub PR detector: not statistically measured. GitHub API rate-limited unauthenticated sampling after 2 qualifying PRs, below the required 50+ sample.

Verdict in one sentence: SQL would annoy developers quickly, Terraform would miss nearly everything Checkov cares about, and the PR gate is not production-trustworthy as a BLOCK gate from these numbers.

## B. Confusion Matrices

### SQL vs Squawk Safety Rules

Matching key: normalized file + mapped safety category + nearby line when possible. Confidence: medium; SQL line numbers from HubbleOps are approximate because the detector does not expose statement indexes.

|category|agree|HubbleOps-only|Squawk-only|
|---|---|---|---|
|drop_table|205|1457|68|
|create_index_nonconcurrent|372|884|229|
|unbounded_update|0|450|0|
|constraint_missing_not_valid|0|0|335|
|add_foreign_key|0|0|309|
|drop_column|29|214|30|
|unbounded_delete|0|220|0|
|truncate|3|194|3|
|drop_constraint|0|197|0|
|alter_column_type|5|122|23|
|drop_index_nonconcurrent|0|0|72|
|add_not_null|6|39|25|
|rename_column|10|26|6|
|set_not_null|0|41|0|
|reindex_nonconcurrent|0|0|35|
|drop_not_null|0|0|24|
|add_column_default|0|0|21|
|partition_detach_nonconcurrent|0|0|16|
|drop_database|0|0|11|
|serial_primary_key|0|0|11|

Totals: agree=630, HubbleOps-only=3844, Squawk-only=1218.

### Terraform vs Checkov terraform_plan

|category/check|agree|HubbleOps-only|Checkov-only|
|---|---|---|---|
|all comparable Checkov failed checks|4|1|1410|
|CKV2_AWS_62|||82|
|CKV_AWS_144|||82|
|CKV_AWS_145|||74|
|CKV2_AWS_6|||70|
|CKV_AWS_21|||58|
|CKV_AWS_130|||32|
|CKV_AWS_37|||30|
|CKV_AWS_39|||30|
|CKV_AWS_38|||30|
|CKV_AWS_58|||30|
|CKV_AWS_18|||28|
|CKV2_AWS_61|||28|
|CKV_AWS_287|||24|
|CKV_AWS_289|||24|
|CKV_AWS_355|||24|
|CKV_AWS_126|||20|
|CKV_AWS_135|||20|
|CKV_AWS_79|||20|
|CKV_AWS_8|||20|
|CKV_AWS_288|||20|

Totals: agree=4, HubbleOps-only=1, Checkov-only=1410.

## C. Top False Positives

These are measured from `raw/routine_sql_hubbleops_semantic_labels.jsonl`. Confidence: high for same-file new-table index cases; the SQL semantics are straightforward.

|#|input + line|why safe|misfire|fix|
|---|---|---|---|---|
|1|C:\tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20210605225044_init\migration.sql:44|index is on table created in same migration; no existing rows to lock|migration_index_lock / CREATE_INDEX_LOCK|track CREATE TABLE tables per file and suppress non-concurrent index flags for same-migration new tables|
|2|C:\tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20210615153759_add_email_verification_column\migration.sql:17|index is on table created in same migration; no existing rows to lock|migration_index_lock / CREATE_INDEX_LOCK|track CREATE TABLE tables per file and suppress non-concurrent index flags for same-migration new tables|
|3|C:\tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20210813142905_event_payment\migration.sql:29|index is on table created in same migration; no existing rows to lock|migration_index_lock / CREATE_INDEX_LOCK|track CREATE TABLE tables per file and suppress non-concurrent index flags for same-migration new tables|
|4|C:\tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20210908042159_teams_feature\migration.sql:18|index is on table created in same migration; no existing rows to lock|migration_index_lock / CREATE_INDEX_LOCK|track CREATE TABLE tables per file and suppress non-concurrent index flags for same-migration new tables|
|5|C:\tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20210908220336_add_daily_data_table\migration.sql:12|index is on table created in same migration; no existing rows to lock|migration_index_lock / CREATE_INDEX_LOCK|track CREATE TABLE tables per file and suppress non-concurrent index flags for same-migration new tables|
|6|C:\tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20211004231654_add_webhook_model\migration.sql:17|index is on table created in same migration; no existing rows to lock|migration_index_lock / CREATE_INDEX_LOCK|track CREATE TABLE tables per file and suppress non-concurrent index flags for same-migration new tables|
|7|C:\tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20211207010154_add_destination_calendar\migration.sql:14|index is on table created in same migration; no existing rows to lock|migration_index_lock / CREATE_INDEX_LOCK|track CREATE TABLE tables per file and suppress non-concurrent index flags for same-migration new tables|
|8|C:\tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20220413002425_adds_api_keys\migration.sql:15|index is on table created in same migration; no existing rows to lock|migration_index_lock / CREATE_INDEX_LOCK|track CREATE TABLE tables per file and suppress non-concurrent index flags for same-migration new tables|
|9|C:\tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20220420152505_add_hashed_event_url\migration.sql:14|index is on table created in same migration; no existing rows to lock|migration_index_lock / CREATE_INDEX_LOCK|track CREATE TABLE tables per file and suppress non-concurrent index flags for same-migration new tables|
|10|C:\tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20220423175732_added_next_auth_models\migration.sql:30|index is on table created in same migration; no existing rows to lock|migration_index_lock / CREATE_INDEX_LOCK|track CREATE TABLE tables per file and suppress non-concurrent index flags for same-migration new tables|
|11|C:\tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20220502154345_adds_apps\migration.sql:20|index is on table created in same migration; no existing rows to lock|migration_index_lock / CREATE_INDEX_LOCK|track CREATE TABLE tables per file and suppress non-concurrent index flags for same-migration new tables|
|12|C:\tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20220616072241_app_routing_forms\migration.sql:27|index is on table created in same migration; no existing rows to lock|migration_index_lock / CREATE_INDEX_LOCK|track CREATE TABLE tables per file and suppress non-concurrent index flags for same-migration new tables|
|13|C:\tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20220711182928_add_workflows\migration.sql:68|index is on table created in same migration; no existing rows to lock|migration_index_lock / CREATE_INDEX_LOCK|track CREATE TABLE tables per file and suppress non-concurrent index flags for same-migration new tables|
|14|C:\tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20230303162003_add_booking_seat_reference\migration.sql:19|index is on table created in same migration; no existing rows to lock|migration_index_lock / CREATE_INDEX_LOCK|track CREATE TABLE tables per file and suppress non-concurrent index flags for same-migration new tables|
|15|C:\tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20230303195431_add_feature_flags\migration.sql:20|index is on table created in same migration; no existing rows to lock|migration_index_lock / CREATE_INDEX_LOCK|track CREATE TABLE tables per file and suppress non-concurrent index flags for same-migration new tables|

## D. Top False Negatives

### SQL False Negatives

|#|input + line|why dangerous|competitor|fix|
|---|---|---|---|---|
|1|C:/tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20210605225044_init\migration.sql:47|By default new constraints require a table scan and block writes to the table while that scan occurs.|constraint-missing-not-valid|Add SQL grammar rule for constraint_missing_not_valid|
|2|C:/tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20210605225044_init\migration.sql:47|Adding a foreign key constraint requires a table scan and a `SHARE ROW EXCLUSIVE` lock on both tables, which blocks writes to each table.|adding-foreign-key-constraint|Add SQL grammar rule for add_foreign_key|
|3|C:/tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20210605225044_init\migration.sql:50|By default new constraints require a table scan and block writes to the table while that scan occurs.|constraint-missing-not-valid|Add SQL grammar rule for constraint_missing_not_valid|
|4|C:/tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20210605225044_init\migration.sql:50|Adding a foreign key constraint requires a table scan and a `SHARE ROW EXCLUSIVE` lock on both tables, which blocks writes to each table.|adding-foreign-key-constraint|Add SQL grammar rule for add_foreign_key|
|5|C:/tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20210814175645_custom_inputs_type_enum\migration.sql:13|Setting a column `NOT NULL` blocks reads while the table is scanned.|adding-not-nullable-field|Add SQL grammar rule for add_not_null|
|6|C:/tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20210814175645_custom_inputs_type_enum\migration.sql:14|Dropping a column may break existing clients.|ban-drop-column|Add SQL grammar rule for drop_column|
|7|C:/tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20210908235519_undo_unique_user_id_slug\migration.sql:2|A normal `DROP INDEX` acquires an `ACCESS EXCLUSIVE` lock on the table, blocking other accesses until the index drop can complete.|require-concurrent-index-deletion|Add SQL grammar rule for drop_index_nonconcurrent|
|8|C:/tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20211011152041_non_optionals\migration.sql:11|Setting a column `NOT NULL` blocks reads while the table is scanned.|adding-not-nullable-field|Add SQL grammar rule for add_not_null|
|9|C:/tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20211105200545_availability_start_and_end_time_as_time\migration.sql:11|Dropping a column may break existing clients.|ban-drop-column|Add SQL grammar rule for drop_column|
|10|C:/tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20211207010154_add_destination_calendar\migration.sql:20|During normal index creation, table updates are blocked, but reads are still allowed.|require-concurrent-index-creation|Add SQL grammar rule for create_index_nonconcurrent|
|11|C:/tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20220217093836_add_webhook_for_event\migration.sql:3|Dropping a `NOT NULL` constraint may break existing clients.|ban-drop-not-null|Add SQL grammar rule for drop_not_null|
|12|C:/tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20220622110735_allow_one_schedule_to_apply_to_multiple_event_types\migration.sql:6|A normal `DROP INDEX` acquires an `ACCESS EXCLUSIVE` lock on the table, blocking other accesses until the index drop can complete.|require-concurrent-index-deletion|Add SQL grammar rule for drop_index_nonconcurrent|
|13|C:/tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20221107201132_add_team_subscription_cols\migration.sql:4|Dropping a `NOT NULL` constraint may break existing clients.|ban-drop-not-null|Add SQL grammar rule for drop_not_null|
|14|C:/tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20230105212846_add_availability_schedule_indexes\migration.sql:8|During normal index creation, table updates are blocked, but reads are still allowed.|require-concurrent-index-creation|Add SQL grammar rule for create_index_nonconcurrent|
|15|C:/tmp\hubbleops-detection-corpus\repos\calcom\packages\prisma\migrations\20230216171757_host_user_id_event_type_id\migration.sql:11|Adding a primary key constraint requires an `ACCESS EXCLUSIVE` lock that will block all reads and writes to the table while the primary key index is built.|adding-serial-primary-key-field|Add SQL grammar rule for serial_primary_key|
|16|research\detection-quality\2026-07-01\adversarial\sql\fn_01_cte_delete.sql:1|crafted known unsafe/locking migration class produced zero HubbleOps findings|Squawk/manual semantics|Replace prefix heuristic with grammar-aware classifier and add this corpus case|

### Terraform False Negatives

|#|input + resource|why dangerous|competitor|fix|
|---|---|---|---|---|
|1|C:\tmp\hubbleops-detection-corpus\repos\checkov\tests\common\runner_registry\plan_with_external_tf_modules_for_enrichment\tfplan.json :: module.log_group_external.aws_cloudwatch_log_group.this[0]|Ensure that CloudWatch Log Group is encrypted by KMS|CKV_AWS_158|Inspect plan before/after for this security class or delegate to Checkov-style policy engine|
|2|C:\tmp\hubbleops-detection-corpus\repos\checkov\tests\common\runner_registry\plan_with_for_each_for_enrichment\tf_plan.json :: module.sg["awful_example"].aws_security_group.bad|Ensure no security groups allow ingress from 0.0.0.0:0 to port 22|CKV_AWS_24|Inspect plan before/after for this security class or delegate to Checkov-style policy engine|
|3|C:\tmp\hubbleops-detection-corpus\repos\checkov\tests\common\runner_registry\plan_with_for_each_for_enrichment\tf_plan.json :: module.sg["awful_example"].aws_security_group.bad|Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389|CKV_AWS_25|Inspect plan before/after for this security class or delegate to Checkov-style policy engine|
|4|C:\tmp\hubbleops-detection-corpus\repos\checkov\tests\common\runner_registry\plan_with_for_each_for_enrichment\tf_plan.json :: module.sg["awful_example"].aws_security_group.bad|Ensure no security groups allow ingress from 0.0.0.0:0 to port 80|CKV_AWS_260|Inspect plan before/after for this security class or delegate to Checkov-style policy engine|
|5|C:\tmp\hubbleops-detection-corpus\repos\checkov\tests\common\runner_registry\plan_with_for_each_for_enrichment\tf_plan.json :: module.sg["awful_example"].aws_security_group.bad|Ensure no security groups allow ingress from 0.0.0.0:0 to port -1|CKV_AWS_277|Inspect plan before/after for this security class or delegate to Checkov-style policy engine|
|6|C:\tmp\hubbleops-detection-corpus\repos\checkov\tests\common\runner_registry\plan_with_hcl_for_enrichment\tfplan.json :: aws_dynamodb_table.cross-environment-violations|Ensure DynamoDB point in time recovery (backup) is enabled|CKV_AWS_28|Inspect plan before/after for this security class or delegate to Checkov-style policy engine|
|7|C:\tmp\hubbleops-detection-corpus\repos\checkov\tests\common\runner_registry\plan_with_hcl_for_enrichment\tfplan.json :: aws_dynamodb_table.cross-environment-violations|Ensure DynamoDB Tables are encrypted using a KMS Customer Managed CMK|CKV_AWS_119|Inspect plan before/after for this security class or delegate to Checkov-style policy engine|
|8|C:\tmp\hubbleops-detection-corpus\repos\checkov\tests\common\runner_registry\plan_with_hcl_for_enrichment\tfplan.json :: aws_iam_policy.policy|Ensure IAM policies does not allow credentials exposure|CKV_AWS_287|Inspect plan before/after for this security class or delegate to Checkov-style policy engine|
|9|C:\tmp\hubbleops-detection-corpus\repos\checkov\tests\common\runner_registry\plan_with_hcl_for_enrichment\tfplan.json :: aws_iam_policy.policy|Ensure no IAM policies documents allow "*" as a statement's actions|CKV_AWS_63|Inspect plan before/after for this security class or delegate to Checkov-style policy engine|
|10|C:\tmp\hubbleops-detection-corpus\repos\checkov\tests\common\runner_registry\plan_with_tf_modules_for_enrichment\tfplan.json :: module.log_group_local.aws_cloudwatch_log_group.not_encrypted|Ensure CloudWatch log groups retains logs for at least 1 year|CKV_AWS_338|Inspect plan before/after for this security class or delegate to Checkov-style policy engine|
|11|C:\tmp\hubbleops-detection-corpus\repos\checkov\tests\terraform\checks\resource\aws\example_SecretManagerSecretEncrypted\tfplan.json :: aws_secretsmanager_secret.not_specified|Ensure that Secrets Manager secret is encrypted using KMS CMK|CKV_AWS_149|Inspect plan before/after for this security class or delegate to Checkov-style policy engine|
|12|C:\tmp\hubbleops-detection-corpus\repos\checkov\tests\terraform\checks\resource\gcp\example_GoogleComputeBootDiskEncryption\bad.json :: google_compute_instance.bad3|Ensure 'Block Project-wide SSH keys' is enabled for VM instances|CKV_GCP_32|Inspect plan before/after for this security class or delegate to Checkov-style policy engine|
|13|C:\tmp\hubbleops-detection-corpus\repos\checkov\tests\terraform\checks\resource\gcp\example_GoogleComputeBootDiskEncryption\bad.json :: google_compute_instance.bad3|Ensure VM disks for critical VMs are encrypted with Customer Supplied Encryption Keys (CSEK)|CKV_GCP_38|Inspect plan before/after for this security class or delegate to Checkov-style policy engine|
|14|C:\tmp\hubbleops-detection-corpus\repos\checkov\tests\terraform\checks\resource\gcp\example_GoogleComputeBootDiskEncryption\bad.json :: google_compute_instance.bad3|Ensure that no instance in the project overrides the project setting for enabling OSLogin(OSLogin needs to be enabled in project metadata for all instances)|CKV_GCP_34|Inspect plan before/after for this security class or delegate to Checkov-style policy engine|
|15|C:\tmp\hubbleops-detection-corpus\repos\checkov\tests\terraform\checks\resource\gcp\example_GoogleComputeDefaultServiceAccountFullAccess\bad.json :: google_compute_instance.bad3|Ensure that instances are not configured to use the default service account|CKV_GCP_30|Inspect plan before/after for this security class or delegate to Checkov-style policy engine|

## E. Coverage Gap Table

|class|caught/missed|code reason|
|---|---|---|
|SQL DROP TABLE / TRUNCATE|caught by prefix|ScanContent starts with drop table/truncate only; temp tables still false-block|
|SQL unbounded DELETE/UPDATE|caught only when statement starts DELETE/UPDATE|CTE-prefixed DML and MERGE are missed|
|SQL CREATE INDEX non-concurrent|caught, high FP|no same-migration CREATE TABLE/schema context|
|SQL FK/unique/PK/check constraints NOT VALID|missed|classifyAlterTable ignores ADD CONSTRAINT|
|SQL DROP INDEX / REINDEX / DETACH PARTITION|missed|classifier only handles DROP TABLE/TRUNCATE/DML/CREATE INDEX/ALTER TABLE subset|
|SQL volatile DEFAULT / generated column rewrite|missed|ADD COLUMN with DEFAULT is explicitly treated as safe|
|Terraform stateful/protected destroy|caught for hand-curated prefixes/protected list|resourceDanger prefix list + delete action|
|Terraform SG public ingress|missed|create/update network rule attributes not inspected|
|Terraform IAM wildcard/widening|missed|IAM policy JSON not inspected|
|Terraform encryption/public access/versioning/logging|missed|no Checkov/tfsec-style security-policy checks|
|Terraform count/for_each fan-out|missed as fan-out|detector evaluates each resource independently; no aggregate blast-radius count|
|GitHub PR Terraform content|missed|PR gate path/ticket/CODEOWNERS; no Terraform HCL/plan analysis in PR path|

## F. Corpus Manifest And Reproduction

|corpus|repos/files|artifact|
|---|---|---|
|SQL all UTF-8|1430 files; 70785 statements|raw/sql_valid_utf8_files.txt, raw/hubbleops_sql_valid_utf8.jsonl|
|SQL routine migrations|699 files; 2737 statements|raw/sql_routine_migration_files.txt, raw/hubbleops_sql_routine.jsonl|
|SQL Squawk comparator|1207 Postgres-dialect files; Squawk records 23441|raw/sql_postgres_comparator_files.txt, raw/squawk_sql_postgres.jsonl|
|Terraform plans|52 plan JSON files; 408 resources|raw/terraform_plan_files.txt, raw/hubbleops_terraform.jsonl|
|Checkov terraform_plan|Checkov summary resource_count=350, failed=1474|raw/checkov_terraform_plan_combined.json|
|GitHub PR sample|2 qualifying PRs before public API rate-limit; target was 50+|raw/github_pr_sample.json|
|Adversarial SQL|18 handcrafted SQL files|adversarial/sql, raw/hubbleops_sql_adversarial.jsonl, raw/squawk_sql_adversarial.json|

Excluded from SQL comparator: 1 non-UTF-8 SQL file(s), recorded in `raw/sql_invalid_utf8_files.json`.

Primary clone/fetch roots:

- `C:/tmp/hubbleops-detection-corpus/repos/postgres/src/test/regress/sql`
- `C:/tmp/hubbleops-detection-corpus/repos/squawk`
- `C:/tmp/hubbleops-detection-corpus/repos/migrate/database`
- `C:/tmp/hubbleops-detection-corpus/repos/atlas`
- `C:/tmp/hubbleops-detection-corpus/repos/calcom/packages/prisma/migrations`
- `C:/tmp/hubbleops-detection-corpus/repos/supabase/.../migrations`
- `C:/tmp/hubbleops-detection-corpus/repos/prisma/packages/migrate/src/__tests__`
- `C:/tmp/hubbleops-detection-corpus/repos/checkov/tests`
- `C:/tmp/hubbleops-detection-corpus/repos/conftest/examples`

Commands used:

```powershell
# Restore the temporary scanner used during the study, then run it.
New-Item -ItemType Directory -Force -Path cmd/corpusscan
Copy-Item research/detection-quality/2026-07-01/tools/corpusscan-main.go.txt cmd/corpusscan/main.go

go run ./cmd/corpusscan -mode sql -file-list research/detection-quality/2026-07-01/raw/sql_valid_utf8_files.txt -out research/detection-quality/2026-07-01/raw/hubbleops_sql_valid_utf8.jsonl .
go run ./cmd/corpusscan -mode sql -file-list research/detection-quality/2026-07-01/raw/sql_routine_migration_files.txt -out research/detection-quality/2026-07-01/raw/hubbleops_sql_routine.jsonl .
go run ./cmd/corpusscan -mode sql -file-list research/detection-quality/2026-07-01/raw/sql_postgres_comparator_files.txt -out research/detection-quality/2026-07-01/raw/hubbleops_sql_postgres_comparator.jsonl .
go run ./cmd/corpusscan -mode terraform -out research/detection-quality/2026-07-01/raw/hubbleops_terraform.jsonl C:/tmp/hubbleops-detection-corpus/repos/checkov/tests C:/tmp/hubbleops-detection-corpus/repos/conftest/examples internal/preflight/terraform/testdata

# Remove the temporary scanner from the product command tree after the run.
Remove-Item cmd/corpusscan/main.go

# Squawk comparator
npx -y squawk-cli --reporter json <batched file list from raw/sql_postgres_comparator_files.txt>

# Checkov comparator
C:/tmp/hubbleops-detection-corpus/venv-checkov/Scripts/python.exe -m checkov.main -d C:/tmp/hubbleops-detection-corpus/repos/checkov/tests -d C:/tmp/hubbleops-detection-corpus/repos/conftest/examples --framework terraform_plan -o json --skip-download --quiet
```

## G. Verdict

Not production-trustworthy as a BLOCK gate today.

The three changes with the largest expected metric movement:

1. Add SQL schema/context tracking for same-migration new tables and temp tables. Metric: routine SQL FP. Expected delta from this corpus: removes at least 239 false-positive flags, dropping routine positive FP from 38.7% to materially lower.
2. Replace SQL prefix heuristics with a real PostgreSQL parser or Squawk-backed rule engine for CTE/MERGE/constraints/index operations. Metric: SQL FN. Expected delta: attacks 1218 Squawk-only safety misses plus all 15 handcrafted HubbleOps-zero adversarial SQL misses.
3. For Terraform, either integrate Checkov/tfsec-style policy checks or explicitly scope HubbleOps Terraform to destructive lifecycle only and do not market it as IaC security detection. Metric: Terraform FN. Expected delta if integrated: address up to 1410 Checkov-only failed checks in this plan corpus; if scoped, avoid false trust.

Residual uncertainty:

- Manual SQL labels were applied to the dominant routine FP class using same-file SQL semantics, not a production table-size oracle.
- Squawk is PostgreSQL-specific; MySQL/SQLite/SQL Server files were used for HubbleOps flag-rate stress, not Squawk confusion matrices.
- Checkov failed checks are security-policy ground truth, not always action-destructiveness ground truth. The mismatch itself is the point: HubbleOps Terraform does not cover that taxonomy.
- PR-gate realism did not reach the required 50 PRs because the unauthenticated GitHub API returned 403 rate-limit errors; see `raw/github_pr_sample.json`.
