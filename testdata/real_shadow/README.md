# Real Shadow Trace Corpus

Put anonymized customer shadow traces here when design partners send real agent traffic.

Each JSONL line is one tool event:

```json
{"project":"p","session_id":"s","tool_name":"search","args":{"witness_capture":"fingerprint","sha256":"..."},"result_class":"empty","label":"true_runaway","expected_action":"block"}
```

Required fields:

- `project`
- `session_id`
- `tool_name`
- `label`: `true_runaway`, `legit_batch`, `valid_exploration`, `polling`, or `retry_recovery`
- `expected_action`: `allow`, `warn`, or `block`

Recommended fields:

- `step_id`
- `decision_stage`
- `result_class`
- `state_delta_hash`
- `prompt_tokens`
- `output_tokens`
- `cost_usd`
- `unix_millis`

Generate privacy-safe traces:

```bash
go run ./cmd/witness eval raw-shadow.jsonl -anonymize-out testdata/real_shadow/customer-a.jsonl -salt "$WITNESS_ANON_SALT"
```

Evaluate all real traces:

```bash
go run ./cmd/witness eval -assert testdata/real_shadow/*.jsonl
```

Do not commit raw prompts, raw tool args, raw tool results, emails, tokens, customer names, or API payloads.
