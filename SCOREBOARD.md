# Synthetic Corpus Scoreboard — the "wow on install" acceptance gate

## What this is
A generator (`synthgen.py`) + starter corpus (3,000 sessions / 70,517 events / 32 families) + a demo pack of 8 replayed famous incidents. Built to your exact `testdata/loop_corpus` JSONL convention and `toolEventRequest` schema — it feeds your REAL pipeline, not a reimplementation.

- **21 positive families** (must flag) — each mapped to a documented public incident from your evidence table (`source_incident` field: A4, A5, A6, A7, A10, A11, A12, A17/A18, A20, A1-A3, A27, B14, B16, B21) plus adversarial variants (chaff interleaving, paraphrased args, fake-progress jitter, pending suppression, slow loops, multi-tool cycles, fan-out).
- **11 negative families** (must NOT flag) — the false-positive traps: exponential-backoff retries, opaque polling, pagination, batches, cron repeats with long gaps, sub-threshold repeated reads, concurrent agents, streaming retries, well-keyed writes.
- **Demo pack** — 8 deterministic replays with dollar arcs matching the published numbers ($34,895 Cloudflare, $260 OpenAI overnight, $13.55 Aider, the Replit prod delete, LangGraph #7417 re-dispatch, the duplicate refund). Embedded in `internal/demopack/data/`; this is the `witness demo` content.

## How to run it (against the real detector — never a port)

```bash
# Full 3,000-session scoreboard (hard gate; also runs in CI):
go test ./internal/synthcorpus/ -run TestSyntheticCorpusScoreboard -v

# Famous eight only:
go test ./internal/demopack/ -run TestFamousEightDetected -v

# The 2-minute wow (embedded demo pack, no setup):
go run ./cmd/witness demo

# Regenerate the corpus (deterministic):
python synthgen.py --out starter_corpus_3000 --sessions 3000 --seed 7
```

Scoring rule (non-negotiable): a session's verdict is the MAX action across its
event stream (allow < warn < block) vs `expected_action`. Final-turn-only scoring
is the bug that was fixed once — it stays fixed (`internal/loopeval` now uses the
same rule). Misses are written to `out/scoreboard_misses.jsonl`. The demo pack
lives embedded in `internal/demopack/data/`.

## The world-class bar (measurable, no vibes)
1. **Famous eight: 8/8.** Every demo-pack incident detected with the right signal. If your detector misses one of these on stage, nothing else matters.
2. **Positives ≥ 95% per family** — not aggregate. An aggregate hides a dead family. Misses come back to me as JSONL; we fix the detector, not the test.
3. **Negatives: 0 blocks, ≤ 1% warns per family** at default shadow→warn thresholds. `legit_backoff_retry` and `polling_opaque_then_done` are the two that kill customer trust — they must be perfect.
4. **Install → wow ≤ 2 minutes:** `witness demo` bundles the demo pack, replays it through the real pipeline in-memory, prints the shadow report with incident names, signals, and dollar figures. The customer sees "$34,895 runaway blocked at event 14" before they've wired a single line of their own traffic.
5. **Quickstart ≤ 10 minutes** on a clean machine to first receipt from their own agent.

## Scaling to the million
`python3 synthgen.py --out out --sessions 1000000 --seed N` ≈ 10 GB; run 10× 100k with seeds 1–10 in parallel. Diversity comes from the 32 families × randomized parameters, not raw count — 100k is already past the point of diminishing returns for threshold tuning. Tune thresholds on seeds 1–5, **score on seeds 6–10 only** (never grade on the data you tuned on — that's the 100%-on-homework trap).

## What this proves and what it doesn't (the one honest paragraph)
Passing this gate proves **coverage** (you catch every documented failure pattern plus adversarial mutations) and **discipline** (you stay silent on every legitimate pattern we could model). That is a genuinely strong, demoable claim no competitor in your cohort publishes. What it cannot prove is the false-positive rate on traffic shaped like things neither of us imagined — that number still arrives only from pilot shadow data, and the scoreboard you publish must say "synthetic corpus" on it, because the first sophisticated buyer who catches an unlabeled benchmark will assume everything else is inflated too.
