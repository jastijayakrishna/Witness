# Plan: Fix Phase 0-2 Gaps vs Build Plan v5

## 6 Gaps to Fix

### Gap 1: No `X-Session-ID` header handling
**Plan says:** "resolve SessionID from X-Session-ID (load-bearing for the safety floor)"
- Add `ResolveSession(r *http.Request) string` to `internal/proxy/attribution.go`
- Returns `X-Session-ID` header value or empty string
- Pass through handler → WAL record

### Gap 2: WAL Record missing v5 loop fields
**Plan says:** Record carries "loop_signals_fired, loop_confidence, loop_action"
- Replace `LoopSignal bool` in Record struct with:
  - `SessionID string` (json:"session_id,omitempty")
  - `LoopSignalsFired string` (json:"loop_signals_fired,omitempty") — empty until Phase 3
  - `LoopConfidence float64` (json:"loop_confidence,omitempty") — 0 until Phase 3
  - `LoopAction string` (json:"loop_action,omitempty") — empty until Phase 3
  - `ToolSignature string` (json:"tool_signature,omitempty") — Phase 2
  - `ArgsFingerprint string` (json:"args_fingerprint,omitempty") — Phase 2

### Gap 3: No `internal/loop/` with Observation struct
**Plan says:** "the Observation struct the detector consumes is populated on every request from day one"
- Create `internal/loop/observation.go` with:
  - `Observation` struct: ToolName, Args, Result string; PromptTokens, OutputTokens int; CostUSD float64; UnixMillis int64
  - `ToolCall` struct: Name, Arguments string (for extraction)
- The handler builds an Observation per request (stored nowhere yet — Phase 3 wires it to detector+Redis)

### Gap 4: No tool call extraction from responses
**Plan says:** "Tool calls: OpenAI choices[].message.tool_calls; Anthropic content[].type=='tool_use'"
- Add `ToolCall` struct to `providers/provider.go`
- Add `ExtractToolCalls func(body []byte) []ToolCall` to Provider struct
- OpenAI: parse `choices[0].message.tool_calls[0].function.{name,arguments}`
- Anthropic: parse `content[].type=="tool_use"` → `{name, input}`
- For streaming: also accumulate tool_call delta events (OpenAI) / tool_use content blocks (Anthropic)
- Compute tool_signature = first tool name; args_fingerprint = SHA256 of normalized canonical args

### Gap 5: No tool-signature/args-fingerprint in WAL
**Plan says (Phase 2 Thu):** "persist the values to WAL for the audit trail and the shadow report"
- After extracting tool calls, hash them:
  - `tool_signature` = first tool call name (or "" if none)
  - `args_fingerprint` = SHA256(normalized(canonical(args)))[:16] — uses sorted-key JSON + value normalization (timestamps, UUIDs, emails stripped via existing attribution.NormalizePrompt)
- Write both to WAL record

### Gap 6: Drain worker uses line offsets, not byte offsets
**Plan says:** "Position by BYTE OFFSET per file, not a global record counter"
- Change `drainOffset.Line int` → `drainOffset.ByteOffset int64`
- Use `file.Seek(offset, io.SeekStart)` instead of scanning/skipping
- Update all drain tests to verify byte offsets
- The current line-based approach works correctly but the v5 plan explicitly requires byte offset for O(1) seek performance on large files

### Schema update
- Update `wal_records` table: replace `loop_signal BOOLEAN` with new columns:
  - `session_id TEXT NOT NULL DEFAULT ''`
  - `loop_signals_fired TEXT NOT NULL DEFAULT ''`
  - `loop_confidence NUMERIC(5,4) NOT NULL DEFAULT 0`
  - `loop_action TEXT NOT NULL DEFAULT ''`
  - `tool_signature TEXT NOT NULL DEFAULT ''`
  - `args_fingerprint TEXT NOT NULL DEFAULT ''`

## File Change List

| File | Action |
|------|--------|
| `internal/loop/observation.go` | CREATE — Observation + ToolCall types |
| `internal/providers/provider.go` | EDIT — add ToolCall struct, ExtractToolCalls to Provider |
| `internal/providers/openai.go` | EDIT — add extractOpenAIToolCalls + stream tool_call accumulation |
| `internal/providers/anthropic.go` | EDIT — add extractAnthropicToolCalls |
| `internal/proxy/attribution.go` | EDIT — add ResolveSession |
| `internal/wal/writer.go` | EDIT — Record struct: new fields, remove LoopSignal |
| `internal/proxy/handler.go` | EDIT — extract tool calls, build Observation, populate new WAL fields |
| `internal/proxy/streaming.go` | EDIT — accumulate tool_call events, populate new WAL fields |
| `internal/storage/schema.sql` | EDIT — wal_records table columns |
| `cmd/waldrain/main.go` | EDIT — byte offset + new INSERT columns |
| `cmd/waldrain/drain_test.go` | EDIT — byte offset in tests |
| Tests across proxy/ | EDIT — update WAL record assertions for new fields |

## Order of execution
1. Create `internal/loop/observation.go`
2. Update `internal/providers/provider.go` (ToolCall struct)
3. Update OpenAI + Anthropic providers (tool call extraction)
4. Update `internal/proxy/attribution.go` (session ID)
5. Update `internal/wal/writer.go` (Record struct)
6. Update `internal/proxy/handler.go` (wire everything)
7. Update `internal/proxy/streaming.go` (wire everything)
8. Update `internal/storage/schema.sql`
9. Update `cmd/waldrain/main.go` (byte offset + new columns)
10. Update `cmd/waldrain/drain_test.go`
11. Fix any broken tests in proxy/
12. `go build ./...` + `go test ./...` — all green
