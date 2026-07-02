package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/hubbleops/hubbleops/internal/config"
	"github.com/hubbleops/hubbleops/internal/wal"
)

const (
	offsetFile   = "wal-offset.json"
	batchSize    = 100
	pollInterval = 5 * time.Second
)

var (
	drainLagSeconds = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "llmproxy_wal_drain_lag_seconds",
			Help: "Time difference between now and the latest committed WAL record timestamp.",
		},
	)
	chainViolations = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "llmproxy_wal_chain_violation_total",
			Help: "Total number of hash chain violations detected.",
		},
	)
	recordsDrained = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "llmproxy_wal_records_drained_total",
			Help: "Total number of WAL records drained to Postgres.",
		},
	)
	batchesDrained = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "llmproxy_wal_batches_drained_total",
			Help: "Total number of batches drained to Postgres.",
		},
	)
	chainRestarts = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "llmproxy_wal_chain_restart_total",
			Help: "Total number of chain restart markers encountered (crash recovery boundaries).",
		},
	)
)

func init() {
	prometheus.MustRegister(drainLagSeconds)
	prometheus.MustRegister(chainViolations)
	prometheus.MustRegister(recordsDrained)
	prometheus.MustRegister(batchesDrained)
	prometheus.MustRegister(chainRestarts)
}

type drainOffset struct {
	File       string `json:"file"`
	ByteOffset int64  `json:"byte_offset"`
	LastHash   string `json:"last_hash"`
	LastSeq    uint64 `json:"last_seq"`
}

func main() {
	// Logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	log.Logger = zerolog.New(os.Stdout).With().Timestamp().Caller().Logger()

	// Config
	cfgPath := os.Getenv("HUBBLEOPS_CONFIG")
	if cfgPath == "" {
		cfgPath = "configs/hubbleops.yaml"
	}
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		cfgPath = ""
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}

	walDir := os.Getenv("HUBBLEOPS_WAL_DIR")
	if walDir == "" {
		walDir = "data/wal"
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Postgres
	log.Info().Str("dsn", cfg.Postgres.RedactedDSN()).Msg("connecting to postgres")
	pgPool, err := pgxpool.New(ctx, cfg.Postgres.DSN())
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to postgres")
	}
	defer pgPool.Close()

	if err := pgPool.Ping(ctx); err != nil {
		log.Fatal().Err(err).Msg("failed to ping postgres")
	}
	log.Info().Msg("postgres connected")

	// Start metrics server
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		addr := ":9090"
		log.Info().Str("addr", addr).Msg("metrics server starting")
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Error().Err(err).Msg("metrics server error")
		}
	}()

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start drain loop
	drainer := &Drainer{
		walDir: walDir,
		pool:   pgPool,
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := drainer.Run(ctx); err != nil {
			log.Fatal().Err(err).Msg("drain loop failed")
		}
	}()

	sig := <-sigCh
	log.Info().Str("signal", sig.String()).Msg("shutting down")
	cancel()
	wg.Wait() // Run finishes its current batch, then returns on the cancelled context
	log.Info().Msg("waldrain stopped")
}

type Drainer struct {
	walDir string
	pool   *pgxpool.Pool
	// insert overrides the Postgres batch insert; tests inject a fake here so the
	// real drain/offset/chain logic is what gets exercised.
	insert func(ctx context.Context, batch []wal.Record) error
}

func (d *Drainer) insertFn() func(ctx context.Context, batch []wal.Record) error {
	if d.insert != nil {
		return d.insert
	}
	return d.insertBatch
}

func (d *Drainer) Run(ctx context.Context) error {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := d.drainOnce(ctx); err != nil {
				log.Error().Err(err).Msg("drain iteration failed")
				// Don't fatal - keep trying
			}
		}
	}
}

func (d *Drainer) drainOnce(ctx context.Context) error {
	// Load offset
	offset, err := d.loadOffset()
	if err != nil {
		return fmt.Errorf("load offset: %w", err)
	}

	// Find all WAL files
	files, err := filepath.Glob(filepath.Join(d.walDir, "wal-*.jsonl"))
	if err != nil {
		return fmt.Errorf("glob wal files: %w", err)
	}

	if len(files) == 0 {
		return nil
	}

	// Sort files to process in order
	// Files are named wal-YYYY-MM-DD.jsonl, so lexicographic sort works
	// Go's filepath.Glob already returns sorted results

	for _, file := range files {
		baseName := filepath.Base(file)

		// Skip files before our current offset file
		if offset.File != "" && baseName < offset.File {
			continue
		}

		// Determine start byte position within this file
		var startByte int64
		if baseName == offset.File {
			startByte = offset.ByteOffset
		}

		// Drain the current file to EOF before moving to the next.
		// Each iteration processes one batch (up to batchSize records).
		// Without this loop, drain throughput is capped at batchSize/tick
		// which falls behind at sustained load > batchSize/pollInterval.
		for {
			// Check for shutdown between batches
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			bytesConsumed, lastHash, lastSeq, err := d.drainFile(ctx, file, startByte, offset.LastHash, offset.LastSeq)
			if err != nil {
				return fmt.Errorf("drain file %s: %w", baseName, err)
			}

			if bytesConsumed == 0 {
				// File fully drained — break to next file
				break
			}

			// Update offset: reset byte counter when switching to a new file
			if baseName != offset.File {
				offset.File = baseName
				offset.ByteOffset = startByte + bytesConsumed
			} else {
				offset.ByteOffset += bytesConsumed
			}
			offset.LastHash = lastHash
			offset.LastSeq = lastSeq
			startByte = offset.ByteOffset

			if err := d.saveOffset(offset); err != nil {
				return fmt.Errorf("save offset: %w", err)
			}

			log.Info().
				Str("file", baseName).
				Int64("byte_offset", offset.ByteOffset).
				Str("last_hash", shortHash(lastHash)).
				Uint64("last_seq", lastSeq).
				Msg("batch drained")
		}
	}

	return nil
}

func (d *Drainer) drainFile(ctx context.Context, path string, startByte int64, prevHash string, prevSeq uint64) (int64, string, uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, "", 0, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	// O(1) seek to the byte offset instead of scanning/skipping lines
	if startByte > 0 {
		if _, err := file.Seek(startByte, io.SeekStart); err != nil {
			return 0, "", 0, fmt.Errorf("seek to offset %d: %w", startByte, err)
		}
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)

	// Read batch — track bytes consumed for the caller's offset.
	//
	// An unparseable line is NOT consumed immediately: if it is the last line in
	// the file it is a torn tail — a partial record from a crash or an in-flight
	// write — and consuming its bytes would make the offset skip into whatever
	// completes it later, permanently desyncing the chain. Its bytes stay
	// "pending" until a following line proves it was newline-terminated (then it
	// is genuine mid-file corruption: consume, count, log) or the scan ends
	// (leave it for the next drain tick to re-examine).
	var batch []wal.Record
	var bytesConsumed int64
	var pendingBytes int64  // trailing unparseable line, not yet confirmed corrupt
	var pendingOffset int64 // absolute byte offset of that line
	for scanner.Scan() && len(batch) < batchSize {
		line := scanner.Text()
		lineBytes := int64(len(line)) + 1 // +1 for the newline character
		if pendingBytes > 0 {
			// A line followed the pending one, so the pending line was a complete,
			// newline-terminated non-record: mid-file corruption, not a torn tail.
			chainViolations.Inc()
			log.Error().
				Str("file", filepath.Base(path)).
				Int64("byte_offset", pendingOffset).
				Msg("CHAIN VIOLATION: skipping corrupt WAL line")
			bytesConsumed += pendingBytes
			pendingBytes = 0
		}
		if strings.TrimSpace(line) == "" {
			bytesConsumed += lineBytes
			continue
		}

		var rec wal.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			pendingBytes = lineBytes
			pendingOffset = startByte + bytesConsumed
			continue
		}

		bytesConsumed += lineBytes
		batch = append(batch, rec)
	}

	if err := scanner.Err(); err != nil {
		return 0, "", 0, fmt.Errorf("scanner error: %w", err)
	}

	if pendingBytes > 0 {
		log.Warn().
			Str("file", filepath.Base(path)).
			Int64("byte_offset", pendingOffset).
			Msg("torn or in-flight WAL tail line; leaving unconsumed for the next drain")
	}

	// The scanner counts +1 for a newline the final token may not have (a write
	// torn between the record body and its '\n'). Clamp so the offset can never
	// point past the bytes that exist; the missing newline is re-read next tick.
	if stat, statErr := file.Stat(); statErr == nil {
		if max := stat.Size() - startByte; bytesConsumed > max {
			bytesConsumed = max
		}
	}

	if len(batch) == 0 {
		return 0, prevHash, prevSeq, nil
	}

	// Verify hash chain, sequence continuity, and per-record hashes in one pass.
	// A record with ChainRestart=true whose link or seq does not continue the
	// previous segment announces a legitimate new chain segment (the writer
	// re-anchored after a crash, and the records bridging to it may have been
	// lost to corruption) — accept it and resynchronize instead of wedging.
	// Its own record hash is still verified like any other record.
	expectedPrev := prevHash
	if expectedPrev == "" {
		expectedPrev = "genesis"
	}
	expectedSeq := prevSeq + 1
	for i, rec := range batch {
		if rec.Seq == 0 {
			chainViolations.Inc()
			log.Error().
				Int("index", i).
				Int64("byte_offset", startByte).
				Str("decision_id", rec.DecisionID).
				Msg("CHAIN VIOLATION: missing seq")
			return 0, "", 0, fmt.Errorf("chain violation: missing seq at index %d decision_id=%s", i, rec.DecisionID)
		}
		if rec.PrevHash != expectedPrev || rec.Seq != expectedSeq {
			if !rec.ChainRestart {
				chainViolations.Inc()
				log.Error().
					Int("index", i).
					Str("expected_prev", expectedPrev).
					Str("got_prev", rec.PrevHash).
					Uint64("expected_seq", expectedSeq).
					Uint64("got_seq", rec.Seq).
					Str("decision_id", rec.DecisionID).
					Int64("byte_offset", startByte).
					Msg("CHAIN VIOLATION: broken link or seq gap")
				return 0, "", 0, fmt.Errorf("chain violation: expected prev_hash %s seq %d, got prev_hash %s seq %d at index %d",
					expectedPrev, expectedSeq, rec.PrevHash, rec.Seq, i)
			}
			log.Warn().
				Int("index", i).
				Uint64("seq", rec.Seq).
				Msg("accepting chain restart marker as new segment after gap")
			expectedSeq = rec.Seq
		}
		computed := wal.RecomputeHash(rec)
		if computed != rec.RecordHash {
			chainViolations.Inc()
			log.Error().
				Int("index", i).
				Int64("byte_offset", startByte).
				Str("stored", rec.RecordHash).
				Str("computed", computed).
				Msg("CHAIN VIOLATION: record hash mismatch")
			return 0, "", 0, fmt.Errorf("chain violation: record hash mismatch at index %d", i)
		}
		expectedPrev = rec.RecordHash
		expectedSeq++
	}

	// Log chain restart markers for audit trail
	for i, rec := range batch {
		if rec.ChainRestart {
			chainRestarts.Inc()
			log.Warn().
				Int("index", i).
				Str("prev_hash", shortHash(rec.PrevHash)).
				Str("record_hash", shortHash(rec.RecordHash)).
				Msg("chain restart marker: crash recovery boundary")
		}
	}

	// Insert batch into Postgres
	if err := d.insertFn()(ctx, batch); err != nil {
		return 0, "", 0, fmt.Errorf("insert batch: %w", err)
	}

	// Update metrics
	recordsDrained.Add(float64(len(batch)))
	batchesDrained.Inc()

	// Update lag metric (based on last record in batch)
	lastRec := batch[len(batch)-1]
	lag := time.Since(lastRec.Time).Seconds()
	drainLagSeconds.Set(lag)

	// Return bytes consumed for the caller's byte offset.
	return bytesConsumed, lastRec.RecordHash, lastRec.Seq, nil
}

func (d *Drainer) insertBatch(ctx context.Context, batch []wal.Record) error {
	// Single transaction for atomicity
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Insert into wal_records
	for _, rec := range batch {
		ct, err := tx.Exec(ctx, `
			INSERT INTO wal_records (
				ulid, time, project, provider, model, prompt_hash,
				input_tokens, output_tokens, total_tokens,
				cost, latency_ms, status_code, cache_hit, stream,
				session_id, tool_signature, args_fingerprint,
				step_id, result_class, state_delta_hash, decision_stage,
				loop_signals_fired, loop_confidence, loop_action,
				loop_evidence, decision_id, agent_id, user_id,
				action_risk, idempotency_key, policy_version,
				resource_id, amount_cents, max_amount_cents, backup_id,
				recipient_domain, allowed_domain, capability_hash,
				decision_reason, decision_evidence, receipt_signature, receipt_key_id,
				actor, human_delegator, action, target, environment,
				intent_hash, evidence_hashes, blast_radius, risk_score, decision,
				required_approvers, approvals,
				prev_hash, record_hash,
				trajectory_id, detector_version, framework, near_miss, immediate_outcome
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43, $44, $45, $46, $47, $48, $49::jsonb, $50, $51, $52, $53::jsonb, $54::jsonb, $55, $56, $57, $58, $59, $60, $61)
			ON CONFLICT (record_hash) DO NOTHING
		`,
			rec.ID, rec.Time, rec.Project, rec.Provider, rec.Model, rec.PromptHash,
			rec.InputTokens, rec.OutputTokens, rec.TotalTokens,
			rec.Cost, rec.LatencyMs, rec.StatusCode, rec.CacheHit, rec.Stream,
			rec.SessionID, rec.ToolSignature, rec.ArgsFingerprint,
			rec.StepID, rec.ResultClass, rec.StateDeltaHash, rec.DecisionStage,
			rec.LoopSignalsFired, rec.LoopConfidence, rec.LoopAction,
			rec.LoopEvidence, rec.DecisionID, rec.AgentID, rec.UserID,
			rec.ActionRisk, rec.IdempotencyKey, rec.PolicyVersion,
			rec.ResourceID, rec.AmountCents, rec.MaxAmountCents, rec.BackupID,
			rec.RecipientDomain, rec.AllowedDomain, rec.CapabilityHash,
			rec.DecisionReason, rec.DecisionEvidence, rec.ReceiptSignature, rec.ReceiptKeyID,
			rec.Actor, rec.HumanDelegator, rec.Action, rec.Target, rec.Environment,
			rec.IntentHash, jsonStringSlice(rec.EvidenceHashes), rec.BlastRadius, rec.RiskScore, rec.Decision,
			jsonStringSlice(rec.RequiredApprovers), jsonStringSlice(rec.Approvals),
			rec.PrevHash, rec.RecordHash,
			rec.TrajectoryID, rec.DetectorVersion,
			frameworkOrUnknown(rec.Framework), rec.NearMiss, outcomeOrUnknown(rec.ImmediateOutcome),
		)
		if err != nil {
			return fmt.Errorf("insert wal_record: %w", err)
		}

		// Skip prompts upsert if this was a duplicate wal_record (DO NOTHING fired).
		// Without this guard, replayed records inflate total_calls and total_cost.
		if ct.RowsAffected() == 0 {
			continue
		}

		// Upsert into prompts table for aggregation
		// Only if we have a project (not "unknown") and this was a successful request
		if rec.Project != "unknown" && rec.StatusCode >= 200 && rec.StatusCode < 300 {
			// First, try to find or create the project
			var projectID *int64
			err := tx.QueryRow(ctx, `
				INSERT INTO projects (name, slug, timezone)
				VALUES ($1, $1, 'UTC')
				ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
				RETURNING id
			`, rec.Project).Scan(&projectID)

			if err != nil && err != pgx.ErrNoRows {
				// Log but don't fail the batch
				log.Warn().Err(err).Str("project", rec.Project).Msg("failed to upsert project")
			}

			if projectID != nil {
				// Upsert into prompts table
				_, err = tx.Exec(ctx, `
					INSERT INTO prompts (project_id, prompt_hash, sample_prefix, total_calls, total_cost, first_seen, last_seen)
					VALUES ($1, $2, '', 1, $3, $4, $4)
					ON CONFLICT (project_id, prompt_hash) DO UPDATE
					SET total_calls = prompts.total_calls + 1,
					    total_cost = prompts.total_cost + $3,
					    last_seen = $4
				`, projectID, rec.PromptHash, rec.Cost, rec.Time)

				if err != nil {
					// Log but don't fail the batch
					log.Warn().Err(err).Str("project", rec.Project).Msg("failed to upsert prompt")
				}
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

func (d *Drainer) loadOffset() (drainOffset, error) {
	path := filepath.Join(d.walDir, offsetFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// First run - start from the beginning
		return drainOffset{}, nil
	}
	if err != nil {
		return drainOffset{}, fmt.Errorf("read offset file: %w", err)
	}

	var offset drainOffset
	if err := json.Unmarshal(data, &offset); err != nil {
		return drainOffset{}, fmt.Errorf("parse offset file: %w", err)
	}

	return offset, nil
}

func (d *Drainer) saveOffset(offset drainOffset) error {
	data, err := json.Marshal(offset)
	if err != nil {
		return fmt.Errorf("marshal offset: %w", err)
	}

	// Write to temp file, then atomic rename
	tmpPath := filepath.Join(d.walDir, offsetFile+".tmp")
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("write temp offset: %w", err)
	}

	finalPath := filepath.Join(d.walDir, offsetFile)
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("rename offset: %w", err)
	}

	return nil
}

// shortHash abbreviates a hash for log lines. Short values (e.g. "genesis" or
// an empty hash) are returned as-is instead of panicking on a fixed slice.
func shortHash(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "..."
}

// frameworkOrUnknown preserves the 'unknown' column default when the WAL record
// has no detected framework, instead of writing an empty string.
func frameworkOrUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// outcomeOrUnknown preserves the 'unknown' column default when the WAL record
// has no recorded immediate outcome.
func outcomeOrUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func jsonStringSlice(values []string) []byte {
	if values == nil {
		values = []string{}
	}
	data, err := json.Marshal(values)
	if err != nil {
		return []byte("[]")
	}
	return data
}
