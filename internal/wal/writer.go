package wal

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hubbleops/hubbleops/internal/filelock"
	"github.com/rs/zerolog/log"
)

// crockfordBase32 is the encoding alphabet for ULID (Crockford's Base32).
const crockfordBase32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newULID generates a ULID (Universally Unique Lexicographically Sortable Identifier).
// 26 characters: 10 chars timestamp (48-bit ms) + 16 chars entropy (80-bit random).
// No external dependency required.
func newULID() string {
	now := uint64(time.Now().UnixMilli())
	entropy := make([]byte, 10)
	_, _ = rand.Read(entropy)

	var buf [26]byte
	// Encode timestamp (48 bits) into first 10 characters
	buf[0] = crockfordBase32[(now>>45)&0x1F]
	buf[1] = crockfordBase32[(now>>40)&0x1F]
	buf[2] = crockfordBase32[(now>>35)&0x1F]
	buf[3] = crockfordBase32[(now>>30)&0x1F]
	buf[4] = crockfordBase32[(now>>25)&0x1F]
	buf[5] = crockfordBase32[(now>>20)&0x1F]
	buf[6] = crockfordBase32[(now>>15)&0x1F]
	buf[7] = crockfordBase32[(now>>10)&0x1F]
	buf[8] = crockfordBase32[(now>>5)&0x1F]
	buf[9] = crockfordBase32[now&0x1F]
	// Encode entropy (80 bits) into last 16 characters
	buf[10] = crockfordBase32[(entropy[0]>>3)&0x1F]
	buf[11] = crockfordBase32[((entropy[0]&0x07)<<2)|((entropy[1]>>6)&0x03)]
	buf[12] = crockfordBase32[(entropy[1]>>1)&0x1F]
	buf[13] = crockfordBase32[((entropy[1]&0x01)<<4)|((entropy[2]>>4)&0x0F)]
	buf[14] = crockfordBase32[((entropy[2]&0x0F)<<1)|((entropy[3]>>7)&0x01)]
	buf[15] = crockfordBase32[(entropy[3]>>2)&0x1F]
	buf[16] = crockfordBase32[((entropy[3]&0x03)<<3)|((entropy[4]>>5)&0x07)]
	buf[17] = crockfordBase32[entropy[4]&0x1F]
	buf[18] = crockfordBase32[(entropy[5]>>3)&0x1F]
	buf[19] = crockfordBase32[((entropy[5]&0x07)<<2)|((entropy[6]>>6)&0x03)]
	buf[20] = crockfordBase32[(entropy[6]>>1)&0x1F]
	buf[21] = crockfordBase32[((entropy[6]&0x01)<<4)|((entropy[7]>>4)&0x0F)]
	buf[22] = crockfordBase32[((entropy[7]&0x0F)<<1)|((entropy[8]>>7)&0x01)]
	buf[23] = crockfordBase32[(entropy[8]>>2)&0x1F]
	buf[24] = crockfordBase32[((entropy[8]&0x03)<<3)|((entropy[9]>>5)&0x07)]
	buf[25] = crockfordBase32[entropy[9]&0x1F]

	return string(buf[:])
}

// Record is a single WAL entry written as one JSONL line.
// Phase 2: Hash chain fields for tamper-evident audit log.
// Phase 1/2: Session ID, tool signature, args fingerprint, and loop detection fields.
type Record struct {
	Seq              uint64    `json:"seq,omitempty"`
	ID               string    `json:"id,omitempty"`
	Time             time.Time `json:"time"`
	Project          string    `json:"project"`
	Provider         string    `json:"provider"`
	Model            string    `json:"model"`
	PromptHash       string    `json:"prompt_hash"`
	InputTokens      int       `json:"input_tokens"`
	OutputTokens     int       `json:"output_tokens"`
	TotalTokens      int       `json:"total_tokens"`
	Cost             float64   `json:"cost"`
	LatencyMs        int64     `json:"latency_ms"`
	StatusCode       int       `json:"status_code"`
	CacheHit         bool      `json:"cache_hit"`
	Stream           bool      `json:"stream"`
	SessionID        string    `json:"session_id,omitempty"`       // Phase 1: X-Session-ID for loop safety floor
	ToolSignature    string    `json:"tool_signature,omitempty"`   // Phase 2: first tool call name
	ArgsFingerprint  string    `json:"args_fingerprint,omitempty"` // Phase 2: SHA256(normalized canonical args)
	StepID           string    `json:"step_id,omitempty"`
	ResultClass      string    `json:"result_class,omitempty"`
	StateDeltaHash   string    `json:"state_delta_hash,omitempty"`
	DecisionStage    string    `json:"decision_stage,omitempty"`
	LoopSignalsFired string    `json:"loop_signals_fired,omitempty"` // Phase 3: comma-separated fired signals
	LoopConfidence   float64   `json:"loop_confidence,omitempty"`    // Phase 3: detector confidence score
	LoopAction       string    `json:"loop_action,omitempty"`        // Phase 3: shadow/warn/block
	LoopEvidence     string    `json:"loop_evidence,omitempty"`
	PrevHash         string    `json:"prev_hash"`               // Phase 2: hash of previous record
	RecordHash       string    `json:"record_hash"`             // Phase 2: hash of this record
	ChainRestart     bool      `json:"chain_restart,omitempty"` // Phase 2: crash recovery marker

	// v5.2 moat hooks — cheap now, impossible to retrofit later.
	// Every record carries these from day 1 so replay, training, and
	// auditing pipelines can always reconstruct who decided what and why.
	TrajectoryID        string `json:"trajectory_id,omitempty"`     // UUID per session — groups a run into one trajectory
	DetectorVersion     string `json:"detector_version,omitempty"`  // loop.DetectorVersion — which algo made this call
	Framework           string `json:"framework,omitempty"`         // detected agent framework (langchain/crewai/unknown)
	NearMiss            bool   `json:"near_miss,omitempty"`         // confidence 0.50–0.69 — valuable training signal
	ImmediateOutcome    string `json:"immediate_outcome,omitempty"` // success/blocked/error — set by handler
	DecisionID          string `json:"decision_id,omitempty"`
	AgentID             string `json:"agent_id,omitempty"`
	UserID              string `json:"user_id,omitempty"`
	ActionRisk          string `json:"action_risk,omitempty"`
	IdempotencyKey      string `json:"idempotency_key,omitempty"` // legacy read path only; new writes use IdempotencyKeyHash
	IdempotencyKeyHash  string `json:"idempotency_key_hash,omitempty"`
	ResourceID          string `json:"resource_id,omitempty"` // legacy read path only; new writes use ResourceFingerprint
	ResourceFingerprint string `json:"resource_fingerprint,omitempty"`
	AmountCents         int64  `json:"amount_cents,omitempty"`
	MaxAmountCents      int64  `json:"max_amount_cents,omitempty"`
	BackupID            string `json:"backup_id,omitempty"`
	RecipientDomain     string `json:"recipient_domain,omitempty"`
	AllowedDomain       string `json:"allowed_domain,omitempty"`
	CapabilityHash      string `json:"capability_hash,omitempty"`
	PolicyVersion       string `json:"policy_version,omitempty"`
	DecisionReason      string `json:"decision_reason,omitempty"`
	DecisionEvidence    string `json:"decision_evidence,omitempty"`
	ReceiptSignature    string `json:"receipt_signature,omitempty"`
	ReceiptKeyID        string `json:"receipt_key_id,omitempty"`

	Actor             string   `json:"actor,omitempty"`
	HumanDelegator    string   `json:"human_delegator,omitempty"`
	Action            string   `json:"action,omitempty"`
	Target            string   `json:"target,omitempty"`
	Environment       string   `json:"environment,omitempty"`
	IntentHash        string   `json:"intent_hash,omitempty"`
	EvidenceHashes    []string `json:"evidence_hashes,omitempty"`
	BlastRadius       string   `json:"blast_radius,omitempty"`
	RiskScore         int      `json:"risk_score,omitempty"`
	Decision          string   `json:"decision,omitempty"`
	RequiredApprovers []string `json:"required_approvers,omitempty"`
	Approvals         []string `json:"approvals,omitempty"`
}

// SyncMode constants for WAL writer fsync behavior.
const (
	// SyncModeBatch defers fsync to batch boundaries (every 50 records) or
	// a background goroutine (every 100ms). Fast, but up to ~100ms of
	// records may be lost on a hard crash (kernel panic, power loss).
	SyncModeBatch = "batch"

	// SyncModeSync calls fsync on every Write() before returning.
	// True per-request durability at the cost of ~0.5ms per write.
	SyncModeSync = "sync"
)

// Writer is an append-only WAL writer with configurable fsync behavior.
//
// In "batch" mode (default): fsync is batched — every 50 records or every
// 100ms via a background goroutine. Write() returns after the bytes hit the
// OS buffer. On a hard crash, up to ~100ms of records may be lost.
//
// In "sync" mode: fsync is called on every Write() before returning.
// True per-request durability, suitable for regulated/paranoid deployments.
//
// Phase 2: Now maintains hash chain for tamper-evident audit log.
type Writer struct {
	dir               string
	lockPath          string
	syncMode          string
	mu                sync.Mutex
	file              *os.File
	fileDate          string
	fileSize          int64
	pending           int
	done              chan struct{}
	closeOnce         sync.Once
	lastHash          string // Phase 2: hash of last written record
	lastSeq           uint64 // Phase 5: sequence of last written record
	chainDirty        bool   // Phase 2: true if chain head needs saving
	needsChainRestart bool   // Phase 2: true if crash gap detected on init
	anchor            Anchor
	checkpointSigner  CheckpointSigner
	checkpointEveryN  uint64
	checkpointEvery   time.Duration
	lastCheckpointAt  time.Time
	checkpointDirty   bool
}

type SignRecordFunc func(Record) (signature string, keyID string, err error)

type WriterOptions struct {
	SyncMode           string
	Anchor             Anchor
	CheckpointSigner   CheckpointSigner
	CheckpointEveryN   uint64
	CheckpointInterval time.Duration
}

// NewWriter creates a WAL writer that writes to the given directory.
//
// syncMode controls fsync behavior:
//   - "batch" (default): fsync every 50 records or every 100ms (background goroutine)
//   - "sync": fsync on every Write() call (per-request durability)
//   - "" or unrecognized: treated as "batch"
//
// Phase 2: Loads the last hash from wal-chain-head.json to continue the chain.
// Detects crash gaps where records on disk exceed the saved chain head.
func NewWriter(dir string, syncMode string) (*Writer, error) {
	return NewWriterWithOptions(dir, WriterOptions{SyncMode: syncMode})
}

func NewWriterWithOptions(dir string, opts WriterOptions) (*Writer, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create wal dir: %w", err)
	}

	lockPath := filepath.Join(dir, "wal-chain.lock")
	unlock, err := filelock.Acquire(lockPath)
	if err != nil {
		return nil, fmt.Errorf("acquire wal lock: %w", err)
	}
	defer unlock()

	// Load the last hash from chain head file
	savedHash, savedSeq, err := loadChainHead(dir)
	if err != nil {
		return nil, fmt.Errorf("load chain head: %w", err)
	}

	// Detect crash gap: saved chain head doesn't match actual last record on disk.
	// This happens when the proxy crashes between fsyncs — records made it to disk
	// but the chain head file is stale. Without recovery, the next record's prev_hash
	// won't match the drainer's last_hash, permanently wedging the drain.
	lastHash := savedHash
	lastSeq := savedSeq
	needsRestart := false
	diskHash, diskSeq, err := LastRecordHeadOnDisk(dir)
	if err != nil {
		return nil, fmt.Errorf("scan disk for chain recovery: %w", err)
	}
	if diskHash != "" && diskHash != savedHash {
		log.Warn().
			Str("saved_head", savedHash).
			Str("disk_last", diskHash).
			Msg("crash gap detected: chain head stale, will write restart marker")
		lastHash = diskHash // Continue chain from actual disk state
		lastSeq = diskSeq
		needsRestart = true
	}

	// Normalize sync mode
	syncMode := opts.SyncMode
	if syncMode != SyncModeSync {
		syncMode = SyncModeBatch
	}
	if opts.CheckpointEveryN == 0 {
		opts.CheckpointEveryN = 50
	}
	if opts.CheckpointInterval == 0 {
		opts.CheckpointInterval = time.Minute
	}

	w := &Writer{
		dir:               dir,
		lockPath:          lockPath,
		syncMode:          syncMode,
		done:              make(chan struct{}),
		lastHash:          lastHash,
		lastSeq:           lastSeq,
		needsChainRestart: needsRestart,
		anchor:            opts.Anchor,
		checkpointSigner:  opts.CheckpointSigner,
		checkpointEveryN:  opts.CheckpointEveryN,
		checkpointEvery:   opts.CheckpointInterval,
		lastCheckpointAt:  time.Now().UTC(),
	}
	go w.syncLoop()

	log.Info().
		Str("last_hash", lastHash).
		Uint64("last_seq", lastSeq).
		Bool("crash_recovery", needsRestart).
		Str("sync_mode", syncMode).
		Msg("WAL chain initialized")
	return w, nil
}

// Write appends a record to the WAL.
//
// In "sync" mode: blocks until the record is written AND fsynced to disk.
// In "batch" mode: blocks until the record is written to the OS buffer;
// fsync is deferred to the batch threshold (50 records) or background loop (100ms).
//
// Phase 2: Computes hash chain before writing.
// If a crash gap was detected on init, emits a chain restart marker first.
func (w *Writer) Write(rec Record) error {
	rec.Time = time.Now().UTC()
	return w.appendRecord(rec, nil)
}

// WriteRecovered appends a record that was previously persisted to the dead-letter
// queue after a failed write. Unlike Write it preserves the record's original
// decision Time (so the durable audit reflects when the decision was made, not when
// the WAL recovered) while still assigning a fresh ID and re-chaining the record at
// its real position in the log.
func (w *Writer) WriteRecovered(rec Record) error {
	if rec.Time.IsZero() {
		rec.Time = time.Now().UTC()
	}
	return w.appendRecord(rec, nil)
}

func (w *Writer) WriteSigned(rec Record, sign SignRecordFunc) error {
	rec.Time = time.Now().UTC()
	return w.appendRecord(rec, sign)
}

func (w *Writer) refreshChainHeadForAppendLocked() error {
	needsScan := w.needsChainRestart || w.file == nil || w.fileDate != time.Now().UTC().Format("2006-01-02")
	if !needsScan {
		info, err := os.Stat(filepath.Join(w.dir, fmt.Sprintf("wal-%s.jsonl", w.fileDate)))
		if err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("stat wal file: %w", err)
			}
			needsScan = true
		} else if info.Size() != w.fileSize {
			needsScan = true
			w.fileSize = info.Size()
		}
	}
	if !needsScan {
		return nil
	}

	savedHash, savedSeq, err := loadChainHead(w.dir)
	if err != nil {
		return fmt.Errorf("load chain head: %w", err)
	}
	headHash := savedHash
	headSeq := savedSeq
	diskHash, diskSeq, err := LastRecordHeadOnDisk(w.dir)
	if err != nil {
		return fmt.Errorf("scan disk for chain head: %w", err)
	}
	if diskHash != "" {
		headHash = diskHash
		headSeq = diskSeq
	}

	if w.needsChainRestart {
		if headSeq > w.lastSeq {
			w.lastHash = headHash
			w.lastSeq = headSeq
			w.needsChainRestart = false
		}
		return nil
	}
	w.lastHash = headHash
	w.lastSeq = headSeq
	if w.file != nil && w.fileDate == time.Now().UTC().Format("2006-01-02") {
		if info, err := w.file.Stat(); err == nil {
			w.fileSize = info.Size()
		}
	}
	return nil
}

func (w *Writer) appendRecord(rec Record, sign SignRecordFunc) error {
	rec.ID = newULID()
	// Drop any stale chain fields carried in from a recovered record; the chain is
	// recomputed below against this writer's current head.
	rec.Seq = 0
	rec.PrevHash = ""
	rec.RecordHash = ""

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.lockPath == "" {
		w.lockPath = filepath.Join(w.dir, "wal-chain.lock")
	}
	unlock, err := filelock.Acquire(w.lockPath)
	if err != nil {
		return fmt.Errorf("acquire wal lock: %w", err)
	}
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	if err := w.refreshChainHeadForAppendLocked(); err != nil {
		return err
	}

	// Emit chain restart marker if crash gap was detected on init.
	// This bridges the gap between the actual last record on disk and
	// the new chain segment, so the drainer sees an unbroken chain.
	if w.needsChainRestart {
		if err := w.writeChainRestartMarkerLocked(); err != nil {
			return fmt.Errorf("write chain restart marker: %w", err)
		}
		w.needsChainRestart = false
	}

	// Phase 2: Apply hash chaining
	nextSeq := w.lastSeq + 1
	if err := Chain(&rec, w.lastHash, nextSeq); err != nil {
		return fmt.Errorf("chain record: %w", err)
	}
	if sign != nil {
		sig, keyID, err := sign(rec)
		if err != nil {
			return fmt.Errorf("sign record: %w", err)
		}
		rec.ReceiptSignature = sig
		rec.ReceiptKeyID = keyID
		if err := Chain(&rec, w.lastHash, nextSeq); err != nil {
			return fmt.Errorf("chain signed record: %w", err)
		}
	}

	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal wal record: %w", err)
	}
	line = append(line, '\n')

	if err := w.ensureFile(); err != nil {
		return err
	}

	if _, err := w.file.Write(line); err != nil {
		return fmt.Errorf("write wal: %w", err)
	}
	w.fileSize += int64(len(line))

	// Update last hash for next record
	w.lastHash = rec.RecordHash
	w.lastSeq = rec.Seq
	w.chainDirty = true
	w.checkpointDirty = true

	w.pending++

	shouldSaveChainHead := false
	shouldPublishCheckpoint := false
	if w.syncMode == SyncModeSync {
		// Sync mode: fsync on every write for per-request durability.
		if err := w.file.Sync(); err != nil {
			return fmt.Errorf("fsync wal: %w", err)
		}
		w.pending = 0
		shouldSaveChainHead = true
		shouldPublishCheckpoint = true
	} else if w.pending >= 50 {
		// Batch mode: fsync every 50 records for throughput.
		// Remaining pending writes are fsynced by the background syncLoop (100ms).
		if err := w.file.Sync(); err != nil {
			return fmt.Errorf("fsync wal: %w", err)
		}
		w.pending = 0
		shouldSaveChainHead = true
		shouldPublishCheckpoint = true
	}

	if shouldSaveChainHead {
		if err := saveChainHead(w.dir, w.lastHash, w.lastSeq); err != nil {
			return fmt.Errorf("save chain head: %w", err)
		}
		w.chainDirty = false
	}
	unlock()
	unlock = nil

	if shouldPublishCheckpoint {
		if err := w.maybePublishCheckpointLocked(false); err != nil {
			log.Warn().Err(err).Msg("failed to publish WAL checkpoint")
		}
	}

	return nil
}

func (w *Writer) saveDiskChainHeadWithLockLocked() error {
	if w.lockPath == "" {
		w.lockPath = filepath.Join(w.dir, "wal-chain.lock")
	}
	unlock, err := filelock.Acquire(w.lockPath)
	if err != nil {
		return fmt.Errorf("acquire wal lock: %w", err)
	}
	defer unlock()

	diskHash, diskSeq, err := LastRecordHeadOnDisk(w.dir)
	if err != nil {
		return fmt.Errorf("scan disk for chain head: %w", err)
	}
	if diskHash == "" {
		diskHash = w.lastHash
		diskSeq = w.lastSeq
	}
	if diskHash == "" || diskSeq == 0 {
		return nil
	}
	if err := saveChainHead(w.dir, diskHash, diskSeq); err != nil {
		return fmt.Errorf("save chain head: %w", err)
	}
	w.lastHash = diskHash
	w.lastSeq = diskSeq
	w.chainDirty = false
	if w.file != nil && w.fileDate == time.Now().UTC().Format("2006-01-02") {
		if info, err := w.file.Stat(); err == nil {
			w.fileSize = info.Size()
		}
	}
	return nil
}

// Close shuts down the sync loop and closes the file. Safe to call multiple times.
func (w *Writer) Close() error {
	var err error
	w.closeOnce.Do(func() {
		close(w.done)
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.file != nil {
			_ = w.file.Sync()
			err = w.file.Close()
		}
		if err == nil && w.chainDirty {
			err = w.saveDiskChainHeadWithLockLocked()
		}
		if err == nil {
			err = w.publishCheckpointLocked(true)
		}
	})
	return err
}

// CheckWritable verifies the WAL directory can still accept durable writes
// without appending a health-check record to the audit chain.
func (w *Writer) CheckWritable() error {
	if w == nil {
		return fmt.Errorf("wal writer unavailable")
	}
	w.mu.Lock()
	dir := w.dir
	w.mu.Unlock()

	if dir == "" {
		return fmt.Errorf("wal dir empty")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create wal dir: %w", err)
	}
	f, err := os.CreateTemp(dir, ".wal-health-*.tmp")
	if err != nil {
		return fmt.Errorf("create wal health file: %w", err)
	}
	name := f.Name()
	defer func() {
		_ = os.Remove(name)
	}()
	if _, err := f.Write([]byte("ok\n")); err != nil {
		_ = f.Close()
		return fmt.Errorf("write wal health file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync wal health file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close wal health file: %w", err)
	}
	return nil
}

// writeChainRestartMarkerLocked writes a chain restart marker to the WAL.
// Must be called while holding w.mu. The marker is a properly chained record
// with ChainRestart=true, so the drainer processes it without chain violations.
// Distinguishes crash recovery from malicious tampering in the audit trail.
func (w *Writer) writeChainRestartMarkerLocked() error {
	marker := Record{
		Time:         time.Now().UTC(),
		Project:      "_chain",
		Provider:     "_system",
		Model:        "_restart",
		ChainRestart: true,
	}
	if err := Chain(&marker, w.lastHash, w.lastSeq+1); err != nil {
		return fmt.Errorf("chain restart marker: %w", err)
	}

	line, err := json.Marshal(marker)
	if err != nil {
		return fmt.Errorf("marshal chain restart marker: %w", err)
	}
	line = append(line, '\n')

	if err := w.ensureFile(); err != nil {
		return err
	}

	if _, err := w.file.Write(line); err != nil {
		return fmt.Errorf("write chain restart marker: %w", err)
	}
	w.fileSize += int64(len(line))

	w.lastHash = marker.RecordHash
	w.lastSeq = marker.Seq
	w.chainDirty = true
	w.checkpointDirty = true
	w.pending++

	log.Warn().
		Str("prev_hash", marker.PrevHash[:16]+"...").
		Str("record_hash", marker.RecordHash[:16]+"...").
		Msg("chain restart marker written (crash recovery)")

	return nil
}

func (w *Writer) ensureFile() error {
	today := time.Now().UTC().Format("2006-01-02")
	if w.file != nil && w.fileDate == today {
		return nil
	}
	// Close old file if date rolled over.
	if w.file != nil {
		_ = w.file.Sync()
		_ = w.file.Close()
		w.pending = 0
	}
	path := filepath.Join(w.dir, fmt.Sprintf("wal-%s.jsonl", today))
	size := int64(0)
	if info, err := os.Stat(path); err == nil {
		size = info.Size()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat wal file: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open wal file: %w", err)
	}
	w.file = f
	w.fileDate = today
	w.fileSize = size
	return nil
}

// syncLoop fsyncs the WAL file every 100ms if there are pending writes.
func (w *Writer) syncLoop() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-w.done:
			return
		case <-ticker.C:
			w.mu.Lock()
			if w.file != nil && w.pending > 0 {
				if err := w.file.Sync(); err != nil {
					log.Error().Err(err).Msg("wal fsync error")
				}
				w.pending = 0

				if w.chainDirty {
					if err := w.saveDiskChainHeadWithLockLocked(); err != nil {
						log.Warn().Err(err).Msg("failed to save chain head in sync loop")
					}
				}
				if err := w.maybePublishCheckpointLocked(false); err != nil {
					log.Warn().Err(err).Msg("failed to publish WAL checkpoint")
				}
			}
			w.mu.Unlock()
		}
	}
}

func (w *Writer) maybePublishCheckpointLocked(force bool) error {
	if w.anchor == nil || !w.checkpointDirty || w.lastSeq == 0 {
		return nil
	}
	if !force {
		if w.checkpointEveryN > 0 && w.lastSeq%w.checkpointEveryN == 0 {
			return w.publishCheckpointLocked(false)
		}
		if w.checkpointEvery > 0 && time.Since(w.lastCheckpointAt) >= w.checkpointEvery {
			return w.publishCheckpointLocked(false)
		}
		return nil
	}
	return w.publishCheckpointLocked(true)
}

func (w *Writer) publishCheckpointLocked(force bool) error {
	if w.anchor == nil || w.lastSeq == 0 {
		return nil
	}
	if !force && !w.checkpointDirty {
		return nil
	}
	cp := Checkpoint{
		Seq:      w.lastSeq,
		HeadHash: w.lastHash,
		Count:    w.lastSeq,
		SignedAt: time.Now().UTC(),
	}
	if w.checkpointSigner != nil {
		var err error
		cp, err = w.checkpointSigner(cp)
		if err != nil {
			return err
		}
	}
	if err := w.anchor.Publish(context.Background(), cp); err != nil {
		return err
	}
	w.checkpointDirty = false
	w.lastCheckpointAt = time.Now().UTC()
	return nil
}
