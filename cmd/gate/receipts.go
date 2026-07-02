package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/hubbleops/hubbleops/internal/wal"
)

type receiptResponse struct {
	DecisionID       string   `json:"decision_id"`
	ReceiptID        string   `json:"receipt_id,omitempty"`
	Project          string   `json:"project,omitempty"`
	SessionID        string   `json:"session_id,omitempty"`
	Action           string   `json:"action,omitempty"`
	Decision         string   `json:"decision,omitempty"`
	RiskScore        int      `json:"risk_score,omitempty"`
	Approvals        []string `json:"approvals,omitempty"`
	RecordHash       string   `json:"record_hash,omitempty"`
	ReceiptSignature string   `json:"receipt_signature,omitempty"`
	ReceiptKeyID     string   `json:"receipt_key_id,omitempty"`
}

func (s *server) handleGetReceipt(w http.ResponseWriter, r *http.Request) {
	rec, err := findReceiptByDecisionID(s.receiptOpts.WALDir, chi.URLParam(r, "decision_id"))
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "receipt not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, receiptResponse{
		DecisionID:       rec.DecisionID,
		ReceiptID:        rec.DecisionID,
		Project:          rec.Project,
		SessionID:        rec.SessionID,
		Action:           rec.Action,
		Decision:         rec.Decision,
		RiskScore:        rec.RiskScore,
		Approvals:        rec.Approvals,
		RecordHash:       rec.RecordHash,
		ReceiptSignature: rec.ReceiptSignature,
		ReceiptKeyID:     rec.ReceiptKeyID,
	})
}

func findReceiptByDecisionID(walDir, decisionID string) (wal.Record, error) {
	decisionID = strings.TrimSpace(decisionID)
	if decisionID == "" {
		return wal.Record{}, os.ErrNotExist
	}
	files, err := filepath.Glob(filepath.Join(walDir, "wal-*.jsonl"))
	if err != nil {
		return wal.Record{}, err
	}
	sort.Strings(files)
	for i, j := 0, len(files)-1; i < j; i, j = i+1, j-1 {
		files[i], files[j] = files[j], files[i]
	}
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			return wal.Record{}, err
		}
		rec, found, readErr := scanReceiptFile(f, decisionID)
		closeErr := f.Close()
		if readErr != nil {
			return wal.Record{}, readErr
		}
		if closeErr != nil {
			return wal.Record{}, closeErr
		}
		if found {
			return rec, nil
		}
	}
	return wal.Record{}, os.ErrNotExist
}

func scanReceiptFile(r io.Reader, decisionID string) (wal.Record, bool, error) {
	dec := json.NewDecoder(r)
	var last wal.Record
	found := false
	for {
		var rec wal.Record
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				return last, found, nil
			}
			return wal.Record{}, false, err
		}
		if rec.DecisionID == decisionID {
			last = rec
			found = true
		}
	}
}
