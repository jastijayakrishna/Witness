package wal

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Checkpoint struct {
	Seq       uint64    `json:"seq"`
	HeadHash  string    `json:"head_hash"`
	Count     uint64    `json:"count"`
	SignedAt  time.Time `json:"signed_at"`
	Signature string    `json:"signature,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
}

type CheckpointSigner func(Checkpoint) (Checkpoint, error)

type Anchor interface {
	Publish(ctx context.Context, checkpoint Checkpoint) error
	Latest(ctx context.Context) (Checkpoint, error)
}

type FileAnchor struct {
	Path string
}

func NewFileAnchor(path string) *FileAnchor {
	return &FileAnchor{Path: strings.TrimSpace(path)}
}

func (a *FileAnchor) Publish(ctx context.Context, checkpoint Checkpoint) error {
	if a == nil || strings.TrimSpace(a.Path) == "" {
		return fmt.Errorf("anchor path is required")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if dir := filepath.Dir(a.Path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create anchor dir: %w", err)
		}
	}
	f, err := os.OpenFile(a.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open anchor: %w", err)
	}
	defer f.Close()
	if checkpoint.SignedAt.IsZero() {
		checkpoint.SignedAt = time.Now().UTC()
	}
	data, err := json.Marshal(checkpoint)
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write checkpoint: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync checkpoint: %w", err)
	}
	return nil
}

func (a *FileAnchor) Latest(ctx context.Context) (Checkpoint, error) {
	if a == nil || strings.TrimSpace(a.Path) == "" {
		return Checkpoint{}, fmt.Errorf("anchor path is required")
	}
	select {
	case <-ctx.Done():
		return Checkpoint{}, ctx.Err()
	default:
	}
	f, err := os.Open(a.Path)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("open anchor: %w", err)
	}
	defer f.Close()
	return latestCheckpointFromReader(f)
}

type StdoutAnchor struct {
	Writer io.Writer
}

func (a StdoutAnchor) Publish(ctx context.Context, checkpoint Checkpoint) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	w := a.Writer
	if w == nil {
		w = os.Stdout
	}
	if checkpoint.SignedAt.IsZero() {
		checkpoint.SignedAt = time.Now().UTC()
	}
	data, err := json.Marshal(checkpoint)
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

func (a StdoutAnchor) Latest(context.Context) (Checkpoint, error) {
	return Checkpoint{}, fmt.Errorf("stdout anchor is publish-only")
}

func latestCheckpointFromReader(r io.Reader) (Checkpoint, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var latest Checkpoint
	found := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var cp Checkpoint
		if err := json.Unmarshal([]byte(line), &cp); err != nil {
			return Checkpoint{}, fmt.Errorf("parse checkpoint: %w", err)
		}
		latest = cp
		found = true
	}
	if err := scanner.Err(); err != nil {
		return Checkpoint{}, err
	}
	if !found {
		return Checkpoint{}, fmt.Errorf("anchor has no checkpoints")
	}
	return latest, nil
}
