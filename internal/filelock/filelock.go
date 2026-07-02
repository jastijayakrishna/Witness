package filelock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const (
	staleTTL  = 30 * time.Second
	maxWait   = 10 * time.Second
	pollEvery = 3 * time.Millisecond
)

// Acquire implements a portable, dependency-free cross-process lock via atomic
// O_EXCL create. A lock left by a crashed holder is reclaimed after staleTTL, and the
// holder removes its lock file on release.
func Acquire(lockPath string) (func(), error) {
	if dir := filepath.Dir(lockPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
	}
	deadline := time.Now().Add(maxWait)
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			_, _ = f.WriteString(strconv.FormatInt(time.Now().UnixNano(), 10))
			_ = f.Close()
			return func() { _ = os.Remove(lockPath) }, nil
		}
		// ErrExist = a live holder. On Windows, a create racing a holder's release sees
		// ACCESS_DENIED (pending-delete) -> ErrPermission. Both are transient: retry.
		if !errors.Is(err, os.ErrExist) && !errors.Is(err, os.ErrPermission) {
			return nil, err
		}
		if info, statErr := os.Stat(lockPath); statErr == nil && time.Since(info.ModTime()) > staleTTL {
			_ = os.Remove(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout acquiring file lock %s: %w", lockPath, err)
		}
		time.Sleep(pollEvery)
	}
}
