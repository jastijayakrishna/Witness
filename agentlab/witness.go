package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/hubbleops/hubbleops/internal/auth"
	"github.com/hubbleops/hubbleops/internal/loop"
	"github.com/hubbleops/hubbleops/internal/proxy"
	"github.com/hubbleops/hubbleops/internal/wal"
)

const (
	labProject = "agentlab"
	labAPIKey  = "agentlab-local-key"
	// labLease keeps the demo snappy: a held money-movement claim frees in
	// seconds, not the production 2 minutes. Narrated honestly in the report.
	labLease = 3 * time.Second
)

// hubbleopsLab is a real HubbleOps (real handler, real auth middleware, real Lua
// scripts via miniredis, real WAL) on an embedded HTTP listener.
type hubbleopsLab struct {
	baseURL         string
	apiKey          string
	walDir          string
	client          *http.Client
	inFlightBackoff time.Duration

	server    *httptest.Server
	redis     *miniredis.Miniredis
	walW      *wal.Writer
	stopClock chan struct{}
}

type staticKeyStore struct{}

// Every scene authenticates with its own derived key ("agentlab-key-<scene>")
// so each plays the role of a distinct agent: resource limits are scoped to
// the key identity, and scenes must not share buckets.
func (staticKeyStore) LookupAPIKey(_ context.Context, rawKey string) (auth.KeyRecord, error) {
	if strings.HasPrefix(rawKey, "agentlab") {
		return auth.KeyRecord{Project: labProject}, nil
	}
	return auth.KeyRecord{}, auth.ErrInvalidKey
}

func startHubbleOps() (*hubbleopsLab, error) {
	walDir, err := os.MkdirTemp("", "agentlab-wal-")
	if err != nil {
		return nil, err
	}
	w, err := wal.NewWriter(walDir, "sync")
	if err != nil {
		return nil, fmt.Errorf("wal writer: %w", err)
	}
	mr, err := miniredis.Run()
	if err != nil {
		return nil, fmt.Errorf("embedded redis: %w", err)
	}
	// miniredis does not expire TTLs with wall-clock time; tick its clock
	// forward in real time so pending-claim leases actually lapse in the lab.
	stopClock := make(chan struct{})
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopClock:
				return
			case <-ticker.C:
				mr.FastForward(100 * time.Millisecond)
			}
		}
	}()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	cfg := loop.DefaultConfig()
	cfg.Action = "block" // enforce, not shadow: the lab tests the teeth
	h := proxy.NewHandler(w, loop.NewStateStore(rdb), cfg)
	h.ActionStore = loop.NewActionStore(rdb).WithLease(labLease)
	// The resource-rogue layer (step 4): cumulative caps, velocity, breaker.
	// These are the rules that flip W7/W8/W9 from MISSED to CAUGHT.
	h.LimitStore = loop.NewLimitStore(rdb, loop.LimitsConfig{
		Cumulative: []loop.CumulativeRule{{
			Name: "refund-cap-per-agent-hour", Tool: "stripe_refund",
			Scope: "agent", WindowSeconds: 3600, MaxAmountCents: 25_000,
		}},
		Velocity: []loop.VelocityRule{{
			Name: "crm-sync-rate", Tool: "sync_crm_record", MinRisk: "write",
			Scope: "agent", WindowSeconds: 60, MaxActions: 4,
		}},
		Breaker: loop.BreakerRule{Trips: 3, WindowSeconds: 600, CooldownSeconds: 900},
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/action/check", h.HandleActionCheck)
	mux.HandleFunc("/v1/action/result", h.HandleActionResult)

	middleware := auth.Middleware(auth.Options{
		Enabled:     true,
		Environment: "prod",
		Store:       staticKeyStore{},
	})
	server := httptest.NewServer(middleware(mux))

	return &hubbleopsLab{
		baseURL:         server.URL,
		apiKey:          labAPIKey,
		walDir:          walDir,
		client:          &http.Client{Timeout: 15 * time.Second},
		inFlightBackoff: labLease + time.Second,
		server:          server,
		redis:           mr,
		walW:            w,
		stopClock:       stopClock,
	}, nil
}

func (l *hubbleopsLab) Close() {
	close(l.stopClock)
	l.server.Close()
	_ = l.walW.Close()
	l.redis.Close()
}
