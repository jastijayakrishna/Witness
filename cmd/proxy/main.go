package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/witness-proxy/witness-proxy/internal/config"
	"github.com/witness-proxy/witness-proxy/internal/loop"
	"github.com/witness-proxy/witness-proxy/internal/providers"
	"github.com/witness-proxy/witness-proxy/internal/proxy"
	"github.com/witness-proxy/witness-proxy/internal/receipts"
	"github.com/witness-proxy/witness-proxy/internal/storage"
	"github.com/witness-proxy/witness-proxy/internal/wal"
	"net/url"
)

var (
	requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "witness_http_requests_total",
			Help: "Total HTTP requests by method and status.",
		},
		[]string{"method", "status"},
	)
	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "witness_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method"},
	)
)

func init() {
	prometheus.MustRegister(requestsTotal)
	prometheus.MustRegister(requestDuration)
}

func main() {
	// Logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	log.Logger = zerolog.New(os.Stdout).With().Timestamp().Caller().Logger()

	// Config
	cfgPath := os.Getenv("WITNESS_CONFIG")
	if cfgPath == "" {
		cfgPath = "configs/proxy.yaml"
	}
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		cfgPath = ""
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}

	// Override provider targets from env vars (for testing/dev with mock servers)
	if targetURL := os.Getenv("WITNESS_OPENAI_TARGET"); targetURL != "" {
		if u, err := url.Parse(targetURL); err == nil {
			if p := providers.Registry["/openai"]; p != nil {
				p.Target = u
				log.Info().Str("target", targetURL).Msg("OpenAI target overridden")
			}
		}
	}
	if targetURL := os.Getenv("WITNESS_ANTHROPIC_TARGET"); targetURL != "" {
		if u, err := url.Parse(targetURL); err == nil {
			if p := providers.Registry["/anthropic"]; p != nil {
				p.Target = u
				log.Info().Str("target", targetURL).Msg("Anthropic target overridden")
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Postgres
	log.Info().Str("dsn", cfg.Postgres.DSN()).Msg("connecting to postgres")
	poolCfg, err := pgxpool.ParseConfig(cfg.Postgres.DSN())
	if err != nil {
		log.Fatal().Err(err).Msg("failed to parse postgres dsn")
	}
	poolCfg.MaxConns = 20
	poolCfg.MinConns = 2
	poolCfg.MaxConnLifetime = time.Hour
	poolCfg.MaxConnIdleTime = 30 * time.Minute
	poolCfg.HealthCheckPeriod = time.Minute
	poolCfg.ConnConfig.RuntimeParams["statement_timeout"] = "30000"
	poolCfg.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "60000"

	pgPool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to postgres")
	}
	defer pgPool.Close()

	if err := pgPool.Ping(ctx); err != nil {
		log.Fatal().Err(err).Msg("failed to ping postgres")
	}
	log.Info().Msg("postgres connected")

	// Run migrations
	if err := storage.Migrate(ctx, pgPool); err != nil {
		log.Fatal().Err(err).Msg("failed to run migrations")
	}
	log.Info().Msg("migrations applied")

	// Redis
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr(),
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	defer rdb.Close()

	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatal().Err(err).Msg("failed to ping redis")
	}
	log.Info().Msg("redis connected")

	// WAL writer
	walWriter, err := wal.NewWriter(cfg.WAL.Dir, cfg.WAL.SyncMode)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create WAL writer")
	}
	defer walWriter.Close()
	log.Info().Str("dir", cfg.WAL.Dir).Str("sync_mode", cfg.WAL.SyncMode).Msg("WAL writer initialized")

	// Loop detection
	var loopStore *loop.StateStore
	if cfg.LoopDetection.Enabled {
		loopStore = loop.NewStateStore(rdb)
		log.Info().Str("action", cfg.LoopDetection.Action).Msg("loop detection enabled")
	}
	loopCfg := loop.Config{
		Action:                 cfg.LoopDetection.Action,
		MaxRepeated:            cfg.LoopDetection.MaxRepeated,
		VelocityAccelRatio:     cfg.LoopDetection.VelocityAccelRatio,
		VelocityWindowMs:       cfg.LoopDetection.VelocityWindowMs,
		WarnConfidence:         cfg.LoopDetection.WarnConfidence,
		BlockConfidence:        cfg.LoopDetection.BlockConfidence,
		RequireSessionForBlock: cfg.LoopDetection.RequireSessionForBlock,
	}

	// Override tokens
	var overrideStore *loop.OverrideStore
	if cfg.LoopDetection.Enabled && cfg.LoopDetection.Action != "shadow" {
		overrideStore = loop.NewOverrideStore(rdb)
		log.Info().Msg("override token system enabled")
	}

	// Budget enforcement
	var budgetEnforcer *loop.BudgetEnforcer
	if cfg.Budget.DailyHardUSD > 0 || cfg.Budget.DailySoftUSD > 0 {
		budgetEnforcer = loop.NewBudgetEnforcer(rdb, cfg.Budget.DailySoftUSD, cfg.Budget.DailyHardUSD, cfg.Budget.ReservePerRequestUSD)
		log.Info().
			Float64("daily_soft_usd", cfg.Budget.DailySoftUSD).
			Float64("daily_hard_usd", cfg.Budget.DailyHardUSD).
			Msg("budget enforcement enabled")
	}

	// Alerter
	var alerter *loop.Alerter
	if cfg.Alerts.WebhookURL != "" {
		alerter = loop.NewAlerter(cfg.Alerts.WebhookURL, rdb)
		log.Info().Str("webhook_url", cfg.Alerts.WebhookURL).Msg("alerter enabled")
	}

	// Proxy handler
	proxyHandler := proxy.NewHandler(walWriter, loopStore, loopCfg)
	proxyHandler.ActionStore = loop.NewPostgresActionStore(pgPool).WithCapabilitySecret(os.Getenv("WITNESS_ACTION_CAPABILITY_SECRET"))
	if receiptSecret := os.Getenv("WITNESS_RECEIPT_SIGNING_SECRET"); receiptSecret != "" {
		keyID := os.Getenv("WITNESS_RECEIPT_KEY_ID")
		proxyHandler.ReceiptSigner = receipts.NewSigner(keyID, []byte(receiptSecret))
		logKeyID := keyID
		if logKeyID == "" {
			logKeyID = "local"
		}
		log.Info().Str("key_id", logKeyID).Msg("receipt signing enabled")
	}
	proxyHandler.OverrideStore = overrideStore
	proxyHandler.BudgetEnforcer = budgetEnforcer
	proxyHandler.Alerter = alerter
	proxyHandler.DB = pgPool

	// Router
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)
	r.Use(metricsMiddleware)

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := pgPool.Ping(r.Context()); err != nil {
			http.Error(w, `{"status":"unhealthy","error":"postgres"}`, http.StatusServiceUnavailable)
			return
		}
		if err := rdb.Ping(r.Context()).Err(); err != nil {
			http.Error(w, `{"status":"unhealthy","error":"redis"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"healthy"}`)
	})

	r.Handle("/metrics", promhttp.Handler())

	// Mount proxy routes for each provider. Concurrency is bounded by the
	// Handler's inflight semaphore (with metrics + 503 shedding), so no
	// chi-level throttle is needed.
	r.Handle("/openai/*", proxyHandler)
	r.Handle("/anthropic/*", proxyHandler)
	r.Handle("/gemini/*", proxyHandler)
	r.Post("/v1/action/check", proxyHandler.HandleActionCheck)
	r.Post("/v1/action/result", proxyHandler.HandleActionResult)
	r.Post("/v1/tool/check", proxyHandler.HandleToolCheck)
	r.Post("/v1/tool/result", proxyHandler.HandleToolResult)

	// Server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:    addr,
		Handler: r,
		// WriteTimeout MUST be 0 for a streaming proxy — a fixed value severs
		// long token streams mid-flight. Exposure is bounded instead by
		// ReadHeaderTimeout (client-side slowloris) and the Transport's
		// ResponseHeaderTimeout (hung upstream).
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Info().Str("addr", addr).Msg("starting server")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("server error")
		}
	}()

	sig := <-sigCh
	log.Info().Str("signal", sig.String()).Msg("shutting down")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("shutdown error")
	}
	log.Info().Msg("server stopped")
}

func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		duration := time.Since(start).Seconds()
		status := fmt.Sprintf("%d", ww.Status())
		requestsTotal.WithLabelValues(r.Method, status).Inc()
		requestDuration.WithLabelValues(r.Method).Observe(duration)
	})
}
