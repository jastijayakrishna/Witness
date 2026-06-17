package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
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

	"github.com/hubbleops/hubbleops/internal/auth"
	"github.com/hubbleops/hubbleops/internal/config"
	"github.com/hubbleops/hubbleops/internal/loop"
	"github.com/hubbleops/hubbleops/internal/providers"
	"github.com/hubbleops/hubbleops/internal/proxy"
	"github.com/hubbleops/hubbleops/internal/receipts"
	"github.com/hubbleops/hubbleops/internal/storage"
	"github.com/hubbleops/hubbleops/internal/wal"
)

var (
	requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "hubbleops_http_requests_total",
			Help: "Total HTTP requests by method and status.",
		},
		[]string{"method", "status"},
	)
	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "hubbleops_http_request_duration_seconds",
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
	cfgPath := os.Getenv("HUBBLEOPS_CONFIG")
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
	runtimeSecrets := config.RuntimeSecrets{
		ReceiptSigningSecretSet:   secretSet("HUBBLEOPS_RECEIPT_SIGNING_SECRET"),
		ActionCapabilitySecretSet: secretSet("HUBBLEOPS_ACTION_CAPABILITY_SECRET"),
	}
	validation, err := cfg.Validate(runtimeSecrets)
	log.Info().Interface("config", cfg.RedactedSummary(runtimeSecrets)).Msg("HubbleOps startup config summary")
	for _, warning := range validation.Warnings {
		log.Warn().Str("warning", warning).Msg("unsafe HubbleOps configuration")
	}
	if err != nil {
		log.Fatal().Err(err).Msg("failed config safety validation")
	}

	// Override provider targets from env vars (for testing/dev with mock servers)
	if targetURL := os.Getenv("HUBBLEOPS_OPENAI_TARGET"); targetURL != "" {
		if u, err := url.Parse(targetURL); err == nil {
			if p := providers.Registry["/openai"]; p != nil {
				p.Target = u
				log.Info().Str("target", config.RedactURL(targetURL)).Msg("OpenAI target overridden")
			}
		}
	}
	if targetURL := os.Getenv("HUBBLEOPS_ANTHROPIC_TARGET"); targetURL != "" {
		if u, err := url.Parse(targetURL); err == nil {
			if p := providers.Registry["/anthropic"]; p != nil {
				p.Target = u
				log.Info().Str("target", config.RedactURL(targetURL)).Msg("Anthropic target overridden")
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Postgres
	log.Info().Str("dsn", cfg.Postgres.RedactedDSN()).Msg("connecting to postgres")
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
		ToolRiskFloor:          cfg.LoopDetection.ToolRiskFloors,
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

	// Resource limits: cumulative caps, velocity, circuit breaker
	var limitStore *loop.LimitStore
	if limitsCfg := buildLimitsConfig(cfg.Limits); limitsCfg.Enabled() {
		limitStore = loop.NewLimitStore(rdb, limitsCfg)
		log.Info().
			Int("cumulative_rules", len(limitsCfg.Cumulative)).
			Int("velocity_rules", len(limitsCfg.Velocity)).
			Int("breaker_trips", limitsCfg.Breaker.Trips).
			Msg("resource limits enabled")
	}

	// Alerter
	var alerter *loop.Alerter
	if cfg.Alerts.WebhookURL != "" {
		alerter = loop.NewAlerter(cfg.Alerts.WebhookURL, rdb)
		log.Info().Str("webhook_url", config.RedactURL(cfg.Alerts.WebhookURL)).Msg("alerter enabled")
	}

	// Proxy handler
	proxyHandler := proxy.NewHandler(walWriter, loopStore, loopCfg)
	proxyHandler.ActionStore = loop.NewPostgresActionStore(pgPool).WithCapabilitySecret(os.Getenv("HUBBLEOPS_ACTION_CAPABILITY_SECRET"))
	if receiptSecret := os.Getenv("HUBBLEOPS_RECEIPT_SIGNING_SECRET"); receiptSecret != "" {
		keyID := os.Getenv("HUBBLEOPS_RECEIPT_KEY_ID")
		signer := receipts.NewSigner(keyID, []byte(receiptSecret))
		proxyHandler.ReceiptSigner = signer
		logKeyID := keyID
		if logKeyID == "" {
			logKeyID = "local"
		}
		// Publish the Ed25519 public key on startup so operators can hand it to auditors,
		// who can then verify receipts (hubbleops verify-receipts -receipt-public-key ...)
		// without ever holding the signing secret.
		log.Info().
			Str("key_id", logKeyID).
			Str("algorithm", "ed25519").
			Str("public_key", signer.PublicKeyBase64()).
			Msg("receipt signing enabled; publish public_key for external verification")
	}
	proxyHandler.OverrideStore = overrideStore
	proxyHandler.LimitStore = limitStore
	proxyHandler.BudgetEnforcer = budgetEnforcer
	proxyHandler.Alerter = alerter
	proxyHandler.DB = pgPool
	moatStore := storage.NewMoatStore(pgPool)
	if cfg.OutcomeCapture.Enabled {
		proxyHandler.OutcomeStore = moatStore
		proxyHandler.OutcomeCapture = proxy.OutcomeCaptureConfig{
			Enabled: true,
			Mode:    cfg.OutcomeCapture.Mode,
			Raw:     cfg.OutcomeCapture.Raw,
		}
		log.Info().Str("mode", cfg.OutcomeCapture.Mode).Bool("raw", cfg.OutcomeCapture.Raw).Msg("data moat outcome capture enabled")
	}
	proxyHandler.DecisionReviewStore = moatStore
	proxyHandler.ReviewRawNotes = cfg.Reviews.RawNotes
	proxyHandler.RawCaptureEnabled = cfg.Capture.Mode == config.CaptureModeRaw
	if cfg.Reviews.RawNotes {
		log.Warn().Msg("raw decision review notes enabled")
	}
	proxyHandler.RequireReceiptForBlock = cfg.Receipts.RequireForBlock
	proxyHandler.EnforceWithoutReceipt = cfg.Receipts.EnforceWithoutReceipt
	if cfg.Receipts.EnforceWithoutReceipt {
		log.Error().Msg("CRITICAL: HubbleOps may enforce blocks without durable receipts")
	}

	// Durable receipt recovery: any decision receipt that fails its WAL write while a
	// block is enforced is persisted to an on-disk dead-letter queue and replayed once
	// the WAL recovers. Because the queue lives on disk under the WAL dir, recovery
	// survives process restarts — not just transient in-process retries.
	if deadLetter, dlErr := wal.NewDeadLetter(cfg.WAL.Dir); dlErr != nil {
		log.Error().Err(dlErr).Msg("failed to initialize receipt dead-letter queue; durable receipt recovery disabled")
	} else {
		proxyHandler.ReceiptQueue = deadLetter
		proxyHandler.StartReceiptDrainer(30*time.Second, ctx.Done())
		log.Info().Str("dir", cfg.WAL.Dir).Msg("durable receipt dead-letter recovery enabled")
	}

	authMiddleware := auth.Middleware(auth.Options{
		Store:         auth.NewPostgresKeyStore(pgPool),
		Enabled:       cfg.Auth.Enabled,
		DevBypass:     cfg.Auth.DevBypass,
		Environment:   cfg.Environment,
		MetricsPublic: cfg.Auth.MetricsPublic,
	})
	if !cfg.Auth.Enabled {
		log.Warn().Msg("HubbleOps API-key auth disabled; do not use this setting in production")
	}
	if cfg.Auth.DevBypass {
		log.Warn().Msg("HubbleOps dev auth bypass enabled; only safe for local development")
	}
	if cfg.Auth.MetricsPublic {
		log.Warn().Msg("HubbleOps metrics endpoint is public")
	}

	// Router
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)
	r.Use(metricsMiddleware)

	r.Get("/livez", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"alive"}`)
	})
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeReadiness(w, r, pgPool, rdb, walWriter)
	})
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		writeReadiness(w, r, pgPool, rdb, walWriter)
	})

	// Public, unauthenticated: anyone can fetch the receipt verification key. A public
	// key grants verification, never signing, so it is safe to expose.
	r.Get("/v1/receipts/public-key", proxyHandler.HandleReceiptPublicKey)
	r.Get("/.well-known/hubbleops-receipt-key", proxyHandler.HandleReceiptPublicKey)

	if cfg.Auth.MetricsPublic {
		r.Handle("/metrics", promhttp.Handler())
	} else {
		r.With(authMiddleware).Handle("/metrics", promhttp.Handler())
	}

	// Mount proxy routes for each provider. Concurrency is bounded by the
	// Handler's inflight semaphore (with metrics + 503 shedding), so no
	// chi-level throttle is needed.
	r.Group(func(protected chi.Router) {
		protected.Use(authMiddleware)
		protected.Handle("/openai/*", proxyHandler)
		protected.Handle("/anthropic/*", proxyHandler)
		protected.Handle("/gemini/*", proxyHandler)
		protected.Post("/v1/action/check", proxyHandler.HandleActionCheck)
		protected.Post("/v1/action/result", proxyHandler.HandleActionResult)
		protected.Post("/v1/tool/check", proxyHandler.HandleToolCheck)
		protected.Post("/v1/tool/result", proxyHandler.HandleToolResult)
		protected.Post("/v1/decisions/{decision_id}/review", proxyHandler.HandleDecisionReview)
	})

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

func writeReadiness(w http.ResponseWriter, r *http.Request, pgPool *pgxpool.Pool, rdb *redis.Client, walWriter *wal.Writer) {
	body := map[string]string{
		"status":   "healthy",
		"postgres": "ok",
		"redis":    "ok",
		"wal":      "ok",
	}
	if err := pgPool.Ping(r.Context()); err != nil {
		body["status"] = "unhealthy"
		body["postgres"] = "error"
		body["error"] = "postgres"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(body)
		return
	}
	if err := rdb.Ping(r.Context()).Err(); err != nil {
		body["status"] = "unhealthy"
		body["redis"] = "error"
		body["error"] = "redis"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(body)
		return
	}
	if err := walWriter.CheckWritable(); err != nil {
		body["status"] = "unhealthy"
		body["wal"] = "error"
		body["error"] = "wal"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(body)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

func secretSet(name string) bool {
	return strings.TrimSpace(os.Getenv(name)) != ""
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

// buildLimitsConfig converts the yaml limits section into the loop package's
// rule types. Validation already ran at startup, so rules arrive well-formed.
func buildLimitsConfig(cfg config.LimitsConfig) loop.LimitsConfig {
	out := loop.LimitsConfig{
		Breaker: loop.BreakerRule{
			Trips:           cfg.Breaker.Trips,
			WindowSeconds:   cfg.Breaker.WindowSeconds,
			CooldownSeconds: cfg.Breaker.CooldownSeconds,
		},
	}
	for _, rule := range cfg.Cumulative {
		out.Cumulative = append(out.Cumulative, loop.CumulativeRule{
			Name:           rule.Name,
			Tool:           rule.Tool,
			Scope:          rule.Scope,
			WindowSeconds:  rule.WindowSeconds,
			MaxAmountCents: rule.MaxAmountCents,
		})
	}
	for _, rule := range cfg.Velocity {
		out.Velocity = append(out.Velocity, loop.VelocityRule{
			Name:          rule.Name,
			Tool:          rule.Tool,
			MinRisk:       rule.MinRisk,
			Scope:         rule.Scope,
			WindowSeconds: rule.WindowSeconds,
			MaxActions:    rule.MaxActions,
		})
	}
	return out
}
