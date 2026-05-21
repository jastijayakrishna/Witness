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
	_ "github.com/witness-proxy/witness-proxy/internal/providers" // register providers via init()
	"github.com/witness-proxy/witness-proxy/internal/proxy"
	"github.com/witness-proxy/witness-proxy/internal/storage"
	"github.com/witness-proxy/witness-proxy/internal/wal"
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Postgres
	log.Info().Str("dsn", cfg.Postgres.DSN()).Msg("connecting to postgres")
	pgPool, err := pgxpool.New(ctx, cfg.Postgres.DSN())
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
	walDir := os.Getenv("WITNESS_WAL_DIR")
	if walDir == "" {
		walDir = "data/wal"
	}
	walWriter, err := wal.NewWriter(walDir)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create WAL writer")
	}
	defer walWriter.Close()
	log.Info().Str("dir", walDir).Msg("WAL writer initialized")

	// Proxy handler
	proxyHandler := proxy.NewHandler(walWriter)

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

	// Mount proxy routes for each provider
	r.Handle("/openai/*", proxyHandler)
	r.Handle("/anthropic/*", proxyHandler)

	// Server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
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
