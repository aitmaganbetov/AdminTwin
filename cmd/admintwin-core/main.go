// Command admintwin-core — один бинарник ядра для on-prem (§3.5): API Gateway, Change Coordinator,
// Policy, Approval, Execution Gateway, Audit, реестры.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aitmaganbetov/admintwin/internal/app"
)

var version = "0.1.0-dev"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := app.Config{
		Root:         env("ADMINTWIN_ROOT", "."),
		FixturesPath: os.Getenv("ADMINTWIN_FIXTURES"),
		DevAuth:      os.Getenv("ADMINTWIN_DEV_AUTH") == "true",
		OIDCIssuer:   os.Getenv("ADMINTWIN_OIDC_ISSUER"),
		OIDCAudience: os.Getenv("ADMINTWIN_OIDC_AUDIENCE"),
		OIDCJWKSURL:  os.Getenv("ADMINTWIN_OIDC_JWKS_URL"),
		ServiceToken: os.Getenv("ADMINTWIN_SERVICE_TOKEN"),
		DatabaseURL:  os.Getenv("ADMINTWIN_DATABASE_URL"),
		Migrate:      os.Getenv("ADMINTWIN_DB_MIGRATE") != "false",
		// Ключи — из секрет-хранилища развертывания (Vault Agent / Kubernetes Secret), не из репозитория.
		AuditSigningKey: os.Getenv("ADMINTWIN_AUDIT_SIGNING_KEY"),
		PIIMasterKey:    os.Getenv("ADMINTWIN_PII_MASTER_KEY"),
		OrchestratorURL: os.Getenv("ADMINTWIN_ORCHESTRATOR_URL"),
		Simulator:       os.Getenv("ADMINTWIN_SIMULATOR") == "true",
		Version:         version,
		Logger:          log,
	}
	if cfg.DevAuth {
		log.Warn("DEV AUTH ENABLED: identity is taken from request headers; never use outside local development")
	}
	if cfg.Simulator {
		log.Warn("SIMULATOR ENABLED: executions run against simulated infrastructure")
	}
	a, err := app.New(cfg)
	if err != nil {
		log.Error("startup failed", "error", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr: env("ADMINTWIN_ADDR", ":8080"), Handler: a.Server.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go a.RunBackground(ctx, 30*time.Second, time.Hour)
	// Метрики Prometheus — на отдельном (по умолчанию локальном) адресе, не через публичный API.
	metricsSrv := &http.Server{Addr: env("ADMINTWIN_METRICS_ADDR", "127.0.0.1:9464"), ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			a.Metrics.Write(w)
		})}
	go func() {
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics listener failed", "error", err)
		}
	}()
	go func() {
		log.Info("admintwin-core listening", "addr", srv.Addr, "version", version)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server failed", "error", err)
			stop()
		}
	}()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	_ = metricsSrv.Shutdown(shutdown)
	a.Coordinator.Wait()
	log.Info("admintwin-core stopped")
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
