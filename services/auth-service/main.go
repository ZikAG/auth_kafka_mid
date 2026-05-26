package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/kafkaoauth/auth-service/internal/config"
	"github.com/kafkaoauth/auth-service/internal/handlers"
	"github.com/kafkaoauth/auth-service/internal/keycloak"
	"github.com/kafkaoauth/auth-service/internal/middleware"
)

func main() {
	cfg := config.Load()
	logger := setupLogger(cfg)
	defer logger.Sync() //nolint:errcheck

	logger.Info("starting auth-service",
		zap.String("port", cfg.Port),
		zap.String("environment", cfg.Environment),
		zap.String("keycloak_url", cfg.KeycloakURL),
		zap.String("realm", cfg.KeycloakRealm),
	)

	// Keycloak client.
	kc := keycloak.New(cfg)

	// Gin mode.
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// ── Global middleware ─────────────────────────────────────────────────────

	// Panic recovery.
	router.Use(gin.RecoveryWithWriter(os.Stderr))

	// Structured request logging.
	router.Use(zapLogger(logger))

	// CORS: allow all origins (tighten in production via a reverse proxy or
	// by replacing this with a proper CORS config).
	router.Use(corsMiddleware())

	// Prometheus metrics (only when enabled).
	if cfg.EnableMetrics {
		router.Use(middleware.Metrics())
	}

	// Per-IP rate limiting.
	router.Use(middleware.RateLimit(cfg.RateLimitRPS))

	// ── Routes ───────────────────────────────────────────────────────────────

	// Health check – no rate limiting, no auth.
	router.GET("/health", healthHandler(kc, logger))

	// Prometheus metrics endpoint.
	if cfg.EnableMetrics {
		router.GET("/metrics", gin.WrapH(promhttp.Handler()))
	}

	// API v1.
	v1 := router.Group("/api/v1")
	{
		v1.POST("/login", handlers.LoginHandler(kc, logger))
		v1.POST("/token-exchange", handlers.TokenExchangeHandler(kc, logger))
		v1.POST("/refresh", handlers.RefreshHandler(kc, logger))
		v1.POST("/introspect", handlers.IntrospectHandler(kc, logger))
	}

	// ── HTTP server ───────────────────────────────────────────────────────────

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in background.
	go func() {
		logger.Info("http server listening", zap.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("server failed", zap.Error(err))
		}
	}()

	// ── Graceful shutdown ─────────────────────────────────────────────────────

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	logger.Info("shutdown signal received", zap.String("signal", sig.String()))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("server forced to shut down", zap.Error(err))
	} else {
		logger.Info("server exited gracefully")
	}
}

// ── Logger setup ──────────────────────────────────────────────────────────────

func setupLogger(cfg *config.Config) *zap.Logger {
	var level zapcore.Level
	switch cfg.LogLevel {
	case "debug":
		level = zapcore.DebugLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	default:
		level = zapcore.InfoLevel
	}

	var logger *zap.Logger
	var err error

	if cfg.Environment == "production" {
		zapCfg := zap.NewProductionConfig()
		zapCfg.Level = zap.NewAtomicLevelAt(level)
		logger, err = zapCfg.Build()
	} else {
		zapCfg := zap.NewDevelopmentConfig()
		zapCfg.Level = zap.NewAtomicLevelAt(level)
		logger, err = zapCfg.Build()
	}

	if err != nil {
		// Fallback to a no-op logger on catastrophic failure.
		return zap.NewNop()
	}
	return logger
}

// ── Middleware helpers ────────────────────────────────────────────────────────

// zapLogger returns a Gin middleware that emits a structured zap log line for
// every request.
func zapLogger(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		statusCode := c.Writer.Status()

		fields := []zap.Field{
			zap.Int("status", statusCode),
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.String("query", query),
			zap.String("ip", c.ClientIP()),
			zap.Duration("latency", latency),
			zap.String("user_agent", c.Request.UserAgent()),
		}

		if len(c.Errors) > 0 {
			fields = append(fields, zap.String("errors", c.Errors.ByType(gin.ErrorTypePrivate).String()))
		}

		switch {
		case statusCode >= 500:
			logger.Error("request", fields...)
		case statusCode >= 400:
			logger.Warn("request", fields...)
		default:
			logger.Info("request", fields...)
		}
	}
}

// corsMiddleware adds permissive CORS headers.  Tighten for production use.
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// ── Health check handler ──────────────────────────────────────────────────────

type healthStatus struct {
	Status    string            `json:"status"`
	Checks    map[string]string `json:"checks"`
	Timestamp string            `json:"timestamp"`
}

func healthHandler(kc *keycloak.Client, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
		defer cancel()

		checks := map[string]string{}
		overall := "ok"

		if err := kc.HealthCheck(ctx); err != nil {
			logger.Warn("health check: keycloak unreachable", zap.Error(err))
			checks["keycloak"] = "unreachable: " + err.Error()
			overall = "degraded"
		} else {
			checks["keycloak"] = "ok"
		}

		statusCode := http.StatusOK
		if overall != "ok" {
			statusCode = http.StatusServiceUnavailable
		}

		c.JSON(statusCode, healthStatus{
			Status:    overall,
			Checks:    checks,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
	}
}
