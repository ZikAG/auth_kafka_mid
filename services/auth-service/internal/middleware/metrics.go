package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// httpRequestsTotal counts every HTTP request handled by the service.
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests processed, partitioned by method, path and status code.",
		},
		[]string{"method", "path", "status_code"},
	)

	// httpRequestDuration measures the latency of every HTTP request.
	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request latency in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	// tokenExchangeTotal counts token-exchange operations.
	tokenExchangeTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "token_exchange_total",
			Help: "Total number of token exchange operations, partitioned by tenant and success status.",
		},
		[]string{"tenant_id", "success"},
	)

	// activeTokensGauge tracks the current number of active (in-flight) token requests.
	activeTokensGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "active_tokens_gauge",
			Help: "Current number of in-flight token requests.",
		},
	)
)

// Metrics returns a Gin middleware that records Prometheus metrics for every
// request: total count, duration histogram, and an in-flight gauge.
func Metrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.FullPath()
		if path == "" {
			// FullPath is empty for 404s; fall back to the raw URL path.
			path = c.Request.URL.Path
		}

		activeTokensGauge.Inc()
		defer activeTokensGauge.Dec()

		c.Next()

		duration := time.Since(start).Seconds()
		statusCode := strconv.Itoa(c.Writer.Status())

		httpRequestsTotal.WithLabelValues(c.Request.Method, path, statusCode).Inc()
		httpRequestDuration.WithLabelValues(c.Request.Method, path).Observe(duration)
	}
}

// RecordTokenExchange increments the token_exchange_total counter.
// It is exported so that the token-exchange handler can call it directly.
func RecordTokenExchange(tenantID string, success bool) {
	successStr := "false"
	if success {
		successStr = "true"
	}
	tokenExchangeTotal.WithLabelValues(tenantID, successStr).Inc()
}
