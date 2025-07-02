package middleware

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sentinel_gate/pkg/telemetry"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// InstrumentationConfig holds configuration for the instrumentation middleware
type InstrumentationConfig struct {
	ServiceName    string
	ServiceVersion string
	SkipPaths      []string
	Logger         *zap.Logger
}

// Instrumentation middleware for telemetry data collection
func Instrumentation(tel *telemetry.Telemetry, config InstrumentationConfig) gin.HandlerFunc {
	// Use OpenTelemetry Gin middleware for automatic tracing
	otelMiddleware := otelgin.Middleware(config.ServiceName)

	return gin.HandlerFunc(func(c *gin.Context) {
		// Skip instrumentation for certain paths
		if shouldSkipPath(c.Request.URL.Path, config.SkipPaths) {
			c.Next()
			return
		}

		start := time.Now()

		// Increment in-flight requests
		tel.IncrementRequestsInFlight(c.Request.Context())
		defer tel.DecrementRequestsInFlight(c.Request.Context())

		// Apply OpenTelemetry middleware first
		otelMiddleware(c)

		// Continue with request processing
		c.Next()

		// Collect metrics after request processing
		duration := time.Since(start)
		method := c.Request.Method
		path := sanitizePath(c.FullPath())
		statusCode := c.Writer.Status()
		statusClass := getStatusClass(statusCode)

		// Record metrics
		tel.IncrementRequestCounter(c.Request.Context(), method, path, strconv.Itoa(statusCode))
		tel.RecordRequestDuration(c.Request.Context(), duration, method, path)

		// Record errors
		if statusCode >= 400 {
			errorType := getErrorType(statusCode)
			tel.IncrementErrorTotal(c.Request.Context(), errorType, "http")
		}

		// Add span attributes
		if span := trace.SpanFromContext(c.Request.Context()); span.IsRecording() {
			span.SetAttributes(
				attribute.String("http.method", method),
				attribute.String("http.route", path),
				attribute.Int("http.status_code", statusCode),
				attribute.String("http.status_class", statusClass),
				attribute.Float64("http.duration_ms", float64(duration.Nanoseconds())/1e6),
				attribute.String("http.user_agent", c.GetHeader("User-Agent")),
				attribute.String("http.remote_addr", c.ClientIP()),
			)

			// Add error information to span
			if statusCode >= 400 {
				span.SetAttributes(
					attribute.Bool("error", true),
					attribute.String("error.type", getErrorType(statusCode)),
				)

				if len(c.Errors) > 0 {
					span.SetAttributes(
						attribute.String("error.message", c.Errors.String()),
					)
				}
			}
		}

		// Log request details
		config.Logger.Info("HTTP request completed",
			zap.String("method", method),
			zap.String("path", path),
			zap.Int("status", statusCode),
			zap.Duration("duration", duration),
			zap.String("client_ip", c.ClientIP()),
			zap.String("user_agent", c.GetHeader("User-Agent")),
			zap.String("request_id", c.GetString("request_id")),
		)
	})
}

// AuthInstrumentation middleware for authentication-specific metrics
func AuthInstrumentation(tel *telemetry.Telemetry) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Check if this is an auth-related endpoint
		if !isAuthEndpoint(c.Request.URL.Path) {
			c.Next()
			return
		}

		c.Next()

		// Record auth operation metrics
		operation := getAuthOperation(c.Request.URL.Path, c.Request.Method)
		result := getAuthResult(c.Writer.Status())

		tel.IncrementAuthOperations(c.Request.Context(), operation, result)

		// Add span event for auth operations
		tel.AddSpanEvent(c.Request.Context(), "auth.operation",
			attribute.String("auth.operation", operation),
			attribute.String("auth.result", result),
		)
	})
}

// ProxyInstrumentation middleware for proxy-specific metrics
func ProxyInstrumentation(tel *telemetry.Telemetry) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Check if this is a proxy endpoint
		targetService := getTargetService(c.Request.URL.Path)
		if targetService == "" {
			c.Next()
			return
		}

		start := time.Now()

		c.Next()

		duration := time.Since(start)
		statusCode := c.Writer.Status()

		// Record proxy operation metrics
		tel.IncrementProxyOperations(c.Request.Context(), targetService, c.Request.Method, statusCode)

		// Add span attributes for proxy operations
		tel.SetSpanAttributes(c.Request.Context(),
			attribute.String("proxy.target_service", targetService),
			attribute.String("proxy.method", c.Request.Method),
			attribute.Int("proxy.status_code", statusCode),
			attribute.Float64("proxy.duration_ms", float64(duration.Nanoseconds())/1e6),
		)

		// Add span event for proxy operations
		tel.AddSpanEvent(c.Request.Context(), "proxy.request",
			attribute.String("proxy.target", targetService),
			attribute.String("proxy.method", c.Request.Method),
			attribute.Int("proxy.status", statusCode),
		)
	})
}

// RateLimitInstrumentation middleware for rate limiting metrics
func RateLimitInstrumentation(tel *telemetry.Telemetry) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		c.Next()

		// Check if rate limit was exceeded
		if c.Writer.Status() == 429 {
			clientIP := c.ClientIP()
			limitType := c.GetHeader("X-RateLimit-Type")
			if limitType == "" {
				limitType = "unknown"
			}

			tel.IncrementRateLimitExceeded(c.Request.Context(), clientIP, limitType)

			// Add span event for rate limit exceeded
			tel.AddSpanEvent(c.Request.Context(), "rate_limit.exceeded",
				attribute.String("rate_limit.client_ip", clientIP),
				attribute.String("rate_limit.type", limitType),
			)
		}
	})
}

// shouldSkipPath checks if a path should be skipped from instrumentation
func shouldSkipPath(path string, skipPaths []string) bool {
	for _, skipPath := range skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}

	// Skip common health check and metrics endpoints by default
	defaultSkipPaths := []string{
		"/health",
		"/ready",
		"/metrics",
		"/favicon.ico",
	}

	for _, skipPath := range defaultSkipPaths {
		if path == skipPath {
			return true
		}
	}

	return false
}

// sanitizePath normalizes the path for metrics (remove parameters, etc.)
func sanitizePath(path string) string {
	if path == "" {
		return "unknown"
	}

	// Replace path parameters with placeholders
	// Example: /api/users/123 -> /api/users/:id
	re := regexp.MustCompile(`/\d+`)
	path = re.ReplaceAllString(path, "/:id")

	// Replace UUID patterns
	uuidRe := regexp.MustCompile(`/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	path = uuidRe.ReplaceAllString(path, "/:uuid")

	return path
}

// getStatusClass returns the HTTP status class (1xx, 2xx, etc.)
func getStatusClass(statusCode int) string {
	switch {
	case statusCode >= 100 && statusCode < 200:
		return "1xx"
	case statusCode >= 200 && statusCode < 300:
		return "2xx"
	case statusCode >= 300 && statusCode < 400:
		return "3xx"
	case statusCode >= 400 && statusCode < 500:
		return "4xx"
	case statusCode >= 500:
		return "5xx"
	default:
		return "unknown"
	}
}

// getErrorType returns the type of error based on status code
func getErrorType(statusCode int) string {
	switch statusCode {
	case 400:
		return "bad_request"
	case 401:
		return "unauthorized"
	case 403:
		return "forbidden"
	case 404:
		return "not_found"
	case 429:
		return "rate_limited"
	case 500:
		return "internal_error"
	case 502:
		return "bad_gateway"
	case 503:
		return "service_unavailable"
	case 504:
		return "gateway_timeout"
	default:
		if statusCode >= 400 && statusCode < 500 {
			return "client_error"
		} else if statusCode >= 500 {
			return "server_error"
		}
		return "unknown"
	}
}

// isAuthEndpoint checks if the path is an authentication endpoint
func isAuthEndpoint(path string) bool {
	authPaths := []string{
		"/auth/login",
		"/auth/logout",
		"/auth/refresh",
		"/auth/validate",
	}

	for _, authPath := range authPaths {
		if strings.HasPrefix(path, authPath) {
			return true
		}
	}

	return false
}

// getAuthOperation returns the auth operation type
func getAuthOperation(path, method string) string {
	switch {
	case strings.Contains(path, "/login"):
		return "login"
	case strings.Contains(path, "/logout"):
		return "logout"
	case strings.Contains(path, "/refresh"):
		return "refresh"
	case strings.Contains(path, "/validate"):
		return "validate"
	default:
		return "unknown"
	}
}

// getAuthResult returns the auth operation result
func getAuthResult(statusCode int) string {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return "success"
	case statusCode == 401:
		return "unauthorized"
	case statusCode == 403:
		return "forbidden"
	case statusCode >= 400 && statusCode < 500:
		return "client_error"
	case statusCode >= 500:
		return "server_error"
	default:
		return "unknown"
	}
}

// getTargetService extracts target service from proxy path
func getTargetService(path string) string {
	// Extract service name from path like /api/users/* -> api-users
	if strings.HasPrefix(path, "/api/") {
		parts := strings.Split(path, "/")
		if len(parts) >= 3 {
			return fmt.Sprintf("api-%s", parts[2])
		}
	}

	return ""
}

// MetricsEndpoint creates a handler for exposing Prometheus metrics
func MetricsEndpoint(tel *telemetry.Telemetry) gin.HandlerFunc {
	handler := tel.GetPrometheusHandler()

	return gin.WrapH(handler)
}
