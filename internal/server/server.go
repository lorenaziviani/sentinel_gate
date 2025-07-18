package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"sentinel_gate/internal/auth"
	"sentinel_gate/internal/circuitbreaker"
	"sentinel_gate/internal/middleware"
	"sentinel_gate/internal/proxy"
	"sentinel_gate/internal/ratelimiter"
	"sentinel_gate/pkg/config"
	"sentinel_gate/pkg/telemetry"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Server represents the HTTP server
type Server struct {
	config         *config.Config
	logger         *zap.Logger
	router         *gin.Engine
	proxy          *proxy.Proxy
	rateLimiter    *middleware.EnhancedRateLimiter
	circuitBreaker *circuitbreaker.CircuitBreakerManager
	telemetry      *telemetry.Telemetry
}

// New creates a new server instance
func New(cfg *config.Config, logger *zap.Logger) (*Server, error) {
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	tel, telShutdown, err := telemetry.Init(cfg.Telemetry, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize telemetry: %w", err)
	}

	_ = telShutdown

	circuitBreakerManager := circuitbreaker.NewCircuitBreakerManager(cfg.CircuitBreaker, logger)

	proxyHandler, err := proxy.New(cfg.Proxy, circuitBreakerManager, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy: %w", err)
	}

	rateLimiter := middleware.NewEnhancedRateLimiter(cfg, logger)

	server := &Server{
		config:         cfg,
		logger:         logger,
		router:         gin.New(),
		proxy:          proxyHandler,
		rateLimiter:    rateLimiter,
		circuitBreaker: circuitBreakerManager,
		telemetry:      tel,
	}

	server.setupMiddlewares()
	server.setupRoutes()

	return server, nil
}

// Handler returns the HTTP handler
func (s *Server) Handler() http.Handler {
	return s.router
}

// setupMiddlewares configures the global middlewares
func (s *Server) setupMiddlewares() {
	s.router.Use(gin.Recovery())

	s.router.Use(middleware.CORS())

	s.router.Use(middleware.Logger(s.logger))

	s.router.Use(middleware.DetailedLogger(s.logger))

	// Add telemetry instrumentation middleware
	instrumentationConfig := middleware.InstrumentationConfig{
		ServiceName:    s.config.Telemetry.ServiceName,
		ServiceVersion: s.config.Telemetry.ServiceVersion,
		SkipPaths:      []string{"/metrics", "/health", "/ready"},
		Logger:         s.logger,
	}
	s.router.Use(middleware.Instrumentation(s.telemetry, instrumentationConfig))
	s.router.Use(middleware.AuthInstrumentation(s.telemetry))
	s.router.Use(middleware.ProxyInstrumentation(s.telemetry))
	s.router.Use(middleware.RateLimitInstrumentation(s.telemetry))

	s.router.Use(middleware.Metrics())

	s.router.Use(middleware.RequestID())

	s.router.Use(s.rateLimiter.RateLimitMiddleware())
	s.router.Use(middleware.SetRequestIDInContext())
	s.router.Use(middleware.SetAuthContextInRequest())
}

// setupRoutes configures the application routes
func (s *Server) setupRoutes() {
	// Public routes (no authentication required)
	s.router.GET("/health", s.healthCheck)
	s.router.GET("/ready", s.readinessCheck)

	// Prometheus metrics endpoint
	s.router.GET("/metrics", middleware.MetricsEndpoint(s.telemetry))

	// Authentication routes
	authGroup := s.router.Group("/auth")
	{
		authGroup.POST("/login", auth.Login(s.config.JWT, s.logger))
		authGroup.POST("/refresh", auth.RefreshToken(s.config.JWT, s.logger))
		authGroup.POST("/logout", middleware.JWTAuth(s.config.JWT, s.logger), auth.Logout(s.logger))
	}

	// Admin routes for circuit breaker management
	adminGroup := s.router.Group("/admin")
	adminGroup.Use(middleware.JWTAuth(s.config.JWT, s.logger))
	adminGroup.Use(middleware.RequireRole("admin"))
	{
		// Circuit breaker endpoints
		adminGroup.GET("/circuit-breaker/status", s.getCircuitBreakerStatus)
		adminGroup.GET("/circuit-breaker/metrics", s.getCircuitBreakerMetrics)
		adminGroup.POST("/circuit-breaker/reset/:service", s.resetCircuitBreaker)
	}

	// Test routes for JWT validation
	testGroup := s.router.Group("/test")
	{
		// Public test endpoint
		testGroup.GET("/public", s.testPublic)

		// Protected test endpoint (any authenticated user)
		testGroup.GET("/protected", middleware.JWTAuth(s.config.JWT, s.logger), s.testProtected)

		// Admin only test endpoint
		testGroup.GET("/admin",
			middleware.JWTAuth(s.config.JWT, s.logger),
			middleware.RequireRole("admin"),
			s.testAdmin,
		)

		// User role test endpoint
		testGroup.GET("/user",
			middleware.JWTAuth(s.config.JWT, s.logger),
			middleware.RequireRole("user", "admin"),
			s.testUser,
		)

		// Token validation test endpoint
		testGroup.POST("/validate-token", middleware.JWTAuth(s.config.JWT, s.logger), s.testTokenValidation)

		// Rate limiting test endpoints
		testGroup.GET("/rate-limit", s.testRateLimit)
		testGroup.GET("/rate-limit-auth", middleware.JWTAuth(s.config.JWT, s.logger), s.testRateLimitAuth)
		testGroup.POST("/rate-limit-reset", s.testRateLimitReset)
		testGroup.GET("/rate-limit-stats", s.testRateLimitStats)

		// Circuit breaker test endpoints
		testGroup.GET("/circuit-breaker", s.testCircuitBreaker)
		testGroup.POST("/force-failure/:service", s.testForceFailure)
	}

	// Main API routes (protected)
	api := s.router.Group("/api")
	api.Use(middleware.JWTAuth(s.config.JWT, s.logger))
	{
		// Proxy for all backend services
		api.Any("/*path", s.proxy.Handle)
	}
}

// healthCheck endpoint for health check
func (s *Server) healthCheck(c *gin.Context) {
	// Include circuit breaker health in the response
	cbHealth := s.circuitBreaker.HealthCheck()

	response := gin.H{
		"status":          "healthy",
		"service":         "sentinel-gate",
		"version":         "1.0.0",
		"circuit_breaker": cbHealth,
	}

	c.JSON(http.StatusOK, response)
}

// readinessCheck endpoint for readiness check
func (s *Server) readinessCheck(c *gin.Context) {
	checks := map[string]string{
		"gateway": "ok",
	}

	// Check Redis connectivity
	redisStatus := "ok"
	if err := s.rateLimiter.GetRedisHealth(); err != nil {
		redisStatus = fmt.Sprintf("error: %v", err)
		s.logger.Warn("Redis health check failed", zap.Error(err))
	}
	checks["redis"] = redisStatus

	// Check circuit breaker health
	cbHealth := s.circuitBreaker.HealthCheck()
	checks["circuit_breaker"] = "ok"
	if cbCount, ok := cbHealth["circuit_breakers_count"].(int); ok && cbCount > 0 {
		// Check if any circuit breakers are in OPEN state
		if cbStates, ok := cbHealth["circuit_breakers"].(map[string]interface{}); ok {
			for service, state := range cbStates {
				if stateMap, ok := state.(map[string]interface{}); ok {
					if stateStr, ok := stateMap["state"].(string); ok && stateStr == "OPEN" {
						checks["circuit_breaker"] = fmt.Sprintf("warning: %s circuit is OPEN", service)
						break
					}
				}
			}
		}
	}

	allHealthy := true
	for _, status := range checks {
		if !strings.HasPrefix(status, "ok") && !strings.HasPrefix(status, "warning") {
			allHealthy = false
			break
		}
	}

	statusCode := http.StatusOK
	if !allHealthy {
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, gin.H{
		"status": map[string]interface{}{
			"ready":  allHealthy,
			"checks": checks,
		},
	})
}

// getCircuitBreakerStatus returns the status of all circuit breakers
func (s *Server) getCircuitBreakerStatus(c *gin.Context) {
	states := s.proxy.GetCircuitBreakerStates()

	c.JSON(http.StatusOK, gin.H{
		"circuit_breakers": states,
		"timestamp":        time.Now().UTC(),
	})
}

// getCircuitBreakerMetrics returns circuit breaker metrics
func (s *Server) getCircuitBreakerMetrics(c *gin.Context) {
	metrics := s.proxy.GetCircuitBreakerMetrics()

	c.JSON(http.StatusOK, gin.H{
		"metrics":   metrics,
		"timestamp": time.Now().UTC(),
	})
}

// resetCircuitBreaker resets a specific circuit breaker
func (s *Server) resetCircuitBreaker(c *gin.Context) {
	serviceName := c.Param("service")
	if serviceName == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Missing service name",
			"message": "Service name is required in the URL path",
		})
		return
	}

	s.proxy.ResetCircuitBreaker(serviceName)

	s.logger.Info("Circuit breaker reset via admin endpoint",
		zap.String("service", serviceName),
		zap.String("admin_user", c.GetString("username")),
	)

	c.JSON(http.StatusOK, gin.H{
		"message":    fmt.Sprintf("Circuit breaker for service '%s' has been reset", serviceName),
		"service":    serviceName,
		"reset_by":   c.GetString("username"),
		"reset_time": time.Now().UTC(),
	})
}

// testCircuitBreaker tests circuit breaker functionality
func (s *Server) testCircuitBreaker(c *gin.Context) {
	states := s.proxy.GetCircuitBreakerStates()
	metrics := s.proxy.GetCircuitBreakerMetrics()

	c.JSON(http.StatusOK, gin.H{
		"message":        "Circuit breaker test endpoint",
		"states":         states,
		"metrics":        metrics,
		"config_enabled": s.config.CircuitBreaker.Enabled,
		"config_settings": gin.H{
			"max_requests":      s.config.CircuitBreaker.MaxRequests,
			"min_requests":      s.config.CircuitBreaker.MinRequests,
			"failure_threshold": s.config.CircuitBreaker.FailureThreshold,
			"interval":          s.config.CircuitBreaker.Interval.String(),
			"timeout":           s.config.CircuitBreaker.Timeout.String(),
		},
		"timestamp": time.Now().UTC(),
	})
}

// testForceFailure simulates a service failure for testing circuit breaker
func (s *Server) testForceFailure(c *gin.Context) {
	serviceName := c.Param("service")
	if serviceName == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Missing service name",
			"message": "Service name is required in the URL path",
		})
		return
	}

	// This is a test endpoint that simulates failures
	// In a real scenario, this would trigger actual failures in the service
	c.JSON(http.StatusInternalServerError, gin.H{
		"error":     "Simulated failure",
		"message":   fmt.Sprintf("Simulated failure for service '%s' to test circuit breaker", serviceName),
		"service":   serviceName,
		"timestamp": time.Now().UTC(),
	})

	s.logger.Warn("Simulated service failure for circuit breaker testing",
		zap.String("service", serviceName),
		zap.String("client_ip", c.ClientIP()),
	)
}

// testPublic endpoint to test public access
func (s *Server) testPublic(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":    "This is a public endpoint",
		"accessible": "without authentication",
		"timestamp":  gin.H{"iso": "2023-01-01T00:00:00Z"},
		"request_id": c.GetString("request_id"),
	})
}

// testProtected endpoint to test JWT protection
func (s *Server) testProtected(c *gin.Context) {
	authCtx, exists := c.Get("auth")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":      "MISSING_AUTH_CONTEXT",
			"message":    "Authentication context not found",
			"request_id": c.GetString("request_id"),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "This is a protected endpoint",
		"accessible": "only with valid JWT token",
		"auth_info":  authCtx,
		"request_id": c.GetString("request_id"),
		"timestamp":  time.Now(),
	})
}

// testAdmin endpoint to test admin role protection
func (s *Server) testAdmin(c *gin.Context) {
	authCtx, _ := c.Get("auth")
	auth := authCtx.(middleware.AuthContext)

	c.JSON(http.StatusOK, gin.H{
		"message": "This is an admin-only endpoint",
		"user": gin.H{
			"id":       auth.UserID,
			"username": auth.Username,
			"role":     auth.Role,
		},
		"privileges": []string{"read", "write", "delete", "admin"},
		"request_id": c.GetString("request_id"),
	})
}

// testUser endpoint to test user role protection
func (s *Server) testUser(c *gin.Context) {
	authCtx, _ := c.Get("auth")
	auth := authCtx.(middleware.AuthContext)

	c.JSON(http.StatusOK, gin.H{
		"message": "This endpoint is accessible by users and admins",
		"user": gin.H{
			"id":       auth.UserID,
			"username": auth.Username,
			"role":     auth.Role,
		},
		"privileges": []string{"read", "write"},
		"request_id": c.GetString("request_id"),
	})
}

// testTokenValidation endpoint to validate and inspect current token
func (s *Server) testTokenValidation(c *gin.Context) {
	authCtx, _ := c.Get("auth")
	auth := authCtx.(middleware.AuthContext)

	// Extract token for inspection
	token := middleware.ExtractTokenFromHeader(c)

	c.JSON(http.StatusOK, gin.H{
		"message": "Token validation successful",
		"token": gin.H{
			"valid":    true,
			"user_id":  auth.UserID,
			"username": auth.Username,
			"role":     auth.Role,
			"email":    auth.Email,
			"token_id": auth.TokenID,
			"preview":  middleware.MaskToken(token),
		},
		"request_id": c.GetString("request_id"),
	})
}

// testRateLimit endpoint to test rate limiting
func (s *Server) testRateLimit(c *gin.Context) {
	clientIP := c.ClientIP()
	requestID := c.GetString("request_id")

	c.JSON(http.StatusOK, gin.H{
		"message":    "Rate limit test endpoint - successful request",
		"client_ip":  clientIP,
		"request_id": requestID,
		"timestamp":  time.Now(),
		"headers": gin.H{
			"x-ratelimit-limit":     c.GetHeader("X-RateLimit-Limit"),
			"x-ratelimit-remaining": c.GetHeader("X-RateLimit-Remaining"),
			"x-ratelimit-reset":     c.GetHeader("X-RateLimit-Reset"),
			"x-ratelimit-type":      c.GetHeader("X-RateLimit-Type"),
		},
	})
}

// testRateLimitAuth endpoint to test rate limiting with authentication
func (s *Server) testRateLimitAuth(c *gin.Context) {
	authCtx, exists := c.Get("auth")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "MISSING_AUTH_CONTEXT",
			"message": "Authentication context not found",
		})
		return
	}

	auth := authCtx.(middleware.AuthContext)
	clientIP := c.ClientIP()
	requestID := c.GetString("request_id")

	c.JSON(http.StatusOK, gin.H{
		"message":    "Authenticated rate limit test - successful request",
		"client_ip":  clientIP,
		"request_id": requestID,
		"user": gin.H{
			"id":       auth.UserID,
			"username": auth.Username,
			"role":     auth.Role,
		},
		"timestamp": time.Now(),
		"headers": gin.H{
			"x-ratelimit-limit":     c.GetHeader("X-RateLimit-Limit"),
			"x-ratelimit-remaining": c.GetHeader("X-RateLimit-Remaining"),
			"x-ratelimit-reset":     c.GetHeader("X-RateLimit-Reset"),
			"x-ratelimit-type":      c.GetHeader("X-RateLimit-Type"),
		},
	})
}

// testRateLimitReset endpoint to reset rate limiting
func (s *Server) testRateLimitReset(c *gin.Context) {
	limitType := c.DefaultQuery("type", "ip")
	identifier := c.DefaultQuery("identifier", "")

	if identifier == "" {
		if limitType == "ip" {
			identifier = c.ClientIP()
		} else {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "MISSING_IDENTIFIER",
				"message": "Identifier is required for non-IP rate limit types",
			})
			return
		}
	}

	var rateLimitType ratelimiter.RateLimitType
	switch limitType {
	case "ip":
		rateLimitType = ratelimiter.RateLimitByIP
	case "token":
		rateLimitType = ratelimiter.RateLimitByToken
	case "user":
		rateLimitType = ratelimiter.RateLimitByUser
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "INVALID_TYPE",
			"message": "Invalid rate limit type. Use: ip, token, or user",
		})
		return
	}

	err := s.rateLimiter.ResetRateLimit(rateLimitType, identifier)
	if err != nil {
		s.logger.Error("Failed to reset rate limit",
			zap.Error(err),
			zap.String("type", limitType),
			zap.String("identifier", identifier),
		)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "RESET_FAILED",
			"message": "Failed to reset rate limit",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Rate limit reset successfully",
		"type":       limitType,
		"identifier": identifier,
		"timestamp":  time.Now(),
	})
}

// testRateLimitStats endpoint to get rate limiting stats
func (s *Server) testRateLimitStats(c *gin.Context) {
	limitType := c.DefaultQuery("type", "ip")
	identifier := c.DefaultQuery("identifier", "")

	if identifier == "" {
		if limitType == "ip" {
			identifier = c.ClientIP()
		} else {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "MISSING_IDENTIFIER",
				"message": "Identifier is required for non-IP rate limit types",
			})
			return
		}
	}

	var rateLimitType ratelimiter.RateLimitType
	switch limitType {
	case "ip":
		rateLimitType = ratelimiter.RateLimitByIP
	case "token":
		rateLimitType = ratelimiter.RateLimitByToken
	case "user":
		rateLimitType = ratelimiter.RateLimitByUser
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "INVALID_TYPE",
			"message": "Invalid rate limit type. Use: ip, token, or user",
		})
		return
	}

	stats, err := s.rateLimiter.GetRateLimitStats(rateLimitType, identifier)
	if err != nil {
		s.logger.Error("Failed to get rate limit stats",
			zap.Error(err),
			zap.String("type", limitType),
			zap.String("identifier", identifier),
		)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "STATS_FAILED",
			"message": "Failed to get rate limit statistics",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Rate limit statistics",
		"type":       limitType,
		"identifier": identifier,
		"stats": gin.H{
			"allowed":      stats.Allowed,
			"remaining":    stats.Remaining,
			"limit_value":  stats.LimitValue,
			"reset_time":   stats.ResetTime,
			"window_start": stats.WindowStart,
			"window_end":   stats.WindowEnd,
		},
		"timestamp": time.Now(),
	})
}
