package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sentinel_gate/internal/ratelimiter"
	"sentinel_gate/pkg/config"
	"sentinel_gate/pkg/telemetry"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Context keys for storing values
type contextKey string

const (
	RequestIDKey contextKey = "request_id"
	AuthCtxKey   contextKey = "auth_context"
)

// ErrorResponse represents a standard error response
type ErrorResponse struct {
	Error      string    `json:"error"`
	Message    string    `json:"message"`
	Details    string    `json:"details,omitempty"`
	RequestID  string    `json:"request_id"`
	StatusCode int       `json:"-"`
	Timestamp  time.Time `json:"timestamp"`
}

// UserClaims represents the custom JWT claims
type UserClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Email    string `json:"email,omitempty"`
	jwt.RegisteredClaims
}

// AuthContext contains authentication information
type AuthContext struct {
	UserID   string
	Username string
	Role     string
	Email    string
	TokenID  string
}

// GetRequestID extracts request ID from context
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(RequestIDKey).(string); ok {
		return requestID
	}
	return ""
}

// GetAuthContext extracts auth context from context
func GetAuthContext(ctx context.Context) *AuthContext {
	if authCtx, ok := ctx.Value(AuthCtxKey).(*AuthContext); ok {
		return authCtx
	}
	return nil
}

// writeErrorResponse writes a standard error response
func writeErrorResponse(w http.ResponseWriter, errResp ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(errResp.StatusCode)

	if err := json.NewEncoder(w).Encode(errResp); err != nil {
		// Fallback if JSON encoding fails
		http.Error(w, errResp.Message, errResp.StatusCode)
	}
}

// CORS middleware to allow cross-origin requests
func CORS() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})
}

// Logger middleware for structured logging
func Logger(logger *zap.Logger) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		start := time.Now()
		c.Next()

		logger.Info("HTTP Request",
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", time.Since(start)),
			zap.String("client_ip", c.ClientIP()),
			zap.String("user_agent", c.Request.UserAgent()),
		)
	})
}

// DetailedLogger middleware for comprehensive request logging including JWT details
func DetailedLogger(logger *zap.Logger) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		start := time.Now()
		requestID := c.GetString("request_id")

		logger.Info("Request started",
			zap.String("request_id", requestID),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.String("client_ip", c.ClientIP()),
			zap.String("user_agent", c.Request.UserAgent()),
			zap.String("authorization", maskAuthHeader(c.GetHeader("Authorization"))),
		)

		c.Next()

		fields := []zap.Field{
			zap.String("request_id", requestID),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", time.Since(start)),
			zap.String("client_ip", c.ClientIP()),
		}

		if userID, exists := c.Get("user_id"); exists {
			fields = append(fields, zap.String("user_id", fmt.Sprintf("%v", userID)))
		}
		if username, exists := c.Get("username"); exists {
			fields = append(fields, zap.String("username", fmt.Sprintf("%v", username)))
		}
		if role, exists := c.Get("role"); exists {
			fields = append(fields, zap.String("role", fmt.Sprintf("%v", role)))
		}

		if len(c.Errors) > 0 {
			errorStrings := make([]string, len(c.Errors))
			for i, err := range c.Errors {
				errorStrings[i] = err.Error()
			}
			fields = append(fields, zap.Strings("errors", errorStrings))
		}

		logger.Info("Request completed", fields...)
	})
}

// Metrics middleware to collect metrics
func Metrics() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		start := time.Now()

		telemetry.IncrementActiveConnections(c.Request.Context())
		defer telemetry.DecrementActiveConnections(c.Request.Context())

		c.Next()

		duration := time.Since(start).Seconds()
		status := strconv.Itoa(c.Writer.Status())

		telemetry.IncrementRequestCounter(c.Request.Context(), c.Request.Method, c.FullPath(), status)
		telemetry.RecordResponseTime(c.Request.Context(), duration, c.Request.Method, c.FullPath())
	})
}

// RequestID middleware to add a unique ID to each request
func RequestID() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		c.Header("X-Request-ID", requestID)
		c.Set("request_id", requestID)
		c.Next()
	})
}

// EnhancedRateLimiter provides advanced rate limiting with dynamic rules
type EnhancedRateLimiter struct {
	limiter     *ratelimiter.RateLimiter
	rules       *config.RateLimitRules
	config      *config.Config
	logger      *zap.Logger
	environment string
}

// NewEnhancedRateLimiter creates a new enhanced rate limiter with dynamic rules
func NewEnhancedRateLimiter(cfg *config.Config, logger *zap.Logger) *EnhancedRateLimiter {
	// Load rate limiting rules from file
	rules, err := config.LoadRateLimitRules(cfg.RateLimit.RulesFile)
	if err != nil {
		logger.Warn("Failed to load rate limiting rules, using defaults",
			zap.Error(err),
			zap.String("rules_file", cfg.RateLimit.RulesFile),
		)
		// Create default rules if file loading fails
		rules = createDefaultRules()
	}

	limiter := ratelimiter.New(cfg.RateLimit, logger)

	return &EnhancedRateLimiter{
		limiter:     limiter,
		rules:       rules,
		config:      cfg,
		logger:      logger,
		environment: cfg.Environment,
	}
}

// createDefaultRules creates default rate limiting rules when file loading fails
func createDefaultRules() *config.RateLimitRules {
	return &config.RateLimitRules{
		Global: config.GlobalRateLimit{
			RequestsPerMinute: 100,
			BurstSize:         10,
			WindowSize:        "1m",
			Enabled:           true,
		},
		Routes: []config.RouteRateLimit{},
		Environments: config.EnvironmentConfigs{
			Development: config.EnvironmentConfig{Multiplier: 10, Enabled: false},
			Staging:     config.EnvironmentConfig{Multiplier: 3, Enabled: true},
			Production:  config.EnvironmentConfig{Multiplier: 1, Enabled: true},
		},
		IPWhitelist:   []string{"127.0.0.1", "::1"},
		UserWhitelist: []string{"admin", "system"},
	}
}

// EnhancedRateLimit provides dynamic rate limiting based on route rules
func (erl *EnhancedRateLimiter) EnhancedRateLimit() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			requestID := GetRequestID(ctx)

			// Get environment configuration
			envConfig := erl.rules.GetEnvironmentConfig(erl.environment)
			if !envConfig.Enabled {
				erl.logger.Debug("Rate limiting disabled for environment",
					zap.String("request_id", requestID),
					zap.String("environment", erl.environment),
				)
				next.ServeHTTP(w, r)
				return
			}

			// Get client IP
			clientIP := GetClientIP(r)

			// Check IP whitelist
			if erl.rules.IsIPWhitelisted(clientIP) {
				erl.logger.Debug("IP whitelisted, bypassing rate limit",
					zap.String("request_id", requestID),
					zap.String("client_ip", clientIP),
				)
				next.ServeHTTP(w, r)
				return
			}

			// Check user whitelist if authenticated
			authCtx := GetAuthContext(ctx)
			if authCtx != nil && erl.rules.IsUserWhitelisted(authCtx.Username) {
				erl.logger.Debug("User whitelisted, bypassing rate limit",
					zap.String("request_id", requestID),
					zap.String("username", authCtx.Username),
				)
				next.ServeHTTP(w, r)
				return
			}

			// Find route-specific rules
			routeRules := erl.rules.FindRouteRules(r.URL.Path)

			// Apply rate limiting rules
			var rateLimitResults []*ratelimiter.RateLimitResult

			if routeRules != nil {
				// Apply route-specific rules
				for _, rule := range routeRules.Rules {
					if !rule.Enabled {
						continue
					}

					result := erl.applyRuleWithEnvironment(rule, clientIP, authCtx, envConfig)
					if result != nil {
						rateLimitResults = append(rateLimitResults, result)
						if !result.Allowed {
							erl.handleRateLimitExceeded(w, r, result, requestID)
							return
						}
					}
				}
			} else {
				// Apply global rules
				result := erl.applyGlobalRulesWithEnvironment(clientIP, authCtx, envConfig)
				if !result.Allowed {
					erl.handleRateLimitExceeded(w, r, result, requestID)
					return
				}
				rateLimitResults = append(rateLimitResults, result)
			}

			// Add rate limit headers
			if len(rateLimitResults) > 0 {
				erl.addRateLimitHeaders(w, rateLimitResults[0])
			}

			erl.logger.Debug("Rate limit check passed",
				zap.String("request_id", requestID),
				zap.String("path", r.URL.Path),
				zap.String("client_ip", clientIP),
				zap.Int("rules_applied", len(rateLimitResults)),
			)

			next.ServeHTTP(w, r)
		})
	}
}

// applyRuleWithEnvironment applies a specific rate limiting rule with environment multiplier
func (erl *EnhancedRateLimiter) applyRuleWithEnvironment(rule config.RateLimitRule, clientIP string, authCtx *AuthContext, envConfig *config.EnvironmentConfig) *ratelimiter.RateLimitResult {
	// Parse window size
	windowSize, err := time.ParseDuration(rule.WindowSize)
	if err != nil {
		erl.logger.Warn("Invalid window size in rule, using default",
			zap.String("window_size", rule.WindowSize),
			zap.Error(err),
		)
		windowSize = time.Minute
	}

	// Apply environment multiplier
	adjustedLimit := int(float64(rule.RequestsPerMinute) * envConfig.Multiplier)
	if adjustedLimit < 1 {
		adjustedLimit = 1
	}

	// Determine identifier based on rule type
	var identifier string
	var limitType ratelimiter.RateLimitType

	switch rule.Type {
	case "ip":
		identifier = clientIP
		limitType = ratelimiter.RateLimitByIP
	case "token":
		if authCtx == nil {
			// No token available, skip this rule
			return nil
		}
		identifier = authCtx.UserID
		limitType = ratelimiter.RateLimitByToken
	case "user":
		if authCtx == nil {
			// No user available, skip this rule
			return nil
		}
		identifier = authCtx.Username
		limitType = ratelimiter.RateLimitByUser
	default:
		erl.logger.Warn("Unknown rate limit type", zap.String("type", rule.Type))
		return nil
	}

	// Create rule for limiter
	rateLimitRule := ratelimiter.RateLimitRule{
		Type:              limitType,
		RequestsPerMinute: adjustedLimit,
		BurstSize:         rule.BurstSize,
		WindowSize:        windowSize,
		Enabled:           rule.Enabled,
	}

	return erl.limiter.AllowWithRule(limitType, identifier, rateLimitRule)
}

// applyGlobalRulesWithEnvironment applies global rate limiting rules
func (erl *EnhancedRateLimiter) applyGlobalRulesWithEnvironment(clientIP string, authCtx *AuthContext, envConfig *config.EnvironmentConfig) *ratelimiter.RateLimitResult {
	// Parse global window size
	windowSize, err := time.ParseDuration(erl.rules.Global.WindowSize)
	if err != nil {
		windowSize = time.Minute
	}

	// Apply environment multiplier
	adjustedLimit := int(float64(erl.rules.Global.RequestsPerMinute) * envConfig.Multiplier)
	if adjustedLimit < 1 {
		adjustedLimit = 1
	}

	return erl.limiter.CheckRateLimit(ratelimiter.RateLimitByIP, clientIP, adjustedLimit, windowSize)
}

// handleRateLimitExceeded handles rate limit exceeded scenarios
func (erl *EnhancedRateLimiter) handleRateLimitExceeded(w http.ResponseWriter, r *http.Request, result *ratelimiter.RateLimitResult, requestID string) {
	// Add rate limit headers
	erl.addRateLimitHeaders(w, result)

	// Add Retry-After header
	if result.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(result.RetryAfter.Seconds())))
	}

	erl.logger.Warn("Rate limit exceeded",
		zap.String("request_id", requestID),
		zap.String("path", r.URL.Path),
		zap.String("client_ip", GetClientIP(r)),
		zap.String("limit_type", string(result.LimitType)),
		zap.Int("limit_value", result.LimitValue),
		zap.Int64("remaining", result.Remaining),
		zap.Duration("retry_after", result.RetryAfter),
	)

	writeErrorResponse(w, ErrorResponse{
		Error:      "RATE_LIMIT_EXCEEDED",
		Message:    "Too many requests",
		Details:    fmt.Sprintf("Rate limit exceeded. Try again in %v", result.RetryAfter),
		RequestID:  requestID,
		StatusCode: http.StatusTooManyRequests,
		Timestamp:  time.Now(),
	})
}

// addRateLimitHeaders adds standard rate limiting headers to the response
func (erl *EnhancedRateLimiter) addRateLimitHeaders(w http.ResponseWriter, result *ratelimiter.RateLimitResult) {
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.LimitValue))
	w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(result.Remaining, 10))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetTime.Unix(), 10))
	w.Header().Set("X-RateLimit-Type", string(result.LimitType))
}

// GetClientIP extracts the real client IP from the request
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if net.ParseIP(xri) != nil {
			return xri
		}
	}

	// Fallback to RemoteAddr
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	return r.RemoteAddr
}

// Close closes the enhanced rate limiter
func (erl *EnhancedRateLimiter) Close() error {
	return erl.limiter.Close()
}

// GetRedisHealth checks Redis connectivity
func (erl *EnhancedRateLimiter) GetRedisHealth() error {
	return erl.limiter.GetRedisHealth()
}

// ResetRateLimit resets rate limit for a specific identifier
func (erl *EnhancedRateLimiter) ResetRateLimit(limitType ratelimiter.RateLimitType, identifier string) error {
	return erl.limiter.Reset(limitType, identifier)
}

// GetRateLimitStats gets rate limit statistics
func (erl *EnhancedRateLimiter) GetRateLimitStats(limitType ratelimiter.RateLimitType, identifier string) (*ratelimiter.RateLimitResult, error) {
	return erl.limiter.GetStats(limitType, identifier)
}

// JWTAuth middleware for JWT authentication with enhanced validation
func JWTAuth(cfg config.JWTConfig, logger *zap.Logger) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		requestID := c.GetString("request_id")

		tokenString := ExtractTokenFromHeader(c)
		if tokenString == "" {
			logger.Warn("Missing authorization header",
				zap.String("request_id", requestID),
				zap.String("client_ip", c.ClientIP()),
				zap.String("path", c.Request.URL.Path),
			)

			c.JSON(401, gin.H{
				"error":      "UNAUTHORIZED",
				"message":    "Missing or invalid authorization header",
				"request_id": requestID,
			})
			c.Abort()
			return
		}

		token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(cfg.Secret), nil
		})

		if err != nil {
			logger.Warn("JWT parsing error",
				zap.Error(err),
				zap.String("request_id", requestID),
				zap.String("client_ip", c.ClientIP()),
				zap.String("token_preview", MaskToken(tokenString)),
			)

			c.JSON(401, gin.H{
				"error":      "INVALID_TOKEN",
				"message":    "Invalid or malformed token",
				"request_id": requestID,
			})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(*UserClaims)
		if !ok || !token.Valid {
			logger.Warn("Invalid token claims",
				zap.String("request_id", requestID),
				zap.String("client_ip", c.ClientIP()),
				zap.Bool("token_valid", token.Valid),
				zap.Bool("claims_ok", ok),
			)

			c.JSON(401, gin.H{
				"error":      "INVALID_CLAIMS",
				"message":    "Invalid token claims",
				"request_id": requestID,
			})
			c.Abort()
			return
		}

		if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
			logger.Warn("Token expired",
				zap.String("request_id", requestID),
				zap.String("client_ip", c.ClientIP()),
				zap.String("username", claims.Username),
				zap.Time("expired_at", claims.ExpiresAt.Time),
			)

			c.JSON(401, gin.H{
				"error":      "TOKEN_EXPIRED",
				"message":    "Token has expired",
				"request_id": requestID,
				"expired_at": claims.ExpiresAt.Time,
			})
			c.Abort()
			return
		}

		if claims.NotBefore != nil && claims.NotBefore.Time.After(time.Now()) {
			logger.Warn("Token used before valid time",
				zap.String("request_id", requestID),
				zap.String("client_ip", c.ClientIP()),
				zap.String("username", claims.Username),
				zap.Time("not_before", claims.NotBefore.Time),
			)

			c.JSON(401, gin.H{
				"error":      "TOKEN_NOT_VALID_YET",
				"message":    "Token is not valid yet",
				"request_id": requestID,
			})
			c.Abort()
			return
		}

		if claims.UserID == "" || claims.Username == "" {
			logger.Warn("Missing required claims",
				zap.String("request_id", requestID),
				zap.String("client_ip", c.ClientIP()),
				zap.String("user_id", claims.UserID),
				zap.String("username", claims.Username),
			)

			c.JSON(401, gin.H{
				"error":      "INCOMPLETE_CLAIMS",
				"message":    "Token missing required claims",
				"request_id": requestID,
			})
			c.Abort()
			return
		}

		authCtx := AuthContext{
			UserID:   claims.UserID,
			Username: claims.Username,
			Role:     claims.Role,
			Email:    claims.Email,
			TokenID:  claims.ID,
		}

		c.Set("auth", authCtx)
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		c.Set("email", claims.Email)

		logger.Debug("JWT authentication successful",
			zap.String("request_id", requestID),
			zap.String("user_id", claims.UserID),
			zap.String("username", claims.Username),
			zap.String("role", claims.Role),
			zap.String("client_ip", c.ClientIP()),
		)

		c.Next()
	})
}

// RequireRole middleware to enforce role-based access control
func RequireRole(allowedRoles ...string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		requestID := c.GetString("request_id")
		userRole, exists := c.Get("role")

		if !exists {
			c.JSON(403, gin.H{
				"error":      "MISSING_ROLE",
				"message":    "User role not found in token",
				"request_id": requestID,
			})
			c.Abort()
			return
		}

		role := fmt.Sprintf("%v", userRole)
		for _, allowedRole := range allowedRoles {
			if role == allowedRole {
				c.Next()
				return
			}
		}

		c.JSON(403, gin.H{
			"error":      "INSUFFICIENT_PERMISSIONS",
			"message":    fmt.Sprintf("Required role: %v, current role: %s", allowedRoles, role),
			"request_id": requestID,
		})
		c.Abort()
	})
}

// CircuitBreaker middleware for resilience
func CircuitBreaker(cfg config.CircuitBreakerConfig, logger *zap.Logger) gin.HandlerFunc {
	// TODO: Implement real circuit breaker with gobreaker
	return gin.HandlerFunc(func(c *gin.Context) {
		// TODO: Implement real circuit breaker with gobreaker
		c.Next()
	})
}

// ExtractTokenFromHeader extracts the JWT token from the Authorization header
func ExtractTokenFromHeader(c *gin.Context) string {
	bearerToken := c.GetHeader("Authorization")
	if len(bearerToken) > 7 && strings.HasPrefix(bearerToken, "Bearer ") {
		return bearerToken[7:]
	}
	return ""
}

// MaskToken masks JWT token for logging (shows first 6 and last 6 characters)
func MaskToken(token string) string {
	if len(token) <= 12 {
		return "***"
	}
	return token[:6] + "..." + token[len(token)-6:]
}

// maskAuthHeader masks authorization header for logging
func maskAuthHeader(auth string) string {
	if auth == "" {
		return "none"
	}
	if strings.HasPrefix(auth, "Bearer ") {
		token := auth[7:]
		return "Bearer " + MaskToken(token)
	}
	return "***"
}

// RateLimitMiddleware creates a Gin middleware from the EnhancedRateLimiter
func (erl *EnhancedRateLimiter) RateLimitMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		requestID := c.GetString("request_id")

		ctx := context.WithValue(c.Request.Context(), RequestIDKey, requestID)

		if authValue, exists := c.Get("auth"); exists {
			if auth, ok := authValue.(AuthContext); ok {
				ctx = context.WithValue(ctx, AuthCtxKey, &auth)
			}
		}

		c.Request = c.Request.WithContext(ctx)

		recorder := &responseRecorder{
			ResponseWriter: c.Writer,
			statusCode:     http.StatusOK,
		}

		httpHandler := erl.EnhancedRateLimit()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.Next()
		}))

		httpHandler.ServeHTTP(recorder, c.Request)

		if recorder.statusCode == http.StatusTooManyRequests {
			c.Abort()
		}
	})
}

type responseRecorder struct {
	gin.ResponseWriter
	statusCode int
}

func (rr *responseRecorder) WriteHeader(code int) {
	rr.statusCode = code
	rr.ResponseWriter.WriteHeader(code)
}

// SetRequestIDInContext adds request ID to context for net/http handlers
func SetRequestIDInContext() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		requestID := c.GetString("request_id")
		if requestID == "" {
			requestID = uuid.New().String()
			c.Set("request_id", requestID)
		}

		ctx := context.WithValue(c.Request.Context(), RequestIDKey, requestID)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	})
}

// SetAuthContextInRequest updates request context with auth info for net/http handlers
func SetAuthContextInRequest() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		if authValue, exists := c.Get("auth"); exists {
			if auth, ok := authValue.(AuthContext); ok {
				ctx := context.WithValue(c.Request.Context(), AuthCtxKey, &auth)
				c.Request = c.Request.WithContext(ctx)
			}
		}
		c.Next()
	})
}
