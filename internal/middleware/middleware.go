package middleware

import (
	"fmt"
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
	return gin.LoggerWithConfig(gin.LoggerConfig{
		Formatter: func(param gin.LogFormatterParams) string {
			logger.Info("HTTP Request",
				zap.String("method", param.Method),
				zap.String("path", param.Path),
				zap.Int("status", param.StatusCode),
				zap.Duration("latency", param.Latency),
				zap.String("client_ip", param.ClientIP),
				zap.String("user_agent", param.Request.UserAgent()),
			)
			return ""
		},
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

// RateLimit middleware to control the rate
func RateLimit(cfg config.RateLimitConfig, logger *zap.Logger) gin.HandlerFunc {
	limiter := ratelimiter.New(cfg, logger)

	return gin.HandlerFunc(func(c *gin.Context) {
		clientIP := c.ClientIP()

		if !limiter.Allow(clientIP) {
			telemetry.IncrementRateLimitExceeded(c.Request.Context(), clientIP)

			logger.Warn("Rate limit exceeded",
				zap.String("client_ip", clientIP),
				zap.String("path", c.Request.URL.Path),
				zap.String("request_id", c.GetString("request_id")),
			)

			c.JSON(429, gin.H{
				"error":      "RATE_LIMIT_EXCEEDED",
				"message":    "Too many requests. Please try again later.",
				"request_id": c.GetString("request_id"),
			})
			c.Abort()
			return
		}

		c.Next()
	})
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
