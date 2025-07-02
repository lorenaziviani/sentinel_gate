package middleware

import (
	"fmt"
	"strconv"
	"time"

	"sentinel_gate/internal/ratelimiter"
	"sentinel_gate/pkg/config"
	"sentinel_gate/pkg/telemetry"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

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
			)

			c.JSON(429, gin.H{
				"error":   "Rate limit exceeded",
				"message": "Too many requests. Please try again later.",
			})
			c.Abort()
			return
		}

		c.Next()
	})
}

// JWTAuth middleware for JWT authentication
func JWTAuth(cfg config.JWTConfig, logger *zap.Logger) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		tokenString := extractTokenFromHeader(c)
		if tokenString == "" {
			c.JSON(401, gin.H{
				"error":   "Unauthorized",
				"message": "Missing or invalid authorization header",
			})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(cfg.Secret), nil
		})

		if err != nil {
			logger.Warn("JWT parsing error",
				zap.Error(err),
				zap.String("client_ip", c.ClientIP()),
			)
			c.JSON(401, gin.H{
				"error":   "Unauthorized",
				"message": "Invalid token",
			})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if exp, ok := claims["exp"].(float64); ok {
				if time.Now().Unix() > int64(exp) {
					c.JSON(401, gin.H{
						"error":   "Unauthorized",
						"message": "Token expired",
					})
					c.Abort()
					return
				}
			}

			c.Set("user_id", claims["user_id"])
			c.Set("username", claims["username"])
			c.Set("role", claims["role"])
		} else {
			c.JSON(401, gin.H{
				"error":   "Unauthorized",
				"message": "Invalid token claims",
			})
			c.Abort()
			return
		}

		c.Next()
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

// extractTokenFromHeader extracts the JWT token from the Authorization header
func extractTokenFromHeader(c *gin.Context) string {
	bearerToken := c.GetHeader("Authorization")
	if len(bearerToken) > 7 && bearerToken[:7] == "Bearer " {
		return bearerToken[7:]
	}
	return ""
}
