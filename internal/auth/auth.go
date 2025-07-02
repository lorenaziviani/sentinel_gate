package auth

import (
	"net/http"
	"time"

	"sentinel_gate/internal/middleware"
	"sentinel_gate/pkg/config"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// LoginRequest represents the login request data
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents the login response data
type LoginResponse struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int64    `json:"expires_in"`
	User         UserInfo `json:"user"`
}

// RefreshRequest represents the refresh token request data
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// UserInfo represents user information in responses
type UserInfo struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Email    string `json:"email,omitempty"`
}

// Login handler for user authentication
func Login(cfg config.JWTConfig, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetString("request_id")

		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			logger.Warn("Invalid login request",
				zap.String("request_id", requestID),
				zap.Error(err),
				zap.String("client_ip", c.ClientIP()),
			)

			c.JSON(http.StatusBadRequest, gin.H{
				"error":      "INVALID_REQUEST",
				"message":    "Invalid login request format",
				"details":    err.Error(),
				"request_id": requestID,
			})
			return
		}

		// TODO: Implement real credential verification with database/LDAP
		if req.Username == "" || req.Password == "" {
			logger.Warn("Login attempt with empty credentials",
				zap.String("request_id", requestID),
				zap.String("username", req.Username),
				zap.String("client_ip", c.ClientIP()),
			)

			c.JSON(http.StatusUnauthorized, gin.H{
				"error":      "INVALID_CREDENTIALS",
				"message":    "Username and password are required",
				"request_id": requestID,
			})
			return
		}

		// Simulate credential verification with different user types
		userID := uuid.New().String()
		role := "user"
		email := ""

		switch req.Username {
		case "admin":
			role = "admin"
			email = "admin@example.com"
		case "user":
			role = "user"
			email = "user@example.com"
		case "manager":
			role = "manager"
			email = "manager@example.com"
		default:
			// Simulate user not found
			logger.Warn("Login attempt with invalid username",
				zap.String("request_id", requestID),
				zap.String("username", req.Username),
				zap.String("client_ip", c.ClientIP()),
			)

			c.JSON(http.StatusUnauthorized, gin.H{
				"error":      "INVALID_CREDENTIALS",
				"message":    "Invalid username or password",
				"request_id": requestID,
			})
			return
		}

		// Simulate password verification (in production, use bcrypt)
		if req.Password != "password123" {
			logger.Warn("Login attempt with invalid password",
				zap.String("request_id", requestID),
				zap.String("username", req.Username),
				zap.String("client_ip", c.ClientIP()),
			)

			c.JSON(http.StatusUnauthorized, gin.H{
				"error":      "INVALID_CREDENTIALS",
				"message":    "Invalid username or password",
				"request_id": requestID,
			})
			return
		}

		// Generate tokens
		accessToken, err := generateAccessToken(cfg, userID, req.Username, role, email)
		if err != nil {
			logger.Error("Error generating access token",
				zap.String("request_id", requestID),
				zap.Error(err),
				zap.String("username", req.Username),
			)

			c.JSON(http.StatusInternalServerError, gin.H{
				"error":      "TOKEN_GENERATION_FAILED",
				"message":    "Could not generate access token",
				"request_id": requestID,
			})
			return
		}

		refreshToken, err := generateRefreshToken(cfg, userID, req.Username, role, email)
		if err != nil {
			logger.Error("Error generating refresh token",
				zap.String("request_id", requestID),
				zap.Error(err),
				zap.String("username", req.Username),
			)

			c.JSON(http.StatusInternalServerError, gin.H{
				"error":      "TOKEN_GENERATION_FAILED",
				"message":    "Could not generate refresh token",
				"request_id": requestID,
			})
			return
		}

		logger.Info("Login successful",
			zap.String("request_id", requestID),
			zap.String("user_id", userID),
			zap.String("username", req.Username),
			zap.String("role", role),
			zap.String("client_ip", c.ClientIP()),
		)

		c.JSON(http.StatusOK, LoginResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			TokenType:    "Bearer",
			ExpiresIn:    int64(cfg.ExpirationTime.Seconds()),
			User: UserInfo{
				ID:       userID,
				Username: req.Username,
				Role:     role,
				Email:    email,
			},
		})
	}
}

// RefreshToken handler for token refresh
func RefreshToken(cfg config.JWTConfig, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetString("request_id")

		var req RefreshRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			logger.Warn("Invalid refresh request",
				zap.String("request_id", requestID),
				zap.Error(err),
				zap.String("client_ip", c.ClientIP()),
			)

			c.JSON(http.StatusBadRequest, gin.H{
				"error":      "INVALID_REQUEST",
				"message":    "Invalid refresh request format",
				"details":    err.Error(),
				"request_id": requestID,
			})
			return
		}

		token, err := jwt.ParseWithClaims(req.RefreshToken, &middleware.UserClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.Secret), nil
		})

		if err != nil {
			logger.Warn("Invalid refresh token",
				zap.String("request_id", requestID),
				zap.Error(err),
				zap.String("client_ip", c.ClientIP()),
				zap.String("token_preview", middleware.MaskToken(req.RefreshToken)),
			)

			c.JSON(http.StatusUnauthorized, gin.H{
				"error":      "INVALID_REFRESH_TOKEN",
				"message":    "Invalid or malformed refresh token",
				"request_id": requestID,
			})
			return
		}

		if claims, ok := token.Claims.(*middleware.UserClaims); ok && token.Valid {
			if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
				logger.Warn("Expired refresh token",
					zap.String("request_id", requestID),
					zap.String("username", claims.Username),
					zap.Time("expired_at", claims.ExpiresAt.Time),
					zap.String("client_ip", c.ClientIP()),
				)

				c.JSON(http.StatusUnauthorized, gin.H{
					"error":      "REFRESH_TOKEN_EXPIRED",
					"message":    "Refresh token has expired",
					"request_id": requestID,
				})
				return
			}

			accessToken, err := generateAccessToken(cfg, claims.UserID, claims.Username, claims.Role, claims.Email)
			if err != nil {
				logger.Error("Error generating new access token",
					zap.String("request_id", requestID),
					zap.Error(err),
					zap.String("username", claims.Username),
				)

				c.JSON(http.StatusInternalServerError, gin.H{
					"error":      "TOKEN_GENERATION_FAILED",
					"message":    "Could not generate new access token",
					"request_id": requestID,
				})
				return
			}

			logger.Info("Token refreshed",
				zap.String("request_id", requestID),
				zap.String("user_id", claims.UserID),
				zap.String("username", claims.Username),
				zap.String("client_ip", c.ClientIP()),
			)

			c.JSON(http.StatusOK, LoginResponse{
				AccessToken:  accessToken,
				RefreshToken: req.RefreshToken, // Reuse the same refresh token
				TokenType:    "Bearer",
				ExpiresIn:    int64(cfg.ExpirationTime.Seconds()),
				User: UserInfo{
					ID:       claims.UserID,
					Username: claims.Username,
					Role:     claims.Role,
					Email:    claims.Email,
				},
			})
		} else {
			logger.Warn("Invalid refresh token claims",
				zap.String("request_id", requestID),
				zap.String("client_ip", c.ClientIP()),
				zap.Bool("token_valid", token.Valid),
			)

			c.JSON(http.StatusUnauthorized, gin.H{
				"error":      "INVALID_REFRESH_TOKEN",
				"message":    "Refresh token claims are invalid",
				"request_id": requestID,
			})
		}
	}
}

// Logout handler for user logout
func Logout(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetString("request_id")

		// TODO: Implement token blacklist for security
		// For now, we'll just log the logout event

		authCtx, exists := c.Get("auth")
		if exists {
			auth := authCtx.(middleware.AuthContext)

			logger.Info("User logout",
				zap.String("request_id", requestID),
				zap.String("user_id", auth.UserID),
				zap.String("username", auth.Username),
				zap.String("role", auth.Role),
				zap.String("client_ip", c.ClientIP()),
			)

			c.JSON(http.StatusOK, gin.H{
				"message":    "Logout successful",
				"user_id":    auth.UserID,
				"username":   auth.Username,
				"request_id": requestID,
			})
		} else {
			// Fallback for cases where auth context is not available
			userID, _ := c.Get("user_id")
			username, _ := c.Get("username")

			logger.Info("User logout (fallback)",
				zap.String("request_id", requestID),
				zap.Any("user_id", userID),
				zap.Any("username", username),
				zap.String("client_ip", c.ClientIP()),
			)

			c.JSON(http.StatusOK, gin.H{
				"message":    "Logout successful",
				"request_id": requestID,
			})
		}
	}
}

// generateAccessToken generates a new access token
func generateAccessToken(cfg config.JWTConfig, userID, username, role, email string) (string, error) {
	tokenID := uuid.New().String()

	claims := middleware.UserClaims{
		UserID:   userID,
		Username: username,
		Role:     role,
		Email:    email,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(cfg.ExpirationTime)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    cfg.Issuer,
			Subject:   userID,
			Audience:  []string{"sentinel-gate"},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.Secret))
}

// generateRefreshToken generates a new refresh token
func generateRefreshToken(cfg config.JWTConfig, userID, username, role, email string) (string, error) {
	tokenID := uuid.New().String()

	claims := middleware.UserClaims{
		UserID:   userID,
		Username: username,
		Role:     role,
		Email:    email,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(cfg.RefreshTime)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    cfg.Issuer,
			Subject:   userID,
			Audience:  []string{"sentinel-gate-refresh"},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.Secret))
}
