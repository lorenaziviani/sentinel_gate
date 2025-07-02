package auth

import (
	"net/http"
	"time"

	"sentinel_gate/pkg/config"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// LoginRequest represents the login request data
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents the login response data
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// RefreshRequest represents the refresh token request data
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// Claims represents the custom JWT claims
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// Login handler for user authentication
func Login(cfg config.JWTConfig, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		// TODO: Implement real credential verification
		if req.Username == "" || req.Password == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Invalid credentials",
				"message": "Username and password are required",
			})
			return
		}

		// Simulate credential verification
		userID := "123"
		role := "user"
		if req.Username == "admin" {
			role = "admin"
		}

		// Generate tokens
		accessToken, err := generateAccessToken(cfg, userID, req.Username, role)
		if err != nil {
			logger.Error("Error generating access token", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Internal server error",
				"message": "Could not generate access token",
			})
			return
		}

		refreshToken, err := generateRefreshToken(cfg, userID, req.Username, role)
		if err != nil {
			logger.Error("Error generating refresh token", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Internal server error",
				"message": "Could not generate refresh token",
			})
			return
		}

		logger.Info("Login successful",
			zap.String("username", req.Username),
			zap.String("role", role),
			zap.String("client_ip", c.ClientIP()),
		)

		c.JSON(http.StatusOK, LoginResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			TokenType:    "Bearer",
			ExpiresIn:    int64(cfg.ExpirationTime.Seconds()),
		})
	}
}

// RefreshToken handler for token refresh
func RefreshToken(cfg config.JWTConfig, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RefreshRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		token, err := jwt.ParseWithClaims(req.RefreshToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.Secret), nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Invalid refresh token",
				"message": err.Error(),
			})
			return
		}

		if claims, ok := token.Claims.(*Claims); ok && token.Valid {
			// Generate new access token
			accessToken, err := generateAccessToken(cfg, claims.UserID, claims.Username, claims.Role)
			if err != nil {
				logger.Error("Error generating new access token", zap.Error(err))
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":   "Internal server error",
					"message": "Could not generate new access token",
				})
				return
			}

			logger.Info("Token refreshed",
				zap.String("username", claims.Username),
				zap.String("client_ip", c.ClientIP()),
			)

			c.JSON(http.StatusOK, LoginResponse{
				AccessToken:  accessToken,
				RefreshToken: req.RefreshToken, // Reuse the same refresh token
				TokenType:    "Bearer",
				ExpiresIn:    int64(cfg.ExpirationTime.Seconds()),
			})
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Invalid refresh token",
				"message": "Token claims are invalid",
			})
		}
	}
}

// Logout handler for user logout
func Logout(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Implement token blacklist if needed

		userID, _ := c.Get("user_id")
		username, _ := c.Get("username")

		logger.Info("User logout",
			zap.Any("user_id", userID),
			zap.Any("username", username),
			zap.String("client_ip", c.ClientIP()),
		)

		c.JSON(http.StatusOK, gin.H{
			"message": "Logout successful",
		})
	}
}

// generateAccessToken generates a new access token
func generateAccessToken(cfg config.JWTConfig, userID, username, role string) (string, error) {
	claims := Claims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(cfg.ExpirationTime)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    cfg.Issuer,
			Subject:   userID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.Secret))
}

// generateRefreshToken generates a new refresh token
func generateRefreshToken(cfg config.JWTConfig, userID, username, role string) (string, error) {
	claims := Claims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(cfg.RefreshTime)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    cfg.Issuer,
			Subject:   userID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.Secret))
}
