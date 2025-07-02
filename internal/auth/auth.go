package auth

import (
	"net/http"
	"time"

	"sentinel_gate/pkg/config"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// LoginRequest representa os dados de login
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse representa a resposta do login
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// RefreshRequest representa os dados para refresh do token
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// Claims representa os claims customizados do JWT
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// Login handler para autenticação de usuários
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

		// TODO: Implementar verificação real de credenciais
		// Por enquanto, aceita qualquer usuário/senha para demonstração
		if req.Username == "" || req.Password == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Invalid credentials",
				"message": "Username and password are required",
			})
			return
		}

		// Simular verificação de credenciais
		userID := "123"
		role := "user"
		if req.Username == "admin" {
			role = "admin"
		}

		// Gerar tokens
		accessToken, err := generateAccessToken(cfg, userID, req.Username, role)
		if err != nil {
			logger.Error("Erro ao gerar access token", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Internal server error",
				"message": "Could not generate access token",
			})
			return
		}

		refreshToken, err := generateRefreshToken(cfg, userID, req.Username, role)
		if err != nil {
			logger.Error("Erro ao gerar refresh token", zap.Error(err))
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

// RefreshToken handler para renovação de tokens
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

		// Validar refresh token
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
			// Gerar novo access token
			accessToken, err := generateAccessToken(cfg, claims.UserID, claims.Username, claims.Role)
			if err != nil {
				logger.Error("Erro ao gerar novo access token", zap.Error(err))
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
				RefreshToken: req.RefreshToken, // Reutilizar o mesmo refresh token
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

// Logout handler para logout de usuários
func Logout(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Implementar blacklist de tokens se necessário
		// Por enquanto, apenas log do logout

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

// generateAccessToken gera um novo access token
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

// generateRefreshToken gera um novo refresh token
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
