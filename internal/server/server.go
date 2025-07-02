package server

import (
	"fmt"
	"net/http"

	"sentinel_gate/internal/auth"
	"sentinel_gate/internal/middleware"
	"sentinel_gate/internal/proxy"
	"sentinel_gate/pkg/config"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Server representa o servidor HTTP
type Server struct {
	config *config.Config
	logger *zap.Logger
	router *gin.Engine
	proxy  *proxy.Proxy
}

// New cria uma nova instância do servidor
func New(cfg *config.Config, logger *zap.Logger) (*Server, error) {
	// Configurar modo do Gin baseado no ambiente
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Criar proxy para backend services
	proxyHandler, err := proxy.New(cfg.Proxy, logger)
	if err != nil {
		return nil, fmt.Errorf("erro ao criar proxy: %w", err)
	}

	server := &Server{
		config: cfg,
		logger: logger,
		router: gin.New(),
		proxy:  proxyHandler,
	}

	// Configurar middlewares e rotas
	server.setupMiddlewares()
	server.setupRoutes()

	return server, nil
}

// Handler retorna o handler HTTP
func (s *Server) Handler() http.Handler {
	return s.router
}

// setupMiddlewares configura os middlewares globais
func (s *Server) setupMiddlewares() {
	// Recovery middleware
	s.router.Use(gin.Recovery())

	// CORS middleware
	s.router.Use(middleware.CORS())

	// Logger middleware
	s.router.Use(middleware.Logger(s.logger))

	// Metrics middleware
	s.router.Use(middleware.Metrics())

	// Request ID middleware
	s.router.Use(middleware.RequestID())

	// Rate limiting middleware
	s.router.Use(middleware.RateLimit(s.config.RateLimit, s.logger))
}

// setupRoutes configura as rotas da aplicação
func (s *Server) setupRoutes() {
	// Health check endpoint (sem autenticação)
	s.router.GET("/health", s.healthCheck)
	s.router.GET("/ready", s.readinessCheck)

	// Metrics endpoint (sem autenticação)
	s.router.GET("/metrics", gin.WrapH(http.DefaultServeMux))

	// Auth endpoints
	authGroup := s.router.Group("/auth")
	{
		authGroup.POST("/login", auth.Login(s.config.JWT, s.logger))
		authGroup.POST("/refresh", auth.RefreshToken(s.config.JWT, s.logger))
		authGroup.POST("/logout", auth.Logout(s.logger))
	}

	// Protected routes - todas as rotas da API passam por aqui
	api := s.router.Group("/api")
	api.Use(middleware.JWTAuth(s.config.JWT, s.logger))
	api.Use(middleware.CircuitBreaker(s.config.CircuitBreaker, s.logger))
	{
		// Proxy para todos os serviços backend
		api.Any("/*path", s.proxy.Handle)
	}
}

// healthCheck endpoint para verificação de saúde
func (s *Server) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "sentinel-gate",
		"version": "1.0.0",
	})
}

// readinessCheck endpoint para verificação de prontidão
func (s *Server) readinessCheck(c *gin.Context) {
	// Aqui você pode adicionar verificações mais complexas
	// como conectividade com Redis, banco de dados, etc.

	checks := map[string]string{
		"gateway": "ok",
		"redis":   "ok", // TODO: implementar verificação real do Redis
	}

	allHealthy := true
	for _, status := range checks {
		if status != "ok" {
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
