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

// Server represents the HTTP server
type Server struct {
	config *config.Config
	logger *zap.Logger
	router *gin.Engine
	proxy  *proxy.Proxy
}

// New creates a new server instance
func New(cfg *config.Config, logger *zap.Logger) (*Server, error) {
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	proxyHandler, err := proxy.New(cfg.Proxy, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy: %w", err)
	}

	server := &Server{
		config: cfg,
		logger: logger,
		router: gin.New(),
		proxy:  proxyHandler,
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

	s.router.Use(middleware.Metrics())

	s.router.Use(middleware.RequestID())

	s.router.Use(middleware.RateLimit(s.config.RateLimit, s.logger))
}

// setupRoutes configures the application routes
func (s *Server) setupRoutes() {
	s.router.GET("/health", s.healthCheck)
	s.router.GET("/ready", s.readinessCheck)
	s.router.GET("/metrics", gin.WrapH(http.DefaultServeMux))

	authGroup := s.router.Group("/auth")
	{
		authGroup.POST("/login", auth.Login(s.config.JWT, s.logger))
		authGroup.POST("/refresh", auth.RefreshToken(s.config.JWT, s.logger))
		authGroup.POST("/logout", auth.Logout(s.logger))
	}

	api := s.router.Group("/api")
	api.Use(middleware.JWTAuth(s.config.JWT, s.logger))
	api.Use(middleware.CircuitBreaker(s.config.CircuitBreaker, s.logger))
	{
		// Proxy for all backend services
		api.Any("/*path", s.proxy.Handle)
	}
}

// healthCheck endpoint for health check
func (s *Server) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "sentinel-gate",
		"version": "1.0.0",
	})
}

// readinessCheck endpoint for readiness check
func (s *Server) readinessCheck(c *gin.Context) {
	//  TODO: add more complex checks like Redis connectivity, database, etc.

	checks := map[string]string{
		"gateway": "ok",
		"redis":   "ok", // TODO: implement real Redis check
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
