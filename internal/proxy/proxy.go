package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"sentinel_gate/pkg/config"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Proxy represents the reverse proxy
type Proxy struct {
	config  config.ProxyConfig
	logger  *zap.Logger
	targets map[string]*httputil.ReverseProxy
}

// New creates a new proxy instance
func New(cfg config.ProxyConfig, logger *zap.Logger) (*Proxy, error) {
	proxy := &Proxy{
		config:  cfg,
		logger:  logger,
		targets: make(map[string]*httputil.ReverseProxy),
	}

	for _, target := range cfg.Targets {
		if err := proxy.addTarget(target); err != nil {
			return nil, fmt.Errorf("error configuring target %s: %w", target.Name, err)
		}
	}

	return proxy, nil
}

// Handle handles the proxy requests
func (p *Proxy) Handle(c *gin.Context) {
	path := c.Request.URL.Path

	target := p.findTarget(path)
	if target == nil {
		p.logger.Warn("Nenhum target encontrado para o path",
			zap.String("path", path),
			zap.String("client_ip", c.ClientIP()),
		)
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Service not found",
			"message": "No backend service available for this path",
		})
		return
	}

	reverseProxy, exists := p.targets[target.Name]
	if !exists {
		p.logger.Error("Reverse proxy não encontrado para target",
			zap.String("target", target.Name),
		)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal server error",
			"message": "Backend service configuration error",
		})
		return
	}

	c.Request.Header.Set("X-Forwarded-For", c.ClientIP())
	c.Request.Header.Set("X-Forwarded-Proto", "http")
	c.Request.Header.Set("X-Forwarded-Host", c.Request.Host)

	if userID, exists := c.Get("user_id"); exists {
		c.Request.Header.Set("X-User-ID", fmt.Sprintf("%v", userID))
	}
	if username, exists := c.Get("username"); exists {
		c.Request.Header.Set("X-Username", fmt.Sprintf("%v", username))
	}
	if role, exists := c.Get("role"); exists {
		c.Request.Header.Set("X-User-Role", fmt.Sprintf("%v", role))
	}

	p.logger.Info("Proxying request",
		zap.String("path", path),
		zap.String("target", target.Name),
		zap.String("target_url", target.URL),
		zap.String("method", c.Request.Method),
		zap.String("client_ip", c.ClientIP()),
	)

	reverseProxy.ServeHTTP(c.Writer, c.Request)
}

// addTarget adds a new target to the proxy
func (p *Proxy) addTarget(target config.TargetConfig) error {
	targetURL, err := url.Parse(target.URL)
	if err != nil {
		return fmt.Errorf("URL inválida para target %s: %w", target.Name, err)
	}

	reverseProxy := httputil.NewSingleHostReverseProxy(targetURL)

	originalDirector := reverseProxy.Director
	reverseProxy.Director = func(req *http.Request) {
		originalDirector(req)

		if target.Path != "" && target.Path != "/*" {
			pathPrefix := strings.TrimSuffix(target.Path, "/*")
			if strings.HasPrefix(req.URL.Path, pathPrefix) {
				req.URL.Path = strings.TrimPrefix(req.URL.Path, pathPrefix)
				if req.URL.Path == "" {
					req.URL.Path = "/"
				}
			}
		}

		req.Host = targetURL.Host
	}

	reverseProxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		p.logger.Error("Error in proxy",
			zap.String("target", target.Name),
			zap.String("url", req.URL.String()),
			zap.Error(err),
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{
			"error": "Bad Gateway",
			"message": "The backend service is currently unavailable"
		}`))
	}

	p.targets[target.Name] = reverseProxy
	p.logger.Info("Target configurado",
		zap.String("name", target.Name),
		zap.String("url", target.URL),
		zap.String("path", target.Path),
	)

	return nil
}

// findTarget finds the appropriate target based on the path
func (p *Proxy) findTarget(path string) *config.TargetConfig {
	for _, target := range p.config.Targets {
		if p.matchPath(path, target.Path) {
			return &target
		}
	}
	return nil
}

// matchPath checks if a path matches the target pattern
func (p *Proxy) matchPath(requestPath, targetPath string) bool {
	if strings.HasSuffix(targetPath, "/*") {
		prefix := strings.TrimSuffix(targetPath, "/*")
		return strings.HasPrefix(requestPath, prefix)
	}

	return requestPath == targetPath
}

// HealthCheck checks the health of the targets
func (p *Proxy) HealthCheck() map[string]bool {
	results := make(map[string]bool)

	for _, target := range p.config.Targets {
		if target.HealthCheck == "" {
			results[target.Name] = true // Assume that the target is healthy if there is no health check
			continue
		}

		healthURL := target.URL + target.HealthCheck
		resp, err := http.Get(healthURL)
		if err != nil {
			p.logger.Warn("Health check falhou",
				zap.String("target", target.Name),
				zap.String("url", healthURL),
				zap.Error(err),
			)
			results[target.Name] = false
			continue
		}
		defer resp.Body.Close()

		results[target.Name] = resp.StatusCode >= 200 && resp.StatusCode < 300
	}

	return results
}
