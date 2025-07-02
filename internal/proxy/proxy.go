package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"sentinel_gate/internal/circuitbreaker"
	"sentinel_gate/pkg/config"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Proxy represents the reverse proxy
type Proxy struct {
	config         config.ProxyConfig
	logger         *zap.Logger
	targets        map[string]*httputil.ReverseProxy
	circuitBreaker *circuitbreaker.CircuitBreakerManager
}

// New creates a new proxy instance
func New(cfg config.ProxyConfig, cbManager *circuitbreaker.CircuitBreakerManager, logger *zap.Logger) (*Proxy, error) {
	proxy := &Proxy{
		config:         cfg,
		logger:         logger,
		targets:        make(map[string]*httputil.ReverseProxy),
		circuitBreaker: cbManager,
	}

	for _, target := range cfg.Targets {
		if err := proxy.addTarget(target); err != nil {
			return nil, fmt.Errorf("error configuring target %s: %w", target.Name, err)
		}
	}

	return proxy, nil
}

// Handle handles the proxy requests with circuit breaker protection
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

	// Execute request through circuit breaker
	if p.circuitBreaker != nil {
		p.executeWithCircuitBreaker(c, target, reverseProxy)
	} else {
		// Fallback to direct proxy if circuit breaker is not available
		reverseProxy.ServeHTTP(c.Writer, c.Request)
	}
}

// executeWithCircuitBreaker executes the proxy request through circuit breaker
func (p *Proxy) executeWithCircuitBreaker(c *gin.Context, target *config.TargetConfig, reverseProxy *httputil.ReverseProxy) {
	responseWriter := &responseCapture{
		ResponseWriter: c.Writer,
		statusCode:     http.StatusOK,
	}

	response, err := p.circuitBreaker.ExecuteHTTP(target.Name, func() (*http.Response, error) {
		reverseProxy.ServeHTTP(responseWriter, c.Request)

		if responseWriter.statusCode >= 500 {
			return nil, &circuitbreaker.HTTPError{
				StatusCode: responseWriter.statusCode,
				Message:    fmt.Sprintf("Upstream service returned %d", responseWriter.statusCode),
			}
		}

		return &http.Response{
			StatusCode: responseWriter.statusCode,
			Header:     responseWriter.Header(),
		}, nil
	})

	if err != nil {
		if cbErr, ok := err.(*circuitbreaker.CircuitBreakerError); ok {
			p.logger.Warn("Circuit breaker activated",
				zap.String("service", cbErr.ServiceName),
				zap.String("state", cbErr.State.String()),
				zap.String("path", c.Request.URL.Path),
			)

			fallback := p.createFallbackResponse(cbErr)
			c.Header("Retry-After", fmt.Sprintf("%d", fallback.RetryAfter))
			c.Header("X-Circuit-Breaker", string(cbErr.State))
			c.Header("X-Fallback-Reason", "circuit-breaker")
			c.Header("X-Service-Name", cbErr.ServiceName)

			c.JSON(fallback.StatusCode, gin.H{
				"error":         "Service Unavailable",
				"message":       fallback.Message,
				"retry_after":   fallback.RetryAfter,
				"service_name":  cbErr.ServiceName,
				"circuit_state": cbErr.State.String(),
			})
			return
		}

		p.logger.Error("Circuit breaker execution failed",
			zap.String("target", target.Name),
			zap.String("path", c.Request.URL.Path),
			zap.Error(err),
		)

		c.JSON(http.StatusBadGateway, gin.H{
			"error":   "Bad Gateway",
			"message": "The backend service is currently unavailable",
		})
		return
	}

	p.logger.Debug("Circuit breaker execution successful",
		zap.String("target", target.Name),
		zap.String("path", c.Request.URL.Path),
		zap.Int("status", response.StatusCode),
	)
}

// createFallbackResponse creates a fallback response for circuit breaker errors
func (p *Proxy) createFallbackResponse(cbErr *circuitbreaker.CircuitBreakerError) *circuitbreaker.FallbackResponse {
	return &circuitbreaker.FallbackResponse{
		StatusCode: http.StatusServiceUnavailable,
		Message:    fmt.Sprintf("Service %s is temporarily unavailable due to circuit breaker", cbErr.ServiceName),
		RetryAfter: 60, // Default to 60 seconds
		Headers: map[string]string{
			"Retry-After":       "60",
			"X-Circuit-Breaker": cbErr.State.String(),
			"X-Fallback-Reason": "circuit-breaker",
			"X-Service-Name":    cbErr.ServiceName,
		},
	}
}

// responseCapture captures the HTTP response for circuit breaker evaluation
type responseCapture struct {
	gin.ResponseWriter
	statusCode int
}

func (rc *responseCapture) WriteHeader(code int) {
	rc.statusCode = code
	rc.ResponseWriter.WriteHeader(code)
}

func (rc *responseCapture) Write(data []byte) (int, error) {
	return rc.ResponseWriter.Write(data)
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

// GetCircuitBreakerStates returns the states of all circuit breakers
func (p *Proxy) GetCircuitBreakerStates() map[string]*circuitbreaker.CircuitBreakerState {
	if p.circuitBreaker == nil {
		return make(map[string]*circuitbreaker.CircuitBreakerState)
	}
	return p.circuitBreaker.GetAllStates()
}

// GetCircuitBreakerMetrics returns circuit breaker metrics
func (p *Proxy) GetCircuitBreakerMetrics() *circuitbreaker.Metrics {
	if p.circuitBreaker == nil {
		return circuitbreaker.NewMetrics()
	}
	return p.circuitBreaker.GetMetrics()
}

// ResetCircuitBreaker resets a specific circuit breaker
func (p *Proxy) ResetCircuitBreaker(serviceName string) {
	if p.circuitBreaker != nil {
		p.circuitBreaker.Reset(serviceName)
	}
}
