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

// Proxy representa o proxy reverso
type Proxy struct {
	config  config.ProxyConfig
	logger  *zap.Logger
	targets map[string]*httputil.ReverseProxy
}

// New cria uma nova instância do proxy
func New(cfg config.ProxyConfig, logger *zap.Logger) (*Proxy, error) {
	proxy := &Proxy{
		config:  cfg,
		logger:  logger,
		targets: make(map[string]*httputil.ReverseProxy),
	}

	// Inicializar reverse proxies para cada target
	for _, target := range cfg.Targets {
		if err := proxy.addTarget(target); err != nil {
			return nil, fmt.Errorf("erro ao configurar target %s: %w", target.Name, err)
		}
	}

	return proxy, nil
}

// Handle manipula as requisições de proxy
func (p *Proxy) Handle(c *gin.Context) {
	path := c.Request.URL.Path

	// Encontrar o target baseado no path
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

	// Obter o reverse proxy para o target
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

	// Adicionar headers de contexto
	c.Request.Header.Set("X-Forwarded-For", c.ClientIP())
	c.Request.Header.Set("X-Forwarded-Proto", "http")
	c.Request.Header.Set("X-Forwarded-Host", c.Request.Host)

	// Adicionar informações do usuário autenticado
	if userID, exists := c.Get("user_id"); exists {
		c.Request.Header.Set("X-User-ID", fmt.Sprintf("%v", userID))
	}
	if username, exists := c.Get("username"); exists {
		c.Request.Header.Set("X-Username", fmt.Sprintf("%v", username))
	}
	if role, exists := c.Get("role"); exists {
		c.Request.Header.Set("X-User-Role", fmt.Sprintf("%v", role))
	}

	// Log da requisição proxy
	p.logger.Info("Proxying request",
		zap.String("path", path),
		zap.String("target", target.Name),
		zap.String("target_url", target.URL),
		zap.String("method", c.Request.Method),
		zap.String("client_ip", c.ClientIP()),
	)

	// Executar o proxy
	reverseProxy.ServeHTTP(c.Writer, c.Request)
}

// addTarget adiciona um novo target ao proxy
func (p *Proxy) addTarget(target config.TargetConfig) error {
	targetURL, err := url.Parse(target.URL)
	if err != nil {
		return fmt.Errorf("URL inválida para target %s: %w", target.Name, err)
	}

	// Criar reverse proxy personalizado
	reverseProxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Personalizar o director para modificar a requisição
	originalDirector := reverseProxy.Director
	reverseProxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Modificar o path se necessário
		// Remove o prefixo do path configurado
		if target.Path != "" && target.Path != "/*" {
			pathPrefix := strings.TrimSuffix(target.Path, "/*")
			if strings.HasPrefix(req.URL.Path, pathPrefix) {
				req.URL.Path = strings.TrimPrefix(req.URL.Path, pathPrefix)
				if req.URL.Path == "" {
					req.URL.Path = "/"
				}
			}
		}

		// Definir o host do target
		req.Host = targetURL.Host
	}

	// Personalizar tratamento de erros
	reverseProxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		p.logger.Error("Erro no proxy",
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

// findTarget encontra o target apropriado baseado no path
func (p *Proxy) findTarget(path string) *config.TargetConfig {
	for _, target := range p.config.Targets {
		if p.matchPath(path, target.Path) {
			return &target
		}
	}
	return nil
}

// matchPath verifica se um path corresponde ao padrão do target
func (p *Proxy) matchPath(requestPath, targetPath string) bool {
	// Se o target path termina com /*, fazer match do prefixo
	if strings.HasSuffix(targetPath, "/*") {
		prefix := strings.TrimSuffix(targetPath, "/*")
		return strings.HasPrefix(requestPath, prefix)
	}

	// Match exato
	return requestPath == targetPath
}

// HealthCheck verifica a saúde dos targets
func (p *Proxy) HealthCheck() map[string]bool {
	results := make(map[string]bool)

	for _, target := range p.config.Targets {
		if target.HealthCheck == "" {
			results[target.Name] = true // Assume que está saudável se não há health check
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
