# Proxy Module

Sistema de reverse proxy para o Sentinel Gate API Gateway com suporte a múltiplos backends, path matching e health checks.

## **Funcionalidades**

### **Reverse Proxy**

- **Multi-backend**: Suporte a múltiplos serviços backend
- **Path Matching**: Roteamento baseado em patterns de URL
- **Path Rewriting**: Remoção automática de prefixos
- **Load Balancing**: Distribuição entre instâncias (futuro)
- **Request Forwarding**: Proxy transparente de requests

### **Header Injection**

- **X-Forwarded-For**: IP do cliente original
- **X-Forwarded-Proto**: Protocolo utilizado (http/https)
- **X-Forwarded-Host**: Host original da requisição
- **X-User-ID**: ID do usuário autenticado
- **X-Username**: Nome do usuário autenticado
- **X-User-Role**: Role do usuário autenticado

### **Health Monitoring**

- **Health Checks**: Verificação automática de status dos backends
- **Circuit Breaker**: Prevenção de cascata de falhas (futuro)
- **Error Handling**: Respostas padronizadas para falhas
- **Monitoring**: Logs estruturados de status

## **Arquitetura**

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Client API    │───▶│   Proxy Module   │───▶│   Backend API   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ HTTP Request    │    │ Path Matching    │    │ Service Response│
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### **Request Flow**

1. **Path Analysis**: Determina qual backend atender a requisição
2. **Authentication Context**: Injeta headers de usuário se autenticado
3. **Path Rewriting**: Remove prefixos de roteamento
4. **Forward Request**: Encaminha para backend apropriado
5. **Response Handling**: Retorna resposta ou erro padronizado

## **Configuração**

### **Estrutura de Configuração**

```go
type ProxyConfig struct {
    Targets []TargetConfig `mapstructure:"targets"`
}

type TargetConfig struct {
    Name        string `mapstructure:"name"`
    URL         string `mapstructure:"url"`
    Path        string `mapstructure:"path"`
    HealthCheck string `mapstructure:"health_check"`
}
```

### **Exemplo de Configuração**

```yaml
proxy:
  targets:
    - name: "user-service"
      url: "http://user-service:3001"
      path: "/api/users/*"
      health_check: "/health"

    - name: "order-service"
      url: "http://order-service:3002"
      path: "/api/orders/*"
      health_check: "/health"

    - name: "payment-service"
      url: "http://payment-service:3003"
      path: "/api/payments/*"
      health_check: "/ready"
```

## **Path Matching**

### **Tipos de Patterns**

| Pattern         | Descrição       | Exemplo Request         | Backend Called            |
| --------------- | --------------- | ----------------------- | ------------------------- |
| `/api/users/*`  | Wildcard prefix | `/api/users/123`        | `user-service/123`        |
| `/api/orders/*` | Wildcard prefix | `/api/orders/456/items` | `order-service/456/items` |
| `/health`       | Exact match     | `/health`               | `service/health`          |

### **Path Rewriting Logic**

```
Request: GET /api/users/123/profile
Target Path: /api/users/*
Target URL: http://user-service:3001

Rewritten: GET http://user-service:3001/123/profile
```

## **Header Injection**

### **Headers Automáticos**

Todos os requests recebem headers padrão:

```http
X-Forwarded-For: 192.168.1.100
X-Forwarded-Proto: http
X-Forwarded-Host: gateway.example.com
```

### **Headers de Autenticação**

Requests autenticados recebem headers adicionais:

```http
X-User-ID: uuid-v4-user-id
X-Username: john.doe
X-User-Role: admin
```

### **Utilizando Headers no Backend**

```go
// Backend service
func handleRequest(w http.ResponseWriter, r *http.Request) {
    userID := r.Header.Get("X-User-ID")
    username := r.Header.Get("X-Username")
    role := r.Header.Get("X-User-Role")

    if userID != "" {
        // Request autenticado via gateway
        log.Printf("Authenticated request from user: %s", username)
    }
}
```

## **Health Checks**

### **Configuração de Health Check**

```yaml
targets:
  - name: "user-service"
    url: "http://user-service:3001"
    path: "/api/users/*"
    health_check: "/health" # Endpoint de health check
```

### **Implementação no Backend**

```go
// Backend service health endpoint
func healthHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(`{"status": "healthy"}`))
}
```

### **Verificação de Status**

```go
// Proxy health check
healthStatus := proxy.HealthCheck()
for serviceName, isHealthy := range healthStatus {
    if isHealthy {
        log.Printf("Service %s is healthy", serviceName)
    } else {
        log.Printf("Service %s is unhealthy", serviceName)
    }
}
```

## **Error Handling**

### **Service Not Found (404)**

```json
{
  "error": "Service not found",
  "message": "No backend service available for this path"
}
```

### **Backend Unavailable (502)**

```json
{
  "error": "Bad Gateway",
  "message": "The backend service is currently unavailable"
}
```

### **Configuration Error (500)**

```json
{
  "error": "Internal server error",
  "message": "Backend service configuration error"
}
```

## **Logs e Monitoramento**

### **Request Proxying**

```json
{
  "level": "info",
  "message": "Proxying request",
  "path": "/api/users/123",
  "target": "user-service",
  "target_url": "http://user-service:3001",
  "method": "GET",
  "client_ip": "192.168.1.100"
}
```

### **Target Configuration**

```json
{
  "level": "info",
  "message": "Target configurado",
  "name": "user-service",
  "url": "http://user-service:3001",
  "path": "/api/users/*"
}
```

### **Proxy Error**

```json
{
  "level": "error",
  "message": "Error in proxy",
  "target": "user-service",
  "url": "/api/users/123",
  "error": "connection refused"
}
```

### **Health Check Failure**

```json
{
  "level": "warn",
  "message": "Health check falhou",
  "target": "user-service",
  "url": "http://user-service:3001/health",
  "error": "connection timeout"
}
```

## **Uso Programático**

### **Inicialização**

```go
import "sentinel_gate/internal/proxy"

// Criar instância do proxy
proxyInstance, err := proxy.New(config.Proxy, logger)
if err != nil {
    log.Fatal("Failed to create proxy:", err)
}

// Registrar rota no Gin
router.Any("/api/*path", proxyInstance.Handle)
```

### **Health Check Manual**

```go
// Verificar saúde dos backends
healthStatus := proxyInstance.HealthCheck()
for service, healthy := range healthStatus {
    fmt.Printf("%s: %v\n", service, healthy)
}
```

## **Configuração de Backends**

### **Docker Compose**

```yaml
services:
  user-service:
    image: user-service:latest
    ports:
      - "3001:3001"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3001/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  order-service:
    image: order-service:latest
    ports:
      - "3002:3002"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3002/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### **Kubernetes**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: user-service
spec:
  selector:
    app: user-service
  ports:
    - port: 3001
      targetPort: 3001
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-service
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: user-service
          image: user-service:latest
          ports:
            - containerPort: 3001
          livenessProbe:
            httpGet:
              path: /health
              port: 3001
            initialDelaySeconds: 30
            periodSeconds: 10
```

## **Segurança**

### **Header Sanitization**

- **Remoção**: Headers sensíveis são removidos antes do proxy
- **Validação**: Verificação de headers maliciosos
- **Rate Limiting**: Aplicado antes do proxy (via middleware)
- **Authentication**: Verificação JWT antes do encaminhamento

### **Backend Security**

```go
// Backend deve validar headers injetados
func validateProxyHeaders(r *http.Request) bool {
    // Verificar se request veio do gateway
    if r.Header.Get("X-Forwarded-For") == "" {
        return false // Request direto, não via gateway
    }

    // Verificar consistência dos headers de usuário
    userID := r.Header.Get("X-User-ID")
    username := r.Header.Get("X-Username")

    return userID != "" && username != ""
}
```

## **Performance**

### **Otimizações Implementadas**

- **Connection Reuse**: Pool de conexões HTTP para backends
- **Minimal Latency**: Proxy transparente sem processamento desnecessário
- **Efficient Routing**: O(1) lookup para path matching
- **Streaming**: Support para responses grandes

### **Métricas Esperadas**

- **Latency Overhead**: < 1ms para proxy simples
- **Throughput**: Limitado pela capacidade dos backends
- **Memory Usage**: Constante independente do número de requests
- **CPU Usage**: Baixo overhead para forwarding

## **Troubleshooting**

### **Problemas Comuns**

#### **Service Not Found**

```bash
# Verificar configuração de targets
cat configs/config.yaml | grep -A 5 "targets:"

# Testar path matching
curl -v http://localhost:8080/api/users/123
```

#### **Backend Unavailable**

```bash
# Verificar saúde dos backends
curl http://user-service:3001/health
curl http://order-service:3002/health

# Verificar conectividade de rede
ping user-service
telnet user-service 3001
```

#### **Headers Missing**

```bash
# Verificar headers enviados
curl -H "Authorization: Bearer token" \
     -v http://localhost:8080/api/users/me

# Verificar se middleware auth está ativo
grep -r "JWTAuth" internal/server/
```

## **Futuras Melhorias**

### **Load Balancing**

```go
type TargetConfig struct {
    Name        string   `mapstructure:"name"`
    URLs        []string `mapstructure:"urls"`      // Múltiplas URLs
    Strategy    string   `mapstructure:"strategy"`   // round-robin, random, etc
    Path        string   `mapstructure:"path"`
    HealthCheck string   `mapstructure:"health_check"`
}
```

### **Circuit Breaker**

```go
// Integração com circuit breaker
func (p *Proxy) Handle(c *gin.Context) {
    target := p.findTarget(c.Request.URL.Path)

    if p.circuitBreaker.IsOpen(target.Name) {
        c.JSON(503, gin.H{"error": "Service temporarily unavailable"})
        return
    }

    // ... proxy logic
}
```

### **Caching**

```go
// Response caching para GET requests
type ProxyConfig struct {
    Targets []TargetConfig `mapstructure:"targets"`
    Cache   CacheConfig    `mapstructure:"cache"`
}
```

## **Compatibilidade**

- **Go 1.21+**: Testado e compatível
- **HTTP/1.1**: Suporte completo
- **HTTP/2**: Suporte via Go standard library
- **WebSockets**: Proxy transparente
- **Streaming**: Support para SSE e chunked encoding
