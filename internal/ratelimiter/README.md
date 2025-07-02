# Rate Limiter Module

Sistema avançado de rate limiting para o Sentinel Gate API Gateway com suporte a Redis distribuído e configuração dinâmica.

## **Funcionalidades**

### **Middleware Aprimorado**

- **EnhancedRateLimiter**: Sistema completo de rate limiting com suporte a regras dinâmicas
- **Tipos múltiplos**: Rate limiting por IP, Token JWT e Username
- **Configuração dinâmica**: Regras por rota carregadas de arquivo YAML
- **Multiplicadores por ambiente**: 10x dev, 3x staging, 1x prod
- **Redis distribuído**: Backend Redis com sliding window algorithm

### **Backend Redis Robusto**

- **Sliding Window**: Algoritmo preciso com Redis Sorted Sets
- **Pool de conexões**: Configuração otimizada para performance
- **Fail-open**: Sistema continua funcionando mesmo com Redis offline
- **Limpeza automática**: TTL e remoção de entradas antigas
- **Health check**: Monitoramento de conectividade Redis

### **Headers HTTP Padrão**

- **X-RateLimit-Limit**: Limite configurado
- **X-RateLimit-Remaining**: Requests restantes na janela
- **X-RateLimit-Reset**: Timestamp de reset da janela
- **X-RateLimit-Type**: Tipo de rate limiting aplicado
- **Retry-After**: Tempo de espera em caso de 429

## **Arquitetura**

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Gin Router    │───▶│ EnhancedRateLimit │───▶│ Redis Backend   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Request Context │    │ Route Rules YAML │    │ Sliding Window  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### **Redis Data Structure**

```
Key: rate_limit:ip:192.168.1.100
Type: Sorted Set
Members: [timestamp1, timestamp2, ...]
Scores: [unix_timestamp1, unix_timestamp2, ...]
TTL: window_size + 1min buffer
```

## **Configuração**

### **Configuração por Ambiente**

#### Development

- **Multiplicador**: 10x (relaxado para desenvolvimento)
- **Enabled**: false (pode ser desabilitado)
- **Exemplo**: 100/min → 1000/min

#### Staging

- **Multiplicador**: 3x (limites relaxados para testes)
- **Enabled**: true
- **Exemplo**: 100/min → 300/min

#### Production

- **Multiplicador**: 1x (limites exatos)
- **Enabled**: true
- **Exemplo**: 100/min → 100/min

### **Regras por Endpoint**

| Endpoint        | Rate Limit (IP) | Rate Limit (Token) | Window |
| --------------- | --------------- | ------------------ | ------ |
| `/health`       | 60/min          | -                  | 1m     |
| `/metrics`      | 30/min          | -                  | 1m     |
| `/auth/login`   | 10/min          | -                  | 1m     |
| `/auth/refresh` | 30/min          | 20/min             | 1m     |
| `/auth/logout`  | -               | 10/min             | 1m     |
| `/test/*`       | 50/min          | 100/min            | 1m     |
| `/api/users/*`  | 100/min         | 60/min             | 1m     |
| `/api/orders/*` | 50/min          | 30/min             | 1m     |
| `/admin/*`      | 10/min          | 20/min             | 1m     |
| **Global**      | 100/min         | -                  | 1m     |

## **Monitoramento e Logs**

### **Rate Limit Success**

```json
{
  "level": "debug",
  "message": "Rate limit check passed",
  "request_id": "req_abc123",
  "path": "/test/rate-limit",
  "client_ip": "192.168.1.100",
  "limit_type": "ip",
  "current_count": 5,
  "remaining": 95,
  "limit": 100
}
```

### **Rate Limit Exceeded**

```json
{
  "level": "warn",
  "message": "Rate limit exceeded",
  "request_id": "req_abc123",
  "path": "/test/rate-limit",
  "client_ip": "192.168.1.100",
  "limit_type": "ip",
  "current_count": 101,
  "limit": 100,
  "retry_after": "30s"
}
```

## **Testes**

### **Endpoints de Teste**

- **GET /test/rate-limit**: Teste básico de rate limiting por IP
- **GET /test/rate-limit-auth**: Teste com autenticação JWT
- **GET /test/rate-limit-stats**: Estatísticas de uso por identificador
- **POST /test/rate-limit-reset**: Reset de contadores específicos

### **Suite de Testes**

1. **Health Check**: Conectividade Redis
2. **Basic Rate Limiting**: IP-based limiting
3. **Authenticated Rate Limiting**: Token-based limiting
4. **Statistics**: Rate limit usage stats
5. **Reset**: Manual reset de contadores
6. **Endpoint-specific**: Diferentes limites por rota
7. **Threshold Testing**: Trigger de 429
8. **Headers**: Verificação de headers HTTP

## **Performance**

- **Latência**: < 2ms overhead por request (com Redis local)
- **Throughput**: Suporta milhares de requests/segundo
- **Memory**: Pool de conexões Redis otimizado
- **Disk**: Logs estruturados com níveis configuráveis

## **Segurança**

- **Key Sanitization**: Prevenção de Redis key injection
- **Fail-open**: Sistema seguro mesmo com falhas
- **Token Masking**: Logs seguros sem exposição de tokens
- **IP Validation**: Parsing seguro de IPs de headers

## **Como Usar**

### **1. Configuração Básica**

```go
import "sentinel_gate/internal/ratelimiter"

limiter := ratelimiter.NewRateLimiter(redis.Client{...})
```

### **2. Integração com Gin**

```go
r.Use(middleware.EnhancedRateLimiter(limiter, rules))
```

### **3. Configuração YAML**

```yaml
# configs/rate-limit-rules.yaml
global:
  requests_per_minute: 100
  window_size: "1m"

routes:
  - path: "/api/*"
    rules:
      - type: "ip"
        requests_per_minute: 100
```

## 🔧 **Configuração Redis**

```yaml
# docker-compose.yml
redis:
  image: redis:7-alpine
  ports:
    - "6379:6379"
```

## **Compatibilidade**

- **Go 1.21+**: Testado e compatível
- **Redis 7+**: Usando Redis Alpine latest
- **Gin Framework**: Integração nativa
- **JWT**: Suporte completo para rate limiting por token
