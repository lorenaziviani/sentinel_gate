# Sentinel Gate API Gateway

Um API Gateway robusto e performático desenvolvido em Go, oferecendo autenticação JWT, rate limiting com Redis, circuit breaker e observabilidade completa para arquiteturas de microserviços.

## Funcionalidades

### Segurança

- **Autenticação JWT** - Tokens stateless com refresh automático
- **Rate Limiting** - Proteção contra DDoS usando Redis
- **CORS** - Configuração segura para requisições cross-origin
- **Request Validation** - Validação de headers e payloads

### Performance & Resiliência

- **Circuit Breaker** - Proteção contra falhas em cascata
- **Reverse Proxy** - Roteamento inteligente para backends
- **Health Checks** - Monitoramento contínuo dos serviços
- **Graceful Shutdown** - Desligamento elegante sem perda de requisições

### Observabilidade

- **Structured Logging** - Logs estruturados com Zap
- **Metrics (Prometheus)** - Métricas detalhadas via OpenTelemetry
- **Request Tracing** - Rastreamento completo de requisições
- **Performance Monitoring** - Latência, throughput e taxa de erro

## Arquitetura

![Diagrama de Arquitetura](docs/architecture.drawio.png)

### Fluxo de Requisição

```
Cliente → CORS → Logger → Metrics → Rate Limit → JWT Auth → Circuit Breaker → Reverse Proxy → Backend Services
```

**Detalhamento do fluxo:**

1. **Entrada**: Cliente envia requisição HTTP
2. **CORS**: Validação de origem e headers CORS
3. **Logger**: Registro estruturado da requisição
4. **Metrics**: Coleta de métricas de performance
5. **Rate Limit**: Verificação de limites por IP (Redis)
6. **JWT Auth**: Validação de token e extração de claims
7. **Circuit Breaker**: Verificação de saúde do backend
8. **Proxy**: Roteamento para serviço backend apropriado

## Stack Tecnológica

- **Go 1.21** - Linguagem principal
- **Gin Framework** - HTTP router de alta performance
- **Redis** - Cache distribuído para rate limiting
- **OpenTelemetry** - Observabilidade e instrumentação
- **Prometheus** - Coleta e armazenamento de métricas
- **JWT (golang-jwt/jwt)** - Autenticação stateless
- **Zap** - Logging estruturado de alta performance
- **Sony GoBreaker** - Implementação de circuit breaker

## Pré-requisitos

- Go 1.21+
- Redis 6.0+
- Docker & Docker Compose (opcional)

## Instalação e Execução

### 1. Clone o repositório

```bash
git clone https://github.com/lorenaziviani/sentinel_gate.git
cd sentinel_gate
```

### 2. Instale as dependências

```bash
go mod download
```

### 3. Configure as variáveis de ambiente

```bash
cp .env.example .env
# Edite o arquivo .env com suas configurações
```

### 4. Inicie o Redis (se não estiver rodando)

```bash
# Com Docker
docker run -d --name redis -p 6379:6379 redis:alpine

# Ou com Docker Compose
docker-compose up -d redis
```

### 5. Execute o gateway

```bash
# Desenvolvimento
go run cmd/gateway/main.go

# Produção
go build -o bin/gateway cmd/gateway/main.go
./bin/gateway
```

### 6. Usando Docker Compose (recomendado)

```bash
docker-compose up -d
```

## Configuração

O gateway é configurado através de variáveis de ambiente:

### Servidor

```bash
ENVIRONMENT=development              # development, staging, production
SERVER_PORT=:8080                   # Porta do servidor
SERVER_READ_TIMEOUT=10s             # Timeout de leitura
SERVER_WRITE_TIMEOUT=10s            # Timeout de escrita
```

### JWT

```bash
JWT_SECRET=your-super-secret-jwt-key-with-at-least-32-chars
JWT_EXPIRATION=24h                   # Expiração do access token
JWT_REFRESH_TIME=168h                # Expiração do refresh token (7 dias)
JWT_ISSUER=sentinel-gate             # Emissor do token
```

### Redis

```bash
REDIS_HOST=localhost                 # Host do Redis
REDIS_PORT=6379                     # Porta do Redis
REDIS_PASSWORD=                     # Senha do Redis (se houver)
REDIS_DB=0                          # Database do Redis
```

### Rate Limiting

```bash
RATE_LIMIT_RPM=100                  # Requests por minuto por IP
RATE_LIMIT_BURST=10                 # Burst size
RATE_LIMIT_WINDOW=1m                # Janela de tempo
```

### Circuit Breaker

```bash
CB_MAX_REQUESTS=3                   # Máximo de requests no estado meio-aberto
CB_INTERVAL=60s                     # Intervalo para reset
CB_TIMEOUT=60s                      # Timeout para abrir o circuito
CB_READY_TO_TRIP=5                  # Falhas necessárias para abrir
```

### Telemetria

```bash
TELEMETRY_ENABLED=true              # Ativar/desativar telemetria
PROMETHEUS_PORT=:9090               # Porta do Prometheus
SERVICE_NAME=sentinel-gate          # Nome do serviço
SERVICE_VERSION=1.0.0               # Versão do serviço
```

### Backends

```bash
TARGET_USERS_URL=http://localhost:3001    # URL do serviço de usuários
TARGET_ORDERS_URL=http://localhost:3002   # URL do serviço de pedidos
```

## Uso da API

### 1. Autenticação

**Login:**

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'
```

**Resposta:**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

### 2. Requisições Autenticadas

```bash
curl -X GET http://localhost:8080/api/users \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

### 3. Refresh Token

```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
  }'
```

### 4. Health Checks

```bash
# Gateway health
curl http://localhost:8080/health

# Readiness check
curl http://localhost:8080/ready

# Metrics
curl http://localhost:8080/metrics
```

## Monitoramento

### Métricas Disponíveis

- `http_requests_total` - Total de requisições HTTP
- `http_request_duration_seconds` - Duração das requisições
- `http_active_connections` - Conexões ativas
- `rate_limit_exceeded_total` - Rate limits atingidos
- `circuit_breaker_state` - Estado do circuit breaker

### Dashboard Prometheus

Acesse `http://localhost:9090` para visualizar as métricas no Prometheus.

### Logs Estruturados

Todos os logs são estruturados em JSON para fácil parsing:

```json
{
  "level": "info",
  "timestamp": "2024-01-15T10:30:45Z",
  "caller": "server/server.go:45",
  "message": "HTTP Request",
  "method": "GET",
  "path": "/api/users",
  "status": 200,
  "latency": "15.2ms",
  "client_ip": "192.168.1.100"
}
```

## Testes

```bash
# Executar todos os testes
go test ./...

# Testes com coverage
go test -cover ./...

# Testes de integração
go test -tags=integration ./...

# Benchmark
go test -bench=. ./...
```

## Estrutura do Projeto

```
sentinel_gate/
├── cmd/
│   └── gateway/           # Ponto de entrada da aplicação
├── internal/
│   ├── auth/             # Módulo de autenticação JWT
│   ├── middleware/       # Middlewares (CORS, Auth, Rate Limit, etc.)
│   ├── proxy/            # Reverse proxy para backends
│   ├── ratelimiter/      # Rate limiting com Redis
│   └── server/           # Servidor HTTP principal
├── pkg/
│   ├── config/           # Configuração da aplicação
│   ├── logger/           # Logger estruturado
│   └── telemetry/        # OpenTelemetry e métricas
├── docs/                 # Documentação e diagramas
├── configs/              # Arquivos de configuração
├── docker-compose.yml    # Setup completo com Docker
├── Dockerfile           # Imagem Docker do gateway
└── README.md
```

## Segurança

### Boas Práticas Implementadas

- **JWT Secret**: Mínimo de 32 caracteres
- **Token Expiration**: Tokens com tempo de vida limitado
- **Rate Limiting**: Proteção contra ataques de força bruta
- **Input Validation**: Validação rigorosa de inputs
- **Error Handling**: Não exposição de informações sensíveis
- **CORS**: Configuração restritiva de CORS

### Configurações de Segurança

```bash
# JWT com alta entropia
JWT_SECRET=$(openssl rand -base64 32)

# Rate limiting agressivo em produção
RATE_LIMIT_RPM=60
RATE_LIMIT_BURST=5

# Timeouts conservadores
SERVER_READ_TIMEOUT=10s
SERVER_WRITE_TIMEOUT=10s
```

## Contribuição

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## Roadmap

### Versão 1.1

- [ ] Load balancing inteligente
- [ ] Cache distribuído
- [ ] WebSocket support
- [ ] gRPC support

### Versão 1.2

- [ ] Plugin system
- [ ] A/B testing support
- [ ] Request transformation
- [ ] Response caching

### Versão 2.0

- [ ] Service mesh integration
- [ ] Multi-tenant support
- [ ] Advanced analytics
- [ ] Machine learning insights

## Licença

Este projeto está licenciado sob a MIT License - veja o arquivo [LICENSE](LICENSE) para detalhes.
