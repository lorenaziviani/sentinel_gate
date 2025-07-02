# Circuit Breaker Module

Sistema de Circuit Breaker distribuído para proteção contra falhas em serviços downstream usando a biblioteca sony/gobreaker.

## **Funcionalidades**

### **Circuit Breaker Distribuído**

- **Multiple Services**: Gerenciamento independente por serviço downstream
- **State Management**: Estados CLOSED, OPEN e HALF-OPEN automáticos
- **Failure Detection**: Detecção inteligente de falhas baseada em thresholds
- **Auto Recovery**: Tentativas automáticas de recuperação após timeout
- **Concurrent Safe**: Thread-safe para múltiplas goroutines

### **Políticas de Fallback**

- **HTTP 503 Response**: Resposta padronizada para serviços indisponíveis
- **Retry-After Header**: Cliente sabe quando tentar novamente
- **Custom Headers**: Informações sobre estado do circuit breaker
- **Service Identification**: Headers identificam serviço em falha
- **Graceful Degradation**: Fallback transparente sem quebrar a aplicação

### **Métricas Detalhadas**

- **Request Counters**: Total de requests, sucessos e falhas por serviço
- **State Transitions**: Contadores de mudanças de estado
- **Fallback Execution**: Quantas vezes o fallback foi executado
- **Performance Tracking**: Monitoramento de performance por serviço
- **Thread-Safe Metrics**: Contadores protegidos contra race conditions

### **Logs Estruturados**

- **State Changes**: Log detalhado de mudanças de estado
- **Failure Events**: Contexto completo de falhas
- **Recovery Events**: Logs de recuperação de serviços
- **Request Context**: Correlação com requests específicos
- **Configuração**: Parâmetros de configuração no log

## **Configuração**

### **Variáveis de Ambiente**

```bash
# Circuit Breaker Configuration
CB_MAX_REQUESTS=3         # Requests permitidos em HALF-OPEN
CB_MIN_REQUESTS=5         # Mínimo de requests para avaliar falha
CB_FAILURE_THRESHOLD=0.6  # 60% de falhas para abrir o circuito
CB_INTERVAL=60s           # Janela de avaliação
CB_TIMEOUT=60s            # Tempo em OPEN antes de HALF-OPEN
CB_ENABLED=true           # Habilitar circuit breaker
```

### **Parâmetros de Configuração**

- **MaxRequests**: Número máximo de requests permitidos no estado HALF-OPEN
- **MinRequests**: Número mínimo de requests antes de avaliar failure rate
- **FailureThreshold**: Porcentagem de falhas para abrir o circuito (0.0-1.0)
- **Interval**: Janela de tempo para calcular failure rate
- **Timeout**: Tempo que o circuito permanece OPEN antes de ir para HALF-OPEN

## **Estados do Circuit Breaker**

### **CLOSED (Fechado)**

- **Comportamento**: Todas as requests passam normalmente
- **Monitoramento**: Coleta métricas de sucesso/falha
- **Transição**: Va para OPEN se failure rate > threshold

### **OPEN (Aberto)**

- **Comportamento**: Bloqueia todas as requests imediatamente
- **Fallback**: Retorna HTTP 503 com Retry-After header
- **Transição**: Vai para HALF-OPEN após timeout

### **HALF-OPEN (Meio Aberto)**

- **Comportamento**: Permite quantidade limitada de requests de teste
- **Avaliação**: Se requests de teste falharem, volta para OPEN
- **Recuperação**: Se requests de teste passarem, vai para CLOSED

## **Headers HTTP**

### **Response Headers de Fallback**

```http
HTTP/1.1 503 Service Unavailable
Retry-After: 60
X-Circuit-Breaker: OPEN
X-Fallback-Reason: circuit-breaker
X-Service-Name: api-users
```

### **Significado dos Headers**

- **Retry-After**: Segundos para próxima tentativa
- **X-Circuit-Breaker**: Estado atual do circuit breaker
- **X-Fallback-Reason**: Motivo do fallback (circuit-breaker)
- **X-Service-Name**: Nome do serviço em falha

## **Integração com Proxy**

### **Uso no Proxy Module**

```go
// Executar request através do circuit breaker
response, err := circuitBreaker.ExecuteHTTP("api-users", func() (*http.Response, error) {
    return http.Get("http://api-users/endpoint")
})

if err != nil {
    // Circuit breaker ativo - response já contém fallback
    return response, nil
}
```

### **Service Naming Convention**

- **api-users**: Serviço de usuários
- **api-orders**: Serviço de pedidos
- **api-payments**: Serviço de pagamentos
- **Format**: `api-{service-name}` ou `{service-name}`

## **Métricas e Monitoramento**

### **Métricas Disponíveis**

```json
{
  "requests_total": { "api-users": 150, "api-orders": 89 },
  "failures_total": { "api-users": 12, "api-orders": 3 },
  "success_total": { "api-users": 138, "api-orders": 86 },
  "circuit_opened": { "api-users": 2, "api-orders": 0 },
  "circuit_closed": { "api-users": 2, "api-orders": 0 },
  "circuit_half_open": { "api-users": 1, "api-orders": 0 },
  "fallback_executed": { "api-users": 25, "api-orders": 0 }
}
```

### **Estado dos Circuit Breakers**

```json
{
  "api-users": {
    "service_name": "api-users",
    "state": "CLOSED",
    "counts": {
      "requests": 150,
      "total_successes": 138,
      "total_failures": 12,
      "consecutive_successes": 15,
      "consecutive_failures": 0
    },
    "settings": {
      "name": "api-users",
      "max_requests": 3,
      "interval": "1m0s",
      "timeout": "1m0s"
    }
  }
}
```

## **Endpoints de Diagnóstico**

### **Health Check**

```bash
GET /health
```

Inclui informações de todos os circuit breakers no response.

### **Circuit Breaker Metrics**

```bash
GET /admin/circuit-breaker/metrics
```

### **Circuit Breaker States**

```bash
GET /admin/circuit-breaker/status
```

### **Reset Circuit Breaker**

```bash
POST /admin/circuit-breaker/reset/{service-name}
```

## **Logs Estruturados**

### **Exemplo de Logs**

```json
{
  "level": "warn",
  "time": "2024-01-15T10:30:00Z",
  "message": "Circuit breaker OPENED - blocking requests",
  "service": "api-users",
  "timeout": "1m0s",
  "caller": "circuitbreaker/circuitbreaker.go:245"
}

{
  "level": "info",
  "time": "2024-01-15T10:31:00Z",
  "message": "Circuit breaker state changed",
  "service": "api-users",
  "from_state": "OPEN",
  "to_state": "HALF_OPEN"
}
```

### **Log Levels**

- **INFO**: State changes, criação de circuit breakers
- **WARN**: Circuit breaker aberto, requests bloqueadas
- **DEBUG**: Operações bem-sucedidas
- **ERROR**: Falhas críticas no sistema

## **Troubleshooting**

### **Circuit Breaker Muito Sensível**

1. Aumentar `min_requests` para coletar mais dados
2. Aumentar `failure_threshold` para tolerar mais falhas
3. Aumentar `interval` para janela maior de avaliação

### **Circuit Breaker Não Abre**

1. Verificar se `min_requests` está sendo atingido
2. Verificar se `failure_threshold` não está muito alto
3. Verificar logs para confirmar detecção de falhas

### **Recovery Muito Lento**

1. Diminuir `timeout` para tentar recovery mais cedo
2. Aumentar `max_requests` para mais tentativas em HALF-OPEN
3. Verificar se serviço downstream realmente se recuperou

### **Muitos Fallbacks**

1. Verificar saúde dos serviços downstream
2. Revisar configuração de failure detection
3. Verificar logs de falhas para identificar padrões

## **Testing**

### **Simulação de Falhas**

```bash
# Forçar falhas no serviço
curl -X POST /test/force-failure/api-users

# Verificar estado do circuit breaker
curl /admin/circuit-breaker/status

# Reset para testing
curl -X POST /admin/circuit-breaker/reset/api-users
```

### **Load Testing**

```bash
# Gerar carga para testar thresholds
for i in {1..20}; do
  curl -s http://localhost:8080/api/users/ > /dev/null &
done
```
