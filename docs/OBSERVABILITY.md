# Observabilidade - Sentinel Gate

Este documento descreve a implementação completa de observabilidade do Sentinel Gate, incluindo tracing distribuído, métricas e dashboards.

## Visão Geral

O Sentinel Gate implementa uma solução completa de observabilidade baseada em:

- **OpenTelemetry**: Tracing distribuído e instrumentação
- **Jaeger**: Visualização e análise de traces
- **Prometheus**: Coleta e armazenamento de métricas
- **Grafana**: Dashboards e visualização

## Stack de Observabilidade

### 1. OpenTelemetry

OpenTelemetry fornece instrumentação automática e manual para:

- **Traces**: Rastreamento de requests através do sistema
- **Metrics**: Métricas de aplicação e negócio
- **Context Propagation**: Propagação de contexto entre serviços

### 2. Jaeger

Jaeger é usado para:

- Visualização de traces distribuídos
- Análise de latência
- Debugging de requests complexos
- Identificação de gargalos

### 3. Prometheus

Prometheus coleta métricas sobre:

- HTTP requests (latência, throughput, erros)
- Circuit breaker operations
- Rate limiting
- Authentication
- Proxy operations

### 4. Grafana

Grafana fornece dashboards para:

- Overview do sistema
- Métricas de performance
- Alertas e monitoramento

## Configuração

### Variáveis de Ambiente

```bash
# Telemetria geral
TELEMETRY_ENABLED=true
SERVICE_NAME=sentinel-gate
SERVICE_VERSION=1.0.0
TELEMETRY_ENVIRONMENT=development

# Tracing
TRACING_ENABLED=true
JAEGER_ENDPOINT=http://jaeger:14268/api/traces
TRACING_SAMPLE_RATE=1.0

# Métricas
PROMETHEUS_PORT=:9090
```

### Docker Compose

O stack completo é executado via Docker Compose:

```yaml
services:
  gateway:
    # ... configurações do gateway
    environment:
      - TRACING_ENABLED=true
      - JAEGER_ENDPOINT=http://jaeger:14268/api/traces
    depends_on:
      - jaeger
      - prometheus

  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686" # Jaeger UI

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090" # Prometheus UI

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000" # Grafana UI
```

## Endpoints de Observabilidade

### Métricas (Prometheus)

```
GET /metrics
```

Endpoint do Prometheus que expõe todas as métricas do sistema.

### Health Check com Telemetria

```
GET /health
```

Retorna status de saúde incluindo informações de telemetria:

```json
{
  "service": "sentinel-gate",
  "status": "healthy",
  "version": "1.0.0",
  "circuit_breaker": {
    "circuit_breakers": {},
    "circuit_breakers_count": 0
  }
}
```

## Métricas Disponíveis

### 1. HTTP Requests

```
http_requests_total{method, path, status_code}
http_request_duration_seconds{method, path}
http_requests_in_flight
```

### 2. Authentication

```
auth_operations_total{operation, result}
auth_token_validation_duration_seconds
```

### 3. Rate Limiting

```
rate_limit_exceeded_total{limit_type}
rate_limit_operations_total{operation, result}
```

### 4. Circuit Breaker

```
circuit_breaker_operations_total{service, operation, state}
circuit_breaker_state_changes_total{service, from_state, to_state}
```

### 5. Proxy Operations

```
proxy_operations_total{target_service, method, status_code}
proxy_request_duration_seconds{target_service, method}
```

### 6. System Metrics

```
errors_total{error_type}
active_connections
target_info{service_name, service_version, deployment_environment}
```

## Tracing

### Instrumentação Automática

O sistema inclui instrumentação automática para:

- **HTTP requests**: Todos os requests são automaticamente trackeados
- **Middleware operations**: Rate limiting, auth, circuit breaker
- **Proxy calls**: Requests para serviços downstream
- **Database operations**: Operações com Redis

### Spans Customizados

Cada componente adiciona spans específicos:

```go
// Exemplo de span customizado
span := tracer.Start(ctx, "circuit-breaker-operation")
span.SetAttributes(
    attribute.String("service.name", serviceName),
    attribute.String("circuit_breaker.state", state),
)
defer span.End()
```

### Context Propagation

O contexto é propagado automaticamente através de:

- HTTP headers (B3, TraceContext)
- Middlewares
- Goroutines

## Dashboards

### Dashboard Principal

O dashboard principal (`sentinel-gate-overview`) inclui:

1. **HTTP Request Rate**: Taxa de requests por segundo
2. **Response Time**: Latência (95th percentile)
3. **Error Rate**: Taxa de erros por tipo
4. **Authentication Operations**: Login, token validation
5. **Rate Limit Exceeded**: Requests bloqueados
6. **Circuit Breaker Operations**: Estados e transições
7. **Proxy Operations**: Requests para downstream
8. **System Metrics**: Requests em voo, total de requests

### Queries Úteis

#### Top Endpoints por Volume

```promql
topk(10, sum(rate(http_requests_total[5m])) by (path))
```

#### Error Rate por Endpoint

```promql
rate(http_requests_total{status_code=~"5.."}[5m]) /
rate(http_requests_total[5m]) * 100
```

#### Latência P95 por Endpoint

```promql
histogram_quantile(0.95,
  rate(http_request_duration_seconds_bucket[5m])
) * 1000
```

#### Circuit Breaker States

```promql
circuit_breaker_operations_total{state="open"}
```

## Acessando as UIs

### Jaeger UI

```
http://localhost:16686
```

Funcionalidades principais:

- Search traces por serviço, operação, tags
- Trace timeline view
- Service map
- Performance insights

### Prometheus UI

```
http://localhost:9090
```

Funcionalidades principais:

- Query builder
- Metrics explorer
- Targets status
- Configuration

### Grafana UI

```
http://localhost:3000
```

Credenciais padrão:

- **Username**: admin
- **Password**: admin

Funcionalidades principais:

- Dashboards interativos
- Alerting
- Data exploration
- Custom queries

## Debugging com Observabilidade

### 1. Request Tracking

Para rastrear um request específico:

1. No Jaeger, busque por `service: sentinel-gate`
2. Filtre por operação (ex: `GET /api/users`)
3. Analise o trace completo

### 2. Performance Issues

Para identificar gargalos:

1. No Grafana, analise o dashboard de latência
2. Identifique endpoints com alta latência
3. Use Jaeger para analisar traces específicos
4. Verifique métricas de circuit breaker

### 3. Error Investigation

Para investigar erros:

1. No Grafana, identifique picos na taxa de erro
2. Use Prometheus para queries específicas
3. No Jaeger, filtre traces com erro
4. Analise spans de erro para root cause

### 4. Circuit Breaker Analysis

Para analisar circuit breakers:

1. Verifique métricas `circuit_breaker_operations_total`
2. Analise mudanças de estado
3. Correlacione com métricas de erro dos serviços downstream

## Alerting

### Regras de Alerta Sugeridas

```yaml
# High Error Rate
- alert: HighErrorRate
  expr: rate(http_requests_total{status_code=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.1
  for: 5m
  labels:
    severity: warning

# High Latency
- alert: HighLatency
  expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 0.5
  for: 5m
  labels:
    severity: warning

# Circuit Breaker Open
- alert: CircuitBreakerOpen
  expr: circuit_breaker_operations_total{state="open"} > 0
  for: 1m
  labels:
    severity: critical
```

## Performance Impact

### Overhead da Instrumentação

- **CPU**: ~1-3% overhead
- **Memory**: ~10-20MB adicional
- **Network**: Mínimo (batch export)

### Configuração de Produção

Para produção, ajuste:

```bash
TRACING_SAMPLE_RATE=0.1  # 10% dos traces
TELEMETRY_ENABLED=true
```

## Troubleshooting

### Problemas Comuns

1. **Métricas não aparecem**

   - Verifique `TELEMETRY_ENABLED=true`
   - Confirme que Prometheus está configurado corretamente

2. **Traces não aparecem no Jaeger**

   - Verifique `TRACING_ENABLED=true`
   - Confirme `JAEGER_ENDPOINT`

3. **Dashboard vazio no Grafana**

   - Verifique datasources configurados
   - Confirme queries do dashboard

4. **Performance degradada**
   - Reduza `TRACING_SAMPLE_RATE`
   - Ajuste batch export settings

### Logs de Telemetria

Para debug, habilite logs detalhados:

```bash
LOG_LEVEL=debug
```

Os logs incluirão informações sobre:

- Telemetry initialization
- Span creation/completion
- Metric collection
- Export status

## Conclusão

A implementação de observabilidade do Sentinel Gate fornece visibilidade completa sobre:

- Performance e latência
- Padrões de erro
- Comportamento de resiliência
- Uso de recursos

Esta solução permite monitoramento proativo, debugging eficiente e otimização contínua do sistema.
