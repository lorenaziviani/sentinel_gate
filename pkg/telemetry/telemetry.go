package telemetry

import (
	"context"
	"sentinel_gate/pkg/config"
)

// Init inicializa a telemetria (versão simplificada)
func Init(cfg config.TelemetryConfig) (func(), error) {
	if !cfg.Enabled {
		return func() {}, nil
	}

	// TODO: Implementar OpenTelemetry completo nos próximos commits
	// Por enquanto, apenas retorna um shutdown vazio

	shutdown := func() {
		// Graceful shutdown placeholder
	}

	return shutdown, nil
}

// Funções placeholder para métricas
func IncrementRequestCounter(ctx context.Context, method, path, status string) {
	// TODO: Implementar contador de requests
}

func RecordResponseTime(ctx context.Context, duration float64, method, path string) {
	// TODO: Implementar histograma de tempo de resposta
}

func IncrementActiveConnections(ctx context.Context) {
	// TODO: Implementar contador de conexões ativas
}

func DecrementActiveConnections(ctx context.Context) {
	// TODO: Implementar contador de conexões ativas
}

func IncrementRateLimitExceeded(ctx context.Context, clientIP string) {
	// TODO: Implementar contador de rate limit excedido
}
