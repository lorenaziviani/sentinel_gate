package ratelimiter

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"sentinel_gate/pkg/config"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// RateLimiter implementa controle de taxa usando Redis
type RateLimiter struct {
	client *redis.Client
	config config.RateLimitConfig
	logger *zap.Logger
}

// New cria uma nova instância do rate limiter
func New(cfg config.RateLimitConfig, logger *zap.Logger) *RateLimiter {
	// Configurar cliente Redis
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // TODO: usar configuração do Redis
		Password: "",               // TODO: usar configuração do Redis
		DB:       0,                // TODO: usar configuração do Redis
	})

	return &RateLimiter{
		client: rdb,
		config: cfg,
		logger: logger,
	}
}

// Allow verifica se a requisição deve ser permitida baseada no rate limit
func (rl *RateLimiter) Allow(clientIP string) bool {
	ctx := context.Background()
	key := fmt.Sprintf("rate_limit:%s", clientIP)

	// Implementar sliding window log algorithm
	now := time.Now().Unix()
	windowStart := now - int64(rl.config.WindowSize.Seconds())

	pipe := rl.client.Pipeline()

	// Remover entradas antigas da janela
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart, 10))

	// Contar requisições na janela atual
	countCmd := pipe.ZCard(ctx, key)

	// Executar pipeline
	_, err := pipe.Exec(ctx)
	if err != nil {
		rl.logger.Error("Erro ao consultar rate limit", zap.Error(err))
		// Em caso de erro, permitir a requisição (fail open)
		return true
	}

	currentCount := countCmd.Val()

	// Verificar se excedeu o limite
	if int(currentCount) >= rl.config.RequestsPerMinute {
		return false
	}

	// Adicionar a requisição atual
	pipe = rl.client.Pipeline()
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(now), Member: now})
	pipe.Expire(ctx, key, rl.config.WindowSize)

	_, err = pipe.Exec(ctx)
	if err != nil {
		rl.logger.Error("Erro ao registrar requisição no rate limit", zap.Error(err))
		// Em caso de erro, permitir a requisição (fail open)
		return true
	}

	return true
}

// GetStats retorna estatísticas do rate limiter para um cliente
func (rl *RateLimiter) GetStats(clientIP string) (int64, error) {
	ctx := context.Background()
	key := fmt.Sprintf("rate_limit:%s", clientIP)

	now := time.Now().Unix()
	windowStart := now - int64(rl.config.WindowSize.Seconds())

	// Limpar entradas antigas e contar
	pipe := rl.client.Pipeline()
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart, 10))
	countCmd := pipe.ZCard(ctx, key)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}

	return countCmd.Val(), nil
}

// Reset limpa o rate limit para um cliente específico
func (rl *RateLimiter) Reset(clientIP string) error {
	ctx := context.Background()
	key := fmt.Sprintf("rate_limit:%s", clientIP)

	return rl.client.Del(ctx, key).Err()
}

// Close fecha a conexão com o Redis
func (rl *RateLimiter) Close() error {
	return rl.client.Close()
}
