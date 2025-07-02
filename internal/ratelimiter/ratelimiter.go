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

// RateLimiter implements rate limiting using Redis
type RateLimiter struct {
	client *redis.Client
	config config.RateLimitConfig
	logger *zap.Logger
}

// New creates a new rate limiter instance
func New(cfg config.RateLimitConfig, logger *zap.Logger) *RateLimiter {
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // TODO: use Redis configuration
		Password: "",               // TODO: use Redis configuration
		DB:       0,                // TODO: use Redis configuration
	})

	return &RateLimiter{
		client: rdb,
		config: cfg,
		logger: logger,
	}
}

// Allow checks if the request should be allowed based on the rate limit
func (rl *RateLimiter) Allow(clientIP string) bool {
	ctx := context.Background()
	key := fmt.Sprintf("rate_limit:%s", clientIP)

	now := time.Now().Unix()
	windowStart := now - int64(rl.config.WindowSize.Seconds())

	pipe := rl.client.Pipeline()

	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart, 10))

	countCmd := pipe.ZCard(ctx, key)

	_, err := pipe.Exec(ctx)
	if err != nil {
		rl.logger.Error("Error checking rate limit", zap.Error(err))
		// If there is an error, allow the request (fail open)
		return true
	}

	currentCount := countCmd.Val()

	if int(currentCount) >= rl.config.RequestsPerMinute {
		return false
	}

	pipe = rl.client.Pipeline()
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(now), Member: now})
	pipe.Expire(ctx, key, rl.config.WindowSize)

	_, err = pipe.Exec(ctx)
	if err != nil {
		rl.logger.Error("Error registering request in rate limit", zap.Error(err))
		// If there is an error, allow the request (fail open)
		return true
	}

	return true
}

// GetStats returns the rate limiter statistics for a client
func (rl *RateLimiter) GetStats(clientIP string) (int64, error) {
	ctx := context.Background()
	key := fmt.Sprintf("rate_limit:%s", clientIP)

	now := time.Now().Unix()
	windowStart := now - int64(rl.config.WindowSize.Seconds())

	pipe := rl.client.Pipeline()
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart, 10))
	countCmd := pipe.ZCard(ctx, key)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}

	return countCmd.Val(), nil
}

// Reset clears the rate limit for a specific client
func (rl *RateLimiter) Reset(clientIP string) error {
	ctx := context.Background()
	key := fmt.Sprintf("rate_limit:%s", clientIP)

	return rl.client.Del(ctx, key).Err()
}

// Close closes the connection to Redis
func (rl *RateLimiter) Close() error {
	return rl.client.Close()
}
