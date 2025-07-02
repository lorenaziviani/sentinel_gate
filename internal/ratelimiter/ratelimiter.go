package ratelimiter

import (
	"context"
	"fmt"
	"strconv"
	"strings"
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

// RateLimitType defines the type of rate limiting
type RateLimitType string

const (
	RateLimitByIP    RateLimitType = "ip"
	RateLimitByToken RateLimitType = "token"
	RateLimitByUser  RateLimitType = "user"
)

// RateLimitRule defines a specific rate limit rule
type RateLimitRule struct {
	Type              RateLimitType `yaml:"type" json:"type"`
	RequestsPerMinute int           `yaml:"requests_per_minute" json:"requests_per_minute"`
	BurstSize         int           `yaml:"burst_size" json:"burst_size"`
	WindowSize        time.Duration `yaml:"window_size" json:"window_size"`
	Enabled           bool          `yaml:"enabled" json:"enabled"`
}

// RouteRateLimit defines rate limits for specific routes
type RouteRateLimit struct {
	Path  string          `yaml:"path" json:"path"`
	Rules []RateLimitRule `yaml:"rules" json:"rules"`
}

// RateLimitResult contains information about rate limit check
type RateLimitResult struct {
	Allowed     bool
	Remaining   int64
	ResetTime   time.Time
	RetryAfter  time.Duration
	LimitType   RateLimitType
	LimitValue  int
	WindowStart time.Time
	WindowEnd   time.Time
}

// New creates a new rate limiter instance
func New(cfg config.RateLimitConfig, logger *zap.Logger) *RateLimiter {
	redisAddr := fmt.Sprintf("%s:%s", cfg.RedisHost, cfg.RedisPort)

	rdb := redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		Password:     cfg.RedisPassword,
		DB:           cfg.RedisDB,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     10,
		PoolTimeout:  30 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		logger.Warn("Failed to connect to Redis for rate limiting",
			zap.Error(err),
			zap.String("redis_addr", redisAddr),
		)
	} else {
		logger.Info("Connected to Redis for rate limiting",
			zap.String("redis_addr", redisAddr),
		)
	}

	return &RateLimiter{
		client: rdb,
		config: cfg,
		logger: logger,
	}
}

// Allow checks if the request should be allowed based on the rate limit
func (rl *RateLimiter) Allow(clientIP string) bool {
	result := rl.CheckRateLimit(RateLimitByIP, clientIP, rl.config.RequestsPerMinute, rl.config.WindowSize)
	return result.Allowed
}

// AllowWithRule checks rate limit using a specific rule
func (rl *RateLimiter) AllowWithRule(limitType RateLimitType, identifier string, rule RateLimitRule) *RateLimitResult {
	if !rule.Enabled {
		return &RateLimitResult{
			Allowed:    true,
			LimitType:  limitType,
			LimitValue: rule.RequestsPerMinute,
		}
	}

	return rl.CheckRateLimit(limitType, identifier, rule.RequestsPerMinute, rule.WindowSize)
}

// CheckRateLimit performs the actual rate limit check
func (rl *RateLimiter) CheckRateLimit(limitType RateLimitType, identifier string, limit int, window time.Duration) *RateLimitResult {
	ctx := context.Background()
	key := rl.buildKey(limitType, identifier)

	now := time.Now()
	windowStart := now.Add(-window)
	windowStartUnix := windowStart.Unix()
	nowUnix := now.Unix()

	pipe := rl.client.Pipeline()

	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStartUnix, 10))

	countCmd := pipe.ZCard(ctx, key)

	_, err := pipe.Exec(ctx)
	if err != nil {
		rl.logger.Error("Error checking rate limit",
			zap.Error(err),
			zap.String("key", key),
			zap.String("limit_type", string(limitType)),
		)
		return &RateLimitResult{
			Allowed:    true,
			LimitType:  limitType,
			LimitValue: limit,
		}
	}

	currentCount := countCmd.Val()
	remaining := int64(limit) - currentCount

	result := &RateLimitResult{
		Allowed:     currentCount < int64(limit),
		Remaining:   remaining,
		ResetTime:   now.Add(window),
		LimitType:   limitType,
		LimitValue:  limit,
		WindowStart: windowStart,
		WindowEnd:   now,
	}

	if !result.Allowed {
		oldestCmd := rl.client.ZRange(ctx, key, 0, 0).Val()
		if len(oldestCmd) > 0 {
			if oldestUnix, err := strconv.ParseInt(oldestCmd[0], 10, 64); err == nil {
				oldestTime := time.Unix(oldestUnix, 0)
				result.RetryAfter = oldestTime.Add(window).Sub(now)
			}
		}

		rl.logger.Warn("Rate limit exceeded",
			zap.String("key", key),
			zap.String("limit_type", string(limitType)),
			zap.String("identifier", identifier),
			zap.Int64("current_count", currentCount),
			zap.Int("limit", limit),
			zap.Duration("retry_after", result.RetryAfter),
		)

		return result
	}

	pipe = rl.client.Pipeline()
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(nowUnix), Member: nowUnix})
	pipe.Expire(ctx, key, window+time.Minute)

	_, err = pipe.Exec(ctx)
	if err != nil {
		rl.logger.Error("Error registering request in rate limit",
			zap.Error(err),
			zap.String("key", key),
		)
	}

	rl.logger.Debug("Rate limit check passed",
		zap.String("key", key),
		zap.String("limit_type", string(limitType)),
		zap.Int64("current_count", currentCount+1),
		zap.Int64("remaining", remaining-1),
		zap.Int("limit", limit),
	)

	result.Remaining = remaining - 1
	return result
}

// GetStats returns the rate limiter statistics for a client
func (rl *RateLimiter) GetStats(limitType RateLimitType, identifier string) (*RateLimitResult, error) {
	ctx := context.Background()
	key := rl.buildKey(limitType, identifier)

	now := time.Now()
	windowStart := now.Add(-rl.config.WindowSize)
	windowStartUnix := windowStart.Unix()

	pipe := rl.client.Pipeline()
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStartUnix, 10))
	countCmd := pipe.ZCard(ctx, key)
	ttlCmd := pipe.TTL(ctx, key)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, err
	}

	currentCount := countCmd.Val()
	ttl := ttlCmd.Val()

	return &RateLimitResult{
		Allowed:     currentCount < int64(rl.config.RequestsPerMinute),
		Remaining:   int64(rl.config.RequestsPerMinute) - currentCount,
		ResetTime:   now.Add(ttl),
		LimitType:   limitType,
		LimitValue:  rl.config.RequestsPerMinute,
		WindowStart: windowStart,
		WindowEnd:   now,
	}, nil
}

// Reset clears the rate limit for a specific client
func (rl *RateLimiter) Reset(limitType RateLimitType, identifier string) error {
	ctx := context.Background()
	key := rl.buildKey(limitType, identifier)

	err := rl.client.Del(ctx, key).Err()
	if err != nil {
		rl.logger.Error("Error resetting rate limit",
			zap.Error(err),
			zap.String("key", key),
		)
		return err
	}

	rl.logger.Info("Rate limit reset",
		zap.String("key", key),
		zap.String("limit_type", string(limitType)),
		zap.String("identifier", identifier),
	)

	return nil
}

// ResetAll clears all rate limits (useful for testing)
func (rl *RateLimiter) ResetAll() error {
	ctx := context.Background()
	pattern := "rate_limit:*"

	keys, err := rl.client.Keys(ctx, pattern).Result()
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		err = rl.client.Del(ctx, keys...).Err()
		if err != nil {
			return err
		}

		rl.logger.Info("All rate limits reset",
			zap.Int("keys_deleted", len(keys)),
		)
	}

	return nil
}

// GetRedisHealth checks Redis connectivity
func (rl *RateLimiter) GetRedisHealth() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return rl.client.Ping(ctx).Err()
}

// Close closes the connection to Redis
func (rl *RateLimiter) Close() error {
	return rl.client.Close()
}

// buildKey creates a Redis key for rate limiting
func (rl *RateLimiter) buildKey(limitType RateLimitType, identifier string) string {
	cleanIdentifier := strings.ReplaceAll(identifier, ":", "_")
	cleanIdentifier = strings.ReplaceAll(cleanIdentifier, "*", "_")
	cleanIdentifier = strings.ReplaceAll(cleanIdentifier, "?", "_")

	return fmt.Sprintf("rate_limit:%s:%s", limitType, cleanIdentifier)
}
