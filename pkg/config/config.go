package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config implements the configuration for the application
type Config struct {
	Environment    string               `yaml:"environment"`
	Server         ServerConfig         `yaml:"server"`
	Redis          RedisConfig          `yaml:"redis"`
	JWT            JWTConfig            `yaml:"jwt"`
	Telemetry      TelemetryConfig      `yaml:"telemetry"`
	Log            LogConfig            `yaml:"log"`
	RateLimit      RateLimitConfig      `yaml:"rate_limit"`
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker"`
	Proxy          ProxyConfig          `yaml:"proxy"`
}

type ServerConfig struct {
	Port            string        `yaml:"port"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	IdleTimeout     time.Duration `yaml:"idle_timeout"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

type RedisConfig struct {
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type JWTConfig struct {
	Secret         string        `yaml:"secret"`
	ExpirationTime time.Duration `yaml:"expiration_time"`
	RefreshTime    time.Duration `yaml:"refresh_time"`
	Issuer         string        `yaml:"issuer"`
	SigningMethod  string        `yaml:"signing_method"`
}

type TelemetryConfig struct {
	Enabled        bool   `yaml:"enabled"`
	PrometheusPort string `yaml:"prometheus_port"`
	ServiceName    string `yaml:"service_name"`
	ServiceVersion string `yaml:"service_version"`
	Environment    string `yaml:"environment"`
}

type LogConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	Output     string `yaml:"output"`
	MaxSize    int    `yaml:"max_size"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAge     int    `yaml:"max_age"`
}

type RateLimitConfig struct {
	RequestsPerMinute int           `yaml:"requests_per_minute"`
	BurstSize         int           `yaml:"burst_size"`
	WindowSize        time.Duration `yaml:"window_size"`
	CleanupInterval   time.Duration `yaml:"cleanup_interval"`
}

type CircuitBreakerConfig struct {
	MaxRequests uint32        `yaml:"max_requests"`
	Interval    time.Duration `yaml:"interval"`
	Timeout     time.Duration `yaml:"timeout"`
	ReadyToTrip int           `yaml:"ready_to_trip"`
}

type ProxyConfig struct {
	Targets         []TargetConfig `yaml:"targets"`
	DefaultTimeout  time.Duration  `yaml:"default_timeout"`
	FollowRedirects bool           `yaml:"follow_redirects"`
}

type TargetConfig struct {
	Name        string `yaml:"name"`
	URL         string `yaml:"url"`
	Path        string `yaml:"path"`
	HealthCheck string `yaml:"health_check"`
}

// Load loads the configuration from environment variables
func Load() (*Config, error) {
	config := &Config{
		Environment: getEnv("ENVIRONMENT", "development"),
		Server: ServerConfig{
			Port:            getEnv("SERVER_PORT", ":8080"),
			ReadTimeout:     getDurationEnv("SERVER_READ_TIMEOUT", 10*time.Second),
			WriteTimeout:    getDurationEnv("SERVER_WRITE_TIMEOUT", 10*time.Second),
			IdleTimeout:     getDurationEnv("SERVER_IDLE_TIMEOUT", 60*time.Second),
			ShutdownTimeout: getDurationEnv("SERVER_SHUTDOWN_TIMEOUT", 30*time.Second),
		},
		Redis: RedisConfig{
			Host:     getEnv("REDIS_HOST", "localhost"),
			Port:     getEnv("REDIS_PORT", "6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getIntEnv("REDIS_DB", 0),
		},
		JWT: JWTConfig{
			Secret:         getEnv("JWT_SECRET", "your-super-secret-jwt-key"),
			ExpirationTime: getDurationEnv("JWT_EXPIRATION", 24*time.Hour),
			RefreshTime:    getDurationEnv("JWT_REFRESH_TIME", 7*24*time.Hour),
			Issuer:         getEnv("JWT_ISSUER", "sentinel-gate"),
			SigningMethod:  getEnv("JWT_SIGNING_METHOD", "HS256"),
		},
		Telemetry: TelemetryConfig{
			Enabled:        getBoolEnv("TELEMETRY_ENABLED", true),
			PrometheusPort: getEnv("PROMETHEUS_PORT", ":9090"),
			ServiceName:    getEnv("SERVICE_NAME", "sentinel-gate"),
			ServiceVersion: getEnv("SERVICE_VERSION", "1.0.0"),
			Environment:    getEnv("TELEMETRY_ENVIRONMENT", "development"),
		},
		Log: LogConfig{
			Level:      getEnv("LOG_LEVEL", "info"),
			Format:     getEnv("LOG_FORMAT", "json"),
			Output:     getEnv("LOG_OUTPUT", "stdout"),
			MaxSize:    getIntEnv("LOG_MAX_SIZE", 100),
			MaxBackups: getIntEnv("LOG_MAX_BACKUPS", 3),
			MaxAge:     getIntEnv("LOG_MAX_AGE", 28),
		},
		RateLimit: RateLimitConfig{
			RequestsPerMinute: getIntEnv("RATE_LIMIT_RPM", 100),
			BurstSize:         getIntEnv("RATE_LIMIT_BURST", 10),
			WindowSize:        getDurationEnv("RATE_LIMIT_WINDOW", time.Minute),
			CleanupInterval:   getDurationEnv("RATE_LIMIT_CLEANUP", 10*time.Minute),
		},
		CircuitBreaker: CircuitBreakerConfig{
			MaxRequests: uint32(getIntEnv("CB_MAX_REQUESTS", 3)),
			Interval:    getDurationEnv("CB_INTERVAL", 60*time.Second),
			Timeout:     getDurationEnv("CB_TIMEOUT", 60*time.Second),
			ReadyToTrip: getIntEnv("CB_READY_TO_TRIP", 5),
		},
		Proxy: ProxyConfig{
			DefaultTimeout:  getDurationEnv("PROXY_DEFAULT_TIMEOUT", 30*time.Second),
			FollowRedirects: getBoolEnv("PROXY_FOLLOW_REDIRECTS", false),
			Targets: []TargetConfig{
				{
					Name:        "api-users",
					URL:         getEnv("TARGET_USERS_URL", "http://localhost:3001"),
					Path:        "/api/users/*",
					HealthCheck: "/health",
				},
				{
					Name:        "api-orders",
					URL:         getEnv("TARGET_ORDERS_URL", "http://localhost:3002"),
					Path:        "/api/orders/*",
					HealthCheck: "/health",
				},
			},
		},
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.JWT.Secret == "" {
		return fmt.Errorf("JWT_SECRET is required")
	}

	if len(c.JWT.Secret) < 32 {
		return fmt.Errorf("JWT_SECRET must be at least 32 characters long")
	}

	if c.Redis.Host == "" {
		return fmt.Errorf("REDIS_HOST is required")
	}

	return nil
}

// Helper functions to load environment variables
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}
