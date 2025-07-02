package circuitbreaker

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"sentinel_gate/pkg/config"

	"github.com/sony/gobreaker"
	"go.uber.org/zap"
)

// CircuitBreakerManager manages multiple circuit breakers for different services
type CircuitBreakerManager struct {
	breakers map[string]*gobreaker.CircuitBreaker
	settings map[string]gobreaker.Settings
	config   config.CircuitBreakerConfig
	logger   *zap.Logger
	metrics  *Metrics
	mu       sync.RWMutex
}

// Metrics holds circuit breaker metrics
type Metrics struct {
	RequestsTotal    map[string]int64
	FailuresTotal    map[string]int64
	SuccessTotal     map[string]int64
	CircuitOpened    map[string]int64
	CircuitClosed    map[string]int64
	CircuitHalfOpen  map[string]int64
	FallbackExecuted map[string]int64
	mu               sync.RWMutex
}

// CircuitBreakerState represents the current state of a circuit breaker
type CircuitBreakerState struct {
	ServiceName string             `json:"service_name"`
	State       gobreaker.State    `json:"state"`
	Counts      gobreaker.Counts   `json:"counts"`
	Settings    gobreaker.Settings `json:"settings"`
	NextAttempt time.Time          `json:"next_attempt,omitempty"`
}

// FallbackResponse represents a fallback response configuration
type FallbackResponse struct {
	StatusCode int               `json:"status_code"`
	Message    string            `json:"message"`
	RetryAfter int               `json:"retry_after_seconds"`
	Headers    map[string]string `json:"headers,omitempty"`
}

// NewCircuitBreakerManager creates a new circuit breaker manager
func NewCircuitBreakerManager(cfg config.CircuitBreakerConfig, logger *zap.Logger) *CircuitBreakerManager {
	return &CircuitBreakerManager{
		breakers: make(map[string]*gobreaker.CircuitBreaker),
		settings: make(map[string]gobreaker.Settings),
		config:   cfg,
		logger:   logger,
		metrics:  NewMetrics(),
	}
}

// NewMetrics creates a new metrics instance
func NewMetrics() *Metrics {
	return &Metrics{
		RequestsTotal:    make(map[string]int64),
		FailuresTotal:    make(map[string]int64),
		SuccessTotal:     make(map[string]int64),
		CircuitOpened:    make(map[string]int64),
		CircuitClosed:    make(map[string]int64),
		CircuitHalfOpen:  make(map[string]int64),
		FallbackExecuted: make(map[string]int64),
	}
}

// GetOrCreateBreaker gets or creates a circuit breaker for a service
func (cbm *CircuitBreakerManager) GetOrCreateBreaker(serviceName string) *gobreaker.CircuitBreaker {
	cbm.mu.RLock()
	breaker, exists := cbm.breakers[serviceName]
	cbm.mu.RUnlock()

	if exists {
		return breaker
	}

	cbm.mu.Lock()
	defer cbm.mu.Unlock()

	// Double-check pattern
	if breaker, exists := cbm.breakers[serviceName]; exists {
		return breaker
	}

	settings := gobreaker.Settings{
		Name:        serviceName,
		MaxRequests: uint32(cbm.config.MaxRequests),
		Interval:    cbm.config.Interval,
		Timeout:     cbm.config.Timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			// Circuit opens if failure rate > threshold AND minimum requests met
			failureRate := float64(counts.TotalFailures) / float64(counts.Requests)
			return counts.Requests >= uint32(cbm.config.MinRequests) &&
				failureRate >= cbm.config.FailureThreshold
		},
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			cbm.onStateChange(name, from, to)
		},
		IsSuccessful: func(err error) bool {
			// Consider HTTP errors as failures
			if httpErr, ok := err.(*HTTPError); ok {
				return httpErr.StatusCode < 500
			}
			return err == nil
		},
	}

	breaker = gobreaker.NewCircuitBreaker(settings)
	cbm.breakers[serviceName] = breaker
	cbm.settings[serviceName] = settings

	cbm.logger.Info("Circuit breaker created",
		zap.String("service", serviceName),
		zap.Uint32("max_requests", settings.MaxRequests),
		zap.Duration("interval", settings.Interval),
		zap.Duration("timeout", settings.Timeout),
		zap.Float64("failure_threshold", cbm.config.FailureThreshold),
		zap.Int("min_requests", cbm.config.MinRequests),
	)

	return breaker
}

// Execute executes a function through the circuit breaker
func (cbm *CircuitBreakerManager) Execute(serviceName string, operation func() (interface{}, error)) (interface{}, error) {
	breaker := cbm.GetOrCreateBreaker(serviceName)

	cbm.incrementMetric("RequestsTotal", serviceName)

	result, err := breaker.Execute(func() (interface{}, error) {
		return operation()
	})

	if err != nil {
		if err == gobreaker.ErrOpenState {
			cbm.logger.Warn("Circuit breaker open - request blocked",
				zap.String("service", serviceName),
				zap.String("state", "OPEN"),
			)
			cbm.incrementMetric("FallbackExecuted", serviceName)
			return cbm.createFallbackResponse(serviceName), &CircuitBreakerError{
				ServiceName: serviceName,
				State:       gobreaker.StateOpen,
				Message:     "Service temporarily unavailable - circuit breaker open",
			}
		}

		if err == gobreaker.ErrTooManyRequests {
			cbm.logger.Warn("Circuit breaker half-open - too many requests",
				zap.String("service", serviceName),
				zap.String("state", "HALF_OPEN"),
			)
			cbm.incrementMetric("FallbackExecuted", serviceName)
			return cbm.createFallbackResponse(serviceName), &CircuitBreakerError{
				ServiceName: serviceName,
				State:       gobreaker.StateHalfOpen,
				Message:     "Service temporarily unavailable - circuit breaker half-open",
			}
		}

		cbm.incrementMetric("FailuresTotal", serviceName)
		cbm.logger.Warn("Circuit breaker - operation failed",
			zap.String("service", serviceName),
			zap.Error(err),
		)
		return nil, err
	}

	cbm.incrementMetric("SuccessTotal", serviceName)
	cbm.logger.Debug("Circuit breaker - operation succeeded",
		zap.String("service", serviceName),
	)

	return result, nil
}

// ExecuteHTTP executes an HTTP operation through the circuit breaker
func (cbm *CircuitBreakerManager) ExecuteHTTP(serviceName string, operation func() (*http.Response, error)) (*http.Response, error) {
	result, err := cbm.Execute(serviceName, func() (interface{}, error) {
		resp, err := operation()
		if err != nil {
			return nil, err
		}

		// Consider 5xx status codes as failures
		if resp.StatusCode >= 500 {
			return resp, &HTTPError{
				StatusCode: resp.StatusCode,
				Message:    fmt.Sprintf("HTTP %d error", resp.StatusCode),
			}
		}

		return resp, nil
	})

	if err != nil {
		if cbErr, ok := err.(*CircuitBreakerError); ok {
			// Return fallback HTTP response
			return cbm.createFallbackHTTPResponse(cbErr), nil
		}
		return nil, err
	}

	if response, ok := result.(*http.Response); ok {
		return response, nil
	}

	return nil, fmt.Errorf("unexpected response type from circuit breaker")
}

// onStateChange handles circuit breaker state changes
func (cbm *CircuitBreakerManager) onStateChange(name string, from gobreaker.State, to gobreaker.State) {
	cbm.logger.Info("Circuit breaker state changed",
		zap.String("service", name),
		zap.String("from_state", from.String()),
		zap.String("to_state", to.String()),
	)

	switch to {
	case gobreaker.StateOpen:
		cbm.incrementMetric("CircuitOpened", name)
		cbm.logger.Warn("Circuit breaker OPENED - blocking requests",
			zap.String("service", name),
			zap.Duration("timeout", cbm.config.Timeout),
		)
	case gobreaker.StateClosed:
		cbm.incrementMetric("CircuitClosed", name)
		cbm.logger.Info("Circuit breaker CLOSED - allowing requests",
			zap.String("service", name),
		)
	case gobreaker.StateHalfOpen:
		cbm.incrementMetric("CircuitHalfOpen", name)
		cbm.logger.Info("Circuit breaker HALF-OPEN - testing requests",
			zap.String("service", name),
			zap.Uint32("max_requests", cbm.config.MaxRequests),
		)
	}
}

// createFallbackResponse creates a fallback response
func (cbm *CircuitBreakerManager) createFallbackResponse(serviceName string) *FallbackResponse {
	retryAfter := int(cbm.config.Timeout.Seconds())

	return &FallbackResponse{
		StatusCode: http.StatusServiceUnavailable,
		Message:    fmt.Sprintf("Service %s is temporarily unavailable", serviceName),
		RetryAfter: retryAfter,
		Headers: map[string]string{
			"Retry-After":       fmt.Sprintf("%d", retryAfter),
			"X-Circuit-Breaker": "OPEN",
			"X-Fallback-Reason": "circuit-breaker",
			"X-Service-Name":    serviceName,
		},
	}
}

// createFallbackHTTPResponse creates a fallback HTTP response
func (cbm *CircuitBreakerManager) createFallbackHTTPResponse(cbErr *CircuitBreakerError) *http.Response {
	fallback := cbm.createFallbackResponse(cbErr.ServiceName)

	// Create a simple HTTP response (in practice, this would be more sophisticated)
	resp := &http.Response{
		StatusCode: fallback.StatusCode,
		Header:     make(http.Header),
	}

	for key, value := range fallback.Headers {
		resp.Header.Set(key, value)
	}

	return resp
}

// GetState returns the current state of a circuit breaker
func (cbm *CircuitBreakerManager) GetState(serviceName string) *CircuitBreakerState {
	cbm.mu.RLock()
	breaker, exists := cbm.breakers[serviceName]
	settings, settingsExist := cbm.settings[serviceName]
	cbm.mu.RUnlock()

	if !exists {
		return nil
	}

	state := &CircuitBreakerState{
		ServiceName: serviceName,
		State:       breaker.State(),
		Counts:      breaker.Counts(),
	}

	// Add settings if available
	if settingsExist {
		state.Settings = settings
	}

	// Add next attempt time for open state
	if breaker.State() == gobreaker.StateOpen {
		// Estimate next attempt time based on timeout
		state.NextAttempt = time.Now().Add(cbm.config.Timeout)
	}

	return state
}

// GetAllStates returns states of all circuit breakers
func (cbm *CircuitBreakerManager) GetAllStates() map[string]*CircuitBreakerState {
	cbm.mu.RLock()
	defer cbm.mu.RUnlock()

	states := make(map[string]*CircuitBreakerState)
	for name := range cbm.breakers {
		if state := cbm.GetState(name); state != nil {
			states[name] = state
		}
	}

	return states
}

// GetMetrics returns current metrics
func (cbm *CircuitBreakerManager) GetMetrics() *Metrics {
	cbm.metrics.mu.RLock()
	defer cbm.metrics.mu.RUnlock()

	// Create a copy to avoid race conditions
	metrics := &Metrics{
		RequestsTotal:    make(map[string]int64),
		FailuresTotal:    make(map[string]int64),
		SuccessTotal:     make(map[string]int64),
		CircuitOpened:    make(map[string]int64),
		CircuitClosed:    make(map[string]int64),
		CircuitHalfOpen:  make(map[string]int64),
		FallbackExecuted: make(map[string]int64),
	}

	for k, v := range cbm.metrics.RequestsTotal {
		metrics.RequestsTotal[k] = v
	}
	for k, v := range cbm.metrics.FailuresTotal {
		metrics.FailuresTotal[k] = v
	}
	for k, v := range cbm.metrics.SuccessTotal {
		metrics.SuccessTotal[k] = v
	}
	for k, v := range cbm.metrics.CircuitOpened {
		metrics.CircuitOpened[k] = v
	}
	for k, v := range cbm.metrics.CircuitClosed {
		metrics.CircuitClosed[k] = v
	}
	for k, v := range cbm.metrics.CircuitHalfOpen {
		metrics.CircuitHalfOpen[k] = v
	}
	for k, v := range cbm.metrics.FallbackExecuted {
		metrics.FallbackExecuted[k] = v
	}

	return metrics
}

// incrementMetric safely increments a metric
func (cbm *CircuitBreakerManager) incrementMetric(metricName, serviceName string) {
	cbm.metrics.mu.Lock()
	defer cbm.metrics.mu.Unlock()

	switch metricName {
	case "RequestsTotal":
		cbm.metrics.RequestsTotal[serviceName]++
	case "FailuresTotal":
		cbm.metrics.FailuresTotal[serviceName]++
	case "SuccessTotal":
		cbm.metrics.SuccessTotal[serviceName]++
	case "CircuitOpened":
		cbm.metrics.CircuitOpened[serviceName]++
	case "CircuitClosed":
		cbm.metrics.CircuitClosed[serviceName]++
	case "CircuitHalfOpen":
		cbm.metrics.CircuitHalfOpen[serviceName]++
	case "FallbackExecuted":
		cbm.metrics.FallbackExecuted[serviceName]++
	}
}

// Reset resets circuit breaker state for a service (useful for testing)
func (cbm *CircuitBreakerManager) Reset(serviceName string) {
	cbm.mu.Lock()
	defer cbm.mu.Unlock()

	if _, exists := cbm.breakers[serviceName]; exists {
		// Remove and recreate the breaker to reset state
		delete(cbm.breakers, serviceName)
		delete(cbm.settings, serviceName)
		cbm.logger.Info("Circuit breaker reset",
			zap.String("service", serviceName),
		)
	}
}

// HTTPError represents an HTTP-specific error
type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
}

// CircuitBreakerError represents a circuit breaker specific error
type CircuitBreakerError struct {
	ServiceName string
	State       gobreaker.State
	Message     string
}

func (e *CircuitBreakerError) Error() string {
	return fmt.Sprintf("Circuit breaker %s (%s): %s", e.ServiceName, e.State.String(), e.Message)
}

// HealthCheck checks if circuit breakers are functioning
func (cbm *CircuitBreakerManager) HealthCheck() map[string]interface{} {
	cbm.mu.RLock()
	defer cbm.mu.RUnlock()

	health := map[string]interface{}{
		"circuit_breakers_count": len(cbm.breakers),
		"circuit_breakers":       make(map[string]interface{}),
	}

	for name, breaker := range cbm.breakers {
		state := breaker.State()
		counts := breaker.Counts()

		health["circuit_breakers"].(map[string]interface{})[name] = map[string]interface{}{
			"state":                 state.String(),
			"requests":              counts.Requests,
			"total_successes":       counts.TotalSuccesses,
			"total_failures":        counts.TotalFailures,
			"consecutive_successes": counts.ConsecutiveSuccesses,
			"consecutive_failures":  counts.ConsecutiveFailures,
		}
	}

	return health
}
