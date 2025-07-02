package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"sentinel_gate/pkg/config"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	otelprometheus "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	otelmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

const (
	serviceName    = "sentinel-gate"
	serviceVersion = "1.0.0"
)

// Telemetry holds all telemetry providers and metrics
type Telemetry struct {
	logger         *zap.Logger
	tracerProvider *trace.TracerProvider
	meterProvider  *otelmetric.MeterProvider
	tracer         oteltrace.Tracer
	meter          metric.Meter

	// Prometheus metrics
	registry          *prometheus.Registry
	requestsTotal     metric.Int64Counter
	requestDuration   metric.Float64Histogram
	requestsInFlight  metric.Int64UpDownCounter
	rateLimitExceeded metric.Int64Counter
	circuitBreakerOps metric.Int64Counter
	errorTotal        metric.Int64Counter
	authOperations    metric.Int64Counter
	proxyOperations   metric.Int64Counter
}

// Init initializes the complete telemetry stack
func Init(cfg config.TelemetryConfig, logger *zap.Logger) (*Telemetry, func(), error) {
	if !cfg.Enabled {
		return &Telemetry{logger: logger}, func() {}, nil
	}

	t := &Telemetry{
		logger:   logger,
		registry: prometheus.NewRegistry(),
	}

	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(serviceVersion),
			semconv.DeploymentEnvironment(cfg.Environment),
		),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Initialize tracing
	if err := t.initTracing(res, cfg); err != nil {
		return nil, nil, fmt.Errorf("failed to initialize tracing: %w", err)
	}

	// Initialize metrics
	if err := t.initMetrics(res, cfg); err != nil {
		return nil, nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}

	// Create metrics instruments
	if err := t.createMetrics(); err != nil {
		return nil, nil, fmt.Errorf("failed to create metrics: %w", err)
	}

	logger.Info("Telemetry initialized successfully",
		zap.String("service", serviceName),
		zap.String("version", serviceVersion),
		zap.Bool("tracing_enabled", cfg.TracingEnabled),
		zap.String("jaeger_endpoint", cfg.JaegerEndpoint),
	)

	shutdown := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if t.tracerProvider != nil {
			if err := t.tracerProvider.Shutdown(ctx); err != nil {
				logger.Error("Failed to shutdown tracer provider", zap.Error(err))
			}
		}

		if t.meterProvider != nil {
			if err := t.meterProvider.Shutdown(ctx); err != nil {
				logger.Error("Failed to shutdown meter provider", zap.Error(err))
			}
		}

		logger.Info("Telemetry shutdown completed")
	}

	return t, shutdown, nil
}

// initTracing sets up OpenTelemetry tracing with Jaeger exporter
func (t *Telemetry) initTracing(res *resource.Resource, cfg config.TelemetryConfig) error {
	if !cfg.TracingEnabled {
		return nil
	}

	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(cfg.JaegerEndpoint)))
	if err != nil {
		return fmt.Errorf("failed to create Jaeger exporter: %w", err)
	}

	t.tracerProvider = trace.NewTracerProvider(
		trace.WithBatcher(exp),
		trace.WithResource(res),
		trace.WithSampler(trace.TraceIDRatioBased(cfg.TracingSampleRate)),
	)

	otel.SetTracerProvider(t.tracerProvider)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	t.tracer = otel.Tracer(serviceName, oteltrace.WithInstrumentationVersion(serviceVersion))

	return nil
}

// initMetrics sets up OpenTelemetry metrics with Prometheus exporter
func (t *Telemetry) initMetrics(res *resource.Resource, cfg config.TelemetryConfig) error {
	promExporter, err := otelprometheus.New(
		otelprometheus.WithRegisterer(t.registry),
		otelprometheus.WithoutUnits(),
		otelprometheus.WithoutScopeInfo(),
	)
	if err != nil {
		return fmt.Errorf("failed to create Prometheus exporter: %w", err)
	}

	t.meterProvider = otelmetric.NewMeterProvider(
		otelmetric.WithResource(res),
		otelmetric.WithReader(promExporter),
	)

	otel.SetMeterProvider(t.meterProvider)

	t.meter = otel.Meter(serviceName, metric.WithInstrumentationVersion(serviceVersion))

	return nil
}

// createMetrics creates all metric instruments
func (t *Telemetry) createMetrics() error {
	var err error

	t.requestsTotal, err = t.meter.Int64Counter(
		"http_requests_total",
		metric.WithDescription("Total number of HTTP requests"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return fmt.Errorf("failed to create requests counter: %w", err)
	}

	t.requestDuration, err = t.meter.Float64Histogram(
		"http_request_duration_seconds",
		metric.WithDescription("HTTP request duration in seconds"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
	)
	if err != nil {
		return fmt.Errorf("failed to create request duration histogram: %w", err)
	}

	t.requestsInFlight, err = t.meter.Int64UpDownCounter(
		"http_requests_in_flight",
		metric.WithDescription("Current number of HTTP requests being processed"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return fmt.Errorf("failed to create requests in flight gauge: %w", err)
	}

	t.rateLimitExceeded, err = t.meter.Int64Counter(
		"rate_limit_exceeded_total",
		metric.WithDescription("Total number of rate limit exceeded events"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return fmt.Errorf("failed to create rate limit counter: %w", err)
	}

	t.circuitBreakerOps, err = t.meter.Int64Counter(
		"circuit_breaker_operations_total",
		metric.WithDescription("Total number of circuit breaker operations"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return fmt.Errorf("failed to create circuit breaker counter: %w", err)
	}

	t.errorTotal, err = t.meter.Int64Counter(
		"errors_total",
		metric.WithDescription("Total number of errors by type"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return fmt.Errorf("failed to create error counter: %w", err)
	}

	t.authOperations, err = t.meter.Int64Counter(
		"auth_operations_total",
		metric.WithDescription("Total number of authentication operations"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return fmt.Errorf("failed to create auth operations counter: %w", err)
	}

	t.proxyOperations, err = t.meter.Int64Counter(
		"proxy_operations_total",
		metric.WithDescription("Total number of proxy operations"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return fmt.Errorf("failed to create proxy operations counter: %w", err)
	}

	return nil
}

// GetPrometheusHandler returns the Prometheus metrics handler
func (t *Telemetry) GetPrometheusHandler() http.Handler {
	return promhttp.HandlerFor(t.registry, promhttp.HandlerOpts{
		Registry: t.registry,
	})
}

// StartSpan creates a new span with the given name and options
func (t *Telemetry) StartSpan(ctx context.Context, name string, opts ...oteltrace.SpanStartOption) (context.Context, oteltrace.Span) {
	if t.tracer == nil {
		return ctx, oteltrace.SpanFromContext(ctx)
	}
	return t.tracer.Start(ctx, name, opts...)
}

// IncrementRequestCounter increments the HTTP request counter
func (t *Telemetry) IncrementRequestCounter(ctx context.Context, method, path, status string) {
	if t.requestsTotal == nil {
		return
	}

	t.requestsTotal.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("method", method),
			attribute.String("path", path),
			attribute.String("status_code", status),
		),
	)
}

// RecordRequestDuration records the HTTP request duration
func (t *Telemetry) RecordRequestDuration(ctx context.Context, duration time.Duration, method, path string) {
	if t.requestDuration == nil {
		return
	}

	t.requestDuration.Record(ctx, duration.Seconds(),
		metric.WithAttributes(
			attribute.String("method", method),
			attribute.String("path", path),
		),
	)
}

// IncrementRequestsInFlight increments the in-flight requests counter
func (t *Telemetry) IncrementRequestsInFlight(ctx context.Context) {
	if t.requestsInFlight == nil {
		return
	}
	t.requestsInFlight.Add(ctx, 1)
}

// DecrementRequestsInFlight decrements the in-flight requests counter
func (t *Telemetry) DecrementRequestsInFlight(ctx context.Context) {
	if t.requestsInFlight == nil {
		return
	}
	t.requestsInFlight.Add(ctx, -1)
}

// IncrementRateLimitExceeded increments the rate limit exceeded counter
func (t *Telemetry) IncrementRateLimitExceeded(ctx context.Context, clientIP, limitType string) {
	if t.rateLimitExceeded == nil {
		return
	}

	t.rateLimitExceeded.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("client_ip", clientIP),
			attribute.String("limit_type", limitType),
		),
	)
}

// IncrementCircuitBreakerOps increments the circuit breaker operations counter
func (t *Telemetry) IncrementCircuitBreakerOps(ctx context.Context, service, operation, state string) {
	if t.circuitBreakerOps == nil {
		return
	}

	t.circuitBreakerOps.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("service", service),
			attribute.String("operation", operation),
			attribute.String("state", state),
		),
	)
}

// IncrementErrorTotal increments the error counter
func (t *Telemetry) IncrementErrorTotal(ctx context.Context, errorType, component string) {
	if t.errorTotal == nil {
		return
	}

	t.errorTotal.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("error_type", errorType),
			attribute.String("component", component),
		),
	)
}

// IncrementAuthOperations increments the authentication operations counter
func (t *Telemetry) IncrementAuthOperations(ctx context.Context, operation, result string) {
	if t.authOperations == nil {
		return
	}

	t.authOperations.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("operation", operation),
			attribute.String("result", result),
		),
	)
}

// IncrementProxyOperations increments the proxy operations counter
func (t *Telemetry) IncrementProxyOperations(ctx context.Context, targetService, method string, statusCode int) {
	if t.proxyOperations == nil {
		return
	}

	t.proxyOperations.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("target_service", targetService),
			attribute.String("method", method),
			attribute.Int("status_code", statusCode),
		),
	)
}

// AddSpanEvent adds an event to the current span
func (t *Telemetry) AddSpanEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	span := oteltrace.SpanFromContext(ctx)
	if span == nil {
		return
	}
	span.AddEvent(name, oteltrace.WithAttributes(attrs...))
}

// SetSpanAttributes sets attributes on the current span
func (t *Telemetry) SetSpanAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	span := oteltrace.SpanFromContext(ctx)
	if span == nil {
		return
	}
	span.SetAttributes(attrs...)
}

// RecordError records an error on the current span
func (t *Telemetry) RecordError(ctx context.Context, err error) {
	span := oteltrace.SpanFromContext(ctx)
	if span == nil {
		return
	}
	span.RecordError(err)
}

// GetTracer returns the tracer instance
func (t *Telemetry) GetTracer() oteltrace.Tracer {
	return t.tracer
}

// Instrumentation information for the telemetry package
func GetInstrumentationScope() instrumentation.Scope {
	return instrumentation.Scope{
		Name:    serviceName,
		Version: serviceVersion,
	}
}
