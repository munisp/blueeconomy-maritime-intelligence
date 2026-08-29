// Package telemetry wires OpenTelemetry tracing and Prometheus metrics for
// the service. Telemetry is environment-configured and follows the service's
// fail-closed posture: malformed or contradictory configuration is a startup
// error. Tracing is disabled by default; a disabled service runs an explicit
// no-op tracer and still serves local Prometheus metrics on GET /metrics.
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/codes"
	otlptracegrpc "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Config is the validated telemetry configuration. Enabled is false when no
// OTLP endpoint is configured; every other field is then ignored.
type Config struct {
	Enabled     bool
	Endpoint    string
	Insecure    bool
	ServiceName string
}

// LoadConfig reads OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_INSECURE,
// OTEL_SERVICE_NAME and OTEL_SDK_DISABLED. An absent endpoint means tracing is
// disabled; a present but malformed endpoint, an unknown boolean value, or a
// contradictory OTEL_SDK_DISABLED=true fails closed.
func LoadConfig(serviceName string) (Config, error) {
	if strings.TrimSpace(serviceName) == "" {
		return Config{}, errors.New("telemetry service name is required")
	}
	config := Config{ServiceName: serviceName}
	if override := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")); override != "" {
		if len(override) > 128 {
			return Config{}, errors.New("OTEL_SERVICE_NAME must be at most 128 characters")
		}
		config.ServiceName = override
	}
	disabled, err := parseBoolean("OTEL_SDK_DISABLED")
	if err != nil {
		return Config{}, err
	}
	insecure, err := parseBoolean("OTEL_EXPORTER_OTLP_INSECURE")
	if err != nil {
		return Config{}, err
	}
	config.Insecure = insecure
	endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if disabled {
		if endpoint != "" {
			return Config{}, errors.New("OTEL_SDK_DISABLED=true conflicts with OTEL_EXPORTER_OTLP_ENDPOINT; remove one (fail-closed)")
		}
		return config, nil
	}
	if endpoint == "" {
		return config, nil
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" {
		return Config{}, fmt.Errorf("OTEL_EXPORTER_OTLP_ENDPOINT must be a host:port pair without scheme, credentials or path: %q", endpoint)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return Config{}, fmt.Errorf("OTEL_EXPORTER_OTLP_ENDPOINT has an invalid port: %q", endpoint)
	}
	config.Enabled = true
	config.Endpoint = endpoint
	return config, nil
}

// parseBoolean accepts only empty, "true" or "false"; anything else fails
// closed rather than being silently interpreted.
func parseBoolean(name string) (bool, error) {
	switch value := strings.TrimSpace(os.Getenv(name)); value {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("%s must be true or false when set", name)
	}
}

// Telemetry carries the tracer, the Prometheus meter pipeline and the HTTP
// middleware. It is safe to use a zero-capacity instance only through Setup.
type Telemetry struct {
	config         Config
	tracer         trace.Tracer
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider
	metricsHandler http.Handler
	requests       metric.Int64Counter
	duration       metric.Float64Histogram
	fusionLatency  metric.Float64Histogram
	fusionErrors   metric.Int64Counter
	dropped        metric.Int64Counter
}

// Setup builds the meter and tracer pipelines. The Prometheus exporter is
// always local-only (no egress) and is installed even when tracing is
// disabled; the OTLP gRPC trace exporter is created only when enabled.
func Setup(ctx context.Context, config Config) (*Telemetry, error) {
	if strings.TrimSpace(config.ServiceName) == "" {
		return nil, errors.New("telemetry service name is required")
	}
	serviceResource := resource.NewSchemaless(attribute.String("service.name", config.ServiceName))
	meterProvider, metricsHandler, err := newMeterPipeline(serviceResource)
	if err != nil {
		return nil, err
	}
	meter := meterProvider.Meter(config.ServiceName)
	requests, err := meter.Int64Counter("http.server.requests", metric.WithDescription("HTTP requests partitioned by method, route and status code"))
	if err != nil {
		return nil, fmt.Errorf("create request counter: %w", err)
	}
	duration, err := meter.Float64Histogram("http.server.request.duration", metric.WithUnit("s"), metric.WithDescription("HTTP request duration in seconds"))
	if err != nil {
		return nil, fmt.Errorf("create duration histogram: %w", err)
	}
	fusionLatency, err := meter.Float64Histogram("isr.anomaly.detection.latency", metric.WithUnit("s"), metric.WithDescription("Anomaly detection latency in seconds (p99 <= 5s KPI), partitioned by anomaly kind"))
	if err != nil {
		return nil, fmt.Errorf("create anomaly latency histogram: %w", err)
	}
	fusionErrors, err := meter.Int64Counter("isr.fusion.ingest_errors", metric.WithDescription("Fusion ingest failures after durable detection admission"))
	if err != nil {
		return nil, fmt.Errorf("create fusion error counter: %w", err)
	}
	dropped, err := meter.Int64Counter("telemetry_dropped_total", metric.WithDescription("Spans dropped because the OTLP collector was unreachable; telemetry never fails the business path"))
	if err != nil {
		return nil, fmt.Errorf("create dropped-telemetry counter: %w", err)
	}
	telemetry := &Telemetry{
		config:         config,
		meterProvider:  meterProvider,
		metricsHandler: metricsHandler,
		requests:       requests,
		duration:       duration,
		fusionLatency:  fusionLatency,
		fusionErrors:   fusionErrors,
		dropped:        dropped,
	}
	// Propagation is installed even when export is disabled: incoming
	// traceparent/baggage must still be honoured so distributed context
	// survives services running with telemetry off (the one sanctioned
	// fail-open: telemetry absence never changes request handling).
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	if !config.Enabled {
		telemetry.tracer = noop.NewTracerProvider().Tracer(config.ServiceName)
		return telemetry, nil
	}
	exporterOptions := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(config.Endpoint)}
	if config.Insecure {
		exporterOptions = append(exporterOptions, otlptracegrpc.WithInsecure())
	}
	exporter, err := otlptracegrpc.New(ctx, exporterOptions...)
	if err != nil {
		return nil, fmt.Errorf("create OTLP gRPC trace exporter: %w", err)
	}
	telemetry.tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(&countingExporter{next: exporter, dropped: dropped}),
		sdktrace.WithResource(serviceResource),
	)
	otel.SetTracerProvider(telemetry.tracerProvider)
	telemetry.tracer = telemetry.tracerProvider.Tracer(config.ServiceName)
	return telemetry, nil
}

// countingExporter wraps the OTLP exporter so every failed export increments
// telemetry_dropped_total. The batch processor already isolates the business
// path from collector outages (async, bounded queue, drop-on-full); this only
// makes the drops observable.
type countingExporter struct {
	next    sdktrace.SpanExporter
	dropped metric.Int64Counter
}

func (exporter *countingExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	err := exporter.next.ExportSpans(ctx, spans)
	if err != nil {
		exporter.dropped.Add(ctx, int64(len(spans)))
	}
	return err
}

func (exporter *countingExporter) Shutdown(ctx context.Context) error {
	return exporter.next.Shutdown(ctx)
}

// newMeterPipeline installs a Prometheus reader on a private registry so
// repeated Setup calls (tests, in-process binaries) never collide on the
// global Prometheus registry.
func newMeterPipeline(serviceResource *resource.Resource) (*sdkmetric.MeterProvider, http.Handler, error) {
	registry := prometheus.NewRegistry()
	reader, err := otelprom.New(otelprom.WithRegisterer(registry))
	if err != nil {
		return nil, nil, fmt.Errorf("create Prometheus exporter: %w", err)
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader), sdkmetric.WithResource(serviceResource))
	return provider, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}), nil
}

// Enabled reports whether OTLP trace export is active.
func (telemetry *Telemetry) Enabled() bool {
	return telemetry.config.Enabled
}

// Tracer returns the service tracer: the OTLP-backed SDK tracer when enabled,
// otherwise the explicit no-op tracer.
func (telemetry *Telemetry) Tracer() trace.Tracer {
	return telemetry.tracer
}

// MetricsHandler serves the Prometheus scrape endpoint.
func (telemetry *Telemetry) MetricsHandler() http.Handler {
	return telemetry.metricsHandler
}

// Shutdown flushes and stops both providers.
func (telemetry *Telemetry) Shutdown(ctx context.Context) error {
	var shutdownErr error
	if telemetry.tracerProvider != nil {
		shutdownErr = telemetry.tracerProvider.Shutdown(ctx)
	}
	if telemetry.meterProvider != nil {
		if err := telemetry.meterProvider.Shutdown(ctx); shutdownErr == nil {
			shutdownErr = err
		}
	}
	return shutdownErr
}

// statusRecorder captures the response status code for span attributes and
// metrics without changing response semantics.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (recorder *statusRecorder) WriteHeader(status int) {
	recorder.status = status
	recorder.ResponseWriter.WriteHeader(status)
}

// tenantBaggageAttributes copies the platform tenant-attribution baggage
// members (tenant.id, agency — injected at the edge from JWT claims) onto
// server span attributes. Baggage values are free-form strings, so they stay
// on traces only; metrics never carry them (low-cardinality rule).
func tenantBaggageAttributes(ctx context.Context) []attribute.KeyValue {
	members := baggage.FromContext(ctx)
	attributes := make([]attribute.KeyValue, 0, 2)
	if value := members.Member("tenant.id").Value(); value != "" {
		attributes = append(attributes, attribute.String("tenant.id", value))
	}
	if value := members.Member("agency").Value(); value != "" {
		attributes = append(attributes, attribute.String("agency", value))
	}
	return attributes
}

// Middleware traces and meters every request. The incoming W3C
// traceparent/baggage headers are extracted so the server span continues the
// caller's trace. The span starts under the HTTP method and is renamed to the
// matched route pattern (http.Request.Pattern) once the ServeMux has routed,
// so metric labels never carry raw paths or identifiers. Unmatched routes are
// labelled "unmatched".
func (telemetry *Telemetry) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		extracted := otel.GetTextMapPropagator().Extract(request.Context(), propagation.HeaderCarrier(request.Header))
		spanAttributes := append([]attribute.KeyValue{attribute.String("http.request.method", request.Method)}, tenantBaggageAttributes(extracted)...)
		ctx, span := telemetry.tracer.Start(extracted, request.Method,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(spanAttributes...))
		recorder := &statusRecorder{ResponseWriter: writer, status: http.StatusOK}
		// WithContext shallow-copies the request; the ServeMux records the
		// matched route pattern on that copy, so read it back from there.
		routed := request.WithContext(ctx)
		next.ServeHTTP(recorder, routed)
		route := routed.Pattern
		if route == "" {
			route = "unmatched"
		} else {
			span.SetName(route)
		}
		span.SetAttributes(
			attribute.String("http.route", route),
			attribute.Int("http.response.status_code", recorder.status),
		)
		if recorder.status >= http.StatusInternalServerError {
			span.SetStatus(codes.Error, http.StatusText(recorder.status))
		}
		metricAttributes := metric.WithAttributes(
			attribute.String("http.request.method", request.Method),
			attribute.String("http.route", route),
			attribute.Int("http.response.status_code", recorder.status),
		)
		telemetry.requests.Add(ctx, 1, metricAttributes)
		telemetry.duration.Record(ctx, time.Since(started).Seconds(), metricAttributes)
		span.End()
	})
}

// RecordFusionIngestError counts one fusion ingest failure observed after a
// durable detection admission. No labels: classified-data discipline keeps
// track content and source identifiers out of metrics.
func (telemetry *Telemetry) RecordFusionIngestError(ctx context.Context) {
	telemetry.fusionErrors.Add(ctx, 1)
}

// RecordDetectionLatency records one anomaly-detection latency observation
// against the p99 <= 5s KPI. Classified-data discipline: only the anomaly
// kind label is attached, never track content.
func (telemetry *Telemetry) RecordDetectionLatency(ctx context.Context, kind string, seconds float64) {
	if seconds < 0 {
		seconds = 0
	}
	telemetry.fusionLatency.Record(ctx, seconds, metric.WithAttributes(attribute.String("isr.anomaly.kind", kind)))
}
