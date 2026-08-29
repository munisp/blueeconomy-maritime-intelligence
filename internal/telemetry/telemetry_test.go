package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/segmentio/kafka-go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestLoadConfigDefaultsToDisabled(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_SDK_DISABLED", "")
	t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "")
	t.Setenv("OTEL_SERVICE_NAME", "")
	config, err := LoadConfig("blueeconomy-maritime-intelligence")
	if err != nil {
		t.Fatalf("default config must load: %v", err)
	}
	if config.Enabled {
		t.Fatal("tracing must default to disabled when no endpoint is configured")
	}
}

func TestLoadConfigFailsClosedOnMalformedValues(t *testing.T) {
	cases := []struct {
		name string
		envs map[string]string
	}{
		{"endpoint with scheme", map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.example.invalid:4317"}},
		{"endpoint without port", map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "collector.example.invalid"}},
		{"endpoint with bad port", map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "collector.example.invalid:not-a-port"}},
		{"endpoint with credentials", map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "user:secret@collector:4317"}},
		{"disabled flag garbage", map[string]string{"OTEL_SDK_DISABLED": "yes"}},
		{"insecure flag garbage", map[string]string{"OTEL_EXPORTER_OTLP_INSECURE": "1"}},
		{"conflicting disabled and endpoint", map[string]string{"OTEL_SDK_DISABLED": "true", "OTEL_EXPORTER_OTLP_ENDPOINT": "collector:4317"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
			t.Setenv("OTEL_SDK_DISABLED", "")
			t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "")
			for name, value := range testCase.envs {
				t.Setenv(name, value)
			}
			if _, err := LoadConfig("blueeconomy-maritime-intelligence"); err == nil {
				t.Fatalf("case %q must fail closed", testCase.name)
			}
		})
	}
}

// testTelemetry builds a Telemetry backed by an in-memory span recorder and a
// real Prometheus pipeline, mirroring Setup without any network dependency.
// The W3C tracecontext+baggage propagator is installed globally, as Setup
// does, so extraction under test behaves exactly as in production.
func testTelemetry(t *testing.T) (*Telemetry, *tracetest.SpanRecorder) {
	t.Helper()
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	recorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	meterProvider, metricsHandler, err := newMeterPipeline(resource.NewSchemaless(attribute.String("service.name", "telemetry-test")))
	if err != nil {
		t.Fatalf("meter pipeline: %v", err)
	}
	meter := meterProvider.Meter("telemetry-test")
	requests, err := meter.Int64Counter("http.server.requests")
	if err != nil {
		t.Fatalf("counter: %v", err)
	}
	duration, err := meter.Float64Histogram("http.server.request.duration", metric.WithUnit("s"))
	if err != nil {
		t.Fatalf("histogram: %v", err)
	}
	fusionLatency, err := meter.Float64Histogram("isr.anomaly.detection.latency", metric.WithUnit("s"))
	if err != nil {
		t.Fatalf("fusion latency histogram: %v", err)
	}
	fusionErrors, err := meter.Int64Counter("isr.fusion.ingest_errors")
	if err != nil {
		t.Fatalf("fusion error counter: %v", err)
	}
	dropped, err := meter.Int64Counter("telemetry_dropped_total")
	if err != nil {
		t.Fatalf("dropped counter: %v", err)
	}
	telemetry := &Telemetry{
		config:         Config{ServiceName: "telemetry-test", Enabled: true},
		tracer:         tracerProvider.Tracer("telemetry-test"),
		tracerProvider: tracerProvider,
		meterProvider:  meterProvider,
		metricsHandler: metricsHandler,
		requests:       requests,
		duration:       duration,
		fusionLatency:  fusionLatency,
		fusionErrors:   fusionErrors,
		dropped:        dropped,
	}
	t.Cleanup(func() { _ = telemetry.Shutdown(context.Background()) })
	return telemetry, recorder
}

func TestMiddlewareCreatesSpanWithRouteAndStatus(t *testing.T) {
	telemetry, recorder := testTelemetry(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, request *http.Request) {
		if !trace.SpanFromContext(request.Context()).IsRecording() {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.WriteHeader(http.StatusForbidden)
	})
	handler := telemetry.Middleware(mux)
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status must pass through unchanged, got %d", response.Code)
	}
	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("exactly one span must be recorded, got %d", len(spans))
	}
	span := spans[0]
	if span.Name() != "GET /healthz" {
		t.Fatalf("span must be renamed to the matched route, got %q", span.Name())
	}
	assertAttribute(t, span.Attributes(), "http.route", "GET /healthz")
	assertAttribute(t, span.Attributes(), "http.response.status_code", int64(http.StatusForbidden))
}

// TestMiddlewarePropagationRoundTrip proves an incoming W3C traceparent is
// honoured: the server span becomes a child of the remote caller's span, in
// the caller's trace.
func TestMiddlewarePropagationRoundTrip(t *testing.T) {
	telemetry, recorder := testTelemetry(t)
	const traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	handler := telemetry.Middleware(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	request := httptest.NewRequest(http.MethodGet, "/v1/isr/tracks", nil)
	request.Header.Set("traceparent", traceparent)
	handler.ServeHTTP(httptest.NewRecorder(), request)
	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("one span expected, got %d", len(spans))
	}
	spanContext := spans[0].SpanContext()
	if spanContext.TraceID().String() != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("server span must join the caller's trace, got trace %s", spanContext.TraceID())
	}
	parent := spans[0].Parent()
	if !parent.IsValid() || parent.SpanID().String() != "00f067aa0ba902b7" || !parent.IsRemote() {
		t.Fatalf("server span must have the remote caller as parent, got %v", parent)
	}
}

// TestMiddlewareTenantBaggageAttributes proves tenant.id and agency baggage
// injected at the edge land as attributes on the server span (traces only —
// metrics keep low cardinality).
func TestMiddlewareTenantBaggageAttributes(t *testing.T) {
	telemetry, recorder := testTelemetry(t)
	handler := telemetry.Middleware(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	request := httptest.NewRequest(http.MethodGet, "/v1/isr/tracks", nil)
	request.Header.Set("baggage", "tenant.id=tenant-npa-lagos,agency=NIMASA")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("one span expected, got %d", len(spans))
	}
	assertAttribute(t, spans[0].Attributes(), "tenant.id", "tenant-npa-lagos")
	assertAttribute(t, spans[0].Attributes(), "agency", "NIMASA")
}

// TestDisabledSetupServesRequestsUnchanged is the telemetry-off contract:
// boot succeeds with no OTLP endpoint, requests flow with a no-op span, and
// status codes pass through byte-identical (the one sanctioned fail-open).
func TestDisabledSetupServesRequestsUnchanged(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_SDK_DISABLED", "")
	t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "")
	config, err := LoadConfig("blueeconomy-maritime-intelligence")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	telemetry, err := Setup(context.Background(), config)
	if err != nil {
		t.Fatalf("disabled setup must succeed: %v", err)
	}
	if telemetry.Enabled() {
		t.Fatal("telemetry must report disabled")
	}
	handler := telemetry.Middleware(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if span := trace.SpanFromContext(request.Context()); span.IsRecording() {
			t.Error("disabled mode must use a no-op, non-recording span")
		}
		writer.WriteHeader(http.StatusTeapot)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusTeapot {
		t.Fatalf("disabled mode must not change request handling, got status %d", response.Code)
	}
	metricsResponse := httptest.NewRecorder()
	telemetry.MetricsHandler().ServeHTTP(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metricsResponse.Code != http.StatusOK {
		t.Fatal("metrics must be served even when tracing is disabled")
	}
	if err := telemetry.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

// TestKafkaHeaderCarrierRoundTrip proves the manual kafka-go carrier: context
// injected on produce re-emerges on consume, continuing the trace and the
// tenant baggage across the async boundary.
func TestKafkaHeaderCarrierRoundTrip(t *testing.T) {
	_, recorder := testTelemetry(t)
	tracer := otel.Tracer("carrier-test")
	ctx, span := tracer.Start(context.Background(), "produce")
	defer span.End()
	bag, err := baggage.Parse("tenant.id=tenant-niwa,agency=NIWA")
	if err != nil {
		t.Fatalf("parse baggage: %v", err)
	}
	ctx = baggage.ContextWithBaggage(ctx, bag)
	headers := InjectKafkaHeaders(ctx, []kafka.Header{{Key: "x-blueeconomy-event-type", Value: []byte("isr.track_fused")}})
	extracted := ExtractKafkaContext(context.Background(), headers)
	consumerSpanContext := trace.SpanContextFromContext(extracted)
	if consumerSpanContext.TraceID() != span.SpanContext().TraceID() {
		t.Fatalf("extracted context must carry the producer trace, got %s", consumerSpanContext.TraceID())
	}
	if consumerSpanContext.SpanID() != span.SpanContext().SpanID() {
		t.Fatalf("extracted context must carry the producer span id, got %s", consumerSpanContext.SpanID())
	}
	if value := baggage.FromContext(extracted).Member("tenant.id").Value(); value != "tenant-niwa" {
		t.Fatalf("tenant.id baggage must survive the round trip, got %q", value)
	}
	if value := baggage.FromContext(extracted).Member("agency").Value(); value != "NIWA" {
		t.Fatalf("agency baggage must survive the round trip, got %q", value)
	}
	// Uninstrumented producers (no trace headers) must not break consumers.
	plain := ExtractKafkaContext(context.Background(), nil)
	if trace.SpanContextFromContext(plain).IsValid() {
		t.Fatal("header-less messages must yield no remote span context")
	}
	_ = recorder
}

func assertAttribute(t *testing.T, attributes []attribute.KeyValue, key string, expected any) {
	t.Helper()
	for _, item := range attributes {
		if string(item.Key) != key {
			continue
		}
		switch want := expected.(type) {
		case string:
			if item.Value.AsString() == want {
				return
			}
		case int64:
			if item.Value.AsInt64() == want {
				return
			}
		}
		t.Fatalf("attribute %s has unexpected value %v (want %v)", key, item.Value, expected)
	}
	t.Fatalf("attribute %s missing from %v", key, attributes)
}
