// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestNewLoggerJSON(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&LogConfig{Output: &buf})

	logger.Info("hello", slog.String("key", "value"))

	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry); err != nil {
		t.Fatalf("unmarshal log entry: %v", err)
	}

	if entry["msg"] != "hello" {
		t.Fatalf("msg = %v, want hello", entry["msg"])
	}
	if entry["level"] != "INFO" {
		t.Fatalf("level = %v, want INFO", entry["level"])
	}
	if entry["key"] != "value" {
		t.Fatalf("key = %v, want value", entry["key"])
	}
}

func TestNewLoggerText(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&LogConfig{Format: "text", Output: &buf})

	logger.Info("hello", slog.String("key", "value"))

	out := buf.String()
	if !strings.Contains(out, "level=INFO") {
		t.Fatalf("expected text output to contain level, got %q", out)
	}
	if !strings.Contains(out, "msg=hello") {
		t.Fatalf("expected text output to contain message, got %q", out)
	}
	if !strings.Contains(out, "key=value") {
		t.Fatalf("expected text output to contain field, got %q", out)
	}
}

func TestNewLoggerLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&LogConfig{Level: "warn", Output: &buf})

	logger.Debug("debug")
	logger.Info("info")
	logger.Warn("warn")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("log lines = %d, want 1 (%q)", len(lines), buf.String())
	}

	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("unmarshal warn entry: %v", err)
	}
	if entry["msg"] != "warn" {
		t.Fatalf("msg = %v, want warn", entry["msg"])
	}
}

func TestNewLoggerServiceAttrs(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&LogConfig{
		Output:      &buf,
		ServiceName: "api",
		Version:     "1.2.3",
	})

	logger.Info("hello")

	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry); err != nil {
		t.Fatalf("unmarshal log entry: %v", err)
	}
	if entry["service"] != "api" {
		t.Fatalf("service = %v, want api", entry["service"])
	}
	if entry["version"] != "1.2.3" {
		t.Fatalf("version = %v, want 1.2.3", entry["version"])
	}
}

func TestParseLevel(t *testing.T) {
	tests := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"DEBUG":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"other":   slog.LevelInfo,
		"":        slog.LevelInfo,
	}

	for input, want := range tests {
		if got := parseLevel(input); got != want {
			t.Fatalf("parseLevel(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestMetricsRegistryCounter(t *testing.T) {
	registry := NewMetricsRegistry("test", "http")
	counter := registry.NewCounter("requests_total", "Total requests", "method")

	counter.WithLabelValues("GET").Add(3)

	gathered := gatherMetricFamilies(t, registry.Registry)
	metric := findMetric(t, gathered, "test_http_requests_total")
	if got := metric.GetCounter().GetValue(); got != 3 {
		t.Fatalf("counter = %v, want 3", got)
	}
}

func TestMetricsRegistryHistogram(t *testing.T) {
	registry := NewMetricsRegistry("test", "http")
	histogram := registry.NewHistogram("request_duration_seconds", "Request duration", []float64{0.1, 0.5, 1}, "method")

	histogram.WithLabelValues("GET").Observe(0.05)
	histogram.WithLabelValues("GET").Observe(0.75)

	gathered := gatherMetricFamilies(t, registry.Registry)
	metric := findMetric(t, gathered, "test_http_request_duration_seconds")
	h := metric.GetHistogram()
	if h.GetSampleCount() != 2 {
		t.Fatalf("sample count = %d, want 2", h.GetSampleCount())
	}
	if h.GetBucket()[0].GetCumulativeCount() != 1 {
		t.Fatalf("first bucket count = %d, want 1", h.GetBucket()[0].GetCumulativeCount())
	}
	if h.GetBucket()[2].GetCumulativeCount() != 2 {
		t.Fatalf("third bucket count = %d, want 2", h.GetBucket()[2].GetCumulativeCount())
	}
}

func TestMetricsRegistryGauge(t *testing.T) {
	registry := NewMetricsRegistry("test", "workers")
	gauge := registry.NewGauge("active", "Active workers", "queue")

	g := gauge.WithLabelValues("default")
	g.Set(5)
	g.Inc()
	g.Dec()

	gathered := gatherMetricFamilies(t, registry.Registry)
	metric := findMetric(t, gathered, "test_workers_active")
	if got := metric.GetGauge().GetValue(); got != 5 {
		t.Fatalf("gauge = %v, want 5", got)
	}
}

func TestRequestLoggingMiddleware(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&LogConfig{Output: &buf})
	middleware := RequestLogging(logger)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "ok")
	}))

	req := httptest.NewRequest(http.MethodPost, "/health", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry); err != nil {
		t.Fatalf("unmarshal request log: %v", err)
	}
	if entry["method"] != http.MethodPost {
		t.Fatalf("method = %v, want %s", entry["method"], http.MethodPost)
	}
	if entry["path"] != "/health" {
		t.Fatalf("path = %v, want /health", entry["path"])
	}
	if entry["status"] != float64(http.StatusCreated) {
		t.Fatalf("status = %v, want %d", entry["status"], http.StatusCreated)
	}
	if _, ok := entry["duration"]; !ok {
		t.Fatalf("expected duration field in log entry: %v", entry)
	}
}

func TestRequestLoggingMiddleware_WithRequestID(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&LogConfig{Output: &buf})

	// Wrap with chi's RequestID middleware first, then our logging.
	chiReqID := chimiddleware.RequestID
	loggingMW := RequestLogging(logger)

	handler := chiReqID(loggingMW(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest(http.MethodGet, "/api", http.NoBody)
	req.Header.Set("X-Request-Id", "test-req-123")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry); err != nil {
		t.Fatalf("unmarshal request log: %v", err)
	}
	if entry["request_id"] != "test-req-123" {
		t.Fatalf("request_id = %v, want test-req-123", entry["request_id"])
	}
}

func TestRequestLoggingMiddleware_NoRequestID(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&LogConfig{Output: &buf})
	middleware := RequestLogging(logger)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry); err != nil {
		t.Fatalf("unmarshal request log: %v", err)
	}
	// When no request ID middleware is present, the field should be absent.
	if _, ok := entry["request_id"]; ok {
		t.Fatalf("expected no request_id field, but got %v", entry["request_id"])
	}
}

func TestGetRequestID_FromChiMiddleware(t *testing.T) {
	var captured string
	handler := chimiddleware.RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		captured = GetRequestID(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("X-Request-Id", "chi-id-456")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if captured != "chi-id-456" {
		t.Fatalf("GetRequestID = %q, want chi-id-456", captured)
	}
}

func TestGetRequestID_FromSetRequestID(t *testing.T) {
	ctx := SetRequestID(context.Background(), "manual-id-789")
	if got := GetRequestID(ctx); got != "manual-id-789" {
		t.Fatalf("GetRequestID = %q, want manual-id-789", got)
	}
}

func TestGetRequestID_Empty(t *testing.T) {
	if got := GetRequestID(context.Background()); got != "" {
		t.Fatalf("GetRequestID = %q, want empty", got)
	}
}

func TestPropagateRequestID(t *testing.T) {
	ctx := SetRequestID(context.Background(), "propagate-id-001")
	req := httptest.NewRequest(http.MethodPost, "/sink", http.NoBody)
	PropagateRequestID(ctx, req)

	if got := req.Header.Get("X-Request-Id"); got != "propagate-id-001" {
		t.Fatalf("X-Request-Id header = %q, want propagate-id-001", got)
	}
}

func TestPropagateRequestID_NoID(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/sink", http.NoBody)
	PropagateRequestID(context.Background(), req)

	if got := req.Header.Get("X-Request-Id"); got != "" {
		t.Fatalf("X-Request-Id header = %q, want empty", got)
	}
}

func TestRequestMetricsMiddleware(t *testing.T) {
	registry := NewMetricsRegistry("test", "http")
	duration := registry.NewHistogram("request_duration_seconds", "Request duration", DefaultHTTPBuckets, "method", "path", "status")
	total := registry.NewCounter("requests_total", "Total requests", "method", "path", "status")

	handler := RequestMetrics(duration, total)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/ready", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	gathered := gatherMetricFamilies(t, registry.Registry)
	totalMetric := findMetric(t, gathered, "test_http_requests_total")
	if got := totalMetric.GetCounter().GetValue(); got != 1 {
		t.Fatalf("counter = %v, want 1", got)
	}

	durationMetric := findMetric(t, gathered, "test_http_request_duration_seconds")
	if got := durationMetric.GetHistogram().GetSampleCount(); got != 1 {
		t.Fatalf("histogram count = %d, want 1", got)
	}
}

func TestTracePropagationMiddleware(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(recorder),
	)
	originalProvider := otel.GetTracerProvider()
	originalPropagator := otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(originalProvider)
		otel.SetTextMapPropagator(originalPropagator)
		_ = tp.Shutdown(context.Background())
	})

	var spanCtx trace.SpanContext
	handler := TracePropagation("api")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spanCtx = trace.SpanFromContext(r.Context()).SpanContext()
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/trace", http.NoBody)
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !spanCtx.IsValid() {
		t.Fatal("expected request context to contain a valid span")
	}

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans = %d, want 1", len(spans))
	}
	if spans[0].Name() != "GET /trace" {
		t.Fatalf("span name = %q, want %q", spans[0].Name(), "GET /trace")
	}
	if spans[0].Parent().SpanID().String() != "00f067aa0ba902b7" {
		t.Fatalf("parent span ID = %s, want %s", spans[0].Parent().SpanID(), "00f067aa0ba902b7")
	}
}

func TestInitTracerNoEndpoint(t *testing.T) {
	shutdown, err := InitTracer(context.Background(), TracingConfig{ServiceName: "api"})
	if err != nil {
		t.Fatalf("InitTracer returned error: %v", err)
	}
	if shutdown == nil {
		t.Fatal("expected shutdown function")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown returned error: %v", err)
	}

	_, span := otel.Tracer("test").Start(context.Background(), "noop")
	if span.IsRecording() {
		t.Fatal("expected noop tracer provider when endpoint is empty")
	}
	span.End()
}

func TestResponseWriterCapturesStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := newResponseWriter(rec)

	rw.WriteHeader(http.StatusAccepted)
	n, err := rw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("write returned error: %v", err)
	}
	if n != 5 {
		t.Fatalf("bytes written = %d, want 5", n)
	}
	if rw.statusCode != http.StatusAccepted {
		t.Fatalf("statusCode = %d, want %d", rw.statusCode, http.StatusAccepted)
	}
	if rw.written != 5 {
		t.Fatalf("written = %d, want 5", rw.written)
	}
}

func gatherMetricFamilies(t *testing.T, registry interface {
	Gather() ([]*dto.MetricFamily, error)
}) []*dto.MetricFamily {
	t.Helper()

	gathered, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	return gathered
}

func findMetric(t *testing.T, families []*dto.MetricFamily, name string) *dto.Metric {
	t.Helper()

	for _, family := range families {
		if family.GetName() == name {
			if len(family.GetMetric()) != 1 {
				t.Fatalf("metric family %s has %d metrics, want 1", name, len(family.GetMetric()))
			}
			return family.GetMetric()[0]
		}
	}

	t.Fatalf("metric family %s not found", name)
	return nil
}
