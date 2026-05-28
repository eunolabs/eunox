// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package observability

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

// requestIDKey is the context key used to store the request ID for outbound propagation.
// This is compatible with chi's middleware.RequestID; use GetRequestID to extract it.
type requestIDKey struct{}

// GetRequestID extracts the request ID from the context. It first checks chi's
// middleware context key, then falls back to the observability package's own key.
func GetRequestID(ctx context.Context) string {
	// Prefer chi's request ID (set by chimiddleware.RequestID).
	if id := chimiddleware.GetReqID(ctx); id != "" {
		return id
	}
	if id, ok := ctx.Value(requestIDKey{}).(string); ok {
		return id
	}
	return ""
}

// SetRequestID returns a new context with the given request ID stored.
func SetRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// PropagateRequestID sets the X-Request-Id header on the outbound HTTP request
// using the request ID from the context. This enables cross-service log correlation
// without requiring a full distributed tracing backend.
func PropagateRequestID(ctx context.Context, req *http.Request) {
	if id := GetRequestID(ctx); id != "" {
		req.Header.Set("X-Request-Id", id)
	}
}

// responseWriter wraps http.ResponseWriter to capture status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    int64
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
}

// WriteHeader records the response status code before writing it to the client.
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.written += int64(n)
	return n, err
}

// RequestLogging returns middleware that logs each HTTP request.
// It includes the request ID (from chi's middleware.RequestID or SetRequestID)
// in every log entry for cross-service correlation. The RequestID middleware
// must be applied before RequestLogging for the request_id field to be populated.
func RequestLogging(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := newResponseWriter(w)

			next.ServeHTTP(rw, r)

			duration := time.Since(start)
			attrs := []slog.Attr{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", rw.statusCode),
				slog.Duration("duration", duration),
				slog.Int64("bytes", rw.written),
				slog.String("remote_addr", r.RemoteAddr),
			}

			if requestID := GetRequestID(r.Context()); requestID != "" {
				attrs = append(attrs, slog.String("request_id", requestID))
			}

			logger.LogAttrs(r.Context(), slog.LevelInfo, "http request", attrs...)
		})
	}
}

// RequestMetrics returns middleware that records HTTP request metrics.
func RequestMetrics(requestDuration *prometheus.HistogramVec, requestTotal *prometheus.CounterVec) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := newResponseWriter(w)

			next.ServeHTTP(rw, r)

			duration := time.Since(start).Seconds()
			statusStr := http.StatusText(rw.statusCode)

			requestDuration.WithLabelValues(r.Method, r.URL.Path, statusStr).Observe(duration)
			requestTotal.WithLabelValues(r.Method, r.URL.Path, statusStr).Inc()
		})
	}
}

// TracePropagation returns middleware that extracts and propagates W3C trace context.
// Span names use the matched Chi route pattern to avoid high-cardinality names from
// dynamic path segments (e.g. IDs). The raw URL path is kept as the http.url.path
// attribute. Falls back to the raw path when no route pattern is available.
func TracePropagation(serviceName string) func(http.Handler) http.Handler {
	tracer := otel.Tracer(serviceName)
	propagator := otel.GetTextMapPropagator()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
			ctx, span := tracer.Start(ctx, r.Method+" "+r.URL.Path,
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(
					semconv.HTTPRequestMethodKey.String(r.Method),
					semconv.URLPath(r.URL.Path),
				),
			)
			defer span.End()

			next.ServeHTTP(w, r.WithContext(ctx))

			// Update the span name with the matched route pattern after routing is
			// complete to avoid high-cardinality names from dynamic path segments.
			if rctx := chi.RouteContext(r.Context()); rctx != nil {
				if pattern := rctx.RoutePattern(); pattern != "" {
					span.SetName(r.Method + " " + pattern)
					span.SetAttributes(semconv.HTTPRouteKey.String(pattern))
				}
			}
		})
	}
}
