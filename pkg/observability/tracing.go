// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package observability

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace/noop"
)

// TracingConfig configures the OpenTelemetry tracer provider.
type TracingConfig struct {
	// ServiceName is the service name for trace attributes.
	ServiceName string
	// ServiceVersion is the service version.
	ServiceVersion string
	// Endpoint is the OTLP collector endpoint (e.g., "localhost:4317").
	// If empty, tracing is disabled (noop provider).
	Endpoint string
	// Insecure disables TLS for the OTLP connection.
	Insecure bool
	// SampleRatio is the trace sampling ratio (0.0 to 1.0). Set 0.0 to disable sampling.
	SampleRatio float64
}

// InitTracer initializes the OpenTelemetry tracer provider.
// Returns a shutdown function that should be called on application exit.
func InitTracer(ctx context.Context, cfg TracingConfig) (func(context.Context) error, error) {
	if cfg.Endpoint == "" {
		otel.SetTracerProvider(noop.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		))
		return func(context.Context) error { return nil }, nil
	}

	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(cfg.Endpoint),
	}
	if cfg.Insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}

	exporter, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		return nil, err
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
		),
	)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(cfg.SampleRatio)),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp.Shutdown, nil
}
