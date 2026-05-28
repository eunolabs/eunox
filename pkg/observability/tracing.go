// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package observability

import (
	"context"
	"os"
	"strconv"

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

// TracingConfigFromEnv builds a [TracingConfig] from standard OpenTelemetry
// environment variables. The caller supplies serviceName and version so that
// they are never accidentally overridden by an env var.
//
// Supported variables:
//   - OTEL_EXPORTER_OTLP_ENDPOINT  – gRPC collector address (e.g. "localhost:4317")
//   - OTEL_EXPORTER_OTLP_INSECURE  – disables TLS when set to any truthy value accepted by [strconv.ParseBool] (e.g. "true", "1")
//   - OTEL_TRACES_SAMPLER_ARG      – sampling ratio in [0.0, 1.0]; default 1.0
func TracingConfigFromEnv(serviceName, version string) TracingConfig {
	ratio := 1.0
	if raw := os.Getenv("OTEL_TRACES_SAMPLER_ARG"); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil && v >= 0 && v <= 1 {
			ratio = v
		}
	}
	return TracingConfig{
		ServiceName:    serviceName,
		ServiceVersion: version,
		Endpoint:       os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		Insecure:       parseBoolEnv("OTEL_EXPORTER_OTLP_INSECURE"),
		SampleRatio:    ratio,
	}
}

// parseBoolEnv returns true if the named environment variable is set to a
// standard truthy value as accepted by [strconv.ParseBool] (e.g. "true",
// "TRUE", "1", "t"). Unset or unparseable values are treated as false.
func parseBoolEnv(name string) bool {
	v, _ := strconv.ParseBool(os.Getenv(name))
	return v
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
