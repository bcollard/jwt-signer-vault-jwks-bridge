// Package telemetry sets up OpenTelemetry tracing with W3C Trace Context
// propagation.
//
// Propagation is always on: an inbound traceparent header is continued, and
// outbound calls to the secret source carry it. Spans are exported only when
// an exporter is configured with the standard OTEL_* environment variables,
// for example OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318.
package telemetry

import (
	"context"
	"errors"
	"os"

	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
)

// ServiceName is the default service.name resource attribute.
const ServiceName = "jwks-bridge"

// exporterConfigured reports whether the environment asks for span export.
func exporterConfigured() bool {
	for _, k := range []string{"OTEL_TRACES_EXPORTER", "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

// Setup installs the global propagator and tracer provider. The returned
// function flushes and stops the provider.
func Setup(ctx context.Context, version string) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))
	if !exporterConfigured() {
		return func(context.Context) error { return nil }, nil
	}

	exp, err := autoexport.NewSpanExporter(ctx)
	if err != nil {
		return nil, err
	}
	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(semconv.SchemaURL,
		semconv.ServiceName(serviceName()),
		semconv.ServiceVersion(version),
	))
	if err != nil && !errors.Is(err, resource.ErrSchemaURLConflict) {
		return nil, err
	}
	// The SDK reads OTEL_TRACES_SAMPLER; the default is parentbased_always_on.
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}

func serviceName() string {
	if v := os.Getenv("OTEL_SERVICE_NAME"); v != "" {
		return v
	}
	return ServiceName
}
