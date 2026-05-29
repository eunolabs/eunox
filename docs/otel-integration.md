<!-- Copyright 2026 Eunox Authors -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# OpenTelemetry Integration

Eunox emits W3C-compatible distributed traces via **OTLP/gRPC** and exposes
Prometheus metrics on every service. This document covers how to enable tracing,
describes the canonical `eunox.*` span attributes, and provides a Grafana
dashboard quick-start.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Enabling Tracing](#enabling-tracing)
- [Canonical Span Attributes](#canonical-span-attributes)
- [Instrumented Services](#instrumented-services)
- [W3C Trace Context Propagation](#w3c-trace-context-propagation)
- [Grafana / Tempo Quick-Start](#grafana--tempo-quick-start)
- [Prometheus Metrics](#prometheus-metrics)
- [Sampling](#sampling)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Requirement                             | Version |
| --------------------------------------- | ------- |
| OpenTelemetry Collector (or compatible) | 0.100+  |
| Grafana (optional)                      | 10+     |
| Grafana Tempo (optional)                | 2.4+    |
| Prometheus (optional)                   | 2.50+   |

---

## Enabling Tracing

Tracing is **noop by default**. Set `OTEL_EXPORTER_OTLP_ENDPOINT` to activate it:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
export OTEL_EXPORTER_OTLP_PROTOCOL=grpc   # default
```

All eunox services read these standard environment variables at startup. No
code changes are required.

### Per-service overrides

If your collector is service-mesh-local (e.g. a sidecar on `localhost:4317`) you
can keep the default without setting any variable. To override for a single
service, prefix the standard variable with the service name:

```bash
# Gateway only — other services fall back to OTEL_EXPORTER_OTLP_ENDPOINT
GATEWAY_OTEL_EXPORTER_OTLP_ENDPOINT=http://gateway-collector:4317
```

### TLS

```bash
export OTEL_EXPORTER_OTLP_CERTIFICATE=/etc/ssl/otel-ca.crt
export OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE=/etc/ssl/client.crt
export OTEL_EXPORTER_OTLP_CLIENT_KEY=/etc/ssl/client.key
```

---

## Canonical Span Attributes

All eunox services share a single set of `eunox.*` attribute keys, defined in
`pkg/observability/attributes.go`. This ensures consistent filtering across
services in Grafana Tempo and Jaeger.

| Attribute Key               | Type   | Description                                              |
| --------------------------- | ------ | -------------------------------------------------------- |
| `eunox.agent_id`            | string | Subject claim from the capability token (agent identity) |
| `eunox.session_id`          | string | Session identifier from the tool-call payload            |
| `eunox.task_id`             | string | Task identifier from `X-Eunox-Task-Id` header            |
| `eunox.capability_token_id` | string | JWT ID (`jti`) or minted credential ID                   |
| `eunox.tool_name`           | string | MCP/tool name being enforced                             |
| `eunox.policy_decision`     | string | `allow` or `deny`                                        |
| `eunox.tenant_id`           | string | Tenant identifier from token claims                      |
| `eunox.denial_code`         | string | Machine-readable reason for a `deny` decision            |
| `eunox.db_adapter`          | string | DB adapter name (`aws-rds`, `azure-sql`, `gcp-cloudsql`) |

### Example query — all denied tool calls in the last hour

```logql
{service_name="gateway"} | json | eunox_policy_decision="deny"
```

```promql
# Span count by denial code (requires exemplars or Tempo metrics)
sum by (eunox_denial_code) (
  rate(traces_spanmetrics_calls_total{
    service_name="gateway",
    eunox_policy_decision="deny"
  }[5m])
)
```

---

## Instrumented Services

### Gateway (`cmd/gateway/`)

Every `/enforce` call produces a span named `gateway.Enforce` with the
following attributes set:

- `eunox.agent_id` — subject from verified capability token
- `eunox.session_id` — from tool-call payload
- `eunox.task_id` — from tool-call payload (when present)
- `eunox.capability_token_id` — JWT ID (`jti`)
- `eunox.tool_name` — tool name from payload
- `eunox.policy_decision` — final `allow` / `deny`
- `eunox.tenant_id` — from `authorizedBy.tenantId` claim
- `eunox.denial_code` — set only on `deny` outcomes

### DB Token Service (`cmd/db-token-svc/`)

The `/api/v1/db-tokens` endpoint produces a span named `dbtokensvc.MintDBToken`:

- `eunox.db_adapter` — cloud adapter being used
- `eunox.task_id` — from `X-Eunox-Task-Id` header (when present)
- `eunox.agent_id` — subject from verified capability token
- `eunox.tenant_id` — from capability token
- `eunox.capability_token_id` — the minted credential ID (UUID)

The task lifecycle endpoints (`/api/v1/tasks/{taskId}/complete` and
`/api/v1/tasks/{taskId}/fail`) produce a span named `dbtokensvc.RevokeTask`:

- `eunox.task_id` — the task being revoked

---

## W3C Trace Context Propagation

All services inject `observability.TracePropagation` middleware that:

1. **Extracts** `traceparent` / `tracestate` headers from incoming requests.
2. **Starts** a child span in the extracted trace context.
3. **Propagates** the context to outbound calls.

This means a single tool call that traverses `mcp-proxy → gateway →
db-token-svc` produces a single unified trace in Tempo.

To preserve trace context from your AI agent framework, set the `traceparent`
header when calling the gateway:

```
traceparent: 00-{trace-id}-{span-id}-01
```

---

## Grafana / Tempo Quick-Start

### 1. Add the OTLP receiver to your collector

```yaml
# otel-collector-config.yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

exporters:
  otlp/tempo:
    endpoint: tempo:4317
    tls:
      insecure: true

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlp/tempo]
```

### 2. Configure Tempo as a Grafana data source

1. In Grafana → **Connections → Data sources → Add data source**, choose **Tempo**.
2. Set URL to `http://tempo:3200`.
3. Under **Trace to logs**, link your Loki data source using `service_name` as
   the correlation label.
4. Save & test.

### 3. Import the eunox dashboard

Import `docs/grafana-dashboard.json` via **Dashboards → Import → Upload JSON**.

The dashboard provides:

- **Policy decisions** — allow vs. deny rate per minute
- **Denial breakdown** — top denial codes over the selected window
- **DB token mint rate** — mints per minute by adapter and status
- **Task revocation timeline** — revocation events over time
- **P99 enforcement latency** — gateway `/enforce` tail latency

### 4. Explore traces with TraceQL

```traceql
{resource.service.name="gateway" && span.eunox.policy_decision="deny"}
  | select(span.eunox.agent_id, span.eunox.tool_name, span.eunox.denial_code)
```

---

## Prometheus Metrics

In addition to traces, all services expose Prometheus metrics on the main HTTP
port under `/metrics`.

| Metric                                      | Labels                     | Description            |
| ------------------------------------------- | -------------------------- | ---------------------- |
| `gateway_http_requests_total`               | `method`, `path`, `status` | HTTP request count     |
| `gateway_http_request_duration_seconds`     | `method`, `path`           | Latency histogram      |
| `dbtokensvc_db_tokens_minted_total`         | `adapter`, `status`        | Tokens minted          |
| `dbtokensvc_db_token_mint_duration_seconds` | `adapter`                  | Mint latency histogram |

### Alert example — high denial rate

```yaml
groups:
  - name: eunox
    rules:
      - alert: HighToolDenialRate
        expr: |
          rate(gateway_http_requests_total{path="/enforce",status="403"}[5m])
          /
          rate(gateway_http_requests_total{path="/enforce"}[5m])
          > 0.10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "More than 10% of tool calls are being denied"
```

---

## Sampling

By default, eunox uses the OTel SDK's **ParentBased(AlwaysOn)** sampler — every
request is traced. For high-traffic production deployments, configure
head-based sampling at the collector:

```yaml
processors:
  probabilistic_sampler:
    sampling_percentage: 10 # keep 10% of traces
```

For tail-based sampling (keep all traces containing a `deny` decision):

```yaml
processors:
  tail_sampling:
    policies:
      - name: keep-denials
        type: string_attribute
        string_attribute:
          key: eunox.policy_decision
          values: ["deny"]
      - name: probabilistic-rest
        type: probabilistic
        probabilistic:
          sampling_percentage: 5
```

---

## Troubleshooting

| Symptom                                 | Likely cause                         | Fix                                                                                |
| --------------------------------------- | ------------------------------------ | ---------------------------------------------------------------------------------- |
| No spans in Tempo                       | `OTEL_EXPORTER_OTLP_ENDPOINT` unset  | Set the env var and restart                                                        |
| `connection refused` on startup         | Collector not reachable at startup   | Traces are dropped silently — service starts normally; check collector health      |
| Missing `eunox.*` attributes            | Old service binary                   | Rebuild from `main`; attributes were added in T-08                                 |
| `eunox.task_id` absent                  | Client not sending `X-Eunox-Task-Id` | Add header to DB token mint requests from agent runtime                            |
| High cardinality warnings in Prometheus | Many unique agent IDs as labels      | `eunox.*` attributes are span attributes, not Prometheus labels — this is expected |
