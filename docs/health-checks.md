# Health Checks

This document describes the standardized health check convention used by all
Eunox services.

## Endpoints

Every service exposes two mandatory endpoints on its primary HTTP listener:

| Path                | Purpose                                           | Success  | Failure                   |
| ------------------- | ------------------------------------------------- | -------- | ------------------------- |
| `GET /health/live`  | Liveness probe — is the process alive?            | `200 OK` | `503 Service Unavailable` |
| `GET /health/ready` | Readiness probe — can the service accept traffic? | `200 OK` | `503 Service Unavailable` |

### Response Format

All health endpoints return `Content-Type: application/json` with a JSON body:

```json
{ "status": "ok" }
```

Possible `status` values depend on the endpoint:

- **Liveness:** `"ok"` / `"healthy"` (200), `"unhealthy"` (503)
- **Readiness:** `"ready"` (200), `"not_ready"` / `"degraded"` (503)

### Liveness vs Readiness

|                    | Liveness                                  | Readiness                                    |
| ------------------ | ----------------------------------------- | -------------------------------------------- |
| **Purpose**        | Should the orchestrator restart this pod? | Should the load balancer send traffic?       |
| **Checks**         | Process is responsive                     | Dependencies are connected, startup complete |
| **Failure action** | Container restart                         | Remove from service endpoints                |

## Service Implementations

### Gateway (`cmd/gateway`)

- `/health/live` — always returns `200` if the HTTP server is responding.
- `/health/ready` — returns `200` if the service is fully initialized.
- `/healthz/did-ion` — additional deep check for DID:ION resolver connectivity.

### Issuer (`cmd/issuer`)

- `/health/live` — always returns `200`.
- `/health/ready` — returns `200` when KMS signer is initialized and database
  connections are established.

### Minter (`cmd/minter`)

- `/health/live` — always returns `200`.
- `/health/ready` — returns `200` when database pools are healthy and admin key
  is configured.

### Posture (`cmd/posture`)

- `/health/live` — always returns `200`.
- `/health/ready` — returns `200` when event queue depth is below the
  configured threshold (`POSTURE_HEALTH_MAX_QUEUE_DEPTH`). Returns `503` with
  `{"status":"degraded"}` when the queue is backed up.

### Agent Runtime (`cmd/agentruntime`)

- `/health/live` — always returns `200`.
- `/health/ready` — returns `200` when the runtime is initialized.

### Audit (`cmd/audit`)

- `/health/live` — always returns `200`.
- `/health/ready` — returns `200` when the audit store backend is reachable.

## Using `pkg/lifecycle`

The `pkg/lifecycle` package provides a shared lifecycle manager with built-in
health handlers. Services that use it get consistent behavior automatically:

```go
import "github.com/eunolabs/eunox/pkg/lifecycle"

mgr := lifecycle.New(
    lifecycle.WithShutdownTimeout(15 * time.Second),
    lifecycle.WithDrainDelay(5 * time.Second),
)

mux.HandleFunc("GET /health/live", mgr.HealthHandler())
mux.HandleFunc("GET /health/ready", mgr.ReadyHandler())

// Mark ready once initialization is complete.
mgr.SetReady(true)
```

The lifecycle handlers:

- Return `Content-Type: application/json`
- Use `200 OK` / `503 Service Unavailable` status codes
- Track readiness independently from liveness
- Are safe for concurrent access

## Kubernetes Configuration

Standard probe configuration for Eunox services:

```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: http
  initialDelaySeconds: 5
  periodSeconds: 10
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /health/ready
    port: http
  initialDelaySeconds: 5
  periodSeconds: 5
  failureThreshold: 2
```

## Circuit Breaker Integration

When a circuit breaker (see `pkg/circuitbreaker`) is open for a critical
dependency, the readiness endpoint SHOULD return `503` to prevent traffic
routing to a service that cannot fulfill requests. Services may implement this
by wiring the breaker state into their readiness check:

```go
func readyHandler(breaker *circuitbreaker.Breaker) http.HandlerFunc {
    return func(w http.ResponseWriter, _ *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        if breaker.State() == circuitbreaker.StateOpen {
            w.WriteHeader(http.StatusServiceUnavailable)
            fmt.Fprint(w, `{"status":"degraded","reason":"circuit_open"}`)
            return
        }
        w.WriteHeader(http.StatusOK)
        fmt.Fprint(w, `{"status":"ready"}`)
    }
}
```

## Monitoring

Health endpoints are typically scraped by:

- **Kubernetes** — kubelet probes for pod lifecycle
- **Load balancers** — ALB/NLB target group health checks
- **Prometheus** — `probe_success` metric via blackbox exporter
- **Synthetic monitors** — uptime checks (e.g., Datadog, PagerDuty)

For Prometheus monitoring of internal health state, services export:

- `eunox_service_healthy` (gauge, 0/1)
- `eunox_service_ready` (gauge, 0/1)
