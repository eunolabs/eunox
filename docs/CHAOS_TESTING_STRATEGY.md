# Chaos Testing Strategy

This document describes the chaos testing strategy, coverage matrix, and release
gates for the Euno platform. It answers the questions posed in OQ-4 of the
[Technical Architecture Review](TECHNICAL_REVIEW_2026_05_26.md).

---

## 1. Overview

Euno includes a chaos engineering framework (`internal/chaos/`) for verifying
system resilience under fault conditions. The framework enables deterministic,
reproducible fault injection in unit and integration tests — ensuring that
circuit breakers, retry logic, stale-token grace periods, and graceful
degradation paths work correctly before production deployment.

---

## 2. Chaos Framework Architecture

### 2.1 Core Components

```
┌─────────────────────────────────────────────────┐
│  Injector (internal/chaos/injector.go)           │
│                                                  │
│  ├── SetFault(operation, fault)                  │
│  ├── ClearFault(operation)                       │
│  ├── MaybeInject(ctx, operation) → error | nil   │
│  ├── Enable() / Disable()                        │
│  └── HasFault(operation) → bool                  │
│                                                  │
│  Thread-safe (sync.RWMutex)                      │
│  Probability-based injection (0.0–1.0)           │
└─────────────────────────────────────────────────┘
```

### 2.2 Fault Types

| Type | Constant | Behavior | Use Case |
|------|----------|----------|----------|
| **Latency** | `FaultLatency` | Adds configurable delay; respects context cancellation | Simulating slow network, saturated services |
| **Error** | `FaultError` | Returns configured error immediately | Simulating service failures, permission denials |
| **Timeout** | `FaultTimeout` | Returns `ErrTimeout` immediately | Simulating deadline exceeded on upstream calls |
| **Partition** | `FaultPartition` | Returns `ErrPartition` immediately | Simulating network partition, connection refused |

### 2.3 Integration Pattern

The chaos injector integrates with production code via operation points —
named injection sites where `MaybeInject()` is called:

```go
// In production code (e.g., token refresh)
func (p *TokenProvider) refresh(ctx context.Context) error {
    if p.chaosInjector != nil {
        if err := p.chaosInjector.MaybeInject(ctx, "token_refresh"); err != nil {
            return err
        }
    }
    // ... actual refresh logic
}

// In test code
inj := chaos.NewInjector()
inj.SetFault("token_refresh", chaos.Fault{
    Type:        chaos.FaultTimeout,
    Probability: 1.0, // Always inject
})
```

---

## 3. Failure Modes Tested

### 3.1 Coverage Matrix

| Failure Mode | Fault Type | Component Under Test | Verified Behavior |
|-------------|-----------|---------------------|-------------------|
| Token issuer unreachable | Timeout | `AuthTokenProvider` | Circuit breaker opens; stale token served for grace period |
| Token issuer returns errors | Error | `AuthTokenProvider` | Retry with backoff; circuit breaker after threshold |
| Token issuer slow response | Latency | `AuthTokenProvider` | Context deadline cancels request; no goroutine leak |
| Gateway network partition | Partition | `ToolInvoker` | Returns error; agent handles denial gracefully |
| Redis partition (kill switch) | Partition | `KillSwitchManager` | Fail-closed (blocks all requests) |
| Redis partition (revocation) | Partition | `RevocationStore` | Fail-closed (treats tokens as revoked) |
| Redis partition (rate limiter) | Partition | `RateLimiter` | Fail-open (allows with in-memory fallback) |
| Redis partition (call counter) | Partition | `CallCounter` | Fail-open (degrades gracefully) |
| Cascading failures | Error chain | Circuit breaker chain | Cascading circuit breaker activation |
| Service restart during operation | Timeout + Recovery | Token provider | Reconnection with backoff; fresh token acquisition |
| Split-brain (concurrent state) | Latency + Partition | Distributed state | Eventual consistency via safety-net refresh |
| Retry storms | Error at threshold | Retry with backoff | Exponential backoff prevents amplification |
| Rate limit under load | Latency | Rate limiter | Graceful degradation; 429 responses |

### 3.2 Scenarios Covered in Tests

The `internal/chaos/scenarios_test.go` file validates the following real-world
resilience scenarios:

1. **Circuit breaker activation**: Repeated failures trigger circuit breaker
   open state; subsequent calls fail fast without hitting the backend
2. **Stale-token grace period**: Token provider continues serving cached tokens
   during transient refresh failures (60s grace period)
3. **Cascading failures**: Failure in one component propagates through
   dependent components with appropriate circuit breaker activation
4. **Redis partition with recovery**: Redis becomes unreachable, fail-closed/
   fail-open policies activate, then recovery when Redis returns
5. **Service restart with graceful degradation**: Simulates service restart;
   verifies reconnection and state recovery
6. **Split-brain scenario**: Concurrent state updates with simulated network
   delays; eventual consistency verified
7. **Retry with exponential backoff**: Transient errors trigger retries with
   increasing delays; permanent errors fail immediately
8. **Rate limiting under load**: System correctly applies rate limits under
   concurrent load with artificial latency

---

## 4. Fault Injection Points

### 4.1 Current Injection Points

| Component | Operation Name | Location | Fault Types Used |
|-----------|---------------|----------|-----------------|
| Token provider | `token_refresh` | `internal/agentruntime/token_provider.go` | Timeout, Error, Latency |
| HTTP client | `http_request` | `internal/agentruntime/httpclient.go` | Timeout, Partition, Latency |
| Kill switch | `killswitch_check` | `pkg/killswitch/` | Partition, Error |
| Revocation store | `revocation_check` | `pkg/revocation/` | Partition, Error |
| Rate limiter | `ratelimit_check` | `pkg/ratelimit/` | Partition, Error |
| Call counter | `callcounter_increment` | `pkg/callcounter/` | Partition, Error |
| Audit transport | `audit_enqueue` | `pkg/audit/transport.go` | Error, Latency |
| Posture delivery | `posture_deliver` | `internal/posture/delivery.go` | Timeout, Partition |

### 4.2 Adding New Injection Points

To add chaos testing to a new component:

```go
// 1. Accept an optional injector
type MyComponent struct {
    chaosInjector *chaos.Injector
    // ...
}

// 2. Call MaybeInject at the operation boundary
func (c *MyComponent) DoWork(ctx context.Context) error {
    if c.chaosInjector != nil {
        if err := c.chaosInjector.MaybeInject(ctx, "my_operation"); err != nil {
            return fmt.Errorf("my_operation: %w", err)
        }
    }
    // ... actual work
}

// 3. Write chaos test
func TestMyComponent_UnderPartition(t *testing.T) {
    inj := chaos.NewInjector()
    inj.SetFault("my_operation", chaos.Fault{
        Type:        chaos.FaultPartition,
        Probability: 1.0,
    })
    c := &MyComponent{chaosInjector: inj}
    err := c.DoWork(context.Background())
    require.ErrorIs(t, err, chaos.ErrPartition)
}
```

---

## 5. Test Execution Model

### 5.1 CI Integration

Chaos tests are part of the standard test suite and run in CI on every push:

```bash
make test   # Runs all tests including chaos scenarios
# go test -race -count=1 ./...
```

Chaos tests execute within the `internal/chaos/` package and are included in the
standard `go test` run. They require no external infrastructure (no Redis, no
databases) — all dependencies are mocked or stubbed.

### 5.2 Race Detector

All chaos tests run with `-race` flag enabled (configured in the Makefile),
which is critical because:
- Fault injection involves concurrent goroutines
- The injector uses `sync.RWMutex` for thread safety
- Race conditions in chaos handling would be particularly dangerous

### 5.3 Test Characteristics

| Property | Value |
|----------|-------|
| **External dependencies** | None (all mocked) |
| **Determinism** | Fully deterministic (`Probability: 1.0` in tests) |
| **Execution time** | < 2 seconds (no real network calls) |
| **Parallelism** | Safe for parallel execution (`t.Parallel()`) |
| **Coverage** | Covers all four fault types + combinations |

---

## 6. Release Gates

### 6.1 CI Pipeline Gates

All of the following must pass before a release:

| Gate | Tool | Threshold |
|------|------|-----------|
| Unit tests (including chaos) | `go test -race` | 100% pass |
| Lint | `golangci-lint` | 0 issues |
| Coverage (pkg/) | `go test -coverprofile` | ≥ 80% average |
| License headers | `make check-license` | All files compliant |
| Vulnerability scan | Trivy | 0 CRITICAL/HIGH |
| Build matrix | `go build` | linux/windows × amd64/arm64 |

### 6.2 Chaos Test Acceptance Criteria

For each resilience scenario, the acceptance criteria are:

1. **Circuit breaker**: Opens within configured threshold (default: 5 consecutive
   failures); closes after cooldown period
2. **Stale-token grace**: Serves cached token for full grace period (60s);
   returns error only after grace expires
3. **Fail-closed components** (kill switch, revocation): Block all requests
   during Redis unavailability
4. **Fail-open components** (rate limiter, call counter): Allow requests with
   degraded functionality during Redis unavailability
5. **Retry backoff**: Delays increase exponentially; never exceed max delay;
   respect context cancellation
6. **No goroutine leaks**: All background goroutines terminate when context is
   cancelled

### 6.3 Pre-Release Chaos Checklist

Before tagging a release:

- [ ] All `internal/chaos/` tests pass with `-race`
- [ ] Circuit breaker thresholds match production defaults
- [ ] Stale-token grace period is set to production value (60s)
- [ ] Redis failure mode tests cover all four Redis-dependent components
- [ ] No new components with Redis/network dependencies are missing chaos coverage
- [ ] Token provider tests cover issuer outage scenarios

---

## 7. Limitations and Future Work

### 7.1 Current Limitations

| Limitation | Impact | Mitigation |
|-----------|--------|------------|
| No real infrastructure chaos | Cannot test actual Redis failover | Use testcontainers for integration-level chaos |
| No clock skew simulation | Cannot test time-dependent logic under clock drift | Use `time.Now` injection for time-sensitive tests |
| No disk-full simulation | Cannot test SQLite/PostgreSQL under disk pressure | Monitor disk usage in production; alert at 80% |
| No OOM simulation | Cannot test behavior under memory pressure | Set memory limits in K8s; test with `GOMEMLIMIT` |
| Chaos is opt-in per component | New components may lack chaos coverage | Code review checklist includes chaos coverage |

### 7.2 Recommended Future Enhancements

1. **Integration-level chaos with testcontainers**: Use real Redis/PostgreSQL
   containers with `testcontainers-go` to simulate actual infrastructure failures
   (e.g., `docker pause` on Redis container)

2. **Chaos mesh for staging**: Deploy [Chaos Mesh](https://chaos-mesh.org/) in
   staging Kubernetes clusters for pre-production validation of:
   - Pod kill scenarios
   - Network partition between services
   - DNS failures
   - Clock skew injection

3. **Continuous chaos**: Schedule periodic chaos experiments in staging with
   automated result validation (GameDay automation)

4. **Chaos coverage metric**: Track which components have chaos injection points
   as a percentage of components with external dependencies

---

## 8. Related Documents

- [Agent Runtime Security](AGENT_RUNTIME_SECURITY.md) — Token provider resilience model
- [Redis Failure Modes](REDIS_FAILURE_MODES.md) — Fail-open vs. fail-closed policies
- [Distributed State](DISTRIBUTED_STATE.md) — Kill switch and revocation consistency
- [Posture Scaling](POSTURE_SCALING.md) — SQLite queue resilience
- [Architecture Overview](ARCHITECTURE.md) — System-wide component interactions
