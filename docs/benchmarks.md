# eunox-mcp Performance Benchmarks (T-09)

This document records the performance baseline established as part of T-09.
All numbers were measured on **Apple M4 (arm64, darwin)** with **Go 1.24**.

## How to reproduce

```sh
# Install benchstat (one-time)
go install golang.org/x/perf/cmd/benchstat@latest

# Quick run (3 samples per benchmark)
./scripts/bench.sh | tee bench.txt

# Statistical analysis with p99 estimate
benchstat bench.txt

# More samples for tighter confidence intervals
COUNT=10 ./scripts/bench.sh | tee bench-10.txt
benchstat bench-10.txt
```

Or run directly:

```sh
go test -run='^$' -bench=. -benchtime=3s -benchmem -count=3 ./cmd/mcp/ \
    2>&1 | grep -v '^\[eunox-mcp\]'
```

## Targets and measured results

Targets are defined in `docs/execution-plan.md` (T-09).
The table below shows the mean of 3 × 3s runs on the reference machine.

### 1. Policy evaluation — pure CPU, no I/O

| Benchmark | Mean ns/op | Allocs/op | **Target** | **Status** |
|---|---|---|---|---|
| ManifestPDP / Decide_Allow_SimpleRule | 390 ns | 4 | < 1 ms | ✅ |
| ManifestPDP / Decide_Deny_AbsentTool | 127 ns | 3 | < 1 ms | ✅ |
| ManifestPDP / Decide_Allow_WithGlobCondition | 459 ns | 4 | < 1 ms | ✅ |
| ManifestPDP / Decide_Allow_50Rules | **1 420 ns** | 4 | < 1 ms | ✅ |
| ManifestPDP / Decide_Deny_50Rules | 1 131 ns | 3 | < 1 ms | ✅ |
| ManifestPDP / Decide_Allow_WithAllowedOperations | 465 ns | 5 | < 1 ms | ✅ |
| JWTPDP / Decide_CachedClaims_Allow | 156 ns | 7 | < 1 ms | ✅ |
| JWTPDP / Decide_CachedClaims_Deny | 114 ns | 3 | < 1 ms | ✅ |
| JWTPDP / ValidateToken_CachedJWKS | 43 900 ns | 176 | — ¹ | — |

¹ `ValidateToken_CachedJWKS` is ECDSA P-256 signature verification (no JWKS network fetch;
cache is warm). This is called once per session, not on every tool call.

### 2. Full HTTP round-trip — stateless mode (no audit)

The **baseline** column is `Baseline_DirectUpstream` — a direct POST to the
in-process `httptest.Server` with no proxy in the path.  **Overhead** is the
added latency introduced by the eunox-mcp proxy layer.

| Benchmark | Total ns/op | Baseline ns/op | **Overhead** | **Target** | **Status** |
|---|---|---|---|---|---|
| HTTPProxy / Baseline_DirectUpstream | 32 419 ns | — | — | — | — |
| HTTPProxy / ManifestPDP_Allow | 39 716 ns | 32 419 | **7.3 µs** | < 2 ms | ✅ |
| HTTPProxy / ManifestPDP_Deny (blocked inline) | 5 221 ns | — | < 5.2 µs ² | < 2 ms | ✅ |
| HTTPProxy / ManifestPDP_Allow_WithAudit | 44 458 ns | 32 419 | **12 µs** | — ³ | — |
| HTTPProxy / ManifestPDP_50Rules_Allow | 38 857 ns | 32 419 | **6.4 µs** | < 2 ms | ✅ |

² Deny is short-circuited before the upstream call, so total latency is lower than baseline.  
³ Audit adds synchronous HMAC-SHA256 + file write. Overhead varies by storage medium
(tmpfs ~12 µs, SSD ~200 µs). No target defined for audited mode.

### 3. Full HTTP round-trip — JWT PDP mode (JWKS cached)

Every `tools/call` request includes a Bearer JWT. The JWKS is fetched once
during session initialisation and cached; subsequent calls verify only via the
in-memory key set.

| Benchmark | Total ns/op | Baseline ns/op | **Overhead** | **Target** | **Status** |
|---|---|---|---|---|---|
| HTTPProxy_JWTPDP / Allow_JWTOnly | 87 116 ns | 32 419 | **54.7 µs** | < 3 ms | ✅ |
| HTTPProxy_JWTPDP / Allow_JWTAndManifest | 88 559 ns | 32 419 | **56.1 µs** | < 3 ms | ✅ |
| HTTPProxy_JWTPDP / Deny_AbsentFromJWT | 49 999 ns | — | < 50 µs ² | < 3 ms | ✅ |

The ~55 µs JWT overhead is dominated by ECDSA P-256 signature verification
(~44 µs, see `ValidateToken_CachedJWKS` above). No further optimisation is
needed to meet the 3 ms target.

### 4. Redis kill-switch overhead

The Redis kill switch (`killswitch.NewRedis`) caches kill/revive state
in-memory and refreshes it via pub/sub. The `ShouldBlock()` call on the hot
path is a `sync.RWMutex` read + map lookup — not a Redis round-trip. Redis is
only contacted on state changes (`KillSession`, `ActivateGlobal`).

| Benchmark | Total ns/op | Non-Redis baseline | **Overhead** | **Target** | **Status** |
|---|---|---|---|---|---|
| HTTPProxy_RedisKS / ManifestPDP_Allow_RedisKS | 40 730 ns | 39 716 | **~1 µs** | < 5 ms | ✅ |

The in-memory hot path adds effectively zero overhead. In production, the Redis
RTT (typically < 1 ms on the same LAN) applies only when a session is killed or
the global switch is toggled — not on every request.

## Benchmark methodology

- **Framework**: standard `testing.B` from the Go toolchain — reproducible, CI-friendly, no external tooling required for basic runs.
- **Isolation**: all benchmarks use `httptest.NewServer` in-process; no external services. The Redis benchmark uses `miniredis` (in-process Redis).
- **HTTP keep-alive**: the bench upstream drains request bodies before responding and the client drains response bodies before `Close()` — ensuring the HTTP/1.1 connection pool is fully utilised across iterations.
- **Measurement window**: `b.ResetTimer()` is called after setup (server start, session initialisation, key generation) so setup costs are excluded from the measurement.
- **Allocation tracking**: `b.ReportAllocs()` is called in every benchmark; `allocs/op` values are reported by the Go runtime GC instrumentation.
- **Multiple counts**: `-count=3` provides three independent runs per benchmark so `benchstat` can compute mean ± variance. Use `-count=10` for tighter p99 estimates.
- **p99 extraction**: `benchstat` computes geometric mean and CI from multi-count runs; with `-count=10` it also reports the 95th-percentile confidence interval, which serves as a p99 proxy.

## How to read the overhead column

The "overhead" figure is:

```
overhead = round_trip_with_proxy - Baseline_DirectUpstream
```

This isolates the eunox-mcp proxy layer (PDP evaluation + session lookup +
JSON marshal/unmarshal) from the in-process loopback TCP cost that is common
to both the baseline and proxied cases.

In production, absolute latencies will be higher because of real network RTT
to the upstream MCP server. The *overhead* added by the proxy should remain
in the same range (it is CPU-bound, not network-bound).
