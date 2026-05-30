# eunox-mcp — MVP Readiness Report

_Date: 30 May 2026 · Stage 1 — Proxy MVP · commit `main`_  
_Prepared by: Principal Architect / Release Manager_  
_Updated: 30 May 2026 — **all SEC issues (SEC-01 through SEC-07) resolved and tests passing**_

---

## Executive Summary

eunox-mcp is functionally complete for its Stage 1 MVP scope. The core enforcement engine, both transport modes (stdio and HTTP), JWT PDP integration, Redis-backed session state, dry-run mode, and the demo stack are all implemented and passing CI. Performance baselines have been established and all latency targets are met with significant headroom.

**All 7 security issues (SEC-01 – SEC-07) have been remediated.** `cmd/mcp/security_test.go` provides regression coverage for every fix; all tests pass with `-race` and `golangci-lint` is clean. The remaining blockers before shipping to external evaluators are release infrastructure gaps (REL-01, REL-02) and process gates (Stage 1 exit items 8–10).

Additionally, overall test coverage for `cmd/mcp` stands at **28.4%**, with the entire stdio transport and audit subsystem untested by unit tests.

This report identifies every gap, classifies it by severity, and provides a sequenced execution plan. Estimated remaining remediation time is **2–4 engineering days**.

### Status Dashboard

| Area | Status | P0 | P1 | P2 |
|---|---|---|---|---|
| Core enforcement engine | ✅ READY | 0 | 0 | 0 |
| HTTP transport & JWT PDP | ✅ SEC FIXED | 0 | 0 | 0 |
| Audit log subsystem | ✅ SEC FIXED | 0 | 2 | 0 |
| stdio transport | 🟡 AT RISK | 0 | 1 | 0 |
| Release infrastructure | ✅ REL FIXED | 0 | 0 | 0 |
| Performance baselines (T-09) | ✅ READY | 0 | 0 | 0 |
| Stage 1 exit gate (process) | 🟡 IN PROGRESS | — | — | — |

> **Priority definitions:** P0 = release blocker (do not ship until resolved), P1 = high severity (resolve within current sprint), P2 = medium severity (resolve before public GA).

---

## Security Issues

### SEC-01 · Timing-unsafe auth-token comparison `[✅ FIXED]`

~~`[P0 — Release Blocker]`~~

The `--auth-token` bearer validation uses a direct string equality comparison, which is vulnerable to a timing side-channel attack. An attacker on a low-latency connection can measure response time differences character by character and brute-force the token.

| | |
|---|---|
| **File** | `cmd/mcp/http.go` · `checkAuth()` |
| **Finding** | `auth[len("Bearer "):] != p.authToken` — NOT timing-safe |
| **Fix** | `!hmac.Equal([]byte(tok), []byte(p.authToken))` — constant-time |
| **Resolved** | `checkAuth()` now uses `hmac.Equal`; `crypto/hmac` import added |
| **Tests** | `TestSEC01_CheckAuth_ConstantTimeComparison`, `TestSEC01_HMACEqual_ConstantTimeProperty`, `TestSEC01_NoAuthToken_AllowsAll` |

---

### SEC-02 · Timing-unsafe HMAC verification in audit log `[✅ FIXED]`

~~`[P0 — Release Blocker]`~~

`VerifyRecord` compares the stored HMAC string with a re-computed value using `==` rather than a constant-time comparison. This allows timing-oracle attacks against the audit integrity verification path.

| | |
|---|---|
| **File** | `cmd/mcp/audit.go` · `VerifyRecord()` |
| **Finding** | `return storedHMAC == want, nil` — NOT timing-safe |
| **Fix** | `return hmac.Equal([]byte(storedHMAC), []byte(want)), nil` |
| **Resolved** | `VerifyRecord()` now uses `hmac.Equal` |
| **Tests** | `TestSEC02_VerifyRecord_ConstantTimeHMAC` (valid sig, tampered body, wrong HMAC, missing field, invalid JSON) |

---

### SEC-03 · HTTP server lacks `ReadTimeout` and `WriteTimeout` `[✅ FIXED]`

~~`[P0 — Release Blocker]`~~

The HTTP server is configured with only `ReadHeaderTimeout` (10 s). Without `ReadTimeout` and `WriteTimeout`, a slow client can hold connections open indefinitely. This enables a Slowloris-style denial-of-service attack that would starve all proxy sessions.

| | |
|---|---|
| **File** | `cmd/mcp/http.go` · `Serve()` — `&http.Server{...}` |
| **Finding** | `ReadHeaderTimeout: 10s` only — `ReadTimeout` and `WriteTimeout` absent |
| **Fix** | Added `ReadTimeout: 30s, WriteTimeout: 30s`; SSE `handleMCPGet` calls `http.NewResponseController(w).SetWriteDeadline(time.Time{})` to disable write deadline for long-lived streams |
| **Resolved** | Both timeouts set via `httpReadTimeout`/`httpWriteTimeout` constants (30 s each); SSE connections exempt via per-connection `ResponseController` |
| **Tests** | `TestSEC03_ServerTimeouts` (constant validation), `TestSEC03_SSEWriteDeadlineReset` (stream stays alive) |

---

### SEC-04 · No request body size limit `[✅ FIXED]`

~~`[P0 — Release Blocker]`~~

`json.NewDecoder(r.Body).Decode()` in `handleMCPPost` reads an unbounded body. A malicious client can send a gigabyte of JSON to exhaust server memory and cause an OOM kill. The proxy has no defence against this.

| | |
|---|---|
| **File** | `cmd/mcp/http.go` · `handleMCPPost()` and `handleKill()` |
| **Finding** | `json.NewDecoder(r.Body).Decode(&msg)` — unbounded |
| **Fix** | `r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)` (4 MiB) before `Decode`; `*http.MaxBytesError` returns 413 |
| **Resolved** | Both `handleMCPPost` and `handleKill` enforce the 4 MiB limit |
| **Tests** | `TestSEC04_MaxBytesReader_Post`, `TestSEC04_MaxBytesReader_Kill`, `TestSEC04_NormalBodyAccepted` |

---

### SEC-05 · Silent passthrough when no policy is configured `[✅ FIXED]`

~~`[P0 — Release Blocker]`~~

When `eunox-mcp proxy` is launched without `--policy` or `--jwks-uri`, the proxy falls through to an internal `alwaysAllowPDP` that permits every tool call. No warning is printed. A user who forgets `--policy` gets zero enforcement with no indication — indistinguishable from a correctly configured deployment.

| | |
|---|---|
| **File** | `cmd/mcp/main.go` · `cmdProxy()` |
| **Finding** | `if len(*policyFiles) > 0 { ... }` — else: `pdp` remains `nil` → `alwaysAllowPDP` |
| **Resolved** | `cmdProxy()` prints a loud `WARNING` to stderr when both `policyFiles` and `jwksURI` are empty, before any sessions are accepted |
| **Tests** | `TestSEC05_NoPolicyWarning` (canary — confirms the warning constant and condition are present) |

---

### SEC-06 · Denial response echoes user-controlled argument values `[✅ FIXED]`

~~`[P1]`~~

Denial responses from `AllowedValues` and `AllowedExtensions` conditions include the user-supplied argument value in the `details` field (`details.value`, `details.filePath`). This is returned to the MCP client. An adversary can probe which paths and values are permitted by submitting boundary cases and reading the denial details.

| | |
|---|---|
| **File** | `cmd/mcp/http.go` · `sanitizeDenialDetails()` + `handleHTTPToolsCall()` |
| **Risk** | Low severity — leaks that a value was checked, not what is allowed. Audit log exposure is intentional. Client-facing response is the concern. |
| **Resolved** | `sanitizeDenialDetails()` redacts `"value"`, `"filePath"`, `"extension"`, `"operation"`, `"sourceIp"`, `"tables"`, `"recipients"` to `"[redacted]"` in the client-facing JSON-RPC error. Audit log receives the full, unsanitized details. |
| **Tests** | `TestSEC06_SanitizeDenialDetails` (11 sub-cases covering all sensitive keys), `TestSEC06_DenialResponseSanitized` (end-to-end: raw path absent from response, `[redacted]` present) |

---

### SEC-07 · `/control/kill` bypasses `--auth-token` `[✅ FIXED]`

~~`[P2]`~~

The kill endpoint checks only that the request originates from loopback (`127.0.0.1` or `::1`). When `--auth-token` is also set, the kill endpoint does not require the token. If an attacker can make the upstream MCP server issue an SSRF-style loopback request, they can activate the global kill switch.

| | |
|---|---|
| **File** | `cmd/mcp/http.go` · `handleKill()` |
| **Risk** | Low — requires SSRF capability. Loopback restriction is a meaningful control. |
| **Resolved** | `handleKill()` calls `p.checkAuth(w, r)` after the loopback IP check; returns 401 when token is set but absent/wrong |
| **Tests** | `TestSEC07_KillEndpoint_RequiresAuth` (no auth, wrong auth, correct auth), `TestSEC07_KillEndpoint_NoAuthToken_AllowsAll`, `TestSEC07_KillEndpoint_RemoteIP_Blocked` |

---

## Release Infrastructure Gaps

### REL-01 · `eunox-mcp` binary absent from GoReleaser `[✅ FIXED]`

~~`[P0 — Release Blocker]`~~

`.goreleaser.yml` defines builds for six legacy services but did not include `cmd/mcp`. The `go-publish.yml` GitHub Actions workflow was explicitly disabled (`if: false`).

| | |
|---|---|
| **Files** | `.goreleaser.yml` + `.github/workflows/go-publish.yml` |
| **Resolved** | Added `mcp` build entry to `.goreleaser.yml` for `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64` (windows/arm64 excluded). Added separate `mcp` archive entry that bundles `cmd/mcp/LICENSE` (Apache-2.0). Added Docker image entries (`mcp-amd64`, `mcp-arm64`) and `docker_manifests` for `ghcr.io/eunolabs/eunox-mcp`. Removed `if: false` from `go-publish.yml`. |
| **Remaining** | Push `v0.1.0` tag to trigger the release workflow. |

---

### REL-02 · Docker image registry mismatch `[✅ FIXED]`

~~`[P0 — Release Blocker]`~~

`README.md` instructs users to `docker pull ghcr.io/eunolabs/eunox-mcp:latest` but `docker-publish.yml` only pushed to Docker Hub. Every evaluator who follows the README hits a 404.

| | |
|---|---|
| **Files** | `.github/workflows/docker-publish.yml` |
| **Resolved** | Both `docker-linux` and `docker-windows` jobs now log in to GitHub Container Registry (`ghcr.io`) and include `ghcr.io/eunolabs/eunox-mcp` in the `images:` list. Added `permissions: packages: write` for the GITHUB_TOKEN push. Images are now pushed to both Docker Hub and `ghcr.io` on every semver tag. |

---

### REL-03 · No `--version` flag `[✅ FIXED]`

~~`[P1]`~~

The binary did not respond to `eunox-mcp --version` or `eunox-mcp version`. The Docker image `Dockerfile` injected a `VERSION` build arg but the binary never exposed it.

| | |
|---|---|
| **Files** | `cmd/mcp/main.go`, `cmd/mcp/stdio.go`, `.goreleaser.yml` |
| **Resolved** | Added `var version = "dev"` (set via `-ldflags -X main.version={{.Version}}`); added `version`, `--version`, `-version` dispatch in `main()`; `cmdVersion()` prints `eunox-mcp version <version>`; `proxyVersion` (reported in MCP initialize responses) is kept in sync via `init()`. goreleaser ldflags now inject the tag into the binary. |
| **Verify** | `eunox-mcp version` → `eunox-mcp version dev` (local); `eunox-mcp version` → `eunox-mcp version 0.1.0` (release build). |

---

### REL-04 · Audit HMAC key path not configurable `[✅ FIXED]`

~~`[P1]`~~

The audit signing key was hardcoded to `~/.eunox/audit.key` with no CLI flag or environment variable override. In containerised environments the key could not be injected.

| | |
|---|---|
| **Files** | `cmd/mcp/audit.go`, `cmd/mcp/main.go` |
| **Resolved** | `openAuditSink` now accepts a `keyPath string` parameter. `cmdProxy` exposes `--audit-key-path`; `cmdValidateToken` also exposes `--audit-key-path`. Resolution order: flag > `EUNOX_AUDIT_KEY_PATH` env var > `~/.eunox/audit.key` default. |

---

## Test Coverage Gaps

Overall `cmd/mcp` statement coverage: **28.4%** (vs the 80% threshold enforced for `pkg/` packages).

| File | Coverage | Lines | Gap |
|---|---|---|---|
| `audit.go` | 🔴 0% | 247 | `openAuditSink`, `Record`, `Close`, `VerifyRecord`, `rotate`, `loadOrCreateAuditKey` — all untested |
| `stdio.go` | 🔴 0% | 451 | Entire stdio transport: `NewStdioProxy`, `Start`, `initUpstream`, `serveHost`, `handleToolsCall` — all untested |
| `main.go` | 🔴 ~0% | 778 | `cmdProxy`, `cmdValidate`, `cmdKill`, `cmdStats`, `cmdValidateToken`, `cmdProfiles` — no unit tests |
| `http.go` | 🟡 ~30% | 779 | SSE stream path, session close/delete, kill endpoint, upstream error paths |
| `pdp_jwt.go` | ✅ ~85% | 505 | Good coverage. `findJWKS` (66.7%), `matchesAllowedValues` (85.7%) are minor gaps |
| `redis.go` / `resolver.go` | ✅ 100% | 195 | Fully covered |

---

### COV-01 · `audit.go` — 0% coverage `[P1]`

The HMAC-SHA256 signing chain, log rotation, key generation, and `VerifyRecord` are the primary tamper-evidence guarantees of the product. Zero test coverage means regressions in these paths are invisible. The `dry_run_test.go` exercises the `auditSink` struct but bypasses the real `openAuditSink` constructor, leaving all file I/O, key loading, and rotation paths completely uncovered.

**Required tests:** `openAuditSink` creates dir and file; `Record` writes HMAC-signed JSONL; `VerifyRecord` round-trip; rotation triggers at `maxBytes`; `loadOrCreateAuditKey` generates and persists key; `expandHome` handles tilde.

---

### COV-02 · `stdio.go` — 0% coverage `[P1]`

The stdio transport is the primary integration mode for Claude Desktop and other local MCP hosts. Its 451 lines have never been tested. Subprocess management, JSON-RPC framing, tool call enforcement, and upstream error handling are all exercised only in production. Testing the stdio path requires either a fake subprocess or an in-process mock reader/writer pair.

---

### COV-03 · `main.go` subcommands — ~0% coverage `[P2]`

The `validate`, `kill`, `validate-token`, `stats`, and `profiles` subcommands have no unit tests. Basic smoke tests (valid input, invalid input, missing required args) are needed for all user-facing entry points.

---

### COV-04 · `http.go` — SSE and error paths `[P2]`

The `GET /mcp` SSE stream path (`handleMCPGet`), the session delete path (`handleMCPDelete`), and upstream timeout/error paths in `handleHTTPToolsCall` are not covered by `go test ./cmd/mcp/`.

---

## Operational Gaps

### OPS-01 · `profiles.go` uses `panic()` for embedded data failures `[P1]`

The `init()` function calls `panic()` if the embedded profiles directory or any YAML file cannot be read or parsed. A panic in `init()` crashes the binary before `main()` runs with no graceful error message.

| | |
|---|---|
| **File** | `cmd/mcp/profiles.go` · `init()` — lines 44, 53, 57 |
| **Fix** | Convert to a package-level var + `sync.Once` initialization that returns an error, surfaced at first call rather than at startup |
| **Effort** | 1 h |

---

### OPS-02 · Audit log always opens on startup `[P2]`

The audit sink is unconditionally opened in `cmdProxy()` (`// always open audit sink`). In ephemeral environments (unit-test runner, read-only container filesystem), this silently degrades to `sink = nil`, dropping audit records with a single warning line. An explicit `--no-audit` flag is needed for testing and restricted environments.

| | |
|---|---|
| **File** | `cmd/mcp/main.go` · line 277 |
| **Effort** | 30 min — add `--no-audit` flag, skip `openAuditSink` when set |

---

## Stage 1 Exit Gate Status

| # | Condition | Status | Type |
|---|---|---|---|
| 1 | `--upstream-url` flag ships; tested against remote MCP server | ✅ DONE | Code |
| 2 | JWT PDP mode works with Auth0 and Keycloak | ✅ DONE | Code |
| 3 | Dry-run mode exposed as `--dry-run` CLI flag | ✅ DONE | Code |
| 4 | Demo completes in under 10 minutes on a cold machine | ✅ DONE | Process |
| 5 | OPA/Envoy failure demo publicly runnable (`demo/opa-comparison/`) | ✅ DONE | Code |
| 6 | Threat model published at `docs/threat-model-mcp.md` | ✅ DONE | Docs |
| 7 | README leads with `eunox-mcp`, not the 6-service architecture | ✅ DONE | Docs |
| 8 | Audit log schema has not changed for 2 consecutive weeks | ⏳ PENDING | Process |
| 9 | 3 production or active staging deployments running | ⏳ PENDING | Process |
| 10 | At least one unanticipated capability claim pattern from real traffic | ⏳ PENDING | Process |

Items 8, 9, and 10 are process gates that cannot be completed by engineering alone.

---

## Execution Plan

All P0 blockers can be resolved in a single focused sprint of 1–2 days. P1 items add approximately 3–4 additional days. **Total estimated effort: 4–6 engineering days.**

### Sprint A · Security and Release Blockers — Days 1–2

> **Do not tag `v0.1.0` until all items in this sprint are complete.**

| ID | Task | Priority | Effort | Ref | Status |
|---|---|---|---|---|---|
| A-1 | Replace `!=` in `checkAuth` with `hmac.Equal` | P0 | 15 min | SEC-01 | ✅ Done |
| A-2 | Replace `==` in `VerifyRecord` with `hmac.Equal` | P0 | 10 min | SEC-02 | ✅ Done |
| A-3 | Add `ReadTimeout`/`WriteTimeout` + SSE `ResponseController` | P0 | 30 min | SEC-03 | ✅ Done |
| A-4 | Add `http.MaxBytesReader` (4 MiB) in `handleMCPPost` and `handleKill` | P0 | 15 min | SEC-04 | ✅ Done |
| A-5 | Add startup `WARNING` when both `policyFiles` and `jwksURI` are empty | P0 | 15 min | SEC-05 | ✅ Done |
| A-5b | Strip user-controlled values from client-facing denial (moved up from Sprint B) | P1 | 1 h | SEC-06 | ✅ Done |
| A-5c | Add `checkAuth()` to `handleKill` after loopback check | P2 | 30 min | SEC-07 | ✅ Done |
| A-5d | Write `security_test.go` covering all 7 SEC fixes; pass `-race` + `golangci-lint` | P0 | 2 h | — | ✅ Done |
| A-6 | Add `eunox-mcp` build + Docker entries to `.goreleaser.yml` (5 platforms) | P0 | 1 h | REL-01 | ✅ Done |
| A-7 | Enable `go-publish.yml` (remove `if: false`) | P0 | 10 min | REL-01 | ✅ Done |
| A-8 | Add `ghcr.io` login + push target to `docker-publish.yml` | P0 | 30 min | REL-02 | ✅ Done |
| A-8b | Add `--version` flag + `version` subcommand; wire into goreleaser ldflags | P1 | 1 h | REL-03 | ✅ Done |
| A-8c | Add `--audit-key-path` flag + `EUNOX_AUDIT_KEY_PATH` env var | P1 | 2 h | REL-04 | ✅ Done |
| A-9 | Tag `v0.1.0` and verify GoReleaser produces binaries for all 5 platforms | P0 | 30 min | REL-01 | ⏳ TODO — requires tag push |

---

### Sprint B · Quality and Hardening — Days 3–5

| ID | Task | Priority | Effort | Ref |
|---|---|---|---|---|
| B-1 | Add unit tests for `audit.go`: `openAuditSink`, `Record` (HMAC round-trip), `VerifyRecord`, `rotate`, `loadOrCreateAuditKey` | P1 | 3 h | COV-01 |
| B-2 | Add unit tests for `stdio.go`: pipe-based mock, tool allow/deny, upstream error | P1 | 4 h | COV-02 |
| B-3 | ~~Add `--version` flag and `version` subcommand~~ | ~~P1~~ | — | REL-03 | ✅ Done (moved to Sprint A) |
| B-4 | ~~Add `--audit-key-path` flag~~ | ~~P1~~ | — | REL-04 | ✅ Done (moved to Sprint A) |
| B-5 | ~~Strip user-controlled values from denial response~~ | ~~P1~~ | — | SEC-06 | ✅ Done (moved to Sprint A) |
| B-6 | Convert `profiles.go` `panic()` calls to lazy init with error return | P1 | 1 h | OPS-01 |
| B-7 | ~~Add `checkAuth()` to `handleKill`~~ | ~~P2~~ | — | SEC-07 | ✅ Done (moved to Sprint A) |
| B-8 | Add `--no-audit` flag for testing and read-only filesystem environments | P2 | 30 min | OPS-02 |
| B-9 | Add smoke tests for `validate`, `kill`, `stats`, `profiles` subcommands | P2 | 2 h | COV-03 |
| B-10 | Raise `cmd/mcp` test coverage to ≥60%; add coverage gate to `go-ci.yml` | P2 | 1 h | — |

---

### Sprint C · Deployment and Process Gates — Days 6–10+

These items involve external activities and cannot be gated on engineering completion alone.

| ID | Task | Priority | Owner |
|---|---|---|---|
| C-1 | Deploy `v0.1.0` to 3 production or active staging environments | P0 | Founder |
| C-2 | Monitor audit log schema for 2 consecutive weeks without structural changes | P0 | Eng + Ops |
| C-3 | Collect at least one unanticipated capability claim pattern from real traffic | P0 | Product |
| C-4 | Publish `docs/benchmarks.md` (already complete — T-09 done) | ✅ Done | Eng |
| C-5 | Commission third-party penetration test (post-Stage 2) | P1 | Founder |

---

## Appendix A — cmd/mcp Coverage by File

_Measured with `go test -count=1 -coverprofile=coverage.out -covermode=atomic ./cmd/mcp/` on commit `main` @ 30 May 2026._

| File | Coverage | Notes |
|---|---|---|
| `audit.go` | 🔴 0% | HMAC chain, rotation, key management — entirely untested |
| `http.go` | 🟡 ~30% | Core HTTP proxy — PDP and upstream paths exercised; SSE, errors not |
| `http_remote.go` | ✅ ~75% | Remote upstream — good coverage via `http_upstream_test.go` |
| `jsonrpc.go` | 🟡 ~40% | `rpcMsg` helpers — `isResponse`, `isNotification`, `msgWriter` not tested |
| `main.go` | 🔴 ~0% | All subcommands — no unit tests |
| `manifest.go` | 🔴 0% | `LoadManifest`, `MergeManifests` — not tested |
| `pdp.go` | 🟡 ~55% | `ManifestPDP` core path tested; schema validation, extractors partial |
| `pdp_jwt.go` | ✅ ~85% | Good. `findJWKS` (66%) and `matchesAllowedValues` (85%) are gaps |
| `profiles.go` | 🟡 ~72% | `BuiltinResolver` tested; `LoadActionMap`, `BuiltinProfileDescription` at 0% |
| `redis.go` | ✅ 100% | Fully covered by `redis_test.go` |
| `resolver.go` | ✅ 100% | Fully covered by `resolver_test.go` |
| `stdio.go` | 🔴 0% | Entire stdio transport — no tests |

---

## Appendix B — Performance Baseline (T-09)

All performance targets are met with significant headroom. Full methodology and raw numbers: [`docs/benchmarks.md`](./benchmarks.md).

| Scenario | Measured | Target | Status |
|---|---|---|---|
| Stateless proxy overhead (manifest PDP, no Redis) | ~7.3 µs | < 2 ms | ✅ PASS |
| JWT PDP overhead (JWKS cached) | ~55 µs | < 3 ms | ✅ PASS |
| Redis kill-switch hot path | ~1 µs | < 5 ms | ✅ PASS |
| 50-rule manifest policy evaluation | ~1.4 µs | < 1 ms | ✅ PASS |
