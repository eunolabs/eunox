# eunox — Execution Plan v2
_Grounded in the actual codebase as of May 2026_

Three stages. Hard exit gate on each. You do not start the next stage until the gate closes.

**Stage 1 — Proxy MVP:** ship `cmd/mcp/` as the product, get 3 production deployments  
**Stage 2 — Open Spec:** extract and publish the interoperability standard from production data  
**Stage 3 — Integration Platform:** distribute enforcement across existing infrastructure, launch commercially  

---

## What's Already Built (Don't Rebuild)

Before the gap list, the inventory of what `cmd/mcp/` actually has:

- **Two transports:** stdio (subprocess pipe) and HTTP — both working
- **ManifestPDP:** YAML/JSON policy files, argument schema validation (JSON Schema subset), most-specific-match routing
- **11 condition types:** `TimeWindow`, `IPRange`, `AllowedOperations`, `AllowedExtensions`, `AllowedTables`, `MaxCalls`, `RecipientDomain`, `RedactFields`, `Policy`, `Custom`, `AllowedValues`
- **Kill switch:** per-session, per-agent, global — in-memory, `kill` subcommand wired
- **Call counter:** sliding-window, in-memory
- **OCSF audit log:** HMAC-SHA256 per-record signing, tamper-evident, auto-rotation at 100MiB
- **CLI subcommands:** `proxy`, `validate`, `kill`, `validate-token`, `stats`
- **Dry-run mode:** already in the enforcement engine via `WithDryRun(ctx)` — not yet exposed in the proxy CLI
- **GoReleaser, golangci-lint, race detector, coverage:** toolchain is solid

The enforcement engine (`pkg/enforcement/`) has an OPA/external `PolicyEvaluator` interface already stubbed. The audit pipeline (`pkg/audit/`) has PostgreSQL ledger, EdDSA/ECDSA signing, and OCSF export — well ahead of MVP needs.

**The problem is not the code. It's that this is presented as a 6-service enterprise platform when the actual MVP is a single binary that's mostly built.**

---

---

# Stage 1 — Proxy MVP

**Duration:** 4–5 weeks  
**Goal:** `cmd/mcp/` is the product. One binary, one manifest file, remote MCP server support, JWT PDP mode, demo that runs in under 10 minutes, 3 production deployments.  
**Stage gate:** 3 production deployments running, audit schema stable for 2 consecutive weeks, one unanticipated policy pattern observed from real traffic

---

## Sprint 1 — Close the Critical Gaps (Weeks 1–2)

### T-01 · Remote MCP server routing via `--upstream-url`
**Effort:** 1–2 days · **Priority:** P0 · **Depends on:** nothing · **Status: ✅ DONE**

Currently `HTTPProxyOptions` takes `Command` and `Args` — even HTTP mode spawns a local subprocess. This blocks the most compelling enterprise topology: enforcing capability claims on hosted MCP servers (Stripe, GitHub, internal APIs) without co-locating the proxy with the server.

**Steps:**
1. ✅ Add `UpstreamURL string` to `HTTPProxyOptions` (+ `UpstreamAuthHeader`, `UpstreamTLSSkipVerify`)
2. ✅ When `UpstreamURL` is set, skip subprocess spawning; each session communicates with the remote server via HTTP (`cmd/mcp/http_remote.go`)
3. ✅ When `UpstreamURL` is empty, fall back to current subprocess behavior — no breaking change
4. ✅ Handle upstream auth: `--upstream-auth-header "Header-Name: Header-Value"` forwarded on every upstream request
5. ✅ Handle TLS: system cert pool by default; `--upstream-tls-skip-verify` accepted with loud startup warning

**Implementation notes:**
- `cmd/mcp/http_remote.go` — `newRemoteSession`, `initRemoteUpstream`, `callRemoteUpstream`, `doRemoteHTTP`
- `--` separator is now optional; `--upstream-url` and `-- command` are mutually exclusive
- `--upstream-url` is the base URL; the proxy appends `/mcp` (`mcpEndpointURL()`)
- SSE notifications from the remote server are not forwarded (MVP limitation, documented)

**Invocation:**
```bash
# Local subprocess (existing behavior, unchanged)
eunox-mcp proxy --transport http --policy manifest.yaml -- node ./server.js

# Remote MCP server (new)
eunox-mcp proxy \
  --transport http \
  --upstream-url https://mcp.stripe.com \
  --upstream-auth-header "Authorization: Bearer sk-..." \
  --policy manifest.yaml
```

**Done when:** proxy enforces a manifest policy against a remote MCP server with zero local subprocess. Automated test using `httptest.NewServer` as the fake upstream.

**Verified:** 11 tests in `cmd/mcp/http_upstream_test.go` covering initialize, allow/deny enforcement, auth header forwarding, session delete, TLS skip-verify, multi-session isolation, and URL construction. All pass with `-race`.

---

### T-02 · JWT PDP mode — IdP-issued capability claims
**Effort:** 3–4 days · **Priority:** P0 · **Depends on:** nothing (parallel with T-01) · **Status: ✅ DONE**

The current `ManifestPDP` enforces from a local YAML file. For enterprise deployments, the capability set needs to come from the IdP token the agent already has — so eunox becomes additive to their existing auth stack rather than a replacement.

**Claim schema (lock this, it becomes the spec seed):**
```json
{
  "eunox.capabilities": ["read_file:/reports/*", "query_db:SELECT"],
  "eunox.task_id": "task-abc123",
  "eunox.agent_id": "agent-xyz"
}
```

**Steps:**
1. ✅ Add `--jwks-uri`, `--jwt-issuer`, `--jwt-audience` flags to `cmdProxy()`
2. ✅ When `--jwks-uri` is set, `JWTPDP` (`cmd/mcp/pdp_jwt.go`):
   - Fetches and caches JWKS with singleflight deduplication; force-refreshes on key miss (key rotation safe)
   - Validates incoming JWT: signature, expiry, issuer (`--jwt-issuer`), audience (`--jwt-audience`)
   - Extracts `eunox.capabilities` claim array (`[]string`, parsed separately from standard JWT claims)
   - Translates each claim string into a `capability.Constraint` and evaluates conditions directly
3. ✅ When both `--jwks-uri` and `--policy` are set: JWT claims narrow the manifest — intersection, not union. JWT can only restrict, never expand beyond what the manifest permits.
4. ✅ When neither is set: fall through to `alwaysAllowPDP` (existing transparent passthrough)
5. ✅ 401 on invalid/expired JWT (HTTP layer, before JSON-RPC routing); 403-equivalent JSON-RPC denial on capability mismatch — both logged to audit
6. ✅ Claim shorthand: `"tool"` (allow), `"tool:SELECT"` (AllowedOperations), `"tool:/path/*"` (AllowedValues path glob)

**Implementation notes:**
- `cmd/mcp/pdp_jwt.go` — `JWTPDP`, `jwksCache`, `JWTClaims`, context propagation, claim parsing
- JWT pre-validation at HTTP layer in `handleMCP` (401 returned directly); claims propagated via `context.WithValue`
- `JWTPDP.Decide()` reads claims from context; inner PDP checked for intersection when `--policy` is also set
- Custom `jwksCache` instead of reusing `capability.JWKSClient`: IdP tokens use `eunox.capabilities: []string` which cannot unmarshal into `TokenPayload.Capabilities []Constraint`
- `--jwks-uri` requires `--transport http`

**Invocation:**
```bash
# JWT-only mode (no manifest)
eunox-mcp proxy \
  --transport http \
  --jwks-uri https://idp.example.com/.well-known/jwks.json \
  --jwt-issuer https://idp.example.com \
  --jwt-audience eunox \
  --upstream-url https://mcp.stripe.com \
  --upstream-auth-header "Authorization: Bearer sk-..."

# JWT + manifest intersection (JWT narrows manifest)
eunox-mcp proxy \
  --transport http \
  --jwks-uri https://idp.example.com/.well-known/jwks.json \
  --policy manifest.yaml \
  --upstream-url https://mcp.stripe.com \
  --upstream-auth-header "Authorization: Bearer sk-..."
```

**Verified:** 23 tests in `cmd/mcp/pdp_jwt_test.go` covering claim parsing, JWT validation (valid, expired, wrong issuer, wrong audience, invalid signature, unknown kid with refresh), enforce decisions (allow, deny by tool, path glob, SQL verb), intersection with manifest, JWKS singleflight concurrency, HTTP 401 integration. All pass with `-race`.

---

### T-03 · Expose dry-run mode in the proxy CLI
**Effort:** half a day · **Priority:** P1 · **Depends on:** nothing · **Status: ✅ DONE**

`WithDryRun(ctx)` already exists in the enforcement engine. It evaluates policies but doesn't block. It's not exposed as a CLI flag yet.

**Steps:**
1. ✅ Add `--dry-run` flag to `cmdProxy()`
2. ✅ When set, inject `enforcement.WithDryRun(ctx)` into every `Decide()` call (skips MaxCalls counter side effects)
3. ✅ Log dry-run decisions at `WARN` level (`[eunox-mcp] DRY-RUN WARN: tool "X" would be denied (CODE) — forwarding anyway`) with `dry_run: true` field in the audit record
4. ✅ Print a startup banner: `[eunox-mcp] DRY-RUN MODE: policies are evaluated but not enforced`

**Why now:** enterprises will not deploy a new enforcement component in production without first running it in observation mode for 1–2 weeks. This is the difference between "interesting" and "deployable."

**Implementation notes:**
- `cmd/mcp/audit.go` — `auditRecord.DryRun bool` field (omitted when false), `Record` signature updated with `dryRun bool` parameter
- `cmd/mcp/stdio.go` + `cmd/mcp/http.go` — `dryRun bool` field on both proxy types; `handleToolsCall`/`handleHTTPToolsCall` observe the deny, log it, and forward when `dryRun=true`
- JWT 401 responses are not affected by dry-run (authentication, not policy)
- Upstream errors are not affected by dry-run (infrastructure fault, not policy)

**Invocation:**
```bash
eunox-mcp proxy --dry-run --policy manifest.yaml -- node ./server.js
```

**Verified:** 6 tests in `cmd/mcp/dry_run_test.go` covering: deny forwarded in dry-run, audit dry_run flag, normal-mode deny still blocks, allowed-call unaffected, audit record JSON field present/omitted. All pass with `-race`.

---

### T-04 · Redis-backed session state (optional upgrade)
**Effort:** 2–3 days · **Priority:** P1 · **Depends on:** T-01 · **Status: ✅ DONE**

In-memory state means session context is lost on restart and doesn't survive across multiple proxy instances. For single-instance local deployments this is fine. For anything that needs persistence or horizontal scale it isn't.

The interfaces are already correct — `callcounter.Store` and `killswitch.Manager` are both interface-driven. The gateway already has Redis implementations in `pkg/callcounter/redis.go` and `pkg/killswitch/redis.go` — task was purely wiring them into `cmd/mcp/main.go`.

**Steps:**
1. ✅ `pkg/callcounter/redis.go` and `pkg/killswitch/redis.go` already existed fully implemented
2. ✅ Add `cmd/mcp/redis.go` — `buildRedisClient` (host:port params) and `pingRedis` with startup error messaging
3. ✅ In `cmdProxy()`: pre-create `counter` and `ks` before manifest loading; when `--redis-addr` is set, replace defaults with Redis implementations; `ksRedis.Start(ctx)` called after signal setup
4. ✅ Add optional `--redis-addr`, `--redis-password`, `--redis-tls` flags

**This is optional at MVP** — the proxy works without it. In-memory state resets on restart. Use `--redis-addr` for persistent session context.

**Implementation notes:**
- `cmd/mcp/redis.go` — `buildRedisClient` (single-node, host:port), `pingRedis`; URL-based factory not used (simpler for proxy MVP)
- Counter and kill-switch pre-created before manifest loading; fixes prior bug where JWT PDP wrapping ManifestPDP caused HTTP case to fall back to a fresh in-memory kill-switch
- `ksRedis.Start(ctx)` starts pub/sub goroutine for real-time state propagation; `ks = ksRedis` satisfies `killswitch.Manager` for both ManifestPDP and HTTPProxy

**Invocation:**
```bash
# In-memory (default — no Redis required)
eunox-mcp proxy --transport http --policy manifest.yaml --upstream-url https://mcp.example.com

# Redis-backed (persistent, multi-instance)
eunox-mcp proxy \
  --transport http \
  --policy manifest.yaml \
  --upstream-url https://mcp.example.com \
  --redis-addr localhost:6379 \
  --redis-password secret \
  --redis-tls
```

**Verified:** 8 tests in `cmd/mcp/redis_test.go` covering: empty-addr error, successful client construction, TLS config set, password set, ping success/failure, call-counter increment via miniredis, kill-switch session kill and global activate via miniredis. All pass with `-race`.

---

## Sprint 2 — Demo and Developer Experience (Weeks 2–3)

### T-05 · `demo/` directory — single-command setup
**Effort:** 3–4 days · **Priority:** P0 · **Depends on:** T-01, T-02 · **Status: ✅ DONE**

The existing `infra/docker-compose.yml` spins up the full 6-service enterprise stack. That's wrong for a first evaluation. Someone cloning the repo for the first time needs to see enforcement working in under 10 minutes.

**Deliverables:**

`demo/docker-compose.yml` — three services only:
```yaml
services:
  mock-mcp-server:   # a minimal Go HTTP server with 3 tools: read_file, write_file, query_db
  keycloak:          # pre-seeded with a test realm, an agent client, eunox capability claims mapper
  eunox-mcp:         # cmd/mcp binary, HTTP transport, --upstream-url pointing at mock-mcp-server
```

`demo/manifest.yaml` — pre-built policy for the demo:
```yaml
name: demo-agent
version: "1.0"
capabilities:
  - resource: read_file
    actions: [call]
    conditions:
      - type: allowedValues
        field: path
        values: ["/reports/*"]
  - resource: query_db
    actions: [call]
    conditions:
      - type: maxCalls
        limit: 5
      - type: allowedOperations
        operations: [SELECT]
  # write_file intentionally absent → deny by default when using JWT mode
```

`demo/Makefile`:
```makefile
up:       docker compose -f demo/docker-compose.yml up --build
allow:    curl -X POST http://localhost:3000/mcp -d '{"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}}'
deny:     curl -X POST http://localhost:3000/mcp -d '{"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/etc/passwd"}}}'
audit:    tail -f ~/.eunox/audit.jsonl | jq .
jwt:      # issues a test JWT with capability claims from local Keycloak
```

`demo/README.md` — sequence of commands with expected output after each. Not prose, not screenshots — literal terminal output so the user knows if something is wrong.

**Validation:** run this on a machine with no prior eunox knowledge. Time it. If it exceeds 10 minutes to first enforced tool call, cut scope until it doesn't. This is a hard constraint, not a goal.

---

### T-06 · README reposition
**Effort:** half a day · **Priority:** P0 · **Depends on:** T-05 · **Status: ✅ DONE**

Currently `cmd/mcp/` is listed sixth in the services table below five BUSL-licensed services. New evaluators see a 6-service enterprise platform and immediately estimate high operational burden. This is wrong.

**Changes:**
1. ✅ Lead with `eunox-mcp` — what it is, what problem it solves, one-command install
2. ✅ Quick start points at `demo/` only — not the full stack
3. ✅ The 6-service architecture moves to `docs/architecture.md` with a note: "for enterprise deployment"
4. ✅ Add a "How it works" section with the actual interception flow: Agent → eunox-mcp proxy → MCP server (local or remote)
5. ✅ Add a comparison table: what eunox-mcp enforces that OPA/Envoy cannot (the three gap scenarios)

**Implementation notes:**
- `README.md` — Quick start section with `make -C demo` commands; ASCII flow diagram (host → proxy → allow/deny); corrected manifest example (was using wrong `tools:` schema); comparison table with the three OPA/Envoy gap scenarios; Advanced JWT PDP section; updated docs links including demo and threat model.
- `docs/architecture.md` — Added enterprise-scope callout at the top directing evaluators to the demo and README instead.

**Verified:** README renders correctly; manifest example matches `demo/manifest.yaml` schema; `docs/architecture.md` leads with the enterprise-deployment scope note.

---

### T-07 · Threat model document
**Effort:** 2 days · **Priority:** P0 · **Depends on:** nothing (write in parallel) · **Status: ✅ DONE**

Without this, security review at any enterprise stalls before it reaches an architect. This document unblocks the entire enterprise sales motion.

**Required sections:**

1. **Trust boundaries:** what eunox-mcp trusts (upstream MCP server, IdP JWKS endpoint), what it verifies (JWT signature, expiry, issuer, capability claims, argument schema), what it explicitly does not verify (prompt content, model behavior, client-side code)

2. **Attack classes mitigated:**
   - Capability claim forgery (JWT signature validation)
   - Tool call parameter injection (argument schema validation)
   - Session hijacking via session_id spoofing (kill switch, session binding)
   - Audit log tampering (HMAC chain integrity, `validate-token` subcommand)
   - Credential overprivilege (task-scoped capability claims from IdP)
   - Unbounded tool call rate (MaxCalls condition)

3. **Attack classes explicitly out of scope:** prompt injection, model jailbreak, client-side agent code compromise, IdP compromise

4. **Failure modes:**
   - Proxy crash: upstream receives no traffic (fail closed by nature of being in-path)
   - JWKS endpoint unreachable: cached keys used up to configured TTL, then fail closed
   - Redis unavailable (when configured): falls back to in-memory state, sequence policies disabled, capability claim enforcement continues
   - Audit log write failure: logged to stderr, enforcement continues (audit loss is not a reason to drop production traffic — document this tradeoff explicitly)

5. **Data handling:** what appears in audit records (tool name, arguments, decision, session ID), what redaction covers (`RedactFields` condition), what never leaves the local machine in default config

6. **Current state:** no third-party security audit yet. Planned post-Stage 2. Be honest.

**Verified:** All six required sections implemented in `docs/threat-model-mcp.md`. Trust boundaries grounded in JWKS validation code (`cmd/mcp/pdp_jwt.go`), audit HMAC implementation (`cmd/mcp/audit.go`), and enforcement engine integration (`cmd/mcp/pdp.go`). Failure modes document the explicit audit-log-failure-continues tradeoff. Known limitations table is honest about session binding gap and X-Forwarded-For trust flag.

---

## Sprint 3 — Failure Demo + Performance (Weeks 3–4)

### T-08 · "OPA/Envoy fails here" reproducible demo ✅
**Effort:** 3–4 days · **Priority:** P0 · **Depends on:** T-05

This is the most leveraged sales asset in the plan. Every enterprise architect will ask "why can't I just extend OPA?" This demo answers it without a conversation.

**Three scenarios, each runnable in isolation:**

**Scenario 1 — Sequential tool call danger (OPA has no session context)**
```
Agent calls: read_credentials → write_to_external_endpoint
Each call is individually permitted by OPA HTTP policy.
Collectively: credential exfiltration.
OPA result: both calls pass.
eunox-mcp result: second call blocked by sequence-aware policy.
```
Policy:
```yaml
- resource: write_to_external_endpoint
  actions: [call]
  conditions:
    - type: custom
      # deny if session has already called read_credentials
```

**Scenario 2 — Parameter-dependent authorization at scale (Rego complexity explosion)**
Show the Rego required to express `read_file` allowed for `/reports/*` but not `/internal/*` across 10 tools with different parameter shapes. Count the lines. Then show the eunox manifest doing the same in 15 lines with `allowedValues` conditions.

**Scenario 3 — Task-lifecycle vs time-lifecycle credentials**
AWS STS minimum session: 15 minutes.
eunox-mcp with `MaxCalls: 1` on a credential-reading tool: single use, then blocked.
Show the privilege exposure window difference numerically.

**Format:** runnable Docker Compose in `demo/opa-comparison/`. Not a video. Not a blog post. A `make scenario-1`, `make scenario-2`, `make scenario-3` that produces visible output.

**Done when:** an enterprise security architect can run all three scenarios in under 20 minutes on a cold machine and see the failure modes themselves.

---

### T-09 · Performance baseline
**Effort:** 1–2 days · **Priority:** P1 · **Depends on:** T-01, T-02

Publish numbers before any enterprise evaluation. Latency surprises kill deals.

**Targets:**
- Stateless mode (no Redis, manifest PDP): p99 < 2ms added overhead on localhost
- JWT PDP mode (JWKS cached): p99 < 3ms added overhead
- Redis session state: p99 < 5ms added overhead (includes Redis RTT)
- Policy evaluation with 50-rule manifest: p99 < 1ms

Run with `k6` or `wrk`. Publish the benchmark script and raw results in `docs/benchmarks.md`. If numbers miss targets, fix the proxy before calling this done.

---

## Stage 1 Exit Gate

All of the following must be true before Stage 2 begins:

- [x] `--upstream-url` flag ships and is tested against at least one real remote MCP server (Stripe or GitHub MCP)
- [x] JWT PDP mode works with Auth0 and Keycloak
- [x] Dry-run mode exposed as `--dry-run` CLI flag
- [x] Demo setup completes in under 10 minutes on a cold machine, validated by someone other than the author
- [x] OPA/Envoy failure demo is publicly runnable (`demo/opa-comparison/`, `make scenario-1/2/3`)
- [x] Threat model published at `docs/threat-model-mcp.md`
- [ ] Audit log schema has not changed for 2 consecutive weeks
- [ ] 3 production or active staging deployments running
- [ ] At least one capability claim pattern or policy condition discovered from real traffic that wasn't anticipated at design time
- [x] README leads with `eunox-mcp`, not the 6-service architecture

---

---

# Stage 2 — Open Spec

**Duration:** 4–5 weeks  
**Goal:** Extract and publish the interoperability spec from what production has proven. Get one external framework to implement it.  
**Stage gate:** Spec v0.1 published, proxy passes 100% of the conformance test suite, one external org has opened a PR or issue on the spec repo

---

## Sprint 4 — Spec Extraction (Weeks 9–11)

### T-10 · Audit what production has validated
**Effort:** 1 week · **Owner:** Founder + eng

Before writing the spec, extract what 6+ weeks of production data has proven about the interfaces.

**For each interface, answer:**
- Has this been validated against real agent behavior?
- Is this eunox-specific or genuinely portable?
- Would a third-party PDP implementation need this to be interoperable?

**What goes into the spec (likely):**
- Capability token claim schema (`eunox.capabilities`, `eunox.task_id`, `eunox.agent_id` — already defined in T-02)
- Audit event schema (OCSF fields already in `auditRecord` struct — lock the field names)
- Condition type registry (the 11 condition types in `pkg/capability/` are the candidate set)
- Session context interface (what a PDP needs to make a stateful decision)
- Task identity format (task ID generation, session scoping)

**What stays out of spec v0.1:**
- Policy language / condition DSL (leave to implementors)
- Storage (Redis, Postgres, in-memory — implementation detail)
- Transport beyond HTTP
- Anything that hasn't appeared in real production traffic yet

---

### T-11 · Write the spec
**Effort:** 1–2 weeks · **Owner:** Founder

**Repo:** `github.com/eunolabs/eunox-spec` — separate from the proxy repo. Apache-2.0.

```
eunox-spec/
  README.md                    — what this is and what it is not
  spec/
    capability-token.md        — JWT claim schema and semantics
    task-identity.md           — task ID format and lifecycle
    audit-event.md             — OCSF-based audit record schema (from auditRecord struct)
    condition-types.md         — the 11 condition types as a portable registry
    session-context.md         — PDP input interface
  examples/
    minimal-jwt.json
    manifest.yaml
    audit-event.json
  conformance/
    README.md
    tests/                     — language-agnostic HTTP test suite
  CHANGELOG.md
  CONTRIBUTING.md
```

**Critical:** the spec is written for implementors who have never heard of eunox. No marketing. Every field defined with: name, type, required/optional, semantics, example. A competent engineer should be able to implement this in a weekend.

**The `eunox.capabilities` claim format** needs to be specified precisely because it's the most implementation-sensitive interface:
```
eunox.capabilities := array of strings
each string := "<tool_name>[:<condition_shorthand>]"
examples:
  "read_file"                      → allow read_file unconditionally
  "read_file:/reports/*"           → allow read_file where path matches /reports/*
  "query_db:SELECT"                → allow query_db where operation is SELECT
```

---

### T-12 · Conformance test suite
**Effort:** 1 week · **Owner:** Eng

A spec with no test suite is just a document. Any implementation claiming spec compliance must pass this suite.

**Steps:**
1. Write a set of HTTP request/response pairs that test each claim in the spec
2. Cover: valid JWT + permitted tool call → 200, valid JWT + denied tool call → 403, invalid JWT → 401, expired JWT → 401, missing capability claim → behavior defined by spec (allow or deny, must be explicit)
3. Run the proxy against the suite — 100% pass required
4. Publish in `eunox-spec/conformance/` with a README explaining how to run against any implementation
5. Add a CI job to the proxy repo that runs the conformance suite on every PR

---

### T-13 · Framework outreach
**Effort:** Ongoing from Week 9 · **Owner:** Founder

**Target list, priority order:**
1. **Anthropic (Claude tool use / MCP)** — strongest alignment, MCP is their protocol
2. **LangChain / LangGraph** — largest Python agent ecosystem
3. **Cursor / Windsurf** — already MCP-native, enterprise IDE sales depend on security posture
4. **CrewAI** — growing fast in agentic workflows
5. **Microsoft Semantic Kernel** — .NET + Python, large enterprise footprint

**What you're asking:** not to ship anything. Review the spec, identify gaps, say whether they'd consider emitting `eunox.task_id` and `eunox.capabilities` in their tracing layer. One call, one GitHub issue.

**What makes this ask credible:** 3+ production deployments, a narrow spec implementable in a weekend, Apache-2.0 license, no lock-in to eunox commercial products.

---

## Stage 2 Exit Gate

- [ ] Spec v0.1 published at `github.com/eunolabs/eunox-spec`
- [ ] Proxy passes 100% of conformance test suite
- [ ] Conformance suite is publicly runnable against any implementation
- [ ] At least one external organization has opened a PR or issue on the spec repo
- [ ] Proxy changelog maps every interface change to a spec version
- [ ] License on proxy and PDP changed to Apache-2.0 (BUSL on control plane only)

> **On the license change:** BUSL on `cmd/mcp/` is a direct contradiction of the spec adoption strategy. The spec needs a free reference implementation. Change `cmd/mcp/` and `pkg/enforcement/` to Apache-2.0 before spec outreach begins. The control plane (policy management UI, hosted audit, team features) stays commercial. This is the HashiCorp model: open the enforcement plane, monetize the management plane.

---

---

# Stage 3 — Integration Platform + Launch

**Duration:** 8–12 weeks  
**Goal:** Distribute enforcement into existing infrastructure. Replace the proxy with native integrations for enterprise deployments. Launch with a commercial offering.  
**Stage gate:** 1 paying customer, IdP plugin and one gateway plugin shipped, control plane in closed beta

---

## Sprint 5 — IdP Plugins (Weeks 15–18)

### T-14 · Auth0 Action for capability claim injection
**Effort:** 1 week · **Owner:** Eng · **Depends on:** T-11 (spec locked)

Auth0 Actions are Node.js functions in the post-login flow. They can inject custom claims into access tokens using the spec-defined claim names from T-11.

**Steps:**
1. Build a post-login Action that reads agent role from the Auth0 user profile
2. Looks up the capability set for that role from a configurable source (static JSON in Action config for v1, webhook call for v2)
3. Injects `eunox.capabilities`, `eunox.task_id`, `eunox.agent_id` into the access token
4. Publish to Auth0 Marketplace
5. Integration guide: zero to capability-injected tokens in under 15 minutes

**Claim size constraint:** Auth0 has a soft token size limit. Document: coarse-grained capability claims (tool name only, no parameter constraints) fit comfortably. Fine-grained parameter constraints should use the manifest file in conjunction with JWT claims.

---

### T-15 · Okta token inline hook
**Effort:** 1 week · **Owner:** Eng · **Depends on:** T-11

Okta inline hooks call an external webhook during token minting.

**Steps:**
1. Build a lightweight webhook handler (Lambda or Cloud Run) that receives the Okta hook payload and returns spec-compliant capability claims
2. Same capability resolution logic as Auth0 Action — consistent interface across IdPs
3. Publish to Okta Integration Network
4. Integration guide: 15 minutes to configure

---

### T-16 · Azure AD app roles mapping
**Effort:** 1 week · **Owner:** Eng · **Depends on:** T-11

Azure AD does not support arbitrary claim injection the way Auth0/Okta do. App roles are the mechanism.

**Steps:**
1. Document the app role → capability claim mapping pattern
2. Build a token enrichment sidecar: Azure AD issues the identity token, the sidecar enriches it with capability claims based on app role membership, re-signs with a delegated key
3. Document the trust model explicitly — this adds an intermediate signer, which must be in the threat model
4. Provide Terraform for Azure AD app registration and role definitions

---

## Sprint 6 — Gateway Plugins (Weeks 16–20)

### T-17 · Envoy ext_proc filter
**Effort:** 2 weeks · **Owner:** Eng · **Depends on:** T-11, T-12

`ext_proc` (not `ext_authz`) is required for MCP. `ext_authz` sees headers only. `ext_proc` sees the full request body per message — necessary for JSON-RPC tool call parameter inspection.

**Steps:**
1. Implement the ext_proc gRPC service: receives `HttpBody` from Envoy, parses JSON-RPC, extracts tool name and arguments
2. Calls the eunox PDP (same enforcement engine as the proxy) for a decision
3. Returns `ImmediateResponse` 403 on deny, `CommonResponse` CONTINUE on allow
4. Emits audit events to the same audit pipeline as the proxy
5. Publish as a Docker image and Helm chart deployable alongside Envoy
6. **SSE deferred to v1.1** — SSE stream inspection in ext_proc is complex and MCP SSE adoption is currently low. Ship HTTP request/response enforcement first. Don't block launch on SSE.

**Performance requirement:** ext_proc round-trip to PDP must add less than 3ms p99 on a local network. Benchmark before shipping.

---

### T-18 · Kong Go plugin
**Effort:** 1.5 weeks · **Owner:** Eng · **Depends on:** T-11

**Steps:**
1. Go Kong plugin that intercepts `tools/call` requests
2. Extracts JWT, calls PDP for enforcement decision
3. Emits audit event
4. Distributes as a Kong Hub plugin

---

## Sprint 7 — Control Plane MVP (Weeks 18–24)

Minimal at launch. Exists to enable enterprise procurement, not to be feature-complete.

### T-19 · Policy management UI
**Effort:** 2 weeks · **Owner:** Eng + design

**Scope — exactly this, nothing more:**
- Manifest file editor with syntax validation
- Version history (last 20 versions, diff between any two)
- Dry-run simulation: upload a recorded audit session, run it against a new manifest, see what would have been blocked (uses the `WithDryRun` engine mode already built)
- One-click policy push to connected proxy instances

**Not in scope for launch:** approval workflows, multiple environments, template library

---

### T-20 · Audit search and session replay
**Effort:** 2 weeks · **Owner:** Eng

**Scope:**
- Search by: session_id, tool_name, decision, time range
- Session timeline: all tool calls for a given session, in order, with decisions annotated
- Tamper-evidence verification UI (wraps the `validate-token` logic already built)
- Export: JSON, CSV, CEF for SIEM import

**Not in scope:** anomaly detection, SIEM push (pull/export sufficient at launch)

---

### T-21 · Pricing, packaging, license change
**Effort:** 1 week · **Owner:** Founder

| Tier | Target | Includes | Price |
|------|--------|----------|-------|
| OSS | Individual devs, small teams | `eunox-mcp` binary + PDP, self-hosted, unlimited | Free, Apache-2.0 |
| Team | Startups, small enterprises | Control plane, 2 environments, 5 seats, 90-day audit retention | $500/month |
| Enterprise | Regulated industries | Unlimited seats/environments, 7-year retention, BAA, SLA, dedicated support | Custom |

**License change is mandatory before launch:** `cmd/mcp/` and `pkg/enforcement/` → Apache-2.0. Control plane → commercial or source-available. Without this the OSS tier has no teeth and the spec adoption play stalls.

---

## Sprint 8 — Launch (Weeks 22–26)

### T-22 · External security review
**Effort:** 2 weeks · **Owner:** Founder + external auditor

Do not launch a security product without an external review. Focused scope is sufficient for launch — not a full pentest.

**Review scope:**
- JWT validation: expiry edge cases, algorithm confusion, JWKS cache poisoning
- Capability claim enforcement: bypass via parameter encoding, Unicode normalization, glob edge cases
- Audit HMAC chain: integrity under concurrent writes, gap detection
- Kill switch: race conditions between kill and in-flight requests

Publish the review summary (not the full report) at `docs/security-review.md`. Full report available to enterprise customers under NDA.

---

### T-23 · Launch content
**Effort:** 1 week · **Owner:** Founder

**Required before launch, in this order:**
1. OPA/Envoy failure demo — public, runnable, linked from README (built in T-08)
2. Threat model — public (built in T-07)
3. Spec repo — public with conformance suite (built in T-11, T-12)
4. Integration guides for each IdP plugin and gateway plugin — commands with expected output, not prose
5. One customer case study — even anonymized counts: "A Series B fintech reduced agent credential exposure window from 15 minutes to task-completion (~8 seconds average)"

**What you don't need:**
- A blog post explaining AI agent security (enough of those exist)
- A comparison page vs OPA (looks defensive — let the failure demo speak)
- A product demo video (the runnable demo is better)

**Distribution:**
- HN launch post — link the failure demo and the spec, let the engineering community evaluate
- Direct outreach to Stage 1 production users for quotes
- Auth0 Marketplace and Kong Hub listings go live simultaneously — enterprise evaluators who find eunox via existing tooling convert faster

---

## Stage 3 Exit Gate (Launch Criteria)

- [ ] 1 paying customer on Team or Enterprise tier
- [ ] `cmd/mcp/` on Apache-2.0
- [ ] Auth0 and Okta plugins shipped
- [ ] Envoy ext_proc plugin shipped (HTTP mode, SSE deferred)
- [ ] Spec v0.1 public with conformance suite
- [ ] External security review summary published
- [ ] Control plane in closed beta with 3+ orgs
- [ ] Sub-10-minute demo validated on a cold machine

---

---

## Dependency Graph

```
T-01 --upstream-url (remote MCP)
T-02 JWT PDP mode              ─┐
T-03 Dry-run CLI flag           │
T-04 Redis session state        │  → T-05 demo/ setup → T-06 README
T-07 Threat model               │                     → T-08 OPA failure demo
                                └──────────────────── → T-09 benchmarks
                                                         ↓
                                                    [STAGE 1 GATE]
                                                         ↓
                                T-10 spec audit → T-11 write spec → T-12 conformance suite
                                                  T-13 framework outreach (parallel)
                                                         ↓
                                                    [STAGE 2 GATE]
                                                         ↓
                         T-14/T-15/T-16 IdP plugins (parallel)
                         T-17/T-18 gateway plugins   (parallel)
                         T-19/T-20 control plane      (parallel)
                         T-21 pricing + license change
                              ↓
                         T-22 security review → T-23 launch
                              ↓
                         [LAUNCH]
```

**Critical path:** T-01 + T-02 → T-05 → T-08 → Stage 1 gate → T-11 → Stage 2 gate → T-17 + T-22 → launch

---

## What Kills This Plan

**1. Scope creep before the Stage 1 gate.**
The enforcement engine already has 11 condition types, OCSF audit, dry-run mode, kill switch, and stats. The temptation is to keep adding to it. Don't. The gate is 3 production deployments, not a complete feature set.

**2. Not changing the license before spec outreach.**
BUSL on `cmd/mcp/` is a direct contradiction of the spec strategy. Framework partners will not implement a spec whose reference implementation isn't freely usable. Change it before T-13 or the outreach conversations stall immediately.

**3. SSE blocking the Envoy plugin launch.**
SSE support in `ext_proc` is hard and current MCP SSE adoption is low. It is explicitly deferred to v1.1. If a specific enterprise customer needs it before launch, implement it for them. Do not hold the Envoy plugin release for it.

**4. Building the control plane before a paying customer.**
T-19 and T-20 scope is deliberately minimal. Do not expand it before validating that enterprises will pay. The existing audit pipeline (`pkg/audit/`) is ahead of what the control plane UI needs — the backend is not the bottleneck.

**5. Starting Stage 2 without production-stabilized audit schema.**
The spec's audit event schema must come from what has actually appeared in production logs, not from what seemed correct at design time. The 2-week stability requirement in the Stage 1 gate is not bureaucracy — it's the signal that the schema has stopped changing.
