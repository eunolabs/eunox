# Euno Platform — Go Re-Implementation Execution Plan

> **License:** Business Source License (BSL 1.1)
> **Target:** Feature-parity with TypeScript euno-platform (enterprise product from day one)
> **Excluded:** MCP proxy MVP (the `@euno/mcp` local proxy package)

---

## Repository Layout (Target)

```
euno-go/
├── cmd/                          # Service entry points
│   ├── gateway/                  # Tool Gateway binary
│   ├── issuer/                   # Capability Issuer binary
│   ├── minter/                   # API-Key Minter binary
│   ├── db-token-svc/             # DB Token Service binary
│   ├── storage-grant-svc/        # Storage Grant Service binary
│   └── posture-emitter/          # Posture Emitter binary
├── internal/                     # Private application code
│   ├── gateway/                  # Gateway domain logic
│   ├── issuer/                   # Issuer domain logic
│   ├── minter/                   # Minter domain logic
│   ├── dbtokensvc/               # DB token service logic
│   ├── storagegrantsvc/          # Storage grant service logic
│   ├── posture/                  # Posture emitter logic
│   └── agentruntime/             # Agent runtime library
├── pkg/                          # Public importable packages
│   ├── capability/               # Token payload types, constraints, conditions
│   ├── config/                   # Schema-validated config loading (viper + custom)
│   ├── crypto/                   # Signing adapters (KMS, software, EdDSA)
│   ├── did/                      # DID resolver (did:web, did:ion, did:key)
│   ├── enforcement/              # Enforcement engine, condition registry
│   ├── audit/                    # Audit pipeline, evidence signer, OCSF transport
│   ├── identity/                 # Identity provider adapters (OIDC, Cognito, Azure AD, GCP)
│   ├── killswitch/               # Kill-switch manager interface + Redis impl
│   ├── callcounter/              # Call-counter store interface + Redis impl
│   ├── revocation/               # Token revocation store
│   ├── ratelimit/                # Rate-limiter abstractions
│   ├── federation/               # Partner DID registry, circuit breaker
│   ├── ocsf/                     # OCSF event types (class_uid 3003, 6003)
│   ├── transport/                # HTTP client helpers, retry, mTLS
│   ├── observability/            # Structured logging, Prometheus metrics, OTel tracing
│   └── testutil/                 # Shared test helpers, fixtures, mocks
├── api/                          # OpenAPI specs & generated types (oapi-codegen)
│   ├── gateway.yaml
│   ├── issuer.yaml
│   └── minter.yaml
├── migrations/                   # SQL migrations (github.com/golang-migrate/migrate/v4)
│   ├── audit/
│   └── minter/
├── deploy/                       # Deployment artifacts
│   ├── docker/                   # Multi-stage Dockerfiles
│   ├── helm/                     # Helm umbrella chart
│   ├── k8s/                      # Raw manifests, seccomp profiles, network policies
│   └── terraform/                # Cloud provisioning (AWS, Azure, GCP)
├── scripts/                      # Build, lint, CI helpers
├── docs/                         # Architecture, runbooks, threat models
├── go.mod
├── go.sum
└── Makefile
```

---

## Technology Choices

| Concern | Choice | Rationale |
|---------|--------|-----------|
| HTTP framework | `net/http` + `chi` router | Lightweight, stdlib-compatible, middleware composable |
| Config | `viper` + custom Zod-equivalent validator | Typed, env-based, fail-fast on boot |
| JWT/JWS | `go-jose/v4` (Square) | Full JOSE stack, KMS integration, JWK Sets |
| DID resolution | Custom (`pkg/did`) | Minimal dep surface; did:web is HTTP GET, did:key is decode |
| Database | `pgx/v5` (PostgreSQL), `go-redis/v9` | High-performance, connection pool, pipeline support |
| Migrations | `github.com/golang-migrate/migrate/v4` | SQL-first, embeddable, multi-source |
| Metrics | `prometheus/client_golang` | Industry standard, direct Prometheus exposition |
| Tracing | `go.opentelemetry.io/otel` | Vendor-neutral, W3C Trace Context propagation |
| Logging | `log/slog` (stdlib) | Structured, zero-alloc, handler composable |
| Testing | `testing` + `testify` + `testcontainers-go` | Stdlib + assertions + real infra in tests |
| Build | `Makefile` + `goreleaser` | Reproducible, cross-platform, multi-arch containers |
| Linting | `golangci-lint` | Unified lint runner (staticcheck, gosec, errcheck, etc.) |
| Code gen | `oapi-codegen` | Type-safe HTTP handlers from OpenAPI specs |
| Dependency injection | Constructor injection (no framework) | Explicit wiring; `main()` builds the dependency graph |

---

## Stage 1 — Foundation & Shared Libraries

**Goal:** Establish the Go module, shared packages, CI pipeline, and core type system.

### Deliverables

1. **Module initialization** — `go.mod`, directory structure, Makefile targets (`build`, `test`, `lint`, `generate`)
2. **`pkg/capability`** — Domain types:
   - `CapabilityTokenPayload` struct (mirrors JWT claims)
   - `CapabilityConstraint` struct
   - `CapabilityCondition` interface + all concrete condition types (discriminated via `Type() string`)
   - `Obligation` types (redactFields, requireFields)
   - `EnforceRequest` / `EnforceResponse` wire types
   - JSON marshaling with `type` discriminator for conditions
3. **`pkg/config`** — Configuration framework:
   - Struct-tag-based validation (required, min, max, regex, enum)
   - `LoadOrExit[T](prefix string)` generic loader
   - Per-service config structs (gateway, issuer, minter, etc.)
   - Production-mode super-validation (e.g., admin key length, pepper hex)
   - Structured error reporting on validation failure
4. **`pkg/crypto`** — Signing adapter interface:
   - `Signer` interface: `Sign(ctx, digest []byte) ([]byte, error)`, `Algorithm() string`, `KeyID() string`
   - `Verifier` interface: `Verify(ctx, digest, sig []byte) error`
   - Software signer (PEM-based RSA/EC/EdDSA)
   - AWS KMS signer stub (interface + constructor; cloud SDK wired in Stage 3)
   - Azure Key Vault signer stub
   - GCP Cloud KMS signer stub
5. **`pkg/observability`** — Logging, metrics, tracing bootstrap:
   - `slog` handler with JSON output + configurable level
   - Prometheus registry helper (counters, histograms, gauges)
   - OTel tracer provider factory
   - Middleware: request logging, metrics, trace propagation
6. **`pkg/testutil`** — Shared test infrastructure:
   - In-memory signer/verifier (deterministic keys for tests)
   - `testcontainers-go` helpers for PostgreSQL and Redis
   - HTTP test server factory
   - Clock interface + fake clock
7. **CI pipeline** — GitHub Actions:
   - `go vet`, `golangci-lint`, `go test -race -count=1`
   - Coverage threshold (80% for `pkg/`)
   - Multi-arch Docker build (linux/amd64, linux/arm64)
   - License header check (BSL)

### Exit Criteria

- [x] `make lint` passes with zero findings
- [x] `make test` passes; `pkg/capability` has 100% type coverage with round-trip JSON tests
- [x] `pkg/config` validates a sample gateway config and rejects invalid input with structured errors
- [x] `pkg/crypto` software signer signs + verifies a SHA-256 digest
- [x] CI pipeline runs green on `main` branch push
- [x] All source files carry BSL license header

---

## Stage 2 — Enforcement Engine & Tool Gateway (Core)

**Goal:** Implement the enforcement engine and gateway's public HTTP surface with in-memory backends.

### Deliverables

1. **`pkg/enforcement`** — Enforcement engine:
   - `Engine` struct with `ValidateAction(ctx, req EnforceRequest) (EnforceResponse, error)`
   - Condition registry: `RegisterCondition(name string, handler ConditionHandler)`
   - All condition handlers ported:
     - `timeWindow`, `ipRange`, `maxCalls`, `allowedOperations`, `allowedExtensions`, `allowedTables`, `recipientDomain`, `redactFields`, `policy`, `custom`
   - Argument validators (field, file-path, schema)
   - Action resolver (file-based + in-memory registry)
2. **`pkg/killswitch`** — Kill-switch manager:
   - `Manager` interface: `ShouldBlock(ctx, agentID, sessionID string) (bool, error)`
   - In-memory implementation (for single-replica / dev)
   - Redis implementation (pub/sub propagation, local cache)
3. **`pkg/callcounter`** — Call-counter store:
   - `Store` interface: `IncrementAndGet(ctx, key string, windowSec int) (int64, error)`
   - In-memory sliding-window implementation
   - Redis implementation (MULTI/EXEC atomic increment + TTL)
4. **`pkg/revocation`** — Revocation store:
   - `Store` interface: `IsRevoked(ctx, jti string) (bool, error)`, `Revoke(ctx, jti string, ttl time.Duration) error`
   - In-memory + Redis implementations
5. **`internal/gateway`** — Gateway HTTP application:
   - chi router with middleware stack: recovery, request-id, logging, metrics, CORS, rate-limit
   - `POST /api/v1/enforce` — hosted enforcement endpoint
   - `POST /api/v1/validate` — action validation endpoint
   - `ANY /proxy/*` — reverse proxy with enforcement pipeline
   - JWT verification middleware (JWKS-based, multi-issuer support)
   - DPoP proof verification (replay detection via revocation store)
   - Target-host canonicalization middleware
   - Response redaction middleware (for `redactFields` obligations)
   - Health endpoints: `/health/live`, `/health/ready`
6. **`cmd/gateway`** — Binary entry point:
   - Config loading via `pkg/config`
   - Dependency construction (in-memory backends for this stage)
   - Graceful shutdown (SIGTERM, drain connections)
   - Admin port listener (separate `net.Listener`, bind to `127.0.0.1`)

### Exit Criteria

- [x] `POST /api/v1/enforce` correctly evaluates all condition types against a valid JWT
- [x] `ANY /proxy/*` proxies requests to upstream after enforcement passes
- [x] Kill-switch blocks requests for killed agents/sessions/global
- [x] `maxCalls` condition correctly tracks and enforces call limits
- [x] DPoP replay detection rejects replayed proofs
- [x] JWT verification rejects expired, malformed, and untrusted tokens
- [x] Graceful shutdown drains in-flight requests within timeout
- [x] Benchmark: >10,000 enforce decisions/sec on single core (in-memory backends)
- [x] Integration tests cover: allow, deny (each condition type), kill-switch, revocation, proxy

---

## Stage 3 — Capability Issuer

**Goal:** Implement token issuance, attenuation, renewal, and identity provider integration.

### Deliverables

1. **`pkg/identity`** — Identity provider adapters:
   - `Provider` interface: `VerifyToken(ctx, token string) (UserContext, error)`
   - OIDC adapter (generic; works with any OIDC-compliant IdP)
   - AWS Cognito adapter (Cognito-specific claim mapping)
   - Azure AD / Entra ID adapter
   - GCP Cloud Identity adapter
   - DID-based identity (verify DID-Auth presentation)
2. **`internal/issuer`** — Issuer HTTP application:
   - `POST /api/v1/issue` — Capability token issuance:
     - Identity verification via configured provider
     - Role-to-capability policy lookup
     - Manifest intersection (requested ∩ policy ∩ manifest)
     - Condition validation (reject unknown condition types)
     - Token construction + signing (via `pkg/crypto` Signer)
   - `POST /api/v1/attenuate` — Token delegation:
     - Parent token verification
     - Subset invariant enforcement (child ⊆ parent)
     - `parentCapId` linkage
   - `POST /api/v1/renew` — Token renewal:
     - Verify existing token + OIDC re-auth
     - Same scope, extended expiry (capped by policy)
   - `GET /.well-known/jwks.json` — JWKS endpoint (public keys for verification)
   - `GET /.well-known/did.json` — DID document
   - `GET /.well-known/capability-issuer` — Discovery metadata
   - `GET /api/v1/public-key` — Legacy single-key endpoint
   - Role policy admin routes:
     - `POST /admin/role-policy/{role}`, `GET /admin/role-policy`
   - SCIM provisioning:
     - `POST /scim/v2/Users`, `POST /scim/v2/Groups`
3. **`internal/issuer/policy`** — Policy engine:
   - `RoleCapabilityPolicy` — JSON file-based role→capability mapping
   - Policy hot-reload (fsnotify or polling)
   - Manifest validation (schema + bounds check)
   - Consent validation (user authorization check)
   - PIM integration (cap exp ≤ pim.endDateTime − 30s)
4. **`cmd/issuer`** — Binary entry point:
   - Config loading, dependency wiring, graceful shutdown
   - Rate-limiting (per-subject issuance rate)
5. **Issuance rate-limiting** — Pluggable backend:
   - In-memory token bucket
   - Redis-backed distributed rate limiter

### Exit Criteria

- [x] `POST /api/v1/issue` mints a valid JWT verifiable by gateway's JWKS client
- [x] Role-to-capability mapping correctly narrows issued capabilities
- [x] Attenuation enforces strict subset invariant (deny if child > parent)
- [x] Renewal extends expiry without scope widening
- [x] OIDC adapter validates tokens against a test IdP (testcontainers or mock)
- [x] JWKS endpoint serves rotatable keys (add key → serve both → remove old)
- [x] DID document resolves correctly for `did:web`
- [x] Unknown condition types in requests produce 400 (fail-closed)
- [x] Integration test: full issuance → enforcement round-trip (issuer + gateway)
- [x] Rate-limiter rejects issuance bursts beyond configured threshold

---

## Stage 4 — API-Key Minter & Credential Services

**Goal:** Implement API key lifecycle management, anomaly detection, DB token minting, and storage grant minting.

### Deliverables

1. **`internal/minter`** — API-Key Minter HTTP application:
   - `POST /admin/v1/keys` — Mint new API key:
     - Generate random `keyId` + `secret`
     - Compute `secretHash` = base64url(HMAC-SHA256(key: pepper, message: secret))
     - Persist to store (PostgreSQL)
     - Return `sk-{keyId}.{secret}` (never stored in plaintext)
   - `DELETE /admin/v1/keys/{keyId}` — Revoke API key
   - `GET /admin/v1/keys` — List keys (metadata only, no secrets)
   - `POST /admin/v1/policies` — Create/update policies
   - `GET /admin/v1/policies` — List policies
   - `GET /api/v1/ping` — Key verification (rate-limited by IP)
   - Admin authentication:
     - JWT-based (`AdminJwtVerifier` — JWKS URI + audience)
     - X-Admin-Key fallback (deprecated, with warning log)
   - Anomaly detection:
     - Velocity tracking (mint rate per tenant)
     - Geo anomaly (optional, source-IP-based)
     - Redis-backed state
   - Operator audit trail (operatorId logged on all mutations)
2. **`internal/dbtokensvc`** — DB Token Service:
   - `POST /api/v1/db-tokens` — Mint short-lived DB credentials:
     - Verify JWT (issuer JWKS only)
     - Extract `db://` capabilities from token
     - Map capability → DB username (policy-based)
     - Call cloud IAM (AWS STS AssumeRole, Azure token, GCP OAuth2)
     - Return credentials with TTL (15–60 min)
   - Cloud adapter interface: `MintDBCredential(ctx, req) (Credential, error)`
   - AWS RDS IAM adapter
   - Azure SQL token adapter
   - GCP Cloud SQL IAM adapter
3. **`internal/storagegrantsvc`** — Storage Grant Service:
   - `POST /api/v1/storage-grants` — Mint storage credentials:
     - Verify JWT
     - Extract `storage://` capabilities
     - Generate presigned URL (S3), SAS token (Azure Blob), HMAC key (GCS)
     - Return grants with TTL
   - Cloud adapter interface: `MintStorageGrant(ctx, req) (Grant, error)`
   - AWS S3 presigned URL adapter
   - Azure Blob SAS adapter
   - GCP GCS HMAC/signed-URL adapter
4. **`cmd/minter`**, **`cmd/db-token-svc`**, **`cmd/storage-grant-svc`** — Binary entry points

### Exit Criteria

- [ ] API key mint→verify round-trip works (HMAC verification with pepper)
- [ ] Revoked keys return 403 on verify
- [ ] Anomaly detector flags velocity spikes (>N mints per window)
- [ ] Admin JWT auth validates against JWKS; X-Admin-Key works as fallback
- [ ] DB token service mints AWS RDS IAM token from a valid capability JWT (mock STS)
- [ ] Storage grant service generates valid S3 presigned URL structure (mock)
- [ ] All services reject tokens without matching capabilities (fail-closed)
- [ ] Pepper rotation: old keys still verify during transition period
- [ ] Integration test: minter → gateway enforcement (key-based auth flow)
- [ ] Rate-limiter on `/api/v1/ping` rejects abuse (per-IP)

---

## Stage 5 — Audit Pipeline & Cryptographic Evidence

**Goal:** Implement the full audit pipeline with cryptographic signing, PostgreSQL ledger, and OCSF export.

### Deliverables

1. **`pkg/audit`** — Audit pipeline:
   - `Pipeline` interface: `Append(ctx, entry AuditLogEntry) error`
   - `EvidenceSigner` — Signs audit entries with KMS/software key
   - `SignedAuditEvidence` struct (OCSF v1.1 format)
   - PostgreSQL ledger backend:
     - `PostgresLedgerBackend` — Global advisory lock (single-replica)
     - `PerReplicaPostgresLedgerBackend` — Lock-free per-replica chains (multi-replica)
   - HMAC chain integrity (each record signs over previous hash)
   - `AuditQueryStore` — Read-only projection (SELECT queries only)
2. **`pkg/ocsf`** — OCSF event types:
   - Authorization events (class_uid 3003): issuance, denial, revocation, attenuation
   - API Activity events (class_uid 6003): tool call allow/deny, validation, detail
   - SOC2 control mapping metadata
3. **Gateway audit routes**:
   - `GET /api/v1/audit/records` — Query audit log (paginated)
   - `GET /api/v1/audit/export` — Export signed OCSF records
   - `GET /api/v1/audit/signing-keys` — JWKS for evidence verification
   - `GET /api/v1/audit/chain-proof` — Cross-chain anchor proof
4. **OCSF transport** — Fan-out to SIEM sinks:
   - HTTP transport (Splunk HEC, generic webhook)
   - Azure Sentinel transport
   - Configurable batching + retry
5. **Cross-chain anchoring** (optional):
   - Azure Confidential Ledger anchor
   - S3 anchor (immutable object)
   - Periodic hash checkpoint to external ledger
6. **SQL migrations** — `migrations/audit/`:
   - Audit records table (append-only, no UPDATE/DELETE)
   - Chain hash index
   - Replica ID partitioning

### Exit Criteria

- [ ] Audit entries are cryptographically signed and verifiable offline
- [ ] HMAC chain detects tampering (modify one record → chain breaks)
- [ ] Per-replica backend scales linearly with replicas (no advisory lock contention)
- [ ] OCSF export produces valid v1.1 records with correct class/type UIDs
- [ ] Audit query store returns paginated results without write access
- [ ] SIEM transport delivers batched events with retry on failure
- [ ] Cross-chain anchor checkpoint verifiable against external ledger
- [ ] Integration test: enforcement decision → audit record → export → verify signature
- [ ] Performance: >5,000 audit appends/sec per replica (PostgreSQL benchmark)

---

## Stage 6 — Admin API & Operational Controls

**Goal:** Implement the full admin API surface for operational control of the gateway.

### Deliverables

1. **Gateway admin routes** (port 3003, bound to `127.0.0.1`):
   - Kill-switch management:
     - `POST /admin/kill-switch/global/activate|deactivate`
     - `POST /admin/kill-switch/agent/{agentId}/kill|revive`
     - `POST /admin/kill-switch/session/{sessionId}/kill|revive`
     - `POST /admin/kill-switch/reset`
     - `GET /admin/kill-switch/status`
   - Token revocation:
     - `POST /admin/revoke/{jti}`
     - `GET /admin/revocation/status`
   - Usage metering:
     - `GET /admin/usage`
     - `POST /admin/usage/reset`
   - Partner DID management:
     - `POST /admin/partner-dids` — Register trusted partner
     - `DELETE /admin/partner-dids/{did}` — Unregister partner
     - `GET /admin/partner-dids` — List partners
     - `POST /admin/partner-dids/{did}/approve|revoke|refresh`
2. **Admin authentication & authorization**:
   - `X-Admin-Api-Key` header (timing-safe comparison)
   - Per-tenant isolation (`tenantId` from key → scope all reads)
   - `acknowledgesCrossTenantImpact: true` required for global kill
   - Idempotency store (`Idempotency-Key` header, 24h cache)
3. **OCSF audit for admin actions**:
   - Every mutating admin action emits `OcsfAuthorizationEvent` (class_uid 3003)
   - `operatorId` extracted from admin JWT or key identity
4. **Gateway telemetry collector**:
   - Per-tenant opt-out (`EUNO_TELEMETRY=0`)
   - 5-minute flush interval (configurable)
   - JSON event schema matching TypeScript version

### Exit Criteria

- [ ] Kill-switch activations propagate to all gateway replicas within 1s (Redis pub/sub)
- [ ] Admin API rejects requests without valid admin key (timing-safe)
- [ ] Tenant isolation: admin key A cannot access tenant B's data
- [ ] Cross-tenant operations require explicit acknowledgment
- [ ] Idempotency-Key prevents duplicate mutations (24h window)
- [ ] All admin mutations produce OCSF audit events
- [ ] Partner DID CRUD operations work end-to-end with DID resolution
- [ ] Integration test: kill agent → enforcement rejects → revive → enforcement allows

---

## Stage 7 — Partner Federation & DID Resolution

**Goal:** Implement cross-organization trust via W3C DIDs with circuit-breaker resilience.

### Deliverables

1. **`pkg/did`** — DID resolver:
   - `Resolver` interface: `Resolve(ctx, did string) (Document, error)`
   - `did:web` resolver (HTTP GET `/.well-known/did.json` at domain)
   - `did:ion` resolver (Microsoft ION network, configurable endpoint)
   - `did:key` resolver (decode key material from DID URI)
   - Document parsing: extract `verificationMethod` public keys
   - Resolution caching (TTL-based, configurable)
2. **`pkg/federation`** — Partner federation:
   - `PartnerDIDRegistry` — CRUD for trusted partner DIDs
   - `PartnerIssuerResolver` — Resolve partner issuer → public key
   - Circuit breaker per DID method:
     - Configurable failure threshold, cooldown, half-open probe
     - Prometheus gauge: `euno_partner_did_circuit_breaker_state{did,state}`
   - Fail-closed: open circuit → reject partner tokens
3. **Gateway JWT verifier extension**:
   - Multi-issuer support: local issuer IDs + trusted partner DIDs
   - Partner token verification: resolve DID → extract key → verify JWT
   - Cross-org audit annotation (`crossOrg: true`, `partnerDID`)
4. **Token attenuation across orgs**:
   - Parent token from partner → child token from local issuer
   - Subset invariant enforcement across trust boundaries
5. **Health endpoint**: `GET /healthz/did-ion` — DID ION resolver status

### Exit Criteria

- [ ] `did:web` resolution fetches and parses a DID document over HTTP
- [ ] `did:ion` resolution queries ION network with circuit breaker
- [ ] `did:key` decodes Ed25519/P-256 keys from DID URI
- [ ] Circuit breaker opens after N consecutive failures, rejects during cooldown
- [ ] Circuit breaker transitions to half-open and recovers on success
- [ ] Partner JWT verified end-to-end (register DID → present token → enforcement passes)
- [ ] Cross-org audit entries correctly annotated
- [ ] Attenuation across orgs enforces subset invariant
- [ ] Integration test: partner-issuer-sim → gateway acceptance/rejection cycle
- [ ] Prometheus metrics expose circuit breaker state

---

## Stage 8 — Posture Emitter & Cloud CSPM Integration

**Goal:** Implement the posture emitter service for AI asset inventory reporting to cloud security platforms.

### Deliverables

1. **`internal/posture`** — Posture emitter service:
   - Durable queue (SQLite WAL for single-writer guarantee)
   - `AgentInventoryRecord` emission on issuance/renewal/revocation
   - Configurable flush interval
   - Plugin architecture for CSPM backends:
     - `PosturePlugin` interface: `Emit(ctx, records []AgentInventoryRecord) error`
     - Microsoft Defender CSPM plugin
     - AWS Security Hub plugin
     - GCP Security Command Center plugin
   - Retry with exponential backoff
   - Dead-letter handling for persistent failures
2. **`cmd/posture-emitter`** — Binary entry point:
   - Single-replica deployment (SQLite constraint)
   - Health check reflecting queue depth
3. **Integration with issuer**:
   - Issuer calls posture emitter synchronously (< 1ms via local queue)
   - Emit before HTTP response (transactional posture)

### Exit Criteria

- [ ] Posture records durably queued (survive process restart)
- [ ] Each CSPM plugin correctly formats and delivers records
- [ ] Retry logic handles transient cloud API failures
- [ ] Dead-letter captures records after max retries
- [ ] Queue depth exposed as Prometheus metric
- [ ] Single-writer invariant enforced (second instance fails to start)
- [ ] Integration test: issue token → posture record in queue → plugin delivery

---

## Stage 9 — Agent Runtime Library

**Goal:** Implement the agent runtime as a Go library for embedding in agent applications.

### Deliverables

1. **`internal/agentruntime`** — Agent runtime library:
   - `Runtime` struct: manages token lifecycle, tool invocation
   - `AuthTokenProvider` — Acquires/refreshes capability tokens from issuer
   - `IssuanceHintsProvider` — Supplies context for token requests
   - `ToolInvoker` — Routes tool calls through gateway enforcement
   - DPoP proof generation (key-pair management, nonce handling)
   - Token caching with proactive refresh (before expiry)
   - Retry with backoff on transient failures
2. **Framework adapters** (in `internal/agentruntime/adapters/`):
   - Generic HTTP adapter (any REST-based tool)
   - LangChain-compatible interface (Go LangChain ecosystem)
   - Generic function-call adapter
3. **Manifest declaration**:
   - `AgentCapabilityManifest` builder
   - Manifest validation (client-side, before issuance request)

### Exit Criteria

- [ ] Runtime acquires token from issuer and caches it
- [ ] Token refresh occurs before expiry (proactive)
- [ ] DPoP proofs generated correctly and accepted by gateway
- [ ] Tool invocation routes through gateway with proper auth headers
- [ ] Manifest builder produces valid manifests accepted by issuer
- [ ] Integration test: runtime → issuer → gateway → mock upstream (full loop)

---

## Stage 10 — Deployment, Hardening & Production Readiness

**Goal:** Production-grade deployment artifacts, security hardening, and operational tooling.

### Deliverables

1. **Docker images** (multi-stage, distroless base):
   - One image per service (6 images)
   - Non-root user (UID 1000)
   - Read-only filesystem
   - No shell, no package manager in final image
   - Air-gap image list (`deploy/k8s/air-gap-images.txt`)
2. **Helm umbrella chart** (`deploy/helm/euno/`):
   - Per-service sub-charts with values inheritance
   - Cloud-specific value overlays (AWS, Azure, GCP)
   - Pod Security Standards (restricted)
   - Network policies (default-deny + explicit allow)
   - Seccomp profiles
   - HPA (Horizontal Pod Autoscaler) for gateway
   - PDB (Pod Disruption Budget) for availability
3. **Production Redis HA enforcement**:
   - Boot-time validation: reject single-node Redis URLs in production
   - Redis Sentinel or Redis Cluster required
4. **TLS configuration**:
   - mTLS for inter-service communication
   - TLS termination configuration for ingress
   - Certificate rotation support
5. **Graceful lifecycle management**:
   - PreStop hooks for connection draining
   - Readiness gate for rolling updates
   - Startup probes for slow-starting services
6. **Operational runbooks**:
   - Incident response (kill-switch activation)
   - Key rotation procedures
   - Disaster recovery (audit ledger restore)
   - Capacity planning guidelines
7. **Performance validation**:
   - Load test harness (k6 or vegeta)
   - SLO targets:
     - Enforcement latency: p99 < 10ms (in-memory), p99 < 25ms (Redis)
     - Issuance latency: p99 < 50ms (software signer), p99 < 200ms (KMS)
     - Audit append: p99 < 15ms (per-replica Postgres)
   - Chaos engineering scenarios (Redis failure, Postgres failover)

### Exit Criteria

- [ ] All 6 Docker images build and pass `trivy` vulnerability scan (zero critical/high)
- [ ] Helm chart deploys full stack to a fresh K8s cluster (kind or EKS)
- [ ] Pod Security Standards enforced (no privileged containers)
- [ ] Network policies block unauthorized inter-service traffic
- [ ] Production config validation rejects insecure configurations
- [ ] Load test achieves SLO targets under sustained load (30 min)
- [ ] Chaos test: Redis failure → graceful degradation (in-memory fallback where safe)
- [ ] Chaos test: Postgres failover → audit pipeline recovers without data loss
- [ ] Air-gap deployment works with pre-pulled images (no internet required)
- [ ] All operational runbooks reviewed and tested in staging

---

## Stage 11 — Integration Testing & Parity Verification

**Goal:** Comprehensive integration test suite ensuring behavioral parity with the TypeScript implementation.

### Deliverables

1. **Integration test suite** (`tests/integration/`):
   - Full issuance → enforcement round-trip
   - Cross-service contract tests (issuer ↔ gateway ↔ minter)
   - SOC2 audit export verification
   - DB token and storage grant minting
   - JWKS rotation and key rollover
   - Cross-org federation (partner DID trust)
   - Manifest enforcement (bounds checking)
   - All condition types exercised
   - Kill-switch propagation timing
   - Rate-limiting behavior
   - DPoP replay detection
   - Anomaly detection triggers
2. **Wire-protocol parity tests**:
   - JSON request/response fixtures from TypeScript test suite
   - Verify Go services produce identical wire output for identical input
   - OpenAPI spec compliance (request validation, response shape)
3. **Performance regression tests**:
   - Benchmark suite with baseline thresholds
   - CI gate: fail if p99 regresses >20% from baseline
4. **Upgrade/migration tests**:
   - Database schema migration forward/backward
   - Config format compatibility (env vars identical to TypeScript version)
   - API version negotiation

### Exit Criteria

- [ ] All integration test categories pass in CI
- [ ] Wire-protocol parity: Go and TypeScript produce identical JSON for shared test fixtures
- [ ] OpenAPI spec validation passes for all endpoints
- [ ] No performance regression from established baselines
- [ ] Database migrations apply cleanly to fresh and existing schemas
- [ ] Environment variable names match TypeScript version (drop-in config compatibility)
- [ ] Complete test coverage matrix documented

---

## Stage 12 — Documentation & Release

**Goal:** Complete documentation, release automation, and handoff.

### Deliverables

1. **Architecture documentation**:
   - Go-specific architecture decisions (ADRs)
   - Package dependency diagram
   - Sequence diagrams for key flows (issuance, enforcement, audit)
   - Interface catalog (all public `pkg/` interfaces)
2. **Operator documentation**:
   - Deployment guide (EKS, GKE, AKS, bare-metal)
   - Configuration reference (all env vars, organized by service)
   - Upgrade guide (from TypeScript version)
   - Troubleshooting guide
3. **Developer documentation**:
   - Contributing guide
   - Local development setup
   - Testing guide (unit, integration, e2e)
   - Code generation workflow (OpenAPI → Go types)
4. **Release automation**:
   - Semantic versioning via git tags
   - `goreleaser` config (multi-arch binaries + Docker images)
   - Changelog generation
   - Container registry push (GHCR + ECR/ACR/GCR)
5. **License**:
   - BSL 1.1 license file
   - License headers in all source files
   - Third-party license attribution (NOTICE file)

### Exit Criteria

- [ ] All public interfaces documented with godoc comments
- [ ] Deployment guide tested on fresh cluster (EKS or GKE)
- [ ] Configuration reference covers all environment variables
- [ ] `goreleaser` produces tagged release with binaries + images
- [ ] NOTICE file lists all transitive dependencies with licenses
- [ ] README provides quick-start for both dev and production deployment

---

## Cross-Cutting Concerns (All Stages)

### Security Principles
- **Zero-trust:** Every inter-service call carries verifiable identity
- **Fail-closed:** Unknown conditions, schemas, or issuers → reject
- **Least privilege:** Services hold only the keys they need (issuer signs, gateway verifies)
- **Defense in depth:** Network policies + application auth + audit

### Go Idioms to Enforce
- **Explicit error handling:** No panics in library code; `error` returns everywhere
- **Context propagation:** All I/O functions accept `context.Context` as first arg
- **Interface segregation:** Small interfaces (1-3 methods); compose via embedding
- **Constructor injection:** No global state; `main()` wires the graph
- **Table-driven tests:** Shared test fixtures, subtests with `t.Run()`
- **No init() abuse:** Configuration happens explicitly in `main()`

### Migration Strategy (TypeScript → Go)
1. Deploy Go services alongside TypeScript (shadow mode)
2. Compare responses for identical requests (parity verification)
3. Gradually shift traffic (canary → 10% → 50% → 100%)
4. Maintain env-var compatibility (same config, same behavior)
5. Decommission TypeScript services after full parity confirmed

---

## Timeline Dependencies

```
Stage 1 ─────────────────► Stage 2 ─────────────────► Stage 5
  (Foundation)               (Gateway Core)             (Audit)
       │                          │                        │
       │                          ▼                        ▼
       │                     Stage 3 ────────────────► Stage 6
       │                     (Issuer)                   (Admin API)
       │                          │                        │
       │                          ▼                        ▼
       │                     Stage 4                   Stage 7
       │                     (Minter + Creds)          (Federation)
       │                                                   │
       │                                                   ▼
       │                                              Stage 8
       │                                              (Posture)
       │
       └──────────────────────────────────────────► Stage 9
                                                    (Agent Runtime)

Stage 10 requires: Stages 2-9 complete
Stage 11 requires: Stages 2-9 complete
Stage 12 requires: Stage 10 + 11 complete
```

**Parallelization opportunities:**
- Stages 3 + 4 can proceed in parallel after Stage 2
- Stages 5 + 6 + 7 can proceed in parallel after Stage 3
- Stage 8 can proceed after Stage 3
- Stage 9 can proceed after Stage 2
- Stages 10 + 11 can proceed in parallel once all services exist
