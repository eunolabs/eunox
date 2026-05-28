# eunox — Architecture Overview

> **Status:** ✅ Reflects the current two-folder workspace layout as of May 2026.
>
> This document is the consolidated architecture reference for eunox
> _as implemented in this repository_. It complements (not replaces):
>
> - [`diagrams.md`](./diagrams.md) — abstract / engineering / executive
>   diagram set framed around the **design pattern** (capability-native
>   agent governance), not this specific code base.
> - [`diagrams.md`](./diagrams.md) — AGT (semantic guard) ↔ gateway
>   (cryptographic guard) interaction diagrams (Set D).
> - [`capability-model.md`](./capability-model.md) — gap analysis &
>   security model rationale.
> - [`enforcement.md`](./enforcement.md) — why the gateway is the PDP.
>
> Where a diagram in this file conflicts with the older abstract
> diagrams, **this file is authoritative for the implementation**;
> older docs remain authoritative for the conceptual / pattern view.

---

## 1. System purpose, in one paragraph

eunox is a **capability-native zero-trust governance plane for AI
agents**. Every agent action is mediated by a cryptographically
verifiable, time-limited capability token issued by a central
**Capability Issuer**, attenuated as it flows through delegation
chains, and enforced by a **Tool Gateway** that acts as the reference
monitor in front of every protected backend. The gateway emits signed
audit evidence to a SIEM, and an out-of-band **kill switch** /
revocation list lets operators cut off any agent, session, or token in
seconds. The whole control plane is cloud-portable through pluggable
identity-provider and signer adapters (Azure AD + Key Vault,
AWS Cognito + KMS, GCP Cloud Identity + Cloud KMS, W3C DID + DID-bound
keys).

---

## 2. C4 Level 1 — System context

```mermaid
flowchart LR
    User["Human user / agent owner"]
    Admin["Operator / Incident responder"]
    Agent["AI Agent (LangChain / MAF / CrewAI)"]
    Backend["Protected backends (CRM, files, SQL, S3, Kafka, ...)"]
    SIEM["SIEM (Azure Sentinel / Splunk / OCSF sink)"]
    IdP["Enterprise IdP (Entra ID / Cognito / GCP Cloud Identity)"]
    KMS["KMS / HSM (Key Vault / AWS KMS / GCP Cloud KMS)"]
    PartnerIssuer["Partner Capability Issuer (cross-org)"]

    eunox(("eunox control + data plane"))

    User -->|Authenticate, request agent| eunox
    Admin -->|Kill switch / revoke / policy| eunox
    Agent -->|Tool calls + capability token| eunox
    eunox -->|Authorized requests| Backend
    eunox -->|Signed audit events| SIEM
    eunox -->|OIDC validation| IdP
    eunox -->|Sign / verify| KMS
    PartnerIssuer -.->|DID-resolvable signing key| eunox
```

**External actors and systems**

| Actor / system           | Role                                                                              |
| ------------------------ | --------------------------------------------------------------------------------- |
| Human user / agent owner | Authenticates via OIDC, optionally provides a `UserConsent` record per agent      |
| Operator                 | Drives the Admin API on the gateway; owns kill-switch & revocation                |
| AI agent                 | Runs inside `agent-runtime`; framework code is wrapped by `framework-adapters`    |
| Protected backend        | Sits behind the Tool Gateway proxy; no direct network path from the agent runtime |
| Enterprise IdP           | OIDC issuer; identity providers map IdP claims → `UserContext` + role set         |
| KMS / HSM                | Holds the private signing key; only digests cross the boundary                    |
| Partner issuer           | Foreign capability issuer trusted via a DID document (cross-org federation)       |
| SIEM                     | Sink for the gateway's signed audit events and Sentinel analytic-rule firings     |

---

## 3. C4 Level 2 — Container / package view

The repository is a Go codebase rooted at:
`cmd/` (service entrypoints), `internal/` (service implementations),
`pkg/` (shared libraries), and `migrations/` (database migrations).

```mermaid
flowchart TB
    subgraph ControlPlane["Control plane (issuance & policy)"]
        Issuer["issuer service<br/>Go HTTP service<br/>:3001"]
        PostureEmitter["posture emitter<br/>Go service"]
    end

    subgraph DataPlane["Data plane (every agent action passes here)"]
        Gateway["gateway service<br/>Go HTTP service<br/>:3002"]
        Runtime["agentruntime<br/>(library)"]
        Adapters["SDK/tool adapters"]
    end

    subgraph Shared["Shared platform"]
        CommonCore["pkg/* shared libs<br/>capability, config,<br/>audit, identity"]
        CommonInfra["internal/* services<br/>gateway, issuer,<br/>minter, posture"]
        CLI["cmd/* binaries"]
        MCP["client integrations"]
    end

    subgraph External["External (per env)"]
        IdP["IdP adapters:<br/>azure-identity-provider<br/>aws-cognito-identity-provider<br/>gcp-identity-provider<br/>did-identity-provider"]
        Signer["Signer adapters:<br/>azure-signer (Key Vault)<br/>aws-kms-signer<br/>gcp-cloudkms-signer<br/>did-signer"]
        Resolver["did-resolver<br/>did:web / did:ion / did:key"]
        Redis["Redis<br/>(kill-switch,<br/>revocation,<br/>call counters)"]
        Backend["Protected backends"]
    end

    subgraph Tests["Verification"]
        Integ["integration-tests<br/>issuer ↔ gateway ↔ runtime"]
        PartnerSim["partner-issuer-sim<br/>cross-org test fixture"]
    end

    Adapters --> Runtime
    Runtime --> Issuer
    Runtime --> Gateway
    Issuer --> IdP
    Issuer --> Signer
    Issuer --> PostureEmitter
    Gateway --> Resolver
    Gateway --> Redis
    Gateway --> Backend
    Issuer --> CommonCore
    Gateway --> CommonCore
    Runtime --> CommonCore
    Adapters --> CommonCore
    CLI --> CommonCore
    MCP --> CommonCore
    CommonInfra --> CommonCore
    Issuer --> CommonInfra
    Gateway --> CommonInfra
    Integ --> Issuer
    Integ --> Gateway
    Integ --> Runtime
    PartnerSim --> Gateway
```

### Package responsibilities (as implemented)

| Package                    | LOC (approx)        | Public surface                                                                                                                        |
| -------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `pkg/`                     | shared libraries    | Capability contracts and enforcement types, config loading/validation, audit helpers, identity/signing support, and common utilities. |
| `cmd/`                     | service entrypoints | Executable entrypoints for gateway, issuer, minter, DB token service, storage grant service, and posture emitter.                     |
| `internal/issuer`          | service package     | Issuer HTTP handlers and issuance logic.                                                                                              |
| `internal/gateway`         | service package     | Gateway HTTP handlers, enforcement path, and admin APIs.                                                                              |
| `internal/agentruntime`    | runtime library     | Runtime-side request types and tool invocation plumbing.                                                                              |
| `internal/minter`          | service package     | API key minter admin/user APIs and persistence integration.                                                                           |
| `internal/dbtokensvc`      | service package     | Database token service handlers and auth flow.                                                                                        |
| `internal/storagegrantsvc` | service package     | Storage grant service handlers and provider integrations.                                                                             |
| `internal/posture`         | service package     | Posture emitter and plugin integrations.                                                                                              |
| `migrations/`              | schema migrations   | Database migration files used by services that own SQL backends.                                                                      |

The `Makefile` at the repository root provides the canonical `build`, `test`,
`lint`, `coverage`, and `clean` targets. License-boundary enforcement runs via
`make check-license`.

---

## 4. C4 Level 3 — Internal structure of the two services

### 4.1 Capability Issuer (`internal/issuer/`)

```mermaid
flowchart LR
    HTTP["cmd/issuer/main.go<br/>(net/http, chi, rate-limit)"]
    Service["internal/issuer/app.go<br/>IssuerApp"]
    PolicyMap["internal/issuer/policy/<br/>(role mapping)"]
    CondReg["pkg/capability/condition.go<br/>(condition types)"]
    Validators["pkg/capability/validate.go<br/>(condition validation)"]
    Manifests["AgentCapabilityManifest<br/>(declarative upper bound)"]
    Consent["UserConsent record<br/>(REQUIRE_USER_CONSENT)"]
    PIM["Privileged Identity Mgmt<br/>(role-active check)"]
    IDP["IdentityProvider<br/>(pkg/identity/)"]
    SIGN["TokenSigner<br/>(pkg/crypto/signer.go)"]
    DID["pkg/did/resolver.go"]
    SG["storage-grant/<br/>(STS token mint)"]
    DBT["db-token/<br/>(IAM DB cred mint)"]
    POST["PostureEmitter (optional)"]

    HTTP --> Service
    Service --> IDP
    Service --> PolicyMap
    Service --> CondReg
    Service --> Validators
    Service --> Manifests
    Service --> Consent
    Service --> PIM
    Service --> SIGN
    Service --> SG
    Service --> DBT
    Service --> POST
    HTTP --> DID
```

Notable design choices visible in the code:

- **Discriminated-union conditions** (`CapabilityCondition` in
  `pkg/capability/condition.go`) are validated _at mint time_ by
  `validateConditions(...)` — unknown `type` ⇒ hard reject. No
  fail-open path.
- **Action type widened to `string`** (`Action = string`) so tokens can
  carry resource-specific verbs (`db:select`, `s3:putObject`) while the
  `LEGACY_ACTIONS` tuple keeps the original five generic verbs
  meaningful for role mapping. Conditional-Access tiering (the
  former `actionToCaTier` heuristic) is now driven by the pluggable
  **`ActionResolver`** in `pkg/enforcement`; the default resolver
  ships an explicit per-verb table and operators ship a JSON file via
  `ACTION_RESOLVER_FILE` to extend it for deployment-specific verbs
  without modifying source.
- **Consent gate** (`requireConsent: boolean` + `SENSITIVE_ACTIONS` set
  for `write|delete|admin`) — in strict mode the issuer refuses to mint
  any sensitive capability without a validated `UserConsent` payload.
- **PIM cap on TTL** — `PIM_TTL_SAFETY_MARGIN_SECONDS = 30` clips token
  expiry to `min(requested_exp, PIM_endDateTime − 30s)` so a JIT role
  expiry always wins over a longer-lived capability.
- **Schema version is mandatory** — `capability.SchemaVersion = "1.0"`;
  gateways reject anything not in `capability.SupportedSchemaVersions`
  (fail-closed evolution).
- **JWKS endpoint** — `GET /.well-known/jwks.json` exposes the
  active signing key(s) as a standards-compliant JWK Set. Every minted
  token carries a `kid` in its JWS protected header that matches one of
  the published keys, enabling **key rotation without a synchronised
  restart**: add key 2 → wait one cache TTL → switch signing to key 2
  → wait one TTL → remove key 1. The legacy `GET /api/v1/public-key`
  endpoint remains operational (returns the active key's SPKI PEM with
  a `Deprecation` response header) for one deprecation cycle.

### 4.2 Tool Gateway (`internal/gateway/`)

```mermaid
flowchart LR
    HTTP["cmd/gateway/main.go<br/>(net/http, chi, CORS,<br/>rate-limit, /proxy/*)"]
    Verifier["internal/gateway/jwt.go<br/>JWTVerifier"]
    Engine["pkg/enforcement/engine.go<br/>Engine"]
    Admin["internal/gateway/admin.go<br/>kill switch + revoke"]
    Rev["pkg/revocation/<br/>(memory or Redis)"]
    Partner["internal/gateway/partner_verifier.go<br/>cross-org trust"]
    KS["pkg/killswitch/<br/>(in-mem / Redis)"]
    CCS["pkg/callcounter/<br/>(in-mem / Redis)"]
    EV["pkg/audit/audit.go<br/>EvidenceSigner"]
    Cond["enforceConditions()<br/>(pkg/capability/condition.go)"]
    Args["validateArguments()<br/>(pkg/capability/validate.go)"]
    Audit["pkg/audit/audit.go<br/>AuditLogEntry"]

    HTTP --> Admin
    HTTP --> Verifier
    HTTP --> Engine
    Verifier --> Partner
    Verifier --> Rev
    Engine --> KS
    Engine --> Cond
    Engine --> Args
    Engine --> CCS
    Engine --> EV
    Engine --> Audit
```

Notable design choices visible in the code:

- **Resource canonicalisation** in `createTargetHostCanonicalizeMiddleware` +
  `createValidateCapabilityMiddleware` (`internal/gateway/handlers.go`): the gateway
  derives the protected resource as `api://{host}/{tail}` **exclusively from
  the URL path** using a two-middleware pipeline:
  1. `createTargetHostCanonicalizeMiddleware` (strip-and-rewrite) — runs
     first and unconditionally strips any incoming `X-Target-Host` header,
     then rewrites it from the first URL-path segment if that segment
     matches the host pattern. This ensures the header is always
     path-canonical and never a client-controlled value, even if a
     misconfigured or malicious L7 hop (ingress, service mesh, sidecar)
     forwarded the header without overwriting it. A `warn` is emitted when
     the stripped value differed from the path-derived one.
  2. `createValidateCapabilityMiddleware` — reads `X-Target-Host` (now
     guaranteed path-derived) to construct the `api://` resource URI for
     capability enforcement; a residual mismatch check remains as
     defense-in-depth for callers that bypass the canonicalize middleware.
     The Envoy shard router additionally strips `x-target-host` from incoming
     requests (`k8s/envoy-shard-router.yaml`) before they reach the gateway,
     providing a second enforcement point at the ingress layer.
- **HTTP-method → action mapping** is supplied by the pluggable
  `ActionResolver` in `pkg/enforcement`. The built-in default
  preserves the legacy table (`GET→read`, `POST/PUT/PATCH→write`,
  `DELETE→delete`); deployments override it by pointing the gateway
  at an `ACTION_RESOLVER_FILE` JSON config — the same file the issuer
  consumes for CA tiering, so mint-time and enforcement-time action
  vocabularies stay aligned.
- **Fail-closed cryptographic audit** — `ENABLE_CRYPTOGRAPHIC_AUDIT=true`
  refuses to start without a configured `EvidenceSigner` (`pkg/audit/audit.go`).
  No silent unsigned audit.
- **Distributed by env var** — when `REDIS_URL` is set, kill-switch,
  revocation list, and call-counter store are upgraded from in-process
  to Redis-backed; in-process is dev-only.

---

## 5. Dataflow diagrams

### 5.1 DFD-0 — Whole-system control vs. data plane

```mermaid
flowchart LR
    classDef cp fill:#e8f3ff,stroke:#3b82f6
    classDef dp fill:#fff4e5,stroke:#f59e0b
    classDef ext fill:#f3f4f6,stroke:#6b7280
    classDef obs fill:#ecfdf5,stroke:#10b981

    User(["User"]):::ext
    OIDC[("OIDC token<br/>(IdP)")]:::ext
    Issuer["Capability Issuer"]:::cp
    KMS[("KMS / HSM")]:::ext
    Token[("Capability JWT/VC<br/>signed")]:::cp
    Agent["Agent runtime"]:::dp
    Gateway["Tool Gateway"]:::dp
    Backend["Protected backend"]:::ext
    Redis[("Redis<br/>kill / revoke / counters")]:::dp
    Audit[("Signed audit event")]:::obs
    SIEM[("SIEM")]:::obs
    Posture[("AgentInventoryRecord")]:::obs

    User --> OIDC --> Issuer
    Issuer -->|sign digest| KMS
    KMS -->|signature| Issuer
    Issuer --> Token --> Agent
    Issuer --> Posture --> SIEM
    Agent -->|tool call + Token| Gateway
    Gateway -->|verify| Token
    Gateway <--> Redis
    Gateway -->|authorized request| Backend
    Backend -->|response| Gateway --> Agent
    Gateway --> Audit --> SIEM
```

**Trust-boundary legend:** Blue = control plane (mint), Orange = data
plane (every action), Grey = external trust roots, Green =
observability sinks. The agent runtime sits on the **untrusted** side
of the gateway — the gateway is the _only_ PDP and PEP for protected
backends.

### 5.2 DFD-1 — Agent boot and first tool call (decomposed)

```mermaid
flowchart TB
    A1["Agent runtime starts<br/>(with AuthTokenProvider,<br/>IssuanceHintsProvider)"]
    A2["Agent runtime: POST /api/v1/issue<br/>(OIDC bearer + hints)"]
    A3["Issuer: validate IdP token<br/>→ UserContext + roles"]
    A4["Issuer: load AgentCapabilityManifest<br/>+ UserConsent (if required)"]
    A5["Issuer: roles → capabilities<br/>∩ manifest ∩ explicit request"]
    A6["Issuer: validateConditions()<br/>(reject unknown type)"]
    A7["Issuer: build payload<br/>{iss,sub,aud,exp,jti,cap,schemaVersion}"]
    A8["Issuer: KMS.sign(digest)"]
    A9["Issuer → Agent: signed JWT"]
    B1["Agent: tool call<br/>(framework adapter)"]
    B2["Runtime → Gateway: HTTPS<br/>Authorization: Bearer + body + X-Target-Host"]
    B3["Gateway: parse + canonicalise resource"]
    B4["Verifier: JWS verify<br/>(local SPKI or partner DID document key)"]
    B5["Verifier: schemaVersion ∈ supported?"]
    B6["Verifier: revocationStore.has(jti)?"]
    B7["Engine: KillSwitch.check(global, agent, session)"]
    B8["Engine: isActionAllowed(action, resource, cap[])"]
    B9["Engine: enforceConditions(...)<br/>(time, IP, maxCalls, ...)"]
    B10["Engine: validateArguments(body)<br/>(if argumentSchema)"]
    B11["Engine: emit signed AuditLogEntry"]
    B12["Gateway: proxy to backend → 2xx"]

    A1-->A2-->A3-->A4-->A5-->A6-->A7-->A8-->A9
    A9-->B1-->B2-->B3-->B4-->B5-->B6-->B7-->B8-->B9-->B10-->B11-->B12
```

### 5.3 DFD-2 — Cross-org enforcement

```mermaid
flowchart LR
    PartnerAgent["Partner agent"]
    PartnerIssuer["Partner Capability Issuer"]
    DIDDoc["Partner DID Document<br/>(did:web / did:ion / did:key)"]
    Resolver["pkg/did/resolver.go<br/>(local cache)"]
    Gateway["Tool Gateway<br/>partner-issuer-resolver"]
    Backend["Local protected backend"]
    Audit["Audit log<br/>(crossOrg=true,<br/>partnerDID=...)"]

    PartnerIssuer -->|VC for Partner DID sub| PartnerAgent
    PartnerAgent -->|tool call + VC| Gateway
    Gateway -->|iss ∈ TRUSTED_PARTNER_DIDS?| Gateway
    Gateway --> Resolver --> DIDDoc
    DIDDoc -->|verificationMethod public key| Gateway
    Gateway -->|signature OK + scope OK| Backend
    Gateway --> Audit
```

When the issuer claim (`iss`) is in `TRUSTED_PARTNER_DIDS`, the gateway
fetches the partner's DID document, extracts the
`verificationMethod`, and uses _that_ key (not the local SPKI key) to
verify the signature. `LOCAL_ISSUER_IDS` is the symmetric guard that
prevents the local key from being abused to impersonate a foreign DID.

---

## 6. Sequence diagrams (implementation-level)

These reflect the _actual_ request paths in the current code, so
maintainers can trace each line against the source.

### 6.1 Issuance — `POST /api/v1/issue`

```mermaid
sequenceDiagram
    autonumber
    participant Caller as Agent runtime / CLI
    participant API as cmd/issuer/main.go
    participant Svc as IssuerApp
    participant IdP as IdentityProvider adapter (pkg/identity/)
    participant Cond as pkg/capability (condition validation)
    participant Roles as internal/issuer/policy (role mapping)
    participant KMS as TokenSigner adapter (KMS/HSM)
    participant Post as PostureEmitter (optional)

    Caller->>API: POST /api/v1/issue (Bearer OIDC + body)
    API->>API: rate-limit, helmet, JSON parse
    API->>Svc: issueCapability(req)
    Svc->>IdP: verifyToken(bearer) → UserContext + roles
    Svc->>Svc: load AgentCapabilityManifest (if any)
    Svc->>Svc: enforce REQUIRE_USER_CONSENT for SENSITIVE_ACTIONS
    Svc->>Svc: PIM check + cap exp by min(req.exp, pim.endDateTime − 30s)
    Svc->>Roles: mapRolesToCapabilitiesForPolicy(roles, policy)
    Svc->>Svc: intersect (roles ∩ manifest ∩ requested)
    Svc->>Cond: validateConditions(cap.conditions[])  // unknown ⇒ throw
    Svc->>Svc: build CapabilityTokenPayload + schemaVersion
    Svc->>KMS: sign(canonicalSha256(payload))
    KMS-->>Svc: JWS signature
    Svc-->>API: signed JWT
    API->>Post: emitObserved(AgentInventoryRecord)  (best-effort)
    API-->>Caller: 200 { token, expiresAt, jti, ... }
```

### 6.2 Enforcement — `ANY /proxy/*`

```mermaid
sequenceDiagram
    autonumber
    participant Agent
    participant GW as cmd/gateway/main.go
    participant Ver as JWTTokenVerifier
    participant Rev as RevocationStore
    participant Resolver as PartnerIssuerResolver
    participant Eng as EnforcementEngine
    participant KS as KillSwitchManager
    participant Cond as enforceConditions()
    participant CCS as CallCounterStore
    participant Audit as AuditLogger + EvidenceSigner
    participant Backend

    Agent->>GW: REQUEST /proxy/<host>/<path>  (Bearer JWT, X-Target-Host)
    GW->>GW: canonicalise → api://host/path
    GW->>Ver: verify(token)
    Ver->>Resolver: resolve issuer key (local SPKI or partner DID)
    Resolver-->>Ver: public key
    Ver->>Ver: jose verify + schemaVersion check
    Ver->>Rev: has(jti)?
    Rev-->>Ver: revoked? → if so throw 401
    Ver-->>GW: CapabilityTokenPayload
    GW->>Eng: validateAction({token, action, resource, context})
    Eng->>KS: check(global, agent, session)
    KS-->>Eng: allow / kill
    Eng->>Eng: isActionAllowed(action, resource, cap.actions, cap.resources)
    Eng->>Cond: enforceConditions(cap.conditions, ctx)
    Cond->>CCS: increment(jti, windowSeconds) for maxCalls
    CCS-->>Cond: under-limit?
    Cond-->>Eng: allow / deny + reason

    %% Semicolon replaced with "and" below
    Eng->>Audit: write entry and if crypto-audit, sign(entry)

    Eng-->>GW: { allowed: true }
    GW->>Backend: proxy request (httpProxy)
    Backend-->>GW: response
    GW-->>Agent: response
```

### 6.3 Attenuation (delegation) — `POST /api/v1/attenuate`

```mermaid
sequenceDiagram
    autonumber
    participant Parent as Parent agent
    participant API as capability-issuer
    participant Svc as CapabilityIssuerService
    participant Ver as Local JWT verify
    participant Cond as condition-registry
    participant KMS

    Parent->>API: POST /api/v1/attenuate (parent JWT + child req)
    API->>Ver: verify parent token (sig, exp, schemaVersion)
    API->>Svc: attenuate(parent, childRequest)
    Svc->>Svc: subset check actions ⊆ parent.actions
    Svc->>Svc: subset check resources ⊆ parent.resources
    Svc->>Svc: ttl_child ≤ ttl_remaining(parent)
    Svc->>Svc: maxCalls_child ≤ maxCalls_parent (if present)
    Svc->>Cond: validateConditions(child.conditions)
    Svc->>Svc: link parent jti as parentCapId in payload + audit
    Svc->>KMS: sign child digest
    KMS-->>Svc: JWS signature
    Svc-->>API: child JWT
    API-->>Parent: 200 { token, parentCapId, jti }
```

If any subset check fails → `400 NO_NEW_PRIVS` and an audit event with
`outcome=delegation_denied`.

### 6.4 Renewal — `POST /api/v1/renew`

```mermaid
sequenceDiagram
    autonumber
    participant Agent
    participant API as capability-issuer
    participant Svc as CapabilityIssuerService
    participant IdP
    participant KMS

    Agent->>API: POST /api/v1/renew (current JWT + fresh OIDC)
    API->>Svc: renew(currentToken, oidcToken)
    Svc->>IdP: re-verify OIDC + reread roles
    Svc->>Svc: assert roles still cover current capabilities
    Svc->>Svc: assert PIM role still active (if applicable)

    %% Semicolon replaced with "and" below
    Svc->>Svc: bump iat / exp and preserve sub, jti chain

    Svc->>KMS: sign renewed payload
    KMS-->>Svc: signature
    Svc-->>API: renewed JWT
    API-->>Agent: 200 { token, expiresAt }
```

The renewal does **not** widen scope; it can only re-prove the
identity and reset expiry. A change in role membership produces a
narrower (or denied) renewal — never a wider one.

### 6.5 Kill switch & revocation propagation

```mermaid
sequenceDiagram
    autonumber
    participant Admin
    participant Adm as internal/gateway/admin.go
    participant KS as KillSwitchManager (Redis-backed)
    participant Rev as RevocationStore (Redis-backed)
    participant GW1 as Gateway replica 1
    participant GW2 as Gateway replica 2
    participant Agent

    Admin->>Adm: POST /admin/kill-switch/agent/{id}/kill (X-Admin-API-Key)
    Adm->>KS: killAgent(id)
    KS->>KS: write-through to shared Redis (agent-id added to set)
    KS->>KS: PUBLISH <KILL_SWITCH_KEY_PREFIX>events {op:kill_agent,id,...}
    Note over KS,GW2: Other replicas receive the pub/sub event and<br/>invalidate their cache in single-digit ms.<br/>Periodic refresh (KILL_SWITCH_REFRESH_INTERVAL_MS, default 30 s)<br/>is the safety net for dropped pub/sub messages.
    KS-->>GW1: local cache updated (originating replica, immediate)
    KS-->>GW2: cache updated via pub/sub event (sub-second)
    Agent->>GW1: tool call (any token for that agent)
    GW1->>KS: check(agentId)
    KS-->>GW1: KILLED
    GW1-->>Agent: 403 AGENT_KILLED
```

Targeted token revocation (`POST /admin/revoke/{jti}`) follows the
same shape but writes to `RevocationStore`; the revocation is
immediate in the shared Redis store and is enforced on the next
request, when the verifier checks `jti` during token verification.
Kill-switch propagation across replicas is sub-second under normal
conditions because every mutation is broadcast on a Redis pub/sub
channel; the periodic refresh
(`KILL_SWITCH_REFRESH_INTERVAL_MS`, default 30 s) acts as a safety net
for the rare case of a dropped pub/sub message. The originating
replica observes the change immediately via write-through.

### 6.6 Posture inventory emission

```mermaid
sequenceDiagram
    autonumber
    participant Svc as CapabilityIssuerService
    participant Q   as SQLite WAL queue<br/>(DurablePostureEmitter)
    participant W   as DeliveryWorker<br/>(background)
    participant SIEM

    Note over Svc: Step 5 — signPayload() completes
    Svc->>+Q: await emitObserved(record)<br/>(synchronous SQLite INSERT, < 1 ms)
    Q-->>-Svc: resolves — record is durable
    Note over Svc: HTTP response sent
    W->>Q: peek(batch)
    Q-->>W: events
    W->>SIEM: deliver (HTTP / log transport)
    alt success
        W->>Q: ack(id)
    else transient failure
        W->>Q: nack(id, nextRetryAt)

        %% Semicolon replaced with a comma below
        Note over W: exponential back-off, dead-letter after maxAttempts
    end
```

Posture inventory is **transactionally consistent with issuance**:
the `DurablePostureEmitter.emitObserved` call is `await`-ed
immediately after `signPayload` (Step 5b of the issuance pipeline),
so the SQLite WAL write completes _before_ the HTTP response is sent.
A process crash after that point leaves the record in the on-disk
queue, where the `DeliveryWorker` will pick it up on the next pod
start.

The `DeliveryWorker` background loop fans out to cloud surfaces
(Defender CSPM / Security Hub / SCC) asynchronously; plugin delivery
failures are retried with exponential back-off and dead-lettered after
`POSTURE_DURABLE_MAX_ATTEMPTS` exhaustion. A plugin outage therefore
never affects issuance latency, and dead-lettered events are counted
via the `eunox_issuer_posture_dead_lettered_total` Prometheus counter.

**Remaining gap:** the crash window between `signPayload` completing
and the SQLite `push` call completing is sub-millisecond but non-zero.
Closing it entirely would require either (a) a single atomic
transaction spanning KMS and SQLite (impractical) or (b) idempotent
re-issuance on crash recovery (out of scope). The current design is
the best practical approximation: enqueue-before-response with a WAL
queue that survives pod restarts.

The issuer service treats the emitter as `PostureEmitterLike`
(structural interface), so `internal/issuer/app.go` is interface-based and
can be wired with any compatible emitter implementation. The service entry
point `cmd/issuer/main.go` wires the concrete `DurablePostureEmitter`; the
structural-interface boundary is at the service struct, not the package.

Set `POSTURE_DURABLE_QUEUE_PATH` to a writable path on a persistent
volume in production (e.g. `/var/lib/eunox/posture-queue.db`);
omitting it defaults to `':memory:'` which loses the queue on pod
restart and is equivalent to the old best-effort behaviour.

---

## 7. Deployment view

```mermaid
flowchart TB
    subgraph K8s["Kubernetes namespace 'eunox' (per env)"]
        IssuerPod["capability-issuer<br/>HPA 2..N"]
        GatewayPod["tool-gateway<br/>HPA 2..N"]
        RuntimePod["agent-runtime pods<br/>(per agent / per workload)"]
        Web["site/ Astro website<br/>(landing, docs, blog)"]
    end

    subgraph AzureRefImpl["Azure reference implementation"]
        AAD["Entra ID"]
        KV["Key Vault"]
        ACR["Azure Container Registry"]
        Sentinel["Sentinel analytic rules<br/>(infra/sentinel/)"]
        Mon["Azure Monitor"]
        RedisAzure["Azure Cache for Redis"]
    end

    AWS["AWS profile (infra/terraform/aws)<br/>Cognito / KMS / EKS"]
    GCP["GCP profile (infra/terraform/gcp)<br/>Cloud Identity / Cloud KMS / GKE"]

    IssuerPod --> AAD
    IssuerPod --> KV
    IssuerPod --> Mon
    GatewayPod --> RedisAzure
    GatewayPod --> Mon
    Mon --> Sentinel
    RuntimePod --> GatewayPod
    RuntimePod --> IssuerPod
```

Pod-security baseline (see `k8s/pod-security-standards.yaml`,
`network-policies.yaml`, `ha-policies.yaml`):

- `restricted` PSS profile, non-root UID (1001/1002), read-only rootfs
  with tmpfs scratch.
- Default-deny network policy; only the gateway egresses to backends.
- HPA + PDB on issuer & gateway; resource quotas at namespace level.
- AppArmor / SELinux profiles enabled where the cluster supports them.

---

## 8. Cross-cutting concerns

| Concern              | Where it lives                                                                                                                                            | Notes                                                                                                                                                                                                                                                                                                                                                                                                      |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| AuthN (humans)       | IdP adapters in `pkg/identity/` (`azure_ad.go`, `cognito.go`, `gcp.go`, `did.go`)                                                                         | OIDC at the boundary; never inside the rest of the system                                                                                                                                                                                                                                                                                                                                                  |
| AuthN (services)     | Cloud-managed identity (workload identity / managed identity)                                                                                             | Issuer→KMS, gateway→Redis, etc.                                                                                                                                                                                                                                                                                                                                                                            |
| AuthZ (capabilities) | `pkg/enforcement/engine.go` + `pkg/capability/condition.go`                                                                                               | Single PDP+PEP at the gateway                                                                                                                                                                                                                                                                                                                                                                              |
| Crypto signing       | `pkg/crypto/signer.go` adapter; `kms_azure.go`, `kms_aws.go`, `kms_gcp.go`                                                                                | KMS never sees the message body — digest only                                                                                                                                                                                                                                                                                                                                                              |
| Key rotation         | `GET /.well-known/jwks.json` (issuer); `JwksVerifier` (gateway)                                                                                           | Issuer publishes a JWK Set; every token carries a `kid`. Gateway caches JWKS with a configurable TTL (`EUNOX_JWKS_CACHE_TTL_SECONDS`, default 300 s) and refreshes on `kid` miss (no restart needed). Rotation procedure: add key 2 → wait one TTL → sign with key 2 → wait one TTL → remove key 1. Strict `kid` enforcement: tokens without a `kid` are rejected when `EUNOX_REQUIRE_KID=true` (default). |
| Audit                | `pkg/audit/audit.go` + `NewEvidenceSigner` + `EvidenceSigner`                                                                                             | Fail-closed: cannot enable crypto-audit without a signer                                                                                                                                                                                                                                                                                                                                                   |
| Observability        | `log/slog` + `pkg/observability/` + Sentinel rules                                                                                                        | W3C trace-context (`traceparent`/`tracestate`) wired via `go.opentelemetry.io/otel`. `tracingMiddleware` runs on every gateway and minter request; audit log entries carry `trace_id`/`span_id` when a span is active. Attaching an OTel SDK exporter (Jaeger, OTLP, etc.) is a config-only deployment change — no code modification required.                                                             |
| Rate limiting        | Issuer: `IssuanceRateLimiter` backed by the shared call-counter store. Gateway: quota engine per token/action/resource when `GATEWAY_QUOTA_ENABLED=true`. | Issuer and gateway share counter abstractions from `pkg/callcounter`; Redis-backed production implementations live in `pkg/callcounter/redis.go`.                                                                                                                                                                                                                                                          |
| Schema evolution     | `capability.SchemaVersion` + `capability.SupportedSchemaVersions`                                                                                         | Fail-closed on unknown versions                                                                                                                                                                                                                                                                                                                                                                            |
| Configuration        | `pkg/config/` — struct tags with `env` and `default` annotations                                                                                          | Single config struct per service drives boot validation and env-var loading via `config.LoadOrExit(prefix)`                                                                                                                                                                                                                                                                                                |
| Tests                | Per-package `*_test.go` + `internal/integration/`                                                                                                         | Go test suite exercises package and cross-service behaviour via `make test`.                                                                                                                                                                                                                                                                                                                               |

---

## 9. What this architecture buys you (and what it does not)

**Strong properties** (validated by the code):

- **No ambient authority for agents.** The runtime forces every tool
  call through the gateway; without a valid token the call is dropped.
- **Cryptographic rather than configurational trust.** Tokens are
  KMS-signed, not bearer secrets shared with backends.
- **Defence in depth.** AGT (semantic, in-process) + gateway
  (cryptographic, out-of-process) + sandbox (Linux/K8s primitives) +
  kill switch (operator-controlled). Compromise of any single layer
  does not collapse the system.
- **Pluggable everywhere it matters.** Identity, signing, and DID
  resolution are all behind adapter interfaces in `pkg/identity` and `pkg/crypto`
  with cloud-specific concretes in the same packages.
- **Fail-closed by default.** Unknown condition `type`, unknown
  `schemaVersion`, missing call-counter store with a `maxCalls`
  capability, missing evidence signer with crypto-audit on — all hard
  refusals.

**Properties this architecture does _not_ yet give you:**

- A self-service UI for non-engineers to author manifests.
- DPoP sender-constrained tokens.
- OCSF-formatted audit transport.

---

## 10. How to read the rest of the docs against this file

| If you want to …                                  | Read this next                                                                       |
| ------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Understand _why_ the design looks like this       | [`capability-model.md`](./capability-model.md), [`enforcement.md`](./enforcement.md) |
| See abstract / executive-friendly diagrams        | [`diagrams.md`](./diagrams.md)                                                       |
| Use the MCP proxy                                 | [`agent-sdk.md`](./agent-sdk.md)                                                     |
| Deploy the full stack                             | [`deployment.md`](./deployment.md)                                                   |
| Find the gaps and the proposed work to close them | [`capability-model.md`](./capability-model.md)                                       |
