# eunox — Threat Model

**Document status:** Active  
**Classification:** Public  
**Version:** 1.0  
**Date:** 2026-05-28  
**Authors:** Eunox Platform Security  
**Reviewers:** Pending external audit (see §8)

> This document is intended for enterprise security teams, CISOs, and compliance reviewers evaluating eunox for production deployment. It covers trust boundaries, attack classes in and out of scope, failure modes, data sensitivity, and cryptographic design. If you have questions not answered here, open a GitHub issue tagged `security` or email security@eunolabs.com.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Trust Boundaries](#2-trust-boundaries)
3. [Asset Inventory](#3-asset-inventory)
4. [Threat Analysis — Attacks Prevented](#4-threat-analysis--attacks-prevented)
5. [Explicit Out-of-Scope Threats](#5-explicit-out-of-scope-threats)
6. [Failure Modes and Resilience Posture](#6-failure-modes-and-resilience-posture)
7. [Data Classification and Sensitivity](#7-data-classification-and-sensitivity)
8. [Cryptographic Design](#8-cryptographic-design)
9. [Known Findings and Remediation Status](#9-known-findings-and-remediation-status)
10. [Third-Party Audit Status](#10-third-party-audit-status)
11. [Change Log](#11-change-log)

---

## 1. System Overview

eunox is a **capability-native zero-trust enforcement plane for AI agents**. It sits between an AI agent runtime and the backend services (APIs, databases, filesystems, external SaaS) that the agent is permitted to call. Every tool invocation is mediated by a cryptographically signed, time-limited capability token; the gateway validates that token, evaluates the policy, and either forwards or blocks the request before any backend sees it.

### 1.1 What problem eunox solves

Existing API gateways and policy engines (Envoy, OPA, Kong) enforce access control at the HTTP layer based on static identity — who the caller is. They have no concept of _what an agent is doing_, _what it has already done this session_, or _whether a sequence of individually permitted calls is collectively dangerous_. eunox introduces three constructs that existing infrastructure cannot provide:

| Construct                     | What it enables                                                                                                                                                                           |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Capability token**          | A signed, scoped, time-limited credential issued per-task — not per-user. Limits what a specific agent invocation can do, regardless of the identity of the user who spawned it.          |
| **Session context**           | The gateway tracks tool call history within a task. Policies can express sequential constraints ("deny `write_external_endpoint` if `read_credentials` was called earlier this session"). |
| **Task-lifecycle revocation** | Credentials minted for a task are revoked when the task completes or fails — not when the static token expires. Privilege exposure window is bounded by task duration, not token TTL.     |

### 1.2 Component map

```
┌──────────────────────────────────────────────────────────────┐
│  Enterprise Identity Provider (Entra ID / Cognito / GCP CI)  │
└──────────────────────────────┬───────────────────────────────┘
                               │ OIDC (verified)
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                    Capability Issuer (:3001)                 │
│  • Validates IdP token via OIDC                              │
│  • Maps identity → role → capability policy                  │
│  • Mints signed capability token (JWT, KMS-backed)           │
│  • Admin API: role-policy CRUD                               │
└──────────────────────────────┬───────────────────────────────┘
                               │ Signed capability token
                               ▼
                    ┌──────────────────────┐
                    │  AI Agent Runtime    │
                    │  (LangGraph / MAF /  │
                    │   CrewAI / custom)   │
                    └──────────┬───────────┘
                               │ Tool call + capability token
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                    Tool Gateway (:3002)                      │
│  • Verifies token signature (JWKS / KMS)                     │
│  • Checks revocation (Redis JTI store)                       │
│  • Checks kill-switch state (Redis Pub/Sub)                  │
│  • Evaluates capability conditions (IP, time, quota, policy) │
│  • Validates DPoP binding (if present)                       │
│  • Emits signed audit event (OCSF 1.1.0)                     │
│  • Proxies request to backend on ALLOW                       │
└───────────────┬──────────────────────────┬───────────────────┘
                │ Authorized requests      │ Signed audit events
                ▼                          ▼
      Protected backends            SIEM / audit store
      (APIs, DBs, files)            (Splunk / Sentinel /
                                     custom OCSF sink)
```

**Supporting services:**

| Service           | Role                                                                             |
| ----------------- | -------------------------------------------------------------------------------- |
| Redis             | Kill-switch state, token revocation list, DPoP replay store, call-counter quotas |
| PostgreSQL        | API key store (minter), policy store, audit ledger                               |
| KMS / HSM         | Private signing key holder (Azure Key Vault / AWS KMS / GCP Cloud KMS)           |
| Admin API (:3003) | Kill-switch activation, bulk revocation — localhost-bound by default             |

---

## 2. Trust Boundaries

### 2.1 Trust boundary diagram

```
╔═══════════════════════════════════════════════════════════════╗
║  TRUSTED ZONE — cryptographically verified before use         ║
║                                                               ║
║  • Capability token claims (after JWT signature verified      ║
║    against JWKS and revocation confirmed)                     ║
║  • IdP identity claims (after OIDC validation with PKCE S256) ║
║  • Partner issuer tokens (after DID resolution + signature    ║
║    verification against resolved DID document)                ║
║  • KMS-returned signatures (TLS to KMS endpoint required)     ║
╚═══════════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════════╗
║  VERIFIED AT RUNTIME — checked but not unconditionally trusted║
║                                                               ║
║  • JWT expiry (exp / iat with 60-second clock skew tolerance) ║
║  • Token revocation (jti lookup in Redis on every request)    ║
║  • Kill-switch state (Redis Pub/Sub + 30-second refresh poll) ║
║  • DPoP proof (RFC 9449: signature, thumbprint, replay store) ║
║  • Capability conditions (IP range, time window, call quota,  ║
║    allowedTables, allowedOperations, argumentSchema)          ║
║  • Admin API key (constant-time comparison of SHA-256 hashes) ║
╚═══════════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════════╗
║  EXPLICITLY UNTRUSTED — eunox makes no assertions about these ║
║                                                               ║
║  • Content of LLM prompts or completions                      ║
║  • Agent-side code integrity or runtime environment           ║
║  • Tool call argument semantics (content is opaque to eunox;  ║
║    only schema-level validation is performed)                 ║
║  • Client-side token storage security                         ║
║  • Network between agent and gateway (assume hostile; use TLS)║
╚═══════════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════════╗
║  TRUSTED INFRASTRUCTURE — compromise expands blast radius     ║
║                                                               ║
║  • Redis (holds revocation list and kill-switch state)        ║
║  • KMS / HSM (holds private signing key)                      ║
║  • Enterprise IdP (issues identity tokens consumed by issuer) ║
║  • PostgreSQL (holds audit ledger; compromise = log tampering ║
║    risk, mitigated by cryptographic chain)                    ║
╚═══════════════════════════════════════════════════════════════╝
```

### 2.2 What the gateway trusts after signature verification

Once the gateway successfully verifies a capability token's signature against the issuer's JWKS, it treats the following claims as authoritative without further verification:

- `sub` — agent or user subject identity
- `aud` — intended audience (checked: must match `GATEWAY_AUDIENCE`)
- `iat` / `exp` — issuance and expiry timestamps (checked with clock skew tolerance)
- `capabilities` — the set of permitted resources, actions, and conditions
- `authorizedBy.userId`, `authorizedBy.roles`, `authorizedBy.tenantId` — identity embedded at issuance
- `parentCapabilityId` — delegation chain identifier

These claims are not re-validated against the issuer's policy store on every request. The signature is the source of trust.

### 2.3 Trust decisions NOT made by eunox

| Decision                                                              | Who is responsible            |
| --------------------------------------------------------------------- | ----------------------------- |
| Whether the LLM's instructions are safe                               | Application / LLM provider    |
| Whether a prompt injection has occurred                               | Application / input sanitizer |
| Whether the agent executable has been tampered with                   | Host OS / container runtime   |
| Whether the backend service correctly processes an authorized request | The backend itself            |
| Whether the user who requested the token had legitimate intent        | Enterprise IdP + HR process   |

---

## 3. Asset Inventory

| Asset                                 | Sensitivity | Location                                  | Compromise impact                                                                             |
| ------------------------------------- | ----------- | ----------------------------------------- | --------------------------------------------------------------------------------------------- |
| KMS / HSM private signing key         | Critical    | Azure Key Vault / AWS KMS / GCP Cloud KMS | Full token forgery for the tenant; all tokens become untrustworthy                            |
| Admin API key / admin JWT signing key | Critical    | Environment variable / secrets manager    | Attacker can create arbitrary policies, activate kill-switches, revoke any token              |
| JWKS public keys                      | Public      | `/.well-known/jwks.json`                  | No direct impact; compromise of private key makes rotation necessary                          |
| Redis revocation store                | High        | Redis cluster                             | Cleared store: revoked tokens become valid again until expiry                                 |
| Redis kill-switch state               | High        | Redis cluster                             | Cleared state: killed agents can resume tool calls                                            |
| Capability tokens (in transit)        | High        | Agent memory / TLS                        | Token theft enables tool calls up to expiry (typically 15 minutes)                            |
| Audit log database                    | Medium      | PostgreSQL                                | Deleted records: compliance and forensic capability lost; tampering detectable via HMAC chain |
| Role-capability policy file           | Medium      | Filesystem / PostgreSQL                   | Widened policies: agents receive broader capabilities than intended                           |
| Tool call metadata (audit records)    | Medium      | PostgreSQL                                | Tool names, resource paths, outcomes — not argument values                                    |
| Enterprise IdP credentials            | High        | Managed by customer IdP                   | IdP compromise allows issuance of tokens for any role the IdP maps                            |

---

## 4. Threat Analysis — Attacks Prevented

This section uses the STRIDE framework. Each threat entry states the attack vector, the specific mechanism eunox uses to prevent or contain it, and a reference to the relevant code or configuration.

---

### 4.1 Token Forgery

**STRIDE category:** Spoofing  
**Attack:** An attacker crafts a capability token with elevated permissions (`"actions": ["admin"]`, broader resources) without access to the issuer's private key.

**Prevention:**

All capability tokens are signed JWTs. The gateway verifies every token's signature against the issuer's JWKS (`GET /.well-known/jwks.json`) before evaluating any claim. The signing key never leaves the KMS boundary — only the SHA-256 digest of the payload crosses the KMS API boundary; the plaintext is never sent.

Supported signature algorithms: RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA. The `none` algorithm is explicitly rejected. Tokens without a `kid` header are rejected when `EUNOX_REQUIRE_KID=true` (default). Tokens with an unrecognised `schemaVersion` field are rejected.

The JWKS endpoint is cached by the gateway with a configurable TTL (`EUNOX_JWKS_CACHE_TTL_SECONDS`, default 300 seconds). If a `kid` is not found in the cache, the gateway immediately re-fetches JWKS (refresh-on-miss) before rejecting the token.

**Residual risk:** A compromise of the KMS service identity that holds `sign` permission would allow token forgery. Mitigated by: KMS audit logs, KMS access policy scoped to issuer service identity only, key rotation capability (add new key → wait cache TTL → sign with new key → remove old key).

---

### 4.2 Capability Escalation

**STRIDE category:** Elevation of Privilege  
**Attack:** An agent attempts to access resources or perform actions beyond what its capability token permits — either by modifying the token's `capabilities` claim or by requesting a backend resource that the token does not cover.

**Prevention (token modification):** Token signature verification (§4.1) makes modification detectable. Any change to the `capabilities` claim invalidates the signature.

**Prevention (policy enforcement):** The gateway's enforcement engine evaluates every incoming tool call against the `capabilities` array in the verified token. The evaluation:

1. Finds the capability constraint whose `resource` glob covers the requested resource (`api://tools/**` covers `api://tools/read_file`).
2. Confirms the requested action is in the constraint's `actions` set.
3. Evaluates all attached conditions (time window, IP range, call quota, allowed operations, argument schema, etc.).
4. If no constraint covers the request: **DENY**.

The enforcement engine (`pkg/enforcement/engine.go`) is the sole policy decision point. Backends are not expected to perform their own authorization against capability tokens.

**Prevention (attenuation integrity):** When a token is attenuated (delegated to a child agent with narrowed scope), `ValidateSubset` enforces that child capabilities ⊆ parent capabilities. An agent cannot delegate broader permissions than it holds.

---

### 4.3 Session Hijacking / Token Theft

**STRIDE category:** Spoofing  
**Attack:** An attacker intercepts a capability token in transit and replays it to make unauthorized tool calls before it expires.

**Prevention layer 1 — TLS:** All traffic between the agent runtime and the gateway requires TLS 1.2 minimum. `InsecureSkipVerify` is never set in production code paths.

**Prevention layer 2 — Short TTL:** The default token TTL is 15 minutes (`maxTtlSeconds: 900`). Maximum configurable TTL is 24 hours. Task-lifecycle revocation (§4.4) further reduces the effective window to average task duration (typically seconds to minutes for most tool calls).

**Prevention layer 3 — DPoP binding (RFC 9449):** When DPoP is enabled, the capability token contains a `cnf.jkt` claim binding it to a specific client public key. The gateway verifies:

- The DPoP proof JWT is signed by the key whose thumbprint matches `cnf.jkt`
- The `htm` (method) and `htu` (URI) claims match the actual request
- The `iat` claim is within the acceptable clock skew
- The `jti` has not been seen before (Redis-backed replay store)

A stolen token without the matching private key cannot produce a valid DPoP proof.

**Prevention layer 4 — Revocation:** Tokens can be revoked immediately by submitting their `jti` to `POST /admin/revoke/{jti}`. Revocation takes effect on the next gateway enforcement decision for that token (no cache delay for revocation — the gateway checks the revocation store on every request).

---

### 4.4 Credential Theft via Tool Call

**STRIDE category:** Information Disclosure / Elevation of Privilege  
**Attack scenario:** An agent calls `read_file("/etc/credentials")` or queries a database table containing secrets, then uses those secrets to escalate privileges or exfiltrate data.

**Prevention layer 1 — Resource and action scoping:** Capability constraints explicitly enumerate which resources an agent can access and with which actions. A token scoped to `storage://workspace/output/**` with `["write"]` cannot `read` from it, and cannot access `storage://credentials/**` at all.

**Prevention layer 2 — Argument schema validation:** Constraints can include an `argumentSchema` field (JSON Schema subset) that validates the actual arguments of a tool call before it is forwarded. Example: a `read_file` capability can include a `pattern` constraint on the `path` argument: `"^/reports/.*"` — any call to `read_file("/etc/credentials")` fails at argument schema validation before reaching the backend.

**Prevention layer 3 — Task-lifecycle revocation:** Database credentials minted by the minter for a specific task are tied to the task's lifecycle. When the task completes or fails, the minter calls the revocation hook: the DB session token is revoked, and the STS role session is revoked via the cloud provider's API. The privilege exposure window is bounded by task duration, not by the minimum credential TTL imposed by the cloud provider (typically 15 minutes for AWS STS).

**Prevention layer 4 — Condition enforcement:** The `allowedTables` condition limits a database tool to a specific set of tables (and optionally columns). The `allowedOperations` condition limits SQL to specific statement types (`SELECT`, not `INSERT`/`DROP`). The `redactFields` condition flags specific fields for redaction by the backend adapter.

---

### 4.5 Sequential / Compound Attack (Individually Safe, Collectively Dangerous)

**STRIDE category:** Elevation of Privilege  
**Attack:** An agent performs a sequence of tool calls that are each individually within policy, but the sequence constitutes an attack (e.g., `read_credentials` → `write_to_external_endpoint`).

**Prevention:** Session-level conditions in capability constraints. The `maxCalls` condition tracks call count within a rolling time window per token (Redis-backed call counter). The `policy` condition delegates to a named policy backend (OPA or Cedar) that receives the full session context — including call history, active task, and issued capability tokens — as an input document.

The OPA bridge (T-07) specifically enables Rego policies to express: "deny `write_external_endpoint` if the token for this session has already authorized a call to a resource matching `*credentials*`." This session context is the enforcement surface that HTTP-layer policy engines cannot access.

---

### 4.6 Audit Log Tampering

**STRIDE category:** Tampering / Repudiation  
**Attack:** An attacker with database access deletes or modifies audit records to conceal unauthorized tool calls.

**Prevention layer 1 — Cryptographic signatures:** Every audit record is signed using the same KMS-backed signing key as capability tokens. The signature covers the full `LogEntry` payload. A modified record has an invalid signature detectable by any party with access to the issuer's JWKS.

**Prevention layer 2 — HMAC-SHA256 chain:** Records are linked in a hash chain. Each record includes `previousHash` (the chain hash of the prior record) and `chainHash` (HMAC-SHA256 over the current record's content and the previous hash). Deleting or reordering records breaks the chain. The `eunox-mcp validate-token` command verifies chain integrity for a session.

**Prevention layer 3 — Append-only schema:** The audit table (`audit_records`) has no `UPDATE` or `DELETE` grants for the application role. Schema enforcement is a complement to, not a substitute for, the cryptographic chain.

**Prevention layer 4 — SIEM export:** Audit events are streamed to the configured SIEM (Splunk, Azure Sentinel, or any OCSF-compatible sink) in real time. An attacker who compromises the PostgreSQL instance cannot retroactively remove events already acknowledged by the SIEM.

**Residual risk:** Events in the in-process audit buffer (bounded channel) that have not yet been flushed to PostgreSQL would be lost if the process is killed with SIGKILL. Graceful shutdown drains the buffer. SIGKILL loss is documented in the operations runbook.

---

### 4.7 Kill-Switch Bypass

**STRIDE category:** Elevation of Privilege  
**Attack:** An agent continues to make tool calls after an operator has activated a kill switch for that agent or session.

**Prevention:** Kill-switch state is checked on every gateway enforcement decision, independent of token signature verification. The check hierarchy is: global kill → agent kill → session kill → token revocation → capability evaluation. A kill-switch activation propagates via two paths:

1. **Redis Pub/Sub:** Sub-second propagation to all gateway replicas.
2. **Periodic refresh poll:** Every 30 seconds (`KILL_SWITCH_REFRESH_INTERVAL_MS`), each replica re-reads the full kill-switch state from Redis. This is a safety net for dropped Pub/Sub messages.

If Redis becomes unavailable after a kill switch has been activated, the in-process cached state (from the last successful refresh) is used. The kill switch remains active. The gateway does not clear the kill-switch state on Redis failure.

---

### 4.8 Admin API Abuse

**STRIDE category:** Elevation of Privilege  
**Attack:** An attacker gains access to the admin API to widen role policies, disable kill switches, or bulk-revoke legitimate tokens.

**Prevention:**

The gateway admin API is bound to `localhost` (port 3003) by default and is not exposed externally. Operators access it via a privileged pod exec or VPN-gated jump host.

Authentication supports two modes:

- **JWT mode (recommended):** `Authorization: Bearer <jwt>` validated against `ADMIN_JWKS_URI`. Required claims: `sub`, `aud` (must match `ADMIN_JWT_AUDIENCE`), `iss`, `exp`. Cross-tenant operations additionally require the `platformAdmin` claim.
- **Static key mode (legacy):** `X-Admin-Api-Key` header; constant-time comparison using `subtle.ConstantTimeCompare` on SHA-256 hashes. Emits a deprecation warning log.

Rate limiting: 10 requests/minute per authenticated identity (`ADMIN_RATE_LIMIT_PER_MINUTE`).

Idempotency: All admin mutations accept an idempotency key. Replayed mutations return the cached response for 24 hours without re-executing.

All admin API calls are logged to the audit ledger with the operator's `sub` and the action taken.

---

### 4.9 Cross-Organization Token Impersonation (Federation)

**STRIDE category:** Spoofing  
**Attack:** An attacker forges a token claiming to be from a trusted partner issuer.

**Prevention:** Partner issuers are identified by DID (`TRUSTED_PARTNER_DIDS` configuration). The gateway resolves the DID document from the authoritative DID endpoint (did:web / did:ion / did:key), extracts the public keys, and verifies the token signature against those keys. Locally configured `LOCAL_ISSUER_IDS` prevents the local signing key from being used to verify tokens claiming a foreign DID as issuer.

Multi-issuer co-signatures: when a token's `proofs.signatures` field is non-empty, all co-signatures must verify successfully. A missing or invalid co-signature causes token rejection.

---

### 4.10 Replay Attacks

**STRIDE category:** Spoofing  
**Attack:** An attacker captures a valid DPoP proof and replays it to make the same request multiple times.

**Prevention:** DPoP proofs are single-use. The `jti` (proof ID) is stored in a Redis-backed set on first use. Subsequent requests presenting the same `jti` are rejected with 403 Forbidden. If the Redis replay store is unavailable, DPoP proof verification fails closed (the request is rejected).

---

## 5. Explicit Out-of-Scope Threats

The following attack classes are explicitly outside eunox's enforcement boundary. This is not an evasion of responsibility — it reflects that these threats require controls at a different layer, and claiming otherwise would be misleading to security reviewers.

---

### 5.1 Prompt Injection

**What it is:** An attacker embeds malicious instructions in data that an LLM reads (a document, a database record, a web page), causing the agent to take actions that the legitimate user did not authorize.

**Why it is out of scope:** Prompt injection is a property of the LLM's behavior in response to input content. eunox operates at the tool-call layer — it enforces _what the agent is permitted to do_ given a valid capability token, not _why the agent decided to do it_. An agent that has been prompt-injected to call `read_file("/reports/Q4.xlsx")` will be authorized by eunox if the token permits that call, because the call is indistinguishable from a legitimate one at the protocol layer.

**What eunox does reduce (but does not eliminate):** By scoping capability tokens to specific resources, actions, and argument patterns, eunox limits the _blast radius_ of a successful prompt injection. An injected agent cannot access resources outside its capability token's scope, and cannot remain active beyond the token's TTL or the task lifecycle.

**Recommended complementary controls:** Input sanitization at the application layer; LLM-specific guardrails (e.g., constitutional AI, system prompt hardening); content scanning before feeding external data to the agent.

---

### 5.2 Model Jailbreak

**What it is:** An attacker circumvents the LLM's safety guidelines or system prompt to generate harmful output or take unintended actions.

**Why it is out of scope:** Jailbreak is a property of the model's response to adversarial prompts. eunox does not inspect prompt content, cannot evaluate the intent of a tool call, and does not interface with the LLM inference layer.

**What eunox does reduce:** Same blast-radius argument as §5.1. A jailbroken agent that attempts to call tools beyond its capability token's scope will be blocked.

---

### 5.3 Client-Side Compromise

**What it is:** An attacker compromises the agent runtime environment — the OS, the container, the Python/Node.js process — and extracts the capability token from memory or intercepts it before it is sent.

**Why it is out of scope:** eunox cannot attest the integrity of a client process. This is a host-level security problem requiring TEEs, process isolation, or eBPF-based syscall monitoring — not a gateway.

**What eunox does reduce:** DPoP binding (§4.3) makes a stolen token unusable without the corresponding private key. Short TTLs bound the useful life of a stolen token. Task-lifecycle revocation bounds it further.

---

### 5.4 Backend Service Vulnerabilities

**What it is:** A backend service that eunox has authorized a request to contains its own vulnerability — a SQL injection in the CRM API, an insecure direct object reference in the file service.

**Why it is out of scope:** eunox acts as the reference monitor in front of backends. It enforces the capability token policy. It does not perform penetration testing, DAST, or runtime application security testing of the backends it proxies to.

---

### 5.5 Denial of Service

**What it is:** An attacker floods the gateway or issuer with requests to exhaust capacity.

**Why it is partially out of scope:** Rate limiting is implemented at the gateway (public enforcement rate limiter, Redis-backed) and at the admin API (10 req/min). However, volumetric DDoS at the network layer is not eunox's responsibility — it requires a WAF, CDN, or DDoS scrubbing service in front of the gateway.

---

## 6. Failure Modes and Resilience Posture

eunox defaults to **fail-closed**: when a dependency required for a security decision is unavailable, the default behavior is to deny the request rather than allow it. This section documents every significant failure mode, the observed behavior, and the configuration option where the behavior is adjustable.

---

### 6.1 Gateway Crash or Unreachable

**Observed behavior:** Requests to the gateway receive no response (connection refused or timeout). No tool calls are forwarded to backends.

**Configuration:** No configuration needed — an absent gateway is inherently fail-closed. The agent runtime receives a network error and should surface it as a task failure.

**Recovery:** Restart the gateway. The gateway is stateless with respect to enforcement decisions; all state (revocation, kill-switch, call counters) lives in Redis. A restarted gateway becomes operational as soon as it can reach Redis and the JWKS endpoint.

---

### 6.2 Redis Unavailable

Redis serves four enforcement functions. Each has a distinct failure mode:

| Function                            | Failure behavior                                                                                                                 | Config to change                                                                  |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Token revocation store              | 503 Service Unavailable — cannot confirm token not revoked                                                                       | `REDIS_REVOCATION_FAILOPEN=true` (not recommended; documents the override exists) |
| Kill-switch state                   | Falls back to in-process cached state from last successful refresh (up to `KILL_SWITCH_REFRESH_INTERVAL_MS`, default 30 seconds) | N/A — in-process cache is the designed fallback                                   |
| DPoP replay store                   | 403 Forbidden — treats unavailability as a replay                                                                                | No override; fail-closed is intentional                                           |
| Call counter (`maxCalls` condition) | 503 Service Unavailable — cannot verify quota                                                                                    | N/A                                                                               |

**Operational note:** The kill-switch fallback is the only case where Redis unavailability does not immediately result in a 5xx. A kill switch that was active before Redis went down remains active in the in-process cache. A kill switch activated _after_ Redis went down will not propagate until Redis recovers and the periodic refresh runs.

**Redis high availability:** Production deployments should use Redis Sentinel or Redis Cluster. The gateway Redis client handles Sentinel failover transparently. The `REDIS_URL` configuration accepts Sentinel-format URIs.

---

### 6.3 Capability Issuer Unavailable

**Observed behavior:** New capability tokens cannot be issued. Agents that already hold a valid, unexpired token continue to have their requests enforced by the gateway normally. The gateway validates tokens against its cached JWKS — it does not call the issuer on every request.

**JWKS cache behavior:** If the issuer's JWKS endpoint is unreachable:

- Cached JWKS is preserved and used for signature verification.
- If a token presents a `kid` not in the cached JWKS, a re-fetch is attempted. If the re-fetch fails, the token is rejected.
- A circuit breaker in the JWKS verifier protects against thundering-herd retry storms during issuer outages.

**Recovery:** Once the issuer recovers, agents can obtain new tokens. No gateway restart is needed.

---

### 6.4 Database (PostgreSQL) Unavailable

**Observed behavior:** The audit pipeline's write path fails. Audit events accumulate in the in-process bounded channel. If the channel fills before PostgreSQL recovers, new events are dropped with a warning log.

**Security implication:** Dropped audit events are a compliance risk (audit trail gap), not an enforcement risk. The gateway continues to enforce tool calls correctly regardless of audit write success. Compliance teams should monitor the `audit_buffer_drops_total` metric and alert on non-zero values.

**Recovery:** PostgreSQL recovery drains the buffered events in order.

---

### 6.5 KMS / HSM Unavailable

**Observed behavior (issuer):** Token issuance fails — the issuer cannot sign new capability tokens. Returns 500. There is no fallback to software signing when KMS is configured.

**Observed behavior (gateway):** Token verification is unaffected. Verification uses the JWKS public key, which does not require a KMS call.

**Recovery:** KMS recovery restores token issuance immediately. No restart required.

---

### 6.6 Clock Skew Between Gateway and Issuer

**Observed behavior:** Tokens issued by the issuer may be rejected by the gateway if `iat` is in the future or `exp` is in the past from the gateway's perspective.

**Mitigation:** A 60-second clock skew tolerance is applied to `iat` and `exp` validation. NTP synchronization is required for production deployments. Skew beyond 60 seconds results in token rejection (fail-closed).

---

### 6.7 JWKS Key Rotation During High Traffic

**Observed behavior:** When a key rotation occurs (new key added, old key removed after TTL), tokens signed with the new key arrive at the gateway before the cache has refreshed.

**Mitigation:** The gateway performs a refresh-on-miss: if the token's `kid` is not found in the cached JWKS, the JWKS endpoint is fetched immediately (not waiting for the next cache TTL expiry). The token is verified against the refreshed JWKS. This provides seamless key rotation with no enforcement gap.

---

## 7. Data Classification and Sensitivity

### 7.1 What eunox logs

The following fields appear in audit records for every enforcement decision:

| Field             | Description                                   | Example value                                                                                        |
| ----------------- | --------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `id`              | Unique audit record ID                        | `01HWXYZ...` (ULID)                                                                                  |
| `timestamp`       | Event timestamp (microsecond precision)       | `2026-05-28T14:32:11.421Z`                                                                           |
| `tenant_id`       | Tenant scope                                  | `acme-corp`                                                                                          |
| `event_type`      | Event category                                | `TOOL_CALL_AUTHORIZED`, `TOOL_CALL_DENIED`, `TOKEN_ISSUED`, `TOKEN_REVOKED`, `KILL_SWITCH_ACTIVATED` |
| `actor_user_id`   | Identity of the user who authorized the agent | `user@acme.com`                                                                                      |
| `actor_tenant_id` | Tenant of the authorizing user                | `acme-corp`                                                                                          |
| `action`          | HTTP method or tool operation                 | `POST`, `read`, `execute`                                                                            |
| `resource_uid`    | Resource targeted by the tool call            | `api://tools/read_file`                                                                              |
| `resource_type`   | Resource category                             | `MCP_TOOL`                                                                                           |
| `outcome`         | Enforcement decision                          | `allow`, `deny`                                                                                      |
| `detail`          | Event-specific JSON                           | Condition evaluation results, denial reason                                                          |
| `signature`       | Cryptographic signature of the record         | Base64url-encoded                                                                                    |
| `algorithm`       | Signing algorithm used                        | `ES256`                                                                                              |
| `key_id`          | Key that produced the signature               | `key-2026-05`                                                                                        |
| `chain_hash`      | HMAC-SHA256 chain integrity value             | Hex string                                                                                           |
| `previous_hash`   | Chain hash of the prior record                | Hex string                                                                                           |
| `ocsf_event`      | Full OCSF 1.1.0 event (class 3003 or 6003)    | JSON object                                                                                          |

### 7.2 What eunox never logs

The following data is explicitly excluded from all log outputs:

| Data                                          | Rationale                                                             |
| --------------------------------------------- | --------------------------------------------------------------------- |
| Bearer token (JWT) content                    | Contains sensitive identity claims; logging would enable replay       |
| DPoP proof JWT                                | Single-use credential; logging increases replay window                |
| Tool call argument values                     | May contain PII, PHI, credentials, or proprietary data                |
| IdP authentication tokens                     | Identity credential                                                   |
| KMS signing key material                      | Never in application memory; only SHA-256 digest crosses KMS boundary |
| Admin API keys                                | Operator credential                                                   |
| Database connection strings / passwords       | Infrastructure credential                                             |
| Query parameters containing potential secrets | Conservative: URL tails are logged, full query strings are not        |

### 7.3 Configuring argument-level redaction

Tool call arguments are not logged by default. Operators who require selective argument logging can configure redaction at the transport adapter layer:

- The `redactFields` condition on a capability constraint specifies field names that must be redacted (replaced with `[REDACTED]`) before the audit record is written.
- The condition applies to tool call arguments matching the named fields: `{"type": "redactFields", "fields": ["ssn", "dob", "card_number"]}`.

This enables HIPAA-compliant audit trails that log _that_ a tool call occurred without logging _which patient record_ was accessed.

### 7.4 Data residency

Audit records are written to the PostgreSQL instance specified in `AUDIT_DB_URL`. eunox does not transmit audit data to any external Eunox-operated system. Cloud Team tier deployments synchronize audit metadata (event type, outcome, timestamps — not tool call content) to the hosted control plane; this boundary is documented in the Cloud Team deployment guide.

---

## 8. Cryptographic Design

### 8.1 Signing algorithms

| Algorithm                         | Key type       | Key size         | Use                                                                         |
| --------------------------------- | -------------- | ---------------- | --------------------------------------------------------------------------- |
| **EdDSA** (Ed25519)               | Elliptic curve | 256-bit          | Recommended; smallest signature, fastest verification, no parameter choices |
| **ES256** (ECDSA P-256)           | Elliptic curve | 256-bit          | Default for software (non-KMS) deployments; FIPS 186-4 compliant            |
| **ES384** (ECDSA P-384)           | Elliptic curve | 384-bit          | FIPS 140-2 environments requiring P-384                                     |
| **RS256** / **RS384** / **RS512** | RSA            | 2048-bit minimum | Compatibility with legacy HSMs that do not support EC                       |
| **PS256** / **PS384** / **PS512** | RSA-PSS        | 2048-bit minimum | RSA with probabilistic padding; preferred over PKCS1v1.5 variants           |

The `none` algorithm is unconditionally rejected. There is no configuration to re-enable it.

All key material is generated using `crypto/rand.Reader` (Go's cryptographically secure PRNG backed by the OS entropy source). No `math/rand` or seeded PRNGs are used for security-relevant material.

### 8.2 KMS integration

In production deployments, the signing key never leaves the KMS boundary:

1. The issuer sends the SHA-256 digest of the JWT header+payload to the KMS sign API over TLS.
2. KMS returns the signature.
3. The issuer assembles the final JWS.

The KMS service identity holds `sign` permission only on issuer keys — separate from the `decrypt` or `admin` permissions held by other service identities. Key access is logged by the cloud provider's KMS audit trail independent of eunox's own audit log.

| Cloud       | KMS product            | Key alias pattern                          |
| ----------- | ---------------------- | ------------------------------------------ |
| Azure       | Key Vault              | `eunox-issuer-tenant-<tenantId>`           |
| AWS         | KMS                    | `eunox-issuer-tenant-<tenantId>`           |
| GCP         | Cloud KMS              | `eunox-issuer-tenant-<tenantId>`           |
| Self-hosted | Software (ECDSA P-256) | In-memory; key exported to JWKS at startup |

### 8.3 Audit chain integrity

Audit records are linked by an HMAC-SHA256 chain:

```
chainHash[n] = HMAC-SHA256(
  key: chainSecret,
  message: record[n].content || previousHash[n-1]
)
```

The `chainSecret` is a dedicated secret independent of the signing key (`AUDIT_CHAIN_SECRET`). Loss of the chain secret does not affect token verification. Compromise of the chain secret allows an attacker to forge a chain, but not to forge individual record signatures (which still require the KMS key).

### 8.4 Transport security

- **All external connections:** TLS 1.2 minimum. TLS 1.3 preferred where supported.
- **`InsecureSkipVerify`:** Never set in production code paths. CI tests use self-signed certificates via a custom CA, not by disabling verification.
- **OIDC discovery:** Validated at startup via the well-known endpoint. The discovered JWKS URI must be HTTPS.
- **Admin API key comparison:** `subtle.ConstantTimeCompare` on SHA-256 hashes of the provided and configured keys, preventing timing attacks.
- **DPoP (RFC 9449):** Proof signatures validated with `go-jose/v4`. Replay detection via Redis-backed JTI store.

### 8.5 OIDC / IdP authentication

- **PKCE S256 enforced:** `code_challenge_method` must be `S256`; `plain` is rejected.
- **Algorithms accepted:** RS256, ES256. The `none` algorithm and symmetric algorithms (HS256, HS384, HS512) are rejected.
- **Nonce replay protection:** Nonces stored in Redis (multi-replica) or in-process LRU (single-replica). A nonce presented twice results in rejection of the second request.
- **Clock skew tolerance:** 60 seconds on `exp` and `iat` claims.

---

## 9. Known Findings and Remediation Status

The following findings were identified during internal static analysis (report: `docs/security-audit.md`, 2026-05-27). No external penetration test has been conducted yet (see §10).

| ID  | Severity   | Title                                                          | Status                                     | Target resolution  |
| --- | ---------- | -------------------------------------------------------------- | ------------------------------------------ | ------------------ |
| F-1 | **Medium** | X-Forwarded-For IP spoofing in enforcement context             | Open                                       | Q2 2026            |
| F-2 | Low        | `http.DefaultClient` fallback without timeout in OIDC provider | Open                                       | Q2 2026            |
| F-3 | Low        | `math/rand/v2` used for token refresh jitter                   | Accepted (not a vulnerability in Go 1.22+) | No action required |
| F-4 | Low        | CORS wildcard allowed in production with warning only          | Open                                       | Q3 2026            |

### F-1 Detail — X-Forwarded-For IP Spoofing

The `extractClientIP` function in `internal/gateway/handlers.go` unconditionally trusts the `X-Forwarded-For` header when evaluating `ipRange` capability conditions. An attacker who can set this header (e.g., any client not behind a reverse proxy that strips it) can set an arbitrary source IP and satisfy IP-allowlist conditions.

**Impact:** An agent deployed in an environment that uses IP-range conditions as a security control (not just an operational convenience) can bypass those conditions by setting `X-Forwarded-For: <allowed-ip>`. Environments where the gateway is behind a trusted reverse proxy that sets and strips `X-Forwarded-For` are not affected.

**Interim mitigation:** Do not rely solely on `ipRange` conditions for security enforcement in environments where agents can set arbitrary HTTP headers. Deploy the gateway behind a trusted reverse proxy (Envoy, nginx, AWS ALB) that strips and rewrites `X-Forwarded-For`. Configure `TRUSTED_PROXY_CIDRS` (in development) once the fix ships.

**Planned fix:** Add `TrustedProxyCIDRs` configuration; only honor `X-Forwarded-For` when `RemoteAddr` matches a trusted proxy CIDR.

---

## 10. Third-Party Audit Status

| Engagement                                  | Scope                                                | Status                | Expected completion |
| ------------------------------------------- | ---------------------------------------------------- | --------------------- | ------------------- |
| Internal static analysis                    | Full Go codebase (`cmd/`, `internal/`, `pkg/`)       | Complete (2026-05-27) | See §9              |
| Penetration test — gateway enforcement path | Black-box + gray-box; token forge, bypass, injection | **Planned Q3 2026**   | 2026-08             |
| Penetration test — issuer and minter        | OIDC flow, policy manipulation, key exposure         | **Planned Q3 2026**   | 2026-08             |
| SOC 2 Type I readiness assessment           | Trust Service Criteria: Security, Availability       | **Planned Q4 2026**   | 2026-10             |
| SOC 2 Type II audit                         | 6-month observation period                           | **Planned H1 2027**   | 2027-06             |
| FIPS 140-2 cryptographic module validation  | Signing key operations, key storage                  | Under evaluation      | TBD                 |

We are committed to transparency about where we are in this process. The absence of a completed third-party penetration test does not mean eunox is untested — it means the independent validation timeline is honest. Security teams evaluating eunox for deployment before Q3 2026 should conduct their own assessment of the gateway and issuer using the information in this document.

To request the full internal audit report (`docs/security-audit.md`), access to a dedicated evaluation environment, or a security briefing call, contact security@eunolabs.com.

---

## 11. Change Log

| Version | Date       | Author                  | Changes             |
| ------- | ---------- | ----------------------- | ------------------- |
| 1.0     | 2026-05-28 | Eunox Platform Security | Initial publication |

---

_Questions or corrections: open a GitHub issue tagged `security`, or email security@eunolabs.com. For active vulnerability reports, use the GitHub private security advisory workflow._
