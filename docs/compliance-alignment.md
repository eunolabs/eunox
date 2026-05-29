# Compliance Alignment Matrix

> **Audience:** Security and compliance teams mapping Eunox controls to
> regulatory and framework requirements for SOC 2 Type II, HIPAA, NIST 800-207,
> and PCI-DSS audits.

---

## Overview

This matrix maps Eunox platform controls to specific requirements across four
compliance frameworks. Each row identifies the requirement, the Eunox control
that satisfies it, and the evidence location.

For each control, the "Evidence" column points to the artifact a compliance
reviewer can inspect: log fields, API endpoints, configuration, or documentation.

---

## SOC 2 Type II — CC6: Logical Access Controls

| Control | Requirement                                     | Eunox Control                                                                                                                                     | Evidence                                                                                                |
| ------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| CC6.1   | Restrict logical access to information assets   | Capability token enforcement: every tool call must present a valid capability token; default-deny policy blocks all uncredentialed requests       | `pkg/enforcement/engine.go:93` (default-deny); `docs/redis-failure-modes.md §Kill-Switch` (fail-closed) |
| CC6.2   | Identify and authenticate users prior to access | JWKS-verified JWTs with `sub` (agent identity) and `jti` (unique token ID); DPoP proof binding prevents replay                                    | `internal/gateway/handlers.go §handleEnforce`; `pkg/capability/token.go`                                |
| CC6.3   | Authorize access based on least privilege       | Capability token scopes limit tools and actions; conditions (time window, call count) further restrict; obligation engine enforces redaction      | `pkg/enforcement/engine.go`; `docs/capability-model.md`                                                 |
| CC6.4   | Remove access for terminated users/agents       | Kill-switch with sub-second propagation via Redis pub/sub; `KillAgent()` blocks all subsequent requests within < 5 ms                             | `pkg/killswitch/redis.go`; `docs/redis-failure-modes.md §Kill-Switch`                                   |
| CC6.5   | Control access by role                          | Admin API requires `X-Admin-Api-Key` or admin JWT (`GATEWAY_ADMIN_JWKS_URI`); enforcement API uses agent capability tokens; roles are distinct    | `internal/gateway/admin_jwt.go`; `docs/gateway-operator-runbook.md §Authentication`                     |
| CC6.6   | Restrict network access                         | Gateway is the single ingress point for all tool calls; direct backend access is blocked at network layer; sidecar mode binds to `127.0.0.1` only | `docs/deployment.md §Multi-AZ`; `docs/adr/001-sidecar-deployment-model.md`                              |
| CC6.7   | Restrict access changes                         | Policy hot-reload requires operator credentials; kill-switch and revocation operations require admin API key; audit log records all admin actions | `internal/gateway/admin_routes.go`; `pkg/audit/audit.go`                                                |
| CC6.8   | Detect and prevent unauthorized access          | Kill-switch, rate limiting, DPoP replay prevention, revocation store; all enforcement denials are recorded in the tamper-evident audit chain      | `pkg/killswitch/`; `pkg/revocation/`; `pkg/audit/`                                                      |

---

## HIPAA Security Rule — §164.312: Technical Safeguards

| Specification      | Requirement                                     | Eunox Control                                                                                                                                                    | Evidence                                                                  |
| ------------------ | ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| §164.312(a)(1)     | Access control — unique user identification     | Each capability token carries a unique `sub` (agent identity) and `jti` (token ID); all audit records include both fields                                        | `pkg/capability/token.go §Claims.AgentID`; `pkg/audit/audit.go §Record`   |
| §164.312(a)(1)     | Access control — automatic logoff               | Token TTL enforces time-bounded access; `GATEWAY_TOKEN_CACHE_TTL_SECONDS` ensures cached tokens expire; kill-switch provides immediate termination               | `pkg/capability/token.go §Claims.ExpiresAt`; `pkg/killswitch/`            |
| §164.312(a)(1)     | Access control — encryption and decryption      | Capability tokens are JWS-signed (RS256); DPoP proofs bind tokens to specific request keys; TLS required in production                                           | `internal/gateway/jwks_verifier.go`; `pkg/capability/proofs.go`           |
| §164.312(b)        | Audit controls — hardware and software activity | Every enforcement decision (allow and deny) is recorded in the tamper-evident audit chain with agent ID, session ID, tool, action, decision, and timestamp       | `pkg/audit/audit.go`; `GET /api/v1/audit/records`                         |
| §164.312(c)(1)     | Integrity — protect ePHI from alteration        | HMAC chain: each audit record includes the HMAC of the previous record; any record deletion or modification breaks the chain proof                               | `pkg/audit/transport.go §HMACTransport`; `GET /api/v1/audit/chain-proof`  |
| §164.312(d)        | Person authentication                           | Agent identity is cryptographically established via JWS signature over a key pair managed by the issuer; DPoP further binds the token to the agent's private key | `internal/gateway/handlers.go §handleEnforce`; `pkg/capability/proofs.go` |
| §164.312(e)(1)     | Transmission security — encryption              | TLS 1.2+ required for all gateway communication in production; enforced at startup via `GATEWAY_NODE_ENV=production` check                                       | `docs/deployment.md §TLS`; `cmd/gateway/main.go §validateConfig`          |
| §164.312(e)(2)(ii) | Encryption of ePHI at rest                      | Audit records in PostgreSQL: operators responsible for PostgreSQL-level encryption (`pg_crypto`, AWS RDS encryption at rest); documented in runbook              | `docs/gateway-operator-runbook.md §Data at Rest`                          |

---

## NIST SP 800-207: Zero Trust Architecture

| Section                                              | Principle                                          | Eunox Implementation                                                                                                     |
| ---------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------- |
| §2.1 — Tenant                                        | All resources are considered private and protected | Capability token required for every tool call; no unauthenticated bypass                                                 |
| §2.2 — All communication is authenticated            | All connections use verified identity              | JWKS-verified JWTs + DPoP; no anonymous enforcement                                                                      |
| §2.3 — Access per-session                            | Access granted per-request after verification      | Capability token evaluated on every enforcement request; no session-level authorization caching beyond `TOKEN_CACHE_TTL` |
| §2.4 — Dynamic policy with environmental observables | Policy evaluated with contextual conditions        | Condition engine: time-of-day, call count, resource match, network conditions                                            | `pkg/enforcement/conditions.go`                             |
| §2.5 — Monitor integrity and posture                 | Continuous monitoring of asset posture             | Kill-switch propagation; revocation store; chaos test coverage in `docs/chaos-results.md`                                |
| §2.6 — Authenticate and authorize dynamically        | Re-authenticate on each request                    | Enforcement call re-verifies token signature and revocation on every request (or within cache TTL)                       |
| §2.7 — Collect and improve security posture          | Feedback loop from audit data                      | Tamper-evident audit chain; `GET /api/v1/audit/records` for SIEM export                                                  |
| §3.3 — PEP/PDP architecture                          | Separate policy enforcement and decision           | Gateway is PEP (enforces decision); enforcement engine is PDP (evaluates policy); policy loaded from store               | `internal/gateway/handlers.go`; `pkg/enforcement/engine.go` |
| §5.2 — Deployment variations                         | Centralized and distributed PEP                    | Centralized (default) and sidecar (P3-2) topologies; see `docs/adr/001-sidecar-deployment-model.md`                      |

---

## PCI-DSS v4.0 — Requirement 10: Log and Monitor All Access

| Sub-requirement | Requirement                                                       | Eunox Control                                                                                                                                            | Evidence                                                                               |
| --------------- | ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| 10.2.1          | Log all individual user access to cardholder data                 | Every enforcement request (allow and deny) for tools with cardholder data access is logged with agent ID, session, tool, action, timestamp, and decision | `pkg/audit/audit.go §Record`; `GET /api/v1/audit/records`                              |
| 10.2.1.1        | Log all actions by individuals with root or administrative access | Admin API calls (kill-switch, revocation, policy management) are logged with `operatorId`                                                                | `internal/gateway/admin_routes.go`; admin audit fields                                 |
| 10.2.1.2        | Log all access to audit trails                                    | `/api/v1/audit/*` routes require authentication; access attempts logged                                                                                  | `internal/gateway/audit_routes.go §auditAuthMiddleware`                                |
| 10.2.1.3        | Log all invalid logical access attempts                           | All enforcement denials recorded; 401/403 responses include `request_id` for log correlation                                                             | `internal/gateway/handlers.go §handleEnforce`                                          |
| 10.2.1.5        | Log all changes to identification and authentication mechanisms   | Token issuance and revocation recorded; kill-switch activations recorded                                                                                 | `pkg/revocation/`; `pkg/killswitch/`                                                   |
| 10.3.2          | Protect audit logs from destruction and unauthorized modification | HMAC chain: each record signs the previous; any modification is detectable via `GET /api/v1/audit/chain-proof`                                           | `pkg/audit/transport.go §HMACTransport`                                                |
| 10.3.3          | Log files promptly backed up to a centralized server              | Async audit pipeline (`pkg/audit/async_pipeline.go`) buffers records durably; PostgreSQL provides ACID durability                                        | `pkg/audit/async_pipeline.go §Close` (drain on shutdown)                               |
| 10.4.1          | Examine logs for security events daily                            | SIEM export via `GET /api/v1/audit/export`; Prometheus metrics for enforcement totals and latency                                                        | `internal/gateway/audit_routes.go §handleAuditExport`; `internal/gateway/telemetry.go` |
| 10.5.1          | Retain audit logs for at least 12 months                          | Retention policy configured at PostgreSQL layer; `docs/gateway-operator-runbook.md §Audit Retention` documents recommended retention settings            | `docs/gateway-operator-runbook.md`                                                     |
| 10.7            | Detect and report failures of critical security controls          | Kill-switch health reported via readiness probe and Prometheus gauge; `docs/gateway-operator-runbook.md §Alert Rules` defines alert thresholds           | `pkg/redisfailover/`; `docs/gateway-operator-runbook.md §Prometheus Alert Rules`       |

---

## Compliance Control Summary

| Framework      | Requirements covered              | Requirements requiring operator action                          |
| -------------- | --------------------------------- | --------------------------------------------------------------- |
| SOC 2 CC6      | CC6.1–CC6.8 (8/8)                 | Network policy (CC6.6) — Kubernetes NetworkPolicy configuration |
| HIPAA §164.312 | All technical safeguards          | §164.312(e)(2)(ii) — PostgreSQL encryption at rest              |
| NIST 800-207   | All 7 tenets + §3.3 + §5.2        | §2.5 posture monitoring — integrate Prometheus with SIEM        |
| PCI-DSS 10     | 10.2.1–10.7 (11 sub-requirements) | 10.5.1 — configure PostgreSQL retention policy                  |

---

## How to Use This Matrix

**For a SOC 2 Type II audit:**

1. Provide the auditor with `GET /api/v1/audit/records?from=<period-start>` output
2. Demonstrate chain proof integrity: `GET /api/v1/audit/chain-proof`
3. Show kill-switch test: `POST /admin/v1/kill-switch/activate` → verify enforcement
   blocks → `POST /admin/v1/kill-switch/deactivate` → verify enforcement resumes
4. Provide `docs/gateway-operator-runbook.md` as the operational procedure evidence

**For a HIPAA Security Rule review:**

1. Demonstrate agent identity: show a decoded capability token `sub` field
2. Demonstrate audit completeness: show HMAC chain proof for a sample period
3. Provide TLS configuration evidence from production deployment manifests
4. Confirm PostgreSQL encryption at rest is enabled (operator responsibility)

**For a PCI-DSS assessment:**

1. Provide audit export (`/api/v1/audit/export`) for the cardholder data environment
2. Demonstrate HMAC chain tamper detection by submitting a modified record
3. Show Prometheus metrics for enforcement totals and kill-switch health
4. Confirm PostgreSQL retention policy satisfies 12-month requirement

---

## References

- `docs/redis-failure-modes.md` — failure mode policies for all dependencies
- `docs/deployment.md §Multi-AZ Reference Architecture`
- `docs/gateway-operator-runbook.md`
- `docs/runbooks/gateway-triage.md`
- `docs/adr/001-sidecar-deployment-model.md §(e) Compliance Implications`
- `pkg/audit/` — audit chain implementation
- `pkg/enforcement/engine.go` — default-deny enforcement
