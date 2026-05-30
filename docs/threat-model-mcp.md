# eunox-mcp — Threat Model

**Document status:** Active  
**Classification:** Public  
**Scope:** `eunox-mcp` proxy binary (`cmd/mcp/`)  
**Version:** 1.0  
**Date:** 2026-05-29  
**Authors:** Eunolabs Platform Security  
**Reviewers:** Pending external audit (see §6)

> This document is for enterprise security teams, architects, and compliance reviewers
> evaluating the `eunox-mcp` proxy for production deployment. It covers exactly what
> the proxy enforces, what it cannot enforce, and what happens when dependencies fail.
> For the full enterprise platform (Capability Issuer, Tool Gateway, control plane),
> see [threat-model.md](./threat-model.md).

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Trust Boundaries](#2-trust-boundaries)
3. [Attack Classes Mitigated](#3-attack-classes-mitigated)
4. [Explicit Out-of-Scope Threats](#4-explicit-out-of-scope-threats)
5. [Failure Modes and Resilience Posture](#5-failure-modes-and-resilience-posture)
6. [Data Classification and Handling](#6-data-classification-and-handling)
7. [Current Security Status](#7-current-security-status)
8. [Change Log](#8-change-log)

---

## 1. System Overview

`eunox-mcp` is a single binary that sits in-path between an MCP host (Claude Desktop,
an agent runtime, a test harness) and an MCP server (local subprocess or remote HTTP
endpoint). Every `tools/call` JSON-RPC message is evaluated against a policy before
it is forwarded. Calls that violate policy are blocked and logged; calls that are
permitted are forwarded and logged.

```
MCP host → eunox-mcp proxy → MCP server (subprocess or remote HTTP)
```

The proxy supports two transports:

| Transport | How the upstream MCP server is reached                                                |
| --------- | ------------------------------------------------------------------------------------- |
| `stdio`   | Upstream is a local subprocess; proxy bridges stdin/stdout                            |
| `http`    | Upstream is the proxy's HTTP listener; upstream is a subprocess (default) or a remote URL (`--upstream-url`) |

Three policy sources can be combined:

| Mode                         | How it is activated                          | What it enforces                               |
| ---------------------------- | -------------------------------------------- | ---------------------------------------------- |
| No policy (pass-through)     | Neither `--policy` nor `--jwks-uri` supplied | All tool calls forwarded without enforcement   |
| Manifest PDP                 | `--policy manifest.yaml`                     | Constraint file on disk                        |
| JWT PDP                      | `--jwks-uri` + optional `--jwt-issuer` / `--jwt-audience` | IdP-issued capability claims in bearer token |
| Manifest + JWT (intersection) | Both flags set                              | JWT can only narrow what the manifest permits  |

---

## 2. Trust Boundaries

### 2.1 What the proxy trusts after verification

| Item                                       | How trust is established                                                                        |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| JWT capability claims (`eunox.capabilities`, `eunox.task_id`, `eunox.agent_id`) | JWT signature verified against the JWKS endpoint; `exp`, `iss`, `aud` validated |
| Manifest policy file contents              | Loaded at startup from a local path the operator controls; not re-fetched at runtime            |
| Kill-switch state (in-memory or Redis)     | Checked on every `Decide()` call before capability evaluation                                  |
| Call counter state (in-memory or Redis)    | Checked on every `Decide()` call; enforces `maxCalls` conditions                               |

### 2.2 What the proxy verifies on every request

**JWT PDP mode** (`--jwks-uri` set):

1. `Authorization: Bearer <token>` header is present and well-formed.
2. JWT signature is valid against one of the keys in the cached JWKS (algorithm restricted to RS256/RS384/RS512, PS256/PS384/PS512, ES256/ES384/ES512, EdDSA — symmetric algorithms are unconditionally rejected).
3. `exp` has not passed (1-minute clock-skew tolerance applied).
4. `iss` matches `--jwt-issuer` (when configured).
5. `aud` contains `--jwt-audience` (when configured).
6. `eunox.capabilities` claim covers the requested tool name.
7. Any condition shorthand in the capability claim (path glob, SQL verb) matches the actual arguments.

**Manifest PDP** (`--policy` set):

1. Kill-switch state is not active for this session (checked first, before anything else).
2. A capability constraint in the manifest covers the tool name (glob match; no matching constraint → allow).
3. The constraint's `actions` list permits the call (exact match `"call"` / wildcard `"*"`, or semantic category via action resolver).
4. `argumentSchema` validation passes (JSON Schema subset: type, pattern, length, min/max, enum, required, properties, additionalProperties, items).
5. All attached conditions pass: `TimeWindow`, `IPRange`, `AllowedOperations`, `AllowedExtensions`, `AllowedTables`, `MaxCalls`, `RecipientDomain`, `RedactFields`, `AllowedValues`, `Policy`, `Custom`.

When both `--jwks-uri` and `--policy` are set, a call must pass **both** checks. The JWT can only narrow what the manifest permits — it cannot expand it.

### 2.3 What the proxy explicitly does not verify

| Item                                  | Why                                                                                              |
| ------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Content of LLM prompts or completions | The proxy operates at the tool-call protocol layer, not the inference layer                      |
| Reason the agent decided to call a tool | Intent is opaque; the proxy enforces *what* is called, not *why*                               |
| Integrity of the MCP server's response | The proxy forwards upstream responses verbatim (except `RedactFields` obligations)              |
| Integrity of the agent process        | Host OS/container responsibility; the proxy cannot attest client-side code                      |
| Content of tool call arguments (semantically) | The proxy validates argument *shape* (schema) and specific *values* (allowedValues), not meaning |
| IdP infrastructure security           | The proxy trusts JWTs that pass signature verification; IdP compromise is out of scope          |

### 2.4 Trust boundary diagram

```
╔══════════════════════════════════════════════════════════════╗
║  VERIFIED — proxy makes an explicit security check           ║
║                                                              ║
║  • JWT signature (JWKS, asymmetric algorithms only)          ║
║  • JWT expiry, issuer, audience                              ║
║  • Capability claims (tool name coverage, condition params)  ║
║  • Argument schema (JSON Schema subset)                      ║
║  • Kill-switch state (per-session, global)                   ║
║  • MaxCalls sliding-window quota                             ║
║  • HMAC-SHA256 signature on each audit record                ║
╚══════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════╗
║  TRUSTED WITHOUT RE-VERIFICATION                             ║
║                                                              ║
║  • Manifest policy file (operator-controlled path on disk)   ║
║  • Upstream MCP server responses                             ║
║  • Loopback-only /control/kill API (IP check only)           ║
╚══════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════╗
║  EXPLICITLY UNTRUSTED — proxy makes no assertion here        ║
║                                                              ║
║  • LLM prompt and completion content                         ║
║  • Agent process integrity                                   ║
║  • Client-side token storage                                 ║
║  • Semantic meaning of tool call arguments                   ║
║  • Security of the IdP infrastructure                        ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 3. Attack Classes Mitigated

### 3.1 Capability Claim Forgery

**Attack:** An attacker crafts or modifies a JWT to include capability claims (`eunox.capabilities`) for tools they are not permitted to call — for example, adding `"write_file"` to a token that was issued with only `"read_file"`.

**Mitigation:** JWT signature validation using the JWKS fetched from `--jwks-uri`. The proxy:

- Accepts only asymmetric algorithms (RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA). Symmetric algorithms (HS256, HS384, HS512) and the `none` algorithm are rejected unconditionally by the go-jose/v4 parser.
- Rejects tokens whose `kid` does not appear in the cached JWKS; performs an immediate forced re-fetch in case the IdP rotated keys before falling back to rejection.
- Deduplicates concurrent JWKS fetches using a singleflight implementation, preventing thundering-herd behaviour on key rotation.
- Applies a 1-minute clock-skew tolerance on `exp` validation.

Any modification to the JWT payload invalidates the signature, and the modified token is rejected before its claims are read.

**Residual risk:** A compromised IdP can issue arbitrary tokens that pass signature verification. IdP security is explicitly out of scope (§4.4).

---

### 3.2 Tool Call Parameter Injection

**Attack:** An agent (or an adversary that has influenced the agent) calls a permitted tool with arguments that exceed the intended scope — for example, calling `read_file` with `path=/etc/shadow` when the policy was intended to permit only `/reports/*`.

**Mitigation (argument schema validation):** The manifest's `argumentSchema` field applies a JSON Schema subset to the actual arguments of every tool call before the call is forwarded. The validator covers: `type`, `pattern` (regexp), `minLength`, `maxLength`, `minimum`, `maximum`, `required`, `enum`, `properties`, `additionalProperties`, `items`, `minItems`, `maxItems`. A call that fails schema validation is denied with code `ARGUMENT_VALIDATION_FAILED` before reaching the upstream server.

**Mitigation (condition types):** Several built-in condition types enforce argument-level restrictions directly:

| Condition            | What it restricts                                         |
| -------------------- | --------------------------------------------------------- |
| `allowedValues`      | Argument value must match one of the allowed strings or globs (e.g., `path` must match `/reports/*`) |
| `allowedOperations`  | SQL verb in `sql`/`query`/`statement` argument must be in the permitted set (`SELECT`, not `DROP`) |
| `allowedTables`      | Table names referenced in the call must be in the permitted set |
| `allowedExtensions`  | File extension of the `path` argument must be in the permitted set |
| `recipientDomain`    | Email recipients must belong to the permitted domain      |

**Mitigation (JWT condition shorthands):** In JWT PDP mode, capability claim shorthands enforce argument-level restrictions inline: `"read_file:/reports/*"` restricts the `path` argument to the glob `/reports/*`; `"query_db:SELECT"` restricts the SQL operation.

---

### 3.3 Session Hijacking via Session-ID Spoofing

**Attack:** A malicious client presents an existing session ID in the `Mcp-Session-Id` HTTP header to impersonate an authenticated session and perform tool calls under that session's policy context.

**Mitigation:** Session IDs are UUID v4 values minted by the proxy at session creation. An attacker who does not know a valid session ID cannot successfully route a request. The proxy validates the session ID against its in-memory session registry on every request; unknown session IDs receive 404.

**Kill-switch binding:** When a session is killed (via `eunox-mcp kill <session-id>` or the `/control/kill` API), the session ID is registered in the kill-switch store. Every subsequent `Decide()` call checks kill-switch state first, before evaluating capability conditions. A session whose ID has been killed is denied regardless of whether a valid JWT or manifest policy would otherwise permit the call.

The `/control/kill` HTTP endpoint is restricted to loopback addresses only (`127.0.0.1`, `::1`) — any request from a non-loopback source is rejected with 403.

**Limitation:** The proxy does not implement token binding between the bearer JWT and the session ID. An attacker who learns both a valid JWT and a valid session ID could make requests. This is the tradeoff of the MCP session model; mitigate in high-security environments by enabling `--auth-token` to add a shared secret layer on the proxy's HTTP listener.

---

### 3.4 Audit Log Tampering

**Attack:** An attacker with local filesystem access modifies or deletes audit records in `~/.eunox/audit.jsonl` to conceal unauthorized tool calls or suppress evidence of policy violations.

**Mitigation (HMAC-SHA256 per-record signing):** Each audit record is signed with HMAC-SHA256 using a 256-bit key loaded from `~/.eunox/audit.key`. The HMAC covers the full record JSON excluding the `_hmac` field itself. The signature is appended as `"_hmac": "sha256:<hex>"` before the record is written.

Tampering with any field in a record produces an HMAC mismatch. The `eunox-mcp validate-token` subcommand reads the log, recomputes the HMAC for every record, and reports any mismatches:

```
$ eunox-mcp validate-token
Checked 142 record(s): 142 valid, 0 invalid, 0 skipped.
```

The audit key is generated once at first startup using `crypto/rand` (Go's CSPRNG, backed by the OS entropy source) and stored at `~/.eunox/audit.key` with mode `0600`. Loss of the key means existing records cannot be re-verified, but does not affect enforcement.

**Residual risk:** The HMAC key is stored on the same machine as the log file. An attacker with read access to `~/.eunox/audit.key` can forge records that pass HMAC verification. For regulated environments requiring tamper evidence against a privileged local attacker, configure the proxy to ship audit records to an external sink (SIEM, append-only object storage) in real time.

---

### 3.5 Credential Overprivilege

**Attack:** An agent accumulates broader API access than any specific task requires because credentials are issued for the user's full role rather than for the current task's scope.

**Mitigation (JWT PDP mode):** When the IdP is configured to inject `eunox.capabilities` claims into access tokens, the proxy enforces the task-scoped capability set rather than the full role. The JWT carries exactly what this agent invocation is permitted to call — `"read_file:/reports/*"`, not `"*"`. Calls to any tool not listed in the capability claims are denied with `CAPABILITY_NOT_GRANTED`.

**Mitigation (manifest + JWT intersection):** When `--policy` is also set, the proxy computes the intersection: a tool call must be permitted by **both** the manifest constraints and the JWT capability claims. The JWT can only restrict what the manifest allows; it cannot expand it. This prevents a misconfigured IdP from accidentally granting broader access than the manifest operator intended.

**Mitigation (MaxCalls condition):** The `maxCalls` condition limits how many times a tool can be called within a sliding time window. For tools that retrieve credentials or sensitive resources, a `maxCalls: 1` limit bounds the privilege exposure window to a single use per session, regardless of token TTL.

---

### 3.6 Unbounded Tool Call Rate

**Attack:** An agent (or a prompt-injected agent) calls a tool in a tight loop, causing backend resource exhaustion, runaway API costs, or unintended mass operations.

**Mitigation:** The `maxCalls` condition type enforces a call-count ceiling within a configurable sliding window per session. The counter is backed by:

- **In-memory store (default):** Counter resets on proxy restart. Sufficient for single-instance, short-session deployments.
- **Redis store (`--redis-addr`):** Counter survives proxy restarts and is shared across multiple proxy instances. Suitable for persistent or multi-replica deployments.

When the limit is reached, the call is denied with code `MAX_CALLS_EXCEEDED` and the block is recorded in the audit log. The counter increment is not applied in dry-run mode (`--dry-run`), allowing observation of what would be blocked without affecting the count.

---

## 4. Explicit Out-of-Scope Threats

These attack classes are outside the proxy's enforcement boundary. This is not a gap to be filled — it reflects that these threats require controls at a different layer.

### 4.1 Prompt Injection

**What it is:** Malicious instructions embedded in data the LLM reads (documents, API responses, database records) cause the agent to issue tool calls that the legitimate user did not intend.

**Why it is out of scope:** The proxy enforces *what the agent is permitted to call*, not *why the agent decided to call it*. A prompt-injected call to `read_file("/reports/Q4.pdf")` is indistinguishable from a legitimate one at the JSON-RPC layer, and will be allowed if the capability token permits it.

**What the proxy does reduce (but does not eliminate):** By scoping capabilities to specific resources and argument patterns, the proxy limits the blast radius of a successful injection. An injected agent cannot exfiltrate data from resources outside its `eunox.capabilities` scope, and cannot call tools not listed in its manifest constraints.

**Recommended complementary control:** Input sanitization and content scanning at the application layer before feeding external data to the agent. The proxy is a last line of defense on tool calls, not a substitute for application-level sanitization.

---

### 4.2 Model Jailbreak

**What it is:** Adversarial prompting causes the LLM to disregard its system prompt or produce harmful outputs.

**Why it is out of scope:** Jailbreak is a property of the model's response to inputs. The proxy does not inspect model inputs or outputs. As with prompt injection (§4.1), the proxy reduces blast radius by enforcing capability constraints on whatever the jailbroken model instructs the agent to call.

---

### 4.3 Client-Side Agent Code Compromise

**What it is:** An attacker compromises the agent process — the Python runtime, the Node.js process, the container — and extracts the bearer JWT or the session ID from memory.

**Why it is out of scope:** The proxy cannot attest the integrity of a client process. Process isolation and host security are the responsible controls here.

**What the proxy does reduce:** Short-lived JWTs bound by `exp` limit the useful window of a stolen token. The kill-switch provides immediate revocation once compromise is detected.

---

### 4.4 IdP Compromise

**What it is:** The identity provider that issues JWTs with `eunox.capabilities` claims is compromised, allowing an attacker to mint arbitrary tokens.

**Why it is out of scope:** The proxy trusts any JWT that passes signature verification against the IdP's JWKS. An attacker who can issue valid signed JWTs from the IdP can call any tool they include in the capability claims. The proxy is not in a position to second-guess the IdP's issuance decisions.

**Mitigation the manifest provides:** When `--policy` is also configured, the manifest acts as a second envelope. Even a fully compromised IdP cannot grant more than the manifest allows, because the intersection logic ensures the manifest is the ceiling.

---

### 4.5 Backend Service Vulnerabilities

**What it is:** A backend that the proxy forwards authorized calls to contains its own vulnerability — SQL injection, IDOR, privilege escalation within the backend service.

**Why it is out of scope:** The proxy enforces capability policy in front of backends. It does not perform DAST or runtime security testing of the backends it proxies to. Backends are responsible for their own internal security posture.

---

## 5. Failure Modes and Resilience Posture

The proxy defaults to **fail-closed**: when a dependency required for a security decision is unavailable, the default is to deny rather than allow. The exceptions are documented explicitly below, with the security tradeoff stated plainly.

### 5.1 Proxy Crash

**Observed behavior:** The process exits. The upstream MCP server receives no further traffic. No tool calls are forwarded.

**Security posture:** Fail-closed by nature of being in the request path. The agent runtime receives a connection error and the task fails.

**Recovery:** Restart the proxy binary. In-memory state (call counters, kill-switch) is reset on restart. If persistence is required, configure `--redis-addr` before deploying.

---

### 5.2 JWKS Endpoint Unreachable

**Observed behavior:** The proxy uses its in-process JWKS cache. Tokens signed with a key that is in the cache are accepted normally. Tokens whose `kid` is not in the cache trigger a force-refresh attempt; if the re-fetch fails, the token is rejected with 401.

**Cache TTL:** 5 minutes by default (configurable). When the cache expires and the endpoint is still unreachable, the next token validation that requires a key not in the cache will fail closed.

**Security posture:** Cached-then-fail-closed. A proxy that has already fetched the JWKS can continue to enforce for up to the cache TTL without the IdP being reachable. This is intentional: it prevents an IdP outage from causing an immediate enforcement outage. However, key rotation events that require a new `kid` are blocked during the outage window.

**Recovery:** JWKS endpoint recovery is transparent. The next forced re-fetch (triggered by a token with a `kid` not in cache) restores normal operation immediately.

---

### 5.3 Redis Unavailable (When `--redis-addr` Is Configured)

When Redis is configured, it backs two enforcement functions:

| Function           | Redis unavailable behavior                                                                                   |
| ------------------ | ------------------------------------------------------------------------------------------------------------ |
| `MaxCalls` counter | The enforcement engine returns an error for `MaxCalls` conditions; the PDP denies the call with `ENFORCEMENT_ERROR` |
| Kill-switch state  | The proxy falls back to the in-memory kill-switch state at the time Redis became unavailable                 |

**Security implication of kill-switch fallback:** A kill-switch that was activated *before* Redis became unavailable remains active in the in-process state. A kill-switch activated *after* Redis became unavailable will not take effect until Redis recovers. This is a known gap: if you need immediate kill-switch propagation across a Redis outage, deploy a local sidecar proxy per instance with its own in-memory state.

**Security implication of MaxCalls denial:** When Redis is unavailable, `MaxCalls` conditions fail closed — calls are denied rather than allowed without a counter check. This is conservative and may cause false positives during Redis outages, but it prevents unbounded call rates.

**Recovery:** Redis recovery is transparent. The Redis-backed stores resume their normal role immediately.

---

### 5.4 Audit Log Write Failure

**Observed behavior:** If writing an audit record fails (disk full, permission error, file descriptor limit), the error is logged to stderr:

```
[eunox-mcp] audit write error: <reason>
```

Enforcement continues. The tool call result (allow or deny) is still applied to the upstream and returned to the client. The audit record for that call is lost.

**Security tradeoff — documented explicitly:** Audit log write failure does not block enforcement. This is a deliberate design decision: dropping production traffic because the local audit log is full would be worse than a partial audit trail gap in most deployment contexts. Operators who require guaranteed audit completeness should:

1. Monitor disk space on the machine running the proxy.
2. Ship audit records to an external sink (SIEM, object storage) by tailing `~/.eunox/audit.jsonl` with a log shipper.
3. Set the `--audit-rotate-size` flag to match available disk space (default: 100 MiB auto-rotation).

Use `eunox-mcp validate-token` to detect HMAC verification failures in existing records; it cannot detect *missing* records caused by write failures.

---

### 5.5 Upstream MCP Server Unavailable

**Observed behavior:** If the upstream subprocess fails to start or a remote `--upstream-url` is unreachable, the session initialization fails and the client receives an HTTP 500 with the error message.

For in-session failures (upstream dies after initialization), the next tool call that attempts to reach the upstream returns an `UPSTREAM_ERROR` JSON-RPC result and an audit record is written with that denial code.

**Security posture:** Fail-closed on upstream errors. An unreachable upstream does not cause the proxy to bypass enforcement — it causes the call to be denied with an infrastructure error code distinct from policy denial codes.

---

## 6. Data Classification and Handling

### 6.1 What appears in every audit record

The proxy writes one OCSF-based audit record per `tools/call` decision to `~/.eunox/audit.jsonl` (configurable via `--audit-log`).

| Field             | Type    | Example                              | Notes                                |
| ----------------- | ------- | ------------------------------------ | ------------------------------------ |
| `class_uid`       | int     | `6003`                               | OCSF class: API Activity             |
| `category_uid`    | int     | `6`                                  | OCSF category: Application Activity  |
| `activity_id`     | int     | `1` (allow) or `2` (deny)           | OCSF activity encoding               |
| `time`            | string  | `"2026-05-29T14:32:11.421Z"`         | RFC3339Nano, UTC                     |
| `request_id`      | string  | `"d3b07384-d113-..."`                | UUID v4, unique per record           |
| `session_id`      | string  | `"a1b2c3d4-..."`                     | Proxy-minted UUID v4                 |
| `tool_name`       | string  | `"read_file"`                        | Name of the MCP tool called          |
| `decision`        | string  | `"allow"` or `"deny"`               |                                      |
| `dry_run`         | bool    | `true`                               | Present only when `--dry-run` is set |
| `denial_code`     | string  | `"CAPABILITY_NOT_GRANTED"`           | Omitted on allow                     |
| `condition_type`  | string  | `"allowedValues"`                    | Omitted on allow; which condition triggered the denial |
| `details`         | object  | `{"error": "..."}`                   | Condition-specific detail; omitted when empty |
| `obligations`     | array   | `["redactFields"]`                   | Obligations applied to the response; omitted when empty |
| `_hmac`           | string  | `"sha256:3a7b..."`                   | HMAC-SHA256 over all other fields    |

### 6.2 What the proxy never logs

| Data                              | Why                                                                                   |
| --------------------------------- | ------------------------------------------------------------------------------------- |
| Tool call argument values         | May contain PII, PHI, credentials, or proprietary data; never written to the log     |
| Bearer JWT content                | Contains identity claims; logging would create a replay window                        |
| `--auth-token` value              | Operator credential; never echoed in logs                                             |
| `--upstream-auth-header` value    | Upstream credential; never echoed in logs                                             |
| `--redis-password` value          | Infrastructure credential; never echoed in logs                                       |
| Upstream MCP server responses     | May contain sensitive data; forwarded to client, not logged                           |
| HMAC key (`~/.eunox/audit.key`)   | Never logged; only used in-process for signing                                        |

### 6.3 Argument redaction via `RedactFields`

When a manifest constraint includes a `redactFields` obligation (e.g., `{"type": "redactFields", "fields": ["$.ssn", "$.card_number"]}`), the proxy removes those dot-path fields from the tool call *result* returned to the MCP host before forwarding it. The redaction is applied to JSON text content blocks in the upstream response.

Redaction affects the data the MCP host sees, not the audit log (which logs obligations applied, but not argument values). This allows operators to build audit trails that record *that* a tool was called without capturing which specific sensitive fields it returned.

### 6.4 Data residency in default configuration

In the default configuration, all data stays on the machine running the proxy:

| Data                        | Location                              |
| --------------------------- | ------------------------------------- |
| Audit records               | `~/.eunox/audit.jsonl` (local file)   |
| HMAC signing key            | `~/.eunox/audit.key` (local file)     |
| Kill-switch state           | In-process memory                     |
| Call counter state          | In-process memory                     |
| JWKS cache                  | In-process memory                     |
| Policy manifest             | Local file path provided by operator  |

When `--redis-addr` is configured, kill-switch and call-counter state are persisted to the Redis instance at that address. When a remote `--upstream-url` is configured, tool call requests are forwarded to that URL (with the `--upstream-auth-header` if provided). No other data is transmitted externally by the proxy.

---

## 7. Current Security Status

### 7.1 Audit status

| Engagement                    | Scope                                       | Status              | Expected completion |
| ----------------------------- | ------------------------------------------- | ------------------- | ------------------- |
| Internal code review          | `cmd/mcp/` and its `pkg/` dependencies      | Ongoing             | Continuous          |
| External penetration test     | Black-box JWT bypass, argument injection, audit HMAC | **Planned post-Stage 2** | 2026-Q4 |
| SOC 2 readiness               | N/A for the proxy binary (single-binary OSS tool) | Not applicable | —                  |

No external security audit of the `eunox-mcp` proxy has been completed. This document is the primary public security reference for the proxy until an external assessment is published at `docs/security-review.md`.

Security teams evaluating the proxy for production deployment before the external audit completes should conduct their own review. The source code is available at `cmd/mcp/` and its dependency packages under `pkg/enforcement/`, `pkg/capability/`, `pkg/killswitch/`, and `pkg/callcounter/`. The JWKS validation, JWT claim parsing, and argument schema evaluation paths are the highest-priority areas for independent review.

### 7.2 Known limitations and open items

| ID  | Area                  | Description                                                                                                  | Severity   | Status |
| --- | --------------------- | ------------------------------------------------------------------------------------------------------------ | ---------- | ------ |
| L-1 | Session binding       | No cryptographic binding between bearer JWT and session ID (§3.3). Mitigated by `--auth-token` for HTTP transport. | Low | Open |
| L-2 | Kill-switch gap       | Kill switches activated during a Redis outage do not propagate until Redis recovers (§5.3).                  | Low        | Open   |
| L-3 | Audit completeness    | Write failures produce a gap in the audit trail without blocking enforcement (§5.4). Mitigated by external log shipping. | Info | Accepted — documented tradeoff |
| L-4 | SSE notifications     | SSE notifications from a remote `--upstream-url` are not forwarded to the client (MVP limitation, documented in `http_remote.go`). | Info | Deferred to post-MVP |
| L-5 | X-Forwarded-For trust | When `--trust-forwarded-for` is enabled without a trusted-proxy CIDR restriction, clients can spoof source IP for `IPRange` conditions. | Medium | Open — only enable `--trust-forwarded-for` when the proxy is behind a trusted reverse proxy that strips and rewrites the header |

### 7.3 Reporting security issues

To report a security issue:

- **GitHub private security advisory:** preferred for vulnerability reports (creates a private discussion before public disclosure).
- **Email:** security@eunolabs.com — for issues where a GitHub advisory is not appropriate.

We aim to acknowledge security reports within 48 hours and to provide an initial assessment within 7 business days.

---

## 8. Change Log

| Version | Date       | Author                  | Changes             |
| ------- | ---------- | ----------------------- | ------------------- |
| 1.0     | 2026-05-29 | Eunolabs Platform Security | Initial publication covering T-01 through T-04 feature set |

---

_Questions or corrections: open a GitHub issue tagged `security`, or email security@eunolabs.com._
