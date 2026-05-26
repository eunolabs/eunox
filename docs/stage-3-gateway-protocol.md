# Stage-3 Gateway Enforcement Protocol

> **Version:** 1 (current)
> **Status:** Implemented — `tool-gateway@0.1.0`, `@euno/mcp` Stage-3
> **RFC anchor:** `docs/stage-3-design.md` §6 "Enforcer Wire Protocol"
> **Execution plan task:** `docs/stage3executionplan.md` §Task 9

---

## Overview

`@euno/mcp` running in remote-enforcer mode (`enforcer: "https://..."`) forwards
each intercepted `tools/call` request to the gateway's hosted enforcement
endpoint and applies the returned obligations locally. This document is the
authoritative specification of that HTTP contract.

The canonical type definitions live in
`pkg//src/wire.ts` — `EnforceRequest`, `EnforceRequestContext`,
`EnforceResponse`, `Obligation`, `DenialInfo` — so both the gateway
(`tool-gateway`) and the client (`@euno/mcp`) compile against the same types
without duplication. Any change to those types MUST land in `@euno/common-core`
first (per the cross-cutting obligation in `docs/stage3executionplan.md`).

---

## 1. Configuration

`@euno/mcp` accepts two syntactically equivalent enforcer configuration forms.
The flat form is the canonical user-facing shape (see `docs/mvp.md` line 633).

```jsonc
// Stage 1–2: local enforcement (default — no change required)
{ "enforcer": "local" }

// Stage 3: remote gateway — flat form (canonical)
{
  "enforcer": "https://gateway.euno.example",
  "apiKey": "sk-x7Kp9mRq.bL3nYv2wQsT6dFhG8jZcAiUeR1oP4mKxN5yW7uE0tBpV9gC",
  "enforcerTimeoutMs": 5000
}

// Stage 3: remote gateway — nested-object form (equivalent, optional)
{
  "enforcer": {
    "url": "https://gateway.euno.example",
    "apiKey": "sk-x7Kp9mRq.bL3nYv2wQsT6dFhG8jZcAiUeR1oP4mKxN5yW7uE0tBpV9gC",
    "timeoutMs": 5000
  }
}
```

**Parsing rule:** When `enforcer` is a non-`"local"` string it is the gateway
URL (flat form) and `apiKey` is read from the sibling field. When `enforcer` is
an object it is the nested form. The string `"local"` triggers the existing
in-process enforcement path unchanged.

---

## 2. Endpoint

### Deployment topology and authentication

This endpoint is the **internal** (post-minter) leg of the enforcement call. It
**always** receives a JWT Bearer token in `Authorization`. The `sk-…` API key
that `@euno/mcp` presents in the hosted deployment is handled by the minter
façade (Task 10) before requests arrive here — the façade exchanges the API key
for a short-lived JWT and then forwards this endpoint's JWT-authenticated call.
Self-hosted deployments skip the façade and send the operator's issuer JWT
directly.

```
POST /api/v1/enforce
Host: gateway.euno.example
Authorization: Bearer <jwt-capability-token>   ← JWT in both topologies
Content-Type: application/json
Accept: application/json
X-Euno-Protocol-Version: 1
X-Request-Id: <uuid>   (optional; reflected verbatim in the response)
```

**Hosted deployment (API key path):**
```
@euno/mcp ──(sk-…)──► minter façade ──(JWT)──► /api/v1/enforce
```

**Self-hosted deployment (direct JWT):**
```
@euno/mcp ──(JWT from operator's issuer)──► /api/v1/enforce
```

---

## 3. Request Body

```typescript
/**
 * Defined in pkg//src/wire.ts — EnforceRequest
 */
interface EnforceRequest {
  /** MCP session ID from the initialize handshake. */
  sessionId: string;

  /** MCP tool name exactly as sent in tools/call. */
  toolName: string;

  /**
   * Raw arguments object from the tools/call request. MUST be
   * JSON-serialisable; binary values should be base64-encoded strings.
   */
  arguments: Record<string, unknown>;

  /** Per-request context for condition evaluation. */
  context: EnforceRequestContext;
}

interface EnforceRequestContext {
  /**
   * Source IP of the MCP client (no IPv4-mapped prefix).
   * In Cloud, the edge overwrites caller-supplied values from the
   * observed connection. Omit for stdio-transport requests.
   */
  sourceIp?: string;

  /**
   * Recipient addresses extracted from the tool arguments
   * (to/recipients/cc/bcc fields).
   */
  recipients?: string[];

  /**
   * Wall-clock time of the request (ISO-8601). Recorded in the audit
   * event; NOT used for timeWindow enforcement on the hosted service.
   * Divergence > 60 s from the gateway clock → INVALID_REQUEST.
   */
  now?: string;
}
```

**Size limit:** 512 KiB. Requests exceeding this limit receive HTTP 413 with
`REQUEST_TOO_LARGE`.

### Field presence rules

| Condition type     | Required `context` field | Denial when absent |
|--------------------|--------------------------|-------------------|
| `ipRange`          | `sourceIp`               | `MISSING_CONTEXT` |
| `recipientDomain`  | `recipients`             | `MISSING_CONTEXT` |
| `timeWindow`       | *(uses gateway clock)*   | — (never absent)  |
| All others         | none                     | —                 |

---

## 4. Response Body

```typescript
/**
 * Defined in pkg//src/wire.ts — EnforceResponse
 */
interface EnforceResponse {
  /**
   * Echoes X-Request-Id, or a gateway-generated UUID.
   * Callers SHOULD log this for cross-system audit correlation.
   */
  requestId: string;

  /** Enforcement decision. */
  decision: 'allow' | 'deny';

  /**
   * Obligations to apply before returning the upstream response to
   * the MCP client. Present only when decision is 'allow'.
   */
  obligations?: Obligation[];

  /**
   * Denial details. Present only when decision is 'deny'.
   */
  denial?: DenialInfo;

  /**
   * ISO-8601 timestamp of the decision (gateway clock).
   * Callers may populate activityTime in their own audit event.
   */
  decidedAt: string;
}

type Obligation =
  | { type: 'redactFields'; paths: string[] }
  | { type: 'annotate'; key: string; value: string };

interface DenialInfo {
  /** Machine-readable code from ErrorCode in @euno/common. */
  code: string;

  /**
   * Condition type that triggered the denial, or 'killSwitch' /
   * 'policy' / 'tokenVerification' for non-condition denials.
   */
  conditionType: string;

  /** Human-readable message — server logs only; MUST NOT reach end users. */
  message: string;

  /** Optional structured details (see §4.1). */
  details?: Record<string, unknown>;
}
```

### 4.1 Obligation types

| `type`         | Fields          | Semantics                                              |
|----------------|-----------------|--------------------------------------------------------|
| `redactFields` | `paths: string[]` | Strip the listed dotted-path fields from the upstream response before it reaches the MCP client. Applied in listed order. |
| `annotate`     | `key`, `value`  | Attach `key=value` metadata to the caller's own audit event for this tool call. |

### 4.2 DenialInfo details by condition

| Condition / code           | `details` shape                                                |
|----------------------------|----------------------------------------------------------------|
| `argumentSchema`           | `{ schemaErrors: Array<{ path: string, message: string }> }`  |
| `ipRange`                  | `{ sourceIp: string, allowedRanges: string[] }`               |
| `maxCalls`                 | `{ currentCount: number, maxCalls: number, windowSeconds: number }` |

---

## 5. HTTP Status Codes

| Situation                                           | Status | Error code in body              |
|-----------------------------------------------------|--------|---------------------------------|
| Decision reached (allow or deny)                    | 200    | — (use `decision` field)        |
| Missing or invalid API key                          | 401    | `AUTHENTICATION_FAILED`         |
| Valid key but insufficient scope                    | 403    | `PERMISSION_DENIED`             |
| Request body malformed / missing required fields    | 400    | `INVALID_REQUEST`               |
| Request body exceeds 512 KiB                        | 413    | `REQUEST_TOO_LARGE`             |
| Gateway circuit open or temporary overload          | 503    | `GATEWAY_UNAVAILABLE`           |
| `X-Euno-Protocol-Version` not in supported set      | 400    | `UNSUPPORTED_PROTOCOL_VERSION`  |

All non-200 error responses use the shared envelope:

```typescript
interface ErrorResponse {
  error: {
    code: string;
    message: string;
    requestId?: string;
    /** Only present on UNSUPPORTED_PROTOCOL_VERSION */
    supportedVersions?: number[];
  };
}
```

---

## 6. Protocol Versioning

The `X-Euno-Protocol-Version` header carries a monotonic positive integer.
The gateway echoes the negotiated version in the same response header.

**Current version:** `1`

**Compatibility rules:**

1. The gateway MUST accept every version it has ever published.
2. When a client sends an unsupported version, the gateway returns HTTP 400
   with `UNSUPPORTED_PROTOCOL_VERSION` and a `supportedVersions` array in the
   error body, so the client can surface an actionable upgrade message.
3. Bumping the protocol version requires a **deprecation window of ≥1 minor
   `@euno/mcp` release** during which the gateway serves both versions.
4. Deprecated versions are announced per-response via the
   `X-Euno-Deprecation: version=<N>; sunset=<ISO-8601-date>` response header.
5. `@euno/mcp` sends the highest version it supports. The gateway responds on
   the received version, so no explicit negotiation round-trip is needed.
6. When a server-side translator is in place (§6.1), it translates the old
   version request into the current internal representation and translates the
   response back, so the versioned boundary is contained in the route handler.

### 6.1 Server-side translator contract

When version `N+1` is introduced:

- A `translateV<N>Request(raw)` function converts an old request into the
  internal `EnforceRequest` shape (additions get defaults, removed fields are
  dropped).
- A `translateV<N>Response(internal)` function converts the internal
  `EnforceResponse` back to the old response shape (new fields omitted).
- Both functions live in `tool-gateway/src/routes/enforce-compat.ts`.
- They remain in place until the deprecated version is retired.

---

## 7. Authentication and Session Lifecycle

1. `@euno/mcp` starts with an `enforcer` config containing the gateway URL and
   API key (`sk-<p8>.<s48>`).
2. On each intercepted `tools/call`, the proxy constructs an `EnforceRequest`
   and sends it to `POST /api/v1/enforce` with the API key in `Authorization`.
3. The hosted minter façade verifies the API key (see `docs/stage-3-design.md`
   §5.3), loads `(tenant_id, policy_id, policy_hash)`, signs a ≤5 min
   capability JWT with the tenant's HSM key, and writes the mint-audit row.
4. The façade forwards the request to the internal gateway with the capability
   JWT. The internal gateway runs the full PDP (token verification → kill-switch
   → conditions) and returns a decision.
5. The proxy applies returned obligations before forwarding the upstream response
   to the MCP client (`allow`), or returns a structured denial to the MCP client
   (`deny`).
6. The gateway writes an OCSF audit event **before** returning the enforcement
   response. The proxy does NOT write a duplicate local audit record for the same
   tool call (to avoid double-counting). The `requestId` in the response is logged
   by the proxy for cross-system correlation.

**Timeout:** The gateway MUST return a response within `enforcerTimeoutMs`
(default 5 000 ms). If the timeout elapses, `@euno/mcp` falls back to
**deny-by-default** and surfaces `GATEWAY_UNAVAILABLE` to the MCP client.
There is no fail-open path on timeout.

---

## 8. Policy Caching

The gateway caches the resolved `AgentCapabilityManifest` keyed by
`(tenant_id, policy_id, policy_hash)` with a 60-second TTL. Cache
invalidation is triggered by:

- TTL expiry.
- Admin API call `POST /admin/v1/policies/:id/invalidate`.
- Kill-switch activation (propagated via Redis pub/sub within milliseconds;
  the policy cache is a separate concern).

---

## 9. Error-Class Taxonomy

| Class                    | Codes                                                                 | Retry?                  |
|--------------------------|-----------------------------------------------------------------------|-------------------------|
| Authentication           | `AUTHENTICATION_FAILED`                                               | No — fix the API key    |
| Authorization            | `PERMISSION_DENIED`                                                   | No — fix the key scopes |
| Protocol                 | `UNSUPPORTED_PROTOCOL_VERSION`, `INVALID_REQUEST`, `REQUEST_TOO_LARGE` | No — fix the client    |
| Policy denial (in-band)  | `MISSING_CONTEXT`, `ARGUMENT_SCHEMA_VIOLATION`, `KILL_SWITCH_ACTIVE`, `MAX_CALLS_EXCEEDED`, `IP_RANGE_DENIED`, `TOKEN_REVOKED`, `EXPIRED_TOKEN`, `AUTHORIZATION_FAILED` | No — propagate to MCP client |
| Transient infrastructure | `GATEWAY_UNAVAILABLE`, `REVOCATION_UNAVAILABLE`                       | After back-off; treat as deny until resolved |

All in-band policy denials arrive as HTTP 200 with `decision: 'deny'`.
Infrastructure errors arrive as HTTP 4xx/5xx with the `ErrorResponse` envelope.

---

## 10. Backward-Compatibility Promise

- The `EnforceRequest` shape is **additive-only** within a protocol version:
  new optional fields may be added; existing fields are never removed or
  renamed within version 1.
- The `EnforceResponse` shape is equally additive-only within version 1.
- New `Obligation` types may be added within version 1; clients MUST silently
  ignore obligation types they do not recognise (tolerate-unknown rule) rather
  than failing the whole response.
- The `DenialInfo.code` set may grow within version 1; clients MUST treat
  unknown codes as opaque denial codes and propagate the `DenialInfo.message`
  to their logs.

---

## 12. Stage-4 Interoperability

The gateway's enforcement path (`POST /api/v1/enforce`) is **issuance-path
agnostic**: it evaluates the `capabilities` claim array using the same condition
engine regardless of whether the bearer token was produced by the Stage-3 API-key
minter or the Stage-4 OIDC issuer.

### Token shape commonality

Both issuance paths produce structurally identical tokens from the gateway's
perspective:

| JWT claim              | Stage-3 minter                  | Stage-4 issuer                  |
|------------------------|---------------------------------|---------------------------------|
| `iss`                  | issuer DID                      | issuer DID (same)               |
| `sub`                  | agentId                         | agentId (same)                  |
| `aud`                  | `tool-gateway`                  | `tool-gateway` (same)           |
| `capabilities`         | from role-capability policy      | from manifest / template        |
| `schemaVersion`        | `CAPABILITY_TOKEN_SCHEMA_VERSION`| same constant                   |
| `authorizedBy.userId`  | **apiKeyPrefix** (synthetic)     | **IdP user identity** (real)    |
| `authorizedBy.tenantId`| tenantId                        | tenantId (same)                 |

### Intentional divergence: `authorizedBy.userId`

The `authorizedBy.userId` claim carries different semantics in the two paths:

- **Stage-3 minter**: `userId` = the API-key prefix (e.g. `"sk-abc12345"`). This
  is a synthetic identifier that traces back to the minted API key — not a real
  human identity.
- **Stage-4 issuer**: `userId` = the IdP-resolved user identity (e.g.
  `"user@corp.com"` for Entra ID, or a Cognito `sub` UUID). This is a durable,
  auditable real-user principal.

**The gateway does not evaluate `authorizedBy.userId` in its enforcement logic.**
Both token shapes produce identical decisions, identical obligations, and identical
OCSF `conditionType` values for the same capability constraints. `authorizedBy.userId`
is persisted in `AuditEvidence` for forensics and support queries only.

Gateway operators comparing minter-vs-issuer audit rows **must** exclude
`authorizedBy.userId` when asserting decision parity. All other pre-signature
OCSF fields are identical between the two issuance paths.

This behaviour is proven by the parity test in
`internal/integration-tests/tests/cross-stage-parity.test.ts`
(describe block: *"Stage-4 parity: minter-vs-issuer produces identical gateway
decisions (Task 11)"*).

---

## 13. Changelog

| Date       | Change                                              | Protocol version |
|------------|-----------------------------------------------------|-----------------|
| 2026-05-11 | Initial definition (Task 9)                         | 1               |
| 2026-05-18 | Stage-4 interoperability note added (§ 12, Task 11) | 1               |
