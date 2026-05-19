# Agent SDK — Calling `/attenuate` and `/renew`

This guide explains how to call the capability issuer's attenuation and renewal endpoints from any HTTP client (non-CLI).

## Prerequisites

You have a valid capability token (JWT) issued by the capability issuer. Obtain one via `euno request` or directly via `POST /api/v1/oidc/token`.

## Attenuate a Token

Attenuation produces a child token scoped to a narrower set of capabilities. The `cnf.jkt` (DPoP binding) and `region` claims are preserved from the parent.

### curl
```bash
curl -X POST https://issuer.example.com/api/v1/attenuate \
  -H "Authorization: Bearer <parent-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "requestedCapabilities": [
      { "resource": "api://myservice/readonly", "actions": ["read"] }
    ]
  }'
```

### fetch (Node.js / browser)
```typescript
const response = await fetch('https://issuer.example.com/api/v1/attenuate', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${parentToken}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    requestedCapabilities: [
      { resource: 'api://myservice/readonly', actions: ['read'] }
    ]
  }),
});

if (!response.ok) {
  if (response.status === 429) {
    const retryAfter = response.headers.get('Retry-After');
    throw new Error(`Rate limited. Retry after ${retryAfter}s`);
  }
  const err = await response.json();
  throw new Error(err.message);
}

const { token } = await response.json();
```

### axios
```typescript
import axios from 'axios';

const { data } = await axios.post(
  'https://issuer.example.com/api/v1/attenuate',
  { requestedCapabilities: [{ resource: 'api://myservice/readonly', actions: ['read'] }] },
  { headers: { Authorization: `Bearer ${parentToken}` } }
);
const childToken: string = data.token;
```

## Renew a Token

Renewal extends the expiry of an existing token without changing its capabilities. `cnf.jkt`, `region`, and `policyHash` are preserved.

### curl
```bash
curl -X POST https://issuer.example.com/api/v1/renew \
  -H "Authorization: Bearer <current-token>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

### fetch
```typescript
const response = await fetch('https://issuer.example.com/api/v1/renew', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${currentToken}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({}),
});

if (!response.ok) {
  if (response.status === 429) {
    const retryAfter = response.headers.get('Retry-After');
    throw new Error(`Rate limited. Retry after ${retryAfter}s`);
  }
  throw new Error(`Renewal failed: ${response.status}`);
}
const { token: renewedToken } = await response.json();
```

## Error Handling

| Status | Meaning | Action |
|--------|---------|--------|
| 200 | Success | Use `response.token` |
| 401 | Invalid/expired bearer token | Re-authenticate, get new token |
| 403 | Token lacks permission to attenuate | Check parent token capabilities |
| 422 | Invalid request body | Fix capability format |
| 429 | Rate limited | Wait `Retry-After` seconds |
| 500 | Issuer internal error | Retry with exponential backoff |

## Rate Limiting

Both `/attenuate` and `/renew` use the same rate limiter as `/issue`, but are keyed by a different subject: fresh `/issue` requests are keyed by `(tenantId, userId, agentId, ip)`, while `/attenuate` and `/renew` include the parent token `jti` in the bucket key. This means each parent token has its own rate-limit counter, independent of fresh issuance. The default hosted limit is 20 requests per 60-second window per subject. On 429, read the `Retry-After` response header and back off accordingly.

---

## AGT in-process guard

The `@euno/agent-runtime` package ships `createAgtGuard()` — an in-process capability pre-screen that sits between your agent logic and the outer tool gateway. It implements the Set-D architecture described in [`docs/diagrams.md`](./diagrams.md) (Set D, diagrams D1–D4).

### Architecture overview

```
Agent logic
    │
    ▼
┌──────────────────────────────────────────┐
│  AgtGuard (soft inner guard)             │
│  • checks tool name against policy       │
│  • calls tokenSupplier() per invocation  │
│  • forwards allowed calls to transport   │
└──────────────────────────────────────────┘
    │ allowed calls only
    ▼
Tool Gateway (hard outer guard)
    │ validated, signed, scope-checked
    ▼
External API / Tool
```

See the full sequence diagram in [`docs/diagrams.md`](./diagrams.md) §D2 ("Runtime Action Enforcement Flow").

### Installation

`createAgtGuard` is exported from `@euno/agent-runtime` (BSL-1.1). The three
configuration types — `AgtGuardOptions`, `AgtGuardResult`, and
`AgtGuardDenyReason` — are exported from both `@euno/agent-runtime` and
`@euno/common-core` (Apache-2.0), so consumers that only need the type
declarations can take a lighter dependency.

### Quick-start wiring

```typescript
import {
  createAgtGuard,
  HttpToolTransport,
  type AgtGuardOptions,
} from '@euno/agent-runtime';
import type { AgentCapabilityManifest } from '@euno/common-core';

// 1. Declare the agent's capability manifest (or load it from a file / registry).
const manifest: AgentCapabilityManifest = {
  agentId: 'my-data-agent',
  name: 'Data Analysis Agent',
  version: '1.0.0',
  requiredCapabilities: [
    { resource: 'db:read',      actions: ['read'] },
    { resource: 'storage:read', actions: ['read'] },
  ],
  optionalCapabilities: [
    { resource: 'cache:read', actions: ['read'] },
  ],
};

// 2. Create the guard, wrapping the outer HTTP transport.
const guard = createAgtGuard(
  {
    // Called once per outbound tool invocation; must return the current token.
    tokenSupplier: () => tokenStore.currentToken(),
    policy: manifest,

    // Observation callbacks — use these for metrics / structured logs.
    onDeny: (toolName, reason) => {
      logger.warn('AGT guard blocked tool call', { toolName, reason });
      metrics.increment('agt.guard.deny', { reason });
    },
    onGatewayDeny: (toolName, gatewayErrorCode) => {
      // The guard allowed the call, but the gateway rejected it.
      // The gateway audit log is the authoritative denial record;
      // this callback provides the agent-side signal only.
      logger.warn('Gateway denied guard-allowed call', { toolName, gatewayErrorCode });
      metrics.increment('agt.gateway.deny', { code: gatewayErrorCode });
    },
  } satisfies AgtGuardOptions,
  new HttpToolTransport(process.env.GATEWAY_URL!),
);

// 3. Route all tool calls through the guard.
const response = await guard.invokeTool({
  tool: 'db:read',
  args: { table: 'analytics_events', limit: 100 },
});

if (!response.success) {
  if (response.guardResult === 'deny') {
    // The guard blocked the call in-process; no gateway request was made.
    console.error('Guard deny:', response.denyReason, response.error);
  } else {
    // The guard allowed it but the gateway denied it.
    console.error('Gateway deny:', response.errorCode, response.error);
  }
}
```

### Response shape

`guard.invokeTool()` returns an `AgtGuardInvokeResponse` which extends the
standard `ToolTransportResponse` with two additional fields:

| Field | Type | Description |
|---|---|---|
| `guardResult` | `'allow' \| 'deny'` | The guard's own verdict. `'allow'` means the call was forwarded to the gateway (even if the gateway subsequently denied it). `'deny'` means the guard blocked it before the transport was called. |
| `denyReason` | `AgtGuardDenyReason \| undefined` | Set only when `guardResult === 'deny'`. One of `'capability_not_found'`, `'constraint_violated'`, or `'policy_evaluation_error'`. |

### Policy evaluation

The guard matches each tool call by the `resource` field of the capability
constraints in `policy.requiredCapabilities` and `policy.optionalCapabilities`.
A tool whose name is not found in either array is denied with
`'capability_not_found'`.

The guard intentionally does **not** replicate every constraint type enforced
by the gateway (for example, `maxCalls` counters, `ipRange` checks, or policy
backend calls). The gateway is the authoritative enforcer for those. The
guard's role is to catch obviously out-of-scope calls early and to provide an
agent-side observability signal.

### Token supplier contract

`tokenSupplier` is called once per outbound tool invocation (i.e., per call
that passes the in-process policy check). The guard does **not** cache the
returned token between calls, so a supplier that maintains a refresh loop will
automatically surface fresh tokens on every forwarded call. The supplier must
be safe for concurrent invocations if multiple tool calls can be in-flight
simultaneously.

### Why two guards?

The defense-in-depth rationale is:

| Layer | Who runs it | What it enforces | Auditable? |
|---|---|---|---|
| AGT in-process guard (soft) | Inside the agent process | Capability manifest — "should this agent ever call this tool?" | No (agent-side only) |
| Tool gateway (hard) | Outside the agent process, controlled by the platform | Cryptographic token validity, scope, expiry, revocation, rate limits | **Yes** — every decision is written to the audit log |

The in-process guard adds defense-in-depth: it reduces noise in the gateway
audit log by pre-screening obviously invalid calls, and it gives the agent's
own observability stack (metrics, logs, traces) a signal before any network
round-trip. It **does not** replace the gateway — an operator MUST NOT rely
on the in-process guard as a security boundary. A compromised or misbehaving
agent process can bypass its own guard entirely; the gateway is the sole
enforceable trust boundary from the platform's perspective.

### Security caveat

The guard runs inside the agent process. If the agent process is compromised,
an attacker can bypass the guard by calling the transport directly. This is
expected and by design — the guard is a soft guard, not a security boundary.
The gateway (which runs outside the agent's trust domain, controlled by the
platform operator) is the hard boundary and is the sole authoritative denial
record. See `docs/diagrams.md` Set D and the enterprise threat model addendum
(`docs/security/enterprise-federation-threat-model.md` §"In-process guard
bypass") for the full threat-model treatment.

