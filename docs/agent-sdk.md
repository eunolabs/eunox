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
