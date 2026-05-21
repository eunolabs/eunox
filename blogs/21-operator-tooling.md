# Operator Tooling: Kill Switches, Revocation, and SCIM Provisioning

*Third post in the "User experience and developer ergonomics" series. [Post 9](./09-capability-tokens.md) covered capability tokens — the JWTs that this post's revocation machinery controls. [Post 11](./11-tamper-evident-audit-logs.md) covers the audit chain that records every action described here. See [`docs/blog-articles.md`](../blog-articles.md) for the full series index, including the upcoming post on the Redis substrate that makes the kill switch and revocation checks fast and distributed.*

---

Building the enforcement engine is the architecturally interesting part of a system like euno. Writing the operator tooling — the parts that let humans intervene at runtime — is the part that decides whether the system is actually useful in a real organization.

I've been in incident response situations where the question is: "We believe this agent has been compromised. How do we stop it right now, and how do we prevent any tokens it may have exfiltrated from being used?" The answer to that question needs to be measured in seconds, not minutes. The tooling covered in this post is what makes that kind of rapid response possible.

---

## The kill switch hierarchy

Euno's kill switch operates at three levels of granularity. Understanding when to use each one is the key to effective incident response.

**Session-level kill** targets a specific agent session identified by its session ID. A session is a single invocation of the proxy — one process, one conversation. This is the most surgical option: it stops exactly one running agent without touching anything else.

```bash
curl -X POST http://localhost:3003/admin/kill-switch/session/sess-abc-123/kill \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "X-Admin-Operator: alice@example.com" \
  -H "Content-Type: application/json" \
  -d '{"tenantId": "acme-corp"}'
```

After this call, any subsequent tool call from session `sess-abc-123` returns `KILL_SWITCH_ACTIVE` and is denied. Active tool calls in flight complete normally (the kill switch takes effect at the next tool call boundary), but the session is effectively terminated from a policy perspective.

**Agent-level kill** targets all sessions running a specific agent, identified by `agentId` (the field from the capability manifest). This is appropriate when you've identified a problem with a specific agent deployment — you want to stop all instances of it without touching unrelated agents on the same gateway.

```bash
curl -X POST http://localhost:3003/admin/kill-switch/agent/sales-research-bot/kill \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "X-Admin-Operator: alice@example.com" \
  -H "Content-Type: application/json" \
  -d '{"tenantId": "acme-corp"}'
```

**Global kill** stops all traffic on the gateway regardless of session, agent, or tenant. This is the nuclear option — use it when you need everything stopped while you assess the situation. Because of the obvious blast radius, global activation requires an explicit acknowledgment:

```bash
curl -X POST http://localhost:3003/admin/kill-switch/global/activate \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "X-Admin-Operator: alice@example.com" \
  -H "Content-Type: application/json" \
  -d '{"tenantId": "acme-corp", "acknowledgesCrossTenantImpact": true}'
```

The `acknowledgesCrossTenantImpact: true` field is not just a formality. In the code, the API handler checks for it and returns a `400` without it. The reason is auditability: the audit record for a global kill should reflect that the operator understood the scope of what they were doing. When you're presenting incident response evidence to a regulator, having an explicit acknowledgment in the audit trail is significantly better than a record that says "global kill was activated" with no indication that the operator considered the consequences.

---

## Reviving after a kill switch

Kill switches are reversible. This is important and often overlooked in the incident response plan.

The recovery path after a kill switch activation looks like this: you've identified the problem, mitigated it (revoked the relevant tokens, rotated the compromised key, updated the policy), and now you want to restore service. Reviving a session or agent:

```bash
# Revive a specific session
curl -X POST http://localhost:3003/admin/kill-switch/session/sess-abc-123/revive \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tenantId": "acme-corp"}'

# Revive a specific agent
curl -X POST http://localhost:3003/admin/kill-switch/agent/sales-research-bot/revive \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tenantId": "acme-corp"}'

# Deactivate global kill
curl -X POST http://localhost:3003/admin/kill-switch/global/deactivate \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tenantId": "acme-corp", "acknowledgesCrossTenantImpact": true}'

# Reset all kill switches at once
curl -X POST http://localhost:3003/admin/kill-switch/reset \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{"tenantId": "acme-corp", "acknowledgesCrossTenantImpact": true}'
```

The reset operation also requires the cross-tenant acknowledgment, for the same reason as the global activate: you want the audit record to reflect conscious intent.

One detail worth noting: reviving a killed agent doesn't automatically restore sessions that were running when the kill was activated. Those session IDs are still individually killed unless you explicitly revive them or reset all kill switches. This is the correct behavior — if you killed individual sessions before escalating to agent-level kill, you don't want them silently restored when you revive the agent.

---

## Checking kill switch status

Before activating a kill switch, it's worth checking the current state:

```bash
curl http://localhost:3003/admin/kill-switch/status \
  -H "X-Admin-API-Key: $ADMIN_KEY"
```

The response tells you which kill switches are currently active: whether the global switch is on, which agents are killed, which sessions are killed. This is useful for two reasons: first, you want to know before you activate the global kill whether individual kills are already in place for the relevant targets. Second, after an incident you want a clear status snapshot to include in the post-mortem.

---

## Token revocation

The kill switch is a runtime signal — it affects behavior at the gateway level for the duration of the gateway's operation. Token revocation is a different mechanism: it invalidates a specific capability JWT by its JTI (JWT ID) for the remaining lifetime of that token.

The JTI is embedded in every capability token and recorded in every audit event. When you see a suspicious tool call in the audit log, you can get the JTI from the audit record's `metadata.uid` field and revoke that specific token:

```bash
curl -X POST http://localhost:3003/admin/revoke \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "X-Admin-Operator: alice@example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "tokenId": "jti-a1b2c3d4-...",
    "expiresAt": 1748044800,
    "tenantId": "acme-corp"
  }'
```

The `expiresAt` field is optional. If omitted, the revocation entry is kept for 24 hours — long enough to cover the typical maximum token TTL. If you know when the token expires, pass that timestamp so the gateway can clean up the revocation entry at the right time rather than keeping it for a full 24 hours.

After revocation, any token with that JTI is rejected at the gateway with `TOKEN_REVOKED`, regardless of whether the token's cryptographic signature would otherwise be valid. The revocation list is backed by Redis (see the [series index](../blog-articles.md) for the upcoming post on the Redis enforcement substrate), so it's checked on every tool call with sub-millisecond latency.

---

## Revocation epochs: bulk revocation by issuance time

Individual JTI revocation handles the "stop this specific session" case. But there's a more serious scenario: you believe a signing key has been compromised. Any token issued before you rotated the key could potentially have been exfiltrated and is therefore untrusted, regardless of its JTI.

The revocation epoch handles this:

```bash
curl -X POST http://localhost:3003/admin/revocation/epoch \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "X-Admin-Operator: sre-on-call@example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "issuer": "did:web:issuer.acme-corp.example.com",
    "issuedBefore": 1748044800,
    "tenantId": "acme-corp"
  }'
```

This revokes all tokens from the specified issuer DID whose `iat` (issued-at) claim is strictly before the `issuedBefore` timestamp. Set `issuedBefore` to the moment you rotated the key. Everything issued before that moment is revoked; everything issued after (with the new key) continues to be accepted.

The epoch is stored in Redis alongside the revocation list. On each token verification, the gateway checks: "Is this token's `iat` before the epoch for its issuer?" If yes, reject with `TOKEN_REVOKED_BY_EPOCH`. The check is O(1) — a Redis GET against the issuer DID key — so it adds negligible latency.

There's an important operational consideration here: you need to know when you rotated the key with enough precision to set `issuedBefore` correctly. Too early and you revoke valid tokens. Too late and you leave a window of potentially-compromised tokens still valid. This is why we recommend keeping a timestamped record of every key rotation in your runbooks. The epoch mechanism is only useful if you know the rotation timestamp.

---

## Idempotency keys

Every mutating admin endpoint accepts an `Idempotency-Key` header. This is not optional ceremony — it's how you ensure safe retries.

In an incident response situation, network calls fail. Your curl command times out. You don't know whether the kill switch was activated before the timeout or after. Without idempotency keys, the safe response is to assume the call failed and retry — but if it actually succeeded and you're retrying a revocation with a new request body, you might get unexpected behavior.

With idempotency keys, the safe response is to retry with the same idempotency key. The gateway will return the cached response from the first successful call if it exists, or execute the operation if it hasn't been executed yet. The cache is kept for 24 hours.

The key should be a UUID or other unique random string. Generate it once at the start of the incident response action and reuse it for retries of that specific action. Don't reuse keys across different actions — the gateway validates that the same key always maps to the same endpoint, and returns a 422 if you try to use the same key for a different path.

```bash
IDEM_KEY=$(uuidgen)

# First attempt
curl -X POST http://localhost:3003/admin/kill-switch/agent/sales-research-bot/kill \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Idempotency-Key: $IDEM_KEY" \
  ...

# Safe retry — will return same result without re-executing
curl -X POST http://localhost:3003/admin/kill-switch/agent/sales-research-bot/kill \
  -H "X-Admin-API-Key: $ADMIN_KEY" \
  -H "Idempotency-Key: $IDEM_KEY" \
  ...
```

---

## Operator attribution

Every mutating admin call supports an `X-Admin-Operator` header:

```bash
-H "X-Admin-Operator: alice@example.com"
```

The value is logged in the OCSF Authorization event for the action and in the Winston audit chain. When you're reconstructing an incident timeline and someone asks "who activated the global kill switch at 14:23 UTC?", the answer is in the audit log — not as an inferrable fact from the logs, but as an explicit field in the event record.

This isn't just for post-incident review. It's also a deterrent. Operators who know that their identity is explicitly recorded in every action they take behave differently than operators who assume they're anonymous. The accountability surface is important.

For automated runbooks (where the operator is a service account or a script), use a meaningful service account identifier: `kill-switch-automation@acme-corp.example.com` is more useful in an audit trace than a generic identifier.

When `OCSF_TRANSPORT` is configured on the gateway, these events also go to your SIEM as OCSF Authorization events (class_uid 3003). That means kill-switch activations are queryable in Splunk, Sentinel, or whatever your security team uses for threat hunting, alongside your other authorization events.

---

## SCIM 2.0 provisioning

The kill switch and revocation APIs handle the emergency response layer. SCIM handles the provisioning layer — the mechanism for automatically keeping capability grants in sync with your identity directory.

SCIM 2.0 (System for Cross-domain Identity Management) is the protocol that enterprise identity providers (Okta, Azure AD, Ping Identity) use to push user and group changes to downstream systems. Euno's SCIM implementation receives these pushes and translates them into capability token policy.

The model works like this:

1. Your IdP defines groups. Groups have members. Euno has a role mapping that says "the group named `ai-ops-team` maps to the capability role `ops-agent`."

2. When a new user is added to `ai-ops-team` in your IdP, the IdP pushes a SCIM CREATE User event to Euno's SCIM endpoint. Euno creates a user record with the appropriate capability role assignment.

3. When that user is later removed from the group, the IdP pushes a SCIM group membership update. Euno updates the user's role assignment. Their next token request will reflect the new (reduced) role.

4. When a user is deprovisioned entirely (removed from the IdP), the IdP pushes a SCIM DELETE User event. Euno revokes any active tokens for that user and removes the user record.

The SCIM endpoint supports both `userName` lookup (the standard SCIM attribute) and `externalId` lookup as a fallback, because different IdPs use these fields differently. The fallback strategy means you don't have to perfectly align your IdP configuration before provisioning starts working.

---

## SCIM and the capability token lifecycle

Understanding how SCIM events translate into token lifecycle events is important for getting provisioning right.

**SCIM CREATE User** — A new user appears in the directory, assigned to groups that map to euno capability roles. The user record is created in euno's user store. Their first token request will succeed if the policy for their role permits it.

**SCIM UPDATE User / group membership change** — This is the most complex case. If the update reduces the user's role (removes a group membership), existing tokens issued under the old role continue to be valid until they expire, unless you explicitly revoke them. The SCIM update does not automatically revoke in-flight tokens — that would require a revocation epoch on any token issued before the SCIM update time.

This is a deliberate design choice. Automatic revocation on role change would mean a user's session could be silently interrupted by an IdP sync that happens in the background. That's worse for reliability than letting the token expire naturally, especially since tokens should have short TTLs anyway (hours, not days). If you need immediate effect on role reduction (e.g., you're removing a contractor's access), do it manually: revoke the relevant tokens by JTI or set a revocation epoch.

**SCIM DELETE User** — This is the case where automatic revocation makes sense. A deleted user should not have active tokens. The SCIM DELETE handler triggers an automatic revocation for any token with that user's identity as the subject. If you use a revocation epoch keyed on the user identity, you don't need to enumerate JTIs.

---

## Prometheus metrics and alert examples

For production deployments, euno exposes Prometheus metrics on the admin port's `/metrics` endpoint. Several of these are directly relevant to kill-switch and revocation monitoring.

**Kill switch state:**

```
# Gauge: 1 if global kill switch is active, 0 otherwise
euno_kill_switch_global_active

# Gauge: number of currently killed agent IDs
euno_kill_switch_agents_active_total

# Gauge: number of currently killed session IDs
euno_kill_switch_sessions_active_total
```

**Revocation:**

```
# Counter: total token revocations recorded since startup
euno_token_revocations_total

# Counter: total revocation epoch records set since startup
euno_revocation_epochs_total

# Counter: enforcement decisions that hit the revocation list
euno_enforcement_revoked_total
```

**Circuit breaker state for partner DIDs (see [post 13](./13-partner-did-federation.md)):**

```
# Gauge: per-DID circuit breaker state (0=closed, 1=half-open, 2=open)
euno_partner_did_circuit_breaker_state{did="did:web:partner.example.com", state="open"}
```

Useful Prometheus alerting rules for a production deployment:

```yaml
# Alert immediately when the global kill switch is activated
- alert: EunoGlobalKillSwitchActive
  expr: euno_kill_switch_global_active == 1
  labels:
    severity: critical
  annotations:
    summary: "Euno global kill switch is active — all agent traffic is denied"
    description: "Check the admin audit log to identify who activated it and why."

# Alert if revocation volume spikes (may indicate a key compromise response)
- alert: EunoRevocationSpike
  expr: rate(euno_token_revocations_total[5m]) > 10
  labels:
    severity: warning
  annotations:
    summary: "High rate of token revocations"
    description: "{{ $value }} revocations per second over the last 5 minutes."

# Alert if enforcement is hitting revoked tokens at unusual volume
- alert: EunoRevokedTokenHits
  expr: rate(euno_enforcement_revoked_total[5m]) > 5
  labels:
    severity: warning
  annotations:
    summary: "Agents are attempting to use revoked tokens"
    description: "This may indicate that revocation is not propagating to agent processes."
```

---

## The incident response playbook

The tooling above is most useful when it's incorporated into a documented incident response playbook before you need it. Trying to figure out the right curl commands during an active incident is not a good experience.

Here's the structure I recommend:

**Step 1: Immediate containment.** Identify the scope (specific session? specific agent? everything?) and activate the appropriate kill switch. Do this before you know all the details — the kill switch is reversible, and a few minutes of denied traffic is much better than continued unauthorized access.

**Step 2: Identify affected tokens.** Query the audit log for the relevant time window and agent to enumerate the JTIs of tokens that were active during the incident. You can use `GET /api/v1/audit/export` with appropriate filters for this, or query the Postgres audit ledger directly if you're running the hosted deployment.

**Step 3: Revoke affected tokens.** Revoke individual JTIs for the tokens you've identified. If you believe a signing key is compromised, set a revocation epoch for the issuer to cover all tokens issued before the key rotation.

**Step 4: Preserve evidence.** Export the relevant audit records before doing anything that might affect the audit trail. The OCSF records are signed — their integrity is verifiable independently of whether the gateway is running. Keep a copy.

**Step 5: Root cause and remediation.** Understand how the incident occurred. Update the policy manifest to prevent recurrence. Review related agent deployments for similar vulnerabilities.

**Step 6: Restore service.** Revive killed sessions/agents (or deactivate global kill). Verify with `GET /admin/kill-switch/status` that the state is what you expect. Monitor the enforcement metrics for the next few hours.

The speed at which you can execute steps 1–3 is what determines your exposure window. With the tooling in this post, step 1 should take under 60 seconds for anyone who has run through the playbook once.

---

## A word about the admin API key

Everything described in this post assumes you have the `X-Admin-API-Key` set on the gateway (via `ADMIN_API_KEY` environment variable). Protect this key at least as carefully as you protect your production database credentials.

The admin API key gives its holder the ability to kill any session, revoke any token, and set revocation epochs. It is, intentionally, a very powerful credential. For production deployments, I strongly recommend:

- Storing it in your secrets manager (Vault, AWS Secrets Manager, Azure Key Vault), not in a shell variable or a plain-text config file.
- Rotating it on a regular schedule and after any security incident.
- Using a separate admin API key per environment (dev, staging, prod).
- Auditing admin API key usage via the `X-Admin-Operator` header in your SIEM.

The operator JWT authentication (`MINTER_ADMIN_JWKS_URI`) is the recommended alternative for the minter service — it provides operator-level attribution without sharing a static key. The admin API is the simpler option for getting started, but the JWT-based approach is what you want in a mature production deployment.

---

*Previous: [post 20 — From dev to prod: the euno CLI experience](./20-from-dev-to-prod-cli.md). Next: [post 22 — Reference policies: copy-paste guardrails for common MCP servers](./22-reference-policies.md). See [`docs/blog-articles.md`](../blog-articles.md) for the full series index.*
