---
title: "SCIM 2.0 for AI Agents: Bringing Enterprise Directory Provisioning to Capability Tokens"
description: 'Fifth and final post in the "Technology choices" series. [Post 21](./21-operator-tooling.md) introduced the SCIM integration from an operator perspective — what the SCIM endpoint does and how the token lifecycle maps to SCIM events. This post goes deeper: the protocol details, the schema mapping, the edge cases that only appear with real IdP integrations, and the design decisions behind the `externalId` / `userName` fallback strategy. See [`docs/blog-articles.md`](../blog-articles.md) for the full series index.'
pubDate: "2026-06-15"
---

_Fifth and final post in the "Technology choices" series. [Post 21](./21-operator-tooling.md) introduced the SCIM integration from an operator perspective — what the SCIM endpoint does and how the token lifecycle maps to SCIM events. This post goes deeper: the protocol details, the schema mapping, the edge cases that only appear with real IdP integrations, and the design decisions behind the `externalId` / `userName` fallback strategy. See [`docs/blog-articles.md`](../blog-articles.md) for the full series index._

---

When I was talking to the first enterprise customer who had a fully managed identity provisioning workflow — Okta pushing SCIM events to every downstream system — the question was straightforward: "Can we provision eunox the same way we provision every other SaaS tool we use?" The answer, at the time, was no. We had manual API calls for user management. I watched their face fall and I knew we needed SCIM.

Adding SCIM support sounds like a checkbox exercise: read the spec, implement the endpoints, call it done. What I didn't expect was how many corner cases the spec leaves underspecified, how differently each IdP interprets those underspecified areas, and how the intersection of SCIM lifecycle events with the stateful, cryptographic nature of capability tokens creates edge cases that have no parallel in ordinary SaaS provisioning.

This post covers what I learned building the SCIM integration and operating it with real IdPs.

---

## What SCIM is and why it matters for AI agent governance

SCIM 2.0 (RFC 7643, RFC 7644) is the protocol for automated user and group synchronization between identity providers and downstream applications. Instead of manually adding users to a system when they join an organization and manually removing them when they leave, SCIM automates the full lifecycle: create on hire, update on role change, suspend on leave of absence, delete on termination.

Every major enterprise IdP supports SCIM as an outbound provisioning protocol: Okta, Azure Active Directory (Entra ID), Ping Identity, OneLogin, JumpCloud. Your IdP is authoritative for who exists and what groups they belong to; SCIM is the sync protocol that propagates that state to downstream systems.

For a system like eunox, SCIM solves a specific governance problem: **orphaned access**. Without automated deprovisioning, a contractor who was granted access to an AI agent capability doesn't lose that access when they leave the organization — someone has to remember to revoke it manually. Manual processes fail. People are busy. The ex-contractor's access persists, and the AI agent tool calls they can make persist with it.

With SCIM, deprovisioning is automatic. The moment the contractor's account is deprovisioned in the IdP, the SCIM DELETE event arrives at eunox, existing tokens are revoked, and the user's access is gone. The organizational process (HR deprovisioning the IdP account) automatically produces the security outcome (agent access revoked) without any additional human action.

---

## The SCIM endpoint surface

Eunox's SCIM implementation exposes the endpoints defined in RFC 7644:

| Method   | Path                             | Purpose                  |
| -------- | -------------------------------- | ------------------------ |
| `GET`    | `/scim/v2/Users`                 | List or search users     |
| `GET`    | `/scim/v2/Users/{id}`            | Get a specific user      |
| `POST`   | `/scim/v2/Users`                 | Create a user            |
| `PUT`    | `/scim/v2/Users/{id}`            | Replace a user           |
| `PATCH`  | `/scim/v2/Users/{id}`            | Update a user (partial)  |
| `DELETE` | `/scim/v2/Users/{id}`            | Delete a user            |
| `GET`    | `/scim/v2/Groups`                | List or search groups    |
| `GET`    | `/scim/v2/Groups/{id}`           | Get a specific group     |
| `POST`   | `/scim/v2/Groups`                | Create a group           |
| `PUT`    | `/scim/v2/Groups/{id}`           | Replace a group          |
| `PATCH`  | `/scim/v2/Groups/{id}`           | Update a group (partial) |
| `DELETE` | `/scim/v2/Groups/{id}`           | Delete a group           |
| `GET`    | `/scim/v2/ServiceProviderConfig` | Advertise capabilities   |
| `GET`    | `/scim/v2/Schemas`               | List supported schemas   |
| `GET`    | `/scim/v2/ResourceTypes`         | List resource types      |

The discovery endpoints (`ServiceProviderConfig`, `Schemas`, `ResourceTypes`) are important in practice. When you configure eunox as a SCIM target in Okta or Azure AD, the IdP fetches `ServiceProviderConfig` first to understand what operations and filters are supported. If the config says you don't support `PATCH`, the IdP will use `PUT` for all updates — which is more expensive because it requires the IdP to maintain a full copy of user state. We implement `PATCH` fully because it's the efficient path.

---

## The data model: users, groups, and capability roles

SCIM models identities as Users and Groups. Eunox's internal model has Users, Groups, and CapabilityRoles. The mapping is:

**SCIM User → eunox User**: A SCIM User has a `userName` (usually an email), an `externalId` (the IdP's internal identifier), and extension attributes. Eunox's User record adds `capabilityRoles: string[]` — the set of roles that determine which capability templates this user can request.

**SCIM Group → eunox Group**: A SCIM Group has a `displayName` and `members`. Eunox's Group record adds a `capabilityRole` mapping — the role that membership in this group grants.

The role mapping is configured in the operator configuration, not inferred from the SCIM data. If your IdP has a group named `ai-ops-team`, you configure the mapping in eunox:

```yaml
# config/scim-role-mapping.yaml
groupRoleMappings:
  - groupDisplayName: "ai-ops-team"
    capabilityRole: "ops-agent"
  - groupDisplayName: "ai-readonly-analysts"
    capabilityRole: "read-only-agent"
  - groupDisplayName: "ai-power-users"
    capabilityRole: "full-access-agent"
```

When SCIM pushes a new group membership for a user, eunox looks up the role for that group, adds the role to the user's `capabilityRoles`, and the user's next token request will be authorized against that role's capability template.

---

## The `externalId` / `userName` fallback strategy

This is the detail that most SCIM documentation glosses over but that caused the most operational friction with real IdPs.

The SCIM spec defines `externalId` as "a String that is an identifier for the resource as defined by the provisioning client." In practice, this is the IdP's internal identifier for the user — a UUID-style string that is stable across renames and is the canonical reference. `userName` is the human-readable identifier (usually email) that is shown in UIs but which can change (email address updates on marriage, for example).

The ideal lookup strategy is: match on `externalId` as the primary key. It's stable, unique per IdP, and unambiguous.

The problem is that not every IdP sends `externalId` consistently. Some configurations of Azure AD SCIM provisioning send `externalId` for some operations but not others. Some Okta configurations omit it for group membership update events. Some IdP configurations only ever send `userName`.

If we require `externalId` for all operations, we'll silently fail or create duplicate records whenever an IdP sends a `userName`-only event. If we require `userName`, we'll create duplicate records whenever the same user is pushed with different usernames (which shouldn't happen but does, during configuration mistakes or IdP migrations).

The lookup strategy we implemented:

```
function lookupUser(scimPayload):
  if scimPayload.externalId:
    user = findByExternalId(scimPayload.externalId)
    if user: return user

  if scimPayload.userName:
    user = findByUserName(scimPayload.userName)
    if user: return user

  return null
```

The important constraint is that this lookup does not currently backfill `externalId` when a match is found by `userName`, and it does not emit a dedicated warning log for fallback lookups. That's a known observability limitation in the current implementation. Operationally, it means IdP configuration quality still matters: sending stable `externalId` values from the start is the safest way to avoid duplicate-identity edge cases during sync events.

---

## PATCH operations: the hard part

The SCIM `PATCH` operation uses a specific patch format defined in RFC 7644 and the SCIM filter query syntax. A typical `PATCH` request to add a user to a group looks like:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {
      "op": "add",
      "path": "members",
      "value": [
        { "value": "user-scim-id-abc123", "display": "alice@example.com" }
      ]
    }
  ]
}
```

And to remove one or more members by value list:

```json
{
  "Operations": [
    {
      "op": "remove",
      "path": "members",
      "value": [{ "value": "user-scim-id-abc123" }]
    }
  ]
}
```

For query filtering (`GET /Users?filter=...`, `GET /Groups?filter=...`), the current implementation supports a focused subset: `eq` and `co` on supported attributes. For group membership PATCH, we handle direct `members` add/remove/replace operations; we do not currently parse `members[value eq "..."]` path filters.

---

## Role resolution at token request time

When a user requests a capability token, the flow is:

1. User authenticates via OIDC (PKCE flow or service account credentials)
2. The capability issuer looks up the user's `capabilityRoles` from the SCIM-provisioned user record
3. The issuer finds the capability template for the requested role
4. The token is issued with the scopes and conditions defined in the template

The capability template is the bridge between the SCIM-side world (roles, groups) and the eunox-side world (capability manifests, conditions). A capability template for the `ops-agent` role might look like:

```yaml
# config/capability-templates/ops-agent.yaml
role: ops-agent
manifest:
  agentId: "ops-agent"
  tools:
    - resource: "query_db"
      conditions:
        - type: allowedOperations
          operations: [SELECT]
        - type: maxCalls
          max: 500
          per: session
    - resource: "read_file"
      conditions:
        - type: allowedExtensions
          extensions: [.log, .json, .yaml]
        - type: maxCalls
          max: 100
          per: session
  tokenTtlSeconds: 900
```

The SCIM integration doesn't touch this template. It just manages which users have which roles. The operator controls the templates; the IdP administrator controls group membership; eunox's SCIM integration keeps the two in sync.

---

## The token revocation problem on SCIM DELETE

The most security-critical SCIM event is `DELETE User`. When a user is deleted, any active tokens issued to that user should be immediately invalidated.

The challenge is that capability tokens are stateless JWTs. The token verifier doesn't consult the user store on every verification — that would add database latency to every tool call. It verifies the JWT signature and the claims. A token for a deleted user has a valid signature and valid claims; it will be accepted by the gateway unless we take explicit action.

The action we take on SCIM DELETE is: set a revocation epoch keyed on the user's subject identifier. The epoch structure is:

**Key:** `eunox:epoch:subject:{tenantId}:{userSubject}`

**Value:** Unix timestamp of the DELETE event

**TTL:** `maxTokenTtlSeconds × 2` (double the max TTL to handle clock skew)

On every token verification, after signature validation, the gateway checks:

1. Is there an epoch for this token's `sub` (subject)?
2. If so, was the token issued (`iat`) before the epoch timestamp?
3. If both yes → reject with `TOKEN_REVOKED_BY_EPOCH`.

This gives sub-millisecond revocation effect (the Redis check is fast) with no need to enumerate individual token JTIs for the deleted user. We don't need to know which specific tokens exist; we just need to know when the user was deleted.

The implementation detail: for this to work correctly, the `sub` claim in the capability token must be the same stable identifier as the user subject in the SCIM record. We use the `externalId` from SCIM as the subject when available, falling back to a hash of `userName` when `externalId` is absent. This is why the `externalId` fallback strategy matters for security, not just for correctness.

---

## SCIM UPDATE and role reduction: the async problem

When a user is removed from a group (a `PATCH Groups/{id}` removing a member, or a `PATCH Users/{id}` removing a group attribute), their role should be reduced. But as discussed in post 21, existing tokens are not automatically revoked on role reduction.

The design reasoning: automatic revocation on role change would interrupt live agent sessions unexpectedly. An agent that's mid-workflow — three tool calls into a five-step pipeline — would get a denial on the fourth call because an IdP group sync ran in the background and reduced the user's role. That's worse user experience and worse for reliability than letting the token expire naturally.

The alternative — requiring very short token TTLs so that role changes propagate quickly through natural expiry — is architecturally sound but puts operational pressure on the token issuance infrastructure and on the UX of the agent session model. Token TTL is a security dial, not a provisioning dial, and you don't want those two concerns tangled.

The pragmatic solution: document the model clearly (role reduction takes effect at next token renewal; immediate effect requires explicit revocation), and provide the tooling to do explicit revocation when immediate effect is needed. If you're removing a contractor's access because of a security concern, you use the revocation API. If you're reorganizing groups as part of a routine access review, natural token expiry is fine.

What we do on SCIM role reduction is update the user record immediately: the `capabilityRoles` field reflects the new, reduced set from the moment the SCIM event is processed. The user's next token request will be issued under the new (reduced) role. Any token requested before the SCIM event was processed was issued correctly under the prior role. Only the overlap window — from the SCIM event until the prior token expires — is the exposure.

The audit log emits a `SCIM_ROLE_REDUCTION` event (OCSF Authorization class) every time a SCIM update reduces a user's role. This makes the event queryable: if you're doing a post-incident review and need to know when a user's access was reduced, the SCIM event is in the audit trail.

---

## Handling IdP restarts and full sync operations

Some IdPs periodically do a full sync — they push the complete state of all users and groups, not just delta changes. Okta calls this a "full import." Azure AD's SCIM provisioning does this after configuration changes.

A naïve implementation of SCIM CREATE will create duplicate user records if the same user is pushed again with a new SCIM resource ID. IdPs sometimes change their internal IDs for a user across full syncs (particularly if the IdP configuration changed between syncs).

Our current handling is stricter:

1. On `POST /scim/v2/Users`, attempt to create a new record.
2. If uniqueness constraints are hit, return `409 User already exists`.
3. Use PUT/PATCH flows for updates to existing users.

This is RFC-aligned behavior for create semantics, but it means IdP full-sync jobs must be configured to treat existing-user conflicts as expected update signals, not always-fatal provisioning failures.

---

## Testing your SCIM integration before go-live

The SCIM spec is specific enough that automated testing against a reference implementation is possible. In this repo, the SCIM coverage lives in `eunox/packages/capability-issuer/tests/scim.test.ts` and exercises flows such as:

1. Provisions a test user via `POST /scim/v2/Users`
2. Verifies the user appears in token issuance with the expected role
3. Adds the user to a group via `PATCH /scim/v2/Groups/{id}` and verifies role update
4. Removes the user from the group and verifies role reduction
5. Deletes the user and verifies tokens are revoked
6. Verifies that a deleted user's token is rejected at the gateway

Run this suite against a staging gateway before connecting a real IdP. The failure modes in IdP integration usually show up as filter parsing errors or missing field handling, and it's much easier to debug those against the SCIM test suite than against live Okta provisioning.

For production readiness, also run the suite against the actual IdP in a staging directory. Okta's SCIM integration tester (under Applications → your app → Provisioning → Test Connectivity) is worth using — it exercises a narrower range of operations than our full suite but it exercises them in exactly the way Okta will exercise them in production.

---

## Operational monitoring

For SCIM provisioning, the metrics I watch:

**`eunox_scim_operations_total`** (counter, labeled by operation and result): normal provisioning produces a steady rate of operations with `result=success`. A spike in `result=error` with `operation=patch` usually indicates a filter expression the parser doesn't handle, or an IdP sending a schema extension we don't support.

**`eunox_scim_fallback_username_lookups_total`** (counter): if this is consistently non-zero, the IdP configuration is not sending `externalId`. Worth fixing before it causes duplicate-record edge cases.

**`eunox_scim_role_reductions_total`** (counter): should be low in normal operations. A sudden spike means a large number of users are losing roles — which could be a legitimate group restructuring, or it could be a misconfiguration in the IdP group mapping. Either way, worth alerting on.

**Provisioning latency from SCIM event to token effect:** not a Prometheus metric, but a meaningful SLO to track. Measure: time from IdP-side deprovisioning event to "user's token is rejected at gateway." With SCIM DELETE triggering immediate revocation epoch, this should be under 10 seconds in normal operation (SCIM event arrives, epoch is set in Redis, next token verification check hits Redis and gets rejected). If you're seeing latency above a minute, investigate the SCIM event delivery latency from your IdP.

---

## What I'd build differently

The main thing I'd do differently: implement the SCIM filter parser as a proper ANTLR grammar from the start, not as a hand-rolled recursive descent parser. The hand-rolled parser handles all the real-world cases we've encountered, but adding new filter operators requires touching the parser code carefully. An ANTLR grammar would be easier to maintain and extend.

I'd also invest earlier in the SCIM event reconciliation audit trail — a log that shows, for every SCIM event processed, what changed in the user's role set. We have the OCSF `SCIM_ROLE_REDUCTION` and related events now, but the early implementation just wrote to the application log without OCSF structure. Making it OCSF-structured from the start would have saved one migration.

The `externalId` / `userName` fallback is right in principle but the implementation could be clearer. Today it's in the user lookup function. It should probably be a named concept ("identity correlation strategy") with configuration options for operators to choose between strict-externalId-only, fallback-to-userName, and permissive modes. That would make it easier for operators to understand what the system will do when they configure a new IdP, and easier to audit why specific users were matched the way they were.

---

_Previous: [post 26 — Redis as a shared enforcement substrate](./26-redis-enforcement-substrate.md). The "Technology choices" series is complete. Next up: the "Compliance and enterprise" series beginning with [post 28 — Building for SOC 2: mapping CC6 and CC7 controls to an AI governance platform](../blog-articles.md#compliance-and-enterprise)._
