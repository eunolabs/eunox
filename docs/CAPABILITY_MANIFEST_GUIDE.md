# Capability Manifest Guide

> Sprint 6 deliverable. Patterns "discovered during pilot" for writing
> capability manifests that work the first time, age well, and survive
> Sentinel scrutiny. This guide is the canonical companion to
> `euno init` / `euno validate` / `euno plan` in `packages/cli`.

A **capability manifest** is the YAML / JSON document that the
[`Capability Issuer`](../packages/capability-issuer) consumes to
produce a signed JWT for an agent session. The token is what the
[`Tool Gateway`](../packages/tool-gateway) verifies on every action.
The manifest is therefore the **single source of authority** for what
an agent can do — get it right and the rest of the system enforces it
mechanically.

## 1. Required structure

Every manifest must include the following top-level fields. Anything
missing is rejected by `euno validate`.

```yaml
schemaVersion: "1.1"            # see docs/SCHEMA_VERSIONING.md
agentId: "sales-research-bot"   # stable, kebab-case, globally unique
name: "Sales Research Bot"      # human-readable
description: "Synthesizes account-research briefings."
owner:
  team: "RevOps"
  contact: "revops-oncall@example.com"
issuer:
  did: "did:web:agents.example.com"
ttlSeconds: 900                 # 15 min default; max 3600 in pilot
capabilities: []                # see § 2
```

## 2. The capability list — the four golden patterns

The pilot revealed that 90 % of real manifests fall into one of four
shapes. Use the closest one and resist the urge to invent new shapes
unless none of these fits.

### Pattern A — Single-purpose read agent

> *"This agent looks things up and reports. It never writes anywhere."*

```yaml
capabilities:
  - resource: "api://crm/customers/*"
    actions: ["read"]
  - resource: "api://reports/*"
    actions: ["read"]
```

- Only `read`.
- Resources scoped to a *segment* with `/*`, never bare `*`.
- The Sentinel rule **"Write attempt from a read-only session"** will
  fire immediately if this agent ever attempts a write — that's the
  intended behaviour and it is **not** a false positive. Investigate
  before widening the manifest.

### Pattern B — Workflow agent (read-most, narrow write)

> *"This agent reads broadly but only writes back to one specific path."*

```yaml
capabilities:
  - resource: "api://crm/customers/*"
    actions: ["read"]
  - resource: "api://crm/customers/*/notes"
    actions: ["write"]
  - resource: "api://reports/*"
    actions: ["read"]
```

- Write resource is a **child path** of the read resource.
- Each write resource lists explicit actions; never use
  `["read", "write", "delete"]` "just in case".
- If the agent needs to write into N siblings, list them
  individually — don't widen to `api://crm/*`.

### Pattern C — Tool-specialist agent

> *"This agent calls a single internal tool a lot, with arguments."*

```yaml
capabilities:
  - resource: "api://forecasting/predict"
    actions: ["execute"]
    conditions:
      maxRequestsPerMinute: 30
      maxBodyBytes: 32768
```

- Use `execute` for RPC-style endpoints.
- Apply rate / payload conditions instead of relying on TTL.
- The condition is enforced by the gateway via the typed
  `CapabilityCondition` discriminated union in
  `packages/common/src/capability-validators.ts` — no new validator
  code needed.

### Pattern D — Delegated / attenuated child

> *"A parent agent spins up a child agent for a sub-task with a strictly
> smaller capability set."*

```yaml
# Issued via POST /api/v1/attenuate using the parent token
capabilities:
  - resource: "api://crm/customers/12345"   # exact ID, not wildcard
    actions: ["read"]
ttlSeconds: 120                              # short — task is small
```

- Resource must be a **strict subset** of a parent capability (the
  issuer enforces this; see `packages/capability-issuer`).
- TTL must be ≤ parent TTL (also enforced).
- The audit log will carry `parentCapabilityId` automatically; do not
  invent your own correlation field.

## 3. Resource pattern do's and don'ts

The wildcard semantics are **segment-aware** (`packages/common/src/utils.ts::matchesResource`).
Internalize the table below.

| Pattern                      | Matches                                             | Does **not** match                          |
|------------------------------|-----------------------------------------------------|---------------------------------------------|
| `api://crm/customers`        | `api://crm/customers` only                          | `api://crm/customers/123`                   |
| `api://crm/customers/*`      | `api://crm/customers/123`, `.../abc`                | `api://crm/customers`, `.../123/notes`      |
| `api://crm/customers/**`     | `api://crm/customers/123`, `.../123/notes/xyz`      | `api://crm/customers`, `api://billing/...`  |
| `storage://docs/team/*`      | `storage://docs/team/file.pdf`                      | `storage://docs/file.pdf`                   |
| `api://*`                    | (rejected by `euno validate` — too broad)           | —                                           |

Rules:

- **Schemes are equality-checked.** `api://` and `storage://` never
  cross-match, even if you use `**`.
- **A trailing `/*` matches one segment.** A trailing `/**` matches
  one or more segments.
- **Bare `*` is not allowed.** `euno validate` and the issuer both
  reject it.

## 4. Conditions cookbook

Conditions live next to a capability and are typed (see
`packages/common/src/capability-validators.ts`). Common shapes:

```yaml
- resource: "api://billing/invoices/*"
  actions: ["read"]
  conditions:
    maxRequestsPerMinute: 60          # rate limit at the gateway
    allowedMethods: ["GET"]           # ignored for non-HTTP, harmless

- resource: "storage://exports/team-a/*"
  actions: ["write"]
  conditions:
    maxBodyBytes: 5242880             # 5 MiB cap
    allowedContentTypes: ["text/csv", "application/json"]

- resource: "db://warehouse/sales"
  actions: ["read"]
  conditions:
    allowedColumns: ["customer_id", "amount", "ts"]
    deniedColumns: ["ssn", "dob"]
```

> If a condition you need is not in the registry, **add it to
> `packages/common/src/condition-registry.ts` first**, ship a typed
> validator with tests, and only then reference it from a manifest.
> Free-form conditions are silently ignored at the gateway, which is
> a policy regression.

## 5. TTL guidance

| Scenario                                              | Recommended `ttlSeconds` |
|-------------------------------------------------------|--------------------------|
| Interactive chat / tool call                          | 900 (15 min — the default) |
| Long-running batch (ETL, embedding job)               | 1800–3600 (use `/renew` if you need more) |
| Delegated child for one sub-task                      | 60–300                   |
| Anything that touches money or PII                    | 300 with mandatory `/renew` per action |

Never set TTL to 0 or > 3600 in the pilot; the issuer will reject it.

## 6. Anti-patterns we caught during the pilot

These all *worked* (token issued, gateway happy) but each one degrades
the security posture and triggered tuning churn during hypercare.

1. **Manifest copied between agents** with `agentId` not changed.
   Audit logs lose all attribution. Use a unique `agentId` per logical
   agent, not per pod / replica.
2. **`api://*` with `["read", "write"]`** "for development". This
   passes `validate` only when the strict mode is off. In production
   the issuer rejects it; configure your dev manifests with realistic
   scopes and a separate dev `agentId`.
3. **Adding `delete` "for cleanup"**. If the agent doesn't currently
   delete anything, do not list `delete`. The Sentinel "Write attempt
   from a read-only session" rule treats delete as write; over-broad
   manifests defeat the rule.
4. **Issuing one massive token** that covers every tool the agent
   *might* need. Issue task-scoped tokens via `/issue` and chain via
   `/attenuate`; the token TTL is short for a reason.
5. **Hand-editing a JWT** to extend expiry during testing. Use
   `POST /api/v1/renew` — anything else invalidates the signature and
   is correctly rejected.

## 7. Tooling

| Step                                | CLI command                           |
|-------------------------------------|---------------------------------------|
| Scaffold a new manifest              | `euno init --agent <name> --output ./manifest.yaml` |
| Add a framework scaffold to it       | `euno init --framework langchain` (or `maf` / `crewai`) |
| Add a cloud-deployment scaffold      | `euno init --cloud aws` (or `azure` / `gcp`) |
| Validate the file                    | `euno validate ./manifest.yaml`       |
| Show what the issuer would mint      | `euno plan --manifest ./manifest.yaml` |
| Lint a token's actual claims         | `euno validate-token <jwt>`           |
| Show schema version compatibility    | `euno schema-version`                 |
| Run all manifest checks before PR    | `euno check ./manifest.yaml`          |

`euno check` is the one to wire into your CI — it runs `validate`,
`plan`, and a dry-run against your staging issuer.

## 8. Where this guide lives in the rest of the docs

- **Token format and signing**: [`SCHEMA_VERSIONING.md`](./SCHEMA_VERSIONING.md)
- **Why the gateway is the policy decision point**: [`enforcement.md`](./enforcement.md)
- **Adapter pattern (custom identity / signers)**: [`ADAPTER_PATTERN.md`](./ADAPTER_PATTERN.md)
- **DID / IAM integration**: [`did-iam-integration.md`](./did-iam-integration.md)
- **Sprint 6 hypercare exit and ownership**: [`SPRINT_6_STABILIZATION_HANDOFF.md`](./SPRINT_6_STABILIZATION_HANDOFF.md)
