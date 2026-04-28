# Item #9 — AI Posture Management Inventory Feed

**Plan reference:** `docs/execution-plan.md` Sprint 3 → Team OBS →
"AI Posture Management Integration" (line 242):
> Inventory records (agent ID, owning team, capability manifest hash,
> runtime, region) MUST share field names across the three posture
> surfaces so a single dashboard can show the full agent estate.
> - Azure: Defender CSPM (AI security posture management).
> - AWS: Security Hub (AI / generative-AI security standards) +
>   GuardDuty inventory tags.
> - GCP: Security Command Center (Premium / Enterprise) AI posture
>   findings.

**Files affected:** new `packages/posture-emitter/`,
`packages/common/src/types.ts` (shared inventory record shape),
`packages/capability-issuer/src/issuer-service.ts` (emit on
issuance), `packages/agent-runtime/src/runtime.ts` (emit on agent
start/stop — optional second source).

## Problem

We have audit logs for capability issuances and tool calls, but no
**inventory feed** to the cloud-native posture-management surfaces.
Operators using Defender CSPM / Security Hub / SCC currently see
no record of which agents exist in their estate, who owns them,
which capabilities they hold, or where they run. The plan requires
parity field names across all three clouds so a single dashboard
view is possible.

## Goals

- Define a single, canonical `AgentInventoryRecord` shape used by all
  three cloud emitters.
- Push records on:
  - **Capability issuance** (newly observed agent ID + capability
    manifest hash).
  - **Capability revocation** (record removal — soft delete with a
    `revokedAt` field, never hard delete from the posture surface).
  - **Periodic refresh** (every 1h) to keep records non-stale on
    surfaces that age out entries.
- Each emitter is a plug-in; deploying with only Defender CSPM
  enabled does not require AWS/GCP SDKs.
- Failure to emit MUST NOT fail the originating issuance — posture
  is best-effort observability, not a control-plane gate.

## Non-goals

- Building a unified UI on top of the three surfaces (the plan
  explicitly defers this — same field names enable the operator's
  own dashboard).
- Pulling findings *from* posture surfaces back into euno (one-way
  push only).
- Per-tool-call telemetry to posture surfaces (that's audit logs +
  SIEM, covered by other Sprint 3 OBS work).

## Design

### 1. Canonical record shape

In `packages/common/src/types.ts`:

```
interface AgentInventoryRecord {
  schemaVersion: '1.0';
  agentId: string;                    // matches CapabilityToken.sub
  owningTeam: string;                 // from manifest.metadata.owner
  capabilityManifestHash: string;     // sha256 of canonical manifest JSON
  runtime: string;                    // e.g. 'node:20', 'python:3.12', 'aks:1.29'
  region: string;                     // cloud region the agent runs in
  // Optional context that ALL three surfaces accept under different keys.
  // The emitter maps these to per-surface field names.
  cloudAccount?: string;              // tenant id / aws account / gcp project
  manifestUri?: string;               // pointer to the manifest in storage
  capabilities?: CapabilityConstraint[];
  firstSeen: string;                  // ISO-8601
  lastSeen: string;                   // ISO-8601
  revokedAt?: string;                 // ISO-8601 if revoked
}
```

The five required fields (`agentId`, `owningTeam`,
`capabilityManifestHash`, `runtime`, `region`) are the parity set
called out in the plan. They become the *exact* field names emitted
to all three surfaces (the emitters do *not* rename them).

### 2. Manifest hashing

Reuse the existing deterministic hashing helper from
`@euno/common`. `packages/common/src/utils.ts` already exports
`canonicalize()` (sorted-key JSON serializer with cycle detection)
and `canonicalSha256()` (SHA-256 of the canonical form), and
`packages/common/src/evidence.ts` already uses them for cross-runtime
evidence hashing. The posture emitter MUST call `canonicalSha256(m)`
on `AgentCapabilityManifest`; introducing a second `hashManifest()`
implementation would risk drift between posture records and audit
evidence.

If a thin wrapper is wanted for readability, define it in the
posture package as `export const hashManifest = canonicalSha256;`
(re-export, not re-implement).

### 3. New package: `packages/posture-emitter/`

```
packages/posture-emitter/
  package.json
  tsconfig.json
  src/
    index.ts                  // PostureEmitter facade
    types.ts                  // PostureEmitterPlugin interface
    record-store.ts           // local in-memory + Redis-backed dedupe cache
    plugins/
      defender-cspm.ts        // Azure
      security-hub.ts         // AWS
      scc.ts                  // GCP
      stdout.ts               // dev / no-op shipping
  tests/
```

`PostureEmitter` exposes:

```
emitObserved(record: AgentInventoryRecord): Promise<void>;
emitRevoked(agentId: string, revokedAt: string): Promise<void>;
startPeriodicRefresh(intervalMs: number): () => void;
```

Internally it fans out to all configured plugins in parallel, with
per-plugin timeouts (default 5s) and structured per-plugin error
logging. A failed plugin does not block other plugins.

### 4. Per-plugin mapping

#### `defender-cspm.ts` (Azure)

Defender CSPM's AI posture inventory is fed via Microsoft Graph
Security API (or Azure REST `Microsoft.Security/aiSecurityRecommendations`
once GA). Until that API is GA the operationally available path is:

1. Tag agent compute resources (AKS pods, App Service, Container
   Apps) with `euno-agent-id`, `euno-owning-team`, etc.
2. Push a custom asset record via the Microsoft Defender for Cloud
   inventory API (`PUT /providers/Microsoft.Security/customAssessments`)
   referencing those tags.

Plugin needs `@azure/arm-security` (lazy-loaded). Required role:
`Security Admin` on the subscription (operator setup).

If the official AI-posture API ships during implementation, swap the
custom-assessment path for the native one — the plugin shape doesn't
change.

#### `security-hub.ts` (AWS)

Security Hub accepts custom findings via `BatchImportFindings`. Each
inventory record becomes a finding with:

- `ProductArn` — the issuer's registered Security Hub product.
- `GeneratorId` — `euno/posture-emitter/v1`.
- `Types` — `["Software and Configuration Checks/AWS Security Best Practices/AI-Inventory"]`.
- `ProductFields` — the `AgentInventoryRecord` flattened with the
  exact field names from the canonical shape (no renaming).
- `Resources[].Tags` — same five required fields, so SH's own
  resource view shows them.

Plugin needs `@aws-sdk/client-securityhub`. Required IAM:
`securityhub:BatchImportFindings`.

#### `scc.ts` (GCP)

SCC accepts custom findings via `securitycenter.findings.create`
under a custom source. Each record becomes a `Finding` with:

- `category` — `EUNO_AGENT_INVENTORY`.
- `sourceProperties` — flattened record with parity field names.
- `findingClass` — `OBSERVATION`.

Plugin needs `@google-cloud/security-center`. Required IAM:
`securitycenter.findingsEditor` on the source.

#### `stdout.ts`

Logs the JSON record to stdout. Used in dev and as the default when
no real plugin is configured (so the issuance pipeline doesn't fail
in environments without cloud config).

### 5. Issuer-service integration

In `CapabilityIssuerService.issueCapability()`, *after* the response
is assembled and the audit entry is written:

```
// Fire-and-forget; do not await — posture is best-effort.
postureEmitter.emitObserved({
  schemaVersion: '1.0',
  agentId: request.agentId,
  owningTeam: request.manifest?.metadata?.owner ?? 'unknown',
  capabilityManifestHash: hashManifest(request.manifest),
  runtime: request.manifest?.metadata?.runtime ?? 'unknown',
  region: process.env.EUNO_DEPLOYMENT_REGION ?? 'unknown',
  capabilities: response.capabilities,
  firstSeen: nowIso(),
  lastSeen: nowIso(),
}).catch(err => logger.warn('posture emit failed', { err }));
```

The `posture-emitter` package's `record-store` deduplicates: an
`emitObserved` for an agentId already seen within the past 5 minutes
just updates `lastSeen` in the local cache and skips network I/O
(the periodic refresh handles long-term `lastSeen` updates).

### 6. Periodic refresh

A 1-hour interval timer (only started in long-lived processes —
issuer pod, gateway pod) that walks the in-memory record store and
re-emits each non-revoked record. This keeps surfaces from aging
records out (Security Hub findings expire after 90 days without
update; SCC findings persist but `eventTime` staleness is reported).

In multi-replica deployments, the timer must be leader-elected to
avoid duplicate emits — use the existing Redis-based coordination
already used by the kill-switch (`packages/common/src/redis-kill-switch.ts`).
Alternatively, accept the duplication — Security Hub and SCC are
idempotent on the record key.

Recommend: rely on idempotency, not leader election. Simpler.

### 7. Configuration

```
POSTURE_EMITTER_ENABLED=true
POSTURE_EMITTER_PLUGINS=defender-cspm,security-hub
POSTURE_REFRESH_INTERVAL_MS=3600000
EUNO_DEPLOYMENT_REGION=eastus2
```

Plugin-specific config (subscription IDs, AWS region, GCP project +
source ID) lives in plugin-scoped env vars or a config file mounted
into the pod.

## Test strategy

- **Unit per plugin** with the cloud SDK mocked:
  - Record → SDK call payload mapping; assert the five required
    fields are present with the canonical names.
  - SDK 5xx → caught, logged, does not throw.
  - Disabled plugin → no SDK import (verify via `jest.mock` not
    being triggered).
- **Emitter facade:**
  - One failing plugin doesn't block others.
  - 5-minute dedupe window suppresses duplicate emits.
  - Revocation emits to all plugins.
- **Issuer-service integration:**
  - Issuance with posture disabled → no emit, no overhead in audit.
  - Issuance with posture enabled + emitter throws → issuance still
    succeeds, warning logged.

## Rollout

- Phase 1: shape + facade + stdout plugin (unblocks downstream
  consumers and proves the interface).
- Phase 2: `defender-cspm` plugin (most-requested first).
- Phase 3: `security-hub` and `scc` plugins.

## Risks

- **PII / sensitive metadata in manifests.** A manifest could contain
  an owner email or internal hostnames. Posture surfaces are
  organization-internal but visible to a wider audience than audit
  logs. Define a `redactForPosture(manifest)` helper that strips
  fields not in the parity set unless explicitly opted in via
  config; default is "minimum five fields only".
- **API quotas.** Security Hub `BatchImportFindings` is rate-limited
  (default 30 TPS / account). The dedupe + refresh design keeps us
  far below this for any plausible agent count, but document the
  ceiling.
- **Defender CSPM API churn.** Microsoft is actively shipping AI
  posture features; the API surface may change before GA. Keep the
  plugin behind a stable internal interface so the per-API impl can
  swap.
- **Cross-account / cross-tenant visibility.** Records are emitted
  to whichever cloud account the issuer pod runs in. A multi-cloud
  deployment of euno itself needs one emitter pod per cloud (or
  cross-account credentials, which is operator setup).

## Open questions

- Should the `agent-runtime` package also emit observed-records on
  agent boot (giving us a "I'm alive" signal independent of any
  issuance)? Recommend yes for Phase 4 — useful for detecting
  zombie / orphan agents that hold long-lived tokens but never
  re-issue.
- Should manifest hash use a Merkle tree over capabilities so
  partial changes are detectable? Overkill for posture inventory;
  a flat sha256 is sufficient and matches what the audit log
  already records.
