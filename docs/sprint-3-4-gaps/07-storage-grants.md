# Item #7 — Storage Grant Issuance (Azure SAS / S3 Presigned / GCS Signed URL)

**Plan reference:** `docs/execution-plan.md` Sprint 3 → Team DP →
"Full Spectrum Tool Enforcement / File system operations" (line 216):
> Issue short-lived storage grants as part of capability issuance.
> The agent presents the grant, and access beyond the token's scope is
> denied by the cloud storage control plane.
> - Azure: Azure Storage SAS tokens.
> - AWS: S3 presigned URLs or scoped IAM session policies.
> - GCP: Cloud Storage signed URLs or downscoped credentials.

**Files affected:** new
`packages/capability-issuer/src/storage-grant/{azure,aws,gcp,index}.ts`,
`packages/common/src/types.ts` (new types), `issuer-service.ts`
(integration point), `packages/common/src/capability-validators.ts`
(already validates `storage://` resource patterns — no change).

## Problem

When the issuer mints a capability whose resource matches
`storage://...`, the resulting VC tells the gateway "this agent may
read/write this blob". But the agent still needs **a credential** for
the cloud storage service — without it, the agent must use long-lived
service-principal credentials baked into its environment, which
violates the entire least-privilege premise of the architecture.

The plan calls for the issuer to mint a *short-lived, narrowly-scoped
cloud-native credential* alongside the VC and return both to the
agent. The agent then uses the cloud credential for the actual data
plane call; the cloud's control plane enforces scope independently of
our gateway (defense in depth).

## Goals

- For each of Azure / AWS / GCP, mint a short-lived storage credential
  whose scope (path, action, expiry) matches the issued capability's
  scope exactly — never broader.
- The credential's lifetime is `min(capabilityTtl, configured
  storageGrantMaxTtl, default 15 min)`.
- The credential is returned in the `IssueCapabilityResponse` next to
  (not inside) the VC, so the VC stays small and signature-stable.
- Issuance still succeeds when no `storage://` capabilities are
  present — this feature is a *no-op* for non-storage resources.
- Per-cloud SDKs are lazy-loaded so an Azure-only deployment does not
  pay the AWS/GCP SDK install cost.

## Non-goals

- Minting credentials for storage providers outside the big three
  (e.g. MinIO, Backblaze) — pattern is extensible but not in scope.
- Refreshing storage credentials mid-session — when the capability
  expires, the agent re-issues and gets a fresh storage grant.
- Cross-account / cross-tenant grants (e.g. STS AssumeRole into a
  customer account) — separate design.

## Design

### 1. Resource URI parsing

`storage://` resources today are free-form strings. To mint a SAS or
presigned URL we need to know:

- **Cloud** (azure / aws / gcp).
- **Container / bucket.**
- **Path / prefix** (or wildcard).

Define a canonical form, validated in
`packages/common/src/capability-validators.ts`:

```
storage://{cloud}/{account-or-bucket}/{container-or-prefix}/{key-or-pattern}

examples:
  storage://azure/salesdata/reports/2026/**
  storage://aws/euno-uploads/incoming/*.json
  storage://gcp/euno-models/v3/checkpoint.pt
```

Backwards compat: existing `storage://*` patterns that don't match
this canonical form continue to work for *validation* (gateway-side
deny/allow logic untouched), but only canonical forms are eligible
for grant issuance. Non-canonical patterns produce a structured
warning in the audit log: `storage_grant_skipped: non_canonical_uri`.

### 2. New types

In `packages/common/src/types.ts`:

```
type StorageProvider = 'azure-blob' | 's3' | 'gcs';

interface StorageGrant {
  provider: StorageProvider;
  // Resource the grant scopes to (echoes the capability's resource).
  resource: ResourceId;
  // Allowed actions on this resource (subset of the capability's actions).
  actions: Action[];
  // ISO-8601 expiry of the cloud credential itself (independent of VC exp).
  expiresAt: string;
  // Provider-specific credential payload — exactly one of these is set.
  azureSas?: { url: string; sasToken: string };
  s3Presigned?: { method: 'GET'|'PUT'|'DELETE'; url: string; headers?: Record<string,string> }[];
  gcsSigned?:   { method: 'GET'|'PUT'|'DELETE'; url: string }[];
}

// Extension to existing IssueCapabilityResponse — additive, optional.
interface IssueCapabilityResponse {
  // ... existing fields ...
  storageGrants?: StorageGrant[];
}
```

For multi-object capabilities (wildcards), AWS and GCP cannot mint a
single URL; they need either downscoped session credentials (AWS STS
AssumeRole + scope-down policy; GCP downscoped credentials with
Credential Access Boundaries). Provider modules handle this:

- **Wildcard or prefix** → return downscoped session credentials
  (`StorageGrant.s3Session?: {accessKeyId, secretAccessKey,
  sessionToken, expiration}` and equivalent for GCS).
- **Single-object** → presigned URL.

The plan explicitly mentions both as acceptable, so the union type
covers both shapes.

### 3. Provider module shape

```
packages/capability-issuer/src/storage-grant/
  index.ts        // exports StorageGrantMinter interface + factory
  azure.ts        // Azure Blob SAS via @azure/storage-blob
  aws.ts          // S3 presign / STS AssumeRole via @aws-sdk/client-sts + s3-request-presigner
  gcp.ts          // GCS signed URL / downscoped creds via @google-cloud/storage
  types.ts        // shared minter contract
```

`StorageGrantMinter` interface:

```
mint(input: {
  resource: ResourceId;
  actions: Action[];
  ttlSeconds: number;
  agentId: string;        // for audit + key naming
  authorizedBy: string;   // userId
}): Promise<StorageGrant>;
```

Each provider implementation:

- Validates the resource matches its provider scheme; throws if not.
- Maps euno `actions` to provider permissions:
  - Azure SAS: `read→r`, `write→w`, `delete→d`, `list→l`.
  - S3: `read→GetObject`, `write→PutObject`, `delete→DeleteObject`,
    `list→ListBucket`.
  - GCS: same as S3.
- Caps TTL to provider maximums (Azure SAS user-delegation 7 days
  but we cap at 1h; S3 presigned 7 days but we cap at 1h; GCS 7
  days but we cap at 1h — operator-overridable but never above
  provider max).

#### Azure-specific

Use **user-delegation SAS** (signed with an Azure AD-issued key,
not the storage account key). Requires `@azure/storage-blob`'s
`BlobServiceClient.getUserDelegationKey()`. The credential the
issuer uses to call this must have `Storage Blob Delegator` role on
the storage account.

User-delegation SAS is preferred over account-key SAS because:
- It is bound to the issuer's AAD identity (auditable in storage
  logs).
- Revoking the issuer's role immediately invalidates all outstanding
  SAS tokens.
- It cannot be used to mint admin-scoped SAS even if the storage
  account key is later compromised.

#### AWS-specific

Two paths:

1. **Single object:** `getSignedUrl(s3Client, new GetObjectCommand({
   Bucket, Key }), { expiresIn })` from `@aws-sdk/s3-request-presigner`.
2. **Prefix / wildcard:** `STS.assumeRole` with a scope-down
   `Policy` parameter restricting `s3:*` actions to the prefix.
   The role assumed must have a trust policy allowing the issuer's
   IAM principal.

#### GCP-specific

Two paths:

1. **Single object:** `bucket.file(name).getSignedUrl({...})`.
2. **Prefix / wildcard:** Use Credential Access Boundaries via
   `google-auth-library`'s `DownscopedClient` to bound a service
   account credential to the prefix.

### 4. Issuer-service integration

In `CapabilityIssuerService.issueCapability()`, after the
capabilities are resolved and the VC is signed:

```
// Pseudocode placement only — no implementation in this doc.
const storageCaps = grantedCapabilities.filter(c =>
  parseStorageUri(c.resource) !== null
);
const grants = await Promise.all(
  storageCaps.map(c => grantMinter.mint({
    resource: c.resource,
    actions: c.actions,
    ttlSeconds: Math.min(ttlSeconds, MAX_STORAGE_GRANT_TTL),
    agentId: request.agentId,
    authorizedBy: userContext.userId,
  }))
);
response.storageGrants = grants.length ? grants : undefined;
```

Each grant emits an audit entry:
`eventType: 'issuance', metadata.storageGrant: { provider, resource,
actions, expiresAt }`. The credential payload itself is **never**
written to the audit log.

### 5. Configuration

New env / config block:

```
STORAGE_GRANTS_ENABLED=true
STORAGE_GRANT_MAX_TTL_SECONDS=900
AZURE_STORAGE_DELEGATOR_VAULT=<keyvault url>   # optional - identity used
AWS_STORAGE_GRANT_ROLE_ARN=arn:aws:iam::...:role/euno-storage-grant
GCP_STORAGE_GRANT_SA=euno-grant@project.iam.gserviceaccount.com
```

If `STORAGE_GRANTS_ENABLED=false` (default for now), the entire
storage-grant pipeline is skipped — additive, no behavior change for
existing deployments.

### 6. Failure handling

- If grant minting fails for **one** capability, the entire issuance
  fails (`CapabilityError(STORAGE_GRANT_FAILED, ..., 502)`). Reason:
  partial grants give the agent a misleading view of what it can
  access.
- Cloud-API failures (5xx, timeouts) are retried with exponential
  backoff up to 3 attempts before surfacing as `STORAGE_GRANT_FAILED`.

## Test strategy

- **Unit per provider** with the cloud SDK mocked (existing pattern
  in `aws-kms-signer.test.ts`, `azure-signer.test.ts`):
  - Resource → provider permission mapping for all four actions.
  - TTL capping at provider max and at operator max.
  - Wildcard vs. single-object branch selection.
  - Permission-mapping-failure → throws structured error.
- **Issuer-service integration:**
  - Storage capability + non-storage capability in same request →
    only storage gets a grant.
  - Mint failure → entire issuance fails, no partial response.
  - `STORAGE_GRANTS_ENABLED=false` → no grants, no SDK calls.
- **End-to-end (gated, not in default CI):** opt-in test against
  real Azure Storage emulator (Azurite), MinIO for S3, and the GCS
  fake server (`fsouza/fake-gcs-server`) — round-trips a real upload
  through a real SAS / presigned / signed URL.

## Rollout

- Phase 1: types + interface + Azure-only minter behind flag.
- Phase 2: add AWS minter.
- Phase 3: add GCP minter.
- Phase 4: enable by default in dev compose; document in
  `docs/THIRD_PARTY_PROVIDERS.md`; require operator opt-in for prod.

Each phase is its own PR and its own release.

## Risks

- **Credential leakage in logs.** The grant payload contains
  bearer-equivalent secrets. Add an explicit allow-list of fields in
  the audit logger (already redaction-aware — verify) and a unit test
  asserting `sasToken`, `secretAccessKey`, etc. never appear.
- **TTL inversion.** A grant outliving the capability gives the agent
  data-plane access after its VC has expired. The `min()` cap
  prevents this, but a unit test must assert it.
- **Cloud-IAM misconfiguration.** Issuer needs `Storage Blob Delegator`
  / `sts:AssumeRole` / SA token-creator privileges. Failure mode is
  a 5xx from the cloud — surfaced as `STORAGE_GRANT_FAILED`. Document
  the IAM setup in a runbook.
- **Bucket / account name leakage** in resource URIs. Already public
  in capability validators; no new exposure.

## Open questions

- Should grants be requestable independently of capability issuance
  (e.g. a `/grant-storage` endpoint for already-issued capabilities)?
  Not for Sprint 3 — capability + grant are co-issued. Revisit if
  agents need to refresh grants without re-auth.
- Where do downscoped session credentials (multi-object case) live in
  the response — same `storageGrants` array with a different shape,
  or a separate `storageSessions` array? Recommend same array with
  the discriminated union above; keeps client code uniform.
