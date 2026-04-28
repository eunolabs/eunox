# Item #8 — Short-Lived Database Access Token Issuance

**Plan reference:** `docs/execution-plan.md` Sprint 3 → Team DP →
"Full Spectrum Tool Enforcement / Database queries" (line 220):
> Use token-based auth for Azure SQL DB. Generate short-lived DB
> access tokens as part of the agent's capability. Provide equivalent
> patterns for Amazon RDS / Aurora IAM database authentication and
> Cloud SQL IAM database authentication.

**Files affected:** new
`packages/capability-issuer/src/db-token/{azure-sql,rds,cloudsql,index}.ts`,
`packages/common/src/types.ts`, `issuer-service.ts`,
`packages/common/src/capability-validators.ts` (generic `db://`
capability-family validation only — canonical `db://{cloud}/...`
form parsing and validation lives in the DB token minter/parser
module, so no validator change is required here).

## Problem

Identical shape to #7 but for databases. Today, an agent with a
capability scoped to `db://salesdb/orders.read` still has to present
*some* database credential to actually run a query — and that
credential is currently long-lived and broadly scoped.

The plan calls for IAM database authentication on each cloud, where
the issuer mints a short-lived bearer token that the database
recognizes and authorizes against the cloud's own IAM:

- **Azure SQL Database:** AAD access token (`https://database.windows.net/.default`)
  obtained via `DefaultAzureCredential.getToken()`.
- **AWS RDS / Aurora (PostgreSQL or MySQL with IAM auth enabled):**
  15-minute auth token from `RDS.Signer.getAuthToken({ hostname,
  port, username, region })`.
- **Cloud SQL (PostgreSQL / MySQL with IAM auth):** OAuth2 access
  token for the service account, scoped to
  `https://www.googleapis.com/auth/sqlservice.admin` (used by the
  Cloud SQL Auth Proxy or directly with `password=<token>`).

This is the same architectural pattern as #7 — read both designs
together — but the per-cloud APIs and the per-cloud security model
differ enough to justify a separate module.

## Goals

- Mint a short-lived DB credential alongside the VC for any
  capability whose resource matches `db://...`.
- The credential is bound (via the database's IAM) to the same
  database user / role identified in the capability's resource URI;
  the database — not our gateway — enforces scope.
- Co-located lifetime: DB credential expiry ≤ capability expiry,
  capped at provider max (Azure: 24h soft / cap to 15min; RDS:
  15min hard; Cloud SQL: 1h soft / cap to 15min).
- Lazy SDK loading per cloud.

## Non-goals

- Authoring database GRANTs (operator concern).
- Connection-pool provisioning, proxy bring-up, etc. (agent runtime
  concern).
- Non-IAM database auth (basic password auth is what we are
  *replacing*; we do not maintain a code path for it).

## Design

### 1. Resource URI parsing

Canonical form (parsed and validated by the DB token minter, **not**
by `capability-validators.ts` — see "Files affected" above):

```
db://{cloud}/{instance}/{database}/{schema-or-table}.{action}

examples:
  db://azure-sql/salesserver/salesdb/orders.read
  db://rds/prod-postgres/billing/invoices.read
  db://cloudsql/analytics-pg/events/raw_events.read
```

The DB engine (postgres/mysql/sqlserver) is an *attribute of the
instance*, not the resource URI — fetched from operator config keyed
by `instance`.

### 2. New types

In `packages/common/src/types.ts`:

```
type DbProvider = 'azure-sql' | 'rds-iam' | 'cloudsql-iam';

interface DbCredential {
  provider: DbProvider;
  resource: ResourceId;             // echoes the capability's resource
  actions: Action[];
  expiresAt: string;                // ISO-8601, ≤ capability exp
  // Connection hints (operator-confirmed via config; never invented).
  host: string;
  port: number;
  database: string;
  username: string;                 // the IAM-mapped DB user
  // The bearer token. For Azure SQL this is an AAD JWT; for RDS it
  // is the IAM auth token (passed as the password); for Cloud SQL it
  // is the OAuth2 access token.
  token: string;
}

interface IssueCapabilityResponse {
  // ... existing + storageGrants ...
  dbCredentials?: DbCredential[];
}
```

### 3. Provider modules

```
packages/capability-issuer/src/db-token/
  index.ts        // factory + DbTokenMinter interface
  azure-sql.ts    // @azure/identity: getToken('https://database.windows.net/.default')
  rds.ts          // @aws-sdk/rds-signer
  cloudsql.ts     // google-auth-library: getAccessToken w/ sqlservice.admin scope
```

Each implements:

```
mint(input: {
  resource: ResourceId;
  actions: Action[];
  ttlSeconds: number;
  agentId: string;
  authorizedBy: string;        // userId
  // The IAM principal mapped to the DB user. Resolved by issuer-side
  // role-mapping config — NOT taken from agent input (would be a
  // privilege-escalation vector).
  dbUsername: string;
}): Promise<DbCredential>;
```

#### azure-sql.ts

```
const cred = new ManagedIdentityCredential();           // or DefaultAzureCredential
const tok  = await cred.getToken('https://database.windows.net/.default');
```

The `dbUsername` here is the AAD-mapped DB principal name (e.g.
`agent-app@tenant.onmicrosoft.com`). The token itself encodes the
identity; the username is informational for the agent's connection
string.

#### rds.ts

```
import { Signer } from '@aws-sdk/rds-signer';
const signer = new Signer({ hostname, port, username, region });
const token  = await signer.getAuthToken();   // 15-minute lifetime
```

The IAM principal that the issuer runs as must have
`rds-db:connect` on `arn:aws:rds-db:{region}:{acct}:dbuser:{instance}/{username}`.
Document the IAM policy template.

#### cloudsql.ts

```
import { GoogleAuth } from 'google-auth-library';
const auth = new GoogleAuth({ scopes: ['https://www.googleapis.com/auth/sqlservice.admin'] });
const client = await auth.getClient();
const tok = await client.getAccessToken();
```

For Postgres, the agent connects with `user=<iam-username>,
password=<token>` (Cloud SQL accepts the OAuth token as the
password when IAM auth is enabled).

### 4. Issuer-service integration

Mirrors #7 exactly. After capability resolution:

```
const dbCaps = grantedCapabilities.filter(c =>
  parseDbUri(c.resource) !== null
);
const dbCreds = await Promise.all(dbCaps.map(c => dbMinter.mint({...})));
response.dbCredentials = dbCreds.length ? dbCreds : undefined;
```

If both #7 and #8 land, the issuance loop iterates over capabilities
once, dispatching to the right minter (`storage` vs `db`) — share a
single dispatch table to keep the code readable.

### 5. Configuration

```
DB_TOKENS_ENABLED=true
DB_TOKEN_MAX_TTL_SECONDS=900

# Per-instance config — operator must declare each instance the
# issuer is allowed to mint tokens for. Prevents an agent from
# requesting db://my-attacker-instance/... and getting a token.
DB_INSTANCES_FILE=/etc/euno/db-instances.yaml

# Example file:
# instances:
#   - id: salesserver
#     provider: azure-sql
#     host: salesserver.database.windows.net
#     port: 1433
#     databases: [salesdb, archivedb]
#   - id: prod-postgres
#     provider: rds-iam
#     host: prod-postgres.cluster-xxx.us-east-1.rds.amazonaws.com
#     port: 5432
#     databases: [billing, analytics]
```

The role-mapping layer in `packages/common/src/role-mapping.ts` is
extended to declare, per role, which `dbUsername` is used:

```
role: data-analyst
  capabilities: [db://*/*.read]
  dbUsername: euno_readonly        # IAM-mapped DB principal
```

This decoupling ensures the agent cannot pick its DB principal.

### 6. Failure handling

Same as #7: any minting failure aborts the issuance.

## Test strategy

- **Unit per provider** with cloud SDKs mocked:
  - `azure-sql.ts`: `getToken` mocked to return a fixed JWT;
    assert `expiresAt` echoes the SDK's `expiresOnTimestamp`.
  - `rds.ts`: `Signer.getAuthToken` mocked; assert hostname/port/
    username are wired from the parsed resource and operator config,
    *not* from agent input.
  - `cloudsql.ts`: `GoogleAuth.getClient` + `getAccessToken` mocked.
- **Issuer-service integration:**
  - DB capability for instance not in `DB_INSTANCES_FILE` →
    `DB_INSTANCE_UNKNOWN` error, no SDK call made.
  - Two DB capabilities for two different providers → two
    credentials returned, ordering preserved.
  - Mint failure → entire issuance fails.
- **End-to-end (opt-in):** Postgres + IAM auth in a local docker
  container with a stubbed RDS signer; assert a real `psql`
  connection succeeds with the minted token as password.

## Rollout

Same phasing as #7: Azure-first, then AWS, then GCP. Each behind the
`DB_TOKENS_ENABLED` flag.

## Risks

- **Privilege escalation via username injection.** The agent must
  *never* be able to choose its DB principal — that's the whole
  point of binding `dbUsername` to the role mapping. The role-mapping
  schema change is the single most important security boundary in
  this design; cover it with a dedicated test:
  > "Agent requests `db://salesserver/salesdb/orders.read` while
  >  having only the `data-analyst` role. The minted credential's
  >  `username` MUST equal `euno_readonly`, regardless of any
  >  request-side hint."
- **Token leakage in audit logs.** Same redaction concern as #7;
  reuse the same allow-list infrastructure.
- **TTL drift between cloud and gateway.** All three providers report
  expiry; trust the SDK's value, never compute it ourselves from
  `now + 15min`.
- **RDS region mismatch.** `Signer` requires the exact region; a
  misconfiguration produces a token the database silently rejects.
  Validate region against operator config at startup, not at mint
  time.

## Open questions

- Should we mint tokens for the *Cloud SQL Auth Proxy* (which then
  handles auth) instead of for direct `psql` connections? The proxy
  path is operationally simpler but adds a sidecar. Recommend
  supporting both: `cloudsql.ts` minter is identical (same OAuth
  token); the agent-side connection details differ. Documented in
  the runbook, not in code.
- Postgres vs. MySQL token format differences — RDS auth tokens are
  identical for both engines; Cloud SQL same. No code branch needed.
- Should we mint *connection strings* instead of raw tokens (so
  agents don't have to know the exact format)? Recommend keeping the
  raw token + connection hints (`host`, `port`, etc.) — connection-
  string assembly is framework-specific and belongs in the agent
  runtime adapters.
