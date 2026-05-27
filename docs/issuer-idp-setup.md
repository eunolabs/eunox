# Capability Issuer — IdP Setup Guide

> **Target audience:** Platform engineers configuring the Capability Issuer to
> authenticate users via an enterprise identity provider.
>
> **Status:** Current. Both the hosted product and the self-host docker image
> are covered here.
>
> **Related documents:**
>
> - [`docs/self-host.md`](./self-host.md) — self-host overview and deployment topology
> - [`docs/deployment.md`](./deployment.md) — full environment-variable reference
> - [`docs/security/issuer-threat-model.md`](./security/issuer-threat-model.md) — threat model (IdP-token replay, nonce binding, aud/iss enforcement)

---

## 1. Overview

The Capability Issuer authenticates users by validating an **ID token** issued
by an upstream enterprise IdP. The validation covers:

| Claim / check             | Enforced by                                                   |
| ------------------------- | ------------------------------------------------------------- |
| Signature (RS256 / ES256) | `jose` `jwtVerify` against IdP JWKS                           |
| `iss` (issuer)            | Provider-specific issuer URL                                  |
| `aud` (audience)          | Client ID / app URI                                           |
| `exp` / `iat`             | `jose` `jwtVerify`                                            |
| `nonce` binding           | Endpoint: `claims.nonce` must equal the request `nonce` field |
| Authorization-code replay | `OidcStateStore`: each code accepted at most once             |

Role claims extracted from the validated token are mapped to capability
constraints; the request body can **never** escalate the resulting role set
(role-from-token invariant).

### Supported providers

| Provider                           | `IDENTITY_PROVIDER` value |
| ---------------------------------- | ------------------------- |
| Microsoft Entra ID (Azure AD)      | `azure-ad` (default)      |
| AWS Cognito                        | `aws-cognito`             |
| GCP Cloud Identity / Firebase Auth | `gcp-identity`            |

---

## 2. Entra ID (Azure AD) — app registration

### 2.1 Create an app registration

1. Open **Azure Portal → Entra ID → App registrations → New registration**.
2. **Name**: `eunox-capability-issuer-<env>` (e.g. `eunox-capability-issuer-prod`).
3. **Supported account types**: _Accounts in this organizational directory only
   (Single tenant)_.
4. **Redirect URI**: leave blank for now (the issuer uses the PKCE
   authorization-code flow entirely at the client CLI level; no redirect URI
   is registered on the server side).
5. Click **Register**.

### 2.2 Expose App Roles

The issuer derives capabilities from the `roles` claim in the ID token. Define
at least one app role for each capability tier you intend to grant.

1. In your app registration, open **App roles → Create app role**.
2. Set **Display name** to match the role strings in your
   `ROLE_CAPABILITY_POLICY` file (e.g. `Reader`, `Writer`, `Admin`).
3. **Allowed member types**: Users/Groups.
4. **Value**: must match exactly what the `roles` claim will carry (e.g.
   `Reader`).
5. Enable the role and save.

### 2.3 Assign users (or groups) to roles

1. Open **Entra ID → Enterprise applications → <your app> → Users and groups**.
2. Click **Add user/group**, select the user or group, then assign the relevant
   role.

### 2.4 Collect configuration values

| Variable             | Where to find it                             |
| -------------------- | -------------------------------------------- |
| `AZURE_AD_TENANT_ID` | **Overview** page: _Directory (tenant) ID_   |
| `AZURE_AD_CLIENT_ID` | **Overview** page: _Application (client) ID_ |

### 2.5 Conditional Access (recommended for production)

Add a Conditional Access policy in Entra ID that requires MFA for your app
registration in production environments. The issuer's `AzureADIdentityProvider`
reads the `xms_cc` claim (Continuous Access Evaluation) and enforces it when
`REQUIRE_CA_TIERS` is set.

### 2.6 Privileged Identity Management (PIM) — optional

If you use Azure AD PIM for JIT role activation:

- Set `PIM_REQUIRED_ROLES` to the comma-separated list of roles that MUST be
  currently active.
- Set `CAP_TTL_TO_PIM_ACTIVATION=true` (default) so capability tokens expire
  when the PIM activation window closes.

### 2.7 Environment variables

```bash
IDENTITY_PROVIDER=azure-ad
AZURE_AD_TENANT_ID=<directory-tenant-id>
AZURE_AD_CLIENT_ID=<application-client-id>

# Optional — require Conditional Access tiers
# REQUIRE_CA_TIERS=read,write,admin

# Optional — PIM
# PIM_REQUIRED_ROLES=Writer,Admin
# CAP_TTL_TO_PIM_ACTIVATION=true
```

---

## 3. AWS Cognito — user pool setup

### 3.1 Create a User Pool

1. Open **AWS Console → Cognito → User pools → Create user pool**.
2. **Authentication providers**: Email (or username).
3. **Sign-in experience**: keep defaults.
4. **Security requirements**: enforce strong password + MFA for production.
5. **Sign-up experience**: disable self-registration for enterprise deployments
   (admin-only user creation).
6. **Message delivery**: configure SES for email in production.
7. **App integration → App client**: click **Create app client**.
   - **App type**: Public client.
   - **Authentication flows**: check `ALLOW_USER_SRP_AUTH`,
     `ALLOW_REFRESH_TOKEN_AUTH`.
   - Note the **Client ID**.
8. **Hosted UI**: configure the Cognito Hosted UI with your callback URL if
   using the Cognito-managed authorization endpoint.

### 3.2 Add app roles via Groups

Cognito exposes group membership as the `cognito:groups` claim. The
`AWSCognitoIdentityProvider` maps `cognito:groups` to `roles` in the
`UserContext`.

1. In your User Pool, open **Groups → Create group**.
2. Name the group to match your role policy (e.g. `Reader`, `Writer`, `Admin`).
3. Assign users to groups as appropriate.

### 3.3 Configure a custom `nonce` claim

Cognito's hosted UI automatically includes a `nonce` claim in ID tokens when
the authorization request carries a `nonce` parameter. No extra configuration
is needed — the `eunox request` CLI generates and validates it automatically.

If you are using the programmatic flow (sending `idToken` directly to
`POST /api/v1/oidc/token`), your client is responsible for:

1. Generating a cryptographically random nonce (≥ 128 bits of entropy).
2. Passing `nonce` in the Cognito authorization URL.
3. Passing the same `nonce` value in the `POST /api/v1/oidc/token` body.

### 3.4 Collect configuration values

| Variable                   | Where to find it                                              |
| -------------------------- | ------------------------------------------------------------- |
| `AWS_COGNITO_USER_POOL_ID` | User pool → **Overview**: _Pool ID_ (e.g. `us-east-1_XYZabc`) |
| `AWS_COGNITO_CLIENT_ID`    | App integration → App clients: _Client ID_                    |
| `AWS_COGNITO_REGION`       | First segment of the Pool ID (e.g. `us-east-1`)               |

### 3.5 Environment variables

```bash
IDENTITY_PROVIDER=aws-cognito
AWS_COGNITO_USER_POOL_ID=us-east-1_XYZabc
AWS_COGNITO_CLIENT_ID=<app-client-id>
# Derived from User Pool ID automatically; set explicitly if needed:
# AWS_COGNITO_REGION=us-east-1
# Optional — restrict to id tokens vs access tokens:
# AWS_COGNITO_TOKEN_USE=id    # default: id
```

---

## 4. Per-tenant IdP configuration

For multi-tenant deployments where different tenants authenticate via
different IdP configurations, use the `ISSUER_TENANT_IDP_CONFIG_FILE` variable
to supply a JSON file mapping tenant IDs to per-tenant provider settings.

The global `IDENTITY_PROVIDER` / `AZURE_AD_*` / `AWS_COGNITO_*` settings
serve as the fallback for tenants not listed in the file.

### 4.1 File format

```json
{
  "tenants": {
    "tenant-a": {
      "provider": "azure-ad",
      "azureAD": {
        "tenantId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "clientId": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
      }
    },
    "tenant-b": {
      "provider": "aws-cognito",
      "awsCognito": {
        "region": "us-east-1",
        "userPoolId": "us-east-1_CognitoPool",
        "clientId": "cognito-client-id"
      }
    }
  }
}
```

### 4.2 Hot-reload

Send `SIGHUP` to the issuer process to trigger a live reload of the tenant IdP
config file:

```bash
kill -HUP <issuer-pid>
```

If the new file is invalid JSON or fails schema validation, the previous
configuration is preserved and an error is logged — no traffic is disrupted.

> **Note:** The registry does **not** watch the file for filesystem changes
> automatically. A `SIGHUP` (or a rolling restart) is required to pick up
> edits.

### 4.3 Environment variable

```bash
ISSUER_TENANT_IDP_CONFIG_FILE=/etc/eunox/tenant-idp-config.json
```

---

## 5. OIDC discovery document

The issuer exposes a discovery document at
`GET /.well-known/openid-configuration`. To include the `authorization_endpoint`
and `token_endpoint` URLs, set:

```bash
ISSUER_PUBLIC_URL=https://issuer.example.com
```

When `tenantId` is passed as a query parameter
(`?tenantId=tenant-a`), the document reflects the per-tenant provider:

```
GET /.well-known/openid-configuration?tenantId=tenant-a
```

---

## 6. Authorization-code replay prevention

The issuer tracks every authorization code submitted to
`POST /api/v1/oidc/token`. Each code is accepted at most once within a
configurable TTL window. Replay attempts receive `401 AUTHENTICATION_FAILED`.

```bash
# TTL for used-code tombstones and pending state entries (default: 600 seconds)
OIDC_CODE_TTL_SECONDS=600
```

---

## 7. OIDC token endpoint — client flow

The client (typically the `eunox request` CLI) follows this flow:

```
1. GET  /api/v1/oidc/authorize?agentId=<agent>
   → receives { state, nonce }

2. Build upstream IdP authorization URL:
     <idp-auth-endpoint>
       ?response_type=code
       &client_id=<AZURE_AD_CLIENT_ID | AWS_COGNITO_CLIENT_ID>
       &redirect_uri=<your-redirect-uri>
       &scope=openid+profile+email
       &state=<state from step 1>
       &nonce=<nonce from step 1>
       &code_challenge=<PKCE S256 challenge>
       &code_challenge_method=S256

3. User authenticates in browser; IdP redirects to redirect_uri
   with code= and state= parameters.

4. Client exchanges code at IdP token endpoint for idToken.

5. POST /api/v1/oidc/token
     Content-Type: application/json
     {
       "idToken":  "<ID token from step 4>",
       "nonce":    "<nonce from step 1>",
       "code":     "<code from step 3>",
       "state":    "<state from step 1>",
       "agentId":  "<agent-id>"
     }
   → receives { token, expiresAt, tokenId, capabilities }
```

The `nonce` from step 1 must appear as the `nonce` claim inside the signed ID
token. The issuer rejects any token whose `nonce` claim does not match.

---

## 8. SCIM 2.0 provisioning

The issuer supports push-based group provisioning from enterprise IdPs
(Okta, Microsoft Entra ID, Ping Identity) via the **SCIM 2.0** protocol.
When enabled, the issuer acts as a SCIM service provider: the enterprise
IdP pushes user and group lifecycle events to `/scim/v2/` and the issuer
stores them in its Postgres database.

At issuance time, the user's current SCIM group memberships are looked up
and the mapped roles are **added** to the IdP-provided role set (union).
SCIM group memberships are the authoritative source for _group-derived_
roles; IdP token claims remain the primary authentication signal and
continue to contribute their own roles. SCIM enrichment never removes
roles that were already granted by the IdP.

If the SCIM lookup fails (e.g. database outage), the issuer falls back to
IdP-only roles (fail-open) and logs a warning.

### 8.1 Prerequisites

- `ISSUER_DB_URL` must be set (SCIM data is stored in the same Postgres
  database as the manifest template store).
- The SCIM tables (`scim_users`, `scim_groups`, `scim_group_members`) are
  created automatically on first startup when `ISSUER_SCIM_BEARER_TOKEN`
  is set and `ISSUER_DB_URL` is configured — you do **not** need to set
  `ISSUER_DB_SCHEMA_INIT=true` separately (though setting it is harmless
  and ensures all tables are always in sync).

### 8.2 Environment variables

| Variable                     | Description                                                                                                                                                                                |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `ISSUER_SCIM_BEARER_TOKEN`   | **Required.** Static bearer token the IdP sends on every SCIM request. Validated with constant-time comparison. ≥32 characters; rotate immediately on exposure.                            |
| `ISSUER_SCIM_GROUP_ROLE_MAP` | **Optional.** JSON object mapping SCIM group `displayName` → issuer role key. Example: `{"SalesTeam":"sales","EngineeringTeam":"engineer"}`. Unmapped groups are ignored at issuance time. |

```bash
ISSUER_DB_URL=postgres://issuer:secret@db:5432/issuer_db
ISSUER_SCIM_BEARER_TOKEN=<at-least-32-chars-random-secret>
ISSUER_SCIM_GROUP_ROLE_MAP='{"SalesTeam":"sales","EngineeringTeam":"engineer"}'
```

### 8.3 SCIM endpoints

| Method   | Path                  | Description                                                                                                                                   |
| -------- | --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST`   | `/scim/v2/Users`      | Provision a new user                                                                                                                          |
| `GET`    | `/scim/v2/Users`      | List users (supports `?filter=`, `?count=`, `?startIndex=`)                                                                                   |
| `GET`    | `/scim/v2/Users/:id`  | Get user by SCIM ID                                                                                                                           |
| `PUT`    | `/scim/v2/Users/:id`  | Replace user (preserves `active` when omitted per RFC 7644)                                                                                   |
| `PATCH`  | `/scim/v2/Users/:id`  | Partial update / deprovision (`active=false`); supports `add`, `replace`, `remove` operations                                                 |
| `DELETE` | `/scim/v2/Users/:id`  | Soft-delete user and remove all group memberships                                                                                             |
| `POST`   | `/scim/v2/Groups`     | Provision a new group                                                                                                                         |
| `GET`    | `/scim/v2/Groups`     | List groups (supports `?filter=`, `?count=`, `?startIndex=`)                                                                                  |
| `GET`    | `/scim/v2/Groups/:id` | Get group by SCIM ID                                                                                                                          |
| `PUT`    | `/scim/v2/Groups/:id` | Replace group (replaces full membership set atomically)                                                                                       |
| `PATCH`  | `/scim/v2/Groups/:id` | Membership delta: `add` appends members; `replace` on `members` replaces the full set (RFC 7644 §3.5.2.3); `remove` removes specified members |
| `DELETE` | `/scim/v2/Groups/:id` | Delete group and remove all memberships                                                                                                       |

All endpoints require `Authorization: Bearer <ISSUER_SCIM_BEARER_TOKEN>`.
Unauthenticated requests receive `401 Unauthorized` with
`WWW-Authenticate: Bearer realm="SCIM"`.

### 8.4 User identity mapping

The SCIM user lookup at issuance time uses two identifiers from the IdP token:

1. **externalId** — matched against the IdP `sub` claim (`userContext.userId`).
2. **userName** — matched against `userContext.email` (the user's email /
   UPN from the IdP token), falling back to `userContext.userId`.

For SCIM enrichment to work reliably in production, the IdP MUST push the
user's `sub` claim as the SCIM `externalId` field. If neither the externalId
nor the email/userName match any active SCIM user, enrichment is silently
skipped and only IdP-provided roles are used.

**Okta:** Enable **Push User to App** and map the Okta `externalId`
attribute to the SCIM `externalId` field in the provisioning configuration.

**Entra ID:** The default User attribute mappings include `objectId →
externalId` — leave this mapping active.

### 8.5 Configuring Okta

1. In Okta Admin: **Applications → {your app} → Provisioning → Integration**
   - Enable **SCIM provisioning**.
   - SCIM connector base URL: `https://<issuer-host>/scim/v2`
   - Unique identifier field for users: `userName`
   - Authentication mode: **HTTP Header**
   - Authorization: `Bearer <ISSUER_SCIM_BEARER_TOKEN>`

2. Under **To App**, enable:
   - Create Users
   - Update User Attributes
   - Deactivate Users
   - Sync Password (optional)

3. Assign the groups whose memberships should drive issuer roles to the
   application and ensure `ISSUER_SCIM_GROUP_ROLE_MAP` maps their display
   names to the appropriate role keys.

### 8.6 Configuring Microsoft Entra ID

1. In Entra ID Admin Centre: **Enterprise applications → {your app} →
   Provisioning**
   - Provisioning Mode: **Automatic**
   - Tenant URL: `https://<issuer-host>/scim/v2`
   - Secret Token: `<ISSUER_SCIM_BEARER_TOKEN>`
   - Click **Test Connection** to verify.

2. Under **Mappings**, ensure the default User and Group attribute mappings
   are active. The issuer expects `userName` (typically `userPrincipalName`)
   and `displayName` on groups. The default `objectId → externalId` user
   mapping should remain active so the issuance hot-path can match users by
   their Entra ID `sub` claim.

3. Under **Settings → Scope**, choose _Sync only assigned users and groups_
   and assign only the groups relevant to capability issuance.

### 8.7 Filter support

The issuer supports the following SCIM filter operators:

- `eq` — exact equality (e.g. `userName eq "alice@example.com"`)
- `co` — contains (e.g. `displayName co "Sales"`)

Filters on unsupported attributes return an empty result set.

### 8.8 Multi-tenancy

When the issuer is configured for per-tenant IdPs
(`ISSUER_TENANT_IDP_CONFIG_FILE`), SCIM provisioning is global by default
(a single bearer token covers all tenants). To achieve per-tenant SCIM
isolation, deploy separate issuer instances per tenant (recommended) or
use a reverse proxy that rewrites the Authorization header and routes to
tenant-scoped pools.

---

## 9. Security checklist

Before deploying to production:

- [ ] App registration (Entra ID) or User Pool (Cognito) is **single-tenant** or
      scoped to your organization.
- [ ] Role assignments are controlled by your IAM / directory team, not
      individual users.
- [ ] `OIDC_CODE_TTL_SECONDS` is set to a value ≤ 600 seconds.
- [ ] `ISSUER_PUBLIC_URL` is set to the exact URL clients will use (no trailing
      slash; `https` in production).
- [ ] The issuer is behind TLS termination with a valid certificate.
- [ ] PIM / Conditional Access policies are active for sensitive role tiers.
- [ ] `REQUIRE_CA_TIERS` is set for any capability action tier that should
      require MFA / compliant device (Entra ID only).
- [ ] The `ISSUER_TENANT_IDP_CONFIG_FILE` (if used) is read-only to the
      issuer process and write-protected at the host level.
- [ ] `ISSUER_SCIM_BEARER_TOKEN` (if SCIM is enabled) is at least 32 characters,
      stored in a secret manager, and rotated at least annually.
- [ ] `ISSUER_SCIM_GROUP_ROLE_MAP` is reviewed by an operator before deployment —
      mapping a group to an admin-tier role (e.g. `operator`) grants elevated
      capabilities to all members of that group.

---

## 9. DID-based partner issuers

> **Status:** Production stable. Use this section when configuring the issuer
> to authenticate agents whose identity tokens are signed by a DID-backed key
> rather than a centralized IdP.

### 9.1 Provider configuration

Set `IDENTITY_PROVIDER=did` to enable the DID-based identity provider. The
issuer resolves the JWT issuer field to a DID Document and validates the
signature against the verification method found in that document. Supported
DID methods: `did:web`, `did:ion`, `did:key`.

```bash
IDENTITY_PROVIDER=did
```

### 9.2 `did:ion` resolver

`did:ion` identifiers are resolved via a Sidetree REST API. The default
resolver is the public Microsoft ION node at
`https://ion.msidentity.com/api/v1.0/identifiers`.

```bash
# Override the default ION resolver (optional)
ION_RESOLVER_URL=https://ion.msidentity.com/api/v1.0/identifiers
```

#### 9.2.1 Air-gapped and private ION node

For deployments without outbound access to the Microsoft-hosted resolver,
two alternatives are supported:

**Option A — Azure ION private node (recommended for Entra ID environments)**

1. Deploy the Azure ION service into your subscription following the
   [Azure ION deployment guide](https://github.com/decentralized-identity/ion/blob/master/doc/azure-deployment.md).
2. Set `ION_RESOLVER_URL` to the private node's resolver endpoint:
   ```bash
   ION_RESOLVER_URL=https://ion.internal.example.com/api/v1.0/identifiers
   ```
3. Ensure the issuer process has network access to this endpoint. No
   additional TLS configuration is required — the standard system trust
   store is used.

**Option B — open-source ION sidecar (recommended for Kubernetes / air-gap)**

1. Build and deploy the open-source ION sidecar
   ([github.com/decentralized-identity/ion](https://github.com/decentralized-identity/ion))
   as a pod sidecar or a separate service in your cluster.
2. Expose the resolver via a ClusterIP service at a stable in-cluster URL,
   for example `http://ion-sidecar.eunox.svc.cluster.local:3000`.
3. Set the issuer env var:
   ```bash
   ION_RESOLVER_URL=http://ion-sidecar.eunox.svc.cluster.local:3000/api/v1.0/identifiers
   ```
4. For non-`did:web` DIDs no HTTP allow-list is needed. For `did:web` DIDs
   served internally over plain HTTP, add the host to
   `DID_WEB_ALLOW_HTTP_FOR_HOSTS` (comma-separated, e.g.
   `partner-sim.local:4001,did-registry.internal`).

### 9.3 ION circuit breaker

The issuer wraps every `did:ion` resolution call in a circuit breaker that
opens after repeated failures, preventing a sustained resolver outage from
blocking all DID-based authentication attempts with full network timeouts.

| Env var                    | Default | Description                                               |
| -------------------------- | ------- | --------------------------------------------------------- |
| `ION_CB_FAILURE_THRESHOLD` | `3`     | Number of failures within the window to open the circuit. |
| `ION_CB_WINDOW_SECONDS`    | `30`    | Sliding window (seconds) for failure counting.            |
| `ION_CB_COOLDOWN_SECONDS`  | `60`    | Seconds the circuit stays open before a probe is allowed. |

**Behaviour when circuit is open:**

`resolveDidIon()` immediately throws a `CapabilityError` with
`ErrorCode.AUTHENTICATION_FAILED` and HTTP 502. The error message includes
`circuit breaker is open` so it is distinguishable in logs and alerting.

**Tuning recommendations:**

- Production: keep the defaults (3 / 30 / 60). The window is short enough
  to catch a real outage (three failures in 30 s) without tripping on a
  single transient timeout.
- High-sensitivity environments: lower `ION_CB_FAILURE_THRESHOLD` to `2`
  and raise `ION_CB_COOLDOWN_SECONDS` to `120` to fail faster and recover
  more cautiously.
- High-traffic environments: raise `ION_CB_FAILURE_THRESHOLD` to `5` to
  tolerate transient glitches without opening the circuit.

### 9.4 `did:ion` health check

The issuer exposes a dedicated health check endpoint for the ION resolver:

```
GET /healthz/did-ion
```

**Response (always HTTP 200):**

```json
{ "status": "ok" }
```

or

```json
{ "status": "degraded", "reason": "circuit_open" }
{ "status": "degraded", "reason": "probe_failed" }
```

The endpoint always returns HTTP 200 so Kubernetes liveness probes that
include it continue to pass during transient ION outages — use the `status`
field in an alerting rule rather than the HTTP status code.

The probe DID is the well-known ION document
`did:ion:EiAnKD8-jfdd0MDcZUjAbRgaThBrMxPTFOxcnfJhI7iCCg` (published by
the DIF ION project). It is suitable as a canary for both the public Microsoft
resolver and any private ION sidecar that anchors on the same Bitcoin Mainnet.

> **Air-gapped / test networks:** On deployments where this DID is not
> anchored (private test networks, early-stage ION sidecars, or fully
> air-gapped environments), the probe will always return `degraded`. In
> these cases treat the health endpoint as informational only — the circuit
> breaker still protects against resolver failures at request time, and the
> `circuit_open` reason will appear in the degraded response once enough
> failures have accumulated.

### 9.5 Security notes

- `did:web` DIDs are fetched over HTTPS by default. HTTP is only allowed for
  hosts explicitly listed in `DID_WEB_ALLOW_HTTP_FOR_HOSTS` (intended for
  local CI/CD environments only — never use in production).
- `did:ion` resolution relies on the ION resolver's TLS certificate. For
  private nodes, use a certificate from a CA in the system trust store.
- `did:key` is stateless and requires no network call. It is always available
  regardless of ION resolver connectivity.

---

## 10. Cognito SCIM bridge (AWS IAM Identity Center)

> **Status:** Multi-cloud Phase 1. Use this section when you want to provision
> users and groups into the eunox issuer from AWS Cognito via the SCIM 2.0
> protocol, using **AWS IAM Identity Center** as the SCIM push source.

AWS Cognito User Pools do not have a built-in outbound SCIM push capability.
The recommended integration path is to use **AWS IAM Identity Center** (formerly
AWS SSO) as the SCIM push source, with the IAM Identity Center SCIM endpoint
configured to push to the eunox issuer's SCIM endpoint.

### 10.1 Architecture

```
AWS IAM Identity Center
  (SCIM automatic provisioning)
        │
        │  HTTPS POST /scim/v2/Users
        │  HTTPS POST /scim/v2/Groups
        ▼
eunox capability-issuer (/scim/v2/)
  ──► scim_users / scim_groups tables (Postgres)
        │
        ▼
  role enrichment at token issuance
  (IdP roles ∪ SCIM group-mapped roles)
```

IAM Identity Center acts as the identity source and SCIM push source.
Cognito User Pools authenticate users at runtime; IAM Identity Center
manages the authoritative group memberships that drive SCIM provisioning.

### 10.2 Prerequisites

- AWS IAM Identity Center enabled in your AWS organisation (or standalone account).
- `ISSUER_DB_URL` set and pointing at a Postgres instance.
- `ISSUER_SCIM_BEARER_TOKEN` set (≥ 32 characters, stored in Secrets Manager —
  see [`docs/secrets-aws.md`](./secrets-aws.md)).
- The eunox issuer is reachable from IAM Identity Center over HTTPS.
  On EKS, expose the issuer via an internal ALB with ACM certificate
  (see [`docs/deploy-eks.md`](./deploy-eks.md) §5).

### 10.3 IAM Identity Center — SCIM configuration

1. Open **AWS Console → IAM Identity Center → Settings → Automatic provisioning**.

2. Click **Enable** under _Automatic provisioning_. IAM Identity Center
   generates a **SCIM endpoint URL** and an **Access token**.

3. Copy the generated **SCIM endpoint URL** (e.g.
   `https://scim.us-east-1.amazonaws.com/…/scim/v2/`).
   You do **not** use this URL directly — instead, configure IAM Identity Center
   to push to the **eunox** SCIM endpoint (step 4).

4. Under **Identity source → External identity provider** (or built-in
   directory), navigate to **Provisioning** and supply the eunox SCIM endpoint:

   | Field         | Value                           |
   | ------------- | ------------------------------- |
   | SCIM endpoint | `https://<issuer-host>/scim/v2` |
   | Bearer token  | `<ISSUER_SCIM_BEARER_TOKEN>`    |

   > **Note:** If IAM Identity Center's provisioning UI does not support a
   > custom SCIM endpoint directly, use the **AWS SCIM gateway** Lambda
   > pattern described in §10.6.

5. Under **Attribute mappings**, verify the following mappings are active:

   | IAM Identity Center attribute          | SCIM attribute    |
   | -------------------------------------- | ----------------- |
   | `${user:AD_GUID}` or `${user:subject}` | `externalId`      |
   | `${user:email}`                        | `userName`        |
   | `${user:givenName}`                    | `name.givenName`  |
   | `${user:familyName}`                   | `name.familyName` |
   | `${user:displayName}`                  | `displayName`     |

   The eunox SCIM user lookup uses `externalId` (matched against the IdP `sub`
   claim) first, then `userName` (email). Ensure `externalId` is mapped to
   the same identifier that Cognito will include as the `sub` claim in ID
   tokens.

6. Click **Save configuration** and then **Test connection** to verify
   connectivity.

### 10.4 Group provisioning and role mapping

1. In IAM Identity Center, create **Groups** whose display names match the
   entries in your `ISSUER_SCIM_GROUP_ROLE_MAP`:

   ```bash
   # Example group display names → eunox roles
   ISSUER_SCIM_GROUP_ROLE_MAP='{"EunoReaders":"reader","EunoWriters":"writer","EunoAdmins":"admin"}'
   ```

2. Assign users to the relevant groups in IAM Identity Center.

3. IAM Identity Center pushes `POST /scim/v2/Groups` with the group's `displayName`
   and member list to the eunox issuer.

4. At token issuance time, the issuer looks up the authenticated user's SCIM
   group memberships and adds the mapped roles to the role set provided by
   the Cognito ID token (`cognito:groups` claim).

### 10.5 Attribute mappings for Cognito

When using Cognito as the runtime identity provider alongside IAM Identity
Center for SCIM provisioning, ensure the attribute values are consistent:

| Attribute       | Cognito ID token claim           | IAM Identity Center → SCIM `externalId`                                  |
| --------------- | -------------------------------- | ------------------------------------------------------------------------ |
| User identifier | `sub` (UUID assigned by Cognito) | Must match. Map `${user:subject}` → `externalId` in IAM Identity Center. |
| Email           | `email`                          | `userName` in SCIM                                                       |
| Groups          | `cognito:groups`                 | `members` list in `/scim/v2/Groups`                                      |

The eunox SCIM enrichment matches the Cognito `sub` claim value against
`scim_users.external_id`. For the match to succeed, IAM Identity Center must
push the same `sub` value as the SCIM `externalId`.

If the Cognito `sub` values differ from the IAM Identity Center subject
identifiers (e.g. when IAM Identity Center uses its own internal IDs), use
the **email-based fallback**: eunox will fall back to matching `userName`
against the user's email from the Cognito token if `externalId` does not match.

### 10.6 Alternative: custom SCIM proxy Lambda (advanced)

When IAM Identity Center cannot push directly to an arbitrary SCIM endpoint
(e.g. in organisations that restrict outbound SCIM destinations), deploy a
thin Lambda proxy that:

1. Receives SCIM events from IAM Identity Center's built-in SCIM endpoint.
2. Forwards them to the eunox issuer's `/scim/v2/` endpoint with the
   `ISSUER_SCIM_BEARER_TOKEN`.

```
IAM Identity Center
  → built-in SCIM endpoint
    → EventBridge / SNS
      → Lambda (scim-proxy)
        → eunox /scim/v2/
```

This pattern is also useful when the eunox issuer is deployed in a private VPC
without an internet-facing ALB.

### 10.7 Environment variables

```bash
# Issuer — enable SCIM 2.0
ISSUER_DB_URL=postgres://issuer:secret@db:5432/issuer_db
ISSUER_SCIM_BEARER_TOKEN=<at-least-32-chars-from-secrets-manager>
ISSUER_SCIM_GROUP_ROLE_MAP='{"EunoReaders":"reader","EunoWriters":"writer","EunoAdmins":"admin"}'

# Identity provider remains Cognito for runtime authentication:
IDENTITY_PROVIDER=aws-cognito
AWS_COGNITO_USER_POOL_ID=us-east-1_XXXXXXXXX
AWS_COGNITO_CLIENT_ID=<app-client-id>
```

### 10.8 Security checklist

- [ ] `ISSUER_SCIM_BEARER_TOKEN` is stored in AWS Secrets Manager and rotated
      at least annually (SOC 2 CC6.1).
- [ ] The SCIM endpoint is behind TLS (ACM certificate on the ALB).
- [ ] Access to `/scim/v2/` is restricted to IAM Identity Center source IPs
      at the ALB level (WAF IP set rule), or the endpoint is on an internal ALB.
- [ ] `ISSUER_SCIM_GROUP_ROLE_MAP` has been reviewed — mapping a group to
      an `admin`-tier role grants elevated capabilities to all group members.
- [ ] User `externalId` ↔ Cognito `sub` mapping has been validated end-to-end
      in a staging environment before production rollout.

---

## 11. Google Workspace SCIM bridge (Cloud Identity)

> **Status:** Multi-cloud Phase 1. Use this section when you want to provision
> users and groups into the eunox issuer from Google Workspace (formerly G Suite)
> via the SCIM 2.0 protocol, using a **Google Workspace SCIM provisioning**
> service account and OAuth 2.0 credential.

Google Workspace supports outbound SCIM provisioning to third-party apps via
an **OAuth service account**. The provisioning agent authenticates with a
service account credential and pushes user and group lifecycle events to the
eunox issuer's SCIM endpoint.

### 11.1 Architecture

```
Google Workspace Admin SDK
  (user / group provisioning events)
        │
        │  HTTPS POST /scim/v2/Users
        │  HTTPS POST /scim/v2/Groups
        ▼
eunox capability-issuer (/scim/v2/)
  ──► scim_users / scim_groups tables (Postgres)
        │
        ▼
  role enrichment at token issuance
  (IdP roles ∪ SCIM group-mapped roles)
```

The provisioning agent uses an **OAuth service account** to authenticate to
the eunox SCIM endpoint. At runtime, GCP Cloud Identity / Firebase Auth
authenticates users and issues ID tokens; the SCIM provisioning layer keeps
the group membership data up to date independently.

### 11.2 Prerequisites

- Google Workspace with a domain admin account.
- A GCP project with the **Admin SDK API** enabled.
- `ISSUER_DB_URL` set and pointing at a Postgres instance.
- `ISSUER_SCIM_BEARER_TOKEN` set (≥ 32 characters, stored in GCP Secret
  Manager — see [`docs/secrets-gcp.md`](./secrets-gcp.md)).
- The eunox issuer is reachable from the provisioning agent over HTTPS.
  On GKE, expose the issuer via a GKE Ingress with a Google-managed SSL
  certificate (see [`docs/deploy-gke.md`](./deploy-gke.md) §5).

### 11.3 Create an OAuth service account for SCIM provisioning

Google Workspace SCIM provisioning uses an **OAuth service account** (a GCP
service account with Google Workspace domain-wide delegation).

1. In the GCP Console: **IAM & Admin → Service Accounts → Create**.
   - **Name**: `eunox-scim-provisioner`
   - **Description**: `SCIM provisioning agent for eunox capability issuer`

2. Download a JSON key for the service account (this key will be used by the
   provisioning agent — keep it in Secret Manager):

   ```bash
   gcloud iam service-accounts keys create /tmp/eunox-scim-sa.json \
     --iam-account "eunox-scim-provisioner@${PROJECT_ID}.iam.gserviceaccount.com" \
     --project "${PROJECT_ID}"
   ```

3. In Google Workspace Admin Console: **Security → Access and data controls →
   API controls → Manage Domain-Wide Delegation → Add new**.
   - **Client ID**: `<service-account-client-id>` (from the JSON key file)
   - **OAuth scopes**:
     - `https://www.googleapis.com/auth/admin.directory.user.readonly`
     - `https://www.googleapis.com/auth/admin.directory.group.readonly`

### 11.4 Google Workspace SCIM provisioning — configuration

Google Workspace does not have a built-in "push to arbitrary SCIM endpoint"
feature in all editions. The recommended approaches are:

**Option A — Google Cloud Identity SCIM provisioning (Google Workspace Enterprise)**

1. In Google Admin Console: **Apps → Web and mobile apps → Add app →
   Add SAML app** (or OIDC app) → configure provisioning.
2. Under **Provisioning**, enable **Automatic provisioning** and supply the
   eunox SCIM endpoint:

   | Field              | Value                           |
   | ------------------ | ------------------------------- |
   | SCIM base URL      | `https://<issuer-host>/scim/v2` |
   | OAuth bearer token | `<ISSUER_SCIM_BEARER_TOKEN>`    |

3. Under **Attribute mappings**, ensure the following are active:

   | Google Workspace attribute     | SCIM attribute    |
   | ------------------------------ | ----------------- |
   | `id` (Google internal user ID) | `externalId`      |
   | `primaryEmail`                 | `userName`        |
   | `name.givenName`               | `name.givenName`  |
   | `name.familyName`              | `name.familyName` |
   | `name.fullName`                | `displayName`     |
   | `suspended` → `false`          | `active`          |

   The eunox SCIM user lookup uses `externalId` (matched against the IdP `sub`
   claim). For GCP Cloud Identity / Firebase Auth, the `sub` claim in the ID
   token is the Google internal user ID (`id`). Map `id → externalId` to
   ensure correct matching.

**Option B — Custom SCIM provisioning agent (all Google Workspace editions)**

For editions without built-in SCIM provisioning, deploy a lightweight Cloud
Run service or Cloud Function that polls the Google Admin SDK Directory API
and pushes changes to the eunox SCIM endpoint:

```javascript
// cloud-run/google-workspace-scim-sync.mjs
// Sync Google Workspace users and groups to the eunox SCIM endpoint.
import { google } from "googleapis";

const EUNO_SCIM_BASE = process.env.EUNO_SCIM_BASE_URL;
const EUNO_BEARER = process.env.ISSUER_SCIM_BEARER_TOKEN;
const ADMIN_EMAIL = process.env.GOOGLE_WORKSPACE_ADMIN_EMAIL;

const auth = new google.auth.GoogleAuth({
  scopes: [
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
  ],
});

// Impersonate the Workspace admin for Directory API calls.
const client = await auth.getClient();
client.subject = ADMIN_EMAIL;

const admin = google.admin({ version: "directory_v1", auth: client });

async function syncUsers() {
  const { data } = await admin.users.list({ customer: "my_customer" });
  for (const user of data.users ?? []) {
    await fetch(`${EUNO_SCIM_BASE}/Users`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${EUNO_BEARER}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        externalId: user.id, // Google internal user ID → matches GCP sub claim
        userName: user.primaryEmail,
        displayName: user.name?.fullName ?? user.primaryEmail,
        name: {
          givenName: user.name?.givenName ?? "",
          familyName: user.name?.familyName ?? "",
        },
        active: !user.suspended,
      }),
    });
  }
}
```

### 11.5 Group provisioning and role mapping

1. In Google Workspace Admin Console, create **Groups** whose names match
   entries in your `ISSUER_SCIM_GROUP_ROLE_MAP`:

   ```bash
   # Example group names → eunox roles
   ISSUER_SCIM_GROUP_ROLE_MAP='{"EunoReaders":"reader","EunoWriters":"writer","EunoAdmins":"admin"}'
   ```

2. Assign users to the relevant groups in Google Workspace Admin Console.

3. The provisioning agent pushes `POST /scim/v2/Groups` with the group's
   `displayName` and member list to the eunox issuer.

4. At token issuance time, the issuer looks up the authenticated user's SCIM
   group memberships (by `externalId` = Google `sub` claim, falling back to
   `userName` = email) and adds the mapped roles to the role set provided by
   the GCP Cloud Identity ID token.

### 11.6 Attribute mappings for Cloud Identity

When using GCP Cloud Identity / Firebase Auth as the runtime identity provider
alongside Google Workspace SCIM provisioning, ensure attribute values are
consistent:

| Attribute       | GCP Cloud Identity ID token claim | Google Workspace → SCIM mapping                                      |
| --------------- | --------------------------------- | -------------------------------------------------------------------- |
| User identifier | `sub` (Google internal user ID)   | `id → externalId` — this must match the `sub` value in the ID token. |
| Email           | `email`                           | `primaryEmail → userName`                                            |
| Groups          | (not in token; enriched via SCIM) | `members` list in `/scim/v2/Groups`                                  |

The eunox SCIM enrichment matches the GCP `sub` claim value against
`scim_users.external_id`. For the match to succeed, the provisioning agent
must push the same Google internal user ID as the SCIM `externalId`.

### 11.7 Environment variables

```bash
# Issuer — enable SCIM 2.0
ISSUER_DB_URL=postgres://issuer:secret@db:5432/issuer_db
ISSUER_SCIM_BEARER_TOKEN=<at-least-32-chars-from-secret-manager>
ISSUER_SCIM_GROUP_ROLE_MAP='{"EunoReaders":"reader","EunoWriters":"writer","EunoAdmins":"admin"}'

# Identity provider remains GCP Cloud Identity for runtime authentication:
IDENTITY_PROVIDER=gcp-identity
GCP_PROJECT_ID=my-gcp-project
GCP_IDENTITY_AUDIENCE=https://issuer.eunox.example.com
```

### 11.8 Security checklist

- [ ] `ISSUER_SCIM_BEARER_TOKEN` is stored in GCP Secret Manager and rotated
      at least annually (SOC 2 CC6.1).
- [ ] The SCIM endpoint is behind TLS (Google-managed SSL certificate on the
      GKE Ingress).
- [ ] Access to `/scim/v2/` is restricted to the provisioning agent's source
      IP range or via an internal GKE Ingress.
- [ ] `ISSUER_SCIM_GROUP_ROLE_MAP` has been reviewed — mapping a group to
      an `admin`-tier role grants elevated capabilities to all group members.
- [ ] User `externalId` ↔ GCP Cloud Identity `sub` mapping has been validated
      end-to-end in a staging environment before production rollout.
- [ ] The OAuth service account's domain-wide delegation scopes are limited
      to read-only Directory API scopes.
