# Capability Issuer — IdP Setup Guide

> **Target audience:** Platform engineers configuring the Stage-4 Capability
> Issuer to authenticate users via an enterprise identity provider.
>
> **Status:** Stage 4. Both the hosted product and the self-host docker image
> are covered here.
>
> **Related documents:**
> - [`docs/self-host.md`](./self-host.md) — self-host overview and deployment topology
> - [`docs/DEPLOYMENT.md`](./DEPLOYMENT.md) — full environment-variable reference
> - [`docs/stage4executionplan.md`](./stage4executionplan.md) — Stage-4 execution plan (Task 2)
> - [`docs/security/issuer-threat-model.md`](./security/issuer-threat-model.md) — threat model (IdP-token replay, nonce binding, aud/iss enforcement)

---

## 1. Overview

The Capability Issuer authenticates users by validating an **ID token** issued
by an upstream enterprise IdP.  The validation covers:

| Claim / check | Enforced by |
|---|---|
| Signature (RS256 / ES256) | `jose` `jwtVerify` against IdP JWKS |
| `iss` (issuer) | Provider-specific issuer URL |
| `aud` (audience) | Client ID / app URI |
| `exp` / `iat` | `jose` `jwtVerify` |
| `nonce` binding | Endpoint: `claims.nonce` must equal the request `nonce` field |
| Authorization-code replay | `OidcStateStore`: each code accepted at most once |

Role claims extracted from the validated token are mapped to capability
constraints; the request body can **never** escalate the resulting role set
(role-from-token invariant).

### Supported providers

| Provider | `IDENTITY_PROVIDER` value |
|---|---|
| Microsoft Entra ID (Azure AD) | `azure-ad` (default) |
| AWS Cognito | `aws-cognito` |
| GCP Cloud Identity / Firebase Auth | `gcp-identity` |

---

## 2. Entra ID (Azure AD) — app registration

### 2.1 Create an app registration

1. Open **Azure Portal → Entra ID → App registrations → New registration**.
2. **Name**: `euno-capability-issuer-<env>` (e.g. `euno-capability-issuer-prod`).
3. **Supported account types**: *Accounts in this organizational directory only
   (Single tenant)*.
4. **Redirect URI**: leave blank for now (the issuer uses the PKCE
   authorization-code flow entirely at the client CLI level; no redirect URI
   is registered on the server side).
5. Click **Register**.

### 2.2 Expose App Roles

The issuer derives capabilities from the `roles` claim in the ID token.  Define
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

| Variable | Where to find it |
|---|---|
| `AZURE_AD_TENANT_ID` | **Overview** page: *Directory (tenant) ID* |
| `AZURE_AD_CLIENT_ID` | **Overview** page: *Application (client) ID* |

### 2.5 Conditional Access (recommended for production)

Add a Conditional Access policy in Entra ID that requires MFA for your app
registration in production environments.  The issuer's `AzureADIdentityProvider`
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

Cognito exposes group membership as the `cognito:groups` claim.  The
`AWSCognitoIdentityProvider` maps `cognito:groups` to `roles` in the
`UserContext`.

1. In your User Pool, open **Groups → Create group**.
2. Name the group to match your role policy (e.g. `Reader`, `Writer`, `Admin`).
3. Assign users to groups as appropriate.

### 3.3 Configure a custom `nonce` claim

Cognito's hosted UI automatically includes a `nonce` claim in ID tokens when
the authorization request carries a `nonce` parameter.  No extra configuration
is needed — the `euno request` CLI generates and validates it automatically.

If you are using the programmatic flow (sending `idToken` directly to
`POST /api/v1/oidc/token`), your client is responsible for:

1. Generating a cryptographically random nonce (≥ 128 bits of entropy).
2. Passing `nonce` in the Cognito authorization URL.
3. Passing the same `nonce` value in the `POST /api/v1/oidc/token` body.

### 3.4 Collect configuration values

| Variable | Where to find it |
|---|---|
| `AWS_COGNITO_USER_POOL_ID` | User pool → **Overview**: *Pool ID* (e.g. `us-east-1_XYZabc`) |
| `AWS_COGNITO_CLIENT_ID` | App integration → App clients: *Client ID* |
| `AWS_COGNITO_REGION` | First segment of the Pool ID (e.g. `us-east-1`) |

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
ISSUER_TENANT_IDP_CONFIG_FILE=/etc/euno/tenant-idp-config.json
```

---

## 5. OIDC discovery document

The issuer exposes a discovery document at
`GET /.well-known/openid-configuration`.  To include the `authorization_endpoint`
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
`POST /api/v1/oidc/token`.  Each code is accepted at most once within a
configurable TTL window.  Replay attempts receive `401 AUTHENTICATION_FAILED`.

```bash
# TTL for used-code tombstones and pending state entries (default: 600 seconds)
OIDC_CODE_TTL_SECONDS=600
```

---

## 7. OIDC token endpoint — client flow

The client (typically the `euno request` CLI) follows this flow:

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
token.  The issuer rejects any token whose `nonce` claim does not match.

---

## 8. Security checklist

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

---

## 9. DID-based partner issuers (Stage 5)

> **Status:** Stage 5 — production stable. Use this section when configuring
> the issuer to authenticate agents whose identity tokens are signed by a
> DID-backed key rather than a centralized IdP.

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
   for example `http://ion-sidecar.euno.svc.cluster.local:3000`.
3. Set the issuer env var:
   ```bash
   ION_RESOLVER_URL=http://ion-sidecar.euno.svc.cluster.local:3000/api/v1.0/identifiers
   ```
4. For non-`did:web` DIDs no HTTP allow-list is needed. For `did:web` DIDs
   served internally over plain HTTP, add the host to
   `DID_WEB_ALLOW_HTTP_FOR_HOSTS` (comma-separated, e.g.
   `partner-sim.local:4001,did-registry.internal`).

### 9.3 ION circuit breaker (Stage 5)

The issuer wraps every `did:ion` resolution call in a circuit breaker that
opens after repeated failures, preventing a sustained resolver outage from
blocking all DID-based authentication attempts with full network timeouts.

| Env var | Default | Description |
|---|---|---|
| `ION_CB_FAILURE_THRESHOLD` | `3` | Number of failures within the window to open the circuit. |
| `ION_CB_WINDOW_SECONDS` | `30` | Sliding window (seconds) for failure counting. |
| `ION_CB_COOLDOWN_SECONDS` | `60` | Seconds the circuit stays open before a probe is allowed. |

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

### 9.5 Security notes

- `did:web` DIDs are fetched over HTTPS by default. HTTP is only allowed for
  hosts explicitly listed in `DID_WEB_ALLOW_HTTP_FOR_HOSTS` (intended for
  local CI/CD environments only — never use in production).
- `did:ion` resolution relies on the ION resolver's TLS certificate. For
  private nodes, use a certificate from a CA in the system trust store.
- `did:key` is stateless and requires no network call. It is always available
  regardless of ION resolver connectivity.
