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

The `TenantIdpRegistry` watches the file for changes and reloads it
automatically (SIGHUP-triggered `reload()` is also available).  If the new
file is invalid JSON or fails schema validation, the previous configuration is
preserved and an error is logged — no traffic is disrupted.

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
