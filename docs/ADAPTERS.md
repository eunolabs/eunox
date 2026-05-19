# Pluggable Adapters: Identity Providers and Token Signers

The euno capability governance system implements a clean adapter pattern for
identity providers and token signers. This establishes extensible contracts
that enable support for multiple implementations — Azure AD + Azure Key Vault,
AWS Cognito + AWS KMS, GCP Cloud Identity + GCP Cloud KMS, and W3C
Decentralized Identifiers (DIDs) — all behind the same `IdentityAdapter` /
`SigningAdapter` contracts.

---

## Architecture

### Core components (`public/packages/common/src/adapters.ts`)

- `IdentityAdapter` — abstract base class for identity providers
- `SigningAdapter` — abstract base class for token signers
- `IdentityAdapterRegistry` — factory for creating identity adapters
- `SigningAdapterRegistry` — factory for creating signing adapters

### Built-in implementations

**Identity providers**

| Key | Implementation | Location |
|-----|---------------|----------|
| `azure-ad` | Azure Active Directory / Microsoft Entra ID | `azure-identity-provider.ts` |
| `aws-cognito` | Amazon Cognito user pools / compatible OIDC issuers | `aws-cognito-identity-provider.ts` |
| `gcp-identity` | Google identity tokens / Workforce Identity Federation | `gcp-identity-provider.ts` |
| `did` | W3C DID Documents (`did:web`, `did:ion`, `did:key`) | `did-identity-provider.ts` |

**Token signers**

| Key | Implementation | Location |
|-----|---------------|----------|
| `azure-keyvault` | Azure Key Vault asymmetric key signing | `azure-signer.ts` |
| `aws-kms` | AWS KMS asymmetric key signing | `aws-kms-signer.ts` |
| `gcp-cloudkms` | Google Cloud KMS asymmetric key signing | `gcp-cloudkms-signer.ts` |
| `did` | DID-bound local/private-key signing; public key via `/.well-known/did.json` | `did-signer.ts` |

**Implementation references:** the built-in registry is in
`euno-platform/packages/capability-issuer/src/default-registries.ts`.

### Registry system

Two registries manage providers:
- `defaultIdentityRegistry` — manages identity provider adapters
- `defaultSigningRegistry` — manages token signing adapters

Both registries come pre-loaded with built-in providers and support dynamic
registration.

---

## Using built-in providers

### Azure AD identity provider

```typescript
import { AzureADIdentityProvider, AzureADAdapterConfig } from '@euno/capability-issuer/adapters';

const config: AzureADAdapterConfig = {
  type: 'azure-ad',
  name: 'Azure AD Identity Provider',
  azureAD: {
    tenantId: process.env.AZURE_AD_TENANT_ID!,
    clientId: process.env.AZURE_AD_CLIENT_ID!,
    clientSecret: process.env.AZURE_AD_CLIENT_SECRET,
  },
};

const identityProvider = new AzureADIdentityProvider(config);
await identityProvider.initialize();
const userContext = await identityProvider.validateToken(token);
```

### Azure Key Vault signer

```typescript
import { AzureKeyVaultSigner, AzureKeyVaultAdapterConfig } from '@euno/capability-issuer/adapters';

const config: AzureKeyVaultAdapterConfig = {
  type: 'azure-keyvault',
  name: 'Azure Key Vault Signer',
  keyVault: {
    vaultUrl: process.env.AZURE_KEYVAULT_URL!,
    keyName: 'capability-signing-key',
    credentialType: 'managed-identity',
  },
};

const signer = new AzureKeyVaultSigner(config);
await signer.initialize();
const token = await signer.sign(payload);
```

### AWS KMS signer

```typescript
const awsSigner = await defaultSigningRegistry.createSigningAdapter({
  type: 'aws-kms',
  name: 'AWS KMS Production Signer',
  algorithm: 'RS256',
  awsKMS: {
    region: 'us-east-1',
    keyId: 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});
```

### GCP Cloud KMS signer

```typescript
const gcpSigner = await defaultSigningRegistry.createSigningAdapter({
  type: 'gcp-cloudkms',
  name: 'GCP Cloud KMS Production Signer',
  algorithm: 'RS256',
  gcpKMS: {
    projectId: 'my-project-id',
    locationId: 'us-central1',
    keyRingId: 'my-key-ring',
    cryptoKeyId: 'my-crypto-key',
    cryptoKeyVersion: '1',         // optional; uses primary if omitted
    keyFilePath: '/path/to/sa.json', // optional; uses ADC if omitted
  },
});
```

### Registry pattern (advanced)

```typescript
import { IdentityAdapterRegistry, SigningAdapterRegistry } from '@euno/common';

const identityRegistry = new IdentityAdapterRegistry();
const signingRegistry  = new SigningAdapterRegistry();

identityRegistry.register('azure-ad', AzureADIdentityProvider);
identityRegistry.register('did', DIDIdentityProvider);

const identityProvider = await identityRegistry.createIdentityAdapter({
  type: 'azure-ad',
  name: 'Production Identity Provider',
  azureAD: { tenantId: '...', clientId: '...' },
});
```

---

## Creating custom adapters

### Custom identity provider

```typescript
import { IdentityAdapter, IdentityAdapterConfig, UserContext, CapabilityError, ErrorCode } from '@euno/common';

export interface OktaIdentityConfig extends IdentityAdapterConfig {
  type: 'okta';
  domain: string;
  clientId: string;
  clientSecret?: string;
  authorizationServerId?: string;
}

export class OktaIdentityProvider extends IdentityAdapter {
  public readonly name = 'okta';
  private oktaConfig: OktaIdentityConfig;
  private verifier?: OktaJwtVerifier;

  constructor(config: OktaIdentityConfig) {
    super(config);
    this.oktaConfig = config;
  }

  async initialize(): Promise<void> {
    this.verifier = new OktaJwtVerifier({
      issuer: `https://${this.oktaConfig.domain}/oauth2/${this.oktaConfig.authorizationServerId ?? 'default'}`,
      clientId: this.oktaConfig.clientId,
    });
  }

  async validateToken(token: string): Promise<UserContext> {
    if (!this.verifier) await this.initialize();
    try {
      const jwt = await this.verifier!.verifyAccessToken(token, 'api://default');
      return {
        userId: jwt.claims.sub as string,
        email: jwt.claims.email as string,
        roles: (jwt.claims.groups as string[]) ?? [],
        claims: jwt.claims as Record<string, unknown>,
      };
    } catch (error) {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        `Failed to validate Okta token: ${error instanceof Error ? error.message : 'Unknown error'}`,
        401
      );
    }
  }

  async getUserRoles(userId: string): Promise<string[]> {
    throw new Error('Not implemented');
  }

  async dispose(): Promise<void> {
    this.verifier = undefined;
  }
}
```

### Custom token signer (HSM example)

```typescript
import { SigningAdapter, SigningAdapterConfig, CapabilityTokenPayload } from '@euno/common';

export interface HSMSignerConfig extends SigningAdapterConfig {
  type: 'hsm';
  hsmEndpoint: string;
  keyId: string;
  pin?: string;
  slot?: number;
}

export class HSMSigner extends SigningAdapter {
  private hsmConfig: HSMSignerConfig;

  constructor(config: HSMSignerConfig) {
    super(config);
    this.hsmConfig = config;
  }

  async sign(payload: CapabilityTokenPayload): Promise<string> {
    // Hash locally, sign with HSM — only the digest crosses the boundary.
    // ...your HSM signing implementation...
  }

  async getPublicKey(): Promise<string> {
    // Retrieve public key from HSM
  }

  async getKeyId(): Promise<string> {
    return this.hsmConfig.keyId;
  }

  async initialize(): Promise<void> { /* open HSM session */ }
  async dispose(): Promise<void>    { /* close HSM session */ }
}
```

### Registering and using a custom provider

```typescript
import { defaultIdentityRegistry, defaultSigningRegistry } from '@euno/capability-issuer/adapters';

defaultIdentityRegistry.register('okta', OktaIdentityProvider);
defaultSigningRegistry.register('hsm', HSMSigner);

const provider = await defaultIdentityRegistry.createIdentityAdapter({
  type: 'okta',
  name: 'Okta Identity Provider',
  domain: 'dev-12345.okta.com',
  clientId: process.env.OKTA_CLIENT_ID,
  clientSecret: process.env.OKTA_CLIENT_SECRET,
});
```

### Dynamic loading from configuration

```typescript
async function initializeProviders(config: { identity: any; signing: any }) {
  const identityProvider = await defaultIdentityRegistry.createIdentityAdapter(config.identity);
  const signingProvider  = await defaultSigningRegistry.createSigningAdapter(config.signing);
  return { identityProvider, signingProvider };
}
```

---

## Best practices

### Error handling

Always use `CapabilityError` for consistent error propagation:

```typescript
throw new CapabilityError(ErrorCode.AUTHENTICATION_FAILED, 'Descriptive message', 401);
```

### Lifecycle management

Implement `initialize()` and `dispose()` — the service container calls both:

```typescript
async initialize(): Promise<void> { this.client = await createClient(this.config); }
async dispose():    Promise<void> { await this.client?.close(); this.client = undefined; }
```

### Configuration validation

Fail fast in the constructor rather than at runtime:

```typescript
constructor(config: CustomConfig) {
  super(config);
  if (!config.requiredField) throw new Error('requiredField is required');
  this.customConfig = config;
}
```

---

## Publishing a third-party provider package

Create a separate npm package:

```
my-euno-provider/
├── package.json          # peerDependencies: { "@euno/common": "^0.1.0" }
├── tsconfig.json
├── src/
│   ├── index.ts
│   └── my-provider.ts
└── tests/
    └── my-provider.test.ts
```

Name it `@<scope>/euno-<provider-name>` and export the provider class from
`index.ts`. Consumers import it, call `defaultIdentityRegistry.register(...)`,
and configure it the same way as any built-in provider.

---

## Partner Federation

Partner federation lets a remote organization issue capability tokens from
their own W3C DID-backed signing key. The euno gateway accepts and
cryptographically verifies those tokens without sharing key material.

This is a **Stage 5 GA feature** (Task 3). The integration test harness lives
in `euno-platform/packages/partner-issuer-sim/`. See also
`docs/self-host.md` §12.2 "Partner DID federation" for the operator
self-host runbook.

### Trust model

Euno partner federation is **declarative, not transitive**:

1. The gateway operator opts a partner DID into trust via the admin API's
   two-eyes approval workflow (`POST /admin/partner-dids/proposals` →
   `POST /admin/partner-dids/proposals/:did/approve`).  A second operator
   must approve — the proposer cannot approve their own entry.
2. When the gateway receives a token whose `iss` claim is a partner DID, the
   `PartnerIssuerResolver` resolves the DID document via `did:web`, `did:ion`,
   or `did:key`, extracts the verification method matching the JWT `kid`, and
   verifies the signature.  No partner key material is ever stored locally.
3. A per-DID `RedisCircuitBreaker` wraps the DID-document resolution step.
   Pin-mismatch and key-validation errors do **not** count as circuit failures
   (they indicate data problems, not network outages) — an attacker with a
   malformed DID document cannot force the circuit open against a reachable
   partner.

### DID registration workflow

```bash
DID="did:web:partner.example.com"
ENCODED_DID="did%3Aweb%3Apartner.example.com"

# Step 1 — First-eye submits a proposal
# The operator identity is taken from the X-Admin-Operator header,
# not from the request body.
curl -X POST https://gateway.internal:3003/admin/partner-dids/proposals \
  -H "X-Admin-Api-Key: <GATEWAY_ADMIN_API_KEY>" \
  -H "X-Admin-Operator: alice@corp" \
  -H "Content-Type: application/json" \
  -d '{"did":"'"$DID"'","notes":"Acme Corp onboarding"}'

# Step 2 — Second-eye approves (different admin key / operator identity)
# The :did path segment must be URL-encoded.
curl -X POST "https://gateway.internal:3003/admin/partner-dids/proposals/${ENCODED_DID}/approve" \
  -H "X-Admin-Api-Key: <SECOND_ADMIN_API_KEY>" \
  -H "X-Admin-Operator: bob@corp"

# Step 3 — Verify the DID is active
curl https://gateway.internal:3003/admin/partner-dids \
  -H "X-Admin-Api-Key: <GATEWAY_ADMIN_API_KEY>"
```

### Pin attestation (production)

Pin attestation binds the JCS-SHA-256 fingerprint of the partner's DID
document to the approval event via an HMAC-SHA-256 (keyed by
`PARTNER_DID_PIN_SECRET`).  If the Redis store is tampered with (pin swapped)
or `PARTNER_DID_PIN_SECRET` is rotated, the gateway **fails closed** — the
entry must be re-approved to generate a fresh attestation.

```env
# Required for pin attestation — minimum 32 characters
PARTNER_DID_PIN_SECRET=<at-least-32-char-random-secret>
# Enforce that every registration must include a pin (production hardening)
PARTNER_DID_REQUIRE_PIN=true
```

When `PARTNER_DID_AUTO_FETCH_PIN=true` the gateway automatically fetches the
live DID document at approval time and stores its SHA-256 fingerprint — no
out-of-band pin distribution required.

### Circuit-breaker tuning

| Variable | Default | Description |
|---|---|---|
| `PARTNER_DID_CB_FAILURE_THRESHOLD` | `3` | DID-resolution failures within the window that open the circuit. |
| `PARTNER_DID_CB_WINDOW_SECONDS` | `30` | Sliding window (seconds) for failure counting. |
| `PARTNER_DID_CB_COOLDOWN_SECONDS` | `60` | Cooldown (seconds) before the circuit enters half-open and allows a single probe. |
| `PARTNER_DID_CACHE_TTL_SECONDS` | `300` | Positive-resolution DID cache TTL (seconds). |
| `PARTNER_DID_NEGATIVE_CACHE_TTL_SECONDS` | `30` | Negative-resolution (NXDID) cache TTL (seconds). |

Tune aggressively for production: a flapping partner should open the circuit
quickly so its latency tail does not bleed into unrelated cross-org requests
sharing the same gateway worker pool.

### Prometheus metrics

```
# Current circuit-breaker state per partner DID.
# Value is 1 when {did, state} is the active combination, 0 otherwise.
euno_partner_did_circuit_breaker_state{did="did:web:partner.example.com",state="closed"} 1
euno_partner_did_circuit_breaker_state{did="did:web:partner.example.com",state="open"} 0
euno_partner_did_circuit_breaker_state{did="did:web:partner.example.com",state="half-open"} 0

# Total circuit-breaker state transitions per DID.
euno_gateway_partner_did_circuit_transitions_total{did="...",from="closed",to="open"}
```

**Recommended alert:**

```yaml
- alert: PartnerDIDCircuitOpen
  expr: euno_partner_did_circuit_breaker_state{state="open"} == 1
  for: 2m
  labels:
    severity: warning
  annotations:
    summary: "Partner DID circuit breaker open"
    description: "DID {{ $labels.did }} is unreachable; all tokens from this partner are being denied."
```

### Revocation (off-boarding a partner)

```bash
# Mark the DID as revoked — single-operator, no second-eye required
# (incident response is intentionally fast).
# The :did path segment must be URL-encoded.
ENCODED_DID="did%3Aweb%3Apartner.example.com"
curl -X DELETE "https://gateway.internal:3003/admin/partner-dids/${ENCODED_DID}" \
  -H "X-Admin-Api-Key: <GATEWAY_ADMIN_API_KEY>" \
  -H "X-Admin-Operator: alice@corp" \
  -H "Content-Type: application/json" \
  -d '{"reason":"partner off-boarded 2026-05-19"}'
```

The `PartnerIssuerResolver` checks `registry.trusts(did)` on every `getKey`
call, so revocation takes effect within one positive-cache TTL
(`PARTNER_DID_CACHE_TTL_SECONDS`, default 5 minutes).  Tokens already in
flight that have passed verification will complete normally; new tokens are
denied immediately after the cache expires.

### Discovery-URL auto-bootstrap (dev / staging)

When `PARTNER_ISSUER_DISCOVERY_URL` is set, the gateway fetches the partner's
`/.well-known/capability-issuer` document at startup, extracts the `issuer`
DID, and seeds it directly (bypassing two-eyes approval).  This is equivalent
to `TRUSTED_PARTNER_DIDS` but driven by a discovery document rather than a
hard-coded DID string.

```env
PARTNER_ISSUER_DISCOVERY_URL=https://partner-staging.example.com/.well-known/capability-issuer
```

> **Production restriction:** `PARTNER_DID_REGISTRY_REQUIRED` defaults to
> `true` in production (`NODE_ENV=production`), which blocks the discovery
> shortcut.  Set `PARTNER_DID_REGISTRY_REQUIRED=false` only in staging or
> during initial rollout.

---

## References

- [W3C Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
- [Microsoft Entra Verified ID Architecture](https://learn.microsoft.com/en-us/entra/verified-id/introduction-to-verifiable-credentials-architecture)
