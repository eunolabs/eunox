# Pluggable Adapters: Building a Cloud-Portable Identity and Signing Layer

_Part of the "Architecture deep-dives" series. [Post 9](../../blogs/09-capability-tokens.md) introduced capability tokens; [post 10](../../blogs/10-tool-gateway-reference-monitor.md) covered the enforcement pipeline. This one goes behind both to explain what the capability issuer and gateway actually talk to when they validate an identity or sign a JWT — and why that plumbing is designed to be completely swappable._

---

The question I get most often from enterprise architects evaluating euno isn't about the policy language or the audit log format. It's simpler than that: _"Does this run on AWS?"_ Or Azure. Or GCP. Or — increasingly — _"We have a private PKI and we're not putting signing keys in any public cloud KMS. Can you work with that?"_

The answer in every case is yes, and I want to explain exactly how, because the design here is one of the decisions I'm most satisfied with in the entire codebase. It's also one that took several iterations to get right.

---

## The problem with hardcoded cloud dependencies

The first version of the capability issuer had Azure all the way through it. Token validation was Azure AD. Signing was Azure Key Vault. That was fine for the first customer, who was an Azure shop. The second customer used AWS. The third was GCP. By the time I was talking to the fourth, I'd already refactored twice and was staring at a codebase where "swap out the identity provider" meant a non-trivial amount of conditional logic woven through the core issuance path.

The right solution wasn't more conditionals. It was treating identity validation and token signing as pluggable dependencies — defining an interface for what those operations _need to do_ and letting the runtime supply the concrete implementation. This is the adapter pattern, and it's a textbook solution to exactly this problem. The reason I want to write about it here is that the details of applying it to a security-critical, multi-cloud system are not textbook.

---

## Two interfaces, one contract

The core abstractions live in the `pkg/` Go packages (Apache-2.0 licensed, so the contracts are public even for self-hosted deployments that use BUSL-licensed platform code):

**`IdentityAdapter`** — responsible for validating an inbound identity credential and returning a normalized `UserContext`. Implementations handle the cloud-specific validation logic: verifying OIDC tokens against a Cognito user pool, checking Azure AD claims, resolving a DID document and verifying a signed challenge. What they return is always the same shape: a `UserContext` with a stable subject identifier, a role set, and optional metadata like the original token claims.

**`SigningAdapter`** — responsible for signing a JWT payload and returning a signed token. Implementations call out to Key Vault, KMS, or Cloud KMS to perform the actual cryptographic operation. The private key never leaves the HSM boundary; the adapter just hands the payload to the KMS API and gets a signed JWT back.

Both are abstract base classes (not interfaces, deliberately — I wanted to be able to add non-abstract helper methods without touching implementations). The critical methods are:

```typescript
// IdentityAdapter
abstract validateToken(token: string): Promise<UserContext>;
abstract getPublicKey(): Promise<JsonWebKey>;

// SigningAdapter
abstract sign(payload: JwtPayload): Promise<string>;
abstract getPublicKey(): Promise<JsonWebKey>;
```

Every implementation must provide those four methods. Everything else is cloud-specific setup.

---

## The registry pattern

Implementations are managed through registries:

- `IdentityAdapterRegistry` — factory for identity providers, keyed by a string identifier
- `SigningAdapterRegistry` — factory for signing adapters, keyed by a string identifier

Both registries come pre-loaded with the built-in implementations:

| Key            | Identity implementation                                |
| -------------- | ------------------------------------------------------ |
| `azure-ad`     | Azure Active Directory / Microsoft Entra ID            |
| `aws-cognito`  | Amazon Cognito user pools / compatible OIDC issuers    |
| `gcp-identity` | Google Identity tokens / Workforce Identity Federation |
| `did`          | W3C DID Documents (`did:web`, `did:ion`, `did:key`)    |

| Key              | Signing implementation                  |
| ---------------- | --------------------------------------- |
| `azure-keyvault` | Azure Key Vault asymmetric key signing  |
| `aws-kms`        | AWS KMS asymmetric key signing          |
| `gcp-cloudkms`   | Google Cloud KMS asymmetric key signing |
| `did`            | DID-bound local/private-key signing     |

The runtime picks the right implementations based on environment variables at startup — no conditional logic in the issuer service itself, just a registry lookup by key. The issuer code doesn't know or care whether the signing adapter is making TLS calls to Key Vault or to Cloud KMS; it just calls `sign(payload)`.

---

## What each cloud adapter actually does

Let me go through the four signing adapters specifically, because the differences between them are instructive.

### Azure Key Vault

The Azure Key Vault signer uses Managed Identity (or a service principal, depending on deployment) to authenticate to the Key Vault REST API. The key pair lives in Key Vault; only the digest of the payload is ever sent over the wire — the HSM boundary is inside Key Vault, not at the client. Key rotation is handled by Key Vault versioning: you can rotate the key without changing the `SIGNING_KEY_NAME` env var, and the adapter automatically uses the current version.

The latency profile is around 15-30ms per signing call. That's not free, but for token issuance (which happens once per capability token request, not per tool call), it's acceptable.

### AWS KMS

AWS KMS follows the same pattern: the EC or RSA private key lives in KMS, you authenticate via an IAM role (EC2 instance profile, EKS service account with IRSA, or Lambda execution role), and the `Sign` API returns a DER-encoded signature that the adapter assembles into a valid JWT. The latency is similar — 10-25ms typically, depending on region and key type.

One KMS-specific wrinkle: KMS requires you to specify the `MessageType` (RAW vs DIGEST) and the `SigningAlgorithm` at call time. The adapter handles this internally, but it means the KMS adapter has slightly more configuration surface than the Key Vault adapter. The `aws-kms` adapter config accepts both EC (`ECDSA_SHA_256`, `ECDSA_SHA_384`) and RSA (`RSASSA_PKCS1_V1_5_SHA_256`, `RSASSA_PSS_SHA_256`) algorithms.

### GCP Cloud KMS

Cloud KMS uses service account credentials (typically via Workload Identity Federation in GKE) and calls the `asymmetricSign` method on the Cloud KMS API. The response is base64url-encoded DER, which the adapter normalizes into the JWT format.

GCP is the only one of the three where I hit an interesting edge case: Cloud KMS key names include the full resource path (`projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V`), and unlike Key Vault there's no automatic "current version" concept — you either pin a version or build rotation logic yourself. The adapter handles this by accepting either a pinned version path or a key ring path, and resolving the primary version at initialization time.

### DID-bound signing

The DID signer is the odd one out. It uses a local private key (stored at a configurable path, not in a cloud KMS) but publishes the corresponding public key via the issuer's `/.well-known/did.json` endpoint. This is the signing path used in development and for partner federation scenarios where the issuer has a DID identity but may not have a cloud KMS.

I use the DID signer in the `partner-issuer-sim` test fixture — it produces real JWTs with real asymmetric signatures that the gateway can verify via DID document resolution, without needing a live KMS account during integration tests. That portability turned out to be extremely useful for the CI pipeline.

---

## Why the identity adapter and signer aren't always the same cloud

Here's something that comes up in multi-cloud deployments: the identity provider and the signer don't have to be from the same cloud vendor.

One customer authenticates their users through Azure AD (because their enterprise directory is there) but runs their compute on AWS and wants to use KMS for signing. The capability issuer wires an `azure-ad` identity adapter with an `aws-kms` signer. The OIDC token from Azure AD is validated through the identity adapter; the capability JWT is signed using the KMS key. These are two completely independent operations, and the adapter/registry pattern makes mixing them trivial.

Another customer uses GCP Workforce Identity Federation for human user auth but also has DID-based partner federation enabled. The gateway wires a `gcp-identity` adapter for human principals and a `did` identity adapter for partner tokens. Both are active simultaneously; the gateway routes incoming tokens to the correct adapter based on the `iss` claim.

---

## Implementing a custom adapter

The runtime also supports wiring in custom implementations. If you have a private PKI or a specialized HSM that isn't Azure Key Vault, AWS KMS, or Cloud KMS, you implement the signing interface in Go and wire it into your runtime:

```go
import (
  "context"

  "github.com/edgeobs/eunox/pkg/crypto"
)

type HardwareHsmSigner struct{}

func (s *HardwareHsmSigner) Sign(ctx context.Context, digest []byte) ([]byte, error) {
  // call your HSM vendor's API
  return myHsmClient.Sign(ctx, digest)
}

func (s *HardwareHsmSigner) Algorithm() crypto.Algorithm { return crypto.RS256 }
func (s *HardwareHsmSigner) KeyID() string               { return "my-hsm" }
```

This is the BUSL-licensed extension path. The public contracts (for example, the signing interfaces in `pkg/crypto`) are Apache-2.0 and publicly documented; the runtime wiring and built-in implementations are platform code.

---

## The abstraction paid off in ways I didn't expect

When I built the adapter pattern, I was thinking about multi-cloud portability. That was the explicit goal. But a few benefits showed up that I hadn't anticipated.

**Test isolation.** The `InMemorySigningAdapter` (a test double that signs tokens with a locally generated key pair, never touching a network) made the unit test suite dramatically simpler. Tests that previously needed a mock KMS service or a live Key Vault account now just pass an in-memory signer. The 322 tests in `api-key-minter` and the 166 integration tests both run entirely without cloud credentials.

**Fail-fast at startup.** Each adapter implements an `initialize()` method that's called at service startup. If the Azure Key Vault URL is wrong, or the IAM role doesn't have KMS permissions, or the GCP service account is misconfigured, you find out _before_ the first user request arrives — at startup, not during a capability token issuance attempt in production. This is the kind of thing that sounds obvious but is easy to get wrong: a lot of cloud SDK clients fail lazily on first use.

**The gateway and issuer share the signing adapter.** When the gateway signs audit evidence JWTs (see [post 11](./11-tamper-evident-audit-logs.md)), it uses the same `SigningAdapter` as the capability issuer. This means the JWKS endpoint for verifying audit evidence JWTs is the same endpoint as for verifying capability tokens. One key, one JWKS endpoint, one revocation concern. In a multi-service architecture, that's a meaningful simplification.

---

## What I'd change

The `IdentityAdapter.validateToken()` signature currently returns `UserContext` directly. In practice, I've run into cases where the identity provider returns additional claims that don't fit in `UserContext` but are useful for policy evaluation — for example, Azure AD group membership claims that map to roles, or Cognito custom attributes. Right now those have to be parsed out in the adapter and squashed into the `UserContext.roles` field. A cleaner design would return a `UserContext` plus an opaque `providerClaims` bag that the issuer service can optionally inspect.

The other gap is key-type flexibility. All four built-in signers currently support ECDSA P-256 and RSA-2048/RSA-4096. That covers 99% of deployments. But I've had one customer with a hardware HSM that only supports RSA-PKCS1-1.5 — technically not recommended by modern standards, but a reality in regulated environments where the HSM was procured a decade ago. Supporting their use case required a custom adapter, which is fine, but it also exposed that the JWT assembly code in the base class had baked-in assumptions about signature encoding that needed to be overrideable.

These are solvable problems. The architecture is correct; the details need polish.

---

## The DID identity provider deserves its own post

I've glossed over the `did` identity adapter in this post because W3C DIDs and partner federation are a topic large enough to need their own treatment. The adapter handles `did:web` and `did:ion` resolution, key derivation from DID documents, and the trust registry lookup that decides whether a given DID is authorized to issue capability tokens.

That story — how two organizations establish cross-org trust without sharing secrets, how DID circuit breakers protect you when a partner's resolution endpoint goes flaky, and why the two-eyes approval workflow exists — is [post 13](./13-partner-did-federation.md).

---

_Previous in this series: [post 11 — Tamper-evident audit logs: OCSF, HMAC chaining, and KMS-signed evidence](./11-tamper-evident-audit-logs.md). Next: [post 13 — Partner DID federation: cross-org trust without shared secrets](./13-partner-did-federation.md)._
