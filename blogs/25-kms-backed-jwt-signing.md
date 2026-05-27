# KMS-Backed JWT Signing: Trade-offs Between Azure Key Vault, AWS KMS, and GCP Cloud KMS

_Third post in the "Technology choices" series. [Post 12](./12-pluggable-adapters.md) covers the `SigningAdapter` interface and the adapter pattern that makes cloud-swappable signing possible. [Post 9](./09-capability-tokens.md) explains what these signed JWTs contain and why they're the security primitive the entire system is built on. See [`docs/blog-articles.md`](../blog-articles.md) for the full series index._

---

Signing a JWT sounds like a solved problem. You have a private key, you call `sign(payload, privateKey)`, you get a token back. Every JWT library handles this. Why would I write a whole post about it?

Because in production at enterprise scale, "you have a private key" is the part that's actually complicated. The private key needs to live somewhere it can't be exfiltrated. It needs to be available 24/7 at latencies that don't add noticeable overhead to every authentication and authorization event. It needs to be rotatable without downtime. It needs to be auditable. And it needs to work across the three major cloud providers, because our customers are split roughly three ways between Azure, AWS, and GCP, with a long tail of on-premises deployments that use hardware security modules directly.

Key management services (KMS) from the three major clouds all solve this problem, but they solve it differently. This post is a practical comparison from having built and operated the eunox signing layer across all three.

---

## Why a KMS, not a local private key?

Let me justify the premise first, because there are reasonable deployments where a local private key file is fine — developer machines, integration test environments, low-security internal tools.

For a governance platform that issues cryptographic tokens authorizing AI agents to take actions in production systems, the threat model includes:

- **Exfiltration of the signing key** → an attacker who gets the key can mint arbitrary capability tokens for any agent, any scope, any tenant. Every access control in the system is bypassed.
- **Signing server compromise** → even if the attacker can't get the raw key bytes, if they can run arbitrary code on the signing server, they can invoke the signing endpoint with any payload.

A key file on disk, even with tight file permissions, is accessible to anyone with OS-level access to the host. In a containerized deployment, the container runtime, the orchestration layer, and any operator with `kubectl exec` access can access a file-based key.

A KMS solves this by keeping the private key material inside a Hardware Security Module (HSM) that the cloud provider manages. The raw private key bytes **never leave the HSM boundary**. Your signing code sends a payload to the KMS API and receives a signed JWT (or raw signature). You never touch the private key. An attacker who compromises your application server can invoke the signing endpoint (which is bad), but they cannot exfiltrate the private key and use it to sign from elsewhere. The blast radius of a server compromise is bounded to whatever that compromised server can sign — and your audit trail will show every signing event, so you know exactly what was signed during the compromise window.

That's the baseline justification. Here's where the three services diverge.

---

## Azure Key Vault

**Key types supported:** RSA (2048, 3072, 4096), EC (P-256, P-384, P-521). For JWT signing, we use RSA-4096 with RS256 in lower-trust environments and RSA-4096 with RS512 in high-security configurations. EC P-256 with ES256 is faster and produces shorter tokens, but RSA is more universally recognized by external JWKS consumers.

**How signing works:** The Key Vault API accepts a raw payload hash (not the full payload). Your code computes `SHA-256(payload)`, sends it to Key Vault's `sign` endpoint with the key name and algorithm, and receives the raw signature bytes back. You then construct the JWT manually: base64url-encode the header and payload, sign the hash of `header.payload`, and base64url-encode the signature. This is lower-level than some KMS APIs that accept the full payload.

The Azure SDK handles the Key Vault authentication via Managed Identity when the gateway is deployed on Azure. In a Kubernetes deployment on AKS, the pod identity is configured via Azure Workload Identity — the pod has a Kubernetes service account annotated with the Azure AD application identity, and the SDK exchanges the Kubernetes service account token for an Azure AD token transparently.

**Latency profile:** I've measured Key Vault signing latency extensively across Azure regions. In the same region as the gateway deployment:

| Key type | p50 | p95  | p99  |
| -------- | --- | ---- | ---- |
| RSA-4096 | 8ms | 18ms | 35ms |
| EC P-256 | 5ms | 12ms | 22ms |

These are signing operation latencies only, not including network round trips from the application. If your gateway is in `East US` and your Key Vault is in `East US`, you're adding roughly 2-4ms of network overhead. If they're in different regions (a misconfiguration you want to catch at deployment validation time), you can add 40-100ms.

**Key rotation:** Key Vault handles key versioning natively. Each rotation creates a new key version; the current version is used for new signatures. Old versions remain available for verification (you can't delete them without explicit action). When we rotate a signing key, the new version becomes active for new token issuance immediately. Tokens signed with the old version continue to be valid until they expire (15 minutes by default). The JWKS endpoint exposes all active key versions, so verifiers always find the right key regardless of which version signed a given token. This is clean, well-documented, and has worked reliably in production.

**The Azure-specific gotcha:** Key Vault enforces per-key signing rate limits. The default limit is 2,000 cryptographic operations per 10 seconds per key across all callers in the region. For a high-traffic gateway with multiple replicas all signing tokens concurrently, you can hit this limit. The mitigation is to request a Key Vault premium tier with higher limits, or distribute signing load across multiple keys with an adapter-level strategy. The limit is documented by Microsoft but is easy to miss in planning, and discovering it under load is unpleasant.

---

## AWS KMS

**Key types supported:** RSA (2048, 3072, 4096), EC (P-256, P-384, P-521), SM2 (for China region customers). Same story for algorithm selection as Azure Key Vault.

**How signing works:** Unlike Key Vault, AWS KMS accepts the raw message (not just the hash) in its `Sign` API call. You pass the full `header.payload` string and the algorithm identifier. KMS handles the hashing internally. This is slightly simpler at the integration layer — you don't have to construct the hash yourself.

Authentication in AWS uses IAM roles. In EKS (Kubernetes on AWS), IRSA (IAM Roles for Service Accounts) is the equivalent of Azure Workload Identity — the pod assumes an IAM role via the Kubernetes service account token exchange, and the SDK handles the credential refresh transparently. The operational model is similar to Azure; the configuration syntax is different but the concept is the same.

**Latency profile:** AWS KMS in the same region as the gateway:

| Key type | p50 | p95  | p99  |
| -------- | --- | ---- | ---- |
| RSA-4096 | 6ms | 14ms | 28ms |
| EC P-256 | 4ms | 9ms  | 18ms |

Marginally faster than Azure Key Vault in my benchmarks, but within the same order of magnitude. The difference is not meaningful for the typical eunox deployment where signing happens during token issuance (a relatively infrequent operation compared to token verification, which is local and fast).

**Key rotation in AWS KMS:** AWS KMS supports automatic annual key rotation as a managed feature — you enable it, and KMS rotates the underlying key material every year, with old key versions retained for decryption of existing ciphertext. For our use case (signing, not encryption), automatic rotation is less relevant because a JWT signed with an old key version is still verifiable as long as that key version's public key is in the JWKS endpoint. What matters is that when we rotate, we update the JWKS endpoint to include the new key version and keep old versions accessible for the duration of their maximum token TTL window.

AWS KMS's `EnableKeyRotation` API enables or disables automatic rotation for eligible keys; it is not an on-demand rotate-now operation. In eunox today there is no `POST /admin/v1/keys/rotate` endpoint in the minter. Operational rotation is handled through key/version configuration and rollout procedures (update key/version env config, restart issuer, verify JWKS publication), with JWKS updates allowing old and new keys to coexist through the token TTL window.

**The AWS-specific gotcha:** AWS KMS pricing is per API call. At $0.03 per 10,000 requests for signing operations, a gateway handling 100,000 token issuances per month costs $0.30 in KMS fees, which is negligible. At 10 million issuances per month, it's $30. For high-volume deployments, this is still small relative to infrastructure costs, but it's worth knowing about — customers with aggressive cost optimization sometimes push back on per-call KMS pricing and want to understand alternatives. (There are no good alternatives if you want HSM-backed key storage. The cost of a compromised signing key vastly exceeds any savings from avoiding the KMS API.)

AWS KMS also has a `RequestedTokenTTL` concept for data keys, but that's for envelope encryption, not signing. For JWT signing there's no meaningful session concept — every signing call is independent.

---

## GCP Cloud KMS

**Key types supported:** RSA (2048, 3072, 4096), EC (P-256, P-384, P-521, P-256K). Note the P-256K (secp256k1) support — this is the Bitcoin and Ethereum curve, and it's the only major cloud KMS that supports it natively. Not relevant for JWT signing in standard deployments, but it comes up occasionally with customers who are also building blockchain integrations.

**How signing works:** Cloud KMS has an `asymmetricSign` method that accepts either a raw hash or delegates hashing to the service. We use the digest variant (pre-hash the payload, send the hash) for consistency with our Key Vault adapter — the same code path handles the raw signature regardless of whether the hash computation happened in our code or the KMS.

Authentication in GCP uses Workload Identity Federation on GKE. The model is similar to Azure and AWS: the pod has a Kubernetes service account that's bound to a GCP service account, and the Cloud KMS client library handles the token exchange. The GCP implementation is slightly more complex to configure than the AWS IRSA approach, but the operational result is the same.

**Latency profile:** Cloud KMS in the same region as the gateway:

| Key type | p50 | p95  | p99  |
| -------- | --- | ---- | ---- |
| RSA-4096 | 7ms | 16ms | 32ms |
| EC P-256 | 4ms | 11ms | 20ms |

Consistent with Azure and AWS. The three services are within measurement noise of each other at p50; the tail latencies are slightly different but not meaningfully so for this use case.

**Key rotation in Cloud KMS:** GCP Cloud KMS uses the concept of key "versions." Creating a new key version and setting it as primary is a two-step operation via API: `cryptoKeys.cryptoKeyVersions.create` followed by `cryptoKeys.patch` to set the new version as primary. We expose this through the admin rotation endpoint. One behavioral difference from AWS: GCP Cloud KMS does not automatically expose all key versions in a JWKS-compatible format — we maintain the JWKS cache ourselves, appending new key versions on rotation and purging versions that are past the maximum token TTL window.

**The GCP-specific gotcha:** Cloud KMS key destruction is irreversible and has a mandatory 24-hour scheduled destruction window. If you accidentally create a key with the wrong spec and want to remove it, you schedule it for destruction and wait 24 hours. This is a safety feature (prevents accidental key loss) but is occasionally frustrating in dev/test environments. More importantly, Cloud KMS has a slightly quirky behavior with EC key import — if you're migrating an existing key pair into Cloud KMS from another system, the import process is well-documented but has more steps than the equivalent on Azure or AWS. For eunox deployments that are starting fresh (which is the normal case), this doesn't matter; you generate the key in Cloud KMS from the start.

---

## The on-premises / private KMS case

A non-trivial number of enterprise customers — particularly in financial services and government — cannot use cloud-managed KMS. They either have existing HSM infrastructure (Thales Luna, Entrust nShield) or require keys to stay on-premises for regulatory reasons.

The `SigningAdapter` interface abstracts over this. An on-premises implementation uses the PKCS#11 interface that most HSMs expose, via a PKCS#11 library bundled with the HSM. The adapter calls the HSM through the library to perform signing operations; the private key stays in the HSM. Latency is typically higher (HSMs are not optimized for low-latency API calls; they're optimized for high-assurance key storage) — expect 20-100ms for a signing operation, depending on the HSM model and the cryptographic operation.

We don't ship a first-party PKCS#11 signing adapter in the public package, because the integration is so HSM-vendor-specific. The interface definition is in the `pkg/crypto` Go package (Apache-2.0), and the expected behavior is documented in `docs/adapters.md §Signing`. Enterprise customers with on-premises HSMs implement the adapter themselves; we provide reference code and integration testing support.

The production design principle here: anyone with an HSM, regardless of vendor, should be able to plug into eunox without forking or patching the platform. The adapter pattern exists precisely so that the enforcement core doesn't need to know whether the signing operation is happening in a cloud KMS, a hardware HSM, or a software key store. What the core knows is: call `signingAdapter.sign(payload)`, get back a signed JWT.

---

## JWKS endpoint design: what verifiers actually need

Every signing implementation eventually connects to the JWKS endpoint — the public-facing URL that verifiers use to fetch the public key(s) to verify JWT signatures. For eunox, this is `GET /well-known/jwks` on the capability issuer.

The JWKS endpoint design interacts with key rotation in a specific way that's worth understanding. The endpoint must return all keys that might currently be verifying against — not just the current signing key, but also any key whose signed tokens might still be valid. If a token has a 15-minute TTL and we rotated the signing key 10 minutes ago, the old key still needs to be in the JWKS for the next 5 minutes (until all tokens signed with it expire).

Our JWKS cache maintains a sliding window of key versions: the current signing key version, plus any version that was active within the last `JWKS_RETENTION_WINDOW_SECONDS` (default: `2 * maxTokenTTLSeconds`). This ensures that tokens issued just before a rotation can still be verified after the rotation, without requiring verifiers to cache old keys themselves.

One subtlety: the `kid` (key ID) field in the JWT header and the JWKS entry must match. AWS KMS key version ARNs are long and contain slashes, which are not valid in JWT `kid` values without encoding. We normalize the `kid` to `sha256(keyVersionArn)[0:16]` — a 16-character hex prefix of the ARN hash. Stable, URL-safe, uniquely identifies the key version across rotation, fits in the JWT header without escaping.

---

## A note on latency: when does signing happen?

This is worth clarifying because the latency numbers above might look alarming if you're thinking about the hot enforcement path. Signing does **not** happen on every tool call.

Token signing happens at **token issuance time** — when a new capability token is minted, either through the PKCE flow or through the `eunox request` CLI command. Once the token is issued, it's a signed JWT that any verifier can check locally using the public key from the JWKS endpoint. The enforcement hot path (the gateway evaluating a tool call) does local signature verification — a fast, in-process cryptographic operation with no network calls. The KMS is not involved in enforcement decisions.

So the KMS latency is relevant for token issuance frequency, not enforcement frequency. In practice, tokens are issued at session start and renewed every 15 minutes. For an agent that runs 10,000 tool calls in a session, there are roughly 3-4 token issuance events. The KMS adds 10-30ms to those 3-4 events. Over the session lifetime, this is imperceptible.

The one place where KMS latency matters more acutely is the audit signing path — the optional KMS-signed JWT in the audit record (described in post 11). If every audit record requires a KMS signing call, the hot path suddenly has a KMS dependency. We handle this with async audit signing: the audit record is written synchronously with HMAC, and the KMS-signed JWT is computed asynchronously and added to the record in a background flush. The record appears in the audit ledger immediately; the `evidenceJwt` field is populated within a configurable window (default 5 seconds). For real-time audit monitoring this is a non-issue; for compliance export, all records will have their `evidenceJwt` by the time anyone exports the ledger.

---

## Which one should you choose?

My honest recommendation:

**Use whatever KMS is native to your cloud deployment.** Don't use Azure Key Vault on AWS; don't use AWS KMS on GCP. The managed identity authentication story is the most important operational differentiator, and it's cleanest when everything is in the same cloud. Cross-cloud KMS access from a gateway on a different cloud adds credential management complexity that is almost never worth it.

**If you have an existing KMS that your security team already manages** (whether cloud-native or on-premises HSM), use that. Security teams have strong preferences about key custody, and a deployment that uses an unfamiliar KMS will face friction in security review that a deployment using the existing KMS won't. Pick the battle that matters: the battle is getting eunox deployed and governing your AI agents, not convincing your security team to adopt a new KMS.

**For new deployments without strong constraints**, EC P-256 with ES256 is my recommendation over RSA-4096 with RS256. Shorter tokens, faster signing, smaller JWKS payloads, and modern enough to be supported by every JWT library in active use. The only argument for RSA in new deployments is compatibility with extremely old JWT libraries, which you probably don't have.

---

_Previous: [post 24 — W3C DIDs in production](./24-w3c-dids-in-production.md). Next: [post 26 — Redis as a shared enforcement substrate: call counters, kill-switch, and DPoP replay](./26-redis-enforcement-substrate.md)._
