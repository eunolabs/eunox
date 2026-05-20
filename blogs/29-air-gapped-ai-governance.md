# Air-gapped AI governance: deploying euno with no internet dependency

*Audience: platform engineers and security architects deploying AI governance in regulated, restricted, or sovereign environments*

---

There's a certain class of deployment where "just run it in the cloud" isn't an option. Defence contractors. Financial institutions with strict data residency requirements. Healthcare providers operating in sovereign cloud mandates. Government agencies with networks that are genuinely air-gapped. Organisations that have made a risk decision that internet-connected infrastructure is not acceptable for their AI workloads.

For a long time, this was a hard conversation to have with AI tooling vendors. Most of the early AI governance products were SaaS-first — the entire stack lived in someone else's cloud, and the idea of running it in an isolated environment was either not supported, or supported in a way that basically meant "yes, you can use our VPC-peering arrangement, which still connects to our control plane." That's not air-gapped. That's just air-gapped-ish.

This post is about how euno runs in a genuinely disconnected environment. No call-home. No dependency on public DNS. No reliance on public container registries or public key infrastructure beyond what you pre-stage. I'll cover the Helm deployment, the image management approach, offline DID resolution, and on-premises KMS integration. It's not a simple setup, but it's a supported one, and I want to be honest about where the complexity lives.

---

## What "air-gapped" actually means

Let me be precise about the threat model, because "air-gapped" gets used loosely.

A strict air gap means no network path at all between the deployment environment and any public internet resource — not at deployment time, not at runtime. Images must be pre-staged. Certificates must be pre-loaded. Any external dependencies must be bundled or replaced with local equivalents.

A soft air gap, which is more common in practice, means no runtime internet access but allows internet access during a controlled deployment pipeline — you can pull images over the internet in your build environment, but once they're in your private registry, the deployment network has no outbound internet access.

The euno air-gap support targets the soft air-gap model as the default, with documentation for strict air-gap as well. The distinction matters because strict air-gap requires you to also handle things like NTP synchronisation (JWT `iat`/`exp` validation requires an accurate clock), certificate revocation without OCSP, and DNS resolution without public DNS. These are solvable problems but they're outside the euno stack — they're infrastructure prerequisites.

---

## The image inventory

The first problem in any air-gapped deployment is knowing exactly what container images you need. You can't do `docker pull` at runtime if there's no internet. Everything has to be pre-staged in a private registry that your deployment environment can reach.

The `k8s/air-gap-images.txt` manifest is the authoritative list of every image required by the euno Helm charts. It looks like this:

```
ghcr.io/euno/tool-gateway:1.14.2
ghcr.io/euno/capability-issuer:1.14.2
ghcr.io/euno/api-key-minter:1.14.2
ghcr.io/euno/posture-emitter:1.14.2
ghcr.io/euno/partner-issuer-sim:1.0.0
postgres:16.2-alpine
redis:7.2.4-alpine
```

The list is versioned alongside the Helm charts, so the image manifest and the chart are always in sync. Every chart bump that changes an image dependency updates `air-gap-images.txt` as part of the same commit.

The `scripts/pull-air-gap-images.sh` script takes the manifest and a target registry URL, pulls each image, retags it for the target registry, and pushes it. You run this from a machine that has internet access and can also reach your private registry:

```bash
./scripts/pull-air-gap-images.sh \
  --registry registry.internal.example.com/euno \
  --tag-suffix -airgap
```

After the script completes, every image in the manifest is available at your private registry. The Helm charts accept a global `imageRegistry` override value, so pointing the entire deployment at your private registry is a one-line change in your `values.yaml`:

```yaml
global:
  imageRegistry: registry.internal.example.com/euno
```

One thing to get right: verify the image digests. SHA-256 image digests are in the manifest alongside the tags. When deploying in a security-sensitive environment, you want to deploy by digest, not by tag — tags are mutable. Add the digests to your Kubernetes deployment specs and your private registry settings will enforce them. If an image has been tampered with between pull and deployment, the digest won't match.

---

## The Helm umbrella chart

The `k8s/helm/euno/` directory contains the umbrella chart that deploys the full euno stack. The umbrella chart pulls in the individual service charts as subcharts and provides a single `values.yaml` interface for configuring the whole deployment.

The services covered:

| Service | Chart | Purpose |
|---|---|---|
| tool-gateway | `charts/tool-gateway/` | Enforcement engine, audit ledger writer |
| capability-issuer | `charts/capability-issuer/` | JWT minting, OIDC federation |
| api-key-minter | `charts/api-key-minter/` | API key lifecycle, admin console |
| posture-emitter | `charts/posture-emitter/` | System posture telemetry |
| postgres | upstream chart | Audit ledger, policy store |
| redis | upstream chart | Shared enforcement state |

The upstream charts for postgres and redis need to be vendored into your private Helm repository for air-gap deployments. The air-gap setup docs in `docs/DEPLOYMENT.md` cover how to do this with `helm pull` and your internal chart repository.

For the most constrained deployments, there's also a `docker-compose.yml` in `infra/` with the `full` profile that runs the complete stack. This is useful for single-node deployments (on-premises servers that aren't running Kubernetes) and for development environments. In air-gapped contexts it's often the simpler starting point if you're not already running Kubernetes.

---

## Configuring services for disconnected operation

Several of euno's components have external dependencies that need to be addressed for air-gap operation.

### The capability issuer and OIDC

The capability issuer (`packages/capability-issuer/`) issues JWT capability tokens and can federate with an IdP via OIDC. In connected mode, the OIDC discovery endpoint at `https://login.microsoftonline.com/<tenant>/.well-known/openid-configuration` (or your IdP's equivalent) is fetched periodically to refresh JWKS and configuration.

In air-gapped mode, there are two options. First, use an on-premises IdP — Microsoft AD FS, Keycloak, Dex — that's already in your network. The OIDC discovery URL just points at your internal instance. No internet required.

Second, for truly disconnected environments where there's no IdP at all, the capability issuer can run in API-key-only mode. Users authenticate with long-lived API keys rather than OIDC-issued tokens, and the capability issuer skips the OIDC federation step entirely. This sacrifices some of the SSO ergonomics but maintains all the enforcement properties.

The relevant config values:

```yaml
capabilityIssuer:
  oidc:
    enabled: false  # disable OIDC federation
  apiKeyAuth:
    enabled: true
```

### The tool gateway and JWKS

The gateway verifies capability tokens by fetching the issuer's JWKS. In connected mode, the JWKS URL in the token's `iss` claim is used to discover keys. In air-gapped mode, the gateway needs to be pre-configured with the static public key set for each issuer it trusts.

The `GATEWAY_STATIC_JWKS` environment variable accepts a JSON object mapping issuer URLs to their JWKS:

```json
{
  "https://capability-issuer.internal.example.com": {
    "keys": [
      { "kty": "RSA", "kid": "v1", "n": "...", "e": "AQAB" }
    ]
  }
}
```

When this is set, the gateway skips the HTTP JWKS fetch and uses the static keys. Key rotation in this mode requires updating the static configuration — something to factor into your key management procedures. You'll want to script key rotation so that the static JWKS is updated and the gateway is restarted before the old key is decommissioned.

### Partner DID resolution

W3C Decentralised Identifiers (DIDs) are how euno's partner federation system establishes cross-organisation trust. `did:web` documents live at `https://<domain>/.well-known/did.json`. In connected mode, the gateway fetches these over the public internet. In air-gapped mode, the internet isn't reachable.

For air-gapped partner DID resolution, there are two supported approaches.

**Static DID configuration.** The gateway accepts a `STATIC_DID_DOCUMENTS` environment variable mapping DID identifiers to their DID documents. This is a JSON object:

```json
{
  "did:web:partner.example.com": {
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:web:partner.example.com",
    "verificationMethod": [...]
  }
}
```

When a partner DID is in the static map, the gateway uses the static document rather than attempting HTTP resolution. You update this when your partner rotates their keys (at which point you'd update the static document and redeploy the gateway configuration).

**Internal DID proxy.** For more dynamic environments, you can run a DID resolver proxy on your internal network that serves DID documents from a locally-maintained registry. The gateway's DID resolver is configurable to use a custom resolver endpoint rather than the standard well-known URL pattern. The proxy maintains the DID documents by sync from a controlled external connection (updated during maintenance windows, for example) and serves them to the gateway over the internal network.

The static configuration approach is simpler and appropriate for most air-gapped deployments where the set of partner organisations is small and changes infrequently. The proxy approach is better for deployments that maintain active federation with many partners and need to handle partner key rotations without redeploying gateway configuration.

---

## On-premises KMS integration

Every JWT signed by euno needs a signing key. In cloud deployments this is a KMS-backed key in Azure Key Vault, AWS KMS, or GCP Cloud KMS. In air-gapped environments, you need a local equivalent.

**HashiCorp Vault** is the most common answer. If you're running an air-gapped Kubernetes environment, you're probably already running Vault for secrets management. The signing adapter for Vault is the `VaultSigningAdapter` in `packages/common-infra/`. Configuration:

```yaml
capabilityIssuer:
  signing:
    adapter: vault
    vault:
      address: https://vault.internal.example.com
      authMethod: kubernetes
      roleName: capability-issuer
      transitKeyPath: secret/euno/signing-key
```

The Vault transit secrets engine is used for signing operations — the private key never leaves Vault, which is the same HSM-boundary property you get from the cloud KMS options. Vault Enterprise supports HSM-backed transit keys if you need the physical HSM boundary.

**PKCS#11 / local HSM.** For organisations with dedicated HSM hardware (SafeNet Luna, Thales, etc.), the `Pkcs11SigningAdapter` is available. You configure it with the PKCS#11 library path and the key identifier:

```yaml
capabilityIssuer:
  signing:
    adapter: pkcs11
    pkcs11:
      libraryPath: /usr/lib/pkcs11/libsofthsm2.so
      slot: 0
      pin: ${PKCS11_PIN}
      keyLabel: euno-signing-key
```

SoftHSM2 is supported as a software-only PKCS#11 implementation for environments that need the interface without dedicated hardware — useful for development and testing air-gap configurations before deploying with real hardware.

**Fallback: file-based key.** For deployments that don't have Vault or HSM access — small-scale on-premises deployments, lab environments, emergency scenarios — the signing adapter can be configured to use a key file. This is less secure than a hardware-backed key but maintains the JWT signature chain. Key files should be stored with appropriate permissions (`600`, owned by the service account) and ideally encrypted at rest using your platform's volume encryption.

This fallback is documented but I'd encourage any production deployment to use Vault or hardware. The threat model for tamper-evident audit records depends on an adversary not being able to forge JWT signatures. A key file that someone can read is a key they can use.

---

## The smoke test

After deploying in an air-gapped environment, you need to verify that everything is actually working disconnected — not just "services are up" but "enforcement is functioning correctly without any runtime internet calls."

The `infra/smoke-test.sh` script has a Stage-5 section specifically for this. It tests:

1. Capability token issuance — can the capability issuer mint a JWT without making an external HTTP call?
2. Token verification at the gateway — does the gateway correctly verify the token using its static or local key configuration?
3. Enforcement — does a valid call pass and an invalid call deny?
4. Audit write — does the audit record appear in the Postgres ledger?
5. Kill-switch — does activating the kill-switch block calls within one second?
6. Revocation — does revoking a token prevent subsequent calls?

Run the smoke test with network egress monitoring enabled (your firewall or a tool like `tcpdump`/`ss`) to verify that no test step triggers an outbound connection. If the smoke test passes with no external calls, your deployment is genuinely operating disconnected.

There's also a `scripts/check-deployment-bundle.mjs` script that verifies the integrity of the deployment bundle itself — that the image manifest is consistent with the chart definitions, that the static configuration files are in expected formats, and that no configuration value is set to a URL that points to a public internet endpoint. Run this as part of your deployment pipeline to catch misconfigurations before they reach production.

---

## Certificate management without OCSP

In a standard TLS deployment, certificate revocation is checked via OCSP (Online Certificate Status Protocol) — a call to the CA's OCSP endpoint at TLS handshake time. In an air-gapped environment, that OCSP call can't be made.

The options:

**OCSP stapling.** The server includes the OCSP response in the TLS handshake, so the client doesn't need to contact the CA directly. Nginx and many other servers support OCSP stapling. Configure your internal reverse proxy to staple OCSP responses, which are themselves cached from a periodic fetch during maintenance windows.

**Short-lived certificates.** Certificate validity periods short enough that a revoked certificate expires before an OCSP check would have been meaningful. Combined with automated rotation (cert-manager in Kubernetes handles this), you get an effective revocation mechanism without any runtime OCSP calls.

**Private CA.** For internal service-to-service communication, use a private CA running on your internal network (CFSSL, Vault PKI, or cloud-internal CA if applicable). Certificates issued by your private CA don't need to be checked with external OCSP endpoints.

---

## What you're trading off

I want to be honest about this. Air-gapped deployments are harder to operate than cloud deployments, and some of the failure modes are different.

**Key rotation is more manual.** In a cloud KMS deployment, key rotation is a single API call. In a Vault or HSM deployment, key rotation involves generating a new key, updating the JWKS in any static configurations, and coordinating the switchover. This can be scripted, but it requires more process discipline.

**DID resolution lag.** If a partner organisation rotates their DID keys, you won't automatically pick up the new document. For static DID configurations, you'll have verification failures until the static document is updated. For proxy-based resolution, the lag is the sync interval. Neither is ideal, though the partner DID circuit breaker (described in [the DID federation post](./13-partner-did-federation.md)) will trip correctly on sustained verification failures and prevent calls from proceeding on stale credentials.

**No automatic updates.** Connected deployments can pull new image versions on a schedule. Air-gapped deployments require a managed update cycle — pull new images to the private registry, run the air-gap script, roll out the deployment. This is your standard change management process, and it's better security practice in any case, but it means you're committed to an explicit update schedule.

**Telemetry is absent.** The posture emitter that feeds anonymised usage telemetry to euno's product team can't operate in an air-gapped environment. This is fine from an operational standpoint — it's opt-out — but means we receive less signal from air-gapped deployments for product improvement purposes. Something to be aware of.

None of these are blockers. Regulated-industry deployments accept these trade-offs as the cost of the isolation they require. The euno air-gap support is designed to make those trade-offs manageable, not to pretend they don't exist.

---

## Deployment checklist

For reference, here's the sequence for a first-time air-gapped deployment:

1. Run `scripts/pull-air-gap-images.sh` against the target private registry from an internet-connected machine
2. Vendor the upstream Helm charts (postgres, redis) into your private chart repository
3. Configure your on-premises KMS (Vault, PKCS#11, or key file with appropriate protections)
4. Prepare static DID documents or configure an internal DID proxy
5. Configure static JWKS for the capability issuer if not running an internal IdP
6. Deploy with the Helm umbrella chart, pointing `global.imageRegistry` at your private registry
7. Run `scripts/check-deployment-bundle.mjs` to validate the deployment configuration
8. Run `infra/smoke-test.sh` with network egress monitoring to verify disconnected operation
9. Verify the audit chain is intact with `GET /api/v1/audit/chain-proof`

For on-premises environments that aren't running Kubernetes, the docker-compose path replaces steps 1-3 of the Helm configuration but is otherwise equivalent.

The full deployment guide is in `docs/DEPLOYMENT.md`, Section 12. For compliance requirements that include a formal deployment verification step, the smoke test output and check-deployment-bundle output can be archived as deployment evidence.
