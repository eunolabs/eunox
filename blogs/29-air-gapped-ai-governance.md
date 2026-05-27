# Air-gapped AI governance: deploying eunox with no internet dependency

_Audience: platform engineers and security architects deploying AI governance in regulated, restricted, or sovereign environments_

---

There's a certain class of deployment where "just run it in the cloud" isn't an option. Defence contractors. Financial institutions with strict data residency requirements. Healthcare providers operating in sovereign cloud mandates. Government agencies with networks that are genuinely air-gapped. Organisations that have made a risk decision that internet-connected infrastructure is not acceptable for their AI workloads.

For a long time, this was a hard conversation to have with AI tooling vendors. Most of the early AI governance products were SaaS-first — the entire stack lived in someone else's cloud, and the idea of running it in an isolated environment was either not supported, or supported in a way that basically meant "yes, you can use our VPC-peering arrangement, which still connects to our control plane." That's not air-gapped. That's just air-gapped-ish.

This post is about how eunox runs in a genuinely disconnected environment. No call-home. No dependency on public DNS. No reliance on public container registries or public key infrastructure beyond what you pre-stage. I'll cover the Helm deployment, the image management approach, offline DID resolution, and on-premises KMS integration. It's not a simple setup, but it's a supported one, and I want to be honest about where the complexity lives.

---

## What "air-gapped" actually means

Let me be precise about the threat model, because "air-gapped" gets used loosely.

A strict air gap means no network path at all between the deployment environment and any public internet resource — not at deployment time, not at runtime. Images must be pre-staged. Certificates must be pre-loaded. Any external dependencies must be bundled or replaced with local equivalents.

A soft air gap, which is more common in practice, means no runtime internet access but allows internet access during a controlled deployment pipeline — you can pull images over the internet in your build environment, but once they're in your private registry, the deployment network has no outbound internet access.

The eunox air-gap support targets the soft air-gap model as the default, with documentation for strict air-gap as well. The distinction matters because strict air-gap requires you to also handle things like NTP synchronisation (JWT `iat`/`exp` validation requires an accurate clock), certificate revocation without OCSP, and DNS resolution without public DNS. These are solvable problems but they're outside the eunox stack — they're infrastructure prerequisites.

---

## The image inventory

The first problem in any air-gapped deployment is knowing exactly what container images you need. You can't do `docker pull` at runtime if there's no internet. Everything has to be pre-staged in a private registry that your deployment environment can reach.

The `k8s/air-gap-images.txt` manifest is the authoritative list of the service images, optional simulator image, build-time base images, and optional bundled dependencies used by the Stage-5 deployment assets. It looks like this:

```
ghcr.io/edgeobs/eunox-gateway:1.0.0@sha256:0000000000000000000000000000000000000000000000000000000000000001
ghcr.io/edgeobs/eunox-issuer:1.0.0@sha256:0000000000000000000000000000000000000000000000000000000000000002
ghcr.io/edgeobs/eunox-minter:1.0.0@sha256:0000000000000000000000000000000000000000000000000000000000000003
ghcr.io/edgeobs/eunox-db-token-svc:1.0.0@sha256:0000000000000000000000000000000000000000000000000000000000000004
ghcr.io/edgeobs/eunox-storage-grant-svc:1.0.0@sha256:0000000000000000000000000000000000000000000000000000000000000005
ghcr.io/edgeobs/eunox-posture-emitter:1.0.0@sha256:0000000000000000000000000000000000000000000000000000000000000006
ghcr.io/edgeobs/eunox-partner-issuer-sim:1.0.0@sha256:0000000000000000000000000000000000000000000000000000000000000007
golang:1.25-alpine@sha256:0000000000000000000000000000000000000000000000000000000000000010
alpine/curl:latest@sha256:0000000000000000000000000000000000000000000000000000000000000011
bitnami/postgresql:16@sha256:0000000000000000000000000000000000000000000000000000000000000020
bitnami/redis:7@sha256:0000000000000000000000000000000000000000000000000000000000000021
```

The list is versioned alongside the Helm charts, so the image manifest and the chart are always in sync. Every chart bump that changes an image dependency updates `air-gap-images.txt` as part of the same commit.

The `scripts/pull-air-gap-images.sh` script takes the manifest, pulls each image, and optionally retags/pushes it when you set `PRIVATE_REGISTRY`. You run this from a machine that has internet access and can also reach your private registry:

```bash
PRIVATE_REGISTRY=registry.internal.example.com \
  sh scripts/pull-air-gap-images.sh
```

After the script completes, every image in the manifest is available at your private registry. The umbrella chart currently overrides repositories per service, so the practical pattern is to point each service at your private registry in `values.yaml` (or start from the provider-specific values files under `k8s/helm/eunox/`):

```yaml
gateway:
  image:
    repository: registry.internal.example.com/edgeobs/eunox-gateway
issuer:
  image:
    repository: registry.internal.example.com/edgeobs/eunox-issuer
minter:
  image:
    repository: registry.internal.example.com/edgeobs/eunox-minter
dbTokenService:
  image:
    repository: registry.internal.example.com/edgeobs/eunox-db-token-svc
storageGrantService:
  image:
    repository: registry.internal.example.com/edgeobs/eunox-storage-grant-svc
postureEmitter:
  image:
    repository: registry.internal.example.com/edgeobs/eunox-posture-emitter
```

One thing to get right: verify the image digests. SHA-256 image digests are in the manifest alongside the tags. When deploying in a security-sensitive environment, you want to deploy by digest, not by tag — tags are mutable. Add the digests to your Kubernetes deployment specs and your private registry settings will enforce them. If an image has been tampered with between pull and deployment, the digest won't match.

---

## The Helm umbrella chart

The `k8s/helm/eunox/` directory contains the umbrella chart that deploys the full eunox stack. It renders the core service Deployments, Services, ConfigMaps, and Secrets directly from one chart and provides a single `values.yaml` interface for configuring the whole deployment; the only subcharts are the optional Postgres and Redis dependencies.

The services covered:

| Service           | Helm key              | Purpose                                 |
| ----------------- | --------------------- | --------------------------------------- |
| gateway           | `gateway`             | Enforcement engine, audit ledger writer |
| issuer            | `issuer`              | JWT minting, OIDC federation            |
| minter            | `minter`              | API key lifecycle, admin console        |
| db-token-svc      | `dbTokenService`      | Database token brokering                |
| storage-grant-svc | `storageGrantService` | Storage grant brokering                 |
| posture-emitter   | `postureEmitter`      | System posture telemetry                |

Postgres and Redis are external dependencies by default, not services the umbrella chart installs automatically. For quick local evaluation you can enable the optional Bitnami subcharts with `--set postgresql.enabled=true --set redis.enabled=true`; for production air-gap deployments you normally vendor those upstream charts into your private Helm repository or point the services at operator-managed Postgres and Redis instead.

For the most constrained deployments, there's also a `docker-compose.yml` in `infra/` with the `full` profile that runs the complete stack. This is useful for single-node deployments (on-premises servers that aren't running Kubernetes) and for development environments. In air-gapped contexts it's often the simpler starting point if you're not already running Kubernetes.

---

## Configuring services for disconnected operation

Several of eunox's components have external dependencies that need to be addressed for air-gap operation.

### The issuer and OIDC

The issuer (`cmd/issuer`) issues JWT capability tokens and can federate with an IdP via OIDC. In connected mode, the OIDC discovery endpoint at `https://login.microsoftonline.com/<tenant>/.well-known/openid-configuration` (or your IdP's equivalent) is fetched periodically to refresh JWKS and configuration.

In air-gapped mode, there are two options. First, use an on-premises IdP — Microsoft AD FS, Keycloak, Dex — that's already in your network. The OIDC discovery URL just points at your internal instance. No internet required.

Second, for truly disconnected environments where there's no IdP at all, the issuer can run in API-key-only mode. Users authenticate with long-lived API keys rather than OIDC-issued tokens, and the capability issuer skips the OIDC federation step entirely. This sacrifices some of the SSO ergonomics but maintains all the enforcement properties.

The relevant config values:

```yaml
capabilityIssuer:
  oidc:
    enabled: false # disable OIDC federation
  apiKeyAuth:
    enabled: true
```

### The gateway and JWKS

The gateway verifies capability tokens by fetching the issuer's JWKS from the URL you configure explicitly. In connected and disconnected deployments alike, the supported knob is `ISSUER_JWKS_URL`, optionally paired with `ISSUER_METADATA_URL` when you also mirror the issuer discovery document internally.

In practice, air-gapped operators host the issuer inside the same network segment (or mirror its JWKS onto an internal endpoint) and point the gateway at that internal URL:

```env
ISSUER_JWKS_URL=http://issuer:3001/.well-known/jwks.json
ISSUER_METADATA_URL=http://issuer:3001/.well-known/issuer
```

Key rotation still happens through the JWKS endpoint — you rotate the issuer key, publish the new key in JWKS, and keep the old key available for the normal token-TTL overlap window.

### Partner DID resolution

W3C Decentralised Identifiers (DIDs) are how eunox's partner federation system establishes cross-organisation trust. `did:web` documents live at `https://<domain>/.well-known/did.json`. In connected mode, the gateway fetches these over the public internet. In air-gapped mode, the internet isn't reachable.

For air-gapped partner DID trust, the supported mechanisms today are the bootstrap allowlist and the partner-DID registry workflow.

**Bootstrap allowlist.** `TRUSTED_PARTNER_DIDS` seeds a comma-separated allowlist of partner issuer DIDs. That's the fastest way to stand up a disconnected lab or bootstrap a new environment, but it's intentionally blocked by default in production unless you explicitly relax `PARTNER_DID_REGISTRY_REQUIRED`.

**Partner-DID registry.** For production deployments, the supported path is the gateway's partner-DID registry and admin approval workflow. You register the trusted DIDs there, then host the corresponding `did:web` documents on internal DNS/HTTP endpoints or mirrored domains that the gateway can resolve from the restricted network.

In other words, the disconnected part is operational rather than magical: the gateway still resolves `did:web` from infrastructure you make reachable inside the enclave, and trust is enforced by `TRUSTED_PARTNER_DIDS` or the registry instead of an unsupported static-document map.

---

## On-premises KMS integration

Every JWT signed by eunox needs a signing key. The issuer currently ships with three built-in signing providers: `azure-keyvault`, `aws-kms`, and `gcp-cloudkms`. For regulated on-prem or sovereign deployments, the practical pattern is private connectivity from the enclave to one of those approved KMS endpoints rather than a separate local signer implementation.

That usually means something like private networking to Azure Key Vault, AWS KMS, or GCP Cloud KMS from the restricted environment, with the rest of the application traffic still isolated from the public internet. For local development and rehearsal, the AWS path can also be exercised with LocalStack, which emulates the KMS API closely enough for issuer bring-up.

What the repository does **not** currently ship is a Vault signer, a PKCS#11 signer, or a file-based issuer signer. If you need a fully disconnected local HSM integration, that's an extension point in the signing registry rather than something you can enable with an existing config flag today.

---

## The smoke test

After deploying in an air-gapped environment, you need to verify that everything is actually working disconnected — not just "services are up" but "enforcement is functioning correctly without any runtime internet calls."

The `infra/smoke-test.sh` script has a Stage-5 section specifically for this. It tests:

1. Capability token issuance — can the capability issuer mint a JWT without making an external HTTP call?
2. Token verification at the gateway — does the gateway correctly verify the token using its internal `ISSUER_JWKS_URL` configuration?
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

**Key rotation is more manual.** Even with the currently supported cloud KMS providers, restricted-network deployments still require more choreography: rotate the signing key, publish the new key in the internal JWKS endpoint, and coordinate the overlap window before retiring the old key. This can be scripted, but it requires more process discipline.

**DID resolution lag.** If a partner organisation rotates their DID keys, you won't automatically pick up the new document until your internal mirror or private `did:web` hosting is updated. If you're using the bootstrap allowlist, you'll also need to keep the trusted DID set current; if you're using the registry workflow, you need the corresponding approval/update step. Neither is ideal, though the partner DID circuit breaker (described in [the DID federation post](./13-partner-did-federation.md)) will trip correctly on sustained verification failures and prevent calls from proceeding on stale credentials.

**No automatic updates.** Connected deployments can pull new image versions on a schedule. Air-gapped deployments require a managed update cycle — pull new images to the private registry, run the air-gap script, roll out the deployment. This is your standard change management process, and it's better security practice in any case, but it means you're committed to an explicit update schedule.

**Telemetry is absent.** The posture emitter that feeds anonymised usage telemetry to eunox's product team can't operate in an air-gapped environment. This is fine from an operational standpoint — it's opt-out — but means we receive less signal from air-gapped deployments for product improvement purposes. Something to be aware of.

None of these are blockers. Regulated-industry deployments accept these trade-offs as the cost of the isolation they require. The eunox air-gap support is designed to make those trade-offs manageable, not to pretend they don't exist.

---

## Deployment checklist

For reference, here's the sequence for a first-time air-gapped deployment:

1. Run `scripts/pull-air-gap-images.sh` against the target private registry from an internet-connected machine
2. Vendor the optional upstream Helm charts (postgres, redis) into your private chart repository if you plan to enable the bundled subcharts
3. Override each service's `image.repository` in `values.yaml` (or start from `k8s/helm/eunox/values-aws.yaml` / `values-gcp.yaml`) so the chart points at your private registry
4. Decide how the capability issuer will reach a supported signing provider (`azure-keyvault`, `aws-kms`, or `gcp-cloudkms`) from the restricted network
5. Point `ISSUER_JWKS_URL` at an internal issuer JWKS endpoint
6. Seed partner trust with `TRUSTED_PARTNER_DIDS` for bootstrap or the partner-DID registry workflow for production
7. Deploy with the Helm umbrella chart
8. Run `scripts/check-deployment-bundle.mjs` to validate the deployment configuration
9. Run `infra/smoke-test.sh` with network egress monitoring to verify disconnected operation
10. Verify the audit chain is intact with `GET /api/v1/audit/chain-proof`

For on-premises environments that aren't running Kubernetes, the docker-compose path replaces steps 1-3 of the Helm configuration but is otherwise equivalent.

The full deployment guide is in `docs/deployment.md`, in the "Stage-5 on-prem deployment" section. For compliance requirements that include a formal deployment verification step, the smoke test output and check-deployment-bundle output can be archived as deployment evidence.
