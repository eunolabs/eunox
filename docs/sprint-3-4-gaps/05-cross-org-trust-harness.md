# Item #5 — Cross-Organization Trust Simulation Harness

**Plan reference:** `docs/execution-plan.md` Sprint 4 → Team DP →
"Cross-Organization Simulation" (line 291). Two halves:

1. **Outbound:** instantiate a "partner" service that trusts our DID
   and accepts our agents' VCs.
2. **Inbound:** create a dummy partner-issuer VC; verify our Tool
   Gateway accepts it by resolving the partner's DID document.

**Files affected:** new `packages/partner-issuer-sim/` (source +
Dockerfile), new `k8s/partner-sim/` manifests (with TLS termination —
see §3), `packages/integration-tests/tests/cross-org.test.ts` (new),
`docs/cross-organizations.md` (already exists — extend with harness
docs), and possibly `packages/capability-issuer/src/did-resolver.ts`
(opt-in localhost/test-mode HTTP exception — see §2).

## Problem

The codebase has all the *primitives* for cross-org trust: the DID
resolver in `packages/capability-issuer/src/did-resolver.ts` (869
lines) supports `did:web` / `did:key` / `did:ion` resolution and the
gateway already validates JWT signatures against resolved DIDs.
What's missing is an end-to-end harness that proves the round trip
works in a deployment shape that mirrors a real partner integration.

Without this harness, any regression in DID resolution, JWKS lookup,
or VC envelope handling would be caught only at first contact with a
real partner — far too late.

## Goals

- A standalone "partner" service deployable to a separate Kubernetes
  namespace (or run via docker-compose) that:
  - Has its own DID (`did:web:partner.local`) and signing key.
  - Exposes a `/issue` endpoint that mints VCs for "partner agents".
  - Exposes its DID document at `/.well-known/did.json` so our
    gateway can resolve it.
- An integration test that:
  - Spins up our issuer + gateway and the partner issuer.
  - Has the partner mint a VC with capabilities scoped to a resource
    we control.
  - Submits that VC to our gateway as if a partner agent were calling
    in, and asserts the gateway accepts it.
  - Submits one of our VCs to the partner gateway and asserts the
    partner accepts it (proving outbound trust).
- The harness is invokable from CI (no real DNS, no real cloud).

## Non-goals

- Multi-cloud deployment of the partner sim (Azure App Service, AWS
  EKS, GCP Cloud Run variants are mentioned in the plan but are
  operator-side; a single Kubernetes/docker-compose target is enough
  to validate the trust math).
- Federation policy negotiation (the plan does not require it for
  Sprint 4; we hard-code the partner DID into the gateway's trusted-
  issuer list).

## Design

### 1. New package: `packages/partner-issuer-sim/`

A minimal Express service mirroring the structure of
`capability-issuer` but with only the bits a partner needs:

- `src/index.ts` — Express app with three routes:
  - `GET /.well-known/did.json` — serves the static DID document.
  - `POST /issue` — accepts `{ partnerAgentId, capabilities }` and
    returns a signed VC (using the same `did-signer.ts` from
    `@euno/capability-issuer`, which we re-export). No identity
    provider — partner agents are pre-shared via config.
  - `GET /healthz`.
- `src/keys/` — at startup, generates an Ed25519 key pair if none
  exists on disk; persists to a mounted volume in k8s. The DID
  document is generated from the public key.
- `Dockerfile` — same base image as `capability-issuer` Dockerfile.
- `package.json` — depends on `@euno/common` and `@euno/capability-issuer`
  (via the workspace; no copy-paste).

The package is **not** published to any registry; it lives in the
monorepo solely for testing.

### 2. Trust configuration

The gateway already supports a list of trusted issuers (verify via
DID resolution). Extend the gateway's deployment config to accept
`TRUSTED_PARTNER_DIDS=did:web:partner.local,did:web:other-partner.com`.
The integration test injects
`did:web:partner-issuer-sim.partner-sim.svc.cluster.local` (in-cluster
DNS, served via the in-cluster TLS terminator described in §3) for
the Kubernetes path. For the docker-compose path, the harness runs
the partner sim behind a local TLS terminator (e.g. an `nginx`
sidecar with a self-signed cert mounted into the gateway's trust
store) and uses `did:web:partner-sim.local` mapped via
`extra_hosts`. A pure-HTTP fallback (`did:web:localhost%3A4001`)
is **not** supported by the current `did-resolver.ts`, which always
fetches over HTTPS — picking it would require an opt-in
localhost/test-mode HTTP exception in the resolver, gated behind a
`DID_WEB_ALLOW_HTTP_FOR_HOSTS` allow-list and covered by a dedicated
unit test. This doc recommends the TLS-terminator path; the resolver
change is listed as an alternative in the open questions.

`did:web` resolution must support custom ports — verify in
`did-resolver.ts` and add a unit test if missing. If the
localhost/test-mode HTTP exception is adopted instead, that path
must also be covered by an explicit unit test in `did-resolver.ts`.

### 3. Kubernetes manifests: `k8s/partner-sim/`

- `namespace.yaml` — `partner-sim` namespace.
- `deployment.yaml` — single-replica Deployment of
  `partner-issuer-sim` with a PVC for the key directory.
- `service.yaml` — ClusterIP exposing port 443 → 4001 with TLS
  termination (either at an Ingress in front of the Service, or via
  a sidecar reverse proxy in the pod). The current `did-resolver.ts`
  always fetches DID documents over HTTPS, so a plain-HTTP Service
  will not be resolvable from the gateway. The self-signed CA used
  by the partner sim is mounted into the gateway pod's trust store
  in CI (init-container that appends to `/etc/ssl/certs/`).
- `network-policy.yaml` — allow ingress only from the test runner
  namespace and from the `tool-gateway` namespace (so the gateway
  can fetch `did:web` documents). Egress only to DNS + the issuer's
  port — partner sim is intentionally network-segmented.
- `kustomization.yaml` — for `kubectl apply -k k8s/partner-sim/`.

### 4. docker-compose (CI-friendly path)

Add `infra/docker-compose.cross-org.yml` (or extend the existing
infra compose file) with three services: `our-issuer`, `our-gateway`,
`partner-issuer-sim`. Each in its own network; the test driver runs
on the host and talks to all three.

This is the path used in CI (no Kubernetes runner needed).

### 5. Integration test

`packages/integration-tests/tests/cross-org.test.ts`:

- `beforeAll`: `docker compose -f infra/docker-compose.cross-org.yml up -d`,
  then poll healthz endpoints with a 60s timeout.
- Test 1 — **Inbound (partner → us)**:
  - POST partner's `/issue` with `{ partnerAgentId: 'partner-agent-1',
    capabilities: [{ resource: 'storage://shared-data/**', actions:
    ['read'] }] }`.
  - POST our gateway's `/validate` with the returned VC and a
    matching action/resource.
  - Assert `allowed: true`, and that the audit log shows
    `issuer: 'did:web:...partner...'`.
- Test 2 — **Outbound (us → partner)**:
  - Have our issuer mint a VC for one of our agents.
  - POST partner's `/validate` with it.
  - Assert accepted.
- Test 3 — **Untrusted issuer rejected**:
  - Generate a random `did:key` and mint a VC with it.
  - POST our gateway's `/validate` → assert `allowed: false`,
    reason mentions untrusted issuer.
- `afterAll`: tear down compose.

### 6. Docs

Extend `docs/cross-organizations.md` with a "Running the harness
locally" section pointing to the compose file and to
`packages/partner-issuer-sim/README.md`.

## Test strategy

The harness *is* the test. CI runs it as a separate job (it's slower
than unit tests due to compose startup) gated only on PRs touching:

- `packages/capability-issuer/src/did-*.ts`
- `packages/tool-gateway/`
- `packages/partner-issuer-sim/`
- `infra/docker-compose.cross-org.yml`

Other PRs run it nightly only.

## Rollout

- Phase 1: harness lands, CI nightly only.
- Phase 2 (after one week of green nightlies): promote to per-PR for
  the gated path list.
- Phase 3: document procedure for adding additional partner DID
  methods (`did:ion`, `did:plc`) by adding fixtures.

## Risks

- **CI flake** from compose startup races. Mitigation: explicit
  healthz polling with a generous timeout; never `sleep`.
- **Key persistence** in the container: an ephemeral filesystem means
  the partner DID doc changes between runs. Mitigation: deterministic
  key derivation from a seed env var in CI mode (`PARTNER_SEED=...`),
  random keys in dev.
- **Scope creep:** it is tempting to make the partner sim a fully
  symmetric clone of our issuer. Resist — the partner is a *fixture*,
  not a product. Only the routes listed above.

## Open questions

- TLS terminator vs. resolver HTTP exception: this doc recommends
  running the partner sim behind a TLS terminator (Ingress / nginx
  sidecar) and trusting its self-signed CA in CI. The alternative is
  to add an opt-in `DID_WEB_ALLOW_HTTP_FOR_HOSTS` allow-list to
  `did-resolver.ts` so `did:web:localhost%3A4001` resolves over
  plain HTTP for local/CI runs only. The TLS path is more faithful
  to production but heavier; the HTTP-exception path is simpler but
  introduces a new branch in security-critical code. Pick before
  implementation begins.
- Does the gateway need to support partner DIDs being *added* at
  runtime (admin API), or is a config-file restart acceptable for
  Sprint 4? Recommend config-file (simpler; matches current pattern
  where issuer DIDs are env-configured).
