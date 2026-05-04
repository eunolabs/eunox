# Production Deployment Checklist

This checklist consolidates the operational requirements for deploying Euno to
production.  Work top-to-bottom; everything in **Required** must be completed
before the system handles real agent traffic.  The **Recommended** and
**Optional** sections improve resilience, observability, or developer ergonomics
but do not block go-live.

For deeper background see:

- [`DEPLOYMENT.md`](./DEPLOYMENT.md) – step-by-step Azure deployment
- [`DISTRIBUTED_REVOCATION.md`](./DISTRIBUTED_REVOCATION.md) – Redis architecture
- [`INCIDENT_RESPONSE_RUNBOOK.md`](./INCIDENT_RESPONSE_RUNBOOK.md) – on-call procedures
- [`PILOT_PLAYBOOK.md`](./PILOT_PLAYBOOK.md) – pilot rollout guidance

---

## 1. Required (must be complete before go-live)

### 1.1 Identity & Signing

- [ ] **Signing key in a managed KMS** (Azure Key Vault, AWS KMS, or GCP Cloud KMS).
      Never use a private key on local disk in production.
- [ ] Signing-key permissions follow least privilege:
      - Capability Issuer service principal: `sign` only (no export, no delete)
      - Operators: `rotate` via change-management process
- [ ] **Key rotation procedure** documented and tested at least once in staging
      (see runbook below).
- [ ] `ISSUER_DID` set to the production DID (`did:web:<your-domain>`).
- [ ] `/.well-known/did.json` is publicly served from `<your-domain>` so other
      parties can resolve your DID.
- [ ] **`ISSUER_JWKS_URL`** set on every gateway instance to the issuer's JWKS
      endpoint (e.g. `https://issuer.example.com/.well-known/jwks.json`).
      The gateway pre-warms the JWKS cache on startup; if this URL is
      unreachable the gateway will refuse to start (fail-closed).
- [ ] **`EUNO_JWKS_CACHE_TTL_SECONDS`** tuned to balance JWKS refresh
      frequency and cache stability (default: `300` = 5 min).  Note: the
      current issuer publishes only the active signing key in JWKS, so TTL
      controls how quickly gateways stop trusting the previous key after a
      signer rotation.
- [ ] **`EUNO_REQUIRE_KID=true`** (default) on all gateways once all tokens
      include a `kid`.  Leave as `false` only during a rolling-deploy
      transition window.

#### Key-rotation runbook (current behavior: single active JWKS key)

1. **Plan the rotation window** — the issuer currently publishes only the
   active signer in `GET /.well-known/jwks.json`; it does **not** publish
   old and new keys simultaneously.  After gateways refresh their JWKS cache,
   tokens signed by the previous key will no longer verify.
2. **Wait for old tokens to drain** — before switching the signer, ensure
   the maximum lifetime of tokens signed with the current key has elapsed
   (default token TTL is 15 min), or perform the change during a coordinated
   maintenance window where temporary authentication failures are acceptable.
3. **Switch active signer** — change `SIGNING_PROVIDER`/`AZURE_KEYVAULT_KEY_VERSION`
   (or equivalent KMS pointer) on the issuer so new tokens are signed
   with the new key.  Confirm `GET /.well-known/jwks.json` now returns the
   new active key.
4. **Wait one JWKS cache TTL** (default 5 min) — every gateway replica
   will have refreshed its cache and now trusts only the new key.
5. **Verify** — check gateway logs for any `INVALID_TOKEN` errors with
   `kid=<old-kid>`.  If errors appear after the TTL expires, some clients
   are still presenting tokens signed by the retired key.
6. **Note the limitation** — until the issuer supports publishing overlapping
   keys in JWKS, this procedure cannot guarantee zero-downtime for in-flight
   tokens.  Future work: add a "previous key" retention window to the issuer
   so old and new keys are published simultaneously during rotation.

### 1.2 Tool Gateway – Origin & Transport Security

- [ ] **`ALLOWED_ORIGINS`** set to the exact comma-separated list of front-end
      origins that are permitted to call the gateway from a browser.  When
      `NODE_ENV=production` and this variable is unset the gateway disables
      CORS entirely (fail-safe), which will break browser clients.
- [ ] All public ingress is TLS-terminated (LB / ingress controller / API
      gateway).  No plaintext `http://` listeners.
- [ ] HSTS is enabled on the public hostname.
- [ ] `helmet()` defaults are not weakened in custom middleware.

### 1.3 Tool Gateway – Rate Limiting

- [ ] **`RATE_LIMIT_WINDOW_MS`** and **`RATE_LIMIT_MAX_REQUESTS`** set
      based on observed / forecast traffic.  Suggested starting points
      (per gateway instance):

      | Workload                    | window  | max  |
      | --------------------------- | ------- | ---- |
      | Internal back-office        | 60000ms | 300  |
      | Public-facing API           | 60000ms | 120  |
      | Bursty agent traffic        | 60000ms | 2000 |

- [ ] Per-tenant or per-key rate limiting is added in front of the gateway
      (e.g. Azure API Management, AWS WAF) when serving multiple tenants.

### 1.3.1 Capability Issuer – Per-subject Issuance Rate Limit (F-1)

> Defends against a compromised account flooding the issuer to mint
> tokens, attenuate to defeat per-token revocation, or renew to extend
> lifetime indefinitely. Covers `/api/v1/issue`, `/api/v1/attenuate`,
> and `/api/v1/renew` from a single shared bucket per
> `(tenantId, userId, agentId)`.

- [ ] **`ISSUANCE_RATE_LIMIT_ENABLED=true`** in production. This is the
      default in `IssuerConfigSchema`, so this checkbox is satisfied as
      long as the variable is not explicitly overridden to `false`. The
      only legitimate reason to disable is local development; in
      production it is the primary defence against a compromised
      user/agent flooding `/api/v1/issue`.
- [ ] **`ISSUANCE_RATE_LIMIT_MAX`** and
      **`ISSUANCE_RATE_LIMIT_WINDOW_SECONDS`** tuned for your
      workload. A typical starting point for a single agent is
      `MAX=30, WINDOW=60` (30 mints/minute/subject); tune up for
      heavy chained-attenuation pipelines.
- [ ] **`REDIS_URL`** set on every issuer replica when running more
      than one replica or more than one region — without it each
      replica gets its own private bucket and the budget is
      effectively multiplied by the replica count.
- [ ] **`ISSUANCE_RATE_LIMIT_FAIL_CLOSED=true`** (the default) unless
      you have an explicit operational reason to fail open during a
      Redis outage. Failing open accepts that the F-1 protection is
      bypassed for the duration of the incident.
- [ ] Dashboards alert on a non-zero rate of
      `euno_issuer_issuance_rate_limit_denied_total`. The metric is
      labelled by `tenant` and `reason` (`issuance_rate_limit_exceeded`
      vs `issuance_rate_limiter_unavailable`) so spikes can be
      attributed quickly.
- [ ] Clients on the agent runtime / SDK honour the `Retry-After`
      header on the resulting `429` (RFC 9110 §10.2.3) — verify by
      forcing a denial in staging and observing exponential-style
      back-off rather than a tight retry loop.

### 1.3.2 Multi-region Active/Active (F-7)

> Only required if you run capability-issuer or tool-gateway replicas
> in more than one region. Single-region deployments may skip this
> section. Read [`MULTI_REGION_ISSUER.md`](./MULTI_REGION_ISSUER.md)
> first — it documents the topology, replication contract, RTO/RPO
> targets, and quarterly drill checklist.

- [ ] **`ISSUER_REGION`** set on every issuer replica to a short,
      stable region tag (e.g. `eastus2`, `westeurope`).
- [ ] **`GATEWAY_REGION`** set on every gateway replica — use the
      same tag as the co-located issuer.
- [ ] **Globally-replicated Redis** in front of every region (Redis
      Enterprise Active-Active CRDB, Azure Cache for Redis
      Geo-replication, ElastiCache Global Datastore, or Memorystore
      active-active). Without this you are running active/passive,
      not active/active — see the doc.
- [ ] **F-1 Redis budget verified to be shared** by triggering a
      denial in one region and confirming the next attempt from a
      different region also denies (drill step 2.4).
- [ ] **JWKS strategy chosen** (shared key vs per-region keys, see
      doc § 4) and documented in your runbook.
- [ ] **Audit pipeline filter on `region`** added to your SIEM so
      regional failovers can be reconstructed from the audit
      timeline.
- [ ] **Quarterly failover drill scheduled** following the checklist
      in `MULTI_REGION_ISSUER.md` § 7.

### 1.4 Tool Gateway – Distributed Revocation

> Required whenever the gateway runs with **more than one replica**.  In a
> single-replica deployment the in-process store is acceptable but losing
> revocations on restart is a known risk.

- [ ] Redis instance provisioned (`Standard` or higher in Azure Cache /
      ElastiCache; never `Basic` for production).
- [ ] **`REDIS_URL`** set on every gateway instance to the shared endpoint.
- [ ] Network policy: only gateway pods can reach Redis.
- [ ] Redis AUTH (or managed-identity equivalent) enabled; credentials stored
      in the platform secrets manager.
- [ ] **Fail mode** chosen:
      - Default (`REVOCATION_FAIL_OPEN=false`) – fail-closed: a partitioned
        gateway treats every token as revoked.  Safer; recommended.
      - Set `REVOCATION_FAIL_OPEN=true` only when availability of the
        capability flow strictly outweighs revocation freshness.
- [ ] Test: revoke a token via `POST /admin/revoke` on instance A, then call
      `/api/v1/validate` on instance B – the token must be rejected.

### 1.5 Admin Surface

- [ ] **`ADMIN_API_KEY`** set to a cryptographically random value (≥ 32 bytes
      base64) on every gateway instance.  Without it `/admin/*` is publicly
      callable.
- [ ] Admin endpoints are not exposed on the public internet (separate
      ingress / network policy / VPN-only).
- [ ] Kill-switch test executed: activate global kill, confirm all traffic
      returns 503/403, deactivate, confirm traffic resumes.

### 1.6 Audit & Observability

- [ ] Structured logs shipped to a log aggregator (Azure Monitor, ELK,
      Datadog, etc.) – ensure JSON output is preserved.
- [ ] `ENABLE_CRYPTOGRAPHIC_AUDIT=true` AND a real evidence signer is
      configured. The gateway now refuses to start when audit signing is
      enabled but no signer is available — provide either
      `EVIDENCE_SIGNING_KEY_PEM` (inline PEM) or `EVIDENCE_SIGNING_KEY_FILE`
      (path to a PEM-encoded private key), with optional
      `EVIDENCE_SIGNING_ALGORITHM` (default `RS256`) and
      `EVIDENCE_SIGNING_KEY_ID`. KMS-backed signers may be supplied
      programmatically by importing the `EnforcementEngine` and passing a
      custom `evidenceSigner`.
- [ ] Audit logs verified to carry the tamper-evident `auditChain` field
      (`seq`, `prevHash`, `hash`). For cross-replica continuity, seed the
      previous run's terminal hash via
      `EUNO_AUDIT_CHAIN_SEED_<SERVICE_NAME>`.
- [ ] Metrics scraped: request rate, p50/p95/p99 latency per route, 4xx/5xx
      rate, active kill-switches, revocations per minute, Redis errors.
- [ ] Alerts wired:
      - 5xx rate > 1% over 5 min
      - Redis connection errors > 0
      - Public-key fetch failures from gateway
      - Sustained 401/403 spike from a single agent (possible compromise)

### 1.7 Configuration & Secrets

- [ ] No secrets baked into container images.
- [ ] Production `.env` derived from `.env.example`, with secret values
      injected from the platform secret store at runtime.
- [ ] `NODE_ENV=production` set on every replica.
- [ ] `POLICY_VERSION` reflects the deployed policy bundle.

### 1.8 Container & Cluster Hardening

- [ ] Containers run as non-root with read-only root filesystem.
- [ ] Resource requests/limits set on every pod.
- [ ] Liveness / readiness probes pointed at `/health`.
- [ ] PodDisruptionBudget so rolling updates never reduce capacity below
      `minAvailable=1` (issuer) / `minAvailable=2` (gateway).
- [ ] HorizontalPodAutoscaler configured for the gateway based on CPU and/or
      request rate.

---

## 2. Recommended (do these soon after go-live)

- [ ] **Distributed Redis** (cluster or sentinel) instead of single instance
      for HA.  Architecture in [`DISTRIBUTED_REVOCATION.md`](./DISTRIBUTED_REVOCATION.md).
- [ ] **Capacity test** the gateway at the chosen rate-limit ceilings to
      verify the tuned values produce acceptable p99 latency.
- [ ] **DR plan** documented: KMS key backup/recovery, Redis snapshot policy,
      cross-region failover for the issuer (see
      [`MULTI_REGION_ISSUER.md`](./MULTI_REGION_ISSUER.md) for the
      active/active path).
- [ ] **Quarterly key rotation** scheduled and dry-run executed.
- [ ] **Penetration test** focused on capability bypass, replay, and
      revocation-window attacks.
- [ ] **OpenAPI specs** ([`docs/openapi/`](./openapi/)) published to internal
      developer portal so client teams can self-serve.

---

## 3. Optional (nice-to-have)

- [ ] Custom `ION_RESOLVER_URL` pointing at a self-hosted ION node when using
      `did:ion`-anchored issuers (avoids dependency on the public Microsoft
      resolver).
- [ ] Pre-warm the public-key cache in the gateway by hitting `/api/v1/public-key`
      before opening traffic.
- [ ] Add per-endpoint dashboards in your APM tool (issue, attenuate, renew,
      validate, tools/invoke).
- [ ] Generate SDK clients from the OpenAPI specs (`docs/openapi/`) for the
      languages your agent runtimes use.
- [ ] Wire `/admin/revoke` to your IDP de-provisioning flow so revoking a user
      automatically revokes their outstanding agent tokens.

---

## 4. Pre-launch sign-off

| Area                            | Owner | Date | Sign-off |
| ------------------------------- | ----- | ---- | -------- |
| Identity & signing keys         |       |      |          |
| CORS / TLS                      |       |      |          |
| Rate limiting                   |       |      |          |
| Distributed revocation (Redis)  |       |      |          |
| Admin surface protection        |       |      |          |
| Logs, metrics, alerts           |       |      |          |
| Container / cluster hardening   |       |      |          |
| Incident response runbook read  |       |      |          |
| Kill-switch drill executed      |       |      |          |
