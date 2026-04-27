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
- [ ] **Key rotation procedure** documented and tested at least once in staging.
- [ ] `ISSUER_DID` set to the production DID (`did:web:<your-domain>`).
- [ ] `/.well-known/did.json` is publicly served from `<your-domain>` so other
      parties can resolve your DID.

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
- [ ] `ENABLE_CRYPTOGRAPHIC_AUDIT=true` AND a real `evidenceSigner` is
      configured before audit signatures are required for compliance.
      Until then the logs are unsigned.
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
      cross-region failover for the issuer.
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
