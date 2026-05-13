# Architecture Follow-up Tasks — May 2026

Follow-up task list for the latest platform architecture review. Tasks are numbered
in execution order and grouped by priority and dependency.

Related review: [architecture-review-2026-05.md](./architecture-review-2026-05.md)

---

## P0 — Must complete before production hardening is considered done

1. **Fail closed on unsafe API-key minter production configuration** ✅ DONE
   - Block production startup when the minter would use `dev-admin-key`,
     ephemeral pepper material, ephemeral signing keys, in-memory audit storage,
     or in-memory API-key storage.
   - This closes the highest-risk fallback paths in the hosted control plane.
   - Dependencies: None.
   - **Fix:** `validateProductionMinterConfig` in
     `euno-platform/packages/api-key-minter/src/production-guard.ts` (exported
     for testing). Called at the top of `main()` in `bootstrap.ts`. Fails with a
     single, multi-item error message listing every violation so operators can
     fix all issues in one restart cycle. Checks: `MINTER_ADMIN_API_KEY`,
     `MINTER_PEPPER_HEX`, signing key (KMS or PEM), `MINTER_AUDIT_DB_URL`,
     `MINTER_API_KEY_DB_URL` (gate for Task 2), and Redis HA for any configured
     minter Redis URL. 24 new tests in `tests/bootstrap.test.ts`.
     Docs: `docs/DEPLOYMENT.md §"Minter production configuration"`.

2. **Add a durable API-key store for the minter** ✅ DONE
   - Replace the current in-memory-only API-key store with a durable backend.
   - Ensure key creation, revocation, lookup, and policy fan-out survive restarts
     and rolling deploys.
   - Dependencies: Task 1.
   - **Fix:** `PostgresApiKeyStore` in
     `euno-platform/packages/api-key-minter/src/postgres-api-key-store.ts`
     (exported for testing). Implements all `ApiKeyStore` methods against a
     `api_keys` Postgres table (`BIGINT GENERATED ALWAYS AS IDENTITY` PK, JSONB
     capabilities, `TEXT[]` scopes, optional `revoked_at` / `expires_at` /
     `last_used_at`).  Schema managed via `ensureSchema()` (idempotent DDL) or an
     external migration tool.  Bootstrap selects `PostgresApiKeyStore` when
     `MINTER_API_KEY_DB_URL` is set; falls back to `InMemoryApiKeyStore` in dev.
     `API_KEY_DDL` exported for external migration tools.
     37 new tests in `tests/postgres-api-key-store.test.ts`.
     Docs: `docs/DEPLOYMENT.md §"Durable API-key store"`.

3. **Make mint audit guarantees explicit and enforceable** ✅ DONE
   - Decide whether mint audit writes are required before returning success.
   - If audit is mandatory, move from fire-and-forget to acknowledged persistence;
     if best-effort is acceptable, document the loss model and alert on failures.
   - Dependencies: Task 1.
   - **Fix:** Audit write in `euno-platform/packages/api-key-minter/src/routes/mint.ts`
     changed from fire-and-forget (`void …catch`) to `await`ed with explicit
     failure handling. A failed audit write returns **503 Service Unavailable**
     (token not returned) and increments the new
     `euno_minter_audit_failure_total{stage="write"}` counter.
     A local `MintAuditError` sentinel class allows `classifyErrorResult` to label
     the `euno_minter_mint_total` counter with `result="audit_failure"` for
     per-tenant dashboards.  New metric exported from `metrics.ts` and `index.ts`.
     5 new tests in `tests/mint-route.test.ts`.
     Docs: `docs/DEPLOYMENT.md §"Mint audit guarantees"` including alert rule
     template.

4. **Replace single-node Redis assumptions in production** ✅ DONE
   - Make HA Redis mandatory for production deployments and keep the shipped
     single-node manifest clearly dev/pilot only.
   - Validate production configuration against Sentinel, Cluster, or managed
     equivalents.
   - Dependencies: None.
   - **Fix:** `checkProductionRedisHa` extracted as an exported function in
     `euno-platform/packages/tool-gateway/src/bootstrap.ts`. Changed from a
     non-fatal `logger.warn` to a fatal `throw Error` in production when any
     configured Redis URL (`REDIS_URL`, `REVOCATION_REDIS_URL`,
     `KILL_SWITCH_REDIS_URL`, `CALL_COUNTER_REDIS_URL`) matches a single-node
     pattern. The `k8s/redis.yaml` manifest retains its existing
     `euno.dev/dev-only: 'true'` label and the prominent DEV/PILOT-ONLY header.
     The minter's Redis HA check is covered by Task 1 (`validateProductionMinterConfig`).
     17 new tests added to `tests/self-host-config.test.ts`.
     Docs: `docs/DEPLOYMENT.md §"Redis HA for production"` updated to reflect
     the fatal behaviour.

5. **Tighten gateway and issuer egress boundaries** ✅ DONE
   - Remove broad production egress to `0.0.0.0/0` and `::/0`.
   - Restrict outbound traffic to explicit backends, private endpoints, or an
     egress gateway.
   - Dependencies: Task 4 for managed Redis/private endpoint targeting.
   - **Fix:** All `0.0.0.0/0` and `::/0` ipBlock entries removed from the egress
     sections of `gateway-network-policy` and `issuer-network-policy` in
     `k8s/network-policies.yaml`.  The base manifest now contains only
     in-cluster pod-selector rules; each removed broad rule is replaced with a
     commented-out placeholder showing the exact syntax operators need to fill
     in once their private endpoint CIDRs are known.  Broad-egress rules
     extracted into `k8s/network-policies-dev-overlay.yaml` (two
     separate NetworkPolicy objects labelled `euno.dev/dev-only: 'true'`) that
     may be applied in dev/staging clusters alongside the base manifest.
     `k8s/README.md` updated with egress hardening section and Kustomize/Helm
     integration guidance.
     Docs: `docs/DEPLOYMENT.md §"Egress network boundaries"`.

---

## P1 — Structural fixes for scalability and operational safety

6. **Move admin control surfaces to identity-based access** ✅ DONE
   - Replace shared admin keys with operator identity, scoped authorization, and
     attributable audit events.
   - Keep current shared-secret auth only as an explicitly temporary fallback.
   - Dependencies: Task 1.
   - **Fix:** New `AdminJwtVerifier` class in
     `euno-platform/packages/api-key-minter/src/admin-jwt-verifier.ts`
     (exported for testing).  Uses `jose.createRemoteJWKSet` + `jose.jwtVerify`
     to verify operator JWTs against a configurable JWKS endpoint.  Extracts
     `sub` as `operatorId`; optionally enforces a required scope from `scp`/`scope`
     claims.  Both `admin-keys.ts` and `admin-policies.ts` now attempt Bearer JWT
     verification first; the `X-Admin-Key` shared secret remains as an explicit
     temporary fallback that logs a deprecation warning on each use.  Operator
     identity is attached to all audit log entries (`operator` field).
     Bootstrap wires in the verifier via `createAdminJwtVerifierFromEnv()` when
     `MINTER_ADMIN_JWKS_URI` + `MINTER_ADMIN_JWT_AUDIENCE` are set; logs a clear
     warning when JWT auth is not configured.  `AdminJwtVerifier` and
     `createAdminJwtVerifierFromEnv` are exported from the package `index.ts`.
     15 new tests in `tests/admin-jwt-auth.test.ts` (322 total minter tests).

7. **Add workload placement controls for HA services** ✅ DONE
   - Add topology spread constraints and anti-affinity for gateway and issuer
     pods so replica count translates into real failure-domain redundancy.
   - Dependencies: Task 4.
   - **Fix:** `topologySpreadConstraints` (zone: `DoNotSchedule`, hostname:
     `ScheduleAnyway`) and `podAntiAffinity` (`requiredDuringScheduling` on
     `kubernetes.io/hostname`) added to:
     - `k8s/capability-issuer-deployment.yaml` (2 replicas)
     - `k8s/tool-gateway-deployment.yaml` (3 replicas, plain Deployment)
     - `k8s/tool-gateway.yaml` (3 shards, StatefulSet)
     The zone `DoNotSchedule` constraint prevents all replicas landing in a
     single AZ during rollout.  The hostname `requiredDuringScheduling`
     anti-affinity ensures no two gateway shards share a node, preventing
     a single node failure from halving gateway capacity.
     `k8s/README.md` updated with workload-placement-controls section documenting
     node count and AZ requirements.

8. **Improve audit query storage for scale** ✅ DONE
   - Add indexed relational access paths for tenant, decision, token ID, denial
     code, and time-window queries.
   - Avoid relying on unindexed `payload->>` predicates for growing audit tables.
   - Dependencies: None.
   - **Fix:** `PostgresLedgerBackend.migrate()` and
     `PerReplicaPostgresLedgerBackend.migrate()` in
     `euno-platform/packages/common-infra/src/ledger-signer.ts` now emit five
     additional `CREATE INDEX IF NOT EXISTS` statements covering
     `(payload->>'tenantId')`, `(payload->>'decision')`,
     `(payload->>'capabilityId')`, `(payload->>'agentId')`, and
     `(payload->>'denialCode')` — the five JSONB fields queried by
     `queryEntries()` filter predicates.  Indexes are expression indexes so
     PostgreSQL can use them for equality predicates without a full-table JSONB
     scan.  Schema docstrings in `ledger-signer.ts` updated.
     9 new tests in `euno-platform/packages/common/tests/ledger-signer.test.ts`
     covering both backends (868 total common tests).

---

## P2 — Longer-horizon maintainability and architecture simplification

9. **Separate immutable evidence storage from query storage** ✅ DONE
   - Keep the cryptographic ledger focused on integrity and append semantics.
   - Serve tenant/operator queries from a query-optimized store or projection.
   - Dependencies: Task 8.
   - **Fix:** Added `AuditQueryStore` interface and `PostgresAuditQueryStore` class to
     `euno-platform/packages/common-infra/src/ledger-signer.ts`. The interface isolates the
     SELECT-only read path from `LedgerBackend` (which owns chain state, advisory locks,
     and HMAC material). `PostgresAuditQueryStore` is a thin, transaction-free wrapper that
     issues a single `SELECT … WHERE … ORDER BY seq … LIMIT` query per call — no advisory
     locks, no HMAC secrets required. Updated `routes/audit.ts` to accept `AuditQueryStore`
     instead of `LedgerBackend`, updated `AuditModuleResult` and `buildAuditModule` to
     produce a `PostgresAuditQueryStore` for `postgres` and `per-replica-postgres` backends
     (backed by the same pool as the write backend — no extra connections), and updated
     `app-factory.ts` with backward-compat fallback to `auditLedgerBackend`. 16 new tests in
     `euno-platform/packages/common/tests/ledger-signer.test.ts`.

10. **Align issuer and minter bootstrap patterns with the gateway** ✅ DONE
    - Move remaining large bootstraps toward typed config loading and explicit
      composition boundaries.
    - Reduce environment parsing drift and production/dev behavior mismatches.
    - Dependencies: Task 1.
    - **Fix:** Added `MinterConfigSchema` and `MinterConfig` to
      `public/packages/common/src/config/schema.ts`. Registered `'minter'` in
      `EUNO_SERVICE_NAMES`, `EUNO_CONFIG_SCHEMAS`, `EunoConfigFor`, and `EunoConfig`.
      Added `'minter'` header to `SERVICE_HEADERS` in `dump-template.ts`.
      Updated minter `bootstrap.ts` to call `loadConfigOrExit(process.env, 'minter')`
      at startup and access all env vars through the typed `MinterConfig` object — eliminating
      all ad-hoc `parseInt`/`process.env[...]` reads with inline validation.
      `MinterConfigSchema.superRefine` validates the same production constraints as
      `validateProductionMinterConfig` (ADMIN_API_KEY, PEPPER_HEX, signing key, both DB URLs)
      so misconfiguration is caught by both the Zod loader and the existing production guard.
      25 new tests in `tests/config.test.ts` (common package): 22 schema/validation tests
      and 3 dumpEnvTemplate tests.

---

## Suggested execution order

1. Tasks 1, 4
2. Tasks 2, 3, 5
3. Tasks 6, 7, 8 ✅ DONE
4. Tasks 9, 10 ✅ DONE
