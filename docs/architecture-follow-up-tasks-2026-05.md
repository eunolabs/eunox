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

2. **Add a durable API-key store for the minter**
   - Replace the current in-memory-only API-key store with a durable backend.
   - Ensure key creation, revocation, lookup, and policy fan-out survive restarts
     and rolling deploys.
   - Dependencies: Task 1.

3. **Make mint audit guarantees explicit and enforceable**
   - Decide whether mint audit writes are required before returning success.
   - If audit is mandatory, move from fire-and-forget to acknowledged persistence;
     if best-effort is acceptable, document the loss model and alert on failures.
   - Dependencies: Task 1.

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

5. **Tighten gateway and issuer egress boundaries**
   - Remove broad production egress to `0.0.0.0/0` and `::/0`.
   - Restrict outbound traffic to explicit backends, private endpoints, or an
     egress gateway.
   - Dependencies: Task 4 for managed Redis/private endpoint targeting.

---

## P1 — Structural fixes for scalability and operational safety

6. **Move admin control surfaces to identity-based access**
   - Replace shared admin keys with operator identity, scoped authorization, and
     attributable audit events.
   - Keep current shared-secret auth only as an explicitly temporary fallback.
   - Dependencies: Task 1.

7. **Add workload placement controls for HA services**
   - Add topology spread constraints and anti-affinity for gateway and issuer
     pods so replica count translates into real failure-domain redundancy.
   - Dependencies: Task 4.

8. **Improve audit query storage for scale**
   - Add indexed relational access paths for tenant, decision, token ID, denial
     code, and time-window queries.
   - Avoid relying on unindexed `payload->>` predicates for growing audit tables.
   - Dependencies: None.

---

## P2 — Longer-horizon maintainability and architecture simplification

9. **Separate immutable evidence storage from query storage**
   - Keep the cryptographic ledger focused on integrity and append semantics.
   - Serve tenant/operator queries from a query-optimized store or projection.
   - Dependencies: Task 8.

10. **Align issuer and minter bootstrap patterns with the gateway**
    - Move remaining large bootstraps toward typed config loading and explicit
      composition boundaries.
    - Reduce environment parsing drift and production/dev behavior mismatches.
    - Dependencies: Task 1.

---

## Suggested execution order

1. Tasks 1, 4
2. Tasks 2, 3, 5
3. Tasks 6, 7, 8
4. Tasks 9, 10
