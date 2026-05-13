# Architecture Follow-up Tasks v2 — May 2026

Copilot-ready task list for the second-round platform architecture review.
Each task contains the full context needed to implement and test the change without
looking elsewhere.

Related review: [architecture-review-2026-05-v2.md](./architecture-review-2026-05-v2.md)
Prior task list: [architecture-follow-up-tasks-2026-05.md](./architecture-follow-up-tasks-2026-05.md)

---

## P0 — Must complete before Stage 3 ships to paying customers

### Task 11 — Wire fleet-wide Redis rate limiter for the primary `/mint` route

**Review item:** CR-NEW-1
**Dependencies:** None (all supporting classes already exist)

#### Background

CI-5 (prior review) added `RedisBackedMintRateLimiter` and
`createPingRateLimiterFromEnv` for the ping endpoint. The primary `/mint` endpoint
still uses `InMemoryMintRateLimiter`. In a multi-replica minter, an attacker can
distribute requests across N pods and achieve N × `MINTER_RATE_LIMIT_MAX` mints per
window fleet-wide.

#### Existing code to understand

- `euno-platform/packages/api-key-minter/src/mint-rate-limiter.ts`
  — `MintRateLimiter` interface, `InMemoryMintRateLimiter`, `RedisBackedMintRateLimiter`,
    `createPingRateLimiterFromEnv` (the pattern to replicate).
- `euno-platform/packages/api-key-minter/src/bootstrap.ts` line 182
  — hardcoded `new InMemoryMintRateLimiter(...)` that must be replaced.
- `euno-platform/packages/api-key-minter/src/routes/mint.ts`
  — `MintRouterOptions.rateLimiter` injection point; no change needed here.

#### What to implement

1. **Add `createMintRateLimiterFromEnv` factory** in
   `mint-rate-limiter.ts` (alongside `createPingRateLimiterFromEnv`).
   - Accept `env: NodeJS.ProcessEnv` and `logger: Logger` (same signature).
   - Check `env['MINTER_MINT_REDIS_URL'] ?? env['REDIS_URL']`. If present, construct a
     `RedisBackedMintRateLimiter` with `keyPrefix: 'mintrl:mint:'`,
     `maxMintsPerWindow` from `env['MINTER_RATE_LIMIT_MAX']` (parse as integer,
     default 100), and `windowSeconds` from
     `env['MINTER_RATE_LIMIT_WINDOW_SECONDS']` (default 60).
   - If Redis URL is absent, construct `InMemoryMintRateLimiter` with the same
     defaults and emit `logger.warn('No Redis URL configured for mint rate limiter; using in-memory (per-replica only). Set MINTER_MINT_REDIS_URL or REDIS_URL for fleet-wide limiting.')`.
   - Return the constructed `MintRateLimiter`.

2. **Update `bootstrap.ts`** to call `await createMintRateLimiterFromEnv(process.env, logger)`
   instead of `new InMemoryMintRateLimiter(...)`. The `await` is needed because the
   factory may open a Redis connection (same pattern as `createPingRateLimiterFromEnv`).

3. **Update configuration validation and operator-facing docs** for the new dedicated
   mint Redis URL:
   - Extend `validateProductionMinterConfig` so production/HA checks cover
     `MINTER_MINT_REDIS_URL` the same way other dedicated Redis URLs are handled.
   - Add `MINTER_MINT_REDIS_URL` to `docs/DEPLOYMENT.md` with its fallback to
     `REDIS_URL` and when to use it.
   - Add `MINTER_MINT_REDIS_URL` to the minter env template/example so the setting
     is discoverable.

4. **Add tests** in `euno-platform/packages/api-key-minter/tests/` (new file
   `mint-rate-limiter.test.ts` or extend the existing one if it exists):
   - `createMintRateLimiterFromEnv` returns `RedisBackedMintRateLimiter` when
     `MINTER_MINT_REDIS_URL` is set.
   - Returns `InMemoryMintRateLimiter` and logs a warn when no Redis URL is present.
   - Verify the returned instance is wired into `MintRouterOptions.rateLimiter` in
     the bootstrap (integration-level test via the existing bootstrap test pattern).
   - Add/adjust validation coverage so production config checks fail loudly for an
     invalid dedicated mint Redis URL configuration.

#### Acceptance criteria

- `MINTER_MINT_REDIS_URL` set → `RedisBackedMintRateLimiter` used for `/mint`.
- `REDIS_URL` set (no specific mint URL) → same Redis instance shared with anomaly detector.
- Neither set → `InMemoryMintRateLimiter` with structured warn.
- All existing minter tests continue to pass.

---

### Task 12 — Close Postgres connection pools on minter graceful shutdown

**Review item:** CR-NEW-2
**Dependencies:** None

#### Background

The minter shutdown handler in `bootstrap.ts` closes the Redis anomaly detector
(`void anomalyDetector.close()`) but never calls `.end()` on the `pg.Pool` instances
for the audit store (`auditPool`) and the API-key store (`keyPool`). Under a rolling
deploy, dangling connections exhaust the Postgres connection limit, causing audit
writes to fail with 503 on the new pods.

#### Existing code to understand

- `euno-platform/packages/api-key-minter/src/bootstrap.ts`
  - Lines 109–143: `auditPool` created as `new pgModule.Pool(...)`, assigned to
    `pool` locally. Reference is not hoisted above the `shutdown` closure.
  - Lines 150–180: `keyPool` created as `new pgKeyModule.Pool(...)`, assigned to
    `keyPool` locally. Same scoping issue.
  - Lines 242–251: `shutdown` closure — only closes anomaly detector + HTTP server.

#### What to implement

1. **Hoist pool references** to the outer `main()` scope so `shutdown` can access them:
   ```ts
   let auditPool: import('pg').Pool | undefined;
   let keyPool: import('pg').Pool | undefined;
   ```
   Assign `auditPool = pool` (inside the `if (auditDbUrl)` block) and
   `keyPool = pgKeyStore.pool ?? pool` (inside the `if (apiKeyDbUrl)` block). The
   `PostgresMintAuditStore` and `PostgresApiKeyStore` constructors accept a pool and
   expose it — check their constructors; if the pool is not exposed as a public
   property, add a `readonly pool` accessor.

2. **Update `shutdown`**:
   ```ts
   const shutdown = (): void => {
     logger.info('Shutting down minter');
     if (anomalyDetector instanceof RedisAnomalyDetector) {
       void anomalyDetector.close();
     }
     // Close Postgres pools before exit so connections are FIN'd cleanly.
     const poolClosePromises: Promise<void>[] = [];
     if (auditPool) poolClosePromises.push(auditPool.end().catch(() => {}));
     if (keyPool) poolClosePromises.push(keyPool.end().catch(() => {}));
     void Promise.all(poolClosePromises).then(() => {
       server.close(() => process.exit(0));
     });
   };
   ```

3. **Add tests** in `euno-platform/packages/api-key-minter/tests/bootstrap.test.ts`:
   - Mock `pg.Pool` so its `.end()` is a jest spy.
   - Trigger the `shutdown` handler (emit `'SIGTERM'` on `process`).
   - Assert `.end()` was called on both pools when `MINTER_AUDIT_DB_URL` and
     `MINTER_API_KEY_DB_URL` are set.
   - Assert `.end()` is not called when both URLs are absent (in-memory mode).

#### Acceptance criteria

- SIGTERM triggers pool `.end()` before `server.close()`.
- Pool `.end()` errors are swallowed (non-fatal) so shutdown always completes.
- Existing tests pass.

---

### Task 13 — Mandate unique `gatewayAudience` per tenant in hosted mode

**Review item:** CR-NEW-3
**Dependencies:** None

#### Background

`EnforcementEngine` defaults `gatewayAudience` to the literal `"tool-gateway"`. In a
hosted multi-tenant gateway, a token minted for tenant A with `aud: "tool-gateway"`
passes audience validation for tenant B. The `jti` revocation list prevents exact
replay, but a valid unexpired token is accepted at any tenant's resource path.

#### Existing code to understand

- `euno-platform/packages/tool-gateway/src/enforcement.ts` line 302:
  `this.gatewayAudience = options.gatewayAudience ?? 'tool-gateway';`
- `public/packages/common/src/config/schema.ts` — `GatewayConfigSchema`; look for
  `GATEWAY_AUDIENCE`. It is already a config key; verify the field and its default.
- `euno-platform/packages/tool-gateway/src/bootstrap.ts` — `initializeServices`;
  check how `gatewayAudience` is plumbed from config into `EnforcementEngine`.

#### What to implement

1. **Add `HOSTED_MODE` to `GatewayConfigSchema`** in `public/packages/common/src/config/schema.ts`:
   ```ts
   HOSTED_MODE: z.enum(['true', 'false']).optional(),
   ```
   Add a `superRefine` rule (within `GatewayConfigSchema`): when
   `HOSTED_MODE === 'true'` and `GATEWAY_AUDIENCE` equals `"tool-gateway"` (the
   default), emit a Zod issue:
   > `"HOSTED_MODE=true requires GATEWAY_AUDIENCE to be a tenant-scoped value (e.g. 'tool-gateway:acme-corp-prod'). The default 'tool-gateway' allows cross-tenant token replay."`

2. **Update `docs/DEPLOYMENT.md`** in the "Hosted mode" section (or add one) to
   document that `GATEWAY_AUDIENCE` must be unique per tenant, recommend the format
   `"tool-gateway:<tenant-slug>"`, and explain the cross-tenant replay risk.

3. **Add tests** in `euno-platform/packages/common/tests/config.test.ts`:
   - `HOSTED_MODE=true` + `GATEWAY_AUDIENCE=tool-gateway` → validation error.
   - `HOSTED_MODE=true` + `GATEWAY_AUDIENCE=tool-gateway:acme` → valid.
   - `HOSTED_MODE=false` + `GATEWAY_AUDIENCE=tool-gateway` → valid (no enforcement).
   - `HOSTED_MODE` absent + `GATEWAY_AUDIENCE=tool-gateway` → valid.

#### Acceptance criteria

- Schema rejects the default audience when `HOSTED_MODE=true`.
- Deployment docs explain the risk and the required config.
- All existing config tests pass.

---

## P1 — Structural fixes for correctness and operational safety

### Task 14 — Strip unknown context fields in `parseEnforceRequestBody`

**Review item:** CR-NEW-4
**Dependencies:** None

#### Background

`parseEnforceRequestBody` in `enforce.ts` validates `context.sourceIp`,
`context.recipients`, and `context.now` by type but then returns the full raw object
via `b as unknown as EnforceRequest`. Unknown fields are forwarded into
`ConditionContext` and condition evaluation. A v2 client sending new context fields to
a v1 gateway receives no error, and the unknown data leaks into audit records.

#### Existing code to understand

- `euno-platform/packages/tool-gateway/src/routes/enforce.ts` lines 177–241:
  `parseEnforceRequestBody`. The `ctx` binding is a `Record<string, unknown>`.
- `ENFORCE_PROTOCOL_VERSION` is imported from `@euno/common`; `parseProtocolVersion`
  returns the numeric version from the request header (missing = v1).
- `EnforceRequest` wire type: `public/packages/common/src/wire.ts` — the `context`
  field shape.

#### What to implement

1. **After all individual field checks** (after the `ctx.now` check, line ~239), add:
   ```ts
   const KNOWN_CONTEXT_KEYS = new Set(['sourceIp', 'recipients', 'now']);
   const unknownKeys = Object.keys(ctx).filter(k => !KNOWN_CONTEXT_KEYS.has(k));
   if (unknownKeys.length > 0) {
     logger.debug('parseEnforceRequestBody: unknown context fields stripped', {
       unknownKeys,
       protocolVersion,
     });
     for (const k of unknownKeys) {
       delete (ctx as Record<string, unknown>)[k];
     }
   }
   ```
   Note: `parseEnforceRequestBody` currently takes no `logger` argument. Either:
   - Add an optional `logger?: Logger` parameter and update call sites in the route
     handler, **or**
   - Just delete without logging (the `debug` log is nice-to-have; stripping is the
     critical part).

2. **Add `protocolVersion` as a parameter** to `parseEnforceRequestBody` so the
   stripper can be version-aware in the future (pass the already-resolved value from
   the route handler).

3. **Add tests** in `euno-platform/packages/tool-gateway/tests/enforce.test.ts`:
   - POST with `context: { sourceIp: '1.2.3.4', unknownField: 'x' }` → 200 (allowed);
     response body does not contain `unknownField` in any audit shape.
   - POST with only known context fields → 200 (no regression).

#### Acceptance criteria

- Unknown context fields are stripped before reaching `enforceConditions`.
- No breaking change to existing protocol v1 clients.
- Existing enforce tests pass.

---

### Task 15 — Fix production guard to collect all Redis HA violations

**Review item:** DI-NEW-3
**Dependencies:** None

#### Background

`validateProductionMinterConfig` in `production-guard.ts` collects multiple
violations for non-Redis checks (admin key, pepper, signing key, etc.) into a
`violations[]` array. But the Redis HA loop uses `break` after the first failing URL,
so operators must restart multiple times to discover all single-node Redis URLs.

#### Existing code to understand

```ts
// euno-platform/packages/api-key-minter/src/production-guard.ts lines 138–153
for (const [varName, url] of redisVars) {
  if (url && !isHaRedisUrl(url)) {
    violations.push(`${varName} appears to point at a single-node Redis ...`);
    break; // ← REMOVE THIS
  }
}
```

#### What to implement

Remove the `break` statement from the Redis HA loop. Each single-node URL should
produce an independent violation message in `violations[]`.

Update the existing test in `euno-platform/packages/api-key-minter/tests/bootstrap.test.ts`
that asserts the message content, to verify that when both `REDIS_URL` *and*
`ANOMALY_REDIS_URL` are single-node, the error message lists both.

#### Acceptance criteria

- Two single-node Redis URLs → error lists both.
- Single single-node URL → error lists one (unchanged behaviour).
- Existing production guard tests pass.

---

### Task 16 — Enforce non-wildcard `adminHost` at gateway startup

**Review item:** DI-NEW-2
**Dependencies:** None

#### Background

`GatewayDependencies.adminHost` is documented as requiring a non-wildcard value in
production. The Zod schema checks it but there is no explicit startup assertion. If
an operator misconfigures `ADMIN_HOST=0.0.0.0` or omits it in production, the admin
API (kill-switch, revocation, partner-DID) is reachable on the public interface.

#### Existing code to understand

- `euno-platform/packages/tool-gateway/src/bootstrap.ts`
  - `checkProductionRedisHa` (lines 459–497) is the pattern to follow: an exported
    function called at the top of `initializeServices`, throws with a clear message
    in production only.
  - Search for `adminHost` in `initializeServices` to see where it is currently
    read from config.
- `public/packages/common/src/config/schema.ts` — `GatewayConfigSchema`;
  `ADMIN_HOST` field.

#### What to implement

1. **Add `checkProductionAdminHost`** exported function in
   `euno-platform/packages/tool-gateway/src/bootstrap.ts`:
   ```ts
   export function checkProductionAdminHost(
     env: { ADMIN_HOST?: string },
     environment: string,
   ): void {
     if (environment !== 'production') return;
     const host = env.ADMIN_HOST;
     const wildcards = [undefined, '', '0.0.0.0', '::', '::0'];
     if (wildcards.includes(host)) {
       throw new Error(
         'Gateway refused to start — ADMIN_HOST must be set to a non-wildcard ' +
         'address in production (e.g. 127.0.0.1 or the pod cluster IP). ' +
         'Binding the admin API to all interfaces exposes kill-switch and revocation ' +
         'endpoints to the public load balancer. ' +
         'See docs/DEPLOYMENT.md §"Admin API binding".',
       );
     }
   }
   ```

2. **Call `checkProductionAdminHost`** at the top of `initializeServices` alongside
   `checkProductionRedisHa`.

3. **Add tests** in `euno-platform/packages/tool-gateway/tests/self-host-config.test.ts`
   (same file as the Redis HA tests):
   - `NODE_ENV=production` + no `ADMIN_HOST` → throws.
   - `NODE_ENV=production` + `ADMIN_HOST=0.0.0.0` → throws.
   - `NODE_ENV=production` + `ADMIN_HOST=127.0.0.1` → no throw.
   - `NODE_ENV=development` + no `ADMIN_HOST` → no throw.

#### Acceptance criteria

- Production startup with wildcard `ADMIN_HOST` fails with a clear error.
- Existing self-host-config tests pass.

---

### Task 17 — Expose Postgres pool configuration on the minter

**Review item:** DI-NEW-5
**Dependencies:** None (can be done standalone)

#### Background

Both minter Postgres pools (`MintAuditPgPool` and `ApiKeyPgPool`) are created with
`new pgModule.Pool({ connectionString })`, using `pg`'s defaults: 10 max connections,
no `idleTimeoutMillis`, no `connectionTimeoutMillis`. Under sustained load a
saturated pool blocks mint handlers indefinitely. There is also no startup health
check; pool errors are only discovered on the first real request.

#### Existing code to understand

- `euno-platform/packages/api-key-minter/src/bootstrap.ts` lines 112–123 (audit
  pool) and 150–165 (key pool).
- `public/packages/common/src/config/schema.ts` — `MinterConfigSchema` — add three
  new fields here.
- `euno-platform/packages/api-key-minter/src/postgres-mint-audit-store.ts` and
  `euno-platform/packages/api-key-minter/src/postgres-api-key-store.ts` — check
  constructor signatures to see if the pool is already a public property.

#### What to implement

1. **Add to `MinterConfigSchema`** in `public/packages/common/src/config/schema.ts`:
   ```ts
   MINTER_AUDIT_POOL_SIZE: z.coerce.number().int().positive().optional(),
   MINTER_API_KEY_POOL_SIZE: z.coerce.number().int().positive().optional(),
   MINTER_PG_CONNECTION_TIMEOUT_MS: z.coerce.number().int().nonnegative().optional(),
   ```

2. **Update pool construction** in `bootstrap.ts` to pass these values:
   ```ts
   const pool = new pgModule.Pool({
     connectionString: auditDbUrl,
     max: config.MINTER_AUDIT_POOL_SIZE ?? 10,
     connectionTimeoutMillis: config.MINTER_PG_CONNECTION_TIMEOUT_MS ?? 5000,
     idleTimeoutMillis: 30_000,
   });
   ```
   Apply the same pattern to `keyPool`.

3. **Add a startup health check** after each pool is created:
   ```ts
   try {
     const client = await pool.connect();
     await client.query('SELECT 1');
     client.release();
     logger.info('Postgres audit pool health check passed');
   } catch (err) {
     throw new Error(`Minter failed to connect to audit DB: ${err instanceof Error ? err.message : err}`);
   }
   ```

4. **Add tests** verifying new config fields parse correctly and that an unreachable
   DB URL causes a startup error (mock `pg.Pool.connect` to throw).

#### Acceptance criteria

- `MINTER_AUDIT_POOL_SIZE=20` is respected.
- `MINTER_PG_CONNECTION_TIMEOUT_MS=3000` is respected.
- Startup fails fast when the DB is unreachable.
- Existing tests pass.

---

## P2 — Longer-horizon correctness and operational improvements

### Task 18 — Document and enforce SQLite posture-emitter single-writer constraint

**Review item:** DI-NEW-1
**Dependencies:** None

#### Background

`DurablePostureEmitter` uses SQLite as a WAL queue. The capability issuer runs as
`HPA 2..N` replicas. SQLite WAL mode requires filesystem-level locking that does not
work reliably across networked storage (NFS, Azure File). Multi-replica issuers
writing to a shared PVC SQLite file can corrupt data.

#### Existing code to understand

- `euno-platform/packages/capability-issuer/src/issuance/posture.ts` (or wherever
  `DurablePostureEmitter` is implemented) — check `POSTURE_DURABLE_QUEUE_PATH`.
- `k8s/capability-issuer-deployment.yaml` — PVC mount and replica count.
- `docs/ARCHITECTURE.md` §6 posture emitter section.
- `docs/DEPLOYMENT.md` — CI-6 fix section ("POSTURE_DURABLE_QUEUE_PATH").

#### What to implement

1. **Add a startup assertion** in the `DurablePostureEmitter` constructor or factory:
   When `NODE_ENV=production` and the replica count is > 1 (check
   `ISSUER_REPLICA_COUNT` env var or default to warning), emit a structured
   `logger.warn` explaining the single-writer constraint and directing operators to
   use a pod-local `ReadWriteOnce` PVC.

2. **Update `k8s/capability-issuer-deployment.yaml`** PVC spec comment:
   Add a prominent note that `POSTURE_DURABLE_QUEUE_PATH` must be on a
   `ReadWriteOnce` PVC (pod-local), not `ReadWriteMany`.

3. **Update `docs/DEPLOYMENT.md`** in the posture emitter section: add a
   "Multi-replica warning" callout explaining the SQLite single-writer constraint,
   the required PVC access mode, and the fact that each pod maintains an independent
   queue (delivery deduplication is the cloud surface's responsibility).

#### Acceptance criteria

- Docs clearly state the single-writer constraint.
- K8s manifest comments warn against shared PVC.
- Startup emits a warn when multi-replica configuration is detected in production.

---

### Task 19 — Document kill-switch staleness SLA and make interval configurable

**Review item:** DI-NEW-4
**Dependencies:** None

#### Background

`KILL_SWITCH_REFRESH_INTERVAL_MS` defaults to 30 000 ms. The architecture describes
three propagation mechanisms (write-through, pub/sub, periodic refresh) but no SLA is
documented for customers. Enterprise customers relying on kill-switch for incident
containment need to know the worst-case bound.

#### Existing code to understand

- `docs/DISTRIBUTED_STATE.md` — already describes the three mechanisms.
- `public/packages/common/src/config/schema.ts` — `GatewayConfigSchema` — check if
  `KILL_SWITCH_REFRESH_INTERVAL_MS` is already a typed config key (it may already be
  present; verify).
- `euno-platform/packages/common-infra/src/redis-kill-switch.ts` — where the
  refresh interval is consumed.

#### What to implement

1. **Verify** `KILL_SWITCH_REFRESH_INTERVAL_MS` is in `GatewayConfigSchema`. If it
   is not, add it:
   ```ts
   KILL_SWITCH_REFRESH_INTERVAL_MS: z.coerce.number().int().positive().default(30_000),
   ```

2. **Update `docs/DISTRIBUTED_STATE.md`** Kill Switch section. After the "Initial
   seed" bullet, add:

   > ### Propagation SLA
   >
   > | Scenario | Latency |
   > |---|---|
   > | Normal operation (pub/sub reachable) | < 1 s (sub-second pub/sub) |
   > | Dropped pub/sub message | ≤ `KILL_SWITCH_REFRESH_INTERVAL_MS` (default 30 s) |
   > | Redis fully unreachable | Indefinite (locally-cached state; new kills not propagated) |
   >
   > Enterprise operators requiring tighter containment should set
   > `KILL_SWITCH_REFRESH_INTERVAL_MS=5000` (5 s). This increases Redis read load by
   > ~6× but keeps worst-case staleness to 5 s.

3. **Update `docs/DEPLOYMENT.md`** with a cross-reference to this SLA table and a
   note in the "Enterprise" tier section.

#### Acceptance criteria

- `KILL_SWITCH_REFRESH_INTERVAL_MS` is a typed, documented config key.
- Docs commit to the three-tier SLA.
- Existing tests pass (no behaviour change).

---

### Task 20 — Confirm gateway-clock wins for `timeWindow` conditions

**Review item:** CI-NEW-2
**Dependencies:** None

#### Background

`validateClockSkew` rejects `context.now` deviating > 60 s from the gateway clock,
but `enforceConditions` receives the full `EnforceRequest.context` including the
client-supplied `context.now`. If `timeWindow` conditions read the client-supplied
`now`, a client can shift enforcement time by up to 60 s.

#### Existing code to understand

- `euno-platform/packages/tool-gateway/src/routes/enforce.ts` — route handler,
  `validateClockSkew`, `enforceConditions` call site.
- `public/packages/common/src/enforcement.ts` (or wherever `enforceConditions` is
  implemented) — check whether `timeWindow` uses `context.now` or `Date.now()`.

#### What to implement

1. **Read `enforceConditions`** to determine which clock it uses for `timeWindow`.

2. **If it uses `context.now`**: change it to use `Date.now()` and document that
   `context.now` is for audit attribution only. Update the `ConditionContext` type's
   JSDoc for the `now` field accordingly.

3. **If it already uses `Date.now()`**: add a JSDoc comment in the `context.now`
   field on `ConditionContext` confirming this:
   > `context.now` is stored in the audit record as the client's reported
   > activity time. It is **not** used for `timeWindow` condition evaluation —
   > the gateway always uses its own `Date.now()` clock.

4. **Add a regression test** in `euno-platform/packages/tool-gateway/tests/enforce.test.ts`:
   - Issue a request with a `timeWindow` condition that would be *in-range* for the
     gateway's `Date.now()` but *out-of-range* for a `context.now` 55 s in the
     future.
   - Assert the request is **allowed** (proving the gateway clock is used, not
     `context.now`).

#### Acceptance criteria

- Test passes confirming gateway-clock semantics.
- Code or comment makes the clock-source explicit.

---

### Task 21 — Make `RedisBackedMintRateLimiter` INCR+EXPIRE atomic

**Review item:** CI-NEW-3
**Dependencies:** None

#### Background

The current implementation increments the key with `INCR` then, only when `count ===
1`, applies `EXPIRE`. If the pod crashes between `INCR` and `EXPIRE`, the key has no
TTL and permanently blocks the tenant. The `ttl === -1` recovery path only fires on
the deny branch.

#### Existing code to understand

- `euno-platform/packages/api-key-minter/src/mint-rate-limiter.ts` lines 170–216:
  `RedisBackedMintRateLimiter.check` method.
- `RedisMintRateLimiterClient` interface (lines 84–91): already declares `incr`,
  `decr`, `expire`, `ttl`. A Lua script approach would add an `eval` method; a SET NX
  approach would add a `set` method.

#### What to implement

**Option A (Lua script — cleanest atomicity):**

1. Add `eval(script: string, numkeys: number, ...args: string[]): Promise<unknown>` to
   `RedisMintRateLimiterClient`.
2. In `check`, replace the `INCR + conditional EXPIRE` pattern with a Lua script:
   ```lua
   local current = redis.call('INCR', KEYS[1])
   if current == 1 then
     redis.call('EXPIRE', KEYS[1], ARGV[1])
   end
   return current
   ```
   Execute via `this.client.eval(script, 1, fullKey, String(this.windowSeconds))`.
3. The `ttl === -1` safety guard can be retained as a belt-and-suspenders check.

**Option B (SET NX + INCR pipeline — avoids eval):**

Replace `INCR` with two pipelined commands: `SET key 0 EX window NX` then `INCR key`.
This is less atomic than Lua but eliminates the crash window because the key always
gets a TTL at creation time via `SET EX NX`.

Pick either option; Lua is preferred. Update `FakeRedisClient` in tests to implement
the new interface method.

4. **Add tests**:
   - Simulate a crash-between-INCR-EXPIRE by stubbing `expire` to throw; verify the
     key is not left with `ttl === -1` (with Lua: the TTL is always set atomically).
   - Existing rate-limiting semantics tests continue to pass.

#### Acceptance criteria

- Atomic INCR+TTL — no crash window between counter increment and expiry assignment.
- Existing rate limiter tests pass.

---

### Task 22 — Replace `require('pg')` with optional peer dep + dynamic ESM import

**Review item:** CI-NEW-1
**Dependencies:** None

#### Background

`bootstrap.ts` uses `require('pg')` with an `eslint-disable` comment in two places,
preventing compile-time type checking of the `pg.Pool` API. The justification is that
`pg` is optional for self-hosters who use in-memory mode — but this is expressible
with typed optional peer dependencies.

#### Existing code to understand

- `euno-platform/packages/api-key-minter/src/bootstrap.ts` lines 113–116 and
  153–156.
- `euno-platform/packages/api-key-minter/package.json` — current `dependencies` and
  `peerDependencies`.
- `euno-platform/packages/api-key-minter/tsconfig.json` — compiler settings.

#### What to implement

1. **Move `pg` to `peerDependencies`** in `package.json`:
   ```json
   "peerDependencies": {
     "pg": "^8"
   },
   "peerDependenciesMeta": {
     "pg": { "optional": true }
   }
   ```
   Remove `pg` from `dependencies` (or `devDependencies`) if it appears there.

2. **Add `import type { Pool, PoolConfig } from 'pg'` at the top** of `bootstrap.ts`.
   This gives TypeScript the type without a runtime import.

3. **Replace the `require('pg')` calls** with `await import('pg')`:
   ```ts
   let pgPool: Pool;
   try {
     const { Pool } = await import('pg');
     pgPool = new Pool({ ... } satisfies PoolConfig);
   } catch {
     throw new Error('MINTER_AUDIT_DB_URL is set but the `pg` package is not installed. ...');
   }
   ```

4. **Remove the `eslint-disable` comments** now that the pattern is type-safe.

5. **Verify tests still pass** — the existing test mock for `pg` may need updating
   to use `jest.mock('pg')` instead of `jest.mock` on `require`.

#### Acceptance criteria

- `bootstrap.ts` has no `require('pg')` and no eslint-disable for this.
- `pg` pool operations are type-checked at compile time.
- Existing tests pass.

---

## P3 — Observability and documentation improvements

### Task 23 — Feed authentication-failure events to the anomaly detector

**Review item:** CI-NEW-4
**Dependencies:** None

#### Background

`recordMint(tenantId, false)` is skipped when `tenantId` is `undefined` (i.e. when
API-key verification fails before the tenant is resolved). Authentication spray
attacks — the most critical signal for the `failure_clustering` rule — are therefore
invisible to the anomaly detector.

#### Existing code to understand

- `euno-platform/packages/api-key-minter/src/routes/mint.ts` lines 80–90:
  `parseBearerToken` returns the raw key string. After the early-exit for missing
  bearer token (line 83), `rawKeyOrNull` holds the full `sk-<prefix8>.<secret>`
  string.
- `euno-platform/packages/api-key-minter/src/api-key.ts` — key format helpers.
  Check for a `parseKeyPrefix(rawKey): string | null` function or equivalent.
- `euno-platform/packages/api-key-minter/src/anomaly-detector.ts` — `recordMint`
  signature: `recordMint(tenantId: string, success: boolean): string[]`.

#### What to implement

1. **Extract key prefix** from the raw bearer token before the `verifier.verify()`
   call. The API key format is `sk-<prefix8>.<secret>` — extract the first 8-char
   prefix segment as a pseudo-tenant identifier:
   ```ts
   function extractKeyPrefix(raw: string): string | null {
     const match = /^sk-([A-Za-z0-9]{8})\./.exec(raw);
     return match ? `prefix:${match[1]}` : null;
   }
   ```
   Place this helper inside `mint.ts` or use an existing one from `api-key.ts`.

2. **On authentication failure** (before throwing `AUTHENTICATION_FAILED`), call:
   ```ts
   const pseudoTenant = extractKeyPrefix(rawKeyOrNull);
   if (pseudoTenant && opts.anomalyDetector) {
     void Promise.resolve(
       opts.anomalyDetector.recordMint(pseudoTenant, false)
     ).catch(() => {});
   }
   ```

3. **Add tests** in `euno-platform/packages/api-key-minter/tests/mint-route.test.ts`:
   - Failed auth with an `sk-XXXXXXXX.secret` key → anomaly detector receives
     `recordMint('prefix:XXXXXXXX', false)`.
   - Invalid bearer format → anomaly detector is not called.

#### Acceptance criteria

- Authentication failures with a parseable key prefix are fed to the anomaly detector.
- Fire-and-forget (non-blocking); errors are silently swallowed.
- Existing tests pass.

---

### Task 24 — Add consolidated startup summary log to the minter bootstrap

**Review item:** CI-NEW-5
**Dependencies:** None (but ideally after Task 11 and Task 12 are done, so the
summary includes pool config and rate-limiter type)

#### Background

The gateway's `initializeServices` emits a structured summary log entry at the end
of startup. The minter logs individual component choices but no single summary,
making production configuration verification difficult.

#### Existing code to understand

- `euno-platform/packages/api-key-minter/src/bootstrap.ts` — end of `main()`,
  the `server.listen(...)` call (currently the last substantive operation).
- The gateway pattern: search for `logger.info('Gateway ready'` or similar in
  `euno-platform/packages/tool-gateway/src/bootstrap.ts`.

#### What to implement

Add before or after `server.listen(...)` in `main()`:

```ts
logger.info('Minter bootstrap complete', {
  port,
  signerType: kmsSigner ? 'kms' : privateKeyPem ? 'pem' : 'ephemeral',
  kmsProvider: kmsProvider ?? null,
  auditStore: auditDbUrl ? 'postgres' : 'in-memory',
  apiKeyStore: apiKeyDbUrl ? 'postgres' : 'in-memory',
  rateLimiterType: rateLimiter instanceof RedisBackedMintRateLimiter ? 'redis' : 'in-memory',
  pingRateLimiterType: pingRateLimiter instanceof RedisBackedMintRateLimiter ? 'redis' : 'in-memory',
  anomalyDetectorType: anomalyDetector instanceof RedisAnomalyDetector ? 'redis' : 'in-memory',
  adminJwtAuth: adminJwtVerifier ? 'enabled' : 'disabled',
  issuerDid,
  gatewayAudience,
});
```

Adjust field names to match the actual variable names in scope at the end of `main()`.

#### Acceptance criteria

- A single structured log entry at `info` level is emitted at startup completion.
- Entry is machine-parseable (all values are primitives, not nested objects).
- No sensitive values (keys, URLs with passwords) are included.
- Existing tests pass.

---

### Task 25 — Write minter pepper rotation runbook

**Review item:** OQ-NEW-1
**Dependencies:** None

#### Background

The CI-7 fix in the prior review produced `docs/runbooks/ledger-hmac-rotation.md`
for the audit ledger HMAC secret. The minter's pepper has the same rotation challenge:
two concurrent peppers must coexist so in-flight API keys issued under the old pepper
remain verifiable during the rotation window.

#### Existing code to understand

- `euno-platform/packages/api-key-minter/src/bootstrap.ts` lines 68–78:
  `peppers` array construction from `MINTER_PEPPER_HEX` / `MINTER_PEPPER_VERSION`.
  Only a single pepper entry is constructed from env vars today.
- `euno-platform/packages/api-key-minter/src/api-key-verifier.ts` — `PepperEntry`
  type, how `ApiKeyVerifier` selects the pepper for verification vs. issuance.
- `docs/runbooks/ledger-hmac-rotation.md` — style reference.

#### What to implement

Create `docs/runbooks/minter-pepper-rotation.md` covering:

1. **Why rotation is needed** — ephemeral peppers vs. long-lived production peppers;
   the HMAC(pepper, rawKey) binding means rotating the pepper invalidates all existing
   keys.
2. **Secret provisioning** — `openssl rand -hex 32` to generate a new pepper;
   storage in Kubernetes Secret / Azure Key Vault / AWS Secrets Manager.
3. **Dual-pepper rotation window** — explain that `peppers` is an array and the
   verifier tries each entry. Document the env var extension needed: add
   `MINTER_PEPPER_HEX_V2` + `MINTER_PEPPER_VERSION_V2` (or JSON array form) so two
   peppers can coexist. *(This may require a small bootstrap change to parse a
   secondary pepper.)*
4. **Step-by-step procedure**:
   - Step 1: Add new pepper as a secondary entry (all pods use old pepper for
     issuance, accept both for verification).
   - Step 2: Promote new pepper to primary (new keys use new pepper; old keys still
     verifiable via secondary entry).
   - Step 3: Wait for all old-pepper-issued keys to expire or be revoked.
   - Step 4: Remove old pepper entry.
5. **Bootstrap changes needed** to support dual-pepper env vars (link to a follow-on
   implementation task if the code change is not in scope for this task).

#### Acceptance criteria

- Runbook exists at `docs/runbooks/minter-pepper-rotation.md`.
- Covers all four procedural steps with concrete commands and env var examples.
- Cross-referenced from `docs/DEPLOYMENT.md §"Minter production configuration"`.

---

### Task 26 — Document posture-emitter queue topology for HA issuer

**Review item:** OQ-NEW-2
**Dependencies:** Task 18 (DI-NEW-1 SQLite constraint doc)

#### Background

`DurablePostureEmitter` CI-6 fix requires `POSTURE_DURABLE_QUEUE_PATH` in
production. With HA issuer replicas, each pod needs its own queue path on a
pod-local (`ReadWriteOnce`) PVC. There is no guidance on how to wire this in
Kubernetes, nor on what delivery guarantees hold when each replica maintains an
independent queue.

#### Existing code to understand

- `docs/ARCHITECTURE.md` §6 posture emitter section.
- `k8s/capability-issuer-deployment.yaml` — current PVC spec (if any).
- `docs/DEPLOYMENT.md` — posture section (CI-6 fix).

#### What to implement

Update `docs/DEPLOYMENT.md` in the posture emitter section with a new subsection
**"Multi-replica posture queue topology"**:

1. Explain that each issuer pod maintains an **independent** SQLite queue.
2. Provide a Kubernetes `volumeClaimTemplates` snippet for a `StatefulSet` issuer
   deployment that gives each pod its own PVC:
   ```yaml
   volumeClaimTemplates:
   - metadata:
       name: posture-queue
     spec:
       accessModes: ["ReadWriteOnce"]
       resources:
         requests:
           storage: 1Gi
   ```
3. Show the `POSTURE_DURABLE_QUEUE_PATH=/var/lib/euno/posture-queue.db` env var
   pointing at the mounted path.
4. Note that events from dead-lettered records on a crashed pod are not retried
   unless the pod is restarted with the same PVC. Recommend setting
   `POSTURE_DURABLE_MAX_ATTEMPTS` and monitoring
   `euno_issuer_posture_dead_lettered_total`.

Also update `k8s/capability-issuer-deployment.yaml` with a comment:
> If using more than one replica, convert this Deployment to a StatefulSet and use
> `volumeClaimTemplates` so each pod gets its own posture queue PVC.

#### Acceptance criteria

- Docs cover the multi-replica SQLite topology constraint.
- K8s manifest has a clear comment about the StatefulSet requirement for HA.
- Cross-referenced from the SQLite constraint warning added in Task 18.

---

## Suggested execution order

```
Phase 1 (P0 — before any Stage 3 customer traffic):
  Task 11 (mint rate limiter → Redis)
  Task 12 (Postgres pool shutdown)
  Task 13 (hosted mode unique audience)

Phase 2 (P1 — before billing goes live):
  Task 14 (strip unknown context fields)
  Task 15 (production guard collect all Redis violations)
  Task 16 (admin host binding guard)
  Task 17 (Postgres pool config)

Phase 3 (P2 — before GA):
  Task 18 (SQLite single-writer doc)
  Task 19 (kill-switch SLA doc)
  Task 20 (timeWindow clock test)
  Task 21 (atomic INCR for rate limiter)
  Task 22 (pg optional peer dep)

Phase 4 (P3 — ongoing hardening):
  Task 23 (anomaly detection auth failures)
  Task 24 (startup summary log)
  Task 25 (pepper rotation runbook)
  Task 26 (posture emitter HA topology)
```
