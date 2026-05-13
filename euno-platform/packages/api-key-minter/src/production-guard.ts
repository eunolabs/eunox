/**
 * Production configuration guard for the API-key minter.
 *
 * `validateProductionMinterConfig` collects every unsafe fallback that the
 * bootstrap would silently activate in a misconfigured production environment
 * and throws a single, actionable error message so operators cannot accidentally
 * start the minter in an unsafe state.
 *
 * Enforced conditions (all only when `NODE_ENV=production`):
 *
 * 1. **Admin API key** — `MINTER_ADMIN_API_KEY` must be set; the default
 *    `dev-admin-key` cannot be used in production (anyone who has read the
 *    source code could authenticate as admin).
 *
 * 2. **Pepper material** — `MINTER_PEPPER_HEX` must be set; ephemeral pepper
 *    keys are regenerated on every restart, making previously-issued API keys
 *    unverifiable after a pod restart or rolling deploy.
 *
 * 3. **Signing key** — either `MINTER_KMS_PROVIDER` (HSM-backed) or both
 *    `MINTER_PRIVATE_KEY_PEM` + `MINTER_PUBLIC_KEY_PEM` (static software key)
 *    must be configured; ephemeral key pairs prevent token verification after a
 *    restart and expose the private key material to memory dumps.
 *
 * 4. **Audit store** — `MINTER_AUDIT_DB_URL` must be set; the in-memory store
 *    loses the entire mint audit trail on restart, making post-incident forensics
 *    impossible.
 *
 * 5. **API-key store** — `MINTER_API_KEY_DB_URL` must be set; the in-memory
 *    API-key store loses all issued keys on restart, requiring every tenant to
 *    re-issue credentials after a pod restart or rolling deploy.
 *    (Implementation wired in Task 2 — Add a durable API-key store.)
 *
 * 6. **Redis HA** — any Redis URL that is configured (`REDIS_URL`,
 *    `ANOMALY_REDIS_URL`, `MINTER_PING_REDIS_URL`) must use a Sentinel or
 *    Cluster scheme; single-node Redis is a single point of failure for
 *    fleet-wide rate limiting and anomaly detection.
 *    See docs/DEPLOYMENT.md §"Redis HA for production".
 *
 * @internal Exported for unit testing; not part of the public service API.
 */

/**
 * Returns `true` when `url` matches a Redis Sentinel or Redis Cluster
 * connection string.
 *
 * Heuristics (same as the gateway's CR-3 check):
 * - `redis+sentinel://` / `rediss+sentinel://` scheme → Sentinel
 * - `redis+cluster://` / `rediss+cluster://` scheme  → Cluster
 * - URL contains a comma (multiple seed nodes)        → Cluster
 */
function isHaRedisUrl(url: string): boolean {
  return (
    url.startsWith('redis+sentinel://') ||
    url.startsWith('rediss+sentinel://') ||
    url.startsWith('redis+cluster://') ||
    url.startsWith('rediss+cluster://') ||
    url.includes(',') // multiple comma-separated seed nodes → cluster
  );
}

/**
 * Validates the minter's startup configuration for production safety.
 *
 * A no-op when `NODE_ENV` is not `'production'`.
 *
 * Throws a single `Error` listing every unsafe fallback that would be
 * activated, so the operator can fix all issues in one restart cycle.
 *
 * @param env - Environment variable map (defaults to `process.env`).
 */
export function validateProductionMinterConfig(
  env: NodeJS.ProcessEnv = process.env,
): void {
  if (env['NODE_ENV'] !== 'production') return;

  const violations: string[] = [];

  // 1. Admin API key — default value is publicly known source-code literal.
  if (!env['MINTER_ADMIN_API_KEY']) {
    violations.push(
      "MINTER_ADMIN_API_KEY is not set. The default 'dev-admin-key' cannot be used in " +
        'production. Set MINTER_ADMIN_API_KEY to a secret value of at least 32 characters.',
    );
  }

  // 2. Pepper material — ephemeral pepper is regenerated on every restart,
  //    making previously-issued API keys unverifiable.
  if (!env['MINTER_PEPPER_HEX']) {
    violations.push(
      'MINTER_PEPPER_HEX is not set. Ephemeral pepper material (lost on restart) cannot be ' +
        'used in production. Generate a 32-byte random hex value: `openssl rand -hex 32`.',
    );
  }

  // 3. Signing key — ephemeral key pairs cannot be used in production.
  const hasKms = Boolean(env['MINTER_KMS_PROVIDER']);
  const hasPem = Boolean(env['MINTER_PRIVATE_KEY_PEM'] && env['MINTER_PUBLIC_KEY_PEM']);
  if (!hasKms && !hasPem) {
    violations.push(
      'No signing key is configured. Ephemeral RSA key pairs cannot be used in production. ' +
        'Set MINTER_KMS_PROVIDER (HSM-backed) or both MINTER_PRIVATE_KEY_PEM and ' +
        'MINTER_PUBLIC_KEY_PEM (static software key). ' +
        'See docs/DEPLOYMENT.md §"GCP Cloud KMS per-tenant key isolation" for GCP deployments.',
    );
  }

  // 4. Audit store — in-memory store loses the entire audit trail on restart.
  if (!env['MINTER_AUDIT_DB_URL']) {
    violations.push(
      'MINTER_AUDIT_DB_URL is not set. In-memory audit storage (audit trail lost on restart) ' +
        'cannot be used in production. Set MINTER_AUDIT_DB_URL to a Postgres connection string.',
    );
  }

  // 5. API-key store — in-memory store loses all issued keys on restart.
  //    A Postgres-backed implementation is provided in Task 2 (Add a durable API-key store).
  if (!env['MINTER_API_KEY_DB_URL']) {
    violations.push(
      'MINTER_API_KEY_DB_URL is not set. In-memory API-key storage (all keys lost on restart) ' +
        'cannot be used in production. Set MINTER_API_KEY_DB_URL to a Postgres connection string ' +
        'once the durable API-key store backend (Task 2) is deployed.',
    );
  }

  // 6. Redis HA — any configured Redis URL must use Sentinel or Cluster.
  const redisVars: Array<[string, string | undefined]> = [
    ['REDIS_URL', env['REDIS_URL']],
    ['ANOMALY_REDIS_URL', env['ANOMALY_REDIS_URL']],
    ['MINTER_PING_REDIS_URL', env['MINTER_PING_REDIS_URL']],
  ];
  for (const [varName, url] of redisVars) {
    if (url && !isHaRedisUrl(url)) {
      violations.push(
        `${varName} appears to point at a single-node Redis instance. ` +
          'In production, all minter Redis-backed stores (anomaly detection, ping rate ' +
          'limiting) require a high-availability deployment. ' +
          'Replace with a Redis Sentinel or Redis Cluster URL. ' +
          'See docs/DEPLOYMENT.md §"Redis HA for production".',
      );
      break; // Only report the first single-node URL to avoid noisy output.
    }
  }

  if (violations.length === 0) return;

  throw new Error(
    'Minter refused to start: production configuration is unsafe.\n\n' +
      violations.map((v, i) => `  ${i + 1}. ${v}`).join('\n') +
      '\n\nSee docs/DEPLOYMENT.md for production configuration guidance.',
  );
}
