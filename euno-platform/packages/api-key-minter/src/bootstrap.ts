/**
 * Bootstrap for the API-key minter service.
 *
 * Reads env vars, constructs dependencies, and starts the HTTP server.
 *
 * ### Signing key selection
 *
 * | Env var | Mode |
 * |---|---|
 * | `MINTER_KMS_PROVIDER` set | KMS-backed signing (production) |
 * | `MINTER_PRIVATE_KEY_PEM` + `MINTER_PUBLIC_KEY_PEM` set | Local software signing (self-host / CI) |
 * | Neither | Ephemeral RSA key pair generated at startup (dev only; keys lost on restart) |
 *
 * ### Audit store selection
 *
 * | Env var | Mode |
 * |---|---|
 * | `MINTER_AUDIT_DB_URL` set | Postgres-backed append-only audit store (production) |
 * | Not set | In-memory audit store (dev only; audit trail lost on restart) |
 *
 * The Postgres audit store MUST use credentials separate from the minter's
 * main database credentials (threat model §6 — separate credentials).
 */
import * as http from 'http';
import * as crypto from 'crypto';
import { createLogger, loadConfigOrExit } from '@euno/common';
import { createKmsTokenSignerFromEnv } from '@euno/common-infra';
import { validateProductionMinterConfig } from './production-guard';
import { InMemoryApiKeyStore } from './api-key-store';
import { PostgresApiKeyStore } from './postgres-api-key-store';
import type { ApiKeyPgPool } from './postgres-api-key-store';
import { ApiKeyVerifier, PepperEntry } from './api-key-verifier';
import { TokenMinter } from './token-minter';
import { LocalTokenSigner } from './local-token-signer';
import { MeteredTokenSigner } from './metered-token-signer';
import { createAnomalyDetectorFromEnv, RedisAnomalyDetector } from './redis-anomaly-detector';
import { InMemoryMintAuditStore } from './mint-audit';
import { PostgresMintAuditStore } from './postgres-mint-audit-store';
import type { MintAuditPgPool } from './postgres-mint-audit-store';
import { createPingRateLimiterFromEnv, createMintRateLimiterFromEnv, RedisBackedMintRateLimiter } from './mint-rate-limiter';
import { createMinterApp } from './app-factory';
import { createAdminJwtVerifierFromEnv } from './admin-jwt-verifier';
import type { TokenSigner } from '@euno/common';
import os from 'os';

const logger = createLogger('api-key-minter');

async function main(): Promise<void> {
  // ── Production safety guard ─────────────────────────────────────────────────
  // Fail immediately if any unsafe fallback would be activated in production.
  // Must run before any resource allocation so startup fails fast and cleanly.
  validateProductionMinterConfig(process.env);

  // ── Typed configuration ─────────────────────────────────────────────────────
  // Validates and coerces all env vars into their typed counterparts.
  // Exits with a structured error report on misconfiguration.
  const config = loadConfigOrExit(process.env, 'minter');

  const port = config.MINTER_PORT;
  const issuerDid = config.MINTER_ISSUER_DID ?? 'did:web:minter.euno.local';
  const gatewayAudience = config.MINTER_GATEWAY_AUDIENCE ?? 'tool-gateway';
  const ttlSeconds = config.MINTER_TOKEN_TTL_SECONDS;
  const adminApiKey = config.MINTER_ADMIN_API_KEY ?? 'dev-admin-key';

  const pepperHex = config.MINTER_PEPPER_HEX;
  let peppers: PepperEntry[];
  if (pepperHex) {
    if (!/^[0-9a-fA-F]{64}$/.test(pepperHex)) {
      throw new Error(
        'Invalid MINTER_PEPPER_HEX: must be a 64-character hex string (32 bytes / 256-bit pepper).',
      );
    }
    peppers = [{ version: config.MINTER_PEPPER_VERSION ?? 'v1', key: Buffer.from(pepperHex, 'hex') }];
  } else {
    logger.warn('MINTER_PEPPER_HEX not set; using ephemeral random pepper (dev mode only — keys will not survive restarts)');
    peppers = [{ version: 'dev', key: crypto.randomBytes(32) }];
  }

  let signer: TokenSigner;

  const privateKeyPem = config.MINTER_PRIVATE_KEY_PEM;
  const publicKeyPem = config.MINTER_PUBLIC_KEY_PEM;

  // 1. KMS provider (production — HSM-backed, non-exportable keys)
  const kmsProvider = config.MINTER_KMS_PROVIDER;
  const kmsSigner = createKmsTokenSignerFromEnv(process.env);
  if (kmsSigner) {
    logger.info('Using KMS-backed token signer', {
      provider: kmsProvider,
      algorithm: kmsSigner.getAlgorithm() ?? config.MINTER_SIGNING_ALGORITHM ?? 'ES256',
    });
    // Wrap with MeteredTokenSigner so sign latency and KMS errors are tracked.
    signer = new MeteredTokenSigner(kmsSigner, kmsProvider ?? 'unknown');
  } else if (privateKeyPem && publicKeyPem) {
    // 2. Local software signer (self-host / CI with pre-configured key)
    signer = new LocalTokenSigner({ privateKeyPem, publicKeyPem });
  } else {
    // 3. Ephemeral key — dev only
    logger.warn('No signing key configured; generating ephemeral RSA key pair (dev mode only)');
    signer = await LocalTokenSigner.generate('RS256');
  }

  // ── Audit store ────────────────────────────────────────────────────────────
  // Production: Postgres-backed append-only store with separate credentials.
  // Dev: in-memory (audit trail lost on restart).
  const auditDbUrl = config.MINTER_AUDIT_DB_URL;
  let auditStoreBase: InMemoryMintAuditStore | PostgresMintAuditStore;
  // Hoisted so the graceful-shutdown handler can call auditPool.end().
  let auditPool: { end(): Promise<void> } | undefined;
  if (auditDbUrl) {
    // Dynamically import 'pg' so the package is not a hard deploy-time
    // dependency for self-host operators who use the in-memory mode.
    type PgPoolCtor = new (opts: { connectionString: string; max?: number; connectionTimeoutMillis?: number }) => { end(): Promise<void> };
    let PgPool: PgPoolCtor;
    try {
      const pgMod = await import('pg') as unknown as { default?: { Pool: PgPoolCtor }; Pool?: PgPoolCtor };
      PgPool = (pgMod.default?.Pool ?? pgMod.Pool)!;
    } catch {
      throw new Error(
        'MINTER_AUDIT_DB_URL is set but the `pg` package is not installed. ' +
          'Add it to your deployment image: npm install pg',
      );
    }
    auditPool = new PgPool({
      connectionString: auditDbUrl,
      max: config.MINTER_AUDIT_POOL_SIZE,
      connectionTimeoutMillis: config.MINTER_PG_CONNECTION_TIMEOUT_MS,
    });
    // Fail-fast connectivity check: verify the DB is reachable before
    // accepting traffic. A bad connection string or missing network route
    // should fail the pod at startup (under a rolling deploy) rather than
    // silently failing on the first live mint request.
    try {
      const hcClient = await (auditPool as unknown as { connect(): Promise<{ query(sql: string): Promise<unknown>; release(): void }> }).connect();
      await hcClient.query('SELECT 1');
      hcClient.release();
      logger.info('Postgres audit DB health check passed');
    } catch (hcErr) {
      throw new Error(
        `Minter failed to connect to audit DB at startup: ` +
          `${hcErr instanceof Error ? hcErr.message : String(hcErr)}. ` +
          'Verify MINTER_AUDIT_DB_URL and network connectivity.',
      );
    }
    const pgAuditStore = new PostgresMintAuditStore(auditPool as unknown as MintAuditPgPool);
    // Only run DDL when explicitly requested so the service can start under an
    // INSERT-only role (the recommended least-privilege configuration described
    // in the threat model §6).  Schema should be deployed via a migration step.
    if (config.MINTER_AUDIT_SCHEMA_INIT) {
      await pgAuditStore.ensureSchema();
      logger.info('Postgres mint audit schema initialised');
    } else {
      logger.info(
        'Skipping mint audit schema init (set MINTER_AUDIT_SCHEMA_INIT=true to run DDL at startup)',
      );
    }
    logger.info('Using Postgres-backed mint audit store');
    auditStoreBase = pgAuditStore;
  } else {
    logger.warn(
      'MINTER_AUDIT_DB_URL not set; using in-memory audit store (dev mode only — audit trail lost on restart)',
    );
    auditStoreBase = new InMemoryMintAuditStore();
  }
  const auditStore = auditStoreBase;

  // ── API-key store ───────────────────────────────────────────────────────────
  // Production: Postgres-backed durable store — keys survive restarts and
  // rolling deploys.
  // Dev: in-memory (all keys lost on restart).
  const apiKeyDbUrl = config.MINTER_API_KEY_DB_URL;
  let keyStore: InMemoryApiKeyStore | PostgresApiKeyStore;
  // Hoisted so the graceful-shutdown handler can call pgKeyPool.end().
  let pgKeyPool: { end(): Promise<void> } | undefined;
  if (apiKeyDbUrl) {
    type PgPoolCtor = new (opts: { connectionString: string; max?: number; connectionTimeoutMillis?: number }) => { end(): Promise<void> };
    let PgPool: PgPoolCtor;
    try {
      const pgMod = await import('pg') as unknown as { default?: { Pool: PgPoolCtor }; Pool?: PgPoolCtor };
      PgPool = (pgMod.default?.Pool ?? pgMod.Pool)!;
    } catch {
      throw new Error(
        'MINTER_API_KEY_DB_URL is set but the `pg` package is not installed. ' +
          'Add it to your deployment image: npm install pg',
      );
    }
    pgKeyPool = new PgPool({
      connectionString: apiKeyDbUrl,
      max: config.MINTER_API_KEY_POOL_SIZE,
      connectionTimeoutMillis: config.MINTER_PG_CONNECTION_TIMEOUT_MS,
    });
    // Fail-fast connectivity check (mirrors audit pool check above).
    try {
      const hcClient = await (pgKeyPool as unknown as { connect(): Promise<{ query(sql: string): Promise<unknown>; release(): void }> }).connect();
      await hcClient.query('SELECT 1');
      hcClient.release();
      logger.info('Postgres API-key DB health check passed');
    } catch (hcErr) {
      throw new Error(
        `Minter failed to connect to API-key DB at startup: ` +
          `${hcErr instanceof Error ? hcErr.message : String(hcErr)}. ` +
          'Verify MINTER_API_KEY_DB_URL and network connectivity.',
      );
    }
    const pgKeyStore = new PostgresApiKeyStore(pgKeyPool as unknown as ApiKeyPgPool);
    if (config.MINTER_API_KEY_SCHEMA_INIT) {
      await pgKeyStore.ensureSchema();
      logger.info('Postgres API-key store schema initialised');
    } else {
      logger.info(
        'Skipping API-key store schema init (set MINTER_API_KEY_SCHEMA_INIT=true to run DDL at startup)',
      );
    }
    logger.info('Using Postgres-backed API-key store');
    keyStore = pgKeyStore;
  } else {
    logger.warn(
      'MINTER_API_KEY_DB_URL not set; using in-memory API-key store (dev mode only — all keys lost on restart)',
    );
    keyStore = new InMemoryApiKeyStore();
  }

  const rateLimiter = await createMintRateLimiterFromEnv(process.env, logger);
  const verifier = new ApiKeyVerifier({ store: keyStore, peppers, logger });
  const minter = new TokenMinter({ signer, issuerDid, gatewayAudience, ttlSeconds });

  // Anomaly detector — fleet-wide when ANOMALY_REDIS_URL or REDIS_URL is
  // configured (CR-4: backs bucket state in Redis so all replicas share a
  // coherent view), per-replica in-memory otherwise.
  const replicaId = config.MINTER_REPLICA_ID ?? os.hostname();
  const anomalyDetector = createAnomalyDetectorFromEnv(process.env, { replicaId });
  if (anomalyDetector instanceof RedisAnomalyDetector) {
    logger.info('Using Redis-backed anomaly detector (fleet-wide view)', {
      replicaId,
      redisUrl: (config.ANOMALY_REDIS_URL ?? config.REDIS_URL ?? '').replace(
        /\/\/[^@/\s]*@/,
        '//<redacted>@',
      ),
    });
  } else {
    logger.info('Using in-memory anomaly detector (per-replica, CR-4 limitation)', { replicaId });
  }

  // Ping rate limiter — fleet-wide when Redis is configured, per-process
  // in-memory otherwise (suitable for single-replica / dev deployments).
  const pingRateLimiter = await createPingRateLimiterFromEnv(process.env, logger);

  // ── Admin JWT verifier (Task 6) ─────────────────────────────────────────────
  // When MINTER_ADMIN_JWKS_URI + MINTER_ADMIN_JWT_AUDIENCE are set, operator
  // JWTs are accepted as the primary authentication path for admin routes.
  // The shared X-Admin-Key remains as an explicit temporary fallback.
  const adminJwtVerifier = createAdminJwtVerifierFromEnv(process.env);
  if (adminJwtVerifier) {
    logger.info(
      'Admin JWT auth enabled (primary path). ' +
      'X-Admin-Key is the explicit temporary fallback.',
      { jwksUri: config.MINTER_ADMIN_JWKS_URI },
    );
  } else {
    logger.warn(
      'Admin JWT auth not configured (MINTER_ADMIN_JWKS_URI / MINTER_ADMIN_JWT_AUDIENCE not set). ' +
      'Admin routes will only accept the X-Admin-Key shared secret. ' +
      'Set MINTER_ADMIN_JWKS_URI and MINTER_ADMIN_JWT_AUDIENCE to enable operator identity-based access.',
    );
  }

  const app = createMinterApp({
    mintRouterOpts: { verifier, minter, auditStore, rateLimiter, logger },
    adminKeysRouterOpts: { keyStore, peppers, adminApiKey, logger, jwtVerifier: adminJwtVerifier },
    anomalyDetector,
    pingRateLimiter,
    logger,
  });

  const server = http.createServer(app);

  server.listen(port, () => {
    logger.info('Minter ready', {
      port,
      environment: config.NODE_ENV,
      signerType: kmsSigner ? 'kms' : (privateKeyPem ? 'local-pem' : 'ephemeral'),
      auditStore: auditDbUrl ? 'postgres' : 'in-memory',
      apiKeyStore: apiKeyDbUrl ? 'postgres' : 'in-memory',
      rateLimiterType: rateLimiter instanceof RedisBackedMintRateLimiter ? 'redis' : 'in-memory',
      anomalyDetectorType: anomalyDetector instanceof RedisAnomalyDetector ? 'redis' : 'in-memory',
      pingRateLimiterType: pingRateLimiter instanceof RedisBackedMintRateLimiter ? 'redis' : 'in-memory',
      issuerDid,
      gatewayAudience,
    });
  });

  const shutdown = (): void => {
    logger.info('Shutting down minter');
    // Close Redis anomaly detector connection if active.
    if (anomalyDetector instanceof RedisAnomalyDetector) {
      void anomalyDetector.close();
    }
    // Drain Postgres connection pools gracefully before exiting.
    void Promise.allSettled([
      auditPool?.end(),
      pgKeyPool?.end(),
    ]).then(() => server.close(() => process.exit(0)));
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((err: unknown) => {
  console.error('Fatal error in minter bootstrap:', err);
  process.exit(1);
});
