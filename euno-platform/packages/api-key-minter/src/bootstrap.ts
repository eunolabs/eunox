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
import { createLogger } from '@euno/common';
import { createKmsTokenSignerFromEnv } from '@euno/common-infra';
import { InMemoryApiKeyStore } from './api-key-store';
import { ApiKeyVerifier, PepperEntry } from './api-key-verifier';
import { TokenMinter } from './token-minter';
import { LocalTokenSigner } from './local-token-signer';
import { InMemoryMintAuditStore } from './mint-audit';
import { PostgresMintAuditStore } from './postgres-mint-audit-store';
import type { MintAuditPgPool } from './postgres-mint-audit-store';
import { InMemoryMintRateLimiter } from './mint-rate-limiter';
import { createMinterApp } from './app-factory';
import type { TokenSigner } from '@euno/common';

const logger = createLogger('api-key-minter');

async function main(): Promise<void> {
  const port = parseInt(process.env['MINTER_PORT'] ?? '3004', 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid MINTER_PORT: ${process.env['MINTER_PORT']}. Must be 1–65535.`);
  }
  const issuerDid = process.env['MINTER_ISSUER_DID'] ?? 'did:web:minter.euno.local';
  const gatewayAudience = process.env['MINTER_GATEWAY_AUDIENCE'] ?? 'tool-gateway';

  // Validate MINTER_TOKEN_TTL_SECONDS: must parse to a finite positive integer ≤ max.
  const ttlRaw = parseInt(process.env['MINTER_TOKEN_TTL_SECONDS'] ?? '300', 10);
  if (!Number.isFinite(ttlRaw) || !Number.isInteger(ttlRaw) || ttlRaw <= 0) {
    throw new Error(
      `Invalid MINTER_TOKEN_TTL_SECONDS: ${process.env['MINTER_TOKEN_TTL_SECONDS']}. Must be a positive integer.`,
    );
  }
  const ttlSeconds = ttlRaw;

  const adminApiKey = process.env['MINTER_ADMIN_API_KEY'] ?? 'dev-admin-key';

  // Validate MINTER_PEPPER_HEX: must be a valid lowercase hex string that decodes
  // to exactly 32 bytes (256-bit pepper).
  const pepperHex = process.env['MINTER_PEPPER_HEX'];
  let peppers: PepperEntry[];
  if (pepperHex) {
    if (!/^[0-9a-fA-F]{64}$/.test(pepperHex)) {
      throw new Error(
        'Invalid MINTER_PEPPER_HEX: must be a 64-character hex string (32 bytes / 256-bit pepper).',
      );
    }
    peppers = [{ version: process.env['MINTER_PEPPER_VERSION'] ?? 'v1', key: Buffer.from(pepperHex, 'hex') }];
  } else {
    logger.warn('MINTER_PEPPER_HEX not set; using ephemeral random pepper (dev mode only — keys will not survive restarts)');
    peppers = [{ version: 'dev', key: crypto.randomBytes(32) }];
  }

  // Validate rate-limiter env vars: must be finite positive integers.
  const rlMaxRaw = parseInt(process.env['MINTER_RATE_LIMIT_MAX'] ?? '100', 10);
  if (!Number.isFinite(rlMaxRaw) || !Number.isInteger(rlMaxRaw) || rlMaxRaw <= 0) {
    throw new Error(
      `Invalid MINTER_RATE_LIMIT_MAX: ${process.env['MINTER_RATE_LIMIT_MAX']}. Must be a positive integer.`,
    );
  }
  const rlWindowRaw = parseInt(process.env['MINTER_RATE_LIMIT_WINDOW_SECONDS'] ?? '60', 10);
  if (!Number.isFinite(rlWindowRaw) || !Number.isInteger(rlWindowRaw) || rlWindowRaw <= 0) {
    throw new Error(
      `Invalid MINTER_RATE_LIMIT_WINDOW_SECONDS: ${process.env['MINTER_RATE_LIMIT_WINDOW_SECONDS']}. Must be a positive integer.`,
    );
  }

  let signer: TokenSigner;

  const privateKeyPem = process.env['MINTER_PRIVATE_KEY_PEM'];
  const publicKeyPem = process.env['MINTER_PUBLIC_KEY_PEM'];

  // 1. KMS provider (production — HSM-backed, non-exportable keys)
  const kmsSigner = createKmsTokenSignerFromEnv(process.env);
  if (kmsSigner) {
    logger.info('Using KMS-backed token signer', {
      provider: process.env['MINTER_KMS_PROVIDER'],
      algorithm: kmsSigner.getAlgorithm() ?? process.env['MINTER_SIGNING_ALGORITHM'] ?? 'ES256',
    });
    signer = kmsSigner;
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
  const auditDbUrl = process.env['MINTER_AUDIT_DB_URL'];
  let auditStoreBase: InMemoryMintAuditStore | PostgresMintAuditStore;
  if (auditDbUrl) {
    // Dynamically require 'pg' so the package is not a hard deploy-time
    // dependency for self-host operators who use the in-memory mode.
    let pgModule: { Pool: new (opts: { connectionString: string }) => unknown };
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
      pgModule = require('pg');
    } catch {
      throw new Error(
        'MINTER_AUDIT_DB_URL is set but the `pg` package is not installed. ' +
          'Add it to your deployment image: npm install pg',
      );
    }
    const pool = new pgModule.Pool({ connectionString: auditDbUrl });
    const pgAuditStore = new PostgresMintAuditStore(pool as MintAuditPgPool);
    // Only run DDL when explicitly requested so the service can start under an
    // INSERT-only role (the recommended least-privilege configuration described
    // in the threat model §6).  Schema should be deployed via a migration step.
    if (process.env['MINTER_AUDIT_SCHEMA_INIT']?.toLowerCase() === 'true') {
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

  const keyStore = new InMemoryApiKeyStore();
  const rateLimiter = new InMemoryMintRateLimiter({
    maxMintsPerWindow: rlMaxRaw,
    windowSeconds: rlWindowRaw,
  });
  const verifier = new ApiKeyVerifier({ store: keyStore, peppers, logger });
  const minter = new TokenMinter({ signer, issuerDid, gatewayAudience, ttlSeconds });

  const app = createMinterApp({
    mintRouterOpts: { verifier, minter, auditStore, rateLimiter, logger },
    adminKeysRouterOpts: { keyStore, peppers, adminApiKey, logger },
    logger,
  });

  const server = http.createServer(app);
  server.listen(port, () => {
    logger.info(`API-key minter listening on port ${port}`, { issuerDid, gatewayAudience });
  });

  const shutdown = (): void => {
    logger.info('Shutting down minter');
    server.close(() => process.exit(0));
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((err: unknown) => {
  console.error('Fatal error in minter bootstrap:', err);
  process.exit(1);
});
