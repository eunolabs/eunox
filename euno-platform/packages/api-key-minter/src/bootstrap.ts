/**
 * Bootstrap for the API-key minter service.
 *
 * Reads env vars, constructs dependencies, and starts the HTTP server.
 * For dev: ephemeral RSA key pair + in-memory stores.
 * For prod: inject MINTER_PRIVATE_KEY_PEM + MINTER_PUBLIC_KEY_PEM + MINTER_PEPPER_HEX.
 */
import * as http from 'http';
import * as crypto from 'crypto';
import { createLogger } from '@euno/common';
import { InMemoryApiKeyStore } from './api-key-store';
import { ApiKeyVerifier, PepperEntry } from './api-key-verifier';
import { TokenMinter } from './token-minter';
import { LocalTokenSigner } from './local-token-signer';
import { InMemoryMintAuditStore } from './mint-audit';
import { InMemoryMintRateLimiter } from './mint-rate-limiter';
import { createMinterApp } from './app-factory';

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

  let signer: LocalTokenSigner;
  const privateKeyPem = process.env['MINTER_PRIVATE_KEY_PEM'];
  const publicKeyPem = process.env['MINTER_PUBLIC_KEY_PEM'];
  if (privateKeyPem && publicKeyPem) {
    signer = new LocalTokenSigner({ privateKeyPem, publicKeyPem });
  } else {
    logger.warn('No signing key configured; generating ephemeral RSA key pair (dev mode only)');
    signer = await LocalTokenSigner.generate('RS256');
  }

  const keyStore = new InMemoryApiKeyStore();
  const auditStore = new InMemoryMintAuditStore();
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
