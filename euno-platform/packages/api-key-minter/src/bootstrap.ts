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
  const issuerDid = process.env['MINTER_ISSUER_DID'] ?? 'did:web:minter.euno.local';
  const gatewayAudience = process.env['MINTER_GATEWAY_AUDIENCE'] ?? 'tool-gateway';
  const ttlSeconds = parseInt(process.env['MINTER_TOKEN_TTL_SECONDS'] ?? '300', 10);
  const adminApiKey = process.env['MINTER_ADMIN_API_KEY'] ?? 'dev-admin-key';

  const pepperHex = process.env['MINTER_PEPPER_HEX'];
  const peppers: PepperEntry[] = pepperHex
    ? [{ version: process.env['MINTER_PEPPER_VERSION'] ?? 'v1', key: Buffer.from(pepperHex, 'hex') }]
    : [{ version: 'dev', key: crypto.randomBytes(32) }];

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
    maxMintsPerWindow: parseInt(process.env['MINTER_RATE_LIMIT_MAX'] ?? '100', 10),
    windowSeconds: parseInt(process.env['MINTER_RATE_LIMIT_WINDOW_SECONDS'] ?? '60', 10),
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
