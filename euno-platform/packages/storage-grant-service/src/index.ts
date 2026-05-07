/**
 * Storage Grant Service — entry point.
 *
 * All configuration is validated at boot via the typed `StorageGrantServiceConfigSchema`
 * (see packages/common/src/config/schema.ts).  Run:
 *
 *   euno config dump-template --service storage-grant-service
 *
 * to generate a `.env.example` listing every supported variable with its
 * description and default value.
 */

import dotenv from 'dotenv';
import * as jose from 'jose';
import { createLogger, loadConfigOrExit } from '@euno/common';
import { StorageGrantService } from '@euno/capability-issuer';
import { createStorageGrantApp } from './app';

dotenv.config();

// Validate the environment against the typed schema and exit with a
// structured error report on misconfig — no service code runs until
// every required variable is present and valid.
const cfg = loadConfigOrExit(process.env, 'storage-grant-service');

const logger = createLogger('storage-grant-service', cfg.NODE_ENV);

async function main(): Promise<void> {
  const storageGrantService = StorageGrantService.fromEnv(process.env, logger);

  const app = createStorageGrantApp({
    issuerDid: cfg.ISSUER_DID,
    audience: cfg.GATEWAY_AUDIENCE ?? 'tool-gateway',
    verificationKey: jose.createRemoteJWKSet(new URL(cfg.ISSUER_JWKS_URI)),
    storageGrantService,
    logger,
    environment: cfg.NODE_ENV,
  });

  app.listen(cfg.PORT, () => {
    logger.info(`Storage Grant Service listening on port ${cfg.PORT}`, {
      issuerDid: cfg.ISSUER_DID,
      audience: cfg.GATEWAY_AUDIENCE ?? 'tool-gateway',
      storageEnabled: storageGrantService.isEnabled(),
    });
  });
}

if (require.main === module) {
  main().catch((err: Error) => {
    // eslint-disable-next-line no-console
    console.error('Failed to start storage-grant-service:', err.message);
    process.exit(1);
  });
}

export { createStorageGrantApp } from './app';
export type { StorageGrantAppOptions } from './app';
