/**
 * DB Token Service — entry point.
 *
 * All configuration is validated at boot via the typed `DbTokenServiceConfigSchema`
 * (see packages/common/src/config/schema.ts).  Run:
 *
 *   euno config dump-template --service db-token-service
 *
 * to generate a `.env.example` listing every supported variable with its
 * description and default value.
 */

import dotenv from 'dotenv';
import * as jose from 'jose';
import { createLogger, loadConfigOrExit, loadRoleCapabilityPolicyFromFile } from '@euno/common';
import { DbTokenService } from '@euno/capability-issuer';
import { createDbTokenApp } from './app';

dotenv.config();

// Validate the environment against the typed schema and exit with a
// structured error report on misconfig — no service code runs until
// every required variable is present and valid.
const cfg = loadConfigOrExit(process.env, 'db-token-service');

const logger = createLogger('db-token-service', cfg.NODE_ENV);

async function main(): Promise<void> {
  const dbTokenService = DbTokenService.fromEnv(process.env, logger);

  // Load the DB-username policy — separate from the capability-issuer's
  // role policy so per-customer DB-cred changes are isolated here.
  const dbPolicy = cfg.DB_USERNAME_POLICY_FILE
    ? loadRoleCapabilityPolicyFromFile(cfg.DB_USERNAME_POLICY_FILE)
    : { default: {} };

  const app = createDbTokenApp({
    issuerDid: cfg.ISSUER_DID,
    audience: cfg.GATEWAY_AUDIENCE ?? 'tool-gateway',
    verificationKey: jose.createRemoteJWKSet(new URL(cfg.ISSUER_JWKS_URI)),
    dbTokenService,
    dbPolicy,
    logger,
    environment: cfg.NODE_ENV,
  });

  app.listen(cfg.PORT, () => {
    logger.info(`DB Token Service listening on port ${cfg.PORT}`, {
      issuerDid: cfg.ISSUER_DID,
      audience: cfg.GATEWAY_AUDIENCE ?? 'tool-gateway',
      dbEnabled: dbTokenService.isEnabled(),
    });
  });
}

if (require.main === module) {
  main().catch((err: Error) => {
    // eslint-disable-next-line no-console
    console.error('Failed to start db-token-service:', err.message);
    process.exit(1);
  });
}

export { createDbTokenApp } from './app';
export type { DbTokenAppOptions } from './app';
