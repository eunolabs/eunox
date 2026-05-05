/**
 * DB Token Service — entry point.
 *
 * Environment variables:
 *
 *   ISSUER_JWKS_URI             REQUIRED  JWKS endpoint of the capability-issuer.
 *   ISSUER_DID                  REQUIRED  Expected `iss` claim.
 *   GATEWAY_AUDIENCE            Optional  Expected `aud` claim (default: "tool-gateway").
 *   PORT                        Optional  HTTP port (default: 8083).
 *   NODE_ENV                    Optional  Environment label.
 *   DB_TOKENS_ENABLED           Optional  Must be "true" for minting (default: false).
 *   DB_INSTANCES_FILE           Required when DB_TOKENS_ENABLED=true.
 *   DB_TOKEN_MAX_TTL_SECONDS    Optional  Cap on token lifetime.
 *   DB_USERNAME_POLICY_FILE     Optional  Role-to-dbUsername policy JSON file.
 *   AWS_DB_TOKEN_ROLE_ARN       Optional  IAM role for RDS token minting.
 */

import dotenv from 'dotenv';
import * as jose from 'jose';
import { createLogger, loadRoleCapabilityPolicyFromFile } from '@euno/common';
import { DbTokenService } from '@euno/capability-issuer';
import { createDbTokenApp } from './app';

dotenv.config();

const logger = createLogger('db-token-service', process.env.NODE_ENV);

async function main(): Promise<void> {
  const jwksUri = process.env.ISSUER_JWKS_URI;
  const issuerDid = process.env.ISSUER_DID;
  if (!jwksUri) throw new Error('ISSUER_JWKS_URI is required');
  if (!issuerDid) throw new Error('ISSUER_DID is required');

  const audience = process.env.GATEWAY_AUDIENCE ?? 'tool-gateway';
  const port = parseInt(process.env.PORT ?? '8083', 10);

  const dbTokenService = DbTokenService.fromEnv(process.env, logger);

  // Load the DB-username policy — separate from the capability-issuer's
  // role policy so per-customer DB-cred changes are isolated here.
  const policyFile = process.env.DB_USERNAME_POLICY_FILE;
  const dbPolicy = policyFile
    ? loadRoleCapabilityPolicyFromFile(policyFile)
    : { default: {} };

  const app = createDbTokenApp({
    issuerDid,
    audience,
    verificationKey: jose.createRemoteJWKSet(new URL(jwksUri)),
    dbTokenService,
    dbPolicy,
    logger,
    environment: process.env.NODE_ENV,
  });

  app.listen(port, () => {
    logger.info(`DB Token Service listening on port ${port}`, {
      issuerDid,
      audience,
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
