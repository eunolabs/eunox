/**
 * Storage Grant Service — entry point.
 *
 * Reads configuration from environment variables, builds a
 * {@link StorageGrantService} from env config, creates the Express app,
 * and starts listening.
 *
 * Environment variables:
 *
 *   ISSUER_JWKS_URI           REQUIRED  JWKS endpoint of the capability-issuer.
 *   ISSUER_DID                REQUIRED  Expected `iss` claim in incoming JWTs.
 *   GATEWAY_AUDIENCE          Optional  Expected `aud` claim (default: "tool-gateway").
 *   PORT                      Optional  HTTP port (default: 8082).
 *   NODE_ENV                  Optional  Environment label.
 *   STORAGE_GRANTS_ENABLED    Optional  Must be "true" for the service to mint (default: false).
 *   STORAGE_GRANT_MAX_TTL_SECONDS  Optional  Cap on STS session / SAS TTL.
 *   AWS_REGION                Optional  AWS region for S3 grants.
 *   AWS_STORAGE_GRANT_ROLE_ARN  Optional  IAM role to assume for S3 minting.
 */

import dotenv from 'dotenv';
import * as jose from 'jose';
import { createLogger } from '@euno/common';
import { StorageGrantService } from '@euno/capability-issuer';
import { createStorageGrantApp } from './app';

dotenv.config();

const logger = createLogger('storage-grant-service', process.env.NODE_ENV);

async function main(): Promise<void> {
  const jwksUri = process.env.ISSUER_JWKS_URI;
  const issuerDid = process.env.ISSUER_DID;
  if (!jwksUri) throw new Error('ISSUER_JWKS_URI is required');
  if (!issuerDid) throw new Error('ISSUER_DID is required');

  const audience = process.env.GATEWAY_AUDIENCE ?? 'tool-gateway';
  const port = parseInt(process.env.PORT ?? '8082', 10);

  const storageGrantService = StorageGrantService.fromEnv(process.env, logger);

  const app = createStorageGrantApp({
    issuerDid,
    audience,
    verificationKey: jose.createRemoteJWKSet(new URL(jwksUri)),
    storageGrantService,
    logger,
    environment: process.env.NODE_ENV,
  });

  app.listen(port, () => {
    logger.info(`Storage Grant Service listening on port ${port}`, {
      issuerDid,
      audience,
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
