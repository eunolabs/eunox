/**
 * `GET /api/v1/audit/signing-keys` — Evidence-signing JWKS endpoint (Task 6)
 * ---------------------------------------------------------------------------
 * Serves the evidence-signing public key as a JWK Set so compliance consumers
 * can verify `SignedAuditEvidence` records returned by
 * `GET /api/v1/audit/export` offline — without accessing the capability
 * issuer's JWKS (which holds _capability-token_ verification keys, not
 * evidence-signing keys).
 *
 * ### When is this endpoint available?
 *
 * The route is only mounted when `auditSigningPublicKeyPem` is present in
 * `GatewayDependencies`, which happens when:
 *   - `ENABLE_CRYPTOGRAPHIC_AUDIT=true`, AND
 *   - the active signer is a **software signer** (`AUDIT_SIGNING_KMS_PROVIDER`
 *     is not set).
 *
 * KMS-backed signers do not expose the public key locally; for those
 * deployments the public key must be retrieved directly from the KMS control
 * plane (e.g., Azure Key Vault `GET key` API).
 *
 * ### Offline verification procedure
 *
 * 1. Fetch the JWK Set from `GET /api/v1/audit/signing-keys`.
 * 2. For each exported `SignedAuditEvidence` record, locate the key whose
 *    `kid` matches `record.keyId`.
 * 3. Import the key using its `kty` and `alg`.
 * 4. Canonicalize the evidence fields (all fields except `signature`, `keyId`,
 *    `algorithm`, `previousHash`, and `seq`) using the same stable JSON
 *    serialization the signer uses, then compute SHA-256.
 * 5. Verify `record.signature` (base64) against the digest.
 *
 * Step 4 uses `canonicalSha256` from `@euno/common`.
 *
 * @module
 */

import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { createLogger } from '@euno/common';

type Logger = ReturnType<typeof createLogger>;

// ── Types ─────────────────────────────────────────────────────────────────────

export interface AuditSigningKeysRouterOptions {
  /**
   * SPKI PEM of the evidence-signing public key.
   * The key's `keyId` and `algorithm` are extracted from the signer at
   * construction time and embedded in the JWK's `kid` and `alg` fields.
   */
  publicKeyPem: string;
  /**
   * Logical key identifier recorded in every signed evidence record.
   * Must match `SignedAuditEvidence.keyId` so consumers can locate the
   * correct key in the set.
   */
  keyId: string;
  /**
   * Signing algorithm (JWS name, e.g. `RS256`).  Embedded as the `alg`
   * field in the JWK so importers know the intended algorithm without
   * inspecting the key type.
   */
  algorithm: string;
  logger: Logger;
}

// ── Factory ───────────────────────────────────────────────────────────────────

/**
 * Build the `GET /api/v1/audit/signing-keys` JWKS router.
 *
 * The JWK Set is computed synchronously at construction time using Node's
 * built-in `KeyObject.export({ format: 'jwk' })` (available since Node 15).
 * Every request is served from the cached in-memory object — the signing key
 * does not change at runtime.
 */
export function createAuditSigningKeysRouter(opts: AuditSigningKeysRouterOptions): Router {
  const { publicKeyPem, keyId, algorithm, logger } = opts;

  let cachedJwkSet: { keys: object[] } | null = null;

  try {
    const keyObject = crypto.createPublicKey(publicKeyPem);
    // Node 15+ exports a JWK synchronously; no I/O involved.
    const jwk = keyObject.export({ format: 'jwk' }) as Record<string, unknown>;
    cachedJwkSet = { keys: [{ ...jwk, kid: keyId, alg: algorithm, use: 'sig' }] };
    logger.info('Audit signing-keys JWKS built', { keyId, algorithm, numKeys: 1 });
  } catch (err) {
    logger.error('Failed to build audit signing-keys JWKS', {
      error: err instanceof Error ? err.message : String(err),
    });
    // If the PEM is invalid, mount a route that returns 503.
    const errRouter = Router();
    errRouter.get('/api/v1/audit/signing-keys', (_req: Request, res: Response) => {
      res.status(503).json({ error: { code: 'SERVICE_UNAVAILABLE', message: 'Signing key unavailable' } });
    });
    return errRouter;
  }

  const router = Router();
  const jwkSetSnapshot = cachedJwkSet;

  router.get('/api/v1/audit/signing-keys', (_req: Request, res: Response) => {
    res
      .setHeader('Cache-Control', 'public, max-age=3600')
      .setHeader('Content-Type', 'application/json')
      .json(jwkSetSnapshot);
  });

  return router;
}
