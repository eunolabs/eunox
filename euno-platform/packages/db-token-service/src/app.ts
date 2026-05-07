/**
 * DB Token Service — Express application factory.
 *
 * # Responsibility
 *
 * This standalone microservice accepts a signed capability JWT and mints
 * short-lived database IAM credentials (Azure SQL AAD tokens, AWS RDS
 * IAM auth tokens, GCP Cloud SQL IAM tokens) for every `db://` capability
 * contained in the token.
 *
 * # KMS isolation
 *
 * Verification uses the issuer's public JWKS only — no KMS signing
 * credentials are held by this service. A compromise of the DB-token
 * service cannot produce forged capability JWTs.
 *
 * # DB-username policy isolation
 *
 * The `db-token-service` owns its own copy of the dbUsernamesByRole
 * policy (configured via DB_USERNAME_POLICY_FILE). Per-customer DB-cred
 * policy changes require only a rolling restart of these pods — the
 * capability-issuer is not touched.
 *
 * # Separation of concerns
 *
 *   - Fault isolation: an RDS IAM outage cannot crash the
 *     capability-issuer pod.
 *   - Independent scaling: DB-heavy workloads scale independently.
 *   - Independent IAM: DB-token IAM credentials (AWS_DB_TOKEN_ROLE_ARN,
 *     AZURE_CLIENT_ID, GCP_KEY_FILE_PATH) are scoped to this service.
 *   - Separate rate limits: per-subject limiter is independent.
 *
 * # API
 *
 *   POST /api/v1/db-tokens
 *     Authorization: Bearer <capability-jwt>
 *     Content-Type: application/json
 *     { "agentId": "<agent-id>" }
 *
 *     200: { "credentials": DbCredential[] }
 *     401: JWT verification failed
 *     403: no db:// capabilities in token
 *     500/502: internal minting failure
 *
 *   GET  /health
 *   GET  /health/live
 *   GET  /health/ready
 *
 *   GET  /.well-known/db-token-service
 */

import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import * as jose from 'jose';
import {
  CapabilityError,
  CapabilityTokenPayload,
  DbCredential,
  ErrorCode,
  Logger,
  RoleCapabilityPolicy,
  SIGNING_ALGORITHMS,
  SUPPORTED_SCHEMA_VERSIONS,
  createLogger,
  parseBearerToken,
} from '@euno/common';
import { DbTokenService } from '@euno/capability-issuer';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface DbTokenAppOptions {
  /** Expected `iss` JWT claim. */
  issuerDid: string;

  /**
   * Expected `aud` JWT claim — must match the capability-issuer's
   * configured GATEWAY_AUDIENCE.
   */
  audience: string;

  /**
   * Pre-imported jose verification key (for tests / static deployments).
   * Production deployments should pass `jose.createRemoteJWKSet(...)`.
   */
  verificationKey?: jose.KeyLike | Uint8Array | jose.JWTVerifyGetKey;

  /**
   * JWKS URI of the capability-issuer. Used to build a
   * `createRemoteJWKSet` when `verificationKey` is absent.
   */
  jwksUri?: string;

  /** Configured and enabled DbTokenService instance. */
  dbTokenService: DbTokenService;

  /**
   * Role-to-dbUsername mapping for this service's policy domain.
   * The service resolves the database principal from the JWT's
   * `authorizedBy.roles` claim using this map.
   *
   * This policy is independent of the capability-issuer's policy so
   * per-customer DB-cred changes can be deployed without restarting
   * the capability-issuer.
   */
  dbPolicy: RoleCapabilityPolicy;

  /** Optional logger. */
  logger?: Logger;

  /** Environment label used in health responses. */
  environment?: string;

  /**
   * Maximum number of db-token requests per window per IP.
   * Defaults to 10 per 60-second window.  DB IAM tokens (especially
   * RDS 15-minute auth tokens) have a larger blast radius than
   * storage SAS tokens, so the default is intentionally tighter.
   * Set to 0 to disable rate limiting entirely (not recommended in production).
   */
  rateLimitMaxPerWindow?: number;

  /**
   * Rate-limit window duration in milliseconds.
   * Defaults to 60 000 ms (1 minute).
   */
  rateLimitWindowMs?: number;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createDbTokenApp(opts: DbTokenAppOptions): express.Application {
  if (!opts.verificationKey && !opts.jwksUri) {
    throw new Error(
      'DbTokenApp: either verificationKey or jwksUri must be provided for JWT verification',
    );
  }

  const log = opts.logger ?? createLogger('db-token-service', opts.environment ?? 'production');
  const environment = opts.environment ?? 'production';

  const verifyKey = opts.verificationKey ?? jose.createRemoteJWKSet(new URL(opts.jwksUri!));
  const jwtVerify = (
    jwt: string,
    options: jose.JWTVerifyOptions,
  ) => {
    if (typeof verifyKey === 'function') {
      return jose.jwtVerify(jwt, verifyKey, options);
    }
    return jose.jwtVerify(jwt, verifyKey, options);
  };

  const app = express();
  app.use(helmet());
  // Server-to-server internal service — disable wildcard CORS.
  app.use(cors({ origin: false }));
  app.use(express.json());

  // -------------------------------------------------------------------------
  // Health
  // -------------------------------------------------------------------------

  app.get('/health', (_req, res) => {
    res.json({ status: 'healthy', service: 'db-token-service' });
  });
  app.get('/health/live', (_req, res) => {
    res.json({ status: 'healthy', service: 'db-token-service' });
  });
  app.get('/health/ready', (_req, res) => {
    if (opts.dbTokenService.isEnabled()) {
      res.json({ status: 'ready', service: 'db-token-service' });
    } else {
      res.status(503).json({ status: 'not_ready', reason: 'dbTokenService not enabled' });
    }
  });

  // -------------------------------------------------------------------------
  // Service metadata
  // -------------------------------------------------------------------------

  app.get('/.well-known/db-token-service', (_req, res) => {
    res.json({
      service: 'db-token-service',
      issuerDid: opts.issuerDid,
      audience: opts.audience,
      environment,
      endpoints: { dbTokens: '/api/v1/db-tokens' },
    });
  });

  // -------------------------------------------------------------------------
  // POST /api/v1/db-tokens
  // -------------------------------------------------------------------------

  const rateLimitMax = opts.rateLimitMaxPerWindow ?? 10;
  // Per-IP rate limiter: DB IAM tokens (especially RDS 15-minute auth tokens)
  // have a larger blast radius than capability JWTs, so this service-level
  // limiter is tighter than the storage-grant service's default.
  const dbTokenLimiter = rateLimit({
    windowMs: opts.rateLimitWindowMs ?? 60_000,
    max: rateLimitMax,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (_req, res) => {
      res.status(429).json({
        error: { code: 'RATE_LIMIT_EXCEEDED', message: 'DB-token rate limit exceeded' },
      });
    },
    // Skip when: service disabled OR max === 0 (operator-disabled rate limiting).
    skip: () => !opts.dbTokenService.isEnabled() || rateLimitMax === 0,
  });

  app.post('/api/v1/db-tokens', dbTokenLimiter, async (req: Request, res: Response, next: NextFunction) => {
    try {
      // 1. Extract bearer token.
      const rawToken = parseBearerToken(req.headers.authorization);
      if (!rawToken) {
        throw new CapabilityError(
          ErrorCode.AUTHENTICATION_FAILED,
          'Authorization header with Bearer capability token is required',
          401,
        );
      }

      // 2. Verify JWT (signature + expiry + iss + aud + algorithm allow-list).
      let payload: CapabilityTokenPayload;
      try {
        const { payload: raw } = await jwtVerify(rawToken, {
          issuer: opts.issuerDid,
          audience: opts.audience,
          algorithms: [...SIGNING_ALGORITHMS],
        });
        payload = raw as unknown as CapabilityTokenPayload;
      } catch (err) {
        const code =
          err instanceof Error && (err as { code?: string }).code === 'ERR_JWT_EXPIRED'
            ? ErrorCode.EXPIRED_TOKEN
            : ErrorCode.INVALID_TOKEN;
        throw new CapabilityError(
          code,
          `Invalid capability token: ${err instanceof Error ? err.message : String(err)}`,
          401,
        );
      }

      // 3. Runtime payload shape validation — a malformed-but-signed token
      //    (e.g. missing `capabilities`, non-numeric `exp`, or unrecognised
      //    `schemaVersion`) is rejected here rather than crashing downstream.
      if (
        !Array.isArray(payload.capabilities) ||
        typeof payload.exp !== 'number' ||
        !SUPPORTED_SCHEMA_VERSIONS.has(payload.schemaVersion)
      ) {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          `Invalid capability token payload: capabilities must be an array, exp must be a number, and schemaVersion must be one of [${[...SUPPORTED_SCHEMA_VERSIONS].join(', ')}] (got '${payload.schemaVersion}')`,
          401,
        );
      }

      const agentId = (req.body as { agentId?: unknown }).agentId ?? payload.sub ?? 'unknown';
      log.info('DB token request', {
        agentId,
        userId: payload.authorizedBy?.userId,
        capCount: payload.capabilities.length,
      });

      // 4. Reject if the token contains no db:// capabilities.
      const hasDb = payload.capabilities.some(
        (c) => typeof c.resource === 'string' && c.resource.startsWith('db://'),
      );
      if (!hasDb) {
        throw new CapabilityError(
          ErrorCode.INSUFFICIENT_PERMISSIONS,
          'Capability token does not grant any db:// resources',
          403,
        );
      }

      // 5. Derive TTL from the token's remaining lifetime.
      const now = Math.floor(Date.now() / 1000);
      const capabilityTtlSeconds = Math.max(0, payload.exp - now);

      // 6. Derive user roles from the JWT's authorizedBy claim.
      //    The db-token service owns the dbUsernamesByRole policy —
      //    it does NOT rely on the issuer's policy, which is intentional:
      //    per-customer DB-cred policies can change independently.
      const userRoles = payload.authorizedBy?.roles ?? [];

      // 7. Mint DB credentials.
      const credentials: DbCredential[] | undefined =
        await opts.dbTokenService.mintForCapabilities(payload.capabilities, {
          agentId: String(agentId),
          authorizedBy: payload.authorizedBy?.userId ?? String(agentId),
          capabilityTtlSeconds,
          userRoles,
          policy: opts.dbPolicy,
        });

      res.json({ credentials: credentials ?? [] });
    } catch (err) {
      next(err);
    }
  });

  // -------------------------------------------------------------------------
  // Error handler
  // -------------------------------------------------------------------------

  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof CapabilityError) {
      log.warn('Request failed', { code: err.code, message: err.message });
      if (err.responseHeaders) {
        for (const [k, v] of Object.entries(err.responseHeaders)) res.setHeader(k, v);
      }
      res.status(err.statusCode).json({ error: { code: err.code, message: err.message } });
    } else {
      log.error('Unexpected error', { error: err.message });
      res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' } });
    }
  });

  return app;
}
