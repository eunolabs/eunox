/**
 * Storage Grant Service — Express application factory.
 *
 * # Responsibility
 *
 * This standalone microservice accepts a signed capability JWT and
 * mints short-lived cloud storage credentials (AWS STS presigned URLs,
 * Azure User-Delegation SAS, GCP HMAC tokens) for every `storage://`
 * capability contained in the token.
 *
 * # KMS isolation
 *
 * Verification is performed against the issuer's public JWKS only
 * (configured via the `verificationKey` option or the
 * `ISSUER_JWKS_URI` environment variable at runtime).  **This service
 * carries no KMS signing credentials** — a compromise of this service
 * does not grant the attacker the ability to forge capability tokens.
 *
 * # Separation of concerns
 *
 * By running as a separate process the storage-grant path gains:
 *
 *   - **Fault isolation**: an STS outage or a bug in the SAS-token
 *     signing logic cannot crash the capability-issuer pod.
 *   - **Independent scaling**: blob-heavy workloads can scale
 *     storage-grant replicas without touching the JWT-signing service.
 *   - **Independent policy**: AWS_STORAGE_GRANT_ROLE_ARN and
 *     per-cloud configuration are scoped to this service; a policy
 *     change requires only a rolling restart of these pods.
 *   - **Separate rate limits**: the per-subject rate limiter
 *     here is independent of the capability-issuer's issuance limiter.
 *
 * # API
 *
 *   POST /api/v1/storage-grants
 *     Authorization: Bearer <capability-jwt>
 *     Content-Type: application/json
 *     { "agentId": "<agent-id>" }   ← informational, used in audit log
 *
 *     200: { "grants": StorageGrant[] }
 *     400: invalid / missing token or body
 *     401: JWT signature / expiry / issuer / audience check failed
 *     403: token does not contain any storage:// capabilities
 *     429: rate limit exceeded
 *     500/502: internal minting failure
 *
 *   GET  /health
 *   GET  /health/live
 *   GET  /health/ready
 *
 *   GET  /.well-known/storage-grant-service
 *     Returns service metadata (issuerDid, audience, enabled clouds).
 */

import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import * as jose from 'jose';
import {
  CapabilityError,
  CapabilityTokenPayload,
  ErrorCode,
  Logger,
  SIGNING_ALGORITHMS,
  SUPPORTED_SCHEMA_VERSIONS,
  StorageGrant,
  createLogger,
  parseBearerToken,
} from '@euno/common';
import { StorageGrantService } from '@euno/capability-issuer';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Options for {@link createStorageGrantApp}.
 *
 * Either `verificationKey` (for tests / static deployments) or
 * `jwksUri` (for production) must be provided; if both are supplied
 * `verificationKey` takes precedence.
 */
export interface StorageGrantAppOptions {
  /** Expected `iss` JWT claim — must match the capability-issuer's DID. */
  issuerDid: string;

  /**
   * Expected `aud` JWT claim.  Tokens issued by a capability-issuer
   * configured with `GATEWAY_AUDIENCE=tool-gateway:acme-corp` will
   * carry that value here.  The storage-grant service validates it so
   * tokens from another tenant's issuer are rejected.
   */
  audience: string;

  /**
   * Pre-imported `jose` verification key (KeyLike, Uint8Array, or
   * RemoteJWKSet / JWTVerifyGetKey function).  Suitable for unit tests
   * where no live JWKS endpoint is available.
   *
   * Production deployments should pass `jose.createRemoteJWKSet(...)`.
   */
  verificationKey?: jose.KeyLike | Uint8Array | jose.JWTVerifyGetKey;

  /**
   * JWKS URI of the capability-issuer (e.g.
   * `https://issuer.example.com/.well-known/jwks.json`).  Used to
   * create a `createRemoteJWKSet` when `verificationKey` is absent.
   */
  jwksUri?: string;

  /** Configured and enabled `StorageGrantService` instance. */
  storageGrantService: StorageGrantService;

  /** Optional logger (defaults to a new `createLogger` instance). */
  logger?: Logger;

  /** Service environment label, used in health responses. */
  environment?: string;

  /**
   * Maximum number of storage-grant requests per window per IP.
   * Defaults to 20 per 60-second window.  Each grant mints a
   * cloud STS session, so this limits the rate at which a
   * compromised token can produce new cloud credentials.
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

/**
 * Build and return the configured Express application.
 *
 * The returned app is not yet listening; callers call `app.listen(port)`
 * or pass it to a test runner.
 */
export function createStorageGrantApp(opts: StorageGrantAppOptions): express.Application {
  if (!opts.verificationKey && !opts.jwksUri) {
    throw new Error(
      'StorageGrantApp: either verificationKey or jwksUri must be provided for JWT verification',
    );
  }

  const log = opts.logger ?? createLogger('storage-grant-service', opts.environment ?? 'production');
  const environment = opts.environment ?? 'production';

  // Resolve the verification key once at app-construction time.
  // jose.jwtVerify has two overloads: one for KeyLike|Uint8Array, one for
  // JWTVerifyGetKey.  TypeScript can't narrow a union variable spanning both,
  // so we dispatch with an explicit type-guard helper.
  const verifyKey = opts.verificationKey ?? jose.createRemoteJWKSet(new URL(opts.jwksUri!));
  // jose.jwtVerify has two separate overloads (KeyLike vs JWTVerifyGetKey) with
  // different return types. TypeScript cannot resolve a union spanning both, so
  // we use a simple if/else to narrow verifyKey before each call, which avoids
  // any type cast while keeping the call-site readable.
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
  // This is a server-to-server internal microservice — disable the wildcard
  // CORS that cors() would set by default.  Allowed origins can be configured
  // via the `corsOptions` parameter if cross-origin browser access is ever
  // needed.  Leaving it closed is the secure default for internal services.
  app.use(cors({ origin: false }));
  app.use(express.json());

  // -------------------------------------------------------------------------
  // Health
  // -------------------------------------------------------------------------

  app.get('/health', (_req, res) => {
    res.json({ status: 'healthy', service: 'storage-grant-service' });
  });
  app.get('/health/live', (_req, res) => {
    res.json({ status: 'healthy', service: 'storage-grant-service' });
  });
  app.get('/health/ready', (_req, res) => {
    if (opts.storageGrantService.isEnabled()) {
      res.json({ status: 'ready', service: 'storage-grant-service' });
    } else {
      res.status(503).json({ status: 'not_ready', reason: 'storageGrantService not enabled' });
    }
  });

  // -------------------------------------------------------------------------
  // Service metadata
  // -------------------------------------------------------------------------

  app.get('/.well-known/storage-grant-service', (_req, res) => {
    res.json({
      service: 'storage-grant-service',
      issuerDid: opts.issuerDid,
      audience: opts.audience,
      environment,
      endpoints: { storageGrants: '/api/v1/storage-grants' },
    });
  });

  // -------------------------------------------------------------------------
  // POST /api/v1/storage-grants
  // -------------------------------------------------------------------------

  const rateLimitMax = opts.rateLimitMaxPerWindow ?? 20;
  // Per-IP rate limiter: caps the rate at which a single IP can mint cloud
  // STS credentials, independent of the capability-issuer's rate limiter.
  // This is the service's own backstop — an attacker who obtained many
  // valid tokens is still bounded in how fast they can convert them to
  // long-lived STS sessions.
  const storageGrantLimiter = rateLimit({
    windowMs: opts.rateLimitWindowMs ?? 60_000,
    max: rateLimitMax,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (_req, res) => {
      res.status(429).json({
        error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Storage-grant rate limit exceeded' },
      });
    },
    // Skip when: service disabled (returns 503 before any minting) OR
    // max === 0 (operator explicitly disabled rate limiting).
    skip: () => !opts.storageGrantService.isEnabled() || rateLimitMax === 0,
  });

  app.post('/api/v1/storage-grants', storageGrantLimiter, async (req: Request, res: Response, next: NextFunction) => {
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
      log.info('Storage grant request', {
        agentId,
        userId: payload.authorizedBy?.userId,
        capCount: payload.capabilities.length,
      });

      // 4. Reject if the token contains no storage:// capabilities —
      //    this is an operator misconfiguration or a mis-routed call.
      const hasStorage = payload.capabilities.some(
        (c) => typeof c.resource === 'string' && c.resource.startsWith('storage://'),
      );
      if (!hasStorage) {
        throw new CapabilityError(
          ErrorCode.INSUFFICIENT_PERMISSIONS,
          'Capability token does not grant any storage:// resources',
          403,
        );
      }

      // 5. Derive TTL from the token's remaining lifetime.
      const now = Math.floor(Date.now() / 1000);
      const capabilityTtlSeconds = Math.max(0, payload.exp - now);

      // 6. Mint storage grants.
      const grants: StorageGrant[] | undefined = await opts.storageGrantService.mintForCapabilities(
        payload.capabilities,
        {
          agentId: String(agentId),
          authorizedBy: payload.authorizedBy?.userId ?? String(agentId),
          capabilityTtlSeconds,
        },
      );

      res.json({ grants: grants ?? [] });
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
