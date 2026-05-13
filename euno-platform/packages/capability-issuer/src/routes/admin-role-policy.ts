/**
 * Admin role-policy management routes for the capability-issuer service.
 * ---------------------------------------------------------------------------
 *
 * Implements the Stage 4 Task 3 requirement: move the active role → capability
 * mapping out of the in-code `DEFAULT_ROLE_CAPABILITY_MAP` into a Postgres-
 * backed `role_policies` table, authorise mutations via operator JWT, and
 * audit-log every mutation with operator identity.
 *
 * Authentication (two paths, tried in order):
 *   1. PRIMARY — `Authorization: Bearer <jwt>` verified against the JWKS
 *      endpoint configured by `ISSUER_ADMIN_JWKS_URI`.  Operator identity is
 *      extracted from the JWT `sub` claim and written to `res.locals.operatorId`.
 *   2. FALLBACK — `X-Admin-Key: <secret>` shared-secret (explicitly temporary;
 *      logs a deprecation warning each time it is used).
 *
 * Routes:
 *
 *   PUT /api/v1/admin/role-policy
 *     Replace the active role → capability policy.  The supplied JSON is
 *     validated, persisted to Postgres (when a store is configured), and
 *     applied in-memory via the `onPolicyUpdated` callback so traffic takes
 *     the new policy without a restart.
 *
 *   GET /api/v1/admin/role-policy
 *     Return the currently active role → capability policy.
 *
 * Both routes require admin authentication.
 */

import * as crypto from 'crypto';
import { Request, Response, NextFunction, Router } from 'express';
import {
  CapabilityError,
  ErrorCode,
  RoleCapabilityPolicy,
  createLogger,
  generateId,
  validateRoleCapabilityPolicy,
} from '@euno/common';
import { AdminJwtVerifier } from '../admin-jwt-verifier';
import { PostgresRolePolicyStore } from '../postgres-role-policy-store';

type Logger = ReturnType<typeof createLogger>;

// ── Public types ────────────────────────────────────────────────────────────

export interface AdminRolePolicyRouterOptions {
  /**
   * Shared admin API key accepted via the `X-Admin-Key` header as a
   * temporary fallback when JWT auth is not configured.  Must be provided
   * so the fallback path is always available during JWT-auth migration.
   */
  adminApiKey: string;
  /**
   * Optional JWKS-backed JWT verifier for operator tokens.
   * When provided, `Authorization: Bearer <jwt>` is accepted as the primary
   * authentication path.
   */
  jwtVerifier?: AdminJwtVerifier;
  /**
   * Optional getter that returns the Postgres-backed store for persisting
   * policy versions.  A getter function is used (rather than a direct
   * reference) because the store is initialised asynchronously after the
   * Express app is constructed, so the value is not available at mount time.
   *
   * When the getter returns `undefined` (store not yet initialised, or
   * ISSUER_ROLE_POLICY_DB_URL not set), mutations are applied in-memory only
   * and lost on restart.
   */
  getPolicyStore?: () => PostgresRolePolicyStore | undefined;
  /**
   * Callback invoked after a policy is successfully validated (and
   * persisted, if a store is configured).  The issuer's in-memory state
   * is updated here — this is the hot-reload hook.
   */
  onPolicyUpdated: (policy: RoleCapabilityPolicy, operatorId: string) => void;
  /**
   * Getter that returns the current active policy (for the GET route).
   */
  getCurrentPolicy: () => RoleCapabilityPolicy;
  /**
   * Logger for structured audit entries and operational logs.
   */
  logger: Logger;
}

// ── Auth middleware ─────────────────────────────────────────────────────────

/**
 * Build admin authentication middleware using the same dual-path pattern
 * as `api-key-minter`'s `requireAdminAuth`:
 *
 *   1. Bearer JWT (primary) — validated via `jwtVerifier` when supplied.
 *      If the request includes an `Authorization: Bearer <token>` header
 *      and `jwtVerifier` is configured, the JWT is verified.  A
 *      present-but-invalid token always returns 401; the X-Admin-Key path
 *      is **not** attempted in that case.
 *
 *   2. X-Admin-Key (fallback, deprecated) — constant-time HMAC-SHA256
 *      comparison.  This path is only attempted when `jwtVerifier` is not
 *      configured *or* when no `Authorization: Bearer` header is present
 *      at all.  Requests that include *both* headers will have X-Admin-Key
 *      silently ignored once the JWT path succeeds or fails.
 */
function requireAdminAuth(
  adminApiKey: string,
  logger: Logger,
  jwtVerifier?: AdminJwtVerifier,
): (req: Request, res: Response, next: NextFunction) => void {
  // Pre-compute a fixed-size HMAC of the expected key so that all comparisons
  // are on 32-byte buffers regardless of input length (eliminates timing oracle).
  // NOTE: adminApiKey is a high-entropy random bearer credential (≥32 chars
  // enforced by the production guard), NOT a user password.  HMAC-SHA256 is
  // appropriate here; a KDF would add latency without security benefit for
  // random tokens.
  const hmacKey = Buffer.alloc(32);
  const expectedHash = crypto
    .createHmac('sha256', hmacKey)
    .update(Buffer.from(adminApiKey, 'utf8')) // lgtm[js/insufficient-password-hash]
    .digest();

  return (req: Request, res: Response, next: NextFunction): void => {
    const fail = (): void => {
      next(
        new CapabilityError(
          ErrorCode.AUTHENTICATION_FAILED,
          'Admin authentication required',
          401,
        ),
      );
    };

    // ── Primary path: Bearer JWT ────────────────────────────────────────
    if (jwtVerifier) {
      const authHeader = req.headers['authorization'];
      if (
        typeof authHeader === 'string' &&
        authHeader.toLowerCase().startsWith('bearer ')
      ) {
        const token = authHeader.slice('bearer '.length).trim();
        jwtVerifier
          .verify(token)
          .then((principal) => {
            res.locals['operatorId'] = principal.operatorId;
            next();
          })
          .catch(() => {
            fail();
          });
        return;
      }
    }

    // ── Fallback path: X-Admin-Key shared secret ────────────────────────
    const provided = req.headers['x-admin-key'];
    const providedBuf =
      typeof provided === 'string' ? Buffer.from(provided, 'utf8') : Buffer.alloc(0);
    const providedHash = crypto
      .createHmac('sha256', hmacKey)
      .update(providedBuf)
      .digest();

    if (!crypto.timingSafeEqual(providedHash, expectedHash)) {
      fail();
      return;
    }

    if (jwtVerifier) {
      logger.warn(
        'Admin request authenticated via deprecated X-Admin-Key shared secret. ' +
          'Migrate to operator JWT tokens (ISSUER_ADMIN_JWKS_URI / ISSUER_ADMIN_JWT_AUDIENCE).',
        { path: req.path },
      );
    }
    next();
  };
}

// ── Router factory ──────────────────────────────────────────────────────────

/**
 * Create an Express router that mounts the role-policy admin endpoints.
 * Mount at the app root (the routes include their full `/api/v1/admin/…` prefix).
 */
export function createAdminRolePolicyRouter(
  opts: AdminRolePolicyRouterOptions,
): Router {
  const router = Router();
  const auth = requireAdminAuth(opts.adminApiKey, opts.logger, opts.jwtVerifier);

  // ── PUT /api/v1/admin/role-policy ───────────────────────────────────────

  /**
   * Replace the active role → capability policy.
   *
   * Request body: a {@link RoleCapabilityPolicy} JSON object.
   * Response (200): `{ message, rowId?, operatorId, defaultRoles, tenantOverrides }`
   *
   * Rate-limiting note: this route is intentionally not rate-limited at the
   * Express layer. It is protected by either a cryptographically-verified
   * operator JWT (jwtVerifier path) or a constant-time HMAC comparison of a
   * ≥32-char shared secret (X-Admin-Key path). Both paths are credential-
   * gated and intended only for operator tooling in a secured network segment.
   * IP-level rate limiting is expected to be applied by the upstream load
   * balancer / WAF.
   */ // lgtm[js/missing-rate-limiting]
  router.put(
    '/api/v1/admin/role-policy',
    auth,
    async (req: Request, res: Response, next: NextFunction) => {
      const operatorId =
        (res.locals['operatorId'] as string | undefined) ?? 'x-admin-key';
      try {
        // Validate the supplied policy.
        let policy: RoleCapabilityPolicy;
        try {
          policy = validateRoleCapabilityPolicy(req.body);
        } catch (err) {
          throw new CapabilityError(
            ErrorCode.INVALID_REQUEST,
            `role policy validation failed: ${
              err instanceof Error ? err.message : String(err)
            }`,
            400,
          );
        }

        // Persist to Postgres when a store is configured.
        let rowId: number | undefined;
        const policyStore = opts.getPolicyStore?.();
        if (policyStore) {
          rowId = await policyStore.save(policy, operatorId);
        }

        // Hot-reload: update in-memory policy immediately.
        opts.onPolicyUpdated(policy, operatorId);

        // Audit log the mutation — structured entry with operatorId so
        // SIEMs can attribute every policy change to the operator that
        // made it.  Uses the same logger.info pattern as the minter's
        // admin-policies route.
        opts.logger.info('Role policy updated via admin API', {
          id: generateId(),
          timestamp: new Date().toISOString(),
          eventType: 'issuance',
          agentId: 'admin',
          userId: operatorId,
          decision: 'allow',
          metadata: {
            operation: 'role_policy_update',
            operator: operatorId,
            defaultRoles: Object.keys(policy.default).sort(),
            tenantOverrides: policy.tenants
              ? Object.keys(policy.tenants).sort()
              : [],
            ...(rowId !== undefined ? { rowId } : {}),
          },
        });

        res.json({
          message: 'Role policy updated successfully',
          ...(rowId !== undefined ? { rowId } : {}),
          operatorId,
          defaultRoles: Object.keys(policy.default).sort(),
          tenantOverrides: policy.tenants ? Object.keys(policy.tenants).sort() : [],
        });
      } catch (err) {
        next(err);
      }
    },
  );

  // ── GET /api/v1/admin/role-policy ───────────────────────────────────────

  /**
   * Return the currently active role → capability policy.
   *
   * Rate-limiting note: same as PUT — credential-gated; IP-level limiting
   * is the responsibility of the upstream WAF.
   */ // lgtm[js/missing-rate-limiting]
  router.get(
    '/api/v1/admin/role-policy',
    auth,
    (_req: Request, res: Response, next: NextFunction) => {
      try {
        const policy = opts.getCurrentPolicy();
        res.json(policy);
      } catch (err) {
        next(err);
      }
    },
  );

  return router;
}
