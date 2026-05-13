/**
 * Admin API routes for manifest templates — Task 6 of Stage 4.
 *
 * All endpoints are under `/api/v1/admin/templates` and require an
 * operator JWT (same `Authorization: Bearer <jwt>` pattern as the minter
 * admin routes).  The `operatorId` claim from the JWT is persisted as
 * `created_by` / `assigned_by` on every mutation.
 *
 * Authentication (two paths, tried in order):
 *   1. PRIMARY — `Authorization: Bearer <jwt>` verified against the JWKS
 *      endpoint configured by `jwtVerifier`. Operator identity (sub) and
 *      tenant identity (tenantId claim) are extracted from the JWT.
 *   2. FALLBACK — `X-Admin-Key: <secret>` shared-secret (explicitly
 *      temporary; logs a deprecation warning each use).
 *
 * Endpoints:
 *   POST   /api/v1/admin/templates                        — create template
 *   GET    /api/v1/admin/templates                        — list templates
 *   GET    /api/v1/admin/templates/:id                    — fetch latest version
 *   GET    /api/v1/admin/templates/:id/versions/:version  — fetch specific version
 *   POST   /api/v1/admin/templates/:id/versions           — append new version
 *   POST   /api/v1/admin/templates/:id/assign             — assign to agents
 *   DELETE /api/v1/admin/templates/:id                    — soft-delete
 */

import * as crypto from 'crypto';
import * as jose from 'jose';
import { Router, Request, Response, NextFunction } from 'express';
import { CapabilityError, ErrorCode, createLogger } from '@euno/common';
import {
  ManifestTemplateStore,
  TemplateBinding,
  TemplateStoreError,
} from '../manifest-template-store';

type Logger = ReturnType<typeof createLogger>;

// ── JWT verifier ───────────────────────────────────────────────────────────

export interface IssuerAdminJwtVerifierOptions {
  jwksUri: string;
  audience: string;
  issuer?: string;
}

/** Resolved principal from a successfully verified operator JWT. */
export interface IssuerAdminPrincipal {
  /** JWT `sub` claim — the operator's stable user identifier. */
  operatorId: string;
  /**
   * Tenant ID for this operator, resolved from the `tenantId` claim
   * (or `tid` as the Azure AD alias). Falls back to `''` when absent
   * so callers can decide whether to accept un-scoped tokens.
   */
  tenantId: string;
  /** Whether the operator holds platform-admin privileges (`platformAdmin: true` claim). */
  isPlatformAdmin: boolean;
}

export class IssuerAdminJwtVerifier {
  private readonly keySet: ReturnType<typeof jose.createRemoteJWKSet>;
  private readonly audience: string;
  private readonly issuer: string | undefined;

  constructor(opts: IssuerAdminJwtVerifierOptions) {
    this.keySet = jose.createRemoteJWKSet(new URL(opts.jwksUri));
    this.audience = opts.audience;
    this.issuer = opts.issuer;
  }

  async verify(token: string): Promise<IssuerAdminPrincipal> {
    const verifyOptions: jose.JWTVerifyOptions = { audience: this.audience };
    if (this.issuer) verifyOptions.issuer = this.issuer;

    const { payload } = await jose.jwtVerify(token, this.keySet, verifyOptions);

    const operatorId =
      typeof payload.sub === 'string' && payload.sub.length > 0 ? payload.sub : undefined;
    if (!operatorId) {
      throw new Error('JWT is missing the `sub` claim required to identify the operator');
    }

    // Azure AD uses `tid`; standard OIDC uses `tenantId`.
    const tenantId =
      typeof payload['tenantId'] === 'string'
        ? payload['tenantId']
        : typeof payload['tid'] === 'string'
          ? payload['tid']
          : '';

    const isPlatformAdmin = payload['platformAdmin'] === true;

    return { operatorId, tenantId, isPlatformAdmin };
  }
}

export function createIssuerAdminJwtVerifier(
  env: Record<string, string | undefined>,
): IssuerAdminJwtVerifier | undefined {
  const jwksUri = env['ISSUER_ADMIN_JWKS_URI'];
  const audience = env['ISSUER_ADMIN_JWT_AUDIENCE'];
  if (!jwksUri || !audience) return undefined;
  return new IssuerAdminJwtVerifier({
    jwksUri,
    audience,
    issuer: env['ISSUER_ADMIN_JWT_ISSUER'],
  });
}

// ── Router options ─────────────────────────────────────────────────────────

export interface AdminTemplatesRouterOptions {
  store: ManifestTemplateStore;
  adminApiKey: string;
  logger: Logger;
  jwtVerifier?: IssuerAdminJwtVerifier;
}

// ── Auth middleware ────────────────────────────────────────────────────────

function requireAdminAuth(
  adminApiKey: string,
  logger: Logger,
  jwtVerifier?: IssuerAdminJwtVerifier,
): (req: Request, res: Response, next: NextFunction) => void {
  // Pre-compute HMAC so all comparisons are constant-time on 32-byte buffers.
  // lgtm[js/insufficient-password-hash]
  const hmacKey = Buffer.alloc(32);
  const expectedHash = crypto
    .createHmac('sha256', hmacKey) // lgtm[js/insufficient-password-hash]
    .update(Buffer.from(adminApiKey, 'utf8'))
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

    // ── Primary path: Bearer JWT ──────────────────────────────────────────
    if (jwtVerifier) {
      const authHeader = req.headers['authorization'];
      if (typeof authHeader === 'string' && authHeader.toLowerCase().startsWith('bearer ')) {
        const token = authHeader.slice('bearer '.length).trim();
        jwtVerifier
          .verify(token)
          .then((principal) => {
            res.locals['operatorId'] = principal.operatorId;
            res.locals['tenantId'] = principal.tenantId;
            res.locals['isPlatformAdmin'] = principal.isPlatformAdmin;
            next();
          })
          .catch(() => {
            fail();
          });
        return;
      }
    }

    // ── Fallback path: X-Admin-Key shared secret ──────────────────────────
    const provided = req.headers['x-admin-key'];
    const providedBuf =
      typeof provided === 'string' ? Buffer.from(provided, 'utf8') : Buffer.alloc(0);
    const providedHash = crypto.createHmac('sha256', hmacKey).update(providedBuf).digest();
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

/** Resolve the operatorId to use in mutations (defaults to '_unknown'). */
function getOperatorId(res: Response): string {
  return typeof res.locals['operatorId'] === 'string' ? res.locals['operatorId'] : '_unknown';
}

/** Resolve the tenantId from the JWT or the request body. */
function resolveTenantId(res: Response, body: Record<string, unknown>): string {
  // JWT path: tenantId from the verified JWT principal.
  if (typeof res.locals['tenantId'] === 'string' && res.locals['tenantId'].length > 0) {
    return res.locals['tenantId'] as string;
  }
  // Fallback (X-Admin-Key path): tenantId from the request body.
  if (typeof body['ownerTenantId'] === 'string' && body['ownerTenantId'].length > 0) {
    return body['ownerTenantId'] as string;
  }
  return '';
}

// ── Router factory ─────────────────────────────────────────────────────────

export function createAdminTemplatesRouter(opts: AdminTemplatesRouterOptions): Router {
  const router = Router();
  const auth = requireAdminAuth(opts.adminApiKey, opts.logger, opts.jwtVerifier);

  // Apply admin auth to all routes in this router.
  router.use(auth);

  // ── POST /api/v1/admin/templates — Create template ───────────────────────
  router.post('/', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const body = req.body as Record<string, unknown>;
      const ownerTenantId = resolveTenantId(res, body);
      if (!ownerTenantId) {
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          'ownerTenantId is required (from JWT tenantId claim or request body)',
          400,
        );
      }

      const name = body['name'];
      if (typeof name !== 'string' || name.trim().length === 0) {
        throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'name is required', 400);
      }
      if (name.length > 255) {
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          'name must be 255 characters or fewer',
          400,
        );
      }

      const manifest = body['manifest'];
      if (typeof manifest !== 'object' || manifest === null || Array.isArray(manifest)) {
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          'manifest must be an object',
          400,
        );
      }

      const { record, version } = await opts.store.createTemplate({
        ownerTenantId,
        name: name.trim(),
        manifest: manifest as Parameters<ManifestTemplateStore['createTemplate']>[0]['manifest'],
        createdBy: getOperatorId(res),
      });

      opts.logger.info('Template created', {
        templateId: record.templateId,
        operatorId: getOperatorId(res),
        policyHash: version.policyHash,
      });

      res.status(201).json({
        templateId: record.templateId,
        version: version.version,
        policyHash: version.policyHash,
        createdAt: version.createdAt,
      });
    } catch (err) {
      if (isPgUniqueViolation(err)) {
        next(
          new CapabilityError(
            ErrorCode.INVALID_REQUEST,
            'A template with that name already exists for this tenant',
            409,
          ),
        );
        return;
      }
      next(err);
    }
  });

  // ── GET /api/v1/admin/templates — List templates ─────────────────────────
  router.get('/', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const ownerTenantId = resolveTenantId(res, req.query as Record<string, unknown>);
      if (!ownerTenantId) {
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          'ownerTenantId is required',
          400,
        );
      }

      const cursor =
        typeof req.query['cursor'] === 'string' ? req.query['cursor'] : undefined;
      const limit =
        req.query['limit'] !== undefined ? parseInt(String(req.query['limit']), 10) : 50;
      const includeDeleted = req.query['includeDeleted'] === 'true';

      if (!Number.isFinite(limit) || limit < 1) {
        throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'limit must be a positive integer', 400);
      }

      const result = await opts.store.listTemplates(ownerTenantId, {
        cursor,
        limit,
        includeDeleted,
      });

      res.json({
        items: result.items.map((item) => ({
          templateId: item.templateId,
          name: item.name,
          latestVersion: item.latestVersion,
          policyHash: item.policyHash,
          createdAt: item.createdAt,
          deletedAt: item.deletedAt,
        })),
        nextCursor: result.nextCursor,
      });
    } catch (err) {
      next(err);
    }
  });

  // ── GET /api/v1/admin/templates/:id — Fetch latest version ───────────────
  router.get('/:id', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const ownerTenantId = resolveTenantId(res, req.query as Record<string, unknown>);
      if (!ownerTenantId) {
        throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'ownerTenantId is required', 400);
      }

      const result = await opts.store.getTemplate(req.params['id']!, ownerTenantId);
      if (!result) {
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          `Template ${req.params['id']} not found`,
          404,
        );
      }

      res.json({
        templateId: result.record.templateId,
        name: result.record.name,
        version: result.version.version,
        manifest: result.version.manifest,
        policyHash: result.version.policyHash,
        createdAt: result.record.createdAt,
        createdBy: result.version.createdBy,
        deletedAt: result.record.deletedAt,
      });
    } catch (err) {
      next(err);
    }
  });

  // ── GET /api/v1/admin/templates/:id/versions/:version — Fetch specific version
  router.get(
    '/:id/versions/:version',
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        const ownerTenantId = resolveTenantId(res, req.query as Record<string, unknown>);
        if (!ownerTenantId) {
          throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'ownerTenantId is required', 400);
        }

        const version = parseInt(req.params['version']!, 10);
        if (!Number.isFinite(version) || version < 1) {
          throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'version must be a positive integer', 400);
        }

        const result = await opts.store.getTemplateVersion(
          req.params['id']!,
          version,
          ownerTenantId,
        );
        if (!result) {
          throw new CapabilityError(
            ErrorCode.INVALID_REQUEST,
            `Template ${req.params['id']} version ${version} not found`,
            404,
          );
        }

        res.json({
          templateId: result.record.templateId,
          name: result.record.name,
          version: result.version.version,
          manifest: result.version.manifest,
          policyHash: result.version.policyHash,
          createdAt: result.record.createdAt,
          createdBy: result.version.createdBy,
          deletedAt: result.record.deletedAt,
        });
      } catch (err) {
        next(err);
      }
    },
  );

  // ── POST /api/v1/admin/templates/:id/versions — Append new version ────────
  router.post(
    '/:id/versions',
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        const ownerTenantId = resolveTenantId(res, req.body as Record<string, unknown>);
        if (!ownerTenantId) {
          throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'ownerTenantId is required', 400);
        }

        const manifest = (req.body as Record<string, unknown>)['manifest'];
        if (typeof manifest !== 'object' || manifest === null || Array.isArray(manifest)) {
          throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'manifest must be an object', 400);
        }

        const version = await opts.store.appendVersion({
          templateId: req.params['id']!,
          ownerTenantId,
          manifest: manifest as Parameters<ManifestTemplateStore['createTemplate']>[0]['manifest'],
          createdBy: getOperatorId(res),
        });

        opts.logger.info('Template version appended', {
          templateId: req.params['id'],
          version: version.version,
          operatorId: getOperatorId(res),
          policyHash: version.policyHash,
        });

        res.status(201).json({
          templateId: version.templateId,
          version: version.version,
          policyHash: version.policyHash,
          createdAt: version.createdAt,
        });
      } catch (err) {
        if (err instanceof TemplateStoreError) {
          if (err.code === 'NOT_FOUND') {
            next(new CapabilityError(ErrorCode.INVALID_REQUEST, err.message, 404));
            return;
          }
          if (err.code === 'DELETED') {
            next(new CapabilityError(ErrorCode.INVALID_REQUEST, err.message, 409));
            return;
          }
        }
        next(err);
      }
    },
  );

  // ── POST /api/v1/admin/templates/:id/assign — Assign to agents ────────────
  router.post(
    '/:id/assign',
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        const body = req.body as Record<string, unknown>;
        const ownerTenantId = resolveTenantId(res, body);
        if (!ownerTenantId) {
          throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'ownerTenantId is required', 400);
        }

        const bindings = body['bindings'];
        if (!Array.isArray(bindings) || bindings.length === 0) {
          throw new CapabilityError(
            ErrorCode.INVALID_REQUEST,
            'bindings must be a non-empty array',
            400,
          );
        }

        const isPlatformAdmin = res.locals['isPlatformAdmin'] === true;

        // Validate bindings and check cross-tenant guard.
        const parsedBindings: TemplateBinding[] = [];
        for (const b of bindings as Record<string, unknown>[]) {
          if (typeof b['tenantId'] !== 'string' || b['tenantId'].length === 0) {
            throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'Each binding must have a tenantId', 400);
          }
          if (typeof b['agentId'] !== 'string' || b['agentId'].length === 0) {
            throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'Each binding must have an agentId', 400);
          }
          if (typeof b['role'] !== 'string' || b['role'].length === 0) {
            throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'Each binding must have a role', 400);
          }
          // Cross-tenant guard: bindings for a different tenant require platformAdmin.
          if (b['tenantId'] !== ownerTenantId && !isPlatformAdmin) {
            throw new CapabilityError(
              ErrorCode.INSUFFICIENT_PERMISSIONS,
              `Cross-tenant assignment to tenantId=${b['tenantId']} requires platformAdmin privilege`,
              403,
            );
          }
          parsedBindings.push({
            tenantId: b['tenantId'],
            agentId: b['agentId'],
            role: b['role'],
            version: typeof b['version'] === 'number' ? b['version'] : undefined,
          });
        }

        const results = await opts.store.assignTemplate(
          req.params['id']!,
          ownerTenantId,
          parsedBindings,
          getOperatorId(res),
        );

        const created = results
          .map((r, i) =>
            r.kind === 'created'
              ? {
                  assignmentId: r.assignmentId,
                  tenantId: parsedBindings[i]!.tenantId,
                  agentId: parsedBindings[i]!.agentId,
                  role: parsedBindings[i]!.role,
                  version: r.version,
                }
              : null,
          )
          .filter(Boolean);

        const skipped = results
          .map((r, i) =>
            r.kind === 'skipped'
              ? {
                  tenantId: parsedBindings[i]!.tenantId,
                  agentId: parsedBindings[i]!.agentId,
                  role: parsedBindings[i]!.role,
                  reason: r.reason,
                }
              : null,
          )
          .filter(Boolean);

        if (created.length > 0) {
          opts.logger.info('Template assigned', {
            templateId: req.params['id'],
            count: created.length,
            operatorId: getOperatorId(res),
          });
        }

        res.json({ created, skipped });
      } catch (err) {
        if (err instanceof TemplateStoreError) {
          if (err.code === 'NOT_FOUND') {
            next(new CapabilityError(ErrorCode.INVALID_REQUEST, err.message, 404));
            return;
          }
          if (err.code === 'DELETED') {
            next(new CapabilityError(ErrorCode.INVALID_REQUEST, err.message, 409));
            return;
          }
        }
        next(err);
      }
    },
  );

  // ── DELETE /api/v1/admin/templates/:id — Soft-delete ─────────────────────
  router.delete(
    '/:id',
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        const ownerTenantId = resolveTenantId(res, req.query as Record<string, unknown>);
        if (!ownerTenantId) {
          throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'ownerTenantId is required', 400);
        }

        const deletedAt = await opts.store.softDelete(req.params['id']!, ownerTenantId);

        if (!deletedAt) {
          throw new CapabilityError(
            ErrorCode.INVALID_REQUEST,
            `Template ${req.params['id']} not found`,
            404,
          );
        }

        opts.logger.info('Template deleted', {
          templateId: req.params['id'],
          operatorId: getOperatorId(res),
          deletedAt,
        });

        res.json({ templateId: req.params['id'], deletedAt });
      } catch (err) {
        if (err instanceof TemplateStoreError && err.code === 'ALREADY_DELETED') {
          next(new CapabilityError(ErrorCode.INVALID_REQUEST, err.message, 409));
          return;
        }
        next(err);
      }
    },
  );

  return router;
}

// ── Helpers ────────────────────────────────────────────────────────────────

function isPgUniqueViolation(err: unknown): boolean {
  if (typeof err === 'object' && err !== null) {
    const pg = err as { code?: string };
    return pg.code === '23505';
  }
  return false;
}
