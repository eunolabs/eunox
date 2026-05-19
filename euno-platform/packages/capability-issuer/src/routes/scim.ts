/**
 * SCIM 2.0 provisioning router for the capability issuer.
 *
 * Mounted at `/scim/v2/` when `ISSUER_SCIM_BEARER_TOKEN` is configured.
 *
 * Endpoints:
 *   POST   /scim/v2/Users
 *   GET    /scim/v2/Users?filter=…
 *   GET    /scim/v2/Users/:id
 *   PUT    /scim/v2/Users/:id
 *   PATCH  /scim/v2/Users/:id
 *   DELETE /scim/v2/Users/:id
 *   POST   /scim/v2/Groups
 *   GET    /scim/v2/Groups?filter=…
 *   GET    /scim/v2/Groups/:id
 *   PUT    /scim/v2/Groups/:id
 *   PATCH  /scim/v2/Groups/:id
 *   DELETE /scim/v2/Groups/:id
 *
 * Authentication: `Authorization: Bearer <ISSUER_SCIM_BEARER_TOKEN>` verified
 * with `crypto.timingSafeEqual`. Wrong or absent token → 401 with
 * `WWW-Authenticate: Bearer realm="SCIM"`.
 *
 * SCIM schemas returned:
 *   - User:  `urn:ietf:params:scim:schemas:core:2.0:User`
 *   - Group: `urn:ietf:params:scim:schemas:core:2.0:Group`
 *   - ListResponse: `urn:ietf:params:scim:api:messages:2.0:ListResponse`
 *   - Error:        `urn:ietf:params:scim:api:messages:2.0:Error`
 *
 * See RFC 7644 for the SCIM protocol specification.
 */

import * as crypto from 'crypto';
import { Request, Response, NextFunction, Router } from 'express';
import { createLogger } from '@euno/common';
import type {
  IScimStore,
  ScimUser,
  ScimGroup,
} from '../scim-store';
import { parseScimFilter } from '../scim-store';

type Logger = ReturnType<typeof createLogger>;

// ── SCIM schema URNs ────────────────────────────────────────────────────────

const SCIM_USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const SCIM_GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';
const SCIM_LIST_RESPONSE = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
const SCIM_ERROR_RESPONSE = 'urn:ietf:params:scim:api:messages:2.0:Error';
const SCIM_PATCH_OP_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

// ── Options ─────────────────────────────────────────────────────────────────

export interface ScimRouterOptions {
  store: IScimStore;
  /**
   * Bearer token that authenticates incoming SCIM requests from the IdP.
   * Compared with `crypto.timingSafeEqual` to prevent timing attacks.
   */
  bearerToken: string;
  logger: Logger;
  /**
   * Optional tenant to scope all SCIM operations to.
   * When not set, operations are global (single-tenant deployments).
   */
  tenantId?: string;
}

// ── Serialisers ─────────────────────────────────────────────────────────────

function scimUserBody(user: ScimUser, baseUrl: string): Record<string, unknown> {
  return {
    schemas: [SCIM_USER_SCHEMA],
    id: user.id,
    externalId: user.externalId,
    userName: user.userName,
    displayName: user.displayName,
    active: user.active,
    meta: {
      resourceType: 'User',
      created: user.createdAt.toISOString(),
      lastModified: user.updatedAt.toISOString(),
      location: `${baseUrl}/Users/${user.id}`,
      version: `W/"${user.updatedAt.getTime()}"`,
    },
  };
}

function scimGroupBody(group: ScimGroup, baseUrl: string): Record<string, unknown> {
  return {
    schemas: [SCIM_GROUP_SCHEMA],
    id: group.id,
    displayName: group.displayName,
    meta: {
      resourceType: 'Group',
      created: group.createdAt.toISOString(),
      lastModified: group.updatedAt.toISOString(),
      location: `${baseUrl}/Groups/${group.id}`,
      version: `W/"${group.updatedAt.getTime()}"`,
    },
  };
}

function scimError(status: number, detail: string): Record<string, unknown> {
  return {
    schemas: [SCIM_ERROR_RESPONSE],
    status: String(status),
    detail,
  };
}

// ── Router factory ───────────────────────────────────────────────────────────

export function createScimRouter(opts: ScimRouterOptions): Router {
  const { store, bearerToken, logger } = opts;

  // Pre-compute the expected bearer token bytes for constant-time comparison.
  const expectedTokenBuf = Buffer.from(bearerToken, 'utf8');

  const router = Router({ mergeParams: true });

  // ── Auth middleware ────────────────────────────────────────────────────────
  function requireScimAuth(req: Request, res: Response, next: NextFunction): void {
    const authHeader = req.headers.authorization ?? '';
    const match = /^Bearer (.+)$/.exec(authHeader);
    if (!match) {
      res.setHeader('WWW-Authenticate', 'Bearer realm="SCIM"');
      res.status(401).json(scimError(401, 'Bearer token required'));
      return;
    }

    const suppliedBuf = Buffer.from(match[1]!, 'utf8');
    // Constant-time comparison regardless of lengths to prevent timing oracle.
    const tokensMatch =
      suppliedBuf.length === expectedTokenBuf.length &&
      crypto.timingSafeEqual(suppliedBuf, expectedTokenBuf);

    if (!tokensMatch) {
      res.setHeader('WWW-Authenticate', 'Bearer realm="SCIM"');
      res.status(401).json(scimError(401, 'Invalid bearer token'));
      return;
    }

    next();
  }

  router.use(requireScimAuth);

  // Derive the base URL from the request (used to populate `meta.location`).
  function baseUrl(req: Request): string {
    // Fall back to relative URL if protocol detection is unavailable.
    const proto = (req.headers['x-forwarded-proto'] as string | undefined) ?? req.protocol;
    return `${proto}://${req.headers.host}/scim/v2`;
  }

  // ── Helper: parse pagination params ────────────────────────────────────────
  function parsePagination(req: Request): { limit: number; offset: number } {
    const count = parseInt(String(req.query['count'] ?? '100'), 10);
    const startIndex = parseInt(String(req.query['startIndex'] ?? '1'), 10);
    return {
      limit: isNaN(count) || count < 1 ? 100 : Math.min(count, 1000),
      offset: isNaN(startIndex) || startIndex < 1 ? 0 : startIndex - 1,
    };
  }

  // ── Users ──────────────────────────────────────────────────────────────────

  // POST /scim/v2/Users
  router.post('/Users', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const body = req.body as Record<string, unknown>;
      const userName = body['userName'] as string | undefined;
      if (!userName) {
        res.status(400).json(scimError(400, '"userName" is required'));
        return;
      }

      const user = await store.createUser({
        externalId: body['externalId'] as string | undefined,
        userName,
        displayName: body['displayName'] as string | undefined,
        active: body['active'] !== false,
        tenantId: opts.tenantId,
      });

      logger.info('SCIM: user provisioned', { userId: user.id, userName: user.userName });
      res.status(201).location(`${baseUrl(req)}/Users/${user.id}`).json(scimUserBody(user, baseUrl(req)));
    } catch (err) {
      const scimStatus = (err as { scimStatus?: number }).scimStatus;
      if (scimStatus === 409 || (err instanceof Error && /unique/i.test(err.message))) {
        res.status(409).json(scimError(409, 'User already exists'));
        return;
      }
      next(err);
    }
  });

  // GET /scim/v2/Users
  router.get('/Users', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const filterStr = req.query['filter'] as string | undefined;
      let filter;
      if (filterStr) {
        try {
          filter = parseScimFilter(filterStr);
        } catch {
          res.status(400).json(scimError(400, `Invalid filter: ${filterStr}`));
          return;
        }
      }

      const { limit, offset } = parsePagination(req);
      const { users, totalCount } = await store.listUsers({
        filter,
        tenantId: opts.tenantId,
        limit,
        offset,
      });

      res.status(200).json({
        schemas: [SCIM_LIST_RESPONSE],
        totalResults: totalCount,
        startIndex: offset + 1,
        itemsPerPage: users.length,
        Resources: users.map((u) => scimUserBody(u, baseUrl(req))),
      });
    } catch (err) {
      next(err);
    }
  });

  // GET /scim/v2/Users/:id
  router.get('/Users/:id', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = await store.getUser(req.params['id']!, opts.tenantId);
      if (!user) {
        res.status(404).json(scimError(404, `User ${req.params['id']} not found`));
        return;
      }
      res.status(200).json(scimUserBody(user, baseUrl(req)));
    } catch (err) {
      next(err);
    }
  });

  // PUT /scim/v2/Users/:id
  router.put('/Users/:id', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const body = req.body as Record<string, unknown>;
      const userName = body['userName'] as string | undefined;
      if (!userName) {
        res.status(400).json(scimError(400, '"userName" is required'));
        return;
      }
      const user = await store.replaceUser(
        req.params['id']!,
        {
          externalId: body['externalId'] as string | undefined,
          userName,
          displayName: body['displayName'] as string | undefined,
          active: body['active'] !== false,
          tenantId: opts.tenantId,
        },
        opts.tenantId,
      );
      logger.info('SCIM: user replaced', { userId: user.id });
      res.status(200).json(scimUserBody(user, baseUrl(req)));
    } catch (err) {
      const scimStatus = (err as { scimStatus?: number }).scimStatus;
      if (scimStatus === 404) {
        res.status(404).json(scimError(404, `User ${req.params['id']} not found`));
        return;
      }
      next(err);
    }
  });

  // PATCH /scim/v2/Users/:id
  router.patch('/Users/:id', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const body = req.body as Record<string, unknown>;
      // Support both SCIM patch (Operations array) and direct partial-update.
      const operations = body['Operations'] as Array<{
        op: string;
        path?: string;
        value: unknown;
      }> | undefined;

      let patch: Record<string, unknown> = {};

      if (operations) {
        // Process SCIM PatchOp Operations.
        for (const op of operations) {
          const opLower = op.op?.toLowerCase();
          if (opLower === 'replace' || opLower === 'add') {
            if (op.path) {
              // Path-based operation (e.g. path="active", value=false).
              patch[op.path] = op.value;
            } else if (op.value && typeof op.value === 'object') {
              // Value is an object map of attribute → value.
              Object.assign(patch, op.value);
            }
          }
        }
      } else {
        // Direct partial update (non-standard but accepted for simplicity).
        patch = { ...body };
        delete patch['schemas'];
        delete patch['id'];
        delete patch['meta'];
      }

      const schemas = (body['schemas'] as string[] | undefined) ?? [];
      if (schemas.length > 0 && !schemas.includes(SCIM_PATCH_OP_SCHEMA) && operations) {
        res.status(400).json(scimError(400, `Expected schema ${SCIM_PATCH_OP_SCHEMA}`));
        return;
      }

      const user = await store.patchUser(
        req.params['id']!,
        {
          externalId: (patch['externalId'] as string | undefined),
          userName: (patch['userName'] as string | undefined),
          displayName: (patch['displayName'] as string | undefined),
          active: (patch['active'] as boolean | undefined),
        },
        opts.tenantId,
      );
      logger.info('SCIM: user patched', { userId: user.id });
      res.status(200).json(scimUserBody(user, baseUrl(req)));
    } catch (err) {
      const scimStatus = (err as { scimStatus?: number }).scimStatus;
      if (scimStatus === 404) {
        res.status(404).json(scimError(404, `User ${req.params['id']} not found`));
        return;
      }
      next(err);
    }
  });

  // DELETE /scim/v2/Users/:id
  router.delete('/Users/:id', async (req: Request, res: Response, next: NextFunction) => {
    try {
      await store.deleteUser(req.params['id']!, opts.tenantId);
      logger.info('SCIM: user deprovisioned', { userId: req.params['id'] });
      res.status(204).send();
    } catch (err) {
      const scimStatus = (err as { scimStatus?: number }).scimStatus;
      if (scimStatus === 404) {
        res.status(404).json(scimError(404, `User ${req.params['id']} not found`));
        return;
      }
      next(err);
    }
  });

  // ── Groups ─────────────────────────────────────────────────────────────────

  // POST /scim/v2/Groups
  router.post('/Groups', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const body = req.body as Record<string, unknown>;
      const displayName = body['displayName'] as string | undefined;
      if (!displayName) {
        res.status(400).json(scimError(400, '"displayName" is required'));
        return;
      }

      const group = await store.createGroup({
        displayName,
        tenantId: opts.tenantId,
      });

      // Handle initial membership if provided.
      const memberRefs = body['members'] as Array<{ value: string }> | undefined;
      if (memberRefs && memberRefs.length > 0) {
        const memberIds = memberRefs.map((m) => m.value).filter(Boolean);
        if (memberIds.length > 0) {
          await store.patchGroupMembers(group.id, memberIds, [], opts.tenantId);
        }
      }

      logger.info('SCIM: group provisioned', { groupId: group.id, displayName: group.displayName });
      res.status(201).location(`${baseUrl(req)}/Groups/${group.id}`).json(scimGroupBody(group, baseUrl(req)));
    } catch (err) {
      const scimStatus = (err as { scimStatus?: number }).scimStatus;
      if (scimStatus === 409 || (err instanceof Error && /unique/i.test(err.message))) {
        res.status(409).json(scimError(409, 'Group already exists'));
        return;
      }
      next(err);
    }
  });

  // GET /scim/v2/Groups
  router.get('/Groups', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const filterStr = req.query['filter'] as string | undefined;
      let filter;
      if (filterStr) {
        try {
          filter = parseScimFilter(filterStr);
        } catch {
          res.status(400).json(scimError(400, `Invalid filter: ${filterStr}`));
          return;
        }
      }

      const { limit, offset } = parsePagination(req);
      const { groups, totalCount } = await store.listGroups({
        filter,
        tenantId: opts.tenantId,
        limit,
        offset,
      });

      res.status(200).json({
        schemas: [SCIM_LIST_RESPONSE],
        totalResults: totalCount,
        startIndex: offset + 1,
        itemsPerPage: groups.length,
        Resources: groups.map((g) => scimGroupBody(g, baseUrl(req))),
      });
    } catch (err) {
      next(err);
    }
  });

  // GET /scim/v2/Groups/:id
  router.get('/Groups/:id', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const group = await store.getGroup(req.params['id']!, opts.tenantId);
      if (!group) {
        res.status(404).json(scimError(404, `Group ${req.params['id']} not found`));
        return;
      }
      res.status(200).json(scimGroupBody(group, baseUrl(req)));
    } catch (err) {
      next(err);
    }
  });

  // PUT /scim/v2/Groups/:id
  router.put('/Groups/:id', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const body = req.body as Record<string, unknown>;
      const displayName = body['displayName'] as string | undefined;
      if (!displayName) {
        res.status(400).json(scimError(400, '"displayName" is required'));
        return;
      }

      const memberRefs = body['members'] as Array<{ value: string }> | undefined;
      const memberIds = memberRefs ? memberRefs.map((m) => m.value).filter(Boolean) : undefined;

      const group = await store.replaceGroup(
        req.params['id']!,
        { displayName, tenantId: opts.tenantId },
        memberIds,
      );

      logger.info('SCIM: group replaced', { groupId: group.id });
      res.status(200).json(scimGroupBody(group, baseUrl(req)));
    } catch (err) {
      const scimStatus = (err as { scimStatus?: number }).scimStatus;
      if (scimStatus === 404) {
        res.status(404).json(scimError(404, `Group ${req.params['id']} not found`));
        return;
      }
      next(err);
    }
  });

  // PATCH /scim/v2/Groups/:id
  router.patch('/Groups/:id', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const body = req.body as Record<string, unknown>;
      const operations = body['Operations'] as Array<{
        op: string;
        path?: string;
        value: unknown;
      }> | undefined;

      const addMembers: string[] = [];
      const removeMembers: string[] = [];
      let newDisplayName: string | undefined;

      if (operations) {
        for (const op of operations) {
          const opLower = op.op?.toLowerCase();
          if ((opLower === 'add' || opLower === 'replace') && op.path === 'members') {
            const vals = Array.isArray(op.value)
              ? (op.value as Array<{ value: string }>).map((v) => v.value)
              : [];
            addMembers.push(...vals.filter(Boolean));
          } else if (opLower === 'remove' && op.path === 'members') {
            const vals = Array.isArray(op.value)
              ? (op.value as Array<{ value: string }>).map((v) => v.value)
              : [];
            removeMembers.push(...vals.filter(Boolean));
          } else if ((opLower === 'replace' || opLower === 'add') && !op.path) {
            // Replace object-level attributes.
            const val = op.value as Record<string, unknown>;
            if (val?.['displayName']) {
              newDisplayName = val['displayName'] as string;
            }
          }
        }
      }

      // Apply displayName rename if present.
      if (newDisplayName) {
        await store.replaceGroup(
          req.params['id']!,
          { displayName: newDisplayName, tenantId: opts.tenantId },
        );
      }

      const group = await store.patchGroupMembers(
        req.params['id']!,
        addMembers,
        removeMembers,
        opts.tenantId,
      );

      logger.info('SCIM: group membership patched', {
        groupId: group.id,
        added: addMembers.length,
        removed: removeMembers.length,
      });
      res.status(200).json(scimGroupBody(group, baseUrl(req)));
    } catch (err) {
      const scimStatus = (err as { scimStatus?: number }).scimStatus;
      if (scimStatus === 404) {
        res.status(404).json(scimError(404, `Group ${req.params['id']} not found`));
        return;
      }
      next(err);
    }
  });

  // DELETE /scim/v2/Groups/:id
  router.delete('/Groups/:id', async (req: Request, res: Response, next: NextFunction) => {
    try {
      await store.deleteGroup(req.params['id']!, opts.tenantId);
      logger.info('SCIM: group deleted', { groupId: req.params['id'] });
      res.status(204).send();
    } catch (err) {
      const scimStatus = (err as { scimStatus?: number }).scimStatus;
      if (scimStatus === 404) {
        res.status(404).json(scimError(404, `Group ${req.params['id']} not found`));
        return;
      }
      next(err);
    }
  });

  return router;
}
