/**
 * Admin API for API key management.
 *
 * Routes (all require admin authentication via X-Admin-Key header):
 *   POST   /admin/v1/keys          Create a new API key (returns raw key once)
 *   GET    /admin/v1/keys          List all keys for tenant (including revoked/expired)
 *   DELETE /admin/v1/keys/:prefix  Revoke a key
 */
import { Request, Response, NextFunction, Router } from 'express';
import * as crypto from 'crypto';
import {
  CapabilityError,
  ErrorCode,
  CapabilityConstraint,
  createLogger,
} from '@euno/common';
import { ApiKeyStore } from '../api-key-store';
import { generateApiKey } from '../api-key';
import { PepperEntry } from '../api-key-verifier';

type Logger = ReturnType<typeof createLogger>;

export interface AdminKeysRouterOptions {
  keyStore: ApiKeyStore;
  peppers: PepperEntry[];
  adminApiKey: string;
  logger: Logger;
}

function requireAdminAuth(adminApiKey: string): (req: Request, res: Response, next: NextFunction) => void {
  // Pre-compute a fixed-size HMAC of the expected key (using a zero key) so that
  // all comparisons are on 32-byte buffers regardless of the input length.
  // This eliminates the timing oracle that would otherwise leak the expected key length
  // when the provided value has a different byte length.
  const hmacKey = Buffer.alloc(32); // fixed zero key: we're normalising length, not doing MAC-as-auth
  const expectedHash = crypto.createHmac('sha256', hmacKey)
    .update(Buffer.from(adminApiKey, 'utf8'))
    .digest();

  return (req: Request, _res: Response, next: NextFunction): void => {
    const provided = req.headers['x-admin-key'];
    const fail = (): void => {
      next(new CapabilityError(ErrorCode.AUTHENTICATION_FAILED, 'Admin authentication required', 401));
    };

    // Always hash the provided value (empty string on missing header) and compare
    // against the expected hash.  Both paths call timingSafeEqual on 32-byte buffers,
    // so the comparison time does not depend on input length.
    const providedBuf = typeof provided === 'string' ? Buffer.from(provided, 'utf8') : Buffer.alloc(0);
    const providedHash = crypto.createHmac('sha256', hmacKey).update(providedBuf).digest();
    if (!crypto.timingSafeEqual(providedHash, expectedHash)) {
      fail();
      return;
    }
    next();
  };
}

interface CreateKeyBody {
  tenantId: string;
  policyId: string;
  capabilities: CapabilityConstraint[];
  scopes?: string[];
  label?: string;
  expiresAt?: string;
}

function parseCreateKeyBody(body: unknown): CreateKeyBody {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'Request body must be a JSON object', 400);
  }
  const b = body as Record<string, unknown>;
  if (typeof b['tenantId'] !== 'string' || b['tenantId'].length === 0) {
    throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'tenantId is required', 400);
  }
  if (typeof b['policyId'] !== 'string' || b['policyId'].length === 0) {
    throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'policyId is required', 400);
  }
  if (!Array.isArray(b['capabilities'])) {
    throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'capabilities must be an array', 400);
  }

  // Validate scopes: must be an array of non-empty strings when provided.
  let scopes: string[] = ['enforce'];
  if (b['scopes'] !== undefined) {
    if (
      !Array.isArray(b['scopes']) ||
      !(b['scopes'] as unknown[]).every((s) => typeof s === 'string' && s.length > 0)
    ) {
      throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'scopes must be an array of non-empty strings', 400);
    }
    scopes = b['scopes'] as string[];
  }

  // Validate expiresAt: must be a parseable ISO-8601 timestamp when provided.
  let expiresAt: string | undefined;
  if (b['expiresAt'] !== undefined) {
    if (typeof b['expiresAt'] !== 'string') {
      throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'expiresAt must be an ISO-8601 string', 400);
    }
    const ts = Date.parse(b['expiresAt']);
    if (!Number.isFinite(ts)) {
      throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'expiresAt is not a valid ISO-8601 timestamp', 400);
    }
    expiresAt = b['expiresAt'];
  }

  return {
    tenantId: b['tenantId'],
    policyId: b['policyId'],
    capabilities: b['capabilities'] as CapabilityConstraint[],
    scopes,
    label: typeof b['label'] === 'string' ? b['label'] : undefined,
    expiresAt,
  };
}

export function createAdminKeysRouter(opts: AdminKeysRouterOptions): Router {
  const router = Router();
  const auth = requireAdminAuth(opts.adminApiKey);

  const activePepper = opts.peppers[0];
  if (!activePepper) throw new Error('At least one pepper is required for API key issuance');

  // POST /admin/v1/keys — create a new API key
  router.post('/admin/v1/keys', auth, async (req: Request, res: Response, next: NextFunction) => {
    try {
      const body = parseCreateKeyBody(req.body);
      const { prefix, secret, raw } = generateApiKey();

      // HMAC-SHA256 with a 256-bit pepper is intentional for API key storage.
      // API keys are high-entropy random values, not user passwords.
      const keyDigest = crypto
        .createHmac('sha256', activePepper.key)
        .update(secret, 'utf8')
        .digest()
        .toString('base64url');

      await opts.keyStore.createKey({
        prefix,
        keyDigest,
        hmacKeyVersion: activePepper.version,
        tenantId: body.tenantId,
        policyId: body.policyId,
        capabilities: body.capabilities,
        scopes: body.scopes ?? ['enforce'],
        label: body.label,
        createdAt: new Date().toISOString(),
        expiresAt: body.expiresAt,
      });

      opts.logger.info('API key created', { tenantId: body.tenantId, prefix, policyId: body.policyId });

      res.status(201).json({
        prefix,
        raw,
        tenantId: body.tenantId,
        policyId: body.policyId,
        scopes: body.scopes ?? ['enforce'],
        createdAt: new Date().toISOString(),
        message: 'Store the raw API key securely. It will not be shown again.',
      });
    } catch (error) {
      next(error);
    }
  });

  // GET /admin/v1/keys?tenantId=... — list keys for tenant
  router.get('/admin/v1/keys', auth, async (req: Request, res: Response, next: NextFunction) => {
    try {
      const tenantId = req.query['tenantId'];
      if (typeof tenantId !== 'string' || tenantId.length === 0) {
        throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'tenantId query parameter is required', 400);
      }
      const keys = await opts.keyStore.listByTenant(tenantId);
      res.status(200).json({
        keys: keys.map(k => ({
          prefix: k.prefix,
          tenantId: k.tenantId,
          policyId: k.policyId,
          scopes: k.scopes,
          label: k.label,
          createdAt: k.createdAt,
          lastUsedAt: k.lastUsedAt,
          expiresAt: k.expiresAt,
          revokedAt: k.revokedAt,
        })),
      });
    } catch (error) {
      next(error);
    }
  });

  // DELETE /admin/v1/keys/:prefix — revoke a key
  router.delete('/admin/v1/keys/:prefix', auth, async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { prefix } = req.params;
      if (!prefix) {
        throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'prefix is required', 400);
      }
      const existing = await opts.keyStore.getByPrefix(prefix);
      if (!existing || existing.revokedAt !== undefined) {
        throw new CapabilityError(ErrorCode.AUTHENTICATION_FAILED, 'API key not found or already revoked', 404);
      }
      await opts.keyStore.revokeKey(prefix);
      opts.logger.info('API key revoked', { tenantId: existing.tenantId, prefix });
      res.status(200).json({ prefix, revokedAt: new Date().toISOString() });
    } catch (error) {
      next(error);
    }
  });

  return router;
}
