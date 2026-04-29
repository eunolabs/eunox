/**
 * Proxy route
 * ---------------------------------------------------------------------------
 * Hosts the `validateCapabilityMiddleware` (capability token + action +
 * resource derivation) and the `httpProxyMiddleware` factory that forwards
 * approved requests to the configured backend.
 *
 * Mounted under `/proxy/*` by `app-factory.ts`.
 *
 * Part of R-2 from `docs/IMPROVEMENTS_AND_REFACTORING.md`.
 */

import { Request, Response, NextFunction, Router } from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import {
  ValidateActionRequest,
  CapabilityError,
  ErrorCode,
  parseBearerToken,
  createLogger,
} from '@euno/common';
import { EnforcementEngine } from '../enforcement';

type Logger = ReturnType<typeof createLogger>;

export interface ProxyRouterOptions {
  enforcementEngine: EnforcementEngine;
  logger: Logger;
  backendServiceUrl: string;
}

/**
 * Capability validation middleware. Exported separately so tests can exercise
 * the action/resource derivation logic without spinning a proxy target.
 */
export function createValidateCapabilityMiddleware(
  enforcementEngine: EnforcementEngine,
) {
  return async function validateCapabilityMiddleware(
    req: Request,
    _res: Response,
    next: NextFunction,
  ) {
    try {
      // Extract capability token from Authorization header
      const token = parseBearerToken(req.headers.authorization);
      if (!token) {
        throw new CapabilityError(
          ErrorCode.AUTHENTICATION_FAILED,
          'Authorization header with Bearer token is required',
          401,
        );
      }

      // Map HTTP method → action.
      // - GET -> read
      // - POST/PUT/PATCH -> write
      // - DELETE -> delete
      const actionMap: Record<string, string> = {
        GET: 'read',
        POST: 'write',
        PUT: 'write',
        PATCH: 'write',
        DELETE: 'delete',
      };
      const action = actionMap[req.method] || 'read';

      // Extract resource from path, deriving canonical api:// URI.
      // req.path has the /proxy prefix already stripped by Express route mounting.
      //
      // The agent runtime forwards the intended target host (from absolute URLs)
      // either as the first path segment OR as an X-Target-Host header. We
      // prefer the header (cheaper, more explicit) and cross-check the path
      // segment to detect tampering. If neither is supplied (e.g. a relative
      // path was used) we fall back to the legacy path-only resource so this
      // change is backwards compatible.
      const headerHost = (req.headers['x-target-host'] as string | undefined)?.trim();
      const rawPath = req.path.replace(/^\/+/, '');
      const firstSegment = rawPath.split('/')[0] || '';
      // A segment looks like a host if it passes a basic hostname/IP pattern.
      // We no longer require a dot so single-label names like `localhost` are
      // recognised; bracketed IPv6 addresses are also accepted.
      const looksLikeHost = /^(\[[\da-fA-F:]+\]|[A-Za-z0-9.\-]+)(:\d+)?$/.test(firstSegment);

      let resource: string;
      if (headerHost) {
        // Header explicitly identifies the host; use it.
        const pathHasHostSegment = firstSegment.toLowerCase() === headerHost.toLowerCase();
        // If the path encodes a *different* host segment, treat as tampered.
        if (looksLikeHost && !pathHasHostSegment) {
          throw new CapabilityError(
            ErrorCode.INVALID_REQUEST,
            'Mismatch between X-Target-Host header and proxy path host segment',
            400,
          );
        }
        const tail = pathHasHostSegment
          ? rawPath.slice(firstSegment.length).replace(/^\/+/, '')
          : rawPath;
        resource = `api://${headerHost}/${tail}`;
      } else if (looksLikeHost) {
        const tail = rawPath.slice(firstSegment.length).replace(/^\/+/, '');
        resource = `api://${firstSegment}/${tail}`;
      } else {
        resource = `api://${rawPath}`;
      }

      // Validate the action. The request body is included in the context
      // so that the enforcement engine can apply the matched capability's
      // `argumentSchema` (if any) — argument-level enforcement is a
      // first-class part of the gateway, not something callers have to
      // remember to invoke.
      const validationRequest: ValidateActionRequest = {
        token,
        action: action as ValidateActionRequest['action'],
        resource,
        context: {
          method: req.method,
          path: req.path,
          body: req.body,
          query: req.query,
        },
      };

      const result = await enforcementEngine.validateAction(validationRequest);

      if (!result.allowed) {
        throw new CapabilityError(
          ErrorCode.AUTHORIZATION_FAILED,
          result.reason || 'Action not allowed',
          403,
        );
      }

      // Attach validation result to request for downstream use
      (req as unknown as { capabilityValidation: typeof result }).capabilityValidation = result;

      next();
    } catch (error) {
      next(error);
    }
  };
}

/**
 * Builds a router that mounts `validateCapabilityMiddleware` followed by the
 * HTTP reverse proxy. The router is mounted under `/proxy` by the factory, so
 * `req.path` inside the middleware is already the post-prefix path.
 */
export function createProxyRouter(opts: ProxyRouterOptions): Router {
  const { enforcementEngine, logger, backendServiceUrl } = opts;
  const router = Router();

  router.use(
    createValidateCapabilityMiddleware(enforcementEngine),
    createProxyMiddleware({
      target: backendServiceUrl,
      changeOrigin: true,
      pathRewrite: {
        '^/proxy': '', // Remove /proxy prefix
      },
      onProxyReq: (proxyReq, req, _res) => {
        logger.info('Proxying request', {
          path: req.path,
          target: proxyReq.path,
        });
      },
      onProxyRes: (proxyRes, req, _res) => {
        logger.info('Proxy response', {
          path: req.path,
          statusCode: proxyRes.statusCode,
        });
      },
      onError: (err, req, res) => {
        logger.error('Proxy error', {
          path: req.path,
          error: err.message,
        });
        (res as Response).status(502).json({
          error: {
            code: 'PROXY_ERROR',
            message: 'Failed to proxy request to backend service',
          },
        });
      },
    }),
  );

  return router;
}
