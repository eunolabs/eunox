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
import { createProxyMiddleware, responseInterceptor } from 'http-proxy-middleware';
import {
  ActionResolver,
  BUILTIN_ACTION_RESOLVER,
  ValidateActionRequest,
  CapabilityError,
  ErrorCode,
  parseBearerToken,
  createLogger,
} from '@euno/common';
import { EnforcementEngine, EnforcementResult } from '../enforcement';

type Logger = ReturnType<typeof createLogger>;

/**
 * Reconstruct the full URL the *agent runtime* called when it sent
 * this request. Used as the canonical `htu` for DPoP proof
 * verification (F-2): the agent signed a proof bound to the URL it
 * dialled, which (after Express route mounting) is `<scheme>://<host>
 * /proxy<req.originalUrl-without-/proxy-prefix>`.
 *
 * Security boundary: we deliberately use Express's `req.protocol` and
 * `req.hostname`, which only honour `X-Forwarded-Proto` /
 * `X-Forwarded-Host` when `app.set('trust proxy', …)` has been
 * configured by the operator (see `TRUST_PROXY` in the gateway
 * config and `app-factory.ts`). Reading those headers
 * unconditionally would let any caller who can reach the gateway
 * directly spoof the proof's `htu` to whatever URL they chose to
 * sign — defeating the sender-constrained URL binding instead of
 * verifying the actual request target.
 *
 * Query string and fragment are preserved here — the verifier strips
 * them via `extractHtu` so both sides agree.
 */
function reconstructRequestUrl(req: Request): string {
  const proto = req.protocol || 'http';
  const host = req.hostname || 'localhost';
  return `${proto}://${host}${req.originalUrl}`;
}

export interface ProxyRouterOptions {
  enforcementEngine: EnforcementEngine;
  logger: Logger;
  backendServiceUrl: string;
  /**
   * Pluggable resolver used to derive the capability action from the
   * inbound HTTP request (R-7). When omitted, the in-process
   * {@link BUILTIN_ACTION_RESOLVER} preserves the legacy
   * `{ GET: read, POST: write, ... }` mapping.
   */
  actionResolver?: ActionResolver;
}

/**
 * Capability validation middleware. Exported separately so tests can exercise
 * the action/resource derivation logic without spinning a proxy target.
 */
export function createValidateCapabilityMiddleware(
  enforcementEngine: EnforcementEngine,
  actionResolver: ActionResolver = BUILTIN_ACTION_RESOLVER,
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

      // R-7 (I-4): derive the capability action from the injectable
      // ActionResolver instead of a fixed inline `actionMap`. The
      // default resolver reproduces the previous HTTP method →
      // action mapping (`GET → read`, `POST/PUT/PATCH → write`,
      // `DELETE → delete`); deployments that need to override (e.g.
      // a backend whose `POST /graphql` endpoint is read-style) ship
      // a JSON file via `ACTION_RESOLVER_FILE` and the same vocabulary
      // is honoured by the issuer at mint time.
      const action = actionResolver.fromHttpRequest({
        method: req.method,
        path: req.path,
        body: req.body,
        headers: req.headers as Record<string, string | string[] | undefined>,
      });

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
      // F-2: forward the DPoP proof + bound URL/method when the
      // client supplied a `DPoP` header. The full URL is reconstructed
      // from the inbound request because the proof's `htu` is
      // expected to bind to the URL the agent runtime called, not the
      // upstream backend URL the gateway proxies to.
      const dpopHeader = req.headers['dpop'];
      const dpopProof = Array.isArray(dpopHeader) ? dpopHeader[0] : dpopHeader;
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
        ...(typeof dpopProof === 'string' && dpopProof.length > 0
          ? {
              dpop: {
                proof: dpopProof,
                httpMethod: req.method,
                httpUrl: reconstructRequestUrl(req),
              },
            }
          : {}),
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
  // Normalise the optional resolver to a concrete instance once so the
  // middleware factory always receives a non-null `ActionResolver`
  // (matches the factory's parameter type, and avoids relying on the
  // default-parameter-on-undefined coercion at the call site).
  const actionResolver = opts.actionResolver ?? BUILTIN_ACTION_RESOLVER;
  const router = Router();

  router.use(
    createValidateCapabilityMiddleware(enforcementEngine, actionResolver),
    createProxyMiddleware({
      target: backendServiceUrl,
      changeOrigin: true,
      pathRewrite: {
        '^/proxy': '', // Remove /proxy prefix
      },
      // R-4 step 1: buffer the response so we can apply the matched
      // capability's response-time obligations (e.g. `redactFields`)
      // before it leaves the gateway. `responseInterceptor` swaps the
      // streaming pipe for a buffered one, so this only kicks in on
      // proxied responses (the JSON-only branch keeps the cost bounded).
      selfHandleResponse: true,
      onProxyReq: (proxyReq, req, _res) => {
        logger.info('Proxying request', {
          path: req.path,
          target: proxyReq.path,
        });
      },
      onProxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, _res) => {
        logger.info('Proxy response', {
          path: (req as Request).path,
          statusCode: proxyRes.statusCode,
        });
        const validation = (req as unknown as { capabilityValidation?: EnforcementResult })
          .capabilityValidation;
        const redactor = validation?.applyResponseRedactions;
        if (!redactor) {
          return responseBuffer;
        }
        // Only attempt redaction on JSON responses — silently passing
        // non-JSON bodies through preserves the existing contract for
        // streaming, binary, or text responses while letting the
        // common JSON path honour the obligation. A failed parse falls
        // back to the original buffer (we never want a malformed
        // upstream body to take the proxy down).
        const contentType = String(proxyRes.headers['content-type'] ?? '').toLowerCase();
        if (!contentType.includes('application/json')) {
          return responseBuffer;
        }
        try {
          const parsed = JSON.parse(responseBuffer.toString('utf8'));
          const redacted = redactor(parsed);
          return Buffer.from(JSON.stringify(redacted), 'utf8');
        } catch (err) {
          logger.warn('Skipping response redaction (body not parseable as JSON)', {
            path: (req as Request).path,
            error: err instanceof Error ? err.message : String(err),
          });
          return responseBuffer;
        }
      }),
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
