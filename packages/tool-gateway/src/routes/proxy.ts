/**
 * Proxy route
 * ---------------------------------------------------------------------------
 * Hosts the `validateCapabilityMiddleware` (capability token + action +
 * resource derivation) and a pair of `httpProxyMiddleware` instances that
 * forward approved requests to the configured backend.
 *
 * **Stream-by-default, buffer-on-obligation.** Two proxy middlewares are
 * built once at router-construction time:
 *
 *   - `streamingProxy` — the *default* path. No `selfHandleResponse`. The
 *     upstream response is piped through to the client byte-for-byte without
 *     buffering. Used for any request whose validated capability carries no
 *     response-time obligation (`applyResponseRedactions === undefined`). This
 *     is the common case (JSON APIs without `redactFields`, file downloads,
 *     NDJSON exports, SSE streams, opaque binary, …).
 *
 *   - `bufferedProxy` — the redaction path. `selfHandleResponse: true` with a
 *     custom `onProxyRes` ({@link buildBufferedOnProxyRes}) that enforces (in
 *     order):
 *       1. `text/event-stream` upstream → 502 `REDACTION_STREAM_UNSUPPORTED`
 *          (dedicated audit code so SSE-based bypass attempts are
 *          distinguishable from generic content-type mismatches);
 *       2. content-type registry lookup ({@link RedactionStrategy}); no
 *          match → 502 `REDACTION_CONTENT_TYPE_UNSUPPORTED`;
 *       3. declared `Content-Length` > cap → 502 `REDACTION_OVERSIZE` (no
 *          body bytes read at all);
 *       4. streaming byte-cap: chunks accumulated into an array and counted
 *          incrementally; first chunk to push total past the cap → socket
 *          destroyed, 502 `REDACTION_OVERSIZE` returned without ever holding
 *          the full body in memory;
 *       5. parse + redact + re-serialize via the matched strategy; parse
 *          failure → 502 `REDACTION_PARSE_ERROR`.
 *     Used only when the matched capability declares a response-time
 *     obligation; the obligation closure (`applyResponseRedactions`) is
 *     attached to the request by `createValidateCapabilityMiddleware`.
 *
 * A tiny dispatcher middleware between `validate` and the two proxies
 * inspects `req.capabilityValidation.applyResponseRedactions` and forwards
 * to the right proxy. Public surface (`/proxy/*`), audit semantics, and
 * fail-closed disposition are unchanged versus the previous always-buffered
 * implementation; the only behavioural difference is that responses without
 * a redaction obligation now stream end-to-end instead of being marshalled
 * through a per-request `Buffer.concat`.
 *
 * Mounted under `/proxy/*` by `app-factory.ts`.
 *
 * Part of R-2 from `docs/IMPROVEMENTS_AND_REFACTORING.md`.
 */

import * as zlib from 'zlib';
import { IncomingMessage, ServerResponse } from 'http';
import { Readable } from 'stream';
import { Request, Response, NextFunction, Router, RequestHandler } from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import {
  ActionResolver,
  BUILTIN_ACTION_RESOLVER,
  ValidateActionRequest,
  CapabilityError,
  ErrorCode,
  parseBearerToken,
  createLogger,
  createAuditLogger,
} from '@euno/common';
import { EnforcementEngine, EnforcementResult } from '../enforcement';
import {
  isStreamingMediaType,
  normalizeMimeType,
  selectRedactionStrategy,
} from './redaction-strategy';

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
  /**
   * Maximum upstream response body size (bytes) to buffer for redaction.
   * Responses larger than this limit that carry a redaction obligation
   * are refused with HTTP 502 (`REDACTION_OVERSIZE`) rather than passed
   * through unredacted. Default: 1 MiB.
   */
  responseRedactionMaxBytes?: number;
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
 * Prepare the Express response for a fail-closed 502 error body so clients
 * always receive a well-formed JSON response regardless of what headers the
 * upstream had set.  Specifically:
 *  - Set `Content-Type: application/json; charset=utf-8` so clients don't
 *    try to interpret the body using the upstream MIME type.
 *  - Remove `Content-Encoding` — the body has already been decompressed by
 *    `decompressProxyResponse`; leaving the header in place would cause
 *    clients to attempt to decompress the JSON error body and fail.
 *  - Remove `Transfer-Encoding` for the same reason (chunked upstream
 *    responses should not be re-chunked by the client after interception).
 *  The `Content-Length` header is set by the caller once the response body
 *  is known (the buffered path calls `res.end(buffer)` which sets it
 *  implicitly, or the caller sets it explicitly before calling `res.end`).
 */
function prepareErrorResponse(res: Response | ServerResponse, statusCode: number): void {
  if ('status' in res && typeof (res as Response).status === 'function') {
    (res as Response).status(statusCode);
  } else {
    (res as ServerResponse).statusCode = statusCode;
  }
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.removeHeader('Content-Encoding');
  res.removeHeader('Transfer-Encoding');
}

/**
 * Decompress a proxy response stream based on its Content-Encoding header.
 * Returns the raw stream when no encoding (or `identity`) is declared.
 *
 * The header value is normalized: lower-cased, trimmed, and arrays are
 * joined. Multiple comma-separated encodings (e.g. `gzip, deflate`) are not
 * supported and cause a throw so the caller can emit a fail-closed error
 * rather than silently passing compressed binary to the JSON parser.
 *
 * @throws {Error} when the upstream uses an encoding we cannot decompress.
 */
function decompressProxyResponse(proxyRes: IncomingMessage): Readable {
  const rawEncoding = proxyRes.headers['content-encoding'];
  // Normalize: arrays (multiple header lines) are trimmed and joined with a
  // comma so the comma-check below catches both `['gzip', 'br']` and
  // `'gzip, br'` uniformly.
  const encoding = (Array.isArray(rawEncoding)
    ? rawEncoding.map((s) => s.trim()).join(',')
    : rawEncoding ?? ''
  )
    .trim()
    .toLowerCase();

  // No encoding or explicit identity → return raw stream as-is.
  if (!encoding || encoding === 'identity') {
    return proxyRes;
  }

  // Comma-separated list (multiple encodings) — we don't chain decompressors.
  if (encoding.includes(',')) {
    throw new Error(
      `Unsupported multi-value Content-Encoding: ${encoding}`,
    );
  }

  switch (encoding) {
    case 'gzip':
      return proxyRes.pipe(zlib.createGunzip());
    case 'br':
      return proxyRes.pipe(zlib.createBrotliDecompress());
    case 'deflate':
      return proxyRes.pipe(zlib.createInflate());
    default:
      throw new Error(`Unsupported Content-Encoding: ${encoding}`);
  }
}

/**
 * Copy upstream response headers to the outbound response, stripping
 * `content-encoding`, `transfer-encoding`, and `content-length` (the caller
 * sets `content-length` from the redacted body size; the other two are
 * meaningless after decompression + redaction).
 */
function copyUpstreamHeaders(proxyRes: IncomingMessage, res: ServerResponse): void {
  res.statusCode = proxyRes.statusCode ?? 200;
  if (proxyRes.statusMessage) res.statusMessage = proxyRes.statusMessage;
  const stripHeaders = new Set(['content-encoding', 'transfer-encoding', 'content-length']);
  for (const [key, value] of Object.entries(proxyRes.headers)) {
    if (stripHeaders.has(key) || value === undefined) continue;
    if (key === 'set-cookie') {
      // Strip Domain attribute from Set-Cookie headers (same behaviour as
      // http-proxy-middleware's own responseInterceptor).
      // Split on semicolons, drop the Domain= attribute, then rejoin — this
      // avoids leaving stray semicolons or double-spaces when the attribute
      // appears in the middle or end of the cookie string.
      const cookies = (Array.isArray(value) ? value : [value]).map((c) =>
        typeof c === 'string'
          ? c
              .split(/;\s*/)
              .filter((attr) => !/^Domain=/i.test(attr.trim()))
              .join('; ')
          : c,
      );
      res.setHeader(key, cookies as string[]);
    } else {
      res.setHeader(key, value);
    }
  }
}

/**
 * Builds the `onProxyRes` callback for `bufferedProxy`.
 *
 * This replaces the library-provided `responseInterceptor` so we can:
 *
 *  1. **Early-abort on declared Content-Length** — if the upstream signals a
 *     body larger than `responseRedactionMaxBytes` via its `Content-Length`
 *     header, we destroy the socket immediately and return a 502 without ever
 *     reading a single byte of the body.
 *
 *  2. **Streaming byte-cap** — chunks are accumulated into an array and their
 *     total length is tracked incrementally. As soon as the cap is exceeded,
 *     the upstream pipe is destroyed and a 502 is written.  This bounds peak
 *     memory to `responseRedactionMaxBytes + one final chunk` rather than the
 *     full response body.
 *
 *  3. **O(n) accumulation** — using `chunks.push(chunk)` + a single
 *     `Buffer.concat(chunks)` on `end` avoids the quadratic allocation pattern
 *     in the library's own `Buffer.concat([buffer, chunk])` per-chunk loop.
 */
function buildBufferedOnProxyRes(
  responseRedactionMaxBytes: number,
  logger: Logger,
  auditLogger: ReturnType<typeof createAuditLogger>,
): (proxyRes: IncomingMessage, req: Request, res: Response) => void {
  return function onProxyRes(proxyRes, req, res): void {
    const mimeType = normalizeMimeType(String(proxyRes.headers['content-type'] ?? ''));
    const validation = (req as unknown as { capabilityValidation?: EnforcementResult })
      .capabilityValidation;
    const redactor = validation?.applyResponseRedactions;

    logger.info('Proxy response (redaction path)', {
      path: req.path,
      statusCode: proxyRes.statusCode,
      mimeType,
      redactionRequired: !!redactor,
    });

    // ── No obligation: passthrough ───────────────────────────────────────
    // The dispatcher should have sent this to streamingProxy; handle
    // gracefully just in case.
    if (!redactor) {
      auditLogger.info('Proxy response transmitted', {
        eventType: 'proxy_response',
        path: req.path,
        statusCode: proxyRes.statusCode,
        contentType: mimeType,
        redactionApplied: false,
      });
      // Forward ALL upstream headers (including content-encoding and
      // transfer-encoding) unchanged — we are piping the raw compressed/
      // chunked body, so stripping those headers would corrupt the response.
      const rawRes = res as unknown as ServerResponse;
      rawRes.statusCode = proxyRes.statusCode ?? 200;
      if (proxyRes.statusMessage) rawRes.statusMessage = proxyRes.statusMessage;
      for (const [key, value] of Object.entries(proxyRes.headers)) {
        if (value !== undefined) rawRes.setHeader(key, value);
      }
      (proxyRes as NodeJS.ReadableStream).pipe(res as unknown as NodeJS.WritableStream);
      return;
    }

    // ── SSE: dedicated fail-closed code ─────────────────────────────────
    if (isStreamingMediaType(mimeType)) {
      logger.warn(
        'Refusing to proxy SSE response: redaction required but upstream is text/event-stream',
        { path: req.path, mimeType },
      );
      auditLogger.warn('Proxy response blocked — redaction_stream_unsupported', {
        eventType: 'proxy_response_blocked',
        path: req.path,
        statusCode: proxyRes.statusCode,
        contentType: mimeType,
        blockReason: 'redaction_stream_unsupported',
        redactionApplied: false,
      });
      proxyRes.destroy();
      prepareErrorResponse(res, 502);
      res.end(
        Buffer.from(
          JSON.stringify({
            error: {
              code: 'REDACTION_STREAM_UNSUPPORTED',
              message:
                'Gateway cannot apply required redaction: response is a Server-Sent Events stream',
            },
          }),
          'utf8',
        ),
      );
      return;
    }

    // ── Content-type strategy lookup ─────────────────────────────────────
    const strategy = selectRedactionStrategy(mimeType);
    if (!strategy) {
      logger.warn(
        'Refusing to proxy response: redaction required but content-type is not supported',
        { path: req.path, mimeType },
      );
      auditLogger.warn('Proxy response blocked — redaction_content_type_unsupported', {
        eventType: 'proxy_response_blocked',
        path: req.path,
        statusCode: proxyRes.statusCode,
        contentType: mimeType,
        blockReason: 'redaction_content_type_unsupported',
        redactionApplied: false,
      });
      proxyRes.destroy();
      prepareErrorResponse(res, 502);
      res.end(
        Buffer.from(
          JSON.stringify({
            error: {
              code: 'REDACTION_CONTENT_TYPE_UNSUPPORTED',
              message: 'Gateway cannot apply required redaction: response content-type is not JSON',
            },
          }),
          'utf8',
        ),
      );
      return;
    }

    // ── Early Content-Length check ───────────────────────────────────────
    const declaredLengthRaw = proxyRes.headers['content-length'];
    const declaredLength =
      declaredLengthRaw !== undefined ? parseInt(String(declaredLengthRaw), 10) : NaN;
    if (!isNaN(declaredLength) && declaredLength > responseRedactionMaxBytes) {
      logger.warn('Refusing to proxy response: declared content-length exceeds redaction size limit', {
        path: req.path,
        declaredLength,
        limit: responseRedactionMaxBytes,
      });
      auditLogger.warn('Proxy response blocked — redaction_oversize', {
        eventType: 'proxy_response_blocked',
        path: req.path,
        statusCode: proxyRes.statusCode,
        responseSize: declaredLength,
        contentType: mimeType,
        blockReason: 'redaction_oversize',
        redactionApplied: false,
      });
      proxyRes.destroy();
      prepareErrorResponse(res, 502);
      res.end(
        Buffer.from(
          JSON.stringify({
            error: {
              code: 'REDACTION_OVERSIZE',
              message: 'Gateway cannot apply required redaction: response body exceeds size limit',
            },
          }),
          'utf8',
        ),
      );
      return;
    }

    // ── Streaming accumulation with live byte-cap ────────────────────────
    // decompressProxyResponse may throw for unsupported Content-Encoding
    // values; treat that as a fail-closed error rather than letting a
    // compressed body silently reach the JSON parser.
    let bodyStream: Readable;
    try {
      bodyStream = decompressProxyResponse(proxyRes);
    } catch (encodingErr) {
      proxyRes.destroy();
      logger.warn('Refusing to proxy response: unsupported Content-Encoding', {
        path: req.path,
        contentEncoding: proxyRes.headers['content-encoding'],
        error: encodingErr instanceof Error ? encodingErr.message : String(encodingErr),
      });
      auditLogger.warn('Proxy response blocked — redaction_parse_error', {
        eventType: 'proxy_response_blocked',
        path: req.path,
        statusCode: proxyRes.statusCode,
        contentType: mimeType,
        blockReason: 'redaction_parse_error',
        redactionApplied: false,
      });
      prepareErrorResponse(res, 502);
      res.end(
        Buffer.from(
          JSON.stringify({
            error: {
              code: 'REDACTION_PARSE_ERROR',
              message: 'Gateway cannot apply required redaction: response body is not valid JSON',
            },
          }),
          'utf8',
        ),
      );
      return;
    }

    const chunks: Buffer[] = [];
    let accumulated = 0;
    let responded = false;

    bodyStream.on('data', (chunk: Buffer) => {
      if (responded) return;
      accumulated += chunk.length;
      if (accumulated > responseRedactionMaxBytes) {
        responded = true;
        // Destroy both the decompressor stream and the underlying socket so
        // the upstream stops sending data — destroying only the decompressor
        // does not close the TCP connection when bodyStream !== proxyRes.
        bodyStream.destroy();
        proxyRes.destroy();
        logger.warn('Refusing to proxy response: body exceeds redaction size limit', {
          path: req.path,
          accumulated,
          limit: responseRedactionMaxBytes,
        });
        auditLogger.warn('Proxy response blocked — redaction_oversize', {
          eventType: 'proxy_response_blocked',
          path: req.path,
          statusCode: proxyRes.statusCode,
          responseSize: accumulated,
          contentType: mimeType,
          blockReason: 'redaction_oversize',
          redactionApplied: false,
        });
        prepareErrorResponse(res, 502);
        res.end(
          Buffer.from(
            JSON.stringify({
              error: {
                code: 'REDACTION_OVERSIZE',
                message:
                  'Gateway cannot apply required redaction: response body exceeds size limit',
              },
            }),
            'utf8',
          ),
        );
        return;
      }
      chunks.push(chunk);
    });

    bodyStream.on('end', () => {
      if (responded) return;
      responded = true;
      const buffer = Buffer.concat(chunks);
      try {
        const redactedBuffer = strategy.apply(buffer, redactor);
        copyUpstreamHeaders(proxyRes, res as unknown as ServerResponse);
        res.setHeader('content-length', String(Buffer.byteLength(redactedBuffer)));
        auditLogger.info('Proxy response transmitted with redaction', {
          eventType: 'proxy_response',
          path: req.path,
          statusCode: proxyRes.statusCode,
          responseSize: buffer.length,
          redactedResponseSize: redactedBuffer.length,
          contentType: mimeType,
          redactionApplied: true,
        });
        res.end(redactedBuffer);
      } catch (err) {
        logger.warn('Response redaction failed (body not parseable)', {
          path: req.path,
          error: err instanceof Error ? err.message : String(err),
        });
        auditLogger.warn('Proxy response blocked — redaction_parse_error', {
          eventType: 'proxy_response_blocked',
          path: req.path,
          statusCode: proxyRes.statusCode,
          responseSize: buffer.length,
          contentType: mimeType,
          blockReason: 'redaction_parse_error',
          redactionApplied: false,
        });
        prepareErrorResponse(res, 502);
        res.end(
          Buffer.from(
            JSON.stringify({
              error: {
                code: 'REDACTION_PARSE_ERROR',
                message: 'Gateway cannot apply required redaction: response body is not valid JSON',
              },
            }),
            'utf8',
          ),
        );
      }
    });

    bodyStream.on('error', (err: Error) => {
      if (responded) return;
      responded = true;
      logger.error('Upstream body stream error during redaction', {
        path: req.path,
        error: err.message,
      });
      prepareErrorResponse(res, 502);
      res.end(
        Buffer.from(
          JSON.stringify({
            error: { code: 'PROXY_ERROR', message: 'Failed to proxy request to backend service' },
          }),
          'utf8',
        ),
      );
    });
  };
}

/**
 * Builds a router that mounts `validateCapabilityMiddleware` followed by the
 * HTTP reverse proxy. The router is mounted under `/proxy` by the factory, so
 * `req.path` inside the middleware is already the post-prefix path.
 *
 * Two proxy instances are built once and shared across requests:
 *   - `streamingProxy` — the default, no buffering; for requests with no
 *     response-time obligation.
 *   - `bufferedProxy` — `selfHandleResponse` + custom `onProxyRes`
 *     ({@link buildBufferedOnProxyRes}) for redaction.
 *
 * The dispatcher middleware routes between them based on whether the
 * validated capability attached a `applyResponseRedactions` closure.
 */
export function createProxyRouter(opts: ProxyRouterOptions): Router {
  const { enforcementEngine, logger, backendServiceUrl } = opts;
  const actionResolver = opts.actionResolver ?? BUILTIN_ACTION_RESOLVER;
  const responseRedactionMaxBytes = opts.responseRedactionMaxBytes ?? 1048576; // 1 MiB default
  const auditLogger = createAuditLogger('tool-gateway');
  const router = Router();

  // ── Streaming proxy ─────────────────────────────────────────────────────
  // Used when the capability carries no response-time obligation.
  // No selfHandleResponse, no responseInterceptor — the upstream pipe is
  // forwarded to the client byte-for-byte, so gzip/chunked headers and
  // arbitrarily large bodies all pass through without touching the GC.
  const streamingProxy = createProxyMiddleware({
    target: backendServiceUrl,
    changeOrigin: true,
    pathRewrite: { '^/proxy': '' },
    onProxyReq: (proxyReq, req) => {
      logger.info('Proxying request', { path: req.path, target: proxyReq.path });
    },
    onProxyRes: (proxyRes, req) => {
      auditLogger.info('Proxy response transmitted', {
        eventType: 'proxy_response',
        path: (req as Request).path,
        statusCode: proxyRes.statusCode,
        contentType: String(proxyRes.headers['content-type'] ?? ''),
        redactionApplied: false,
      });
    },
    onError: (err, req, res) => {
      logger.error('Proxy error', { path: req.path, error: err.message });
      (res as Response).status(502).json({
        error: { code: 'PROXY_ERROR', message: 'Failed to proxy request to backend service' },
      });
    },
  }) as RequestHandler;

  // ── Buffered proxy ──────────────────────────────────────────────────────
  // Used when the capability carries a response-time obligation (redactFields
  // or any other response-time condition). selfHandleResponse gives our custom
  // onProxyRes full ownership of the response so it can: enforce a streaming
  // byte-cap (early-abort before the body is fully received), decompress
  // once, and apply redaction before forwarding.
  const bufferedProxy = createProxyMiddleware({
    target: backendServiceUrl,
    changeOrigin: true,
    pathRewrite: { '^/proxy': '' },
    selfHandleResponse: true,
    onProxyReq: (proxyReq, req) => {
      logger.info('Proxying request (redaction)', { path: req.path, target: proxyReq.path });
    },
    onProxyRes: buildBufferedOnProxyRes(responseRedactionMaxBytes, logger, auditLogger),
    onError: (err, req, res) => {
      logger.error('Proxy error', { path: req.path, error: err.message });
      (res as Response).status(502).json({
        error: { code: 'PROXY_ERROR', message: 'Failed to proxy request to backend service' },
      });
    },
  }) as RequestHandler;

  // ── Dispatcher ──────────────────────────────────────────────────────────
  // After validation, route to streaming or buffered proxy based on whether
  // the matched capability carries a response-time obligation.
  const dispatch = (req: Request, res: Response, next: NextFunction): void => {
    const validation = (req as unknown as { capabilityValidation?: EnforcementResult })
      .capabilityValidation;
    if (validation?.applyResponseRedactions) {
      bufferedProxy(req, res, next);
    } else {
      streamingProxy(req, res, next);
    }
  };

  router.use(
    createValidateCapabilityMiddleware(enforcementEngine, actionResolver),
    dispatch,
  );

  return router;
}
