/**
 * `POST /api/v1/enforce` route — hosted enforcement HTTP contract
 * ---------------------------------------------------------------------------
 * This route is the gateway side of the Stage-3 remote-enforcer protocol
 * (Task 9). `@euno/mcp` running in remote-enforcer mode (`enforcer:
 * "https://..."`) calls this endpoint on every intercepted `tools/call` and
 * applies the returned obligations locally before forwarding the upstream
 * response to the MCP client.
 *
 * **Deployment topology:**
 *
 *   Hosted:    @euno/mcp → (API key) → minter façade → (JWT) → this route
 *   Self-host: @euno/mcp → (JWT from operator's issuer) → this route
 *
 * This route always receives a **JWT Bearer token** in `Authorization`. The
 * minter façade (Task 10) is responsible for converting API keys to JWTs
 * before the request arrives here; this route never handles raw `sk-…` API
 * keys directly.
 *
 * Wire-protocol types (`EnforceRequest`, `EnforceResponse`, `Obligation`,
 * `DenialInfo`) live in `public/packages/common/src/wire.ts` so both the
 * gateway and the client (`@euno/mcp`) compile against the same definitions.
 *
 * Protocol documentation: docs/stage-3-gateway-protocol.md
 * Design RFC:             docs/stage-3-design.md §6
 * Execution plan:         docs/stage3executionplan.md §Task 9
 */

import * as crypto from 'crypto';
import { Request, Response, NextFunction, Router, RequestHandler } from 'express';
import express from 'express';
import {
  CapabilityConstraint,
  CapabilityError,
  ErrorCode,
  ENFORCE_PROTOCOL_VERSION,
  SUPPORTED_ENFORCE_PROTOCOL_VERSIONS,
  EnforceRequest,
  EnforceResponse,
  DenialInfo,
  Obligation,
  ValidateActionRequest,
  ActionResolver,
  BUILTIN_ACTION_RESOLVER,
  parseBearerToken,
  createLogger,
} from '@euno/common';
import { EnforcementEngine, EnforcementResult } from '../enforcement';
import type { GatewayTelemetryHooks } from '../gateway-telemetry';
import { extractTenantIdFromToken } from '../gateway-telemetry';

/** Maximum allowed request body size for POST /api/v1/enforce. */
const ENFORCE_REQUEST_SIZE_LIMIT_BYTES = 512 * 1024;

type Logger = ReturnType<typeof createLogger>;

export interface EnforceRouterOptions {
  enforcementEngine: EnforcementEngine;
  logger: Logger;
  /**
   * Pluggable resolver used to derive the capability action from the named
   * tool (mirrors the tools route). When omitted the built-in resolver is
   * used, which maps MCP tool names to the generic action vocabulary.
   */
  actionResolver?: ActionResolver;
  /**
   * Optional telemetry hooks (Task 16 — Telemetry continuity). When supplied,
   * each enforcement decision is recorded per-tenant so the gateway can emit
   * hosted-mode telemetry events that mirror the local-mode `TelemetryEvent`
   * schema. When omitted (or when `EUNO_TELEMETRY=0`), no telemetry is
   * collected.
   */
  telemetry?: GatewayTelemetryHooks;
  /**
   * Controls which IP address is used as the authoritative `sourceIp` for
   * `ipRange` policy conditions (CR-2 fix).
   *
   * - `'gateway'` (default): the gateway derives the effective IP from the
   *   TCP connection and `X-Forwarded-For` headers via `req.ip`, which already
   *   respects the Express `trust proxy` setting (`TRUST_PROXY` env var).
   *   The client-supplied `context.sourceIp` is ignored for enforcement.
   *   When the two values differ a `warn`-level log entry is emitted so
   *   spoofing attempts are always observable.
   *
   * - `'client'`: legacy behaviour — the gateway trusts the `sourceIp` value
   *   supplied in the request body's `context` field. Only safe when every
   *   caller is a trusted internal service that already enforces its own trust
   *   boundary (e.g. the minter façade overwriting the field from the observed
   *   connection). Using this mode in a self-hosted deployment where
   *   `@euno/mcp` clients connect directly is a security risk: any client can
   *   pass an arbitrary IP to bypass `ipRange` conditions.
   *
   * Wired from `ENFORCE_SOURCE_IP_MODE` in `initializeServices()`.
   */
  sourceIpMode?: 'gateway' | 'client';
}

// ---------------------------------------------------------------------------
// Request parsing helpers
// ---------------------------------------------------------------------------

/**
 * The set of context field names that are understood by the enforcement engine.
 * Unknown fields are stripped in {@link parseEnforceRequestBody} before the
 * request is passed to condition handlers or written to audit records.
 *
 * Declared as a module-level constant to avoid repeated allocation on every
 * request.
 */
const KNOWN_CONTEXT_FIELDS = new Set<string>(['sourceIp', 'recipients', 'now']);

/**
 * Normalize an IPv4-mapped IPv6 address (e.g. `::ffff:127.0.0.1`) to its
 * plain IPv4 form (`127.0.0.1`). Other addresses are returned unchanged.
 *
 * Node.js / Express surface IPv4-mapped IPv6 addresses when the TCP server
 * listens on a dual-stack socket. Policy conditions are typically written with
 * plain IPv4 CIDRs (e.g. `10.0.0.0/8`). Without normalization those CIDRs
 * would never match gateway-derived IPs from dual-stack sockets even when the
 * underlying client address is in the allowed range, because `ipMatchesCidr`
 * treats the two families as distinct.
 *
 * The normalization also ensures that the spoofing-detection comparison
 * in gateway mode is not polluted by representation differences: a client
 * sending `context.sourceIp = "127.0.0.1"` and a gateway deriving
 * `req.ip = "::ffff:127.0.0.1"` are the same address — no warning should
 * be emitted in that case.
 */
function normalizeIpv4Mapped(ip: string): string {
  const lower = ip.toLowerCase();
  const prefix = '::ffff:';
  if (lower.startsWith(prefix)) {
    const candidate = ip.slice(prefix.length);
    // Only strip the prefix when the remainder is a well-formed IPv4 address
    // (four decimal octets separated by dots) so we don't accidentally mangle
    // valid IPv6 addresses that happen to start with "::ffff:".
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(candidate)) {
      return candidate;
    }
  }
  return ip;
}

/**
 * Parse and validate the `X-Euno-Protocol-Version` header.
 *
 * - Missing header: treated as version 1 for backward compatibility with
 *   older clients that do not yet send the header.
 * - Non-integer or unsupported integer: throws `CapabilityError` with code
 *   `UNSUPPORTED_PROTOCOL_VERSION` (HTTP 400). The caller wraps this error
 *   into an `ErrorResponse` that includes the `supportedVersions` array.
 */
function parseProtocolVersion(header: string | string[] | undefined): number {
  const raw = Array.isArray(header) ? header[0] : header;
  if (raw === undefined || raw === '') {
    // Treat missing header as v1 — tolerate clients that predate the header
    // requirement but log so we can track adoption.
    return ENFORCE_PROTOCOL_VERSION;
  }
  const trimmed = raw.trim();
  const parsed = Number(trimmed);
  if (!Number.isInteger(parsed) || parsed <= 0 || String(parsed) !== trimmed) {
    throw new CapabilityError(
      ErrorCode.UNSUPPORTED_PROTOCOL_VERSION,
      `X-Euno-Protocol-Version must be a positive integer; received: ${raw}`,
      400,
    );
  }
  if (!SUPPORTED_ENFORCE_PROTOCOL_VERSIONS.has(parsed)) {
    throw new CapabilityError(
      ErrorCode.UNSUPPORTED_PROTOCOL_VERSION,
      `Protocol version ${parsed} is not supported by this gateway`,
      400,
    );
  }
  return parsed;
}

/**
 * Validate that the body is a well-formed `EnforceRequest`.
 *
 * Throws `CapabilityError(INVALID_REQUEST, ..., 400)` on any structural
 * violation. Uses runtime assertions rather than a full JSON-Schema validator
 * to keep the dependency surface minimal — the request shape is narrow and
 * stable.
 */
function parseEnforceRequestBody(body: unknown): EnforceRequest {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'Request body must be a JSON object', 400);
  }
  const b = body as Record<string, unknown>;

  if (typeof b.sessionId !== 'string' || b.sessionId.length === 0) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'sessionId is required and must be a non-empty string',
      400,
    );
  }
  if (typeof b.toolName !== 'string' || b.toolName.length === 0) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'toolName is required and must be a non-empty string',
      400,
    );
  }
  if (typeof b.arguments !== 'object' || b.arguments === null || Array.isArray(b.arguments)) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'arguments must be a JSON object',
      400,
    );
  }
  if (typeof b.context !== 'object' || b.context === null || Array.isArray(b.context)) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'context must be a JSON object',
      400,
    );
  }

  const ctx = b.context as Record<string, unknown>;

  if (ctx.sourceIp !== undefined && typeof ctx.sourceIp !== 'string') {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'context.sourceIp must be a string',
      400,
    );
  }
  if (ctx.recipients !== undefined) {
    if (
      !Array.isArray(ctx.recipients) ||
      !(ctx.recipients as unknown[]).every((r) => typeof r === 'string')
    ) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'context.recipients must be an array of strings',
        400,
      );
    }
  }
  if (ctx.now !== undefined && typeof ctx.now !== 'string') {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'context.now must be an ISO-8601 string',
      400,
    );
  }

  // Strip unknown context fields before passing the request to the enforcement
  // engine. Unknown fields are silently dropped — they are never read by any
  // condition handler and retaining them would allow untrusted client data to
  // pollute the ConditionContext and potentially reach log sinks or SIEM
  // pipelines in an unexpected shape.
  for (const key of Object.keys(ctx)) {
    if (!KNOWN_CONTEXT_FIELDS.has(key)) {
      delete ctx[key];
    }
  }

  return b as unknown as EnforceRequest;
}

/**
 * Reject requests where `context.now` diverges more than 60 seconds from the
 * gateway's wall-clock. The 60-second bound is the same as the DPoP clock-skew
 * tolerance documented in `verifyDpopProof`.
 *
 * **Gateway clock always wins for enforcement.**
 * The client-supplied `context.now` is validated here for sanity (to detect
 * wildly misconfigured clients and keep audit timestamps meaningful), but it
 * is NEVER passed to the condition registry as the enforcement clock. The
 * gateway sets `ctx.now` from its own `new Date()` at the point of evaluation,
 * so `timeWindow` conditions always use the gateway's authoritative wall-clock
 * regardless of what the client sends. Clients cannot manipulate time-based
 * access decisions.
 *
 * This check is purely a sanity guard on the client-supplied value and ensures
 * the audit event `activityTime` is not wildly misleading.
 */
function validateClockSkew(now: string | undefined): void {
  if (!now) return;
  const clientMs = Date.parse(now);
  if (!Number.isFinite(clientMs)) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      'context.now is not a valid ISO-8601 timestamp',
      400,
    );
  }
  const skewMs = Math.abs(Date.now() - clientMs);
  if (skewMs > 60_000) {
    throw new CapabilityError(
      ErrorCode.INVALID_REQUEST,
      `context.now deviates from the gateway clock by ${Math.round(skewMs / 1000)} s (maximum 60 s)`,
      400,
    );
  }
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

/**
 * Map an `ErrorCode` to a human-useful `conditionType` tag for `DenialInfo`.
 * The `conditionType` field is informational — the machine-readable field is
 * always `code`. Clients MUST NOT key authorisation logic off this tag.
 */
function deriveConditionType(code: string): string {
  switch (code) {
    case ErrorCode.AGENT_TERMINATED:
      return 'killSwitch';
    case ErrorCode.TOKEN_REVOKED:
    case ErrorCode.EXPIRED_TOKEN:
    case ErrorCode.INVALID_TOKEN:
    case ErrorCode.AUTHENTICATION_FAILED:
      return 'tokenVerification';
    case ErrorCode.RATE_LIMIT_EXCEEDED:
      return 'maxCalls';
    case ErrorCode.MISSING_CONTEXT:
      return 'missingContext';
    case ErrorCode.ARGUMENT_SCHEMA_VIOLATION:
      return 'argumentSchema';
    default:
      return 'policy';
  }
}

/**
 * Translate a `CapabilityError` into a `DenialInfo` for an in-band deny
 * response. Used for 4xx errors that represent a policy decision (e.g.
 * kill-switch, audience mismatch, rate-limit) rather than a protocol error.
 */
function capabilityErrorToDenialInfo(err: CapabilityError): DenialInfo {
  return {
    code: err.code,
    conditionType: deriveConditionType(err.code),
    message: err.message,
  };
}

/**
 * Extract obligations from the matched capability's conditions. The gateway
 * returns these to the client so the client can apply them locally to the
 * upstream response before forwarding to the MCP caller.
 *
 * Currently only `redactFields` conditions produce obligations.
 */
function buildObligations(capability: CapabilityConstraint | undefined): Obligation[] {
  if (!capability?.conditions) return [];
  const obligations: Obligation[] = [];
  for (const cond of capability.conditions) {
    if (cond.type === 'redactFields') {
      obligations.push({ type: 'redactFields', paths: cond.fields });
    }
  }
  return obligations;
}

/**
 * Build a `DenialInfo` from an `EnforcementResult` where `allowed === false`.
 * Uses the engine's `denialCode` / `denialConditionType` when present, falling
 * back to generic `AUTHORIZATION_FAILED` / `'policy'` for denials that do not
 * carry a structured code (e.g. simple capability-not-found).
 */
function enforcementResultToDenialInfo(result: EnforcementResult): DenialInfo {
  const code = result.denialCode ?? ErrorCode.AUTHORIZATION_FAILED;
  const conditionType = result.denialConditionType ?? deriveConditionType(code);
  return {
    code,
    conditionType,
    message: result.reason ?? 'Action not permitted by policy',
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extract the `X-Request-Id` header from the request (normalising the
 * multi-value header case) or generate a fresh UUID when absent.
 * Centralised here to ensure consistent behaviour across the main handler,
 * the payload-error handler, and the `replyWithCapabilityError` inner helper.
 */
function getOrGenerateRequestId(req: Request): string {
  const header = req.headers['x-request-id'];
  return (Array.isArray(header) ? header[0] : header) ?? crypto.randomUUID();
}

/**
 * Type augmentation for Express `Request` that allows the enforce route to
 * attach the resolved `requestId` to the request object so the global error
 * handler can include it in 500 responses without the route needing to start
 * a response before calling `next(err)`.
 */
interface EnforceRequest_ extends Request {
  enforceRequestId?: string;
}

// ---------------------------------------------------------------------------
// Body-parser middleware with 512 KiB limit and REQUEST_TOO_LARGE mapping
// ---------------------------------------------------------------------------

/**
 * `express.json()` middleware configured with the enforce endpoint's 512 KiB
 * body limit. When the body exceeds the limit the body-parser emits a
 * `PayloadTooLargeError` (status 413 / type `entity.too.large`). The
 * accompanying error handler ({@link enforcePayloadErrorHandler}) converts
 * that into the typed `REQUEST_TOO_LARGE` envelope.
 *
 * `strict: true` (the default) is set explicitly to document that only JSON
 * objects and arrays are accepted at the top level — primitives and other
 * non-object payloads are rejected by the body-parser before reaching the
 * route handler, which aligns with the `EnforceRequest` schema.
 *
 * This is intentionally a separate middleware (not the global `express.json()`
 * from `app-factory.ts`) so the 512 KiB limit is scoped to this endpoint only.
 * The router is mounted **before** the global body-parser in app-factory.ts so
 * that this per-route parser takes precedence and the global one is a no-op for
 * already-parsed bodies.
 */
const enforceBodyParser: RequestHandler = express.json({
  limit: ENFORCE_REQUEST_SIZE_LIMIT_BYTES,
  strict: true,
});

/**
 * Error handler that runs immediately after {@link enforceBodyParser} in the
 * router. Converts `entity.too.large` errors (HTTP 413) emitted by the body
 * parser into the typed `REQUEST_TOO_LARGE` response shape expected by the
 * protocol. All other errors are forwarded to the next error handler unchanged.
 */
function enforcePayloadErrorHandler(
  err: Error & { type?: string; status?: number },
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  if (err.type === 'entity.too.large' || err.status === 413) {
    const requestId = getOrGenerateRequestId(req);
    res.status(413).json({
      error: {
        code: ErrorCode.REQUEST_TOO_LARGE,
        message: `Request body exceeds the ${ENFORCE_REQUEST_SIZE_LIMIT_BYTES / 1024} KiB limit`,
        requestId,
      },
    });
    return;
  }
  next(err);
}

// ---------------------------------------------------------------------------
// Route factory
// ---------------------------------------------------------------------------

export function createEnforceRouter(opts: EnforceRouterOptions): Router {
  const { enforcementEngine, logger } = opts;
  const actionResolver = opts.actionResolver ?? BUILTIN_ACTION_RESOLVER;
  const telemetry = opts.telemetry;
  // Default to 'gateway' so new deployments get the secure behaviour.
  // Existing deployments that relied on the client-supplied value can opt back
  // in via ENFORCE_SOURCE_IP_MODE=client.
  const sourceIpMode = opts.sourceIpMode ?? 'gateway';
  const router = Router();

  // Mount the per-route body parser + its error handler so that
  // PayloadTooLargeError is caught before the main handler runs.
  router.use('/api/v1/enforce', enforceBodyParser);
  // 4-argument signature is required for Express to recognise this as an error handler
  router.use('/api/v1/enforce', enforcePayloadErrorHandler as express.ErrorRequestHandler);

  router.post(
    '/api/v1/enforce',
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      // Resolve the requestId early so every error path can echo it.
      const requestId = getOrGenerateRequestId(req);

      // Inner helper: serialize any CapabilityError (protocol-level validation
      // errors thrown before enforcement) as a self-contained JSON envelope
      // that includes requestId. This is the correct behaviour for errors like
      // INVALID_REQUEST (body validation, clock-skew guard) — they are not
      // enforcement decisions, but they do have a requestId the caller can log.
      function replyWithCapabilityError(err: CapabilityError): void {
        res.setHeader('X-Euno-Protocol-Version', String(ENFORCE_PROTOCOL_VERSION));
        res.status(err.statusCode).json({
          error: {
            code: err.code,
            message: err.message,
            requestId,
          },
        });
      }

      try {
        // ── 1. Protocol version negotiation ─────────────────────────────────
        // The version header is echoed on *every* response, including the
        // UNSUPPORTED_PROTOCOL_VERSION 400 so clients receive a machine-readable
        // signal that tells them both the error code and which versions to use.
        let protocolVersion: number;
        try {
          protocolVersion = parseProtocolVersion(req.headers['x-euno-protocol-version']);
        } catch (err) {
          if (err instanceof CapabilityError && err.code === ErrorCode.UNSUPPORTED_PROTOCOL_VERSION) {
            // Echo the *latest* supported version so clients can upgrade.
            res.setHeader('X-Euno-Protocol-Version', String(ENFORCE_PROTOCOL_VERSION));
            res.status(400).json({
              error: {
                code: err.code,
                message: err.message,
                requestId,
                supportedVersions: [...SUPPORTED_ENFORCE_PROTOCOL_VERSIONS],
              },
            });
            return;
          }
          throw err;
        }

        // Echo negotiated version on every response (success and error paths).
        res.setHeader('X-Euno-Protocol-Version', String(protocolVersion));

        // ── 2. Authentication — Bearer JWT capability token ──────────────────
        // See docs/stage-3-gateway-protocol.md §7 for the full authentication
        // flow. This route always receives a JWT; the minter façade (Task 10)
        // converts API keys to JWTs before requests reach this route.
        const token = parseBearerToken(req.headers.authorization);
        if (!token) {
          res.status(401).json({
            error: {
              code: ErrorCode.AUTHENTICATION_FAILED,
              message: 'Authorization header with Bearer token is required',
              requestId,
            },
          });
          return;
        }

        // ── 3. Content-Length fast-path size guard ──────────────────────────
        // The body-parser middleware (enforceBodyParser) already enforces the
        // 512 KiB limit and emits a PayloadTooLargeError for chunked uploads.
        // This Content-Length check is an additional fast-path for clients that
        // advertise a large body upfront — it avoids wasting CPU on token
        // verification for bodies that will be rejected anyway.
        const contentLength = Number(req.headers['content-length'] ?? 0);
        if (Number.isFinite(contentLength) && contentLength > ENFORCE_REQUEST_SIZE_LIMIT_BYTES) {
          res.status(413).json({
            error: {
              code: ErrorCode.REQUEST_TOO_LARGE,
              message: `Request body exceeds the ${ENFORCE_REQUEST_SIZE_LIMIT_BYTES / 1024} KiB limit`,
              requestId,
            },
          });
          return;
        }

        // ── 4. Parse and validate request body ──────────────────────────────
        let enforceReq: EnforceRequest;
        try {
          enforceReq = parseEnforceRequestBody(req.body);
          validateClockSkew(enforceReq.context.now);
        } catch (err) {
          if (err instanceof CapabilityError) {
            replyWithCapabilityError(err);
            return;
          }
          throw err;
        }

        // Extract tenantId from the JWT for telemetry routing — only when
        // telemetry hooks are active so the decode cost is zero when
        // EUNO_TELEMETRY=0. The decode is signature-free and used only for
        // per-tenant aggregation, never for any authorization decision.
        // Falls back to 'unknown' on malformed tokens.
        const getTenantId = (): string =>
          telemetry ? extractTenantIdFromToken(token) : 'unknown';

        // ── 5. Derive action and canonical resource ──────────────────────────
        // Server-side derivation only — never trust a client-supplied action
        // or resource string. Mirrors the /api/v1/tools/invoke route.
        const action = actionResolver.fromToolInvocation({
          tool: enforceReq.toolName,
          args: enforceReq.arguments,
        });
        const canonicalResource = `tool://${enforceReq.toolName}`;

        // ── 6. Build the ValidateActionRequest ──────────────────────────────
        // The enforcement engine reads condition-context fields from
        // ValidateActionRequest.context using the conventions documented in
        // enforcement.ts (buildConditionContext). We forward the fields that
        // EnforceRequestContext provides under the same keys.
        const validationContext: Record<string, unknown> = {
          sessionId: enforceReq.sessionId,
          tool: enforceReq.toolName,
          args: enforceReq.arguments,
        };

        // CR-2: Resolve the effective sourceIp according to the configured
        // trust mode. In 'gateway' mode req.ip is derived from the TCP
        // connection and X-Forwarded-For headers (respecting the Express
        // `trust proxy` setting) and takes precedence over the client-supplied
        // body field so callers cannot spoof ipRange conditions. In 'client'
        // mode the body field is used as-is (legacy behaviour).
        if (sourceIpMode === 'gateway') {
          // req.ip may be undefined for non-HTTP transports in tests; fall
          // back to the client-supplied value only in that case.
          // Normalize IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 → 127.0.0.1)
          // so that policy CIDRs written with plain IPv4 notation match
          // correctly even when the gateway accepts connections on a dual-stack
          // socket.
          const gatewayDerivedIp =
            req.ip !== undefined ? normalizeIpv4Mapped(req.ip) : undefined;
          const clientSuppliedIp = enforceReq.context.sourceIp;
          // Normalize the client-supplied value too so the spoofing-detection
          // comparison is not polluted by representation differences (e.g.
          // a client that echoes the same address back in IPv4-mapped form).
          const normalizedClientIp =
            clientSuppliedIp !== undefined ? normalizeIpv4Mapped(clientSuppliedIp) : undefined;
          const effectiveIp = gatewayDerivedIp ?? normalizedClientIp;
          if (effectiveIp !== undefined) {
            validationContext.sourceIp = effectiveIp;
          }
          // Warn when the client asserted a different IP — signals a spoofing
          // attempt or a misconfigured TRUST_PROXY.  Compare the normalized
          // forms so that representation-equivalent addresses (e.g.
          // "127.0.0.1" vs "::ffff:127.0.0.1") do not produce a noisy false
          // positive.
          if (
            gatewayDerivedIp !== undefined &&
            normalizedClientIp !== undefined &&
            normalizedClientIp !== gatewayDerivedIp
          ) {
            logger.warn('Enforce: client-supplied sourceIp differs from gateway-derived IP', {
              requestId,
              gatewayDerivedIp,
              clientSuppliedIp,
              sourceIpMode,
            });
          }
        } else {
          // sourceIpMode === 'client': use the value from the request body
          // (legacy behaviour; only safe when all callers are trusted).
          if (enforceReq.context.sourceIp !== undefined) {
            validationContext.sourceIp = enforceReq.context.sourceIp;
          }
        }

        if (enforceReq.context.recipients !== undefined) {
          validationContext.recipients = enforceReq.context.recipients;
        }

        const validationRequest: ValidateActionRequest = {
          token,
          action: action as ValidateActionRequest['action'],
          resource: canonicalResource,
          context: validationContext,
        };

        // ── 7. Run enforcement ───────────────────────────────────────────────
        let result: EnforcementResult;
        try {
          result = await enforcementEngine.validateAction(validationRequest);
        } catch (err) {
          if (err instanceof CapabilityError) {
            // 401 and 503 remain out-of-band infrastructure errors; the client
            // must distinguish an authentication failure from a policy denial
            // to avoid caching a "deny" decision and calling refresh.
            // All other CapabilityErrors (403, 429, etc.) are in-band denials:
            // the decision was made by the PDP; the caller should apply it.
            if (err.statusCode === 401) {
              res.status(401).json({
                error: { code: err.code, message: err.message, requestId },
              });
              return;
            }
            if (err.statusCode === 503) {
              // Preserve the engine's specific code (e.g. REVOCATION_UNAVAILABLE)
              // rather than hard-coding GATEWAY_UNAVAILABLE so operators can
              // distinguish between different infrastructure failures.
              res.status(503).json({
                error: { code: err.code, message: err.message, requestId },
              });
              return;
            }

            // In-band deny: wrap the CapabilityError into an EnforceResponse
            const denyResponse: EnforceResponse = {
              requestId,
              decision: 'deny',
              denial: capabilityErrorToDenialInfo(err),
              decidedAt: new Date().toISOString(),
            };
            logger.info('Enforce: in-band denial (capability error)', {
              requestId,
              code: err.code,
              toolName: enforceReq.toolName,
              sessionId: enforceReq.sessionId,
            });
            // Record in-band denial for telemetry (these are enforcement
            // decisions — the PDP chose to deny; they are not infrastructure
            // errors and count towards the tenant's denial stats).
            telemetry?.recordDecision(
              getTenantId(),
              enforceReq.sessionId,
              false,
              deriveConditionType(err.code),
            );
            res.json(denyResponse);
            return;
          }
          // Unexpected error — let the Express error handler produce a 500
          throw err;
        }

        // ── 8. Build and return EnforceResponse ─────────────────────────────
        const decidedAt = new Date().toISOString();

        if (result.allowed) {
          const obligations = buildObligations(result.matchedCapability);
          const allowResponse: EnforceResponse = {
            requestId,
            decision: 'allow',
            ...(obligations.length > 0 ? { obligations } : {}),
            decidedAt,
          };
          logger.info('Enforce: allowed', {
            requestId,
            toolName: enforceReq.toolName,
            sessionId: enforceReq.sessionId,
            obligationCount: obligations.length,
          });
          telemetry?.recordDecision(getTenantId(), enforceReq.sessionId, true);
          res.json(allowResponse);
        } else {
          // Use the structured denial code from the engine when available
          // (e.g. ARGUMENT_SCHEMA_VIOLATION) so that the response matches the
          // protocol's DenialInfo contract rather than always emitting the
          // generic AUTHORIZATION_FAILED.
          const denyResponse: EnforceResponse = {
            requestId,
            decision: 'deny',
            denial: enforcementResultToDenialInfo(result),
            decidedAt,
          };
          logger.info('Enforce: denied', {
            requestId,
            toolName: enforceReq.toolName,
            sessionId: enforceReq.sessionId,
            reason: result.reason,
            denialCode: result.denialCode,
          });
          telemetry?.recordDecision(
            getTenantId(),
            enforceReq.sessionId,
            false,
            result.denialConditionType ?? deriveConditionType(result.denialCode ?? ''),
          );
          res.json(denyResponse);
        }
      } catch (error) {
        // Any unhandled error from this route should be forwarded to Express's
        // global error handler. Re-attach the requestId as a request attribute
        // (not a response header that would force the response to start) so the
        // global error handler can optionally include it.
        (req as EnforceRequest_).enforceRequestId = requestId;
        next(error);
      }
    },
  );

  return router;
}
