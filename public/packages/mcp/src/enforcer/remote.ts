/**
 * RemoteEnforcerPDP — Stage-3 remote-enforcer mode.
 * ---------------------------------------------------------------------------
 * This module implements the client side of the Stage-3 remote-enforcer
 * protocol (Task 2 of the Stage 3 execution plan).  When `@euno/mcp` is
 * configured with `enforcer: { url: "https://...", apiKey: "sk-..." }`,
 * the proxy constructs a {@link RemoteEnforcerPDP} instead of the local
 * {@link ConditionEnforcerPDP} and forwards every intercepted `tools/call`
 * to the hosted gateway's `POST /api/v1/enforce` endpoint.
 *
 * **Stage-3 boundary design note (preserve this comment)**
 *
 * The {@link LocalPolicySource} interface in `./policy/source.ts` was
 * designed as a file-loader abstraction for Stage 1–2 with a documented
 * intent to replace it with a JWT loader in Stage 3.  However, the cleaner
 * Stage-3 boundary is at the *enforcer call*, not at the policy-read seam:
 *
 *   - Swapping only the policy loader would still leave the local
 *     CallCounterStore, KillSwitchManager, and HmacSigner running
 *     in-process — you'd be talking to the gateway for policy but still
 *     doing local enforcement, which defeats the purpose of a hosted
 *     boundary.
 *   - Swapping the whole enforcer (this module) skips local construction
 *     of FilePolicySource, LocalHmacSigner, InMemoryCallCounterStore, and
 *     the in-memory kill switch.  The gateway is the sole enforcement
 *     authority; its KMS signer and Redis-backed counters provide the
 *     production-grade guarantees Stage 3 promises.
 *
 * The LocalPolicySource seam is retained in `policy/source.ts` as
 * documented — it will become the JWT-loader entry point when Stage 3
 * ships the full minter (Task 10).
 *
 * **Wire protocol**
 *
 * `EnforceRequest` and `EnforceResponse` are defined in
 * `@euno/common-core/wire.ts` so both the gateway and this client compile
 * against the same types.  The current protocol version is
 * `ENFORCE_PROTOCOL_VERSION = 1`.  See `docs/stage-3-gateway-protocol.md`
 * for the full contract.
 *
 * **Authentication**
 *
 * The client sends its API key (`apiKey`) as a `Bearer` token in the
 * `Authorization` header.  In the hosted deployment topology the minter façade
 * (Task 10) sits in front of the enforcement route: it intercepts the request,
 * exchanges the API key for a short-lived JWT signed by the deployment's issuer,
 * and forwards the JWT to the enforcement route.  The enforcement route itself
 * accepts only JWTs — it never sees or accepts raw API keys directly.  This
 * module does not construct JWTs; the façade handles that conversion
 * transparently so this client only needs to present the API key.
 *
 * In self-hosted deployments where the minter façade is not deployed, the
 * operator is responsible for configuring an issuer JWT in `apiKey` directly.
 *
 * **Fail-closed guarantees**
 *
 * Any network error, non-200 HTTP response, or malformed response body
 * results in a `deny` decision with code `GATEWAY_UNAVAILABLE`.  The proxy
 * never silently allows a call when the gateway is unreachable.
 *
 * @module
 */

import type { CallToolRequest } from '@modelcontextprotocol/sdk/types.js';
import {
  ENFORCE_PROTOCOL_VERSION,
  type EnforceRequest,
  type EnforceResponse,
  type Obligation,
  injectTraceContext,
} from '@euno/common-core';
import type { PolicyDecisionPoint, PdpContext, PdpDecision } from '../pdp';

// ---------------------------------------------------------------------------
// Injectable fetch transport (for testing)
// ---------------------------------------------------------------------------

/**
 * Minimal fetch-compatible interface used by {@link RemoteEnforcerPDP} to
 * communicate with the gateway.
 *
 * The default implementation is the global `fetch` (Node.js ≥ 18).  Inject
 * a mock in tests to avoid real network I/O.
 */
export type EnforceFetcher = (
  url: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body: string;
    signal?: AbortSignal;
  },
) => Promise<{
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
}>;

// ---------------------------------------------------------------------------
// Public options
// ---------------------------------------------------------------------------

/**
 * Configuration for {@link RemoteEnforcerPDP}.
 */
export interface RemoteEnforcerOptions {
  /**
   * Base URL of the hosted enforcement gateway, e.g.
   * `"https://gateway.euno.example"`.  The path `"/api/v1/enforce"` is
   * appended by this client — do NOT include it in this value.
   *
   * Trailing slashes are trimmed automatically.
   */
  url: string;

  /**
   * API key (or issuer JWT in self-hosted deployments) presented as a `Bearer`
   * token in the `Authorization` header of every enforce request.
   *
   * In the hosted deployment topology this value is the `sk-…` API key issued
   * by the Euno console.  The minter façade (Task 10) intercepts requests from
   * this client and exchanges the key for a short-lived JWT before the
   * enforcement route sees it — the enforcement route itself only accepts JWTs.
   *
   * This value MUST NOT be logged.
   */
  apiKey: string;

  /**
   * Timeout in milliseconds for each enforce request.
   *
   * When a request to the gateway exceeds this limit, the proxy returns a
   * fail-closed `deny` decision with code `GATEWAY_UNAVAILABLE` rather than
   * waiting indefinitely.
   *
   * @default 10000 (10 seconds)
   */
  timeoutMs?: number;

  /**
   * Injectable fetch implementation.  Defaults to the global `fetch`.
   * Override in unit tests to avoid real network I/O.
   */
  fetcher?: EnforceFetcher;

  /**
   * Injectable clock function returning the current `Date`.
   * Defaults to `() => new Date()`.  Override in unit tests to produce
   * deterministic `context.now` timestamps.
   */
  clockFn?: () => Date;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Extract recipient addresses from common tool-argument field names. */
function extractRecipients(args: Record<string, unknown>): string[] | undefined {
  const recipients: string[] = [];
  const addField = (value: unknown): void => {
    if (typeof value === 'string' && value.trim().length > 0) {
      recipients.push(value.trim());
    } else if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === 'string' && item.trim().length > 0) {
          recipients.push(item.trim());
        }
      }
    }
  };
  addField(args['to']);
  addField(args['recipients']);
  addField(args['cc']);
  addField(args['bcc']);
  return recipients.length > 0 ? recipients : undefined;
}

// ---------------------------------------------------------------------------
// RemoteEnforcerPDP
// ---------------------------------------------------------------------------

/**
 * A {@link PolicyDecisionPoint} that enforces tool calls via the hosted
 * Euno gateway rather than in-process.
 *
 * Construction is cheap — no local files are read, no keys are loaded, no
 * counters are allocated.  All enforcement state lives in the gateway.
 *
 * ### Usage
 *
 * ```ts
 * const pdp = new RemoteEnforcerPDP({
 *   url: 'https://gateway.euno.example',
 *   apiKey: 'sk-...',
 * });
 * const proxy = new StdioProxy({ command: '...', pdp });
 * await proxy.start();
 * ```
 *
 * ### Obligations
 *
 * When the gateway allows a call it may return `Obligation[]` in the
 * response.  These are forwarded via {@link PdpDecision.obligations} so the
 * transport layer can apply them to the upstream response (e.g. strip fields
 * listed in a `redactFields` obligation) before returning to the MCP client.
 */
export class RemoteEnforcerPDP implements PolicyDecisionPoint {
  private readonly _url: string;
  private readonly _apiKey: string;
  private readonly _timeoutMs: number;
  private readonly _fetcher: EnforceFetcher;
  private readonly _clockFn: () => Date;

  constructor(opts: RemoteEnforcerOptions) {
    const trimmedUrl = opts.url?.trim() ?? '';
    if (!trimmedUrl) {
      throw new Error('RemoteEnforcerPDP: url must be a non-empty string');
    }
    const trimmedApiKey = opts.apiKey?.trim() ?? '';
    if (!trimmedApiKey) {
      throw new Error('RemoteEnforcerPDP: apiKey must be a non-empty string');
    }
    // Strip trailing slashes without a regex to avoid potential ReDoS on
    // adversarial input strings with many repeated '/' characters.
    let end = trimmedUrl.length;
    while (end > 0 && trimmedUrl[end - 1] === '/') end--;
    const normalizedUrl = trimmedUrl.slice(0, end);
    if (!normalizedUrl) {
      // Edge case: url was entirely slashes after trimming (e.g. '///').
      throw new Error('RemoteEnforcerPDP: url must not consist entirely of slashes');
    }
    this._url = normalizedUrl;
    this._apiKey = trimmedApiKey;
    if (opts.timeoutMs !== undefined) {
      if (!Number.isFinite(opts.timeoutMs) || opts.timeoutMs <= 0) {
        throw new Error(
          'RemoteEnforcerPDP: timeoutMs must be a positive finite number',
        );
      }
    }
    this._timeoutMs = opts.timeoutMs ?? 10_000;
    this._fetcher = opts.fetcher ?? defaultFetcher;
    this._clockFn = opts.clockFn ?? (() => new Date());
  }

  /** @inheritdoc */
  async decide(request: CallToolRequest, ctx: PdpContext): Promise<PdpDecision> {
    const toolName = request.params.name;
    const rawArgs: Record<string, unknown> = request.params.arguments ?? {};

    const enforceRequest: EnforceRequest = {
      sessionId: ctx.sessionId,
      toolName,
      arguments: rawArgs,
      context: {
        sourceIp: ctx.sourceIp,
        recipients: extractRecipients(rawArgs),
        now: this._clockFn().toISOString(),
      },
    };

    const endpointUrl = `${this._url}/api/v1/enforce`;
    const body = JSON.stringify(enforceRequest);

    let response: EnforceResponse;
    try {
      response = await this._callGateway(endpointUrl, body);
    } catch (err) {
      // Fail-closed: any error communicating with the gateway → deny.
      process.stderr.write(
        `[euno-mcp] RemoteEnforcerPDP: gateway call failed for tool "${toolName}": ${String(err)}\n`,
      );
      return {
        allow: false,
        reason: `Gateway unavailable: ${err instanceof Error ? err.message : String(err)}`,
        denialCode: 'GATEWAY_UNAVAILABLE',
        conditionType: 'remoteEnforcer',
      };
    }

    if (response.decision === 'allow') {
      const obligations: readonly Obligation[] | undefined =
        response.obligations && response.obligations.length > 0
          ? response.obligations
          : undefined;
      return { allow: true, obligations };
    }

    // Deny decision.
    return {
      allow: false,
      reason: response.denial?.message,
      denialCode: response.denial?.code,
      conditionType: response.denial?.conditionType,
      details: response.denial?.details,
    };
  }

  // --------------------------------------------------------------------------
  // Private helpers
  // --------------------------------------------------------------------------

  /**
   * Call the gateway's `/api/v1/enforce` endpoint and return the parsed
   * `EnforceResponse`.  Throws on network errors, HTTP error responses, or
   * parse failures — all of which the caller maps to a fail-closed `deny`.
   */
  private async _callGateway(url: string, body: string): Promise<EnforceResponse> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this._timeoutMs);

    // Inject W3C trace context so the gateway spans become children of the
    // caller's active span (DI-5). Injects traceparent/tracestate when a
    // valid span context is active; no-op when there is no active span context
    // (regardless of whether an SDK is registered).
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this._apiKey}`,
      'X-Euno-Protocol-Version': String(ENFORCE_PROTOCOL_VERSION),
    };
    injectTraceContext(headers);

    let res: Awaited<ReturnType<EnforceFetcher>>;
    try {
      res = await this._fetcher(url, {
        method: 'POST',
        headers,
        body,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    if (!res.ok) {
      // HTTP 4xx/5xx — the gateway itself responded but indicated an error.
      // Fail-closed so the caller returns a deny decision.
      throw new Error(`HTTP ${res.status} from enforcement gateway`);
    }

    const raw = await res.json();
    return parseEnforceResponse(raw);
  }
}

// ---------------------------------------------------------------------------
// Default fetcher (global fetch — Node.js ≥ 18)
// ---------------------------------------------------------------------------

const defaultFetcher: EnforceFetcher = async (url, init) => {
  const res = await fetch(url, {
    method: init.method,
    headers: init.headers,
    body: init.body,
    signal: init.signal,
  });
  return {
    ok: res.ok,
    status: res.status,
    json: () => res.json() as Promise<unknown>,
  };
};

// ---------------------------------------------------------------------------
// Response validation
// ---------------------------------------------------------------------------

/**
 * Parse and fully validate a raw gateway response body.
 *
 * This function is the fail-closed gate for the remote-enforcer path.  Any
 * structural violation throws an error that the caller maps to a
 * `GATEWAY_UNAVAILABLE` deny decision.  Validating obligation and denial
 * shapes here ensures downstream code (applyRemoteObligations, audit sink)
 * can safely trust the values it receives without defensive try/catch.
 */
function parseEnforceResponse(raw: unknown): EnforceResponse {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new Error('Gateway returned a non-object response body');
  }
  const r = raw as Record<string, unknown>;

  if (r['decision'] !== 'allow' && r['decision'] !== 'deny') {
    throw new Error(
      `Gateway response has invalid decision field: ${String(r['decision'])}`,
    );
  }
  if (typeof r['requestId'] !== 'string') {
    throw new Error('Gateway response missing requestId field');
  }
  if (typeof r['decidedAt'] !== 'string') {
    throw new Error('Gateway response missing decidedAt field');
  }

  // Validate obligations array when present.
  if (r['obligations'] !== undefined) {
    if (!Array.isArray(r['obligations'])) {
      throw new Error('Gateway response obligations must be an array');
    }
    for (const item of r['obligations'] as unknown[]) {
      if (typeof item !== 'object' || item === null || Array.isArray(item)) {
        throw new Error('Gateway response obligation entry must be an object');
      }
      const o = item as Record<string, unknown>;
      if (o['type'] === 'redactFields') {
        if (
          !Array.isArray(o['paths']) ||
          (o['paths'] as unknown[]).some((p) => typeof p !== 'string')
        ) {
          throw new Error(
            'Gateway response redactFields obligation must have a string[] paths field',
          );
        }
      } else if (o['type'] === 'annotate') {
        if (typeof o['key'] !== 'string' || typeof o['value'] !== 'string') {
          throw new Error(
            'Gateway response annotate obligation must have string key and value fields',
          );
        }
      } else {
        // Unknown obligation type — log a warning but do not fail.  This
        // preserves forward-compatibility with gateway versions that may add
        // new obligation types.  Unknown types are silently skipped by
        // applyRemoteObligations.
        process.stderr.write(
          `[euno-mcp] RemoteEnforcerPDP: ignoring unknown obligation type "${String(o['type'])}"\n`,
        );
      }
    }
  }

  // Validate denial object when present (required for deny decisions).
  if (r['decision'] === 'deny') {
    if (r['denial'] === undefined) {
      throw new Error('Gateway deny response is missing the denial field');
    }
    if (
      typeof r['denial'] !== 'object' ||
      r['denial'] === null ||
      Array.isArray(r['denial'])
    ) {
      throw new Error('Gateway response denial field must be an object');
    }
    const d = r['denial'] as Record<string, unknown>;
    if (typeof d['code'] !== 'string') {
      throw new Error('Gateway response denial.code must be a string');
    }
    if (typeof d['conditionType'] !== 'string') {
      throw new Error('Gateway response denial.conditionType must be a string');
    }
    if (typeof d['message'] !== 'string') {
      throw new Error('Gateway response denial.message must be a string');
    }
    if (
      d['details'] !== undefined &&
      (typeof d['details'] !== 'object' ||
        d['details'] === null ||
        Array.isArray(d['details']))
    ) {
      throw new Error('Gateway response denial.details must be an object');
    }
  }

  return r as unknown as EnforceResponse;
}
