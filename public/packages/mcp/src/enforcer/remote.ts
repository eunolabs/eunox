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
 * The client presents its API key (`apiKey`) as a Bearer token in every
 * `Authorization` header.  In the hosted topology the minter façade
 * (Task 10) converts the API key to a short-lived JWT before the request
 * reaches the gateway's enforcement route; until the minter is deployed the
 * gateway may be configured to accept the raw key directly (development /
 * self-host mode).  This module never constructs JWTs — it is the
 * minter's job to do that conversion transparently.
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
   * API key used to authenticate against the gateway.  Sent as a
   * `Bearer` token in the `Authorization` header of every enforce request.
   *
   * In the hosted deployment topology the minter façade (Task 10) converts
   * this key to a short-lived JWT; until then the gateway may accept the
   * raw key.  This value MUST NOT be logged.
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
    if (!opts.url || opts.url.trim().length === 0) {
      throw new Error('RemoteEnforcerPDP: url must be a non-empty string');
    }
    if (!opts.apiKey || opts.apiKey.trim().length === 0) {
      throw new Error('RemoteEnforcerPDP: apiKey must be a non-empty string');
    }
    // Strip trailing slashes without a regex to avoid potential ReDoS on
    // adversarial input strings with many repeated '/' characters.
    let url = opts.url;
    let end = url.length;
    while (end > 0 && url[end - 1] === '/') end--;
    this._url = url.slice(0, end);
    this._apiKey = opts.apiKey;
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

    let res: Awaited<ReturnType<EnforceFetcher>>;
    try {
      res = await this._fetcher(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this._apiKey}`,
          'X-Euno-Protocol-Version': String(ENFORCE_PROTOCOL_VERSION),
        },
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
 * Parse and minimally validate a raw gateway response body.
 * Throws on structural violations (fail-closed path).
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

  return r as unknown as EnforceResponse;
}
