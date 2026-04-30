/**
 * OPA over HTTP — built-in {@link PolicyBackend} for the `'policy'`
 * condition type (R-4 step 2 / F-10).
 *
 * Sends the per-request input to an Open Policy Agent data-API URL
 * and interprets the JSON response. The default contract is the
 * standard OPA shape:
 *
 *     POST https://opa/v1/data/<package>/<rule>
 *     { "input": { ... } }
 *     →  200 { "result": true | false | { "allow": bool, "reason"?: str } }
 *
 * Operators may override `decisionField` if they sit OPA behind a
 * gateway that wraps the response. The backend is **fail-closed by
 * default**: any HTTP error, network error, timeout, or unrecognised
 * decision shape resolves to `deny`. Set `failClosed: false` only
 * when an outage of the policy plane should not take the data plane
 * down with it.
 */

import {
  ConditionResult,
  ConditionContext,
  ConditionValidationError,
  PolicyBackend,
} from '../condition-registry';

/** Stable name under which {@link createOpaHttpBackend} is registered. */
export const OPA_HTTP_BACKEND_NAME = 'opa-http';

export interface OpaHttpBackendConfig {
  /** Full OPA data-API URL, e.g. `http://opa:8181/v1/data/euno/allow`. */
  url: string;
  /**
   * If true (default), any non-200 response, network error, timeout,
   * or unrecognised decision shape resolves to `deny`. Set `false`
   * for advisory enforcement.
   */
  failClosed?: boolean;
  /** Per-request timeout in milliseconds. Default 5000. */
  timeoutMs?: number;
  /** Top-level field in the JSON response that carries the decision. Default `'result'`. */
  decisionField?: string;
  /** Extra headers to send on every request (e.g. `Authorization`). */
  headers?: Record<string, string>;
}

export interface OpaHttpBackendOptions {
  /**
   * Override the global `fetch` used for the OPA call. Tests inject a
   * stub here; production deployments leave it unset and pick up the
   * Node 18+ built-in.
   */
  fetch?: typeof globalThis.fetch;
}

/**
 * Construct a {@link PolicyBackend} that delegates the decision to an
 * OPA HTTP endpoint named in each `policy` condition's `config.url`.
 * Register the result with `registerPolicyBackend` under
 * {@link OPA_HTTP_BACKEND_NAME} (or any other name) at boot:
 *
 *     registerPolicyBackend(OPA_HTTP_BACKEND_NAME, createOpaHttpBackend());
 */
export function createOpaHttpBackend(opts: OpaHttpBackendOptions = {}): PolicyBackend {
  const fetchImpl = opts.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    throw new Error(
      'createOpaHttpBackend: no global fetch is available; pass { fetch } explicitly',
    );
  }
  return {
    validate(config: unknown): void {
      if (!config || typeof config !== 'object' || Array.isArray(config)) {
        throw new ConditionValidationError(
          'opa-http policy.config must be an object',
        );
      }
      const c = config as Partial<OpaHttpBackendConfig>;
      if (typeof c.url !== 'string' || !/^https?:\/\//.test(c.url)) {
        throw new ConditionValidationError(
          "opa-http policy.config.url must be a http(s) URL",
        );
      }
      if (c.timeoutMs !== undefined) {
        if (
          typeof c.timeoutMs !== 'number' ||
          !Number.isInteger(c.timeoutMs) ||
          c.timeoutMs < 1
        ) {
          throw new ConditionValidationError(
            'opa-http policy.config.timeoutMs must be a positive integer',
          );
        }
      }
      if (c.decisionField !== undefined) {
        if (typeof c.decisionField !== 'string' || c.decisionField.length === 0) {
          throw new ConditionValidationError(
            'opa-http policy.config.decisionField must be a non-empty string',
          );
        }
      }
      if (c.failClosed !== undefined && typeof c.failClosed !== 'boolean') {
        throw new ConditionValidationError(
          'opa-http policy.config.failClosed must be a boolean',
        );
      }
      if (c.headers !== undefined) {
        if (
          typeof c.headers !== 'object' ||
          c.headers === null ||
          Array.isArray(c.headers)
        ) {
          throw new ConditionValidationError(
            'opa-http policy.config.headers must be an object',
          );
        }
        for (const [k, v] of Object.entries(c.headers)) {
          if (typeof k !== 'string' || k.length === 0 || typeof v !== 'string') {
            throw new ConditionValidationError(
              'opa-http policy.config.headers entries must be string→string',
            );
          }
        }
      }
    },
    async enforce(
      config: unknown,
      input: unknown,
      ctx: ConditionContext,
    ): Promise<ConditionResult> {
      // Defensive guard: `validate` is invoked at mint time, but a
      // malformed token (or a future caller wiring this backend
      // outside the validate→enforce contract) could still hand us a
      // bogus `config`. Treat anything that doesn't carry a usable
      // `url` as deny — the safer of the two failure modes, regardless
      // of the (also-defensive) `failClosed` setting we couldn't read.
      if (
        !config ||
        typeof config !== 'object' ||
        Array.isArray(config) ||
        typeof (config as { url?: unknown }).url !== 'string' ||
        !/^https?:\/\//.test((config as { url: string }).url)
      ) {
        return {
          allow: false,
          reason: 'opa-http: invalid backend config (missing or non-http(s) url)',
        };
      }
      const c = config as OpaHttpBackendConfig;
      const failClosed = c.failClosed !== false; // default true
      const timeoutMs =
        typeof c.timeoutMs === 'number' && Number.isInteger(c.timeoutMs) && c.timeoutMs > 0
          ? c.timeoutMs
          : 5000;
      const decisionField =
        typeof c.decisionField === 'string' && c.decisionField.length > 0
          ? c.decisionField
          : 'result';

      // Build the OPA input by merging the issuer-supplied static
      // facts with a small projection of the per-request context. We
      // intentionally project rather than spread the full
      // `ConditionContext` because the latter contains non-serialisable
      // fields (counter store, handler maps) and would also leak
      // backend internals to the policy.
      const projectedCtx: Record<string, unknown> = {};
      if (ctx.now !== undefined) projectedCtx.now = ctx.now.toISOString();
      if (ctx.sourceIp !== undefined) projectedCtx.sourceIp = ctx.sourceIp;
      if (ctx.operation !== undefined) projectedCtx.operation = ctx.operation;
      if (ctx.filePath !== undefined) projectedCtx.filePath = ctx.filePath;
      if (ctx.tables !== undefined) projectedCtx.tables = ctx.tables;
      if (ctx.recipients !== undefined) projectedCtx.recipients = ctx.recipients;

      const opaInput =
        input !== undefined &&
        input !== null &&
        typeof input === 'object' &&
        !Array.isArray(input)
          ? { ...(input as Record<string, unknown>), context: projectedCtx }
          : { input, context: projectedCtx };

      const safeHeaders =
        c.headers && typeof c.headers === 'object' && !Array.isArray(c.headers)
          ? c.headers
          : {};
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), timeoutMs);
      try {
        const res = await fetchImpl(c.url, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            ...safeHeaders,
          },
          body: JSON.stringify({ input: opaInput }),
          signal: ac.signal,
        });
        if (!res.ok) {
          return failClosed
            ? {
                allow: false,
                reason: `opa-http: backend returned HTTP ${res.status}`,
              }
            : { allow: true };
        }
        let json: unknown;
        try {
          json = await res.json();
        } catch (err) {
          return failClosed
            ? {
                allow: false,
                reason: `opa-http: response was not valid JSON (${err instanceof Error ? err.message : String(err)})`,
              }
            : { allow: true };
        }
        if (!json || typeof json !== 'object') {
          return failClosed
            ? { allow: false, reason: 'opa-http: response was not a JSON object' }
            : { allow: true };
        }
        const decision = (json as Record<string, unknown>)[decisionField];
        if (decision === true) return { allow: true };
        if (decision === false) {
          return { allow: false, reason: 'opa-http: policy denied' };
        }
        if (decision && typeof decision === 'object' && !Array.isArray(decision)) {
          const d = decision as { allow?: unknown; reason?: unknown };
          if (d.allow === true) return { allow: true };
          if (d.allow === false) {
            const reason =
              typeof d.reason === 'string' && d.reason.length > 0
                ? `opa-http: ${d.reason}`
                : 'opa-http: policy denied';
            return { allow: false, reason };
          }
        }
        return failClosed
          ? {
              allow: false,
              reason: `opa-http: unrecognised decision shape under '${decisionField}'`,
            }
          : { allow: true };
      } catch (err) {
        const aborted = (err as { name?: string } | null)?.name === 'AbortError';
        const msg = aborted
          ? `request timed out after ${timeoutMs}ms`
          : err instanceof Error
            ? err.message
            : String(err);
        return failClosed
          ? { allow: false, reason: `opa-http: ${msg}` }
          : { allow: true };
      } finally {
        clearTimeout(timer);
      }
    },
  };
}
