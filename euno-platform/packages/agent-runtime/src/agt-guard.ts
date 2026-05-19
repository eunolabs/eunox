/**
 * AGT In-Process Guard Adapter
 *
 * Implements `createAgtGuard()` — the BSL-licensed factory that produces an
 * {@link AgtGuard} instance from an {@link AgtGuardOptions} configuration and
 * an outer {@link ToolTransport}.
 *
 * Architecture context: `docs/diagrams.md` Set D (D1–D4) and the
 * stage-5 execution plan §4.6.  The guard is a **soft guard** — it
 * pre-screens tool calls against the declared capability manifest in-process
 * and forwards allowed calls to the outer transport (typically the reference
 * monitor / tool gateway).  The gateway is the hard, audited enforcement
 * boundary and MUST NOT be bypassed.
 *
 * License note: the types (`AgtGuardOptions`, `AgtGuardResult`,
 * `AgtGuardDenyReason`) are Apache-2.0 and live in `@euno/common-core`.
 * This implementation file is BSL-1.1.
 *
 * @module agt-guard
 */

import type {
  AgtGuardOptions,
  AgtGuardDenyReason,
  AgtGuardResult,
} from '@euno/common';
import type {
  ToolTransport,
  ToolTransportInvokeRequest,
  ToolTransportResponse,
} from '@euno/common';

// ── Public interface ──────────────────────────────────────────────────────────

/**
 * The response envelope returned by {@link AgtGuard.invokeTool}.
 *
 * Extends {@link ToolTransportResponse} with guard-specific fields so callers
 * can distinguish a guard-layer block from a gateway-layer denial without
 * parsing error messages.
 */
export interface AgtGuardInvokeResponse extends ToolTransportResponse {
  /**
   * The guard's own verdict for this call.
   *
   * - `'allow'`: the guard pre-screened the call and found it consistent with
   *   the declared policy; the call was forwarded to the outer transport.
   *   Note that `guardResult === 'allow'` does **not** imply `success === true`
   *   — the outer gateway may still have denied the call (see
   *   {@link AgtGuardOptions.onGatewayDeny}).
   * - `'deny'`: the guard blocked the call before it reached the transport;
   *   `success` is `false` and `denyReason` is set.
   */
  guardResult: AgtGuardResult;
  /**
   * Structured reason code when `guardResult === 'deny'` (guard-layer block).
   * `undefined` when the guard allowed the call (including when the gateway
   * subsequently denied it — that is a gateway-layer denial, not a guard-layer
   * denial).
   */
  denyReason?: AgtGuardDenyReason;
}

/**
 * The AGT in-process guard adapter returned by {@link createAgtGuard}.
 *
 * Acts as a policy pre-screen that wraps an outer {@link ToolTransport}.
 * Every tool invocation is checked against the declared
 * {@link AgtGuardOptions.policy} manifest before being forwarded to the
 * transport.  Calls that do not pass the in-process check are blocked at this
 * layer; the transport is never invoked for blocked calls.
 *
 * **The guard is a soft guard only.**  Passing the in-process check does not
 * guarantee the outer gateway will also allow the call — the gateway performs
 * independent cryptographic signature verification, token expiry checks, and
 * revocation lookups that the guard does not replicate.
 */
export interface AgtGuard {
  /**
   * Check the tool call against the in-process policy and, if allowed,
   * forward it to the outer transport.
   *
   * @param request  The tool invocation to check and (if allowed) forward.
   * @returns A response that includes the guard verdict (`guardResult`) and,
   *          when the guard itself blocked the call, the `denyReason`.
   */
  invokeTool(request: ToolTransportInvokeRequest): Promise<AgtGuardInvokeResponse>;
}

// ── Factory ───────────────────────────────────────────────────────────────────

/**
 * Create an AGT in-process guard adapter.
 *
 * The returned {@link AgtGuard} instance wraps the supplied `transport` and
 * pre-screens every tool invocation against `options.policy` before forwarding
 * to the transport.
 *
 * @param options    Guard configuration — policy manifest, token supplier, and
 *                   optional observation callbacks.
 * @param transport  The outer transport (gateway) to forward allowed calls to.
 *                   In production, use an `HttpToolTransport` pointing at the
 *                   tool gateway.  In tests, use an `InProcessToolTransport`
 *                   backed by a mock handler so no HTTP server is needed.
 * @returns An {@link AgtGuard} ready to receive tool invocations.
 *
 * @example
 * ```typescript
 * import { createAgtGuard, HttpToolTransport } from '@euno/agent-runtime';
 *
 * const guard = createAgtGuard(
 *   {
 *     tokenSupplier: () => tokenStore.currentToken(),
 *     policy: manifest,
 *     onDeny: (tool, reason) => logger.warn('guard deny', { tool, reason }),
 *     onGatewayDeny: (tool, code) => metrics.increment('gateway_deny', { tool, code }),
 *   },
 *   new HttpToolTransport(gatewayUrl),
 * );
 *
 * // Use the guard as the sole entry point for all tool calls.
 * const response = await guard.invokeTool({ tool: 'db:read', args: { table: 'users' } });
 * ```
 */
export function createAgtGuard(
  options: AgtGuardOptions,
  transport: ToolTransport,
): AgtGuard {
  const { policy, tokenSupplier, onDeny, onGatewayDeny } = options;

  // Build the combined capability set once at construction time.  The policy
  // is treated as immutable (per the type contract in AgtGuardOptions).
  const allCapabilities = [
    ...policy.requiredCapabilities,
    ...(policy.optionalCapabilities ?? []),
  ];

  return {
    async invokeTool(
      request: ToolTransportInvokeRequest,
    ): Promise<AgtGuardInvokeResponse> {
      const toolName = request.tool;

      // ── Step 1: In-process policy check ────────────────────────────────────

      let matchedIndex: number;
      try {
        matchedIndex = allCapabilities.findIndex(
          (c) => c.resource === toolName,
        );
      } catch (err) {
        // Unexpected error during policy evaluation — fail closed.
        return guardDeny(toolName, 'policy_evaluation_error', onDeny);
      }

      if (matchedIndex === -1) {
        // Tool is not listed in either required or optional capabilities.
        return guardDeny(toolName, 'capability_not_found', onDeny);
      }

      // ── Step 2: Token acquisition ───────────────────────────────────────────

      let token: string;
      try {
        token = await tokenSupplier();
      } catch {
        // Token supplier failure is an unexpected evaluation error — fail closed.
        return guardDeny(toolName, 'policy_evaluation_error', onDeny);
      }

      // ── Step 3: Forward to outer transport ─────────────────────────────────

      const transportResponse = await transport.invokeTool(request, {
        capabilityToken: token,
        agentId: policy.agentId,
      });

      // ── Step 4: Detect gateway-layer denial ────────────────────────────────

      if (!transportResponse.success) {
        const errorCode =
          transportResponse.errorCode ?? `HTTP_${transportResponse.statusCode}`;
        safeInvoke(() => onGatewayDeny?.(toolName, errorCode));
        // guardResult is 'allow': the guard itself did not block this call.
        return { ...transportResponse, guardResult: 'allow' };
      }

      return { ...transportResponse, guardResult: 'allow' };
    },
  };
}

// ── Private helpers ───────────────────────────────────────────────────────────

/**
 * Build a synthetic guard-deny response, invoke the `onDeny` callback (swallowing
 * any thrown errors), and return the deny envelope.
 */
function guardDeny(
  toolName: string,
  reason: AgtGuardDenyReason,
  onDeny: AgtGuardOptions['onDeny'],
): AgtGuardInvokeResponse {
  safeInvoke(() => onDeny?.(toolName, reason));
  return {
    success: false,
    statusCode: 403,
    error: `Guard deny: ${reason}`,
    guardResult: 'deny',
    denyReason: reason,
  };
}

/**
 * Invoke a callback, swallowing any thrown errors.
 *
 * Guard callbacks MUST NOT be able to propagate exceptions into the guard
 * evaluation path — doing so would turn a malfunctioning observability
 * hook into an exploitable denial-of-service vector.
 */
function safeInvoke(fn: () => void): void {
  try {
    fn();
  } catch {
    // intentionally swallowed
  }
}
