/**
 * AGT in-process guard types for `@euno/common-core`.
 *
 * These three types are the **only** seam additions made in Stage 5 to
 * `@euno/common-core`.  They are intentionally minimal: the guard
 * implementation lives in the BSL-licensed
 * `euno-platform/packages/agent-runtime` package; the types land here
 * (Apache-2.0) so consumers that only need to wire the guard interface can
 * depend on `@euno/common-core` without importing BSL-licensed code.
 *
 * Architecture context: `docs/diagrams.md` Set D (D1–D4) and
 * `docs/stage-5-design.md` §5 describe the full in-process guard adapter
 * wiring.  The guard is a **soft guard** — it adds defense-in-depth pre-
 * screening but the outer gateway remains the hard, audited enforcement
 * boundary.  An operator MUST NOT rely on the in-process guard as a security
 * boundary; see the enterprise threat model addendum
 * (`docs/security/enterprise-federation-threat-model.md` §"In-process guard
 * bypass" — to be added in Task 1).
 *
 * Stage 5 decision cross-reference: `docs/stage-5-design.md` §5.
 * MVP anchor: `docs/mvp.md` §"Stage 5: Enterprise + Full Vision" — AGT-style
 * in-process guard for defense-in-depth, `docs/diagrams.md` Set D.
 */

import type { AgentCapabilityManifest } from './wire';

// ── AgtGuardDenyReason ────────────────────────────────────────────────────────

/**
 * Structured reason codes passed to {@link AgtGuardOptions.onDeny} when the
 * in-process guard blocks a tool call.
 *
 * | Value | Meaning |
 * |---|---|
 * | `capability_not_found` | The tool name does not appear in `policy.requiredCapabilities` or `policy.optionalCapabilities`. Guard blocks unconditionally. |
 * | `constraint_violated` | The tool is present but at least one declared capability constraint (resource, action, etc.) is not satisfied by the current call arguments. |
 * | `policy_evaluation_error` | An unexpected error occurred during in-process policy evaluation.  The guard fails closed (blocks) and logs the error. |
 */
export type AgtGuardDenyReason =
  | 'capability_not_found'
  | 'constraint_violated'
  | 'policy_evaluation_error';

// ── AgtGuardResult ────────────────────────────────────────────────────────────

/**
 * The verdict returned by an in-process guard evaluation.
 *
 * - `'allow'` — the guard pre-screened the tool call and found it
 *   consistent with the declared policy.  The call is forwarded to the
 *   outer transport (and ultimately to the gateway for hard enforcement).
 * - `'deny'` — the guard blocked the tool call before it reached the
 *   transport.  The gateway never sees the request; `onDeny` is invoked
 *   with the {@link AgtGuardDenyReason}.
 *
 * **Important:** an `'allow'` verdict does not guarantee the outer gateway
 * will also allow the call.  When the gateway subsequently denies a call
 * that the guard allowed, {@link AgtGuardOptions.onGatewayDeny} is
 * invoked (not `onDeny`).
 */
export type AgtGuardResult = 'allow' | 'deny';

// ── AgtGuardOptions ───────────────────────────────────────────────────────────

/**
 * Construction options for the AGT in-process guard.
 *
 * Passed to `createAgtGuard()` in
 * `euno-platform/packages/agent-runtime/src/agt-guard.ts`.
 * The `createAgtGuard` factory is the only consumer of this type in the
 * BSL implementation; downstream callers import the type from
 * `@euno/common-core` so they can declare their wiring without a BSL
 * dependency.
 *
 * **Thread-safety note:** `tokenSupplier` may be called concurrently.
 * Implementations MUST be safe for concurrent invocations (e.g. use
 * lock-free atomic refresh or synchronised renewal).
 */
export interface AgtGuardOptions {
  /**
   * Supplies the short-lived capability token used to authenticate calls
   * forwarded to the outer gateway.
   *
   * May be a plain function returning a string (for pre-loaded tokens or
   * synchronous suppliers) or a function returning a `Promise<string>` (for
   * async refresh flows such as fetching a new token from the capability
   * issuer when the current one is close to expiry).
   *
   * The guard calls this supplier once per outbound tool invocation that
   * passes the in-process policy check.  Suppliers MUST NOT cache an
   * expired token; the guard does not perform token expiry validation.
   */
  tokenSupplier: () => string | Promise<string>;

  /**
   * The agent capability manifest that the guard evaluates in-process.
   *
   * The guard checks every tool call against `policy.requiredCapabilities`
   * (and `policy.optionalCapabilities` when present) before forwarding it
   * to the outer transport.  Calls for tools not listed in either
   * capabilities array are denied with reason `'capability_not_found'`.
   *
   * The manifest is treated as immutable by the guard.  To update the
   * policy at runtime, construct a new guard instance.
   */
  policy: AgentCapabilityManifest;

  /**
   * Optional callback invoked when the guard itself denies a tool call
   * (guard-layer deny, before the call reaches the outer transport).
   *
   * The `reason` parameter is a {@link AgtGuardDenyReason} value.
   *
   * Use this callback to emit internal metrics, structured logs, or span
   * events for guard-level denials.  Do not raise exceptions inside the
   * callback; the guard swallows thrown errors and continues.
   */
  onDeny?: (toolName: string, reason: AgtGuardDenyReason) => void;

  /**
   * Optional callback invoked when the guard **allowed** a tool call but
   * the outer gateway subsequently denied it.
   *
   * This is intentionally distinct from {@link onDeny}: the guard's
   * allow is not a gateway decision, and must be tracked separately for
   * observability.  A gap between guard allows and gateway allows indicates
   * either a stale policy snapshot in the guard or a constraint visible only
   * to the gateway (e.g. rate limits, revocation).
   *
   * `gatewayErrorCode` is the structured error code extracted from the
   * gateway error envelope (e.g. `'CAPABILITY_DENIED'`,
   * `'EXPIRED_TOKEN'`).  Correlates with the gateway audit entry for the
   * same denial event.
   *
   * The gateway audit entry is the **sole authoritative denial record**;
   * this callback provides the agent-side signal only.
   */
  onGatewayDeny?: (toolName: string, gatewayErrorCode: string) => void;
}
