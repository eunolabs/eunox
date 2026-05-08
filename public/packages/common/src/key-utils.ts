/**
 * Shared key-component escaping utilities for rate-limiting key builders.
 *
 * Both the issuance rate limiter and the gateway quota engine use a
 * pipe-separated compound key format.  Centralising the escape logic
 * here ensures both systems apply identical encoding, preventing
 * cross-system injection/collision attacks on shared Redis keyspaces.
 *
 * Encoding scheme
 * ---------------
 * A raw `|` in a component is encoded as `\|`; a raw `\` is encoded
 * as `\\`.  The decoder (never called in hot-path code — keys are
 * write-once) reverses this by scanning left-to-right.  The encoding
 * is injective: distinct component sequences always produce distinct
 * encoded strings.
 */

/**
 * Escape a single component so neither the pipe separator (`|`) nor the
 * escape character (`\`) inside a value can be mistaken for a structural
 * separator.  Used by both `buildIssuanceRateLimitKey` and
 * `buildGatewayQuotaKey`.
 */
export function escapeRateLimitKeyComponent(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
}
